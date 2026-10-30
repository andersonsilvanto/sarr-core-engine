import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence
from unittest.mock import patch

from core import (
    BLE_INVENTORY_EVENT,
    BluetoothGattInventoryAdapter,
    CoreOrchestrator,
    InventoryImportError,
    Persistence,
    RunState,
    ScopeValidationError,
    ScopeValidator,
    WIFI_INVENTORY_EVENT,
    WifiInventoryAdapter,
    run_inventory_import_module,
)
from sarr_core import cli
from sarr_core.external_scanners import ExternalScannerResult
from sarr_core.simulation import LocalSimulationSession, SimulationSnapshot

_HAS_TKINTER = importlib.util.find_spec("tkinter") is not None
if _HAS_TKINTER:
    from sarr_core.gui import LocalDashboard

FIXTURES = Path(__file__).parent / "fixtures"
AP_1 = "02:00:00:00:00:01"
AP_2 = "02:00:00:00:00:02"
BLE_1 = "02:00:00:00:10:01"
FOREIGN_AP = "02:00:00:00:00:99"
FOREIGN_SSID = "FOREIGN-NEIGHBOR-AP"
NMCLI_OUTPUT = (
    "02\\:00\\:00\\:00\\:00\\:01:SYNTHETIC-LAB-AP-1:6:84:WPA2\n"
    f"02\\:00\\:00\\:00\\:00\\:99:{FOREIGN_SSID}:11:90:WPA2\n"
    "02\\:00\\:00\\:00\\:00\\:02:SYNTHETIC-LAB-OPEN:36:66:--\n"
)


class FakeRunner:
    def __init__(self, output: str = NMCLI_OUTPUT) -> None:
        self.output = output
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str]) -> str:
        self.calls.append(tuple(command))
        return self.output


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class WirelessFiles:
    """Writes operator scope and inventory files with a current validity window."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.now = datetime.now(timezone.utc)

    def _authorization(self, targets: list[str], activity: str) -> dict[str, object]:
        return {
            "reference": f"SYNTHETIC-{activity}",
            "approved_by": "Synthetic lab operator",
            "valid_from_utc": _iso(self.now - timedelta(hours=1)),
            "valid_until_utc": _iso(self.now + timedelta(hours=1)),
            "allowed_targets": targets,
            "activity": activity,
        }

    def write(self, name: str, document: dict[str, object]) -> Path:
        path = self.directory / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def scope(
        self,
        *,
        targets: tuple[str, ...] = (AP_1, AP_2, BLE_1),
        modules: tuple[str, ...] = (
            "wifi_passive_inventory",
            "ble_gatt_inventory_readonly",
        ),
    ) -> Path:
        return self.write(
            "wireless-scope.json",
            {
                "engagement_id": "wireless-lab",
                "environment": "lab",
                "mode": "wireless_inventory",
                "valid_from_utc": _iso(self.now - timedelta(minutes=5)),
                "valid_until_utc": _iso(self.now + timedelta(hours=1)),
                "allowed_targets": list(targets),
                "allowed_modules": list(modules),
                "limits": {
                    "max_duration_seconds": 60,
                    "max_rate_per_second": 5,
                    "max_concurrency": 1,
                    "max_volume_bytes": 100_000,
                    "measurement_window_seconds": 10,
                },
            },
        )

    def wifi_authorization(self, targets: list[str] | None = None) -> Path:
        return self.write(
            "wifi-authorization.json",
            {
                "schema_version": 1,
                "authorization": self._authorization(
                    targets or [AP_1, AP_2], "wifi_passive_inventory"
                ),
                "devices": [],
            },
        )

    def wifi_inventory(self) -> Path:
        document = json.loads(
            (FIXTURES / "wifi_inventory_synthetic.json").read_text(encoding="utf-8")
        )
        document["authorization"] = self._authorization(
            [AP_1, AP_2], "wifi_passive_inventory"
        )
        return self.write("wifi-inventory.json", document)

    def ble_inventory(self) -> Path:
        document = json.loads(
            (FIXTURES / "ble_gatt_inventory_synthetic.json").read_text(encoding="utf-8")
        )
        document["authorization"] = self._authorization(
            [BLE_1], "ble_gatt_inventory_readonly"
        )
        return self.write("ble-inventory.json", document)


class InventoryImportModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.directory = Path(temporary_directory.name)
        self.files = WirelessFiles(self.directory)
        self.audit_path = self.directory / "audit.jsonl"
        self.persistence = Persistence(self.directory / "sarr.sqlite3", self.audit_path)
        self.addCleanup(self.persistence.close)
        self.orchestrator = CoreOrchestrator(persistence=self.persistence)
        self.orchestrator.modules.register(
            "wifi_passive_inventory", WifiInventoryAdapter()
        )
        self.orchestrator.modules.register(
            "ble_gatt_inventory_readonly", BluetoothGattInventoryAdapter()
        )
        self.run = self.orchestrator.create_run("wireless_inventory")

    def start_run(self, **scope_options: tuple[str, ...]) -> None:
        modules = scope_options.get("modules", ("wifi_passive_inventory",))
        self.orchestrator.validate_scope(
            self.run.run_id,
            str(self.files.scope(**scope_options)),
            engagement_id="wireless-lab",
            environment="lab",
            targets=[AP_1],
            modules=[modules[0]],
            validator=ScopeValidator(kill_switch=self.orchestrator.kill_switch),
        )
        self.orchestrator.transition(self.run.run_id, RunState.RUNNING)

    def test_load_authorization_reads_the_inventory_format_without_devices(self) -> None:
        authorization = WifiInventoryAdapter().load_authorization(
            self.files.wifi_authorization()
        )
        self.assertEqual(authorization.allowed_targets, frozenset({AP_1, AP_2}))
        self.assertEqual(authorization.activity, "wifi_passive_inventory")
        with self.assertRaisesRegex(InventoryImportError, "does not permit"):
            BluetoothGattInventoryAdapter().load_authorization(
                self.files.wifi_authorization()
            )

    def test_ble_import_publishes_event_and_reaches_audit(self) -> None:
        self.start_run()

        inventory = run_inventory_import_module(
            self.orchestrator,
            self.run.run_id,
            "ble_gatt_inventory_readonly",
            self.files.ble_inventory(),
        )

        self.assertEqual(inventory.devices[0].address, BLE_1)
        names = [event.name for event in self.orchestrator.events.history]
        self.assertLess(names.index("module.executed"), names.index(BLE_INVENTORY_EVENT))
        audit = [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
        ]
        ble_entries = [e for e in audit if e["event_type"] == BLE_INVENTORY_EVENT]
        self.assertEqual(len(ble_entries), 1)
        self.assertEqual(ble_entries[0]["payload"]["device_count"], 1)
        self.assertEqual(ble_entries[0]["payload"]["devices"][0]["address"], BLE_1)

    def test_wifi_import_uses_same_event_contract(self) -> None:
        self.start_run()

        run_inventory_import_module(
            self.orchestrator,
            self.run.run_id,
            "wifi_passive_inventory",
            self.files.wifi_inventory(),
        )

        events = [
            e for e in self.orchestrator.events.history if e.name == WIFI_INVENTORY_EVENT
        ]
        self.assertEqual(events[0].payload["source"], "file_import")
        self.assertFalse(events[0].payload["rssi_estimated"])

    def test_import_refused_when_module_not_in_scope(self) -> None:
        self.start_run(modules=("wifi_passive_inventory",))

        with self.assertRaises(ScopeValidationError):
            run_inventory_import_module(
                self.orchestrator,
                self.run.run_id,
                "ble_gatt_inventory_readonly",
                self.files.ble_inventory(),
            )
        self.assertNotIn(
            BLE_INVENTORY_EVENT,
            [event.name for event in self.orchestrator.events.history],
        )

    def test_import_refused_when_allowlist_exceeds_scope(self) -> None:
        self.start_run(targets=(AP_1, AP_2))

        with self.assertRaisesRegex(ScopeValidationError, "scope targets"):
            run_inventory_import_module(
                self.orchestrator,
                self.run.run_id,
                "ble_gatt_inventory_readonly",
                self.files.ble_inventory(),
            )


class WirelessSimulationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.directory = Path(temporary_directory.name)
        self.files = WirelessFiles(self.directory)
        self.data_directory = self.directory / "data"
        self.data_directory.mkdir()
        self.runner = FakeRunner()
        for patcher in (
            patch(
                "sarr_core.simulation.resolve_data_directory",
                return_value=self.data_directory,
            ),
            patch(
                "sarr_core.simulation.ExternalScannerManager.run_local_checks",
                return_value=ExternalScannerResult((), ()),
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def session(self, **options: object) -> LocalSimulationSession:
        return LocalSimulationSession(
            wifi_adapter=WifiInventoryAdapter(
                command_runner=self.runner, platform="linux"
            ),
            **options,  # type: ignore[arg-type]
        )

    def audit_text(self) -> str:
        return (self.data_directory / "audit.jsonl").read_text(encoding="utf-8")

    def test_without_wireless_options_nothing_is_collected(self) -> None:
        snapshot = self.session().run()

        self.assertEqual(snapshot.state, RunState.COMPLETED)
        self.assertIsNone(snapshot.wifi_inventory)
        self.assertIsNone(snapshot.ble_inventory)
        self.assertEqual(self.runner.calls, [])

    def test_wireless_options_require_operator_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "operator scope"):
            self.session(wifi_authorization=self.files.wifi_authorization())
        with self.assertRaisesRegex(ValueError, "not both"):
            self.session(
                wireless_scope=self.files.scope(),
                wifi_authorization=self.files.wifi_authorization(),
                wifi_inventory=self.files.wifi_inventory(),
            )

    def test_live_wifi_and_ble_reach_snapshot_events_and_audit(self) -> None:
        session = self.session(
            wireless_scope=self.files.scope(),
            wifi_authorization=self.files.wifi_authorization(),
            ble_inventory=self.files.ble_inventory(),
        )
        snapshot = session.run()

        self.assertEqual(snapshot.state, RunState.COMPLETED)
        self.assertEqual(snapshot.wifi_source, "os_passive")
        self.assertEqual(
            [ap.bssid for ap in snapshot.wifi_inventory.access_points], [AP_1, AP_2]
        )
        self.assertEqual(snapshot.ble_inventory.devices[0].address, BLE_1)
        event_names = [name for _, name in session.event_log()]
        self.assertIn(WIFI_INVENTORY_EVENT, event_names)
        self.assertIn(BLE_INVENTORY_EVENT, event_names)
        audit = self.audit_text()
        self.assertIn(WIFI_INVENTORY_EVENT, audit)
        self.assertIn(BLE_INVENTORY_EVENT, audit)
        self.assertNotIn(FOREIGN_AP, audit)
        self.assertNotIn(FOREIGN_SSID, audit)

    def test_wifi_file_import_reaches_snapshot(self) -> None:
        snapshot = self.session(
            wireless_scope=self.files.scope(),
            wifi_inventory=self.files.wifi_inventory(),
        ).run()

        self.assertEqual(snapshot.wifi_source, "file_import")
        self.assertEqual(len(snapshot.wifi_inventory.access_points), 2)
        self.assertEqual(self.runner.calls, [])

    def test_scope_without_wifi_module_blocks_before_os_command(self) -> None:
        session = self.session(
            wireless_scope=self.files.scope(modules=("ble_gatt_inventory_readonly",)),
            wifi_authorization=self.files.wifi_authorization(),
        )

        with self.assertRaises(ScopeValidationError):
            session.run()

        self.assertIn(session.snapshot.state, (RunState.STOPPED, RunState.BLOCKED))
        self.assertIn("safety.triggered", [name for _, name in session.event_log()])
        self.assertIsNone(session.snapshot.wifi_inventory)
        self.assertEqual(self.runner.calls, [])
        self.assertNotIn(WIFI_INVENTORY_EVENT, self.audit_text())

    def test_authorization_beyond_scope_targets_blocks(self) -> None:
        session = self.session(
            wireless_scope=self.files.scope(targets=(AP_1,)),
            wifi_authorization=self.files.wifi_authorization(),
        )

        with self.assertRaises(ScopeValidationError):
            session.run()

        self.assertIn(session.snapshot.state, (RunState.STOPPED, RunState.BLOCKED))
        self.assertIn("safety.triggered", [name for _, name in session.event_log()])
        self.assertEqual(self.runner.calls, [])


@unittest.skipUnless(_HAS_TKINTER, "Tkinter is not installed")
class WirelessPanelTests(unittest.TestCase):
    def snapshot(self) -> SimulationSnapshot:
        from uuid import uuid4

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        files = WirelessFiles(Path(directory.name))
        wifi = WifiInventoryAdapter(
            command_runner=FakeRunner(), platform="linux"
        ).collect_from_os(
            WifiInventoryAdapter().load_authorization(files.wifi_authorization())
        )
        ble = BluetoothGattInventoryAdapter().import_file(files.ble_inventory())
        return SimulationSnapshot(
            uuid4(),
            RunState.COMPLETED,
            (),
            wifi_inventory=wifi,
            wifi_source="os_passive",
            ble_inventory=ble,
        )

    def test_wifi_security_uses_finding_severity_palette(self) -> None:
        self.assertEqual(LocalDashboard._row_tag_for_wifi_security("open"), "CRITICAL")
        self.assertEqual(LocalDashboard._row_tag_for_wifi_security("wep"), "CRITICAL")
        self.assertEqual(LocalDashboard._row_tag_for_wifi_security("unknown"), "WARNING")
        self.assertEqual(LocalDashboard._row_tag_for_wifi_security("wpa2"), "SECURE")
        self.assertEqual(LocalDashboard._row_tag_for_wifi_security("wpa3"), "SECURE")
        self.assertEqual(LocalDashboard._severity_label("SECURE"), "SEGURO")

    def test_wireless_rows_come_from_snapshot(self) -> None:
        rows = LocalDashboard._wireless_rows(self.snapshot())

        self.assertEqual([values[2] for _, values in rows], [AP_1, AP_2, BLE_1])
        self.assertEqual([tag for tag, _ in rows], ["SECURE", "CRITICAL", "SECURE"])
        self.assertIn("(estimado)", rows[0][1][4])
        self.assertIn("somente leitura", rows[2][1][4])
        self.assertNotIn(FOREIGN_SSID, repr(rows))

    def test_wireless_status_summarizes_sources(self) -> None:
        self.assertEqual(
            LocalDashboard._wireless_status_for(self.snapshot()),
            "2 rede(s) Wi-Fi (cache passivo do SO) + 1 dispositivo(s) BLE",
        )
        from uuid import uuid4

        self.assertEqual(
            LocalDashboard._wireless_status_for(
                SimulationSnapshot(uuid4(), RunState.COMPLETED, ())
            ),
            "NÃO CONFIGURADO",
        )


class WirelessCliTests(unittest.TestCase):
    def test_wireless_options_require_scope_and_execution_mode(self) -> None:
        for argv in (
            ["--wifi-authorization", "auth.json", "--run-sim"],
            ["--wireless-scope", "scope.json", "--run-sim"],
            ["--wireless-scope", "scope.json", "--ble-inventory", "ble.json"],
            [
                "--run-sim",
                "--wireless-scope",
                "scope.json",
                "--wifi-authorization",
                "a.json",
                "--wifi-inventory",
                "b.json",
            ],
        ):
            with self.subTest(argv=argv):
                with (
                    patch("sys.stderr"),
                    self.assertRaises(SystemExit),
                ):
                    cli.main(argv)

    def test_gui_receives_session_factory_with_operator_files(self) -> None:
        with patch("sarr_core.gui.launch_gui", return_value=0) as launch:
            status = cli.main(
                [
                    "--gui",
                    "--wireless-scope",
                    "scope.json",
                    "--ble-inventory",
                    "ble.json",
                ]
            )

        self.assertEqual(status, 0)
        factory = launch.call_args.kwargs["session_factory"]
        self.assertIs(factory.func, LocalSimulationSession)
        self.assertEqual(
            factory.keywords,
            {"wireless_scope": Path("scope.json"), "ble_inventory": Path("ble.json")},
        )


if __name__ == "__main__":
    unittest.main()
