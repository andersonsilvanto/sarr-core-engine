import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence
from unittest import mock

from core import (
    CoreOrchestrator,
    InventoryAuthorization,
    InventoryImportError,
    InvalidTransitionError,
    KillSwitchTriggered,
    LocalAdapterUnavailableError,
    Persistence,
    RunState,
    ScopeValidationError,
    ScopeValidator,
    WIFI_INVENTORY_EVENT,
    WifiAccessPoint,
    WifiInventoryAdapter,
    publish_wifi_inventory,
    run_wifi_inventory_module,
)


FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 29, 12, 30, tzinfo=timezone.utc)
ALLOWED_AP_1 = "02:00:00:00:00:01"
ALLOWED_AP_2 = "02:00:00:00:00:02"
FOREIGN_AP = "02:00:00:00:00:99"
FOREIGN_SSID = "FOREIGN-NEIGHBOR-AP"

NMCLI_OUTPUT = (
    "02\\:00\\:00\\:00\\:00\\:01:SYNTHETIC-LAB-AP-1:6:84:WPA2\n"
    f"02\\:00\\:00\\:00\\:00\\:99:{FOREIGN_SSID}:11:90:WPA2\n"
    "02\\:00\\:00\\:00\\:00\\:02:SYNTHETIC-LAB-AP-2:36:66:WPA3\n"
)


def authorization(**updates: object) -> InventoryAuthorization:
    values: dict[str, object] = {
        "reference": "SYNTHETIC-LAB-WIFI-001",
        "approved_by": "Synthetic lab operator",
        "valid_from_utc": NOW - timedelta(hours=1),
        "valid_until_utc": NOW + timedelta(hours=1),
        "allowed_targets": frozenset({ALLOWED_AP_1, ALLOWED_AP_2}),
        "activity": "wifi_passive_inventory",
    }
    values.update(updates)
    return InventoryAuthorization(**values)  # type: ignore[arg-type]


class FakeRunner:
    def __init__(self, output: str) -> None:
        self.output = output
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str]) -> str:
        self.calls.append(tuple(command))
        return self.output


class WifiCollectFromOsAdapterTests(unittest.TestCase):
    def adapter(self, output: str = NMCLI_OUTPUT, platform: str = "linux"):
        runner = FakeRunner(output)
        return (
            WifiInventoryAdapter(
                clock=lambda: NOW, command_runner=runner, platform=platform
            ),
            runner,
        )

    def test_refuses_without_loaded_authorization(self) -> None:
        adapter, runner = self.adapter()
        with self.assertRaisesRegex(InventoryImportError, "authorization record"):
            adapter.collect_from_os(None)  # type: ignore[arg-type]
        self.assertEqual(runner.calls, [])

    def test_refuses_expired_or_mismatched_authorization(self) -> None:
        adapter, runner = self.adapter()
        expired = authorization(valid_until_utc=NOW - timedelta(seconds=1))
        with self.assertRaisesRegex(InventoryImportError, "not currently valid"):
            adapter.collect_from_os(expired)
        with self.assertRaisesRegex(InventoryImportError, "does not permit"):
            adapter.collect_from_os(
                authorization(activity="ble_gatt_inventory_readonly")
            )
        self.assertEqual(runner.calls, [])

    def test_uses_cached_passive_listing_without_rescan_or_monitor_mode(self) -> None:
        adapter, runner = self.adapter()
        adapter.collect_from_os(authorization())
        self.assertEqual(len(runner.calls), 1)
        command = runner.calls[0]
        self.assertEqual(command[0], "nmcli")
        self.assertEqual(command[-2:], ("--rescan", "no"))
        joined = " ".join(command).lower()
        for forbidden in ("monitor", "iwlist", "iw ", "connect", "rescan yes"):
            self.assertNotIn(forbidden, joined)

    def test_discards_targets_outside_allowlist_before_building_records(self) -> None:
        adapter, _ = self.adapter()
        inventory = adapter.collect_from_os(authorization())

        self.assertEqual(
            [access_point.bssid for access_point in inventory.access_points],
            [ALLOWED_AP_1, ALLOWED_AP_2],
        )
        self.assertNotIn(FOREIGN_SSID, repr(inventory))
        self.assertNotIn(FOREIGN_AP, repr(inventory))

    def test_produces_same_structure_as_json_import(self) -> None:
        imported = WifiInventoryAdapter(clock=lambda: NOW).import_file(
            FIXTURES / "wifi_inventory_synthetic.json"
        )
        adapter, _ = self.adapter()
        collected = adapter.collect_from_os(imported.authorization)

        self.assertIs(type(collected), type(imported))
        self.assertEqual(collected.authorization, imported.authorization)
        for live, from_file in zip(collected.access_points, imported.access_points):
            self.assertIsInstance(live, WifiAccessPoint)
            self.assertEqual(
                (live.bssid, live.ssid, live.channel, live.security),
                (from_file.bssid, from_file.ssid, from_file.channel, from_file.security),
            )
            self.assertEqual(live.observed_at_utc, NOW)
        self.assertEqual(collected.access_points[0].rssi_dbm, -58)

    def test_discards_hidden_ssid_and_unescapes_nmcli_fields(self) -> None:
        adapter, _ = self.adapter(
            "02\\:00\\:00\\:00\\:00\\:01:LAB\\:AP\\\\1:6:50:WPA1 WPA2\n"
            "02\\:00\\:00\\:00\\:00\\:02::36:70:WPA3\n"
        )
        inventory = adapter.collect_from_os(authorization())
        self.assertEqual(len(inventory.access_points), 1)
        self.assertEqual(inventory.access_points[0].ssid, "LAB:AP\\1")
        self.assertEqual(inventory.access_points[0].security, "wpa2")

    def test_malformed_allowlisted_observation_fails_closed(self) -> None:
        adapter, _ = self.adapter(
            "02\\:00\\:00\\:00\\:00\\:01:SYNTHETIC-LAB-AP-1:999:50:WPA2\n"
        )
        with self.assertRaisesRegex(InventoryImportError, "channel"):
            adapter.collect_from_os(authorization())

    def test_parses_windows_netsh_listing_in_english_and_portuguese(self) -> None:
        english = (
            "Interface name : Wi-Fi\r\n"
            "There are 2 networks currently visible.\r\n\r\n"
            "SSID 1 : SYNTHETIC-LAB-AP-1\r\n"
            "    Network type            : Infrastructure\r\n"
            "    Authentication          : WPA2-Personal\r\n"
            "    Encryption              : CCMP\r\n"
            "    BSSID 1                 : 02:00:00:00:00:01\r\n"
            "         Signal             : 84%\r\n"
            "         Radio type         : 802.11ac\r\n"
            "         Channel            : 6\r\n"
            "         Channel Utilization: 12 (4 %)\r\n"
            f"SSID 2 : {FOREIGN_SSID}\r\n"
            "    Authentication          : Open\r\n"
            "    Encryption              : None\r\n"
            f"    BSSID 1                 : {FOREIGN_AP}\r\n"
            "         Signal             : 99%\r\n"
            "         Channel            : 11\r\n"
        )
        portuguese = (
            "SSID 1 : SYNTHETIC-LAB-AP-2\r\n"
            "    Tipo de rede            : Infraestrutura\r\n"
            "    Autenticação            : WPA3-Personal\r\n"
            "    Criptografia            : CCMP\r\n"
            "    BSSID 1                 : 02:00:00:00:00:02\r\n"
            "         Sinal              : 66%\r\n"
            "         Canal              : 36\r\n"
        )
        adapter, runner = self.adapter(english, platform="win32")
        inventory = adapter.collect_from_os(authorization())
        self.assertEqual(runner.calls[0][0], "netsh")
        self.assertEqual(
            [(ap.bssid, ap.channel, ap.security) for ap in inventory.access_points],
            [(ALLOWED_AP_1, 6, "wpa2")],
        )

        adapter, _ = self.adapter(portuguese, platform="win32")
        inventory = adapter.collect_from_os(authorization())
        self.assertEqual(
            [(ap.bssid, ap.channel, ap.security) for ap in inventory.access_points],
            [(ALLOWED_AP_2, 36, "wpa3")],
        )

    def test_unsupported_platform_or_missing_tool_is_unavailable(self) -> None:
        adapter, runner = self.adapter(platform="darwin")
        with self.assertRaises(LocalAdapterUnavailableError):
            adapter.collect_from_os(authorization())
        self.assertEqual(runner.calls, [])

        adapter = WifiInventoryAdapter(clock=lambda: NOW, platform="linux")
        with mock.patch("core.wireless_inventory.shutil.which", return_value=None):
            with self.assertRaisesRegex(LocalAdapterUnavailableError, "nmcli"):
                adapter.collect_from_os(authorization())


class WifiInventoryModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.directory = Path(temporary_directory.name)
        self.audit_path = self.directory / "audit.jsonl"
        self.persistence = Persistence(self.directory / "sarr.sqlite3", self.audit_path)
        self.addCleanup(self.persistence.close)
        self.orchestrator = CoreOrchestrator(
            persistence=self.persistence, clock=lambda: NOW
        )
        self.runner = FakeRunner(NMCLI_OUTPUT)
        self.orchestrator.modules.register(
            "wifi_passive_inventory",
            WifiInventoryAdapter(
                clock=lambda: NOW, command_runner=self.runner, platform="linux"
            ),
        )
        self.run = self.orchestrator.create_run("test")

    def start_run(
        self,
        *,
        modules: tuple[str, ...] = ("wifi_passive_inventory",),
        targets: tuple[str, ...] = (ALLOWED_AP_1, ALLOWED_AP_2),
    ) -> None:
        scope_path = self.directory / "scope.json"
        scope_path.write_text(
            json.dumps(
                {
                    "engagement_id": "wifi-lab",
                    "environment": "lab",
                    "mode": "test",
                    "valid_from_utc": (NOW - timedelta(minutes=5)).isoformat(),
                    "valid_until_utc": (NOW + timedelta(hours=1)).isoformat(),
                    "allowed_targets": list(targets),
                    "allowed_modules": list(modules),
                    "limits": {
                        "max_duration_seconds": 60,
                        "max_rate_per_second": 1,
                        "max_concurrency": 1,
                        "max_volume_bytes": 1000,
                        "measurement_window_seconds": 10,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.orchestrator.validate_scope(
            self.run.run_id,
            str(scope_path),
            engagement_id="wifi-lab",
            environment="lab",
            targets=[targets[0]],
            modules=[modules[0]],
            validator=ScopeValidator(
                clock=lambda: NOW, kill_switch=self.orchestrator.kill_switch
            ),
        )
        self.orchestrator.transition(self.run.run_id, RunState.RUNNING)

    def inventory_events(self):
        return [
            event
            for event in self.orchestrator.events.history
            if event.name == WIFI_INVENTORY_EVENT
        ]

    def audit_entries(self) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_valid_collection_publishes_event_and_reaches_audit(self) -> None:
        self.start_run()

        inventory = run_wifi_inventory_module(
            self.orchestrator, self.run.run_id, authorization()
        )

        self.assertEqual(len(inventory.access_points), 2)
        events = self.inventory_events()
        self.assertEqual(len(events), 1)
        payload = events[0].payload
        self.assertEqual(payload["source"], "os_passive")
        self.assertEqual(payload["access_point_count"], 2)
        self.assertEqual(payload["discarded_count"], 1)
        names = [event.name for event in self.orchestrator.events.history]
        self.assertLess(names.index("module.executed"), names.index(WIFI_INVENTORY_EVENT))

        audit = [
            entry for entry in self.audit_entries()
            if entry["event_type"] == WIFI_INVENTORY_EVENT
        ]
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["payload"]["approval_reference"], "SYNTHETIC-LAB-WIFI-001")
        self.assertEqual(
            [ap["bssid"] for ap in audit[0]["payload"]["access_points"]],
            [ALLOWED_AP_1, ALLOWED_AP_2],
        )
        stored = [
            record for record in self.persistence.events.list_for_run(self.run.run_id)
            if record.name == WIFI_INVENTORY_EVENT
        ]
        self.assertEqual(len(stored), 1)

    def test_targets_outside_allowlist_never_reach_events_or_audit(self) -> None:
        self.start_run()

        run_wifi_inventory_module(self.orchestrator, self.run.run_id, authorization())

        self.assertNotIn(FOREIGN_AP, repr(self.orchestrator.events.history))
        self.assertNotIn(FOREIGN_SSID, repr(self.orchestrator.events.history))
        audit_text = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(FOREIGN_AP, audit_text)
        self.assertNotIn(FOREIGN_SSID, audit_text)

    def test_refuses_without_authorization_record(self) -> None:
        self.start_run()

        with self.assertRaises(InventoryImportError):
            run_wifi_inventory_module(
                self.orchestrator, self.run.run_id, None  # type: ignore[arg-type]
            )

        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.inventory_events(), [])

    def test_refuses_when_scope_does_not_authorize_module(self) -> None:
        self.start_run(modules=("security_audit_demo",))

        with self.assertRaises(ScopeValidationError):
            run_wifi_inventory_module(self.orchestrator, self.run.run_id, authorization())

        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.inventory_events(), [])

    def test_refuses_when_authorization_exceeds_scope_targets(self) -> None:
        self.start_run(targets=(ALLOWED_AP_1,))

        with self.assertRaisesRegex(ScopeValidationError, "scope targets"):
            run_wifi_inventory_module(self.orchestrator, self.run.run_id, authorization())

        self.assertEqual(self.runner.calls, [])

    def test_refuses_without_validated_scope_or_running_state(self) -> None:
        with self.assertRaises(ScopeValidationError):
            run_wifi_inventory_module(self.orchestrator, self.run.run_id, authorization())
        self.assertEqual(self.runner.calls, [])

    def test_refuses_after_kill_switch(self) -> None:
        self.start_run()
        self.orchestrator.kill_switch.trigger("manual stop", run_id=self.run.run_id)

        with self.assertRaises((InvalidTransitionError, KillSwitchTriggered)):
            run_wifi_inventory_module(self.orchestrator, self.run.run_id, authorization())

        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.inventory_events(), [])

    def test_unregistered_module_is_refused(self) -> None:
        self.orchestrator.modules.unregister("wifi_passive_inventory")
        self.start_run()

        with self.assertRaises(KeyError):
            run_wifi_inventory_module(self.orchestrator, self.run.run_id, authorization())

    def test_imported_inventory_uses_same_event_contract(self) -> None:
        imported = WifiInventoryAdapter(clock=lambda: NOW).import_file(
            FIXTURES / "wifi_inventory_synthetic.json"
        )
        event = publish_wifi_inventory(
            self.orchestrator.events, self.run.run_id, imported, source="file_import"
        )
        live = WifiInventoryAdapter(
            clock=lambda: NOW, command_runner=FakeRunner(NMCLI_OUTPUT), platform="linux"
        ).collect_from_os(authorization())
        live_event = publish_wifi_inventory(
            self.orchestrator.events, self.run.run_id, live, source="os_passive"
        )

        self.assertEqual(set(event.payload), set(live_event.payload))
        self.assertEqual(
            set(event.payload["access_points"][0]),
            set(live_event.payload["access_points"][0]),
        )


if __name__ == "__main__":
    unittest.main()
