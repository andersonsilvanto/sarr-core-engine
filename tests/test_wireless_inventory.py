import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core import (
    BluetoothGattInventoryAdapter,
    InventoryImportError,
    LocalAdapterUnavailableError,
    WifiInventoryAdapter,
)


FIXTURES = Path(__file__).parent / "fixtures"
FIXED_NOW = datetime(2026, 10, 29, 12, 30, tzinfo=timezone.utc)


class WirelessInventoryImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wifi_adapter = WifiInventoryAdapter(clock=lambda: FIXED_NOW)
        self.ble_adapter = BluetoothGattInventoryAdapter(clock=lambda: FIXED_NOW)

    def write_json(self, document: object) -> Path:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        source = Path(temporary_directory.name) / "inventory.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        return source

    def test_imports_synthetic_wifi_inventory_with_authorization(self) -> None:
        inventory = self.wifi_adapter.import_file(
            FIXTURES / "wifi_inventory_synthetic.json"
        )

        self.assertEqual(inventory.authorization.reference, "SYNTHETIC-LAB-WIFI-001")
        self.assertEqual(inventory.authorization.activity, "wifi_passive_inventory")
        self.assertEqual(len(inventory.access_points), 2)
        self.assertEqual(inventory.access_points[0].bssid, "02:00:00:00:00:01")
        self.assertEqual(inventory.access_points[0].ssid, "SYNTHETIC-LAB-AP-1")

    def test_imports_synthetic_read_only_gatt_inventory(self) -> None:
        inventory = self.ble_adapter.import_file(
            FIXTURES / "ble_gatt_inventory_synthetic.json"
        )

        self.assertEqual(
            inventory.authorization.reference,
            "SYNTHETIC-LAB-BLE-001",
        )
        self.assertEqual(inventory.authorization.activity, "ble_gatt_inventory_readonly")
        self.assertEqual(len(inventory.devices), 1)
        self.assertEqual(len(inventory.devices[0].services), 2)
        self.assertEqual(
            inventory.devices[0].services[0].characteristics[0].properties,
            ("notify", "read"),
        )

    def test_import_rejects_expired_or_mismatched_authorization(self) -> None:
        document = json.loads(
            (FIXTURES / "wifi_inventory_synthetic.json").read_text(
                encoding="utf-8"
            )
        )
        document["authorization"]["valid_until_utc"] = "2026-10-29T12:00:00Z"
        with self.assertRaisesRegex(InventoryImportError, "not currently valid"):
            self.wifi_adapter.import_file(self.write_json(document))

        document["authorization"]["valid_until_utc"] = "2026-10-30T00:00:00Z"
        document["authorization"]["activity"] = "ble_gatt_inventory_readonly"
        with self.assertRaisesRegex(InventoryImportError, "does not permit"):
            self.wifi_adapter.import_file(self.write_json(document))

    def test_import_rejects_targets_outside_documented_allowlist(self) -> None:
        document = json.loads(
            (FIXTURES / "wifi_inventory_synthetic.json").read_text(
                encoding="utf-8"
            )
        )
        document["devices"][0]["bssid"] = "02:00:00:00:00:99"

        with self.assertRaisesRegex(InventoryImportError, "outside the authorized"):
            self.wifi_adapter.import_file(self.write_json(document))

    def test_import_rejects_credentials_and_unexpected_fields(self) -> None:
        document = json.loads(
            (FIXTURES / "ble_gatt_inventory_synthetic.json").read_text(
                encoding="utf-8"
            )
        )
        document["devices"][0]["password"] = "synthetic-secret"

        with self.assertRaises(InventoryImportError) as error:
            self.ble_adapter.import_file(self.write_json(document))

        self.assertNotIn("synthetic-secret", str(error.exception))

    def test_import_rejects_gatt_values_and_write_capabilities(self) -> None:
        document = json.loads(
            (FIXTURES / "ble_gatt_inventory_synthetic.json").read_text(
                encoding="utf-8"
            )
        )
        characteristic = document["devices"][0]["services"][0]["characteristics"][0]
        characteristic["value"] = "synthetic-data"
        with self.assertRaisesRegex(InventoryImportError, "unsupported fields"):
            self.ble_adapter.import_file(self.write_json(document))

        del characteristic["value"]
        characteristic["properties"] = ["read", "write"]
        with self.assertRaisesRegex(InventoryImportError, "read-only"):
            self.ble_adapter.import_file(self.write_json(document))

    def test_live_os_radio_collection_is_an_explicit_unsupported_stub(self) -> None:
        for adapter in (self.wifi_adapter, self.ble_adapter):
            with self.subTest(adapter=type(adapter).__name__):
                with self.assertRaises(LocalAdapterUnavailableError):
                    adapter.collect_from_os()

    def test_import_rejects_duplicate_json_keys(self) -> None:
        source = self.write_json({})
        source.write_text(
            '{"schema_version":1,"schema_version":1,"authorization":{},"devices":[]}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InventoryImportError, "duplicate keys"):
            self.wifi_adapter.import_file(source)


if __name__ == "__main__":
    unittest.main()
