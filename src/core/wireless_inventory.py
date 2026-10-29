"""Passive importers for explicitly authorized Wi-Fi and BLE inventory files.

These adapters only read local JSON files. They do not enumerate radio devices,
open sockets, scan, associate, pair, read live GATT characteristics, or transmit.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from uuid import UUID

from core.redaction import sanitize_text


_MAC_ADDRESS = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_WIFI_SECURITY = {"open", "wep", "wpa2", "wpa3", "unknown"}
_GATT_INVENTORY_PROPERTIES = {"read", "notify", "indicate"}
_MAX_INVENTORY_BYTES = 1_048_576
_MAX_DEVICES = 1_000
_MAX_SERVICES_PER_DEVICE = 64
_MAX_CHARACTERISTICS_PER_SERVICE = 128


class InventoryImportError(ValueError):
    """Raised when an inventory file or its authorization metadata is invalid."""


class LocalAdapterUnavailableError(RuntimeError):
    """Raised when an OS radio adapter is not implemented for this platform."""


@dataclass(frozen=True)
class InventoryAuthorization:
    reference: str
    approved_by: str
    valid_from_utc: datetime
    valid_until_utc: datetime
    allowed_targets: frozenset[str]
    activity: str


@dataclass(frozen=True)
class WifiAccessPoint:
    bssid: str
    ssid: str
    channel: int
    rssi_dbm: int
    security: str
    observed_at_utc: datetime


@dataclass(frozen=True)
class WifiInventory:
    authorization: InventoryAuthorization
    access_points: tuple[WifiAccessPoint, ...]


@dataclass(frozen=True)
class GattCharacteristic:
    uuid: str
    properties: tuple[str, ...]


@dataclass(frozen=True)
class GattService:
    uuid: str
    characteristics: tuple[GattCharacteristic, ...]


@dataclass(frozen=True)
class BleDevice:
    address: str
    name: str
    observed_at_utc: datetime
    services: tuple[GattService, ...]


@dataclass(frozen=True)
class BleGattInventory:
    authorization: InventoryAuthorization
    devices: tuple[BleDevice, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryImportError("Inventory JSON contains duplicate keys.")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise InventoryImportError(
        f"Inventory JSON contains unsupported numeric constant {value!r}."
    )


def _require_object(
    value: object,
    *,
    required_keys: frozenset[str],
    optional_keys: frozenset[str] = frozenset(),
    context: str,
) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise InventoryImportError(f"{context} must be a JSON object.")
    keys = set(value)
    if not required_keys.issubset(keys) or keys - required_keys - optional_keys:
        raise InventoryImportError(f"{context} has missing or unsupported fields.")
    return value


def _require_string(value: object, context: str, *, max_length: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > max_length
        or any(ord(character) < 32 for character in value)
    ):
        raise InventoryImportError(f"{context} must be a bounded non-empty string.")
    return sanitize_text(value.strip())


def _parse_utc(value: object, context: str) -> datetime:
    if not isinstance(value, str):
        raise InventoryImportError(f"{context} must be a UTC timestamp.")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise InventoryImportError(f"{context} must be a UTC timestamp.") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise InventoryImportError(f"{context} must explicitly use UTC.")
    return parsed.astimezone(timezone.utc)


def _normalize_mac(value: object, context: str) -> str:
    if not isinstance(value, str) or not _MAC_ADDRESS.fullmatch(value):
        raise InventoryImportError(f"{context} must be a six-octet MAC address.")
    return value.lower()


def _normalize_gatt_uuid(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise InventoryImportError(f"{context} must be a GATT UUID.")
    candidate = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{4}", candidate):
        return candidate.lower()
    try:
        return str(UUID(candidate))
    except ValueError as error:
        raise InventoryImportError(f"{context} must be a GATT UUID.") from error


class _AuthorizedInventoryImporter:
    ACTIVITY: str

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _read_document(self, source: str | Path) -> Mapping[str, object]:
        path = Path(source)
        try:
            with path.open("rb") as inventory_file:
                content = inventory_file.read(_MAX_INVENTORY_BYTES + 1)
        except OSError as error:
            raise InventoryImportError(
                "Inventory file is missing or unreadable."
            ) from error
        if len(content) > _MAX_INVENTORY_BYTES:
            raise InventoryImportError("Inventory file exceeds the 1 MiB limit.")
        try:
            document = json.loads(
                content.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InventoryImportError("Inventory file is not valid UTF-8 JSON.") from error
        return _require_object(
            document,
            required_keys=frozenset({"schema_version", "authorization", "devices"}),
            context="Inventory document",
        )

    def _parse_authorization(
        self, value: object, *, targets: set[str]
    ) -> InventoryAuthorization:
        authorization = _require_object(
            value,
            required_keys=frozenset(
                {
                    "reference",
                    "approved_by",
                    "valid_from_utc",
                    "valid_until_utc",
                    "allowed_targets",
                    "activity",
                }
            ),
            context="Authorization record",
        )
        reference = _require_string(
            authorization["reference"], "Authorization reference", max_length=128
        )
        approved_by = _require_string(
            authorization["approved_by"], "Approver", max_length=128
        )
        activity = authorization["activity"]
        if activity != self.ACTIVITY:
            raise InventoryImportError(
                "Authorization does not permit this passive inventory activity."
            )
        allowed_raw = authorization["allowed_targets"]
        if (
            not isinstance(allowed_raw, list)
            or not allowed_raw
            or len(allowed_raw) > _MAX_DEVICES
        ):
            raise InventoryImportError(
                "Authorization allowed_targets must be a non-empty bounded array."
            )
        allowed_targets = {
            _normalize_mac(target, "Authorized target") for target in allowed_raw
        }
        if len(allowed_targets) != len(allowed_raw):
            raise InventoryImportError("Authorization contains duplicate targets.")
        if not targets.issubset(allowed_targets):
            raise InventoryImportError(
                "Inventory contains targets outside the authorized allowlist."
            )

        valid_from = _parse_utc(
            authorization["valid_from_utc"], "Authorization valid_from_utc"
        )
        valid_until = _parse_utc(
            authorization["valid_until_utc"], "Authorization valid_until_utc"
        )
        if valid_until <= valid_from:
            raise InventoryImportError(
                "Authorization validity end must follow its start."
            )
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            raise ValueError("clock must return a timezone-aware UTC datetime.")
        now = now.astimezone(timezone.utc)
        if not valid_from <= now <= valid_until:
            raise InventoryImportError("Authorization is not currently valid.")
        return InventoryAuthorization(
            reference=reference,
            approved_by=approved_by,
            valid_from_utc=valid_from,
            valid_until_utc=valid_until,
            allowed_targets=frozenset(allowed_targets),
            activity=self.ACTIVITY,
        )

    def collect_from_os(self) -> None:
        """Explicitly unsupported: this importer never probes local radios."""
        raise LocalAdapterUnavailableError(
            "OS radio enumeration is not implemented. Import an authorized "
            "local inventory file instead."
        )


class WifiInventoryAdapter(_AuthorizedInventoryImporter):
    """Import passive 802.11 observations from a consented local JSON file."""

    ACTIVITY = "wifi_passive_inventory"

    def import_file(self, source: str | Path) -> WifiInventory:
        document = self._read_document(source)
        if document["schema_version"] != 1:
            raise InventoryImportError("Unsupported Wi-Fi inventory schema_version.")
        raw_devices = document["devices"]
        if (
            not isinstance(raw_devices, list)
            or not raw_devices
            or len(raw_devices) > _MAX_DEVICES
        ):
            raise InventoryImportError("Wi-Fi devices must be a non-empty bounded array.")

        access_points: list[WifiAccessPoint] = []
        targets: set[str] = set()
        for raw_device in raw_devices:
            device = _require_object(
                raw_device,
                required_keys=frozenset(
                    {
                        "bssid",
                        "ssid",
                        "channel",
                        "rssi_dbm",
                        "security",
                        "observed_at_utc",
                    }
                ),
                context="Wi-Fi access point",
            )
            bssid = _normalize_mac(device["bssid"], "BSSID")
            ssid = _require_string(device["ssid"], "SSID", max_length=32)
            channel = device["channel"]
            rssi = device["rssi_dbm"]
            security = device["security"]
            if (
                isinstance(channel, bool)
                or not isinstance(channel, int)
                or not 1 <= channel <= 233
            ):
                raise InventoryImportError("Wi-Fi channel must be an integer from 1 to 233.")
            if (
                isinstance(rssi, bool)
                or not isinstance(rssi, int)
                or not -127 <= rssi <= 0
            ):
                raise InventoryImportError("Wi-Fi RSSI must be an integer from -127 to 0.")
            if not isinstance(security, str) or security not in _WIFI_SECURITY:
                raise InventoryImportError("Wi-Fi security classification is invalid.")
            if bssid in targets:
                raise InventoryImportError("Wi-Fi inventory contains duplicate BSSIDs.")
            targets.add(bssid)
            access_points.append(
                WifiAccessPoint(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    rssi_dbm=rssi,
                    security=security,
                    observed_at_utc=_parse_utc(
                        device["observed_at_utc"], "Wi-Fi observed_at_utc"
                    ),
                )
            )

        authorization = self._parse_authorization(
            document["authorization"],
            targets=targets,
        )
        return WifiInventory(authorization, tuple(access_points))


class BluetoothGattInventoryAdapter(_AuthorizedInventoryImporter):
    """Import read-only GATT structure from a consented local JSON file.

    Characteristic values and descriptors are intentionally not accepted.
    """

    ACTIVITY = "ble_gatt_inventory_readonly"

    def import_file(self, source: str | Path) -> BleGattInventory:
        document = self._read_document(source)
        if document["schema_version"] != 1:
            raise InventoryImportError("Unsupported BLE inventory schema_version.")
        raw_devices = document["devices"]
        if (
            not isinstance(raw_devices, list)
            or not raw_devices
            or len(raw_devices) > _MAX_DEVICES
        ):
            raise InventoryImportError("BLE devices must be a non-empty bounded array.")

        devices: list[BleDevice] = []
        targets: set[str] = set()
        for raw_device in raw_devices:
            device = _require_object(
                raw_device,
                required_keys=frozenset(
                    {"address", "name", "observed_at_utc", "services"}
                ),
                context="BLE device",
            )
            address = _normalize_mac(device["address"], "BLE address")
            name = _require_string(device["name"], "BLE device name", max_length=128)
            if address in targets:
                raise InventoryImportError("BLE inventory contains duplicate addresses.")
            targets.add(address)
            raw_services = device["services"]
            if (
                not isinstance(raw_services, list)
                or not raw_services
                or len(raw_services) > _MAX_SERVICES_PER_DEVICE
            ):
                raise InventoryImportError(
                    "GATT services must be a non-empty bounded array."
                )
            services: list[GattService] = []
            seen_service_uuids: set[str] = set()
            for raw_service in raw_services:
                service = _require_object(
                    raw_service,
                    required_keys=frozenset({"uuid", "characteristics"}),
                    context="GATT service",
                )
                service_uuid = _normalize_gatt_uuid(service["uuid"], "Service UUID")
                if service_uuid in seen_service_uuids:
                    raise InventoryImportError("GATT service UUID is duplicated.")
                seen_service_uuids.add(service_uuid)
                raw_characteristics = service["characteristics"]
                if (
                    not isinstance(raw_characteristics, list)
                    or len(raw_characteristics) > _MAX_CHARACTERISTICS_PER_SERVICE
                ):
                    raise InventoryImportError(
                        "GATT characteristics must be a bounded array."
                    )
                characteristics: list[GattCharacteristic] = []
                seen_characteristic_uuids: set[str] = set()
                for raw_characteristic in raw_characteristics:
                    characteristic = _require_object(
                        raw_characteristic,
                        required_keys=frozenset({"uuid", "properties"}),
                        context="GATT characteristic",
                    )
                    characteristic_uuid = _normalize_gatt_uuid(
                        characteristic["uuid"], "Characteristic UUID"
                    )
                    if characteristic_uuid in seen_characteristic_uuids:
                        raise InventoryImportError(
                            "GATT characteristic UUID is duplicated."
                        )
                    seen_characteristic_uuids.add(characteristic_uuid)
                    raw_properties = characteristic["properties"]
                    if (
                        not isinstance(raw_properties, list)
                        or not raw_properties
                        or any(
                            not isinstance(prop, str)
                            or prop not in _GATT_INVENTORY_PROPERTIES
                            for prop in raw_properties
                        )
                        or len(set(raw_properties)) != len(raw_properties)
                    ):
                        raise InventoryImportError(
                            "GATT properties must be unique read-only inventory properties."
                        )
                    characteristics.append(
                        GattCharacteristic(
                            uuid=characteristic_uuid,
                            properties=tuple(sorted(raw_properties)),
                        )
                    )
                services.append(
                    GattService(
                        uuid=service_uuid,
                        characteristics=tuple(characteristics),
                    )
                )
            devices.append(
                BleDevice(
                    address=address,
                    name=name,
                    observed_at_utc=_parse_utc(
                        device["observed_at_utc"], "BLE observed_at_utc"
                    ),
                    services=tuple(services),
                )
            )

        authorization = self._parse_authorization(
            document["authorization"],
            targets=targets,
        )
        return BleGattInventory(authorization, tuple(devices))
