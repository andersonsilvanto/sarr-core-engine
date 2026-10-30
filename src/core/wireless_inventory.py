"""Passive inventories for explicitly authorized Wi-Fi and BLE targets.

Both adapters import consented local JSON files. ``WifiInventoryAdapter`` can
also read the operating system's cached Wi-Fi listing (``nmcli --rescan no`` or
``netsh wlan show networks``). It never requests a rescan, enables monitor
mode, associates, deauthenticates, injects, or transmits. The BLE adapter does
not enumerate radios or read live GATT characteristics.
"""

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping, Sequence
from uuid import UUID

from core.events import Event, EventBus
from core.redaction import sanitize_text
from core.scope_validator import ScopeValidationError

if TYPE_CHECKING:
    from core.orchestrator import CoreOrchestrator


_MAC_ADDRESS = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_WIFI_SECURITY = {"open", "wep", "wpa2", "wpa3", "unknown"}
_GATT_INVENTORY_PROPERTIES = {"read", "notify", "indicate"}
_MAX_INVENTORY_BYTES = 1_048_576
_MAX_DEVICES = 1_000
_MAX_SERVICES_PER_DEVICE = 64
_MAX_CHARACTERISTICS_PER_SERVICE = 128
_OS_COMMAND_TIMEOUT_SECONDS = 15
_NMCLI_COMMAND = (
    "nmcli",
    "--terse",
    "--escape",
    "yes",
    "--fields",
    "BSSID,SSID,CHAN,SIGNAL,SECURITY",
    "device",
    "wifi",
    "list",
    "--rescan",
    "no",
)
_NETSH_COMMAND = ("netsh", "wlan", "show", "networks", "mode=bssid")
_NETSH_SSID_LINE = re.compile(r"^SSID\s+\d+\s*:\s?(.*)$")
_NETSH_BSSID_LINE = re.compile(r"^\s+BSSID\s+\d+\s*:\s*(\S+)\s*$")
_NETSH_FIELD_LINE = re.compile(r"^\s+([^:]+?)\s*:\s*(.*?)\s*$")

WIFI_INVENTORY_EVENT = "network.wifi.inventory_collected"

CommandRunner = Callable[[Sequence[str]], str]


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
        now = self._now()
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

    def _now(self) -> datetime:
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            raise ValueError("clock must return a timezone-aware UTC datetime.")
        return now.astimezone(timezone.utc)

    def assert_authorization_current(
        self, authorization: InventoryAuthorization | None
    ) -> InventoryAuthorization:
        """Re-check an already loaded authorization record at time of use."""
        if not isinstance(authorization, InventoryAuthorization):
            raise InventoryImportError(
                "A loaded authorization record is required before collection."
            )
        if authorization.activity != self.ACTIVITY:
            raise InventoryImportError(
                "Authorization does not permit this passive inventory activity."
            )
        if (
            not isinstance(authorization.allowed_targets, frozenset)
            or not authorization.allowed_targets
        ):
            raise InventoryImportError(
                "Authorization allowed_targets must be a non-empty allowlist."
            )
        if not (
            authorization.valid_from_utc
            <= self._now()
            <= authorization.valid_until_utc
        ):
            raise InventoryImportError("Authorization is not currently valid.")
        return authorization


class WifiInventoryAdapter(_AuthorizedInventoryImporter):
    """Passive 802.11 inventory from a consented JSON file or the OS cache."""

    ACTIVITY = "wifi_passive_inventory"

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        command_runner: CommandRunner | None = None,
        platform: str | None = None,
    ) -> None:
        super().__init__(clock=clock)
        self._command_runner = command_runner or _run_os_command
        self._platform = platform or sys.platform

    def collect_from_os(self, authorization: InventoryAuthorization) -> WifiInventory:
        """Read the OS cached Wi-Fi listing, keeping only allowlisted BSSIDs.

        Produces the same ``WifiInventory`` structure as ``import_file``.
        Observations outside the authorization allowlist, and hidden SSIDs,
        are dropped before any record is built.
        """
        inventory, _ = self._collect_from_os(authorization)
        return inventory

    def _collect_from_os(
        self, authorization: InventoryAuthorization
    ) -> tuple[WifiInventory, int]:
        self.assert_authorization_current(authorization)
        if self._platform.startswith("linux"):
            observations = _parse_nmcli_output(self._command_runner(_NMCLI_COMMAND))
        elif self._platform == "win32":
            observations = _parse_netsh_output(self._command_runner(_NETSH_COMMAND))
        else:
            raise LocalAdapterUnavailableError(
                f"Passive Wi-Fi listing is not supported on {self._platform!r}."
            )
        observed_at = self._now()
        selected: dict[str, WifiAccessPoint] = {}
        discarded = 0
        for raw_bssid, raw_ssid, raw_channel, raw_signal, raw_security in observations:
            bssid = raw_bssid.strip().lower()
            if (
                not _MAC_ADDRESS.fullmatch(bssid)
                or bssid not in authorization.allowed_targets
                or not raw_ssid.strip()
            ):
                discarded += 1
                continue
            access_point = WifiAccessPoint(
                bssid=bssid,
                ssid=_require_string(raw_ssid, "SSID", max_length=32),
                channel=_parse_os_channel(raw_channel),
                rssi_dbm=_signal_percent_to_dbm(raw_signal),
                security=_classify_os_security(raw_security),
                observed_at_utc=observed_at,
            )
            current = selected.get(bssid)
            if current is None or access_point.rssi_dbm > current.rssi_dbm:
                selected[bssid] = access_point
        self.assert_authorization_current(authorization)
        access_points = tuple(selected[bssid] for bssid in sorted(selected))
        return WifiInventory(authorization, access_points), discarded

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

    def collect_from_os(self) -> None:
        """Explicitly unsupported: this importer never probes local radios."""
        raise LocalAdapterUnavailableError(
            "OS radio enumeration is not implemented. Import an authorized "
            "local inventory file instead."
        )

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


def _run_os_command(command: Sequence[str]) -> str:
    executable = shutil.which(command[0])
    if executable is None:
        raise LocalAdapterUnavailableError(
            f"{command[0]} is not available for passive Wi-Fi listing."
        )
    try:
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            capture_output=True,
            timeout=_OS_COMMAND_TIMEOUT_SECONDS,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LocalAdapterUnavailableError(
            f"{command[0]} could not complete the passive Wi-Fi listing."
        ) from error
    if result.returncode != 0:
        raise LocalAdapterUnavailableError(
            f"{command[0]} exited with status {result.returncode}."
        )
    if len(result.stdout) > _MAX_INVENTORY_BYTES:
        raise InventoryImportError("OS Wi-Fi listing exceeds the 1 MiB limit.")
    return result.stdout.decode("utf-8", errors="replace")


def _split_nmcli_terse(line: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    fields.append("".join(current))
    return fields


def _parse_nmcli_output(output: str) -> list[tuple[str, str, str, str, str]]:
    observations: list[tuple[str, str, str, str, str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = _split_nmcli_terse(line)
        if len(fields) != 5:
            raise InventoryImportError("Unexpected nmcli Wi-Fi listing format.")
        observations.append((fields[0], fields[1], fields[2], fields[3], fields[4]))
        if len(observations) > _MAX_DEVICES:
            raise InventoryImportError("OS Wi-Fi listing exceeds the device limit.")
    return observations


def _parse_netsh_output(output: str) -> list[tuple[str, str, str, str, str]]:
    observations: list[tuple[str, str, str, str, str]] = []
    ssid = ""
    security_parts: list[str] = []
    bssid_record: dict[str, str] | None = None

    def flush() -> None:
        nonlocal bssid_record
        if bssid_record is not None:
            observations.append(
                (
                    bssid_record["bssid"],
                    ssid,
                    bssid_record.get("channel", ""),
                    bssid_record.get("signal", ""),
                    " ".join(security_parts),
                )
            )
            if len(observations) > _MAX_DEVICES:
                raise InventoryImportError("OS Wi-Fi listing exceeds the device limit.")
        bssid_record = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip("\r")
        ssid_match = _NETSH_SSID_LINE.match(line)
        if ssid_match:
            flush()
            ssid = ssid_match.group(1).strip()
            security_parts = []
            continue
        bssid_match = _NETSH_BSSID_LINE.match(line)
        if bssid_match:
            flush()
            bssid_record = {"bssid": bssid_match.group(1)}
            continue
        field_match = _NETSH_FIELD_LINE.match(line)
        if not field_match:
            continue
        key = field_match.group(1).strip().lower()
        value = field_match.group(2)
        if bssid_record is not None:
            if key in {"signal", "sinal"}:
                bssid_record["signal"] = value.rstrip("%").strip()
            elif key in {"channel", "canal"}:
                bssid_record["channel"] = value
        elif key.startswith(("authentication", "autentica", "encryption", "criptografia")):
            security_parts.append(value)
    flush()
    return observations


def _parse_os_channel(value: str) -> int:
    try:
        channel = int(value.strip())
    except ValueError as error:
        raise InventoryImportError(
            "Wi-Fi channel must be an integer from 1 to 233."
        ) from error
    if not 1 <= channel <= 233:
        raise InventoryImportError("Wi-Fi channel must be an integer from 1 to 233.")
    return channel


def _signal_percent_to_dbm(value: str) -> int:
    """Estimate dBm from the 0-100 signal quality reported by nmcli/netsh."""
    try:
        percent = int(value.strip())
    except ValueError as error:
        raise InventoryImportError("Wi-Fi signal must be a 0-100 percentage.") from error
    if not 0 <= percent <= 100:
        raise InventoryImportError("Wi-Fi signal must be a 0-100 percentage.")
    return max(-127, min(0, round(percent / 2 - 100)))


def _classify_os_security(descriptor: str) -> str:
    text = descriptor.upper()
    if "WEP" in text:
        return "wep"
    if "WPA2" in text:
        return "wpa2"
    if "WPA3" in text or "SAE" in text or "OWE" in text:
        return "wpa3"
    stripped = text.strip()
    if not stripped or stripped == "--" or "OPEN" in text or "ABERT" in text:
        return "open"
    return "unknown"


def publish_wifi_inventory(
    event_bus: EventBus,
    run_id: UUID,
    inventory: WifiInventory,
    *,
    source: str,
    discarded_count: int = 0,
) -> Event:
    """Publish a Wi-Fi inventory on the EventBus, regardless of its origin."""
    if source not in {"os_passive", "file_import"}:
        raise ValueError("source must be 'os_passive' or 'file_import'.")
    authorization = inventory.authorization
    event = Event(
        run_id=run_id,
        name=WIFI_INVENTORY_EVENT,
        payload={
            "approval_reference": authorization.reference,
            "approved_by": authorization.approved_by,
            "activity": authorization.activity,
            "source": source,
            "rssi_estimated": source == "os_passive",
            "access_point_count": len(inventory.access_points),
            "discarded_count": discarded_count,
            "access_points": tuple(
                {
                    "bssid": access_point.bssid,
                    "ssid": access_point.ssid,
                    "channel": access_point.channel,
                    "rssi_dbm": access_point.rssi_dbm,
                    "security": access_point.security,
                    "observed_at_utc": access_point.observed_at_utc.isoformat().replace(
                        "+00:00", "Z"
                    ),
                }
                for access_point in inventory.access_points
            ),
        },
    )
    event_bus.publish(event)
    return event


def run_wifi_inventory_module(
    orchestrator: "CoreOrchestrator",
    run_id: UUID,
    authorization: InventoryAuthorization,
) -> WifiInventory:
    """Run the registered Wi-Fi adapter as a scope-gated module.

    The adapter must be registered in ``orchestrator.modules`` under
    ``WifiInventoryAdapter.ACTIVITY``; the same name must be authorized by the
    validated scope, and the authorization allowlist must be within the scope
    targets. ``record_module_execution`` enforces RUNNING, scope validity and
    the kill-switch before any OS command runs.
    """
    adapter = orchestrator.modules.get(WifiInventoryAdapter.ACTIVITY)
    if not isinstance(adapter, WifiInventoryAdapter):
        raise TypeError("Registered Wi-Fi module must be a WifiInventoryAdapter.")
    try:
        scope = orchestrator.get_validated_scope(run_id)
    except KeyError as error:
        raise ScopeValidationError(
            "Wi-Fi inventory requires a validated scope."
        ) from error
    adapter.assert_authorization_current(authorization)
    scope_targets = {target.lower() for target in scope.allowed_targets}
    if not authorization.allowed_targets <= scope_targets:
        raise ScopeValidationError(
            "Authorization allowlist exceeds the validated scope targets."
        )
    orchestrator.record_module_execution(run_id, WifiInventoryAdapter.ACTIVITY)
    with orchestrator.get_operational_limits(run_id).begin_operation():
        inventory, discarded_count = adapter._collect_from_os(authorization)
    orchestrator.kill_switch.assert_clear()
    publish_wifi_inventory(
        orchestrator.events,
        run_id,
        inventory,
        source="os_passive",
        discarded_count=discarded_count,
    )
    return inventory
