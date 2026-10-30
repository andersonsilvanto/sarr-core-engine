"""Dry-run and explicitly enabled IP mitigation backends."""

import ipaddress
import importlib
import logging
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from threading import RLock, Timer
from typing import Protocol, cast

from core.models import SecurityEvent
from core.network.config import DetectionConfig


_LOGGER = logging.getLogger(__name__)
_CHAIN_NAME = "SARR_BLOCK"
_LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class MitigationError(RuntimeError):
    """Raised when a mitigation backend cannot complete an operation."""


class Mitigator(Protocol):
    def block(self, ip: str, ttl_s: int) -> bool: ...

    def unblock(self, ip: str) -> bool: ...

    def list_blocked(self) -> list[str]: ...

    def is_failclosed_active(self) -> bool: ...


class FailClosedPolicy:
    """Track a fail-closed transition, with external actions opt-in."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        on_activate: Callable[[str], None] | None = None,
        on_clear: Callable[[], None] | None = None,
    ) -> None:
        if not isinstance(dry_run, bool):
            raise TypeError("dry_run must be a boolean.")
        if (on_activate is None) != (on_clear is None):
            raise ValueError("Both fail-closed callbacks must be provided together.")
        if not dry_run and on_activate is None:
            raise ValueError(
                "A non-dry-run fail-closed policy requires explicit callbacks."
            )
        self._dry_run = dry_run
        self._on_activate = on_activate
        self._on_clear = on_clear
        self._active = False
        self._lock = RLock()

    @property
    def active(self) -> bool:
        with self._lock:
            return self._active

    def engage(self, reason: str) -> bool:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Fail-closed reason must be a non-empty string.")
        with self._lock:
            if self._active:
                return False
            if not self._dry_run:
                callback = self._on_activate
                if callback is None:
                    raise MitigationError("Fail-closed activation is not configured.")
                callback(reason.strip())
            self._active = True
            return True

    def clear(self) -> bool:
        with self._lock:
            if not self._active:
                return False
            if not self._dry_run:
                callback = self._on_clear
                if callback is None:
                    raise MitigationError("Fail-closed rollback is not configured.")
                callback()
            self._active = False
            return True


@dataclass(frozen=True)
class _BlockEntry:
    timer: Timer


class _TimedMitigator:
    def __init__(
        self,
        config: DetectionConfig | None = None,
        *,
        protected_ips: Iterable[str] = (),
        failclosed_policy: FailClosedPolicy | None = None,
    ) -> None:
        self._config = config or DetectionConfig.from_json_file()
        if not isinstance(self._config, DetectionConfig):
            raise TypeError("config must be a DetectionConfig.")
        protected = tuple(protected_ips)
        self._allowlist = tuple(
            ipaddress.ip_network(value, strict=False)
            for value in (*self._config.allowlist, *protected)
        )
        self._failclosed_policy = failclosed_policy or FailClosedPolicy()
        if not isinstance(self._failclosed_policy, FailClosedPolicy):
            raise TypeError("failclosed_policy must be a FailClosedPolicy.")
        self._blocked: dict[str, _BlockEntry] = {}
        self._closed = False
        self._lock = RLock()

    def block(self, ip: str, ttl_s: int) -> bool:
        normalized_ip = self._normalize_ip(ip)
        if isinstance(ttl_s, bool) or not isinstance(ttl_s, int) or ttl_s <= 0:
            raise ValueError("ttl_s must be a positive integer.")
        with self._lock:
            if self._closed:
                raise MitigationError("Mitigator is closed.")
            if self._is_allowlisted(normalized_ip):
                return False
            if normalized_ip in self._blocked:
                return True
            if len(self._blocked) >= self._config.max_blocked_ips:
                return False
            if not self._apply_block(normalized_ip):
                return False
            timer = Timer(ttl_s, self._expire, args=(normalized_ip,))
            timer.daemon = True
            try:
                timer.start()
            except RuntimeError:
                self._apply_unblock(normalized_ip)
                raise
            self._blocked[normalized_ip] = _BlockEntry(timer=timer)
            return True

    def block_event(self, event: SecurityEvent, ttl_s: int) -> bool:
        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")
        if event.src_ip is None:
            return False
        return self.block(event.src_ip, ttl_s)

    def unblock(self, ip: str) -> bool:
        normalized_ip = self._normalize_ip(ip)
        with self._lock:
            entry = self._blocked.get(normalized_ip)
            if entry is None:
                return True
            if not self._apply_unblock(normalized_ip):
                return False
            del self._blocked[normalized_ip]
            entry.timer.cancel()
            return True

    def list_blocked(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked)

    def is_failclosed_active(self) -> bool:
        return self._failclosed_policy.active

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            failures: list[str] = []
            for ip, entry in tuple(self._blocked.items()):
                try:
                    if self._apply_unblock(ip):
                        del self._blocked[ip]
                        entry.timer.cancel()
                    else:
                        failures.append(ip)
                except MitigationError as error:
                    failures.append(f"{ip}: {error}")
            try:
                self._close_backend()
            except MitigationError as error:
                failures.append(str(error))
            if failures:
                raise MitigationError(
                    "Mitigator shutdown rollback failed: " + "; ".join(failures)
                )
            self._closed = True

    def __enter__(self) -> "_TimedMitigator":
        return self

    def __exit__(
        self,
        _exc_type: object,
        _exc: object,
        _traceback: object,
    ) -> bool:
        self.close()
        return False

    def _expire(self, ip: str) -> None:
        try:
            self.unblock(ip)
        except MitigationError:
            _LOGGER.exception("Automatic IP unblock failed for %s", ip)

    def _is_allowlisted(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return any(
            address.version == network.version and address in network
            for network in (*_LOOPBACK_NETWORKS, *self._allowlist)
        )

    @staticmethod
    def _normalize_ip(value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("ip must be a valid IP address.")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("ip must be a valid IP address.") from error

    def _apply_block(self, ip: str) -> bool:
        raise NotImplementedError

    def _apply_unblock(self, ip: str) -> bool:
        raise NotImplementedError

    def _close_backend(self) -> None:
        return None


class DryRunMitigator(_TimedMitigator):
    """Track blocked IPs in memory without changing host or container state."""

    def _apply_block(self, ip: str) -> bool:
        return True

    def _apply_unblock(self, ip: str) -> bool:
        return True


class IptablesMitigator(_TimedMitigator):
    """Manage source-IP DROP rules in the dedicated SARR_BLOCK chain."""

    def __init__(
        self,
        config: DetectionConfig | None = None,
        *,
        protected_ips: Iterable[str],
        iptables_executable: str = "iptables",
        ip6tables_executable: str = "ip6tables",
        failclosed_policy: FailClosedPolicy | None = None,
    ) -> None:
        protected = tuple(protected_ips)
        if not protected:
            raise ValueError(
                "Explicit gateway, host, and management IPs are required."
            )
        super().__init__(
            config,
            protected_ips=protected,
            failclosed_policy=failclosed_policy,
        )
        if not iptables_executable or not ip6tables_executable:
            raise ValueError("iptables executable names must be non-empty.")
        self._executables = {
            4: iptables_executable,
            6: ip6tables_executable,
        }
        self._created_chains: set[int] = set()
        self._created_jumps: set[int] = set()

    def _apply_block(self, ip: str) -> bool:
        family = ipaddress.ip_address(ip).version
        executable = self._executables[family]
        self._ensure_chain(executable, family)
        rule = ["-s", ip, "-j", "DROP"]
        check = self._run(executable, ["-C", _CHAIN_NAME, *rule])
        if check.returncode == 0:
            return True
        if check.returncode != 1:
            raise MitigationError("Could not inspect the SARR_BLOCK rule.")
        result = self._run(executable, ["-I", _CHAIN_NAME, "1", *rule])
        if result.returncode != 0:
            raise MitigationError("Could not add the SARR_BLOCK IP rule.")
        return True

    def _apply_unblock(self, ip: str) -> bool:
        family = ipaddress.ip_address(ip).version
        executable = self._executables[family]
        rule = ["-s", ip, "-j", "DROP"]
        check = self._run(executable, ["-C", _CHAIN_NAME, *rule])
        if check.returncode == 1:
            return True
        if check.returncode != 0:
            raise MitigationError("Could not inspect the SARR_BLOCK rule.")
        result = self._run(executable, ["-D", _CHAIN_NAME, *rule])
        if result.returncode != 0:
            raise MitigationError("Could not remove the SARR_BLOCK IP rule.")
        return True

    def _ensure_chain(self, executable: str, family: int) -> None:
        chain = self._run(executable, ["-S", _CHAIN_NAME])
        if chain.returncode != 0:
            created = self._run(executable, ["-N", _CHAIN_NAME])
            if created.returncode != 0:
                raise MitigationError("Could not create the SARR_BLOCK chain.")
            self._created_chains.add(family)

        check_jump = self._run(
            executable,
            ["-C", "INPUT", "-j", _CHAIN_NAME],
        )
        if check_jump.returncode == 0:
            return
        if check_jump.returncode != 1:
            raise MitigationError("Could not inspect the SARR_BLOCK chain hook.")
        inserted = self._run(
            executable,
            ["-I", "INPUT", "1", "-j", _CHAIN_NAME],
        )
        if inserted.returncode != 0:
            raise MitigationError("Could not attach the SARR_BLOCK chain.")
        self._created_jumps.add(family)

    def _close_backend(self) -> None:
        failures: list[str] = []
        for family in tuple(self._created_jumps):
            executable = self._executables[family]
            result = self._run(executable, ["-D", "INPUT", "-j", _CHAIN_NAME])
            if result.returncode != 0:
                failures.append(f"IPv{family} chain hook")
            else:
                self._created_jumps.remove(family)
        for family in tuple(self._created_chains):
            executable = self._executables[family]
            result = self._run(executable, ["-X", _CHAIN_NAME])
            if result.returncode != 0:
                failures.append(f"IPv{family} chain")
            else:
                self._created_chains.remove(family)
        if failures:
            raise MitigationError(
                "Could not remove created firewall resources: "
                + ", ".join(failures)
            )

    @staticmethod
    def _run(executable: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [executable, *arguments],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise MitigationError("Firewall command could not be completed.") from error


class _DockerContainer(Protocol):
    @property
    def attrs(self) -> dict[str, object]: ...

    def reload(self) -> None: ...


class _DockerNetwork(Protocol):
    def disconnect(self, container: _DockerContainer) -> object: ...

    def connect(self, container: _DockerContainer, **kwargs: object) -> object: ...


class _DockerContainerCollection(Protocol):
    def list(self) -> list[_DockerContainer]: ...


class _DockerNetworkCollection(Protocol):
    def get(self, network_name: str) -> _DockerNetwork: ...


class _DockerClient(Protocol):
    containers: _DockerContainerCollection
    networks: _DockerNetworkCollection


class _DockerSDKErrors(Protocol):
    DockerException: type[BaseException]


class _DockerSDK(Protocol):
    errors: _DockerSDKErrors

    def from_env(self) -> _DockerClient: ...


class DockerMitigator(_TimedMitigator):
    """Disconnect a matching container from one explicitly selected network."""

    def __init__(
        self,
        network_name: str,
        *,
        protected_ips: Iterable[str],
        config: DetectionConfig | None = None,
        client: _DockerClient | None = None,
        failclosed_policy: FailClosedPolicy | None = None,
    ) -> None:
        if not isinstance(network_name, str) or not network_name.strip():
            raise ValueError("network_name must be a non-empty Docker network name.")
        protected = tuple(protected_ips)
        if not protected:
            raise ValueError(
                "Explicit gateway, host, and management IPs are required."
            )
        docker_errors: tuple[type[BaseException], ...] = ()
        if client is None:
            try:
                sdk = importlib.import_module("docker")
            except ImportError as error:
                raise MitigationError(
                    "Install the Docker SDK or inject an initialized Docker client."
                ) from error
            docker_sdk = cast(_DockerSDK, sdk)
            client = docker_sdk.from_env()
            docker_errors = (docker_sdk.errors.DockerException,)
        super().__init__(
            config,
            protected_ips=protected,
            failclosed_policy=failclosed_policy,
        )
        self._client = client
        self._network_name = network_name.strip()
        self._docker_errors = docker_errors
        self._network: _DockerNetwork
        try:
            self._network = client.networks.get(self._network_name)
        except self._docker_errors as error:
            raise MitigationError("Could not access the selected Docker network.") from error
        self._detached: dict[
            str,
            tuple[_DockerContainer, dict[str, object]],
        ] = {}

    def _apply_block(self, ip: str) -> bool:
        if ip in self._detached:
            return True
        matches: list[tuple[_DockerContainer, dict[str, object]]] = []
        try:
            containers = self._client.containers.list()
            for container in containers:
                container.reload()
                network_settings = container.attrs.get("NetworkSettings")
                if not isinstance(network_settings, dict):
                    continue
                networks = network_settings.get("Networks")
                if not isinstance(networks, dict):
                    continue
                network_data = networks.get(self._network_name)
                if not isinstance(network_data, dict):
                    continue
                address = network_data.get("IPAddress") or network_data.get(
                    "GlobalIPv6Address"
                )
                if address == ip:
                    matches.append((container, network_data))
        except self._docker_errors as error:
            raise MitigationError("Could not inspect Docker containers.") from error
        if not matches:
            return False
        if len(matches) != 1:
            raise MitigationError("The IP matches multiple Docker containers.")
        container, network_data = matches[0]
        try:
            self._network.disconnect(container)
        except self._docker_errors as error:
            raise MitigationError("Could not isolate the Docker container.") from error
        self._detached[ip] = (container, dict(network_data))
        return True

    def _apply_unblock(self, ip: str) -> bool:
        detached = self._detached.get(ip)
        if detached is None:
            return True
        container, network_data = detached
        kwargs: dict[str, object] = {}
        for field_name in ("IPAddress", "GlobalIPv6Address"):
            field_value = network_data.get(field_name)
            if field_value:
                argument = (
                    "ipv4_address"
                    if field_name == "IPAddress"
                    else "ipv6_address"
                )
                kwargs[argument] = field_value
        aliases = network_data.get("Aliases")
        if isinstance(aliases, list):
            kwargs["aliases"] = aliases
        try:
            self._network.connect(container, **kwargs)
        except self._docker_errors as error:
            raise MitigationError("Could not restore the Docker network.") from error
        del self._detached[ip]
        return True


def create_mitigator(
    config: DetectionConfig | None = None,
) -> Mitigator:
    """Return the safe default backend without changing host networking."""
    return DryRunMitigator(config)


__all__ = [
    "DockerMitigator",
    "DryRunMitigator",
    "FailClosedPolicy",
    "IptablesMitigator",
    "MitigationError",
    "Mitigator",
    "TrackingCapacityError",
    "create_mitigator",
]
