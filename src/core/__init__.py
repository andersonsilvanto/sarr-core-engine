"""Núcleo local de orquestração do SARR-Core Engine."""

from core.context import RunContext
from core.events import DuplicateEventError, Event, EventBus
from core.database import Database
from core.kill_switch import KillSwitch, KillSwitchTriggered
from core.operational_limits import OperationalLimitEnforcer, OperationalLimitExceeded
from core.orchestrator import CoreOrchestrator, DuplicateRunError
from core.registry import ModuleRegistry
from core.audit import AuditPersistenceError, AuditTrail, Persistence
from core.repositories import (
    ApprovalRepository,
    EventRepository,
    FindingRepository,
    MetricRepository,
    RunRepository,
)
from core.report_service import AuditReportService, ReportGenerationError
from core.paths import (
    DataDirectoryError,
    application_directory,
    default_user_data_directory,
    resolve_data_directory,
)
from core.demo_server import LocalDemoServer
from core.resilience import (
    CircuitOpenError,
    CircuitState,
    LocalTelemetryProbe,
    SafetyCircuitBreaker,
    TelemetryUnavailable,
)
from core.scope_validator import ScopeLimits, ScopeValidationError, ScopeValidator, ValidatedScope
from core.state_machine import (
    InvalidStateTransitionError,
    InvalidTransitionError,
    RunState,
    RunStateMachine,
)
from core.telemetry import TelemetrySample, TelemetryScenario, TelemetrySimulator
from core.wireless_inventory import (
    BleDevice,
    BleGattInventory,
    BluetoothGattInventoryAdapter,
    GattCharacteristic,
    GattService,
    InventoryAuthorization,
    InventoryImportError,
    LocalAdapterUnavailableError,
    WifiAccessPoint,
    WifiInventory,
    WifiInventoryAdapter,
)

__all__ = [
    "CoreOrchestrator",
    "CircuitOpenError",
    "CircuitState",
    "Database",
    "DataDirectoryError",
    "DuplicateRunError",
    "DuplicateEventError",
    "Event",
    "EventBus",
    "AuditTrail",
    "AuditPersistenceError",
    "AuditReportService",
    "BleDevice",
    "BleGattInventory",
    "BluetoothGattInventoryAdapter",
    "Persistence",
    "InvalidTransitionError",
    "InvalidStateTransitionError",
    "KillSwitch",
    "KillSwitchTriggered",
    "GattCharacteristic",
    "GattService",
    "InventoryAuthorization",
    "InventoryImportError",
    "LocalAdapterUnavailableError",
    "LocalDemoServer",
    "LocalTelemetryProbe",
    "ModuleRegistry",
    "OperationalLimitEnforcer",
    "OperationalLimitExceeded",
    "ApprovalRepository",
    "EventRepository",
    "FindingRepository",
    "MetricRepository",
    "RunRepository",
    "RunContext",
    "RunState",
    "RunStateMachine",
    "ReportGenerationError",
    "SafetyCircuitBreaker",
    "ScopeLimits",
    "ScopeValidationError",
    "ScopeValidator",
    "ValidatedScope",
    "WifiAccessPoint",
    "WifiInventory",
    "WifiInventoryAdapter",
    "application_directory",
    "default_user_data_directory",
    "resolve_data_directory",
    "TelemetrySample",
    "TelemetryScenario",
    "TelemetrySimulator",
    "TelemetryUnavailable",
]
