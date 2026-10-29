"""Composição dos serviços locais de orquestração."""

from datetime import datetime, timezone
from threading import RLock
from typing import Callable
from uuid import UUID

from core.audit import AuditPersistenceError, Persistence
from core.context import RunContext
from core.events import Event, EventBus
from core.kill_switch import KillSwitch, KillSwitchEvent
from core.operational_limits import (
    OperationalLimitEnforcer,
    OperationalLimitExceeded,
)
from core.registry import ModuleRegistry
from core.scope_validator import ScopeValidationError, ScopeValidator, ValidatedScope
from core.state_machine import InvalidTransitionError, RunState, RunStateMachine


class DuplicateRunError(ValueError):
    """Raised when a run ID is registered more than once."""


class CoreOrchestrator:
    def __init__(
        self,
        *,
        persistence: Persistence | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.events = EventBus()
        self.modules = ModuleRegistry()
        self.kill_switch = KillSwitch()
        self._runs: dict[UUID, RunStateMachine] = {}
        self._validated_scopes: dict[UUID, ValidatedScope] = {}
        self._operational_limits: dict[UUID, OperationalLimitEnforcer] = {}
        self._lock = RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.persistence = persistence
        self.kill_switch.subscribe(self._handle_kill_switch)
        if persistence is not None:
            persistence.attach(
                self.events,
                on_audit_failure=self._handle_audit_failure,
            )

    def create_run(self, mode: str) -> RunContext:
        return self.register_run(RunContext.create(mode))

    def register_run(self, context: RunContext) -> RunContext:
        self.kill_switch.assert_clear()
        if not isinstance(context, RunContext):
            raise TypeError("register_run exige um RunContext válido.")
        machine = RunStateMachine(context)
        with self._lock:
            if context.run_id in self._runs:
                raise DuplicateRunError(f"run_id já registrado: {context.run_id}.")
            self._runs[context.run_id] = machine
        self.events.publish(
            Event(
                run_id=context.run_id,
                name="run.created",
                payload={"mode": context.mode, "state": RunState.IDLE.value},
            )
        )
        return context

    def get_state(self, run_id: UUID) -> RunState:
        with self._lock:
            try:
                machine = self._runs[run_id]
            except KeyError as error:
                raise KeyError(f"Execução não registrada: {run_id}.") from error
            enforcer = self._operational_limits.get(run_id)
        if machine.state is RunState.RUNNING and enforcer is not None:
            try:
                enforcer.check_duration()
            except OperationalLimitExceeded:
                pass
        return machine.state

    def validate_scope(
        self,
        run_id: UUID,
        scope_path: str,
        *,
        engagement_id: str,
        environment: str,
        targets: tuple[str, ...] | list[str],
        modules: tuple[str, ...] | list[str],
        validator: ScopeValidator | None = None,
    ) -> ValidatedScope:
        self.kill_switch.assert_clear()
        with self._lock:
            machine = self._get_machine(run_id)
            if machine.state is not RunState.IDLE:
                raise InvalidTransitionError(
                    "O escopo só pode ser validado antes do início da execução."
                )
            previous = machine.state
            current = machine.transition(RunState.VALIDATING)
        self._publish_transition(run_id, previous, current)

        try:
            scope_validator = validator or ScopeValidator(
                kill_switch=self.kill_switch,
                clock=self._clock,
            )
            validated_scope = scope_validator.validate(
                scope_path,
                engagement_id=engagement_id,
                environment=environment,
                mode=machine.context.mode,
                targets=targets,
                modules=modules,
            )
        except ScopeValidationError as error:
            self.kill_switch.trigger(
                f"Falha na validação do escopo: {error}",
                reason_code="scope_validation_failed",
                run_id=run_id,
                blocked_run_id=run_id,
            )
            raise

        with self._lock:
            self.kill_switch.assert_clear()
            if machine.state is not RunState.VALIDATING:
                raise InvalidTransitionError(
                    "A execução foi interrompida durante a validação do escopo."
                )
            self._validated_scopes[run_id] = validated_scope
            self._operational_limits[run_id] = OperationalLimitEnforcer(
                run_id,
                validated_scope.limits,
                self.kill_switch,
                clock=self._clock,
                scope_valid_from_utc=validated_scope.valid_from_utc,
                scope_valid_until_utc=validated_scope.valid_until_utc,
            )
            previous = machine.state
            current = machine.transition(RunState.READY)
        self.events.publish(
            Event(
                run_id=run_id,
                name="scope.validated",
                payload={
                    "engagement_id": validated_scope.engagement_id,
                    "environment": validated_scope.environment,
                    "mode": validated_scope.mode,
                    "target_count": len(validated_scope.allowed_targets),
                    "module_count": len(validated_scope.allowed_modules),
                },
            )
        )
        self._publish_transition(run_id, previous, current)
        return validated_scope

    def get_operational_limits(self, run_id: UUID) -> OperationalLimitEnforcer:
        with self._lock:
            try:
                return self._operational_limits[run_id]
            except KeyError as error:
                raise KeyError(
                    f"Limites operacionais não configurados para execução: {run_id}."
                ) from error

    def get_validated_scope(self, run_id: UUID) -> ValidatedScope:
        with self._lock:
            try:
                return self._validated_scopes[run_id]
            except KeyError as error:
                raise KeyError(
                    f"Escopo não validado para execução: {run_id}."
                ) from error

    def get_run_context(self, run_id: UUID) -> RunContext:
        with self._lock:
            return self._get_machine(run_id).context

    def get_run_timestamps(
        self, run_id: UUID
    ) -> tuple[datetime | None, datetime | None]:
        with self._lock:
            machine = self._get_machine(run_id)
            return machine.started_at_utc, machine.ended_at_utc

    def record_module_execution(self, run_id: UUID, module_name: str) -> None:
        if not isinstance(module_name, str) or not module_name.strip():
            raise ValueError("module_name deve ser uma string não vazia.")
        name = module_name.strip()
        with self._lock:
            machine = self._get_machine(run_id)
            if machine.state is not RunState.RUNNING:
                raise InvalidTransitionError(
                    "Módulos só podem ser registrados durante uma execução RUNNING."
                )
            scope = self._validated_scopes.get(run_id)
            if scope is None or name not in scope.allowed_modules:
                raise ScopeValidationError(
                    "Módulo executado não autorizado pelo escopo validado."
                )
            enforcer = self._operational_limits[run_id]
        enforcer.check_duration()
        with self._lock:
            if machine.state is not RunState.RUNNING:
                raise InvalidTransitionError(
                    "A execução foi interrompida antes do registro do módulo."
                )
            self.kill_switch.assert_clear()
        self.events.publish(
            Event(
                run_id=run_id,
                name="module.executed",
                payload={"module": name},
            )
        )

    def transition(self, run_id: UUID, target: RunState) -> RunState:
        with self._lock:
            machine = self._get_machine(run_id)
            if target in (RunState.READY, RunState.RUNNING):
                if run_id not in self._validated_scopes:
                    self.kill_switch.trigger(
                        "Execução solicitada sem escopo validado.",
                        reason_code="scope_missing",
                        run_id=run_id,
                        blocked_run_id=run_id,
                    )
                    raise ScopeValidationError(
                        "A execução está bloqueada até a validação de um escopo válido."
                    )
                self.kill_switch.assert_clear()
            previous = machine.state
            current = machine.transition(target)
            if target is RunState.RUNNING:
                self._operational_limits[run_id].start()
        self._publish_transition(run_id, previous, current)
        if current is RunState.RUNNING:
            machine_context = machine.context
            validated_scope = self._validated_scopes[run_id]
            self.events.publish(
                Event(
                    run_id=run_id,
                    name="run.started",
                    payload={
                        "mode": machine_context.mode,
                        "environment": validated_scope.environment,
                        "engagement_id": validated_scope.engagement_id,
                    },
                )
            )
        elif current is RunState.STOPPED:
            self.events.publish(
                Event(
                    run_id=run_id,
                    name="run.stopped",
                    payload={"reason_code": "requested"},
                )
            )
        return current

    def _get_machine(self, run_id: UUID) -> RunStateMachine:
        try:
            return self._runs[run_id]
        except KeyError as error:
            raise KeyError(f"Execução não registrada: {run_id}.") from error

    def _publish_transition(
        self, run_id: UUID, previous: RunState, current: RunState
    ) -> None:
        self.events.publish(
            Event(
                run_id=run_id,
                name="run.state_changed",
                payload={"from": previous.value, "to": current.value},
            )
        )

    def _handle_kill_switch(self, event: KillSwitchEvent) -> None:
        transitions: list[tuple[UUID, RunState, RunState]] = []
        with self._lock:
            for run_id, machine in self._runs.items():
                state = machine.state
                if run_id == event.blocked_run_id and state in (
                    RunState.IDLE,
                    RunState.VALIDATING,
                    RunState.READY,
                    RunState.RUNNING,
                ):
                    previous = state
                    if state is RunState.IDLE:
                        machine.transition(RunState.VALIDATING)
                        transitions.append((run_id, state, RunState.VALIDATING))
                        previous = RunState.VALIDATING
                    current = machine.transition(RunState.BLOCKED)
                    transitions.append((run_id, previous, current))
                elif state in (
                    RunState.VALIDATING,
                    RunState.READY,
                    RunState.RUNNING,
                    RunState.BLOCKED,
                ):
                    previous = state
                    machine.transition(RunState.STOPPING)
                    current = machine.transition(RunState.STOPPED)
                    transitions.append((run_id, previous, current))
                elif state is RunState.STOPPING:
                    current = machine.transition(RunState.STOPPED)
                    transitions.append((run_id, state, current))
        self.events.publish(
            Event(
                run_id=event.run_id or event.blocked_run_id,
                name="safety.triggered",
                payload={"reason_code": event.reason_code},
            )
        )
        for run_id, previous, current in transitions:
            self._publish_transition(run_id, previous, current)
            if current is RunState.STOPPED:
                self.events.publish(
                    Event(
                        run_id=run_id,
                        name="run.stopped",
                        payload={"reason_code": event.reason_code},
                    )
                )

    def _handle_audit_failure(
        self, event: Event, error: AuditPersistenceError
    ) -> None:
        self.kill_switch.trigger(
            "Audit persistence failed.",
            reason_code="audit_failure",
            run_id=event.run_id,
            blocked_run_id=event.run_id,
        )
