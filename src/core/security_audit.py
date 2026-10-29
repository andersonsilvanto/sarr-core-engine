"""Read-only, evidence-driven local security checks and audit events."""

import hashlib
import os
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from core.events import Event, EventBus
from core.kill_switch import KillSwitch


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BASE64_CANDIDATE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)
_SUSPICIOUS_COMMAND = re.compile(
    r"(?:-enc(?:odedcommand)?\b|\bpowershell(?:\.exe)?\b|"
    r"\bcmd(?:\.exe)?\s+/c\b|"
    r"\bbash\s+-c\b|\bpython(?:3)?\s+-c\b)",
    re.IGNORECASE,
)
_PERSISTENCE_MECHANISMS = {
    "scheduled_task": ("T1053.005", "Scheduled Task"),
    "autorun": ("T1547.001", "Registry Run Keys / Startup Folder"),
}
_CANARY_RELATIVE_PATH = "config/canary_credentials.json"


def _windows_path(path: str) -> str:
    return path.replace("/", "\\")


@dataclass(frozen=True)
class PortEvidence:
    host: str
    port: int
    service: str
    authorized: bool
    authentication: str = "unknown"

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Port evidence is restricted to 127.0.0.1.")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("Port must be an integer.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if not isinstance(self.service, str) or not self.service.strip():
            raise ValueError("Service must be a non-empty label.")
        if not isinstance(self.authorized, bool):
            raise TypeError("authorized must be a boolean.")
        if not isinstance(self.authentication, str) or self.authentication not in {
            "present",
            "absent",
            "unknown",
        }:
            raise ValueError("authentication must be present, absent, or unknown.")


@dataclass(frozen=True)
class GhostPortAttempt:
    host: str
    port: int
    method: str
    path: str
    signature_sha256: str

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Ghost-port evidence is restricted to 127.0.0.1.")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("Port must be an integer.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if not isinstance(self.method, str) or self.method not in {
            "GET",
            "HEAD",
            "OPTIONS",
            "POST",
        }:
            raise ValueError("Unsupported synthetic request method.")
        if not isinstance(self.path, str) or not re.fullmatch(
            r"/[A-Za-z0-9_./-]{0,100}", self.path
        ):
            raise ValueError("Request path must be a safe synthetic route.")
        if not isinstance(self.signature_sha256, str) or not _SHA256.fullmatch(
            self.signature_sha256
        ):
            raise ValueError("Request signature must be a lowercase SHA-256 digest.")


@dataclass(frozen=True)
class IntegrityEvidence:
    path: Path
    expected_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("Integrity evidence path must be a pathlib.Path.")
        if self.expected_sha256 is None:
            return
        if not isinstance(self.expected_sha256, str) or not _SHA256.fullmatch(
            self.expected_sha256
        ):
            raise ValueError("Integrity evidence requires lowercase SHA-256.")


@dataclass(frozen=True)
class PermissionEvidence:
    path: Path
    group_writable: bool
    world_writable: bool
    synthetic: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("Permission evidence path must be a pathlib.Path.")
        if not isinstance(self.group_writable, bool):
            raise TypeError("group_writable must be a boolean.")
        if not isinstance(self.world_writable, bool):
            raise TypeError("world_writable must be a boolean.")
        if not isinstance(self.synthetic, bool):
            raise TypeError("synthetic must be a boolean.")


@dataclass(frozen=True)
class PersistenceEvidence:
    mechanism: str
    name: str
    authorized: bool = False
    synthetic: bool = True

    def __post_init__(self) -> None:
        if (
            not isinstance(self.mechanism, str)
            or self.mechanism not in _PERSISTENCE_MECHANISMS
        ):
            raise ValueError("Unsupported synthetic persistence mechanism.")
        if not isinstance(self.name, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,80}", self.name
        ):
            raise ValueError("Persistence name must be a safe fixture identifier.")
        if not isinstance(self.authorized, bool):
            raise TypeError("authorized must be a boolean.")
        if self.synthetic is not True:
            raise ValueError("Persistence evidence must be explicitly synthetic.")


@dataclass(frozen=True)
class SecurityFinding:
    event_name: str
    severity: str
    summary: str
    evidence: dict[str, object]
    vetor_ataque: str
    remediacao: str
    mitre_id: str
    acao_bloqueio: str


class SecurityAudit:
    """Consumes explicitly supplied local evidence; never probes networks."""

    AUTH_FAILURE_THRESHOLD = 10

    def __init__(
        self,
        *,
        run_id: UUID,
        event_bus: EventBus,
        kill_switch: KillSwitch,
        project_root: Path,
    ) -> None:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        self._run_id = run_id
        self._event_bus = event_bus
        self._kill_switch = kill_switch
        self._project_root = project_root.resolve()

    def run(
        self,
        *,
        ports: tuple[PortEvidence, ...],
        integrity: tuple[IntegrityEvidence, ...],
        permission_paths: tuple[Path, ...],
        permission_fixtures: tuple[PermissionEvidence, ...] = (),
        simulated_auth_failures: int = 0,
        encoded_payload_samples: tuple[str, ...] = (),
        simulated_subprocess_commands: tuple[str, ...] = (),
        persistence_fixtures: tuple[PersistenceEvidence, ...] = (),
        canary_accessed: bool = False,
        ghost_port_attempts: tuple[GhostPortAttempt, ...] = (),
    ) -> tuple[SecurityFinding, ...]:
        findings: list[SecurityFinding] = []
        self._publish(
            "security.audit.started",
            {"port_evidence_count": len(ports), "integrity_check_count": len(integrity)},
        )

        if not isinstance(canary_accessed, bool):
            raise TypeError("canary_accessed must be a boolean.")
        if canary_accessed:
            findings.append(
                self.notify_canary_activity(
                    self._project_root / _CANARY_RELATIVE_PATH,
                    reason="accessed",
                    source="synthetic_simulation",
                )
            )

        for evidence in ports:
            if not isinstance(evidence, PortEvidence):
                raise TypeError("ports must contain PortEvidence records.")
            if evidence.authorized:
                self._publish(
                    "security.port.reviewed",
                    {
                        "host": evidence.host,
                        "port": evidence.port,
                        "service": evidence.service,
                    },
                )
                continue
            finding = self._finding(
                event_name="security.port.exposed",
                severity="critical",
                summary=(
                    f"Unapproved service {evidence.service!r} is listed on "
                    f"{evidence.host}:{evidence.port}"
                    + (
                        " without authentication."
                        if evidence.authentication == "absent"
                        else "."
                    )
                ),
                evidence={
                    "host": evidence.host,
                    "port": evidence.port,
                    "service": evidence.service,
                    "authentication": evidence.authentication,
                    "source": "synthetic_local_inventory",
                },
                vetor_ataque=(
                    (
                        "Um usuário local ou cliente com conectividade ao serviço "
                        "poderia acessar endpoints sem autenticação. Este cenário é "
                        "apenas inventário sintético e não executa requisições."
                    )
                    if evidence.authentication == "absent"
                    else (
                        "Um serviço listado sem autorização pode oferecer uma "
                        "superfície de ataque a clientes com conectividade; o método "
                        "de autenticação é desconhecido e nenhuma requisição é enviada."
                    )
                ),
                remediacao=(
                    "Windows PowerShell (Admin): "
                    f'New-NetFirewallRule -DisplayName "SARR-Core block TCP {evidence.port}" '
                    f"-Direction Inbound -Action Block -Protocol TCP -LocalPort {evidence.port}\n"
                    f"Linux com UFW: sudo ufw deny {evidence.port}/tcp\n"
                    "Depois, habilite autenticação e autorização no serviço antes de "
                    "reabrir a porta."
                ),
                mitre_id="T1046",
                acao_bloqueio=(
                    f"Manter a execução em BLOCKED e bloquear TCP/{evidence.port} até que o "
                    "serviço seja identificado, autorizado e protegido."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("unauthorized_local_service", finding.summary)

        for attempt in ghost_port_attempts:
            if not isinstance(attempt, GhostPortAttempt):
                raise TypeError(
                    "ghost_port_attempts must contain GhostPortAttempt records."
                )
            finding = self._finding(
                event_name="deception.ghost_port.engaged",
                severity="critical",
                summary="Synthetic request engaged an unauthorized ghost-port fixture.",
                evidence={
                    "host": attempt.host,
                    "port": attempt.port,
                    "method": attempt.method,
                    "path": attempt.path,
                    "request_signature_sha256": attempt.signature_sha256,
                    "source": "synthetic_local_fixture",
                },
                vetor_ataque=(
                    "O indicador representa uma tentativa simulada de acessar um "
                    "serviço-isca. Nenhuma porta foi aberta, pacote capturado ou "
                    "requisição recebida pela rede."
                ),
                remediacao=(
                    "Preserve o hash da assinatura sintética e revise inventários "
                    "autorizados do host. Não bloqueie endereços ou serviços reais "
                    "com base neste fixture."
                ),
                mitre_id="",
                acao_bloqueio=(
                    "Acionar o kill-switch e manter a execução em BLOCKED até a "
                    "revisão do evento."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("ghost_port_engaged", finding.summary)

        for evidence in integrity:
            if not isinstance(evidence, IntegrityEvidence):
                raise TypeError("integrity must contain IntegrityEvidence records.")
            if self._is_canary_path(evidence.path):
                if evidence.path.is_symlink():
                    findings.append(
                        self.notify_canary_activity(
                            evidence.path,
                            reason="modified",
                            source="local_file_audit",
                        )
                    )
                    continue
                try:
                    actual_sha256 = hashlib.sha256(
                        evidence.path.read_bytes()
                    ).hexdigest()
                except OSError:
                    findings.append(
                        self.notify_canary_activity(
                            evidence.path,
                            reason="modified",
                            source="local_file_audit",
                        )
                    )
                    continue
                if actual_sha256 != evidence.expected_sha256:
                    findings.append(
                        self.notify_canary_activity(
                            evidence.path,
                            reason="modified",
                            source="local_file_audit",
                        )
                    )
                    continue
            relative_path = self._project_relative_path(evidence.path)
            if evidence.expected_sha256 is None:
                finding = self._finding(
                    event_name="integrity.baseline.missing",
                    severity="critical",
                    summary=f"No reviewed SHA-256 baseline exists for {relative_path}.",
                    evidence={"path": relative_path},
                    vetor_ataque=(
                        "Sem uma baseline confiável, uma alteração no arquivo não "
                        "pode ser distinguida de seu estado aprovado."
                    ),
                    remediacao=(
                        f"Revise {relative_path} e registre seu SHA-256 em uma mudança "
                        "de baseline revisada por pares antes de executar novamente."
                    ),
                    mitre_id="T1565.001",
                    acao_bloqueio=(
                        "Manter a execução em BLOCKED até que uma baseline aprovada "
                        "seja fornecida."
                    ),
                )
                findings.append(finding)
                self._publish_finding(finding)
                self._trip("integrity_baseline_missing", finding.summary)
                continue
            try:
                actual_sha256 = hashlib.sha256(
                    evidence.path.resolve().read_bytes()
                ).hexdigest()
            except OSError as error:
                finding = SecurityFinding(
                    event_name="integrity.audit.failed",
                    severity="critical",
                    summary="Project file could not be read for integrity verification.",
                    evidence={
                        "path": relative_path,
                        "error_type": type(error).__name__,
                    },
                    vetor_ataque=(
                        "A indisponibilidade da leitura impede confirmar que o arquivo "
                        "permanece íntegro; não prova uma adulteração."
                    ),
                    remediacao=(
                        f"Verifique o acesso ao arquivo {relative_path!r}, restaure-o "
                        "a partir de uma distribuição confiável e repita a auditoria."
                    ),
                    mitre_id="T1565.001",
                    acao_bloqueio=(
                        "Manter o motor bloqueado até que a leitura e a validação de "
                        "integridade sejam concluídas."
                    ),
                )
                findings.append(finding)
                self._publish_finding(finding)
                self._trip("integrity_audit_failed", finding.summary)
                continue
            if actual_sha256 == evidence.expected_sha256:
                self._publish(
                    "integrity.hash.verified",
                    {
                        "path": relative_path,
                        "sha256": actual_sha256,
                    },
                )
                continue
            finding = SecurityFinding(
                event_name="integrity.hash.mismatch",
                severity="critical",
                summary="Project file hash differs from the supplied baseline.",
                evidence={
                    "path": relative_path,
                    "expected_sha256": evidence.expected_sha256,
                    "actual_sha256": actual_sha256,
                },
                vetor_ataque=(
                    "Uma alteração não autorizada no conteúdo pode modificar a "
                    "configuração ou o comportamento do sistema; a divergência do hash "
                    "não identifica por si só quem a causou."
                ),
                remediacao=(
                    f"Restaure {relative_path} de uma distribuição confiável. "
                    "Valide o arquivo restaurado antes de liberar a execução.\n"
                    f"Windows: Get-FileHash '{_windows_path(relative_path)}' -Algorithm SHA256\n"
                    f"Linux/macOS: sha256sum {shlex.quote(relative_path)}"
                ),
                mitre_id="T1565.001",
                acao_bloqueio=(
                    "Quarentenar o artefato divergente, preservar a evidência e manter "
                    "o motor em BLOCKED até a validação por uma fonte confiável."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("integrity_hash_mismatch", finding.summary)

        for evidence in permission_fixtures:
            if not isinstance(evidence, PermissionEvidence):
                raise TypeError(
                    "permission_fixtures must contain PermissionEvidence records."
                )
            if not evidence.synthetic:
                raise ValueError(
                    "permission_fixtures must be explicitly marked synthetic."
                )
            relative_path = self._project_relative_path(evidence.path)
            self._append_permission_result(
                findings,
                relative_path,
                evidence.group_writable,
                evidence.world_writable,
                synthetic=evidence.synthetic,
            )

        for path in permission_paths:
            relative_path = self._project_relative_path(path)
            if os.name == "nt":
                finding = self._finding(
                    event_name="security.permission.audit_unavailable",
                    severity="warning",
                    summary="Windows ACL permissions were not verified.",
                    evidence={"path": relative_path, "platform": "windows"},
                    vetor_ataque=(
                        "ACLs não verificadas significam que esta auditoria não pode "
                        "descartar permissões excessivas; nenhum abuso foi observado."
                    ),
                    remediacao=(
                        f"Inspecione as ACLs com: icacls.exe "
                        f"'{_windows_path(relative_path)}' /verify. "
                        "Revise os grupos com acesso de escrita antes de declarar o "
                        "arquivo seguro."
                    ),
                    mitre_id="",
                    acao_bloqueio=(
                        "Não marcar a postura como SECURE até a revisão manual das "
                        "ACLs do arquivo."
                    ),
                )
                findings.append(finding)
                self._publish_finding(finding)
                continue
            try:
                mode = path.resolve().stat().st_mode
            except OSError as error:
                finding = self._finding(
                    event_name="security.permission.audit_failed",
                    severity="critical",
                    summary="File permissions could not be inspected.",
                    evidence={
                        "path": relative_path,
                        "error_type": type(error).__name__,
                    },
                    vetor_ataque=(
                        "A falha de inspeção impede descartar escrita por usuários "
                        "não autorizados."
                    ),
                    remediacao=(
                        f"Restaure acesso de leitura controlado a {relative_path!r} e "
                        "execute novamente a auditoria de permissões."
                    ),
                    mitre_id="",
                    acao_bloqueio=(
                        "Manter o motor bloqueado até que as permissões possam ser "
                        "verificadas."
                    ),
                )
                findings.append(finding)
                self._publish_finding(finding)
                self._trip(
                    "permission_audit_failed",
                    f"Could not inspect permissions for {relative_path}.",
                )
                continue
            self._append_permission_result(
                findings,
                relative_path,
                bool(mode & stat.S_IWGRP),
                bool(mode & stat.S_IWOTH),
                synthetic=False,
            )

        if (
            isinstance(simulated_auth_failures, bool)
            or not isinstance(simulated_auth_failures, int)
            or simulated_auth_failures < 0
        ):
            raise ValueError("simulated_auth_failures must be a non-negative integer.")
        if simulated_auth_failures >= self.AUTH_FAILURE_THRESHOLD:
            finding = SecurityFinding(
                event_name="auth.brute_force.detected",
                severity="high",
                summary="Simulated authentication-failure sequence exceeded threshold.",
                evidence={
                    "failure_count": simulated_auth_failures,
                    "threshold": self.AUTH_FAILURE_THRESHOLD,
                    "source": "synthetic_local_scenario",
                },
                vetor_ataque=(
                    "Tentativas repetidas de senha podem identificar credenciais fracas; "
                    "o evento é inteiramente sintético e nenhuma autenticação foi tentada."
                ),
                remediacao=(
                    "Habilite MFA, limitação progressiva de tentativas e alertas de "
                    "autenticação no provedor de identidade da aplicação."
                ),
                mitre_id="T1110.001",
                acao_bloqueio=(
                    "Suspender a simulação, preservar os registros de autenticação e "
                    "revalidar a política defensiva antes de retomar."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("simulated_auth_anomaly", finding.summary)

        detected_base64 = self._count_base64_samples(encoded_payload_samples)
        detected_commands = self._count_suspicious_commands(
            simulated_subprocess_commands
        )
        if detected_base64 or detected_commands:
            finding = self._finding(
                event_name="evasion.obfuscation.detected",
                severity="critical",
                summary="Synthetic obfuscation indicators were detected.",
                evidence={
                    "mitre_id": "T1027",
                    "base64_sample_count": detected_base64,
                    "suspicious_command_count": detected_commands,
                    "source": "synthetic_detection_fixture",
                },
                vetor_ataque=(
                    "Conteúdo codificado ou comandos com indicadores de ofuscação "
                    "podem ocultar a intenção de um artefato; nenhuma amostra foi "
                    "executada."
                ),
                remediacao=(
                    "Preserve a amostra, examine-a em ferramenta defensiva isolada e "
                    "compare-a com fontes aprovadas. Não execute o conteúdo."
                ),
                mitre_id="T1027",
                acao_bloqueio=(
                    "Manter a execução em BLOCKED até a revisão manual da amostra e "
                    "da origem do comando."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("synthetic_obfuscation_detected", finding.summary)

        for evidence in persistence_fixtures:
            if not isinstance(evidence, PersistenceEvidence):
                raise TypeError(
                    "persistence_fixtures must contain PersistenceEvidence records."
                )
            if evidence.authorized:
                continue
            mitre_id, technique = _PERSISTENCE_MECHANISMS[evidence.mechanism]
            finding = self._finding(
                event_name="persistence.point.detected",
                severity="critical",
                summary=f"Unauthorized synthetic {technique} indicator was detected.",
                evidence={
                    "mechanism": evidence.mechanism,
                    "fixture_name": evidence.name,
                    "source": "synthetic_persistence_fixture",
                },
                vetor_ataque=(
                    "Um ponto de persistência não autorizado poderia iniciar software "
                    "durante uma sessão ou inicialização futura; este indicador é "
                    "somente uma fixture e nenhum mecanismo do sistema foi consultado."
                ),
                remediacao=(
                    "Revise a origem e a autorização do mecanismo no ambiente de "
                    "laboratório. Não remova tarefas ou entradas de inicialização "
                    "reais com base neste resultado sintético."
                ),
                mitre_id=mitre_id,
                acao_bloqueio=(
                    "Manter a execução em BLOCKED até que a origem do indicador "
                    "sintético seja revisada."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("synthetic_persistence_detected", finding.summary)

        self._publish(
            "security.audit.completed",
            {"finding_count": len(findings)},
        )
        return tuple(findings)

    def notify_canary_activity(
        self,
        path: Path,
        *,
        reason: str,
        source: str,
    ) -> SecurityFinding:
        """Report an explicit synthetic or integrity-based canary signal."""
        if not isinstance(path, Path):
            raise TypeError("Canary path must be a pathlib.Path.")
        if not self._is_canary_path(path):
            raise ValueError(
                "Canary signals are restricted to the configured decoy file."
            )
        if not isinstance(reason, str) or reason not in {"accessed", "modified"}:
            raise ValueError("Canary reason must be accessed or modified.")
        if not isinstance(source, str) or source not in {
            "synthetic_simulation",
            "local_file_audit",
        }:
            raise ValueError("Unsupported canary signal source.")
        finding = self._finding(
            event_name="deception.canary.triggered",
            severity="critical",
            summary=f"Canary decoy file was {reason}.",
            evidence={
                "path": _CANARY_RELATIVE_PATH,
                "reason": reason,
                "source": source,
            },
            vetor_ataque=(
                "Acesso ou alteração do arquivo-isca pode indicar reconhecimento ou "
                "adulteração; o sinal de acesso é explícito/sintético e não monitora "
                "leituras externas do sistema operacional."
            ),
            remediacao=(
                "Preserve os logs, valide a integridade do arquivo-isca e investigue "
                "o processo por meio de controles de auditoria do sistema já "
                "autorizados."
            ),
            mitre_id="",
            acao_bloqueio=(
                "Acionar o kill-switch imediatamente e manter a execução em BLOCKED "
                "até a revisão do incidente."
            ),
        )
        self._publish_finding(finding)
        self._trip("canary_triggered", finding.summary)
        return finding

    def _is_canary_path(self, path: Path) -> bool:
        if not isinstance(path, Path):
            return False
        lexical_path = Path(os.path.abspath(path))
        return lexical_path == self._project_root / _CANARY_RELATIVE_PATH

    @staticmethod
    def _count_base64_samples(samples: tuple[str, ...]) -> int:
        if not isinstance(samples, tuple) or any(
            not isinstance(sample, str) for sample in samples
        ):
            raise TypeError("encoded_payload_samples must be a tuple of strings.")
        return sum(
            len(sample) >= 12 and _BASE64_CANDIDATE.fullmatch(sample) is not None
            for sample in samples
        )

    @staticmethod
    def _count_suspicious_commands(commands: tuple[str, ...]) -> int:
        if not isinstance(commands, tuple) or any(
            not isinstance(command, str) for command in commands
        ):
            raise TypeError("simulated_subprocess_commands must be a tuple of strings.")
        return sum(bool(_SUSPICIOUS_COMMAND.search(command)) for command in commands)

    def _append_permission_result(
        self,
        findings: list[SecurityFinding],
        relative_path: str,
        group_writable: bool,
        world_writable: bool,
        *,
        synthetic: bool,
    ) -> None:
        evidence = {
            "path": relative_path,
            "group_writable": group_writable,
            "world_writable": world_writable,
            "source": "synthetic_fixture" if synthetic else "filesystem",
        }
        if group_writable or world_writable:
            safe_posix_path = shlex.quote(relative_path)
            windows_path = _windows_path(relative_path).replace("'", "''")
            finding = self._finding(
                event_name="security.permission.excessive",
                severity="critical",
                summary="File is writable by group or all users.",
                evidence=evidence,
                vetor_ataque=(
                    "Um usuário com a permissão de escrita pode adulterar a "
                    "configuração e influenciar a execução subsequente; no cenário "
                    "solicitado, isso é uma fixture sintética."
                ),
                remediacao=(
                    f"Linux/macOS: chmod go-w {safe_posix_path}\n"
                    f"Windows PowerShell (Admin): icacls.exe "
                    f"'{windows_path}' /inheritance:d /remove:g Everyone"
                ),
                mitre_id="T1222",
                acao_bloqueio=(
                    "Retirar escrita de grupos/usuários não autorizados, validar a "
                    "ACL efetiva e manter o motor em BLOCKED até nova auditoria."
                ),
            )
            findings.append(finding)
            self._publish_finding(finding)
            self._trip("excessive_file_permissions", finding.summary)
            return
        self._publish(
            "security.permission.verified",
            evidence,
        )

    @staticmethod
    def _finding(
        *,
        event_name: str,
        severity: str,
        summary: str,
        evidence: dict[str, object],
        vetor_ataque: str,
        remediacao: str,
        mitre_id: str,
        acao_bloqueio: str,
    ) -> SecurityFinding:
        return SecurityFinding(
            event_name=event_name,
            severity=severity,
            summary=summary,
            evidence=evidence,
            vetor_ataque=vetor_ataque,
            remediacao=remediacao,
            mitre_id=mitre_id,
            acao_bloqueio=acao_bloqueio,
        )

    def _publish_finding(self, finding: SecurityFinding) -> None:
        payload = {
            **finding.evidence,
            "severity": finding.severity,
            "vetor_ataque": finding.vetor_ataque,
            "remediacao": finding.remediacao,
            "mitre_id": finding.mitre_id,
            "acao_bloqueio": finding.acao_bloqueio,
            "summary": finding.summary,
        }
        self._publish(finding.event_name, payload)

    def _project_relative_path(self, path: Path) -> str:
        if not isinstance(path, Path):
            raise TypeError("Audited paths must be pathlib.Path instances.")
        resolved = path.resolve()
        try:
            return resolved.relative_to(self._project_root).as_posix()
        except ValueError as error:
            raise ValueError("Audit path must remain inside the project root.") from error

    def _publish(self, name: str, payload: dict[str, object]) -> None:
        self._event_bus.publish(Event(run_id=self._run_id, name=name, payload=payload))

    def _trip(self, reason_code: str, reason: str) -> None:
        self._kill_switch.trigger(
            reason,
            reason_code=reason_code,
            run_id=self._run_id,
            blocked_run_id=self._run_id,
        )


__all__ = [
    "IntegrityEvidence",
    "PersistenceEvidence",
    "PermissionEvidence",
    "PortEvidence",
    "SecurityAudit",
    "SecurityFinding",
]
