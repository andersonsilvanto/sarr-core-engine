"""Restricted integrations for local Nmap checks and offline Tshark use."""

import hashlib
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from core.security_audit import SecurityFinding
from sarr_core.scanner_bootstrap import ScannerBootstrap


_MAX_NMAP_OUTPUT_BYTES = 2_000_000
_MAX_CAPTURE_BYTES = 25_000_000
_MAX_TSHARK_OUTPUT_BYTES = 2_000_000


@dataclass(frozen=True)
class ExternalScannerResult:
    statuses: tuple[tuple[str, str], ...]
    findings: tuple[SecurityFinding, ...]


class ExternalScannerManager:
    """Run only a fixed loopback scan; Tshark is restricted to offline files."""

    def __init__(self, project_root: str | Path) -> None:
        self._project_root = Path(project_root).resolve()
        self._bootstrap = ScannerBootstrap()

    def run_local_checks(
        self,
        offline_capture: str | Path | None = None,
    ) -> ExternalScannerResult:
        statuses: list[tuple[str, str]] = []
        findings: list[SecurityFinding] = []
        capture = (
            self._validate_capture_path(offline_capture)
            if offline_capture is not None
            else None
        )
        nmap_installation = self._bootstrap.locate("nmap")
        tshark_installation = self._bootstrap.locate("tshark")
        nmap = nmap_installation.executable
        tshark = tshark_installation.executable
        discovered_ports: dict[int, str] = {}

        if nmap is None:
            statuses.append(("Nmap", "indisponível — fallback interno ativo"))
            findings.append(
                self._availability_finding(
                    "nmap",
                    "Nmap não foi encontrado no PATH; inventário local/sintético permanece ativo.",
                )
            )
        else:
            nmap_findings, warning = self._scan_loopback(str(nmap))
            findings.extend(nmap_findings)
            discovered_ports = {
                int(finding.evidence["port"]): str(finding.evidence["service"])
                for finding in nmap_findings
                if isinstance(finding.evidence.get("port"), int)
                and isinstance(finding.evidence.get("service"), str)
            }
            if warning is not None:
                statuses.append(("Nmap", "falha — fallback interno ativo"))
                findings.append(warning)
            else:
                statuses.append(
                    ("Nmap", "disponível — verificação limitada a 127.0.0.1")
                )

        if tshark is None:
            statuses.append(("Tshark", "indisponível — fallback interno ativo"))
            findings.append(
                self._availability_finding(
                    "tshark",
                    "Tshark não foi encontrado no PATH; inventário local/sintético permanece ativo.",
                )
            )
        else:
            try:
                result = subprocess.run(
                    [str(tshark), "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                statuses.append(("Tshark", "falha ao iniciar — fallback interno ativo"))
                findings.append(
                    self._scanner_failure_finding("tshark", type(error).__name__)
                )
            else:
                if result.returncode == 0:
                    if capture is not None:
                        try:
                            capture_findings = self._analyze_capture(
                                capture,
                                executable=str(tshark),
                                discovered_ports=discovered_ports,
                            )
                        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                            statuses.append(
                                ("Tshark", "falha — fallback interno ativo")
                            )
                            findings.append(
                                self._scanner_failure_finding(
                                    "tshark",
                                    type(error).__name__,
                                )
                            )
                        else:
                            findings.extend(capture_findings)
                            statuses.append(
                                (
                                    "Tshark",
                                    "análise offline concluída; captura ao vivo desativada",
                                )
                            )
                    else:
                        statuses.append(
                            (
                                "Tshark",
                                "disponível — análise offline; captura ao vivo desativada",
                            )
                        )
                else:
                    statuses.append(("Tshark", "indisponível — fallback interno ativo"))
                    findings.append(
                        self._scanner_failure_finding(
                            "tshark",
                            f"version command returned {result.returncode}",
                        )
                    )

        return ExternalScannerResult(tuple(statuses), tuple(findings))

    def analyze_capture(
        self,
        capture_path: str | Path,
        *,
        executable: str | None = None,
    ) -> SecurityFinding:
        """Analyze an authorized local capture without exposing packet payloads."""
        findings = self._analyze_capture(
            capture_path,
            executable=executable,
            discovered_ports={},
        )
        return findings[0]

    def _analyze_capture(
        self,
        capture_path: str | Path,
        *,
        executable: str | None,
        discovered_ports: dict[int, str],
    ) -> tuple[SecurityFinding, ...]:
        tshark_installation = (
            self._bootstrap.locate("tshark") if executable is None else None
        )
        tshark = (
            str(tshark_installation.executable)
            if tshark_installation is not None
            and tshark_installation.executable is not None
            else executable
        )
        if tshark is None:
            raise RuntimeError("Tshark is unavailable; internal fallback remains active.")
        capture = self._validate_capture_path(capture_path)
        result = subprocess.run(
            [
                tshark,
                "-r",
                str(capture),
                "-T",
                "fields",
                "-E",
                "separator=\\t",
                "-c",
                "10000",
                "-e",
                "frame.number",
                "-e",
                "frame.protocols",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.srcport",
                "-e",
                "udp.dstport",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "ipv6.src",
                "-e",
                "ipv6.dst",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            shell=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Tshark could not analyze the authorized capture.")
        output = result.stdout.encode("utf-8", errors="replace")
        if len(output) > _MAX_TSHARK_OUTPUT_BYTES:
            raise RuntimeError("Tshark output exceeded the supported size limit.")
        rows = [
            line.split("\t")
            for line in result.stdout.splitlines()
            if line.strip()
        ]
        if discovered_ports and any(len(row) < 10 for row in rows):
            raise RuntimeError("Tshark output is missing required correlation fields.")
        frame_count = len(rows)
        signature = hashlib.sha256(output).hexdigest()
        findings = [
            SecurityFinding(
                event_name="network.tshark.capture_analyzed",
                severity="info",
                summary=(
                    f"Tshark analyzed {frame_count} frame(s) from an authorized "
                    "offline capture; packet payloads were not exported."
                ),
                evidence={
                    "capture_name": capture.name,
                    "frame_count": frame_count,
                    "analysis_signature_sha256": signature,
                    "source": "tshark_offline_capture",
                },
                vetor_ataque=(
                    "Análise passiva de metadados de captura fornecida pelo operador; "
                    "nenhum tráfego ao vivo foi observado."
                ),
                remediacao=(
                    "Revise o inventário de protocolos no contexto do escopo "
                    "autorizado; o conteúdo dos pacotes não foi armazenado pelo "
                    "SARR-Core."
                ),
                mitre_id="",
                acao_bloqueio=(
                    "Nenhum bloqueio automático baseado somente em metadados."
                ),
            )
        ]
        findings.extend(
            self._correlate_plaintext_traffic(
                rows,
                capture_name=capture.name,
                discovered_ports=discovered_ports,
            )
        )
        return tuple(findings)

    @staticmethod
    def _correlate_plaintext_traffic(
        rows: list[list[str]],
        *,
        capture_name: str,
        discovered_ports: dict[int, str],
    ) -> tuple[SecurityFinding, ...]:
        plaintext_protocols = {
            "ftp",
            "http",
            "http2",
            "imap",
            "irc",
            "ldap",
            "mqtt",
            "pop",
            "smtp",
            "telnet",
            "tftp",
            "amqp",
        }
        loopback_addresses = {"127.0.0.1", "::1"}
        observations: dict[int, tuple[set[str], int]] = {}
        for row in rows:
            if len(row) < 10:
                continue
            if not (set(row[6:10]) & loopback_addresses):
                continue
            protocols = {
                token.lower()
                for token in row[1].split(":")
                if token
            }
            if "tls" in protocols or "ssl" in protocols:
                continue
            plaintext = protocols & plaintext_protocols
            if not plaintext:
                continue
            for port_text in row[2:6]:
                if not port_text.isdigit():
                    continue
                port = int(port_text)
                if port not in discovered_ports:
                    continue
                existing_protocols, frame_count = observations.get(
                    port,
                    (set(), 0),
                )
                existing_protocols.update(plaintext)
                observations[port] = (existing_protocols, frame_count + 1)

        return tuple(
            SecurityFinding(
                event_name="network.correlation.vulnerability_detected",
                severity="critical",
                summary=(
                    f"Plaintext {', '.join(sorted(protocols))} traffic was observed "
                    f"on Nmap-discovered loopback port {port}."
                ),
                evidence={
                    "host": "127.0.0.1",
                    "port": port,
                    "service": discovered_ports[port],
                    "protocols": sorted(protocols),
                    "frame_count": frame_count,
                    "capture_name": capture_name,
                    "source": "nmap_tshark_offline_correlation",
                },
                vetor_ataque=(
                    "Tráfego de aplicação sem TLS pode expor dados em trânsito a "
                    "observadores com acesso ao caminho de rede; a evidência veio "
                    "de captura offline e não demonstra exposição além do loopback."
                ),
                remediacao=(
                    "Configure TLS para o serviço, desative protocolos em texto "
                    "claro quando possível e repita a análise com uma captura "
                    "autorizada após a mudança."
                ),
                mitre_id="T1040",
                acao_bloqueio=(
                    "Manter a execução BLOCKED até a revisão do serviço e a "
                    "validação de uma configuração criptografada."
                ),
            )
            for port, (protocols, frame_count) in sorted(observations.items())
        )

    def _validate_capture_path(self, capture_path: str | Path) -> Path:
        capture = Path(capture_path).resolve(strict=True)
        try:
            capture.relative_to(self._project_root)
        except ValueError as error:
            raise ValueError("Capture files must remain inside the project directory.") from error
        if capture.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("Only .pcap and .pcapng capture files are supported.")
        if not capture.is_file() or capture.stat().st_size > _MAX_CAPTURE_BYTES:
            raise ValueError("Capture is missing or exceeds the supported size limit.")
        return capture

    def _scan_loopback(
        self,
        executable: str,
    ) -> tuple[tuple[SecurityFinding, ...], SecurityFinding | None]:
        try:
            result = subprocess.run(
                [
                    executable,
                    "-n",
                    "-sT",
                    "-F",
                    "-T2",
                    "--host-timeout",
                    "15s",
                    "-oX",
                    "-",
                    "127.0.0.1",
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return (), self._scanner_failure_finding("nmap", type(error).__name__)
        output = result.stdout.encode("utf-8", errors="replace")
        if len(output) > _MAX_NMAP_OUTPUT_BYTES:
            return (), self._scanner_failure_finding("nmap", "output exceeded size limit")
        if result.returncode != 0:
            return (), self._scanner_failure_finding(
                "nmap",
                f"scan returned {result.returncode}",
            )
        try:
            document = ET.fromstring(result.stdout)
        except ET.ParseError:
            return (), self._scanner_failure_finding("nmap", "invalid XML output")

        findings: list[SecurityFinding] = []
        for port_node in document.findall(".//port"):
            state_node = port_node.find("state")
            port_text = port_node.get("portid", "")
            protocol = port_node.get("protocol", "")
            if (
                state_node is None
                or state_node.get("state") != "open"
                or not port_text.isdigit()
                or protocol not in {"tcp", "udp"}
            ):
                continue
            service_node = port_node.find("service")
            service = (
                service_node.get("name", "unknown")
                if service_node is not None
                else "unknown"
            )
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,48}", service):
                service = "unknown"
            port = int(port_text)
            if not 1 <= port <= 65535:
                continue
            findings.append(
                SecurityFinding(
                    event_name="network.nmap.port_discovered",
                    severity="info",
                    summary=(
                        f"Nmap observed {protocol}/{port} ({service}) on 127.0.0.1; "
                        "authorization and service security were not assessed."
                    ),
                    evidence={
                        "host": "127.0.0.1",
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "source": "nmap_loopback",
                    },
                    vetor_ataque=(
                        "A porta é uma superfície local observada; esta verificação "
                        "não avalia autenticação, vulnerabilidades ou acesso remoto."
                    ),
                    remediacao=(
                        "Confirme a necessidade e a autorização do serviço com o "
                        "inventário local antes de alterar sua configuração."
                    ),
                    mitre_id="T1046",
                    acao_bloqueio=(
                        "Nenhum bloqueio automático é recomendado sem validação do "
                        "serviço e da política local."
                    ),
                )
            )
        return tuple(findings), None

    @staticmethod
    def _availability_finding(tool: str, message: str) -> SecurityFinding:
        return SecurityFinding(
            event_name="external.scanner.unavailable",
            severity="info",
            summary=message,
            evidence={"tool": tool, "fallback": "internal_simulation"},
            vetor_ataque="N/A — ferramenta externa indisponível.",
            remediacao=(
                f"Opcional: instale {tool} por um canal confiável e reinicie o motor; "
                "a simulação interna continua disponível."
            ),
            mitre_id="",
            acao_bloqueio="Nenhum bloqueio; continuar somente com evidência local/sintética.",
        )

    @staticmethod
    def _scanner_failure_finding(tool: str, reason: str) -> SecurityFinding:
        return SecurityFinding(
            event_name="external.scanner.failed",
            severity="warning",
            summary=f"{tool} não concluiu a verificação local; fallback interno ativo.",
            evidence={"tool": tool, "reason": reason},
            vetor_ataque="A verificação externa não produziu evidência utilizável.",
            remediacao=(
                "Revise a instalação e os logs locais da ferramenta; não interprete "
                "a ausência de resultados como ausência de risco."
            ),
            mitre_id="",
            acao_bloqueio="Manter os resultados externos como não verificados.",
        )


__all__ = ["ExternalScannerManager", "ExternalScannerResult"]
