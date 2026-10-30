# SARR-Core Engine — Prompts Mestre e Fases

Conjunto alinhado de prompts para o Copilot (VS Code), do zero até a vitrine de portfólio. Use um prompt por vez, na ordem. Cada fase termina com "pare e aguarde 'próxima fase'".

## Prompt Mestre (cole uma vez, ou salve em `.github/copilot-instructions.md`)

```text
Você é um engenheiro sênior de segurança defensiva (purple team) trabalhando no
projeto SARR-Core Engine: plataforma de diagnóstico e resiliência defensiva.
Ambiente: Windows + VS Code + Git; execução real em containers Linux (Docker
Desktop + WSL2). Linguagem: Python 3.11+.

OBJETIVO GERAL
Construir e depois estender o SARR-Core Engine em FASES: detecção heurística de
port scan e SYN flood, mitigação fail-closed, telemetria Prometheus, simulador
de ataque de laboratório, observabilidade (Docker+Prometheus+Grafana),
documentação, vitrine de portfólio e, por fim, um radar passivo de Wi-Fi/BLE.

REGRAS INVIOLÁVEIS
- Trabalhe por FASES (0 a 8, a Fase 8 tem sub-fases 8.1 a 8.4). Ao fim de cada
  fase ou sub-fase: PARE, liste arquivos criados/alterados, como testar, e
  espere eu dizer "próxima fase".
- Antes de criar qualquer arquivo, verifique se já existe algo equivalente no
  repositório. Reutilize e estenda; não duplique.
- Os módulos se comunicam SOMENTE pelos contratos abaixo (C1-C5). Não mude um
  contrato sem avisar e explicar o impacto nas outras fases.
- Código tipado (type hints), docstrings curtas, logging estruturado, sem
  shell=True, IPs validados com o módulo ipaddress, nenhuma entrada de rede
  interpolada em comando.
- Configuração em config.yaml validada na inicialização (limiares, janelas,
  TTL, allowlist, portas, flags de feature). Sem valores mágicos no código.
- Cada módulo com testes pytest; nenhuma fase termina com teste falhando.
- Dependências com versão fixa em requirements.txt. Mitigação em DRY-RUN por
  padrão.
- Todo código de ataque/simulação é exclusivo para laboratório próprio
  (loopback/RFC1918), nunca contra alvo público.
- Nunca invente capacidade ou resultado em documentação que o código não
  comprove.

CONTRATOS ENTRE MÓDULOS
C1 — SecurityEvent(timestamp: float, src_ip: str | None, kind: str,
  severity: int, details: dict). Dataclass imutável, em models.py. kind inclui
  "PORT_SCAN", "SYN_FLOOD" (Fase 1) e, mais tarde, "ROGUE_AP",
  "BLE_UNKNOWN_DEVICE" (Fase 8).
C2 — Mitigator.block(ip: str, ttl_s: int) -> bool; unblock(ip) -> bool;
  list_blocked() -> list[str]; is_failclosed_active() -> bool.
C3 — TelemetryExporter.observe_packet(), .observe_event(event),
  .observe_block(ip), .set_latency(seconds), .set_failclosed(active: bool).
  Toda métrica nova usa o prefixo sarr_. Uma métrica de uma feature desativada
  pelo operador NÃO aparece no /metrics (ausente, não zerada).
C4 — O simulador de ataque só gera tráfego; não importa código do motor. Sua
  validação é externa: compara eventos esperados com as métricas expostas.
C5 — O dashboard Grafana usa exclusivamente as métricas do contrato C3.

SEMÂNTICA FAIL-CLOSED
Se o motor falhar, perder a captura ou não conseguir decidir, aplica-se a
política segura configurada (negar por padrão no segmento protegido), e o
estado é exposto em sarr_failclosed_active. Bloquear um IP após detecção é
mitigação, não fail-closed — os dois conceitos não se confundem.

Confirme que entendeu respondendo apenas com: (a) o resumo das regras em 5
linhas e (b) a lista das fases (0 a 8, com as sub-fases de 8). Depois aguarde
meu comando para iniciar a Fase 0.
```

## Fase 0 — Auditoria e integração

```text
FASE 0. Não escreva código ainda. Varra o repositório e me entregue:
1) árvore de diretórios e arquivos atuais, 2) módulos que já cobrem captura,
detecção, mitigação, métricas ou testes, 3) convenções existentes (nomes,
config, logging, testes), 4) conflitos entre o que existe e os contratos
C1–C5, 5) um plano de integração: o que será estendido, o que será criado e em
qual caminho. Aguarde minha aprovação do plano.
```

## Fase 1 — Detecção heurística

```text
FASE 1 (contrato C1). Implemente a detecção, estendendo o que a Fase 0 apontou.
- Janela deslizante por IP de origem. PORT_SCAN: SYN para mais de X portas
  DISTINTAS em Y segundos. SYN_FLOOD: taxa de SYN acima de N/s sem ACK na
  janela.
- Limite máximo de IPs rastreados, limpeza de IPs inativos e cooldown por
  IP/tipo.
- A análise recebe dados já extraídos (src_ip, dst_port, flags, timestamp),
  nunca objetos Scapy. A captura é separada e aceita: live, arquivo .pcap e
  gerador sintético (para testar no Windows sem privilégios).
- Testes: tráfego legítimo (sem falso positivo), scan lento, scan rápido,
  flood e IP em allowlist.
Pare aqui e aguarde "próxima fase".
```

## Fase 2 — Mitigação fail-closed

```text
FASE 2 (contrato C2, consome C1). Implemente a interface Mitigator com
DryRunMitigator (padrão), IptablesMitigator (cadeia própria SARR_BLOCK,
subprocess com lista de argumentos, operações idempotentes) e
DockerMitigator (isola o container via SDK do Docker).
- Travas: allowlist que nunca é bloqueada (gateway, loopback, IP do host,
  gestão), TTL com desbloqueio automático, limite de bloqueios simultâneos,
  rollback no shutdown limpo.
- Implemente a política fail-closed conforme a semântica do prompt mestre.
- Testes com mock; nunca executar iptables real nos testes.
Pare aqui e aguarde "próxima fase".
```

## Fase 3 — Telemetria e integração do motor

```text
FASE 3 (contrato C3). Implemente o TelemetryExporter com prometheus_client e
as métricas: sarr_packets_analyzed_total (Counter), sarr_events_total{kind}
(Counter), sarr_ips_blocked_total (Counter), sarr_inspection_latency_seconds
(Gauge/Histogram), sarr_failclosed_active (Gauge 0/1),
sarr_suspicious_connections{src_ip} (Gauge, só top N IPs, para não explodir
cardinalidade).
Conecte captura → detecção → mitigação → telemetria no engine, com CLI:
--config, --mode {live,pcap,synthetic}, --dry-run/--enforce.
Teste que cada evento e bloqueio atualiza a métrica certa.
Pare aqui e aguarde "próxima fase".
```

## Fase 4 — Simulador de ataque

```text
FASE 4 (contrato C4). Crie o simulador: tráfego legítimo alternado com
rajadas de port scan e SYN flood, com intensidade e duração configuráveis.
- Travas éticas: aceitar apenas loopback ou RFC1918 listados em allowlist,
  exigir --i-own-this-lab, limitar taxa máxima e recusar qualquer alvo
  público.
- Ao final, gerar relatório "esperado vs. detectado" lendo as métricas do
  exporter.
Pare aqui e aguarde "próxima fase".
```

## Fase 5 — Docker, Prometheus e Grafana

```text
FASE 5 (contrato C5). Crie docker-compose com sarr-engine (NET_ADMIN/NET_RAW
só onde necessário), simulator (profile separado), prometheus e grafana em
rede isolada. Crie prometheus.yml e um dashboard Grafana provisionado com:
pacotes inspecionados/s, eventos por tipo, top IPs suspeitos, IPs bloqueados
ao longo do tempo, latência de inspeção e indicador Ativo/Bloqueado do
fail-closed. Use somente as métricas do contrato C3.
Pare aqui e aguarde "próxima fase".
```

## Fase 6 — README técnico

```text
FASE 6. Escreva o README técnico: visão geral, diagrama de arquitetura em
Mermaid, pré-requisitos no Windows (Docker Desktop + WSL2), quick start,
tabela de configuração, como rodar o simulador, limitações conhecidas, aviso
de uso ético e roadmap (inclua ali, como item futuro, "Fase 8: radar passivo
Wi-Fi/BLE"). Rode uma checagem final: testes, lint, e confirme que cada
contrato C1–C5 está respeitado.
Pare aqui e aguarde "próxima fase".
```

## Fase 7 — Vitrine para o recrutador

```text
FASE 7 — VITRINE PARA O RECRUTADOR (GitHub)
Contexto: o SARR-Core Engine é um projeto de portfólio. Quem avalia dá 30
segundos ao README e, se gostar, explora mais. Use o README da Fase 6 como
base e REORGANIZE, não reescreva do zero.

REGRA DE OURO: não invente nada. Todo número, resultado ou capacidade citada
precisa vir de algo que o projeto realmente faz ou de uma medição executada
agora.

1) README.md (inglês) e README.pt-BR.md (português), com links cruzados no
   topo. Estrutura: título + badges; "Em 30 segundos"; demo (GIF/screenshot
   do Grafana); quick start em até 3 comandos; arquitetura (Mermaid);
   tabela "O que este projeto demonstra" (competência → onde no código);
   resultados de validação (tabela ataque simulado vs. detectado); decisões
   de projeto; limitações e roadmap; aviso de uso ético.
2) Pasta docs/: ARCHITECTURE.md, THREAT_MODEL.md, DEMO.md,
   CONFIGURATION.md.
3) LICENSE (MIT, salvo eu dizer outra), SECURITY.md, CI (pytest + lint),
   templates de issue, .gitignore limpo (sem segredos).
4) Rode o quick start do zero em pasta limpa, valide links internos, remova
   qualquer afirmação não comprovada.
Entregue tudo e termine com um checklist do que eu preciso fazer manualmente
no GitHub (descrição, topics, pin do repositório, release v1.0.0).
```

## Fase 8 — Radar passivo Wi-Fi/BLE (opcional, sub-fases 8.1 a 8.4)

```text
FASE 8 — RADAR PASSIVO MULTI-CAMADA (Wi-Fi/BLE)
Escopo fixo, sem exceção: captura SOMENTE passiva de sinais já presentes no
ar. Proibido: modo monitor, desautenticação, injeção de pacotes, conexão,
pareamento ou escrita em qualquer dispositivo de terceiros. Roda apenas no
host do autor. Reaproveita os contratos C1 e C3 já existentes.

Princípio de controle: wifi.enabled e ble.enabled são um PORTÃO único.
Desligado = corte total: nenhuma varredura roda, nenhum dado é coletado,
nenhuma métrica sarr_wifi_*/sarr_ble_* aparece no /metrics (ausente, não
zerada). O operador liga e desliga explicitamente pela CLI; a decisão nunca
é automática nem fica "lembrada" entre sessões sem o operador ver o estado.

Faça as 4 sub-fases UMA POR VEZ, nesta ordem: 8.1 → 8.2 → 8.3 → 8.4. Ao fim
de cada uma: pare, mostre o que foi criado/alterado, como testar, e espere
"próxima fase".

SUB-FASE 8.1 — Permissão de localização, varredura Wi-Fi e rogue AP
- Crie src/sarr/location_permission.py:
  * check_location_enabled() -> bool: leitura (somente leitura) via winreg da
    chave HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
    CapabilityAccessManager\\ConsentStore\\location, valor "Value".
  * request_enable_location() -> bool: só é chamada após confirmação explícita
    do usuário na CLI. Executa via subprocess chamando powershell com
    Start-Process -Verb RunAs, disparando o UAC real do Windows (nunca
    escrever direto na chave sem elevação, nunca ocultar o prompt do UAC).
    Loga timestamp, usuário do SO e resultado (aceito/recusado/erro).
- Crie src/sarr/wifi_scanner.py: varredura via comando nativo do SO (netsh
  wlan show networks mode=bssid no Windows; nmcli/iwlist como alternativa
  Linux), sem bibliotecas de modo monitor. Extrai SSID, BSSID (se permitido),
  RSSI, canal. config.yaml ganha seção wifi.trusted_aps: lista de
  {ssid, bssid}.
- Estado da feature: wifi_status = "disabled" | "enabled_no_location" |
  "enabled_full". Em "disabled", o scanner nem é instanciado. Em
  "enabled_no_location" (usuário ligou a função mas recusou localização ou
  ela está indisponível), coleta só SSID/RSSI, sem checagem de rogue AP (que
  depende de BSSID para ser confiável). Em "enabled_full", BSSID disponível
  e o rogue-AP check roda: SSID confiável com BSSID fora da lista emite
  SecurityEvent(kind="ROGUE_AP") pelo contrato C1.
- CLI: comando "sarr wifi on" pergunta sobre localização ("Ativar localização
  para detectar o BSSID? [s/N]"), muda o estado, loga "Wi-Fi radar ATIVADO
  por <usuário> às <hora>" (e idem para location). Comando "sarr wifi off"
  para a thread imediatamente, limpa os dados da sessão em memória, loga
  "Wi-Fi radar DESATIVADO — nenhum dado será coletado até reativação".
- Testes: mock do winreg (permissão ligada/desligada/chave ausente), mock do
  subprocess/UAC (aceito/recusado/erro), mock da saída do comando do SO
  (AP confiável, rogue AP, rede desconhecida sem alerta), e confirmação de
  que em "disabled" o scanner nunca é chamado.
Pare aqui e aguarde "próxima fase".

SUB-FASE 8.2 — Descoberta BLE passiva
- Crie src/sarr/ble_scanner.py usando a biblioteca bleak (multiplataforma).
  Descoberta passiva apenas: sem connect(), sem pareamento, sem
  leitura/escrita de característica.
- Registrar dispositivos por endereço MAC/UUID, com timestamp de primeira e
  última vez visto. Config: ble.enabled (mesmo portão liga/desliga de 8.1),
  ble.alert_on_new_device (bool), ble.known_devices (allowlist opcional).
- Se ble.enabled e alert_on_new_device=true e o dispositivo não está em
  known_devices, emitir SecurityEvent(kind="BLE_UNKNOWN_DEVICE").
- CLI: "sarr ble on/off" com o mesmo padrão de log e limpeza de dados da
  sessão descrito em 8.1 para Wi-Fi.
- Testes com mock do bleak; confirmar que em ble.enabled=false o scanner
  nunca é chamado.
Pare aqui e aguarde "próxima fase".

SUB-FASE 8.3 — Integração com telemetria e engine
- Estenda o TelemetryExporter (contrato C3) com: sarr_wifi_networks_seen
  (Gauge), sarr_wifi_rogue_ap_detected (Counter), sarr_ble_devices_seen
  (Gauge), sarr_ble_unknown_device_total (Counter). Crie uma porta única
  is_feature_active(name: Literal["wifi","ble"]) -> bool em config.py; todo o
  resto do código consulta essa função, nunca lê config.yaml diretamente em
  mais de um lugar.
- Quando uma feature está "disabled", suas métricas não existem no /metrics
  (ausentes, não zeradas) — é o jeito auditável de provar que desligado é
  corte total.
- No engine.py, os scanners rodam como fontes opcionais em thread própria,
  com intervalo de varredura configurável, sem interferir no pipeline TCP/IP
  já existente.
- Teste de integração: ativar com mocks e confirmar que eventos chegam ao
  exporter; testar liga→desliga→liga em sequência e confirmar que não sobra
  dado residual da execução anterior.
Pare aqui e aguarde "próxima fase".

SUB-FASE 8.4 — Painel "Radar SARR" no Grafana
- Estenda o dashboard.json existente (não crie um novo arquivo): seção
  "Radar Wi-Fi/BLE" ao lado dos painéis TCP/IP, usando só as métricas de
  8.3. Painéis: tabela de SSIDs vistos (nome, RSSI, status
  confiável/rogue), alerta visual quando sarr_wifi_rogue_ap_detected > 0,
  contador de dispositivos BLE vistos na última hora, lista dos últimos
  dispositivos BLE desconhecidos.
- Quando a feature estiver "disabled", o painel mostra um estado neutro
  ("Desativado pelo operador"), não um gráfico vazio ou zerado.
- README: nova seção "Radar Wi-Fi/BLE (passivo)" explicando que o módulo só
  escuta o que já está no ar, nunca ataca nem interage com dispositivos de
  terceiros, exige ativação explícita do operador (sarr wifi/ble on), e que
  desligar corta a coleta por completo. Adicione wifi.enabled/ble.enabled na
  tabela de configuração.
Pare aqui. Ao final, resuma: todos os contratos (C1, C3) continuam
respeitados, nenhum código de ataque foi introduzido, e confirme que o
gating liga/desliga foi testado nos três módulos (Wi-Fi, BLE, telemetria).
```

## Prompt orquestrador (opcional — continuar sem lembrar a fase)

Use este bloco em vez dos anteriores quando quiser que o Copilot descubra sozinho onde o projeto parou e continue.

```text
Você é o orquestrador do projeto SARR-Core Engine. Descubra automaticamente o
estado atual do projeto e continue a partir de onde parou.

PASSO 1 — DIAGNÓSTICO (sempre primeiro)
Varra o repositório e monte uma tabela: Fase 0 a 7, e Fase 8 com suas
sub-fases 8.1 a 8.4 — cada uma "feita" (código + teste + conectado ao
pipeline), "parcial" ou "não feita".

PASSO 2 — DECISÃO
Se algo está parcial, termine antes de avançar. Se tudo até X está completo,
comece X+1. Nunca pule nem misture fases. Repositório vazio → comece na
Fase 0.

PASSO 3 — EXECUÇÃO
Diga em 1 linha qual fase vai rodar e por quê, execute SOMENTE essa fase
seguindo as regras fixas abaixo, pare, resuma e diga: "Pronto para a próxima
fase. Cole este mesmo prompt de novo quando quiser continuar."

REGRAS FIXAS (as mesmas do Prompt Mestre): tipagem, logging estruturado, sem
shell=True, config.yaml validado, testes obrigatórios, dry-run por padrão,
contratos C1/C2/C3/C4/C5 estáveis, Fase 8 estritamente passiva com gating
liga/desliga real, nunca inventar capacidade não comprovada no README.

Comece agora pelo PASSO 1.
```
