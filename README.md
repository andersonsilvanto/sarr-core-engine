# SARR-Core Engine

Estrutura inicial do SARR-Core Engine.

## Núcleo de orquestração

O pacote `core` em `src/core/` fornece o `CoreOrchestrator`, a máquina de
estados de execução, `RunContext`, o `EventBus` local e o `ModuleRegistry`.
Cada execução é registrada com `run_id` UUID, timestamp UTC e modo não vazio.
O registro rejeita IDs repetidos e a máquina rejeita transições fora do fluxo:

- `IDLE -> VALIDATING`
- `VALIDATING -> READY | STOPPING | BLOCKED | FAILED`
- `READY -> RUNNING | STOPPING | BLOCKED | FAILED`
- `RUNNING -> STOPPING | BLOCKED | FAILED | COMPLETED`
- `STOPPING -> STOPPED | FAILED`
- `BLOCKED -> VALIDATING | STOPPING`

`COMPLETED`, `STOPPED` e `FAILED` são estados terminais.

## Escopo e limites de segurança

Toda transição do orquestrador para `READY` ou `RUNNING` exige um escopo válido
em `schemas/scope.schema.json`. O JSON deve identificar engagement, ambiente,
modo, janela UTC, allowlists literais de alvos/módulos e limites operacionais.
Wildcards, campos extras, IDs duplicados no JSON, escopos expirados e valores
solicitados fora das allowlists são rejeitados; qualquer falha aciona o
kill-switch central e bloqueia a execução.

Os limites por escopo são duração (segundos), taxa média (operações/s) e volume
(bytes) dentro da janela móvel configurada, mais concorrência máxima. RTT
acima de 1500 ms interrompe imediatamente. A taxa HTTP 5xx acima de 5% aciona
o kill-switch a partir de 10 respostas na janela. O kill-switch é latched:
quando acionado, interrompe execuções ativas e não pode ser reiniciado no
mesmo orquestrador.

## Persistência e auditoria

A camada SQLite usa migrações versionadas por `PRAGMA user_version`, chaves
estrangeiras, WAL e transações aninhadas com savepoints. `Persistence` reúne
repositórios para execuções, eventos, métricas, achados e aprovações. Ao
fornecê-la ao orquestrador, os eventos passam a ser persistidos em SQLite e
exportados como JSON Lines:

```python
from core import CoreOrchestrator, Persistence

persistence = Persistence("data/sarr.sqlite3", "logs/audit.jsonl")
engine = CoreOrchestrator(persistence=persistence)
```

O audit registra `run.started`, `scope.validated`, `metric.sample`,
`safety.triggered`, `run.stopped` e `finding.created`. Os payloads são
allowlisted por tipo de evento; credenciais em chaves ou textos reconhecidos
são redigidas, e campos arbitrários não são exportados. Para exportar uma
cópia consistente do arquivo:

```python
persistence.export_jsonl("exports/audit.jsonl")
persistence.close()
```

## Ambiente Windows

O setup suportado nesta etapa é Windows x64 com CPython 3.10–3.15. Crie o
ambiente virtual na raiz do projeto, caso ainda não exista:

```bat
py -3.15 -m venv .venv
```

O comando acima é apenas o bootstrap para criar o venv. Depois disso, os
scripts em `scripts/` usam exclusivamente `.venv\Scripts\python.exe`.
`setup_windows.bat` instala dependências apenas de `requirements-lock.txt`,
com hashes SHA-256 obrigatórios, instala o projeto sem resolver dependências
novamente e executa a suíte:

```bat
scripts\setup_windows.bat
scripts\run_windows.bat
```

O lock contém wheels Windows x64 para CPython 3.10–3.15. O ambiente atualmente
validado neste workspace é CPython 3.15; versões anteriores devem ser
homologadas em máquina limpa antes de uma distribuição ampla.

Para executar o teste de importação diretamente:

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Para incluir também o smoke test (`smoke_test.py`), use:

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -p "*test*.py" -v
```

O setup Windows usa esse padrão para executar a suíte completa.

## CLI local

Execute os comandos da raiz do projeto usando sempre o Python do ambiente
virtual:

```bat
.venv\Scripts\python.exe -m sarr_core --status
.venv\Scripts\python.exe -m sarr_core --run-sim
.venv\Scripts\python.exe -m sarr_core.cli --gui
```

Também é possível chamar o módulo da CLI diretamente com
`.venv\Scripts\python.exe -m sarr_core.cli --status` ou `--run-sim`.

No Linux/macOS, o equivalente é
`.venv/bin/python -m sarr_core.cli --gui`. O diretório persistente usa
`LOCALAPPDATA` no Windows e segue `XDG_DATA_HOME` (ou `~/.local/share`) no
Linux; no macOS usa `~/Library/Application Support`.

`--gui` abre o painel Tk local com estado, CPU/RAM/RTT, eventos, início da
simulação de loopback e um botão de kill-switch. O módulo gráfico importa a
fachada de aplicação `sarr_core.simulation`; ele não manipula diretamente a
máquina de estados ou os repositórios do motor.

Para exportar o JSON da última execução persistida ou o schema do dashboard:

```bat
.venv\Scripts\python.exe -m sarr_core.cli --export-metadata
.venv\Scripts\python.exe -m sarr_core.cli --export-dashboard
```

Os metadados são exportados somente se houver uma execução no banco local, em
`data/exports/metadata-latest.json` (ou no diretório de dados resolvido). O
schema versionado em `schemas/dashboard.schema.json` é copiado para
`config/dashboard.schema.json`. As flags de exportação podem ser combinadas
com `--status` ou `--run-sim`.

A máquina de estados também está disponível pelo namespace público
`sarr_core.core` (`Engine`, `EngineState` e `RunContext`). Ela aplica o mesmo
grafo estrito de transições; validação de escopo e autorização de operações
continuam centralizadas em `CoreOrchestrator`, que é o fluxo recomendado para
execução real ou simulada.

`--status` não inicia uma execução. `--run-sim` cria um escopo temporário
restrito a `127.0.0.1`, valida-o pelo fluxo fail-closed do orquestrador e roda
uma única amostra do servidor de demonstração local. A simulação não envia
requisições para hosts externos.

## Diretório de dados

Por padrão, o motor usa o diretório persistente do usuário. Para modo portátil,
crie um arquivo vazio `portable.flag` ao lado do projeto ou executável; os
dados serão gravados em `data/` nesse diretório. A inicialização testa a
escrita e, se esse local não estiver disponível, emite aviso e tenta o
diretório persistente do usuário. Se ambos falharem, a execução é bloqueada.

## Preparação de release

O checklist atual e o status de prontidão estão em
[`release-checklist.md`](release-checklist.md). O estado é source-only: não
há executável portátil nem validação em uma máquina limpa nesta etapa.

## Simulação local de telemetria

Os cenários de resiliência usam exclusivamente um servidor HTTP vinculado a
`127.0.0.1`. O probe fixa o host e o caminho (`/telemetry`), sem aceitar URLs
externas, redirects ou destinos configuráveis:

```python
from core import (
    KillSwitch,
    LocalDemoServer,
    LocalTelemetryProbe,
    OperationalLimitEnforcer,
    TelemetryScenario,
)

# Use o run_id e os limites de uma execução validada em um fluxo real.
with LocalDemoServer(TelemetryScenario.NORMAL_LATENCY) as server:
    probe = LocalTelemetryProbe(
        port=server.port,
        run_id=run_id,
        limits=operational_limits,
        kill_switch=kill_switch,
    )
    sample = probe.sample()
```

`TelemetryScenario` oferece `NORMAL_LATENCY`, `HIGH_RTT`, `HIGH_5XX_RATE`,
`MISSING_TELEMETRY` e `MANUAL_INTERRUPTION`. Os limites de RTT e respostas 5xx
continuam sendo aplicados pelo `OperationalLimitEnforcer`; a falta de
telemetria e a interrupção manual acionam o kill-switch. Quando ele abre, o
circuit breaker rejeita novas amostras. O servidor restringe o número máximo
de requisições para manter os testes locais e limitados.

## Relatórios estruturados de auditoria

O serviço de relatórios monta um resumo de uma execução com escopo validado,
incluindo SHA-256 do arquivo de escopo, operador, módulos registrados como
executados, horários, agregados métricos, achados, eventos do kill-switch,
motivo de parada, limitações e recomendações defensivas. Dados sensíveis são
sanitizados antes da serialização. Os formatos JSON e CSV são suportados sem
dependências adicionais:

```python
from core import AuditReportService

report = AuditReportService(engine).build_report(run.run_id, operator="analyst")
AuditReportService.export_json(report, "reports/run.json")
AuditReportService.export_csv(report, "reports/run.csv")
```

Para registrar um módulo executado no relatório, use
`engine.record_module_execution(run_id, module_name)` durante uma execução
`RUNNING`; o módulo precisa estar autorizado pelo escopo validado.

## Inventário passivo Wi-Fi e Bluetooth/BLE

Os adaptadores `WifiInventoryAdapter` e `BluetoothGattInventoryAdapter`
importam somente arquivos JSON locais com inventários estruturados. Cada arquivo
precisa conter um registro de autorização com referência, aprovador, validade
UTC, allowlist explícita de endereços e atividade permitida. Os importadores
rejeitam inventários expirados, destinos fora da allowlist, campos extras,
chaves JSON duplicadas e propriedades GATT de escrita. Valores de
características/descriptors não são aceitos.

Estes adaptadores **não enumeram rádios nem fazem operações ao vivo**: não
escaneiam, associam, desautenticam, capturam credenciais, pareiam, leem
características GATT de dispositivos, injetam pacotes ou transmitem. A chamada
`collect_from_os()` falha explicitamente como stub não suportado. Somente os
datasets sintéticos em `tests/fixtures/` acompanham os testes; eles usam
identificadores localmente administrados e nomes marcados como sintéticos.

O registro de autorização importado é evidência documental declarada no
arquivo, não uma assinatura criptográfica verificada pelo motor. Antes de
importar inventários reais, o operador deve validar a referência contra a
aprovação formal da organização e fornecer apenas dados coletados de forma
autorizada e passiva.
