# Checklist de release e sumário executivo

Status baseado no código-fonte e nas verificações registradas neste workspace.
Este documento não representa certificação externa nem autorização para
execução fora do laboratório controlado.

## Checklist

- [x] A CLI exige escolha explícita entre `--status` e `--run-sim`; o script
  Windows de execução chama somente `--run-sim`.
- [x] A simulação documentada restringe o servidor/probe a `127.0.0.1`; os
  adaptadores Wi-Fi e Bluetooth/BLE importam somente arquivos JSON e não
  acessam rádios nem transmitem.
- [x] Expiração do escopo é reavaliada ao iniciar, consultar estado e iniciar
  operações/registrar execução de módulo; a falha aciona o kill-switch.
- [x] Dependências runtime e build estão em versões exatas. O setup Windows
  usa exclusivamente `.venv\Scripts\python.exe` e instala pelo
  `requirements-lock.txt` com `--require-hashes`.
- [x] O lock inclui hashes SHA-256 de wheels Windows x64 para CPython 3.10–3.15.
- [x] A documentação explicita limites: inventário sem coleta ao vivo,
  autorização declarada de inventários não é assinatura criptográfica, dados
  locais e simulação não substituem homologação formal.
- [x] A suíte no CPython 3.15.2 x64 passou: 75 testes (`unittest discover`
  incluindo `smoke_test.py`); os 6 cenários smoke também foram executados
  diretamente com sucesso.
- [x] `scripts\run_windows.bat` foi executado e concluiu uma amostra de
  telemetria apontada somente a `127.0.0.1`, com estado final `COMPLETED`.
- [ ] A invocação solicitada com `python -m pytest` não está disponível:
  `pytest` não está instalado no `.venv`. Não foi instalado via rede; os testes
  equivalentes são `unittest` e passaram localmente.
- [ ] Reexecutar setup e suíte numa máquina Windows limpa, sem dependências
  previamente instaladas; ainda não executado neste workspace.
- [ ] Gerar e validar um pacote/executável portátil; não existe artefato de
  distribuição nesta etapa.
- [ ] Revisar hashes do artefato final e publicá-los junto ao pacote após a
  geração; nenhum pacote foi gerado.

## Sumário executivo

**Prontidão: GO condicionado para homologação local isolada, somente a partir
do código-fonte. Não está pronto para release binária ou distribuição geral.**

O fluxo de simulação, os gates de escopo, o kill-switch, persistência/auditoria,
relatórios e importadores passivos estão cobertos por testes locais. A correção
de expiração impede iniciar e continuar operações após a janela autorizada. As
dependências estão fixadas e protegidas por hashes no caminho de setup Windows.

A validação realizada neste workspace comprova o comportamento na versão de
Python instalada aqui, não a compatibilidade efetiva em todas as versões
suportadas nem em uma instalação limpa. Antes de promover o MVP, execute
`scripts\setup_windows.bat`, confirme a suíte completa e o comando
`scripts\run_windows.bat` em uma máquina Windows x64 isolada; gere o pacote
portátil separadamente e verifique seu SHA-256. Não inclua credenciais ou
segredos reais em fixtures, configuração, logs ou artefatos.

O smoke test está implementado com `unittest`, que também é coletável pelo
pytest caso esse runner seja instalado em ambiente autorizado. Para manter
esta validação sem acesso externo, ele foi executado com
`.venv\Scripts\python.exe -m unittest tests.smoke_test -v`; a tentativa com
`-m pytest` confirmou que o runner não está presente.
