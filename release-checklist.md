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
- [x] Os testes da GUI e do motor passaram após a tradução da interface:
  12 testes GUI e 12 testes de transição/CLI, exceto a execução normal da CLI
  que depende dos arquivos de baseline em LF.
- [x] A documentação de apoio foi organizada em `docs/`, a captura do painel
  está em `assets/fluxograma-arquitetura.png` e a cópia duplicada do PDF foi removida após
  confirmar que os dois arquivos tinham o mesmo MD5.
- [x] A linha de base anterior às alterações passou com 132 testes.
- [ ] A suíte atual executou 139 testes: 8 falhas e 1 erro. Os testes de LF
  confirmam que os três arquivos de baseline ainda estão em CRLF no checkout;
  as falhas de auditoria e restauração dependem desses mesmos hashes.
- [ ] Reestabelecer manualmente o checkout LF dos arquivos JSON de baseline
  seguindo o passo final indicado no plano e repetir a suíte completa e a CLI.
- [ ] Reexecutar `scripts\run_windows.bat` depois de corrigir os arquivos de
  baseline; a validação atual da CLI normal termina em `BLOCKED` por causa da
  divergência de hashes.
- [ ] A invocação solicitada com `python -m pytest` não está disponível:
  `pytest` não está instalado no `.venv`. Não foi instalado via rede; os testes
  equivalentes são executados com `unittest`.
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
relatórios e importadores passivos têm cobertura de testes local. A validação
final está pendente porque os arquivos JSON de baseline no checkout atual usam
CRLF, enquanto os hashes portáveis revisados correspondem aos blobs LF do Git.
Não foi feita renormalização nem recheckout automático.

A validação realizada neste workspace comprova o comportamento na versão de
Python instalada aqui, não a compatibilidade efetiva em todas as versões
suportadas nem em uma instalação limpa. Antes de promover o MVP, conclua o
passo manual de normalização descrito acima e execute
`scripts\setup_windows.bat`, confirme a suíte completa e o comando
`scripts\run_windows.bat` em uma máquina Windows x64 isolada; gere o pacote
portátil separadamente e verifique seu SHA-256. Não inclua credenciais ou
segredos reais em fixtures, configuração, logs ou artefatos.

Os testes da GUI são ignorados automaticamente quando Tkinter não está
instalado; a CLI continua importável sem carregar a interface gráfica. O smoke
test está implementado com `unittest`, que também é coletável pelo pytest caso
esse runner seja instalado em ambiente autorizado.
