# SubExposure

[English](README.en.md) · CLI em Go para auditoria **autorizada** de indicadores de exposição web.

**Use somente em sistemas próprios ou com autorização explícita.** A descoberta padrão amplia o alvo para o domínio registrável e seus subdomínios: confirme que todo esse escopo está autorizado. Para somente o host informado, use `--no-subdomains`.

## Instalação

Requisitos para compilar: Go 1.26 ou superior. Para descoberta: [Subfinder](https://github.com/projectdiscovery/subfinder), instalado separadamente no PATH. Algumas fontes passivas precisam de chaves configuradas no próprio Subfinder. Os binários do SubExposure não incluem Subfinder.

```sh
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go build -trimpath -o subexposure ./cmd/subexposure
./subexposure scan example.com --no-subdomains
```

No Windows / PowerShell:

```powershell
go build -trimpath -o subexposure.exe ./cmd/subexposure
.\subexposure.exe scan https://app.example.com --no-subdomains
```

O repositório usa o nome local de módulo `subexposure`; compile a partir do clone. Não é necessário alterar o módulo para publicar no GitHub.

## Uso

```sh
subexposure scan example.com --output report.json
subexposure scan https://app.example.com --no-subdomains --format jsonl --output report.jsonl
subexposure scan example.com --workers 4 --rate 2 --timeout 15s --verbose
subexposure scan example.com --subfinder-path /opt/tools/subfinder
subexposure scan --help
```

Flags podem vir após o alvo ou antes dele (sem misturar as duas posições). Caminhos, query e fragmento da URL inicial são descartados. Somente domínios ASCII/punycode e portas padrão são aceitos; IPs literais, credenciais e portas personalizadas são rejeitados.

| Flag | Padrão | Limite / comportamento |
| --- | --- | --- |
| `--workers` | 10 | 1–50 hosts concorrentes |
| `--rate` | 5 | 0,1–50 requisições/s globais; burst 1; inclui redirects |
| `--timeout` | 8s | 1s–60s por operação HTTP, incluindo espera de rate limit, redirects e leitura |
| `--output` | stdout | Cria arquivo novo; não sobrescreve existente |
| `--format` | json | `json` (array) ou `jsonl` (um resultado por linha) |
| `--verbose` | false | Progresso estrutural em stderr |
| `--subfinder-path` | subfinder | Caminho do executável |
| `--no-subdomains` | false | Somente o host informado |

`--resume` fica para uma versão futura e não é aceito nesta versão. Ctrl+C cancela descoberta e trabalho pendente; durante o scan, fecha o relatório com resultados parciais. Códigos: 0 execução concluída (mesmo com achados/erros de hosts), 1 erro operacional, 2 argumento inválido, 130 cancelamento durante scan. Cancelamento durante descoberta retorna 1, sem relatório. JSONL é indicado para processamento incremental. A ordem dos hosts no relatório depende da concorrência.

## Fluxo e arquitetura

```text
cmd/subexposure → scope → subfinder → DNS A/AAAA → HTTPS (fallback HTTP)
                                                    ↓
                                   dois baselines aleatórios → detectores → report
```

- `internal/scope`: domínio registrável via `publicsuffix`, normalização e fronteira de domínio.
- `internal/subfinder`: processo externo, sem shell, `subfinder -silent -d <dominio>`; deduplicação e filtro de escopo. Máximo 10.000 hosts, 4 MiB de saída, 4 KiB por linha e 2 minutos de execução. Falhas abortam a descoberta.
- `internal/dns`: consulta A/AAAA; rejeita todo o host se qualquer IP for bloqueado. Bloqueia redes privadas, loopback, link-local, multicast, unspecified, documentação, benchmark, CGNAT e faixas especiais. IPv6 limitado a unicast público `2000::/3`, com exclusões.
- `internal/httpcheck`: valida IPs imediatamente antes de cada nova conexão e conecta ao IP numérico validado. Revalida DNS após cada redirect, inclusive em conexões reutilizadas. Não usa proxies de ambiente; valida certificados TLS. Até 5 redirects, somente no domínio raiz e portas padrão; bloqueia downgrade HTTPS→HTTP. Não mantém cookies, não envia credenciais e não executa JavaScript.
- `internal/exposure`: interface `Detector` com `Name()`, `Paths()` e `Match(path, body)`; registro em `Detectors()`. Adicione detectores ali, mantendo evidências fixas e sem conteúdo remoto.
- `internal/models` e `internal/report`: resultados estruturais e serialização incremental.

O probe prioriza HTTPS: qualquer resposta HTTP válida, inclusive 403/404/500, mantém esse protocolo. HTTP é tentado se o probe HTTPS falhar. Se ambos estiverem ativos, a versão HTTP não recebe uma segunda auditoria nesta versão. Erros de tentativa HTTPS permanecem no relatório mesmo quando o fallback funciona.

## Indicadores e privacidade

Somente GET de `/`, dois caminhos aleatórios inexistentes e os seis indicadores abaixo (mais redirects permitidos). Não há brute force DNS, clonagem, navegação de objetos Git, consulta SQLite ou download de repositórios.

| Indicador | Evidência |
| --- | --- |
| `/.git/HEAD` | Referência Git ou hash de HEAD |
| `/.git/config` | Seção core e estrutura repositoryformatversion |
| `/.env` | Pelo menos duas atribuições KEY=VALUE; nomes e valores omitidos |
| `/.hg/requires` | Pelo menos dois identificadores conhecidos de Mercurial |
| `/.svn/entries` | Estrutura XML ou formato legado SVN |
| `/.svn/wc.db` | Apenas assinatura `SQLite format 3`; não consulta banco |

Cada corpo é inspecionado somente em memória, até 64 KiB (um byte extra detecta truncamento). Respostas truncadas são inconclusivas. Nenhum corpo, header, query, destino de redirect, nome de variável ou segredo é gravado. `.env` produz apenas a descrição `KEY=[REDACTED]`. O relatório conserva host, protocolo, caminho fixo, detector, status, classificação, confiança e descrição estrutural. O transporte não descomprime respostas automaticamente. A leitura limitada pode deixar de reconhecer arquivos maiores; não há garantia de zerar buffers da memória gerenciada pelo Go.

## Classificações

| Resultado | Significado |
| --- | --- |
| EXPOSED | Assinatura estrutural forte; não prova exploração ou conteúdo completo |
| LIKELY_EXPOSED | Estrutura compatível, por exemplo `.env` ou SQLite |
| PROTECTED | HTTP 401/403; não confirma existência do arquivo |
| NOT_FOUND | HTTP 404/410 |
| SOFT_404 | Igual aos dois baselines consistentes, normalizando whitespace e caminho refletido |
| REDIRECT | Redirect observado ou bloqueado; conteúdo final não confirma exposição da origem |
| DNS_UNRESOLVED | Falha de resolução |
| CONNECTION_ERROR | Falha de conexão, TLS ou leitura |
| TIMEOUT | Limite de tempo excedido |
| INCONCLUSIVE | Rede bloqueada, truncamento, status inesperado, assinatura ausente ou baseline instável |

Confiança: HIGH para assinaturas fortes / baseline idêntico / 404; MEDIUM para padrões sugestivos ou acesso negado; LOW para incerteza. Não representa probabilidade estatística. Baselines dinâmicos podem impedir classificação positiva; não há comparação semântica de HTML. Falsos positivos e negativos continuam possíveis; valide achados no sistema autorizado.

Exemplo de resultado (não é resultado de auditoria real):

```json
{"host":"app.example.com","scheme":"https","path":"/.env","detector":"Env","classification":"LIKELY_EXPOSED","confidence":"MEDIUM","status":200,"evidence":"multiple KEY=[REDACTED] assignments; names and values omitted"}
```

## Testes e distribuição

```sh
go test ./...
go vet ./...
make dist
```

Testes usam respostas sintéticas e `httptest.Server`, sem auditar domínios externos. O acesso a loopback dos servidores de teste existe somente em transporte injetado nos testes, sem flag de bypass na CLI. Cobrem escopo, IPs, redirects, DNS de redirect, limites, timeout, soft-404, assinaturas e ausência de segredos nos resultados.

`make dist` gera Windows/Linux/macOS em amd64 e arm64, sem CGO. Sem Make, use [scripts/build.ps1](scripts/build.ps1) no PowerShell. A Action testa e compila em três sistemas em push/PR e disponibiliza builds como artefatos; não cria releases públicas. Execute `go test -race ./...` onde houver compilador C compatível.

## Publicar no GitHub

Após instalar o [GitHub CLI](https://cli.github.com/), dentro deste diretório:

```sh
gh auth login
gh repo create subexposure --public --source=. --remote=origin --push
```

Troque `--public` por `--private` se preferir. Não inclua relatórios reais no repositório. Licença [MIT](LICENSE).
