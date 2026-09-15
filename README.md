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
