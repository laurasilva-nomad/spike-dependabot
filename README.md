# Automação de correção Dependabot (Critical / High)

Automação em GitHub Actions que lista alertas **Dependabot** em npm com severidade **Critical** ou **High**, aplica **um único PR** com bumps de versão indicados pela API do GitHub e documenta **onde cada pacote entra no grafo**, **heurística de múltiplos consumidores** e **risco de quebra** (semver).

## O que é

- Um workflow (`/.github/workflows/cursor-security-fix.yml`) que executa um script Node (`scripts/cursor-fixer.js` dentro da raiz de pacotes configurada).
- Integração com **`gh`** e REST/GraphQL do GitHub para ler alertas abertos (com fallback se a REST falhar).
- **Um branch** fixo (`security/dependabot-critical-high`) e **um PR** consolidando todas as correções possíveis na mesma execução — não há mais um PR por pacote.

## O que resolve

- Reduz número de PRs de segurança concorrentes e padroniza revisão em um só lugar.
- Encoraja versões **fixas** (`npm install pkg@x --save-exact`, `pnpm add -E`, `yarn add --exact`) alinhadas à política de dependências do time.
- Quando a automação falha, o audit local ainda acusa High/Critical ou há conflito de linhas semver, a **primeira linha da descrição do PR** exige **verificação manual obrigatória** antes do merge.

## Como funciona

1. **Permissões:** o job usa `security-events: read`, `contents: write`, `pull-requests: write`. Em organizações com políticas rígidas pode ser necessário um PAT em `GH_DEPENDABOT_ALERTS_TOKEN` com leitura de Dependabot alerts.
2. **Raiz de pacotes:** por padrão `javascript/` neste repositório. Em outros monorepos configure **Repository variable** `SECURITY_PACKAGE_ROOT` ou o input `package_root` no `workflow_dispatch` (ex.: `.` para raiz).
3. **Gerenciador de pacotes:** o workflow detecta pelo lockfile na raiz configurada:
   - `pnpm-lock.yaml` ou workspace pnpm na raiz do repo → **pnpm**
   - `yarn.lock` → **yarn**
   - caso contrário → **npm**
4. **Script:** resolve a raiz git (`GITHUB_WORKSPACE` no Actions ou subindo diretórios até `.git`), resolve `SECURITY_PACKAGE_ROOT`, agrupa alertas npm Critical/High por **nome de pacote**, escolhe a **maior** versão patch entre os identificadores retornados pela API quando compatíveis; se as patches indicam **majors incompatíveis**, não faz bump automático daquele pacote e registra na seção de falhas.
5. **PR único:** branch `security/dependabot-critical-high`, título do tipo `security: Dependabot Critical/High (N alertas, K pacotes)`. Reexecução atualiza descrição via `gh pr edit` se o PR já existir.

### Variáveis e secrets úteis

| Nome | Uso |
| --- | --- |
| `GH_REPO_TOKEN` / `GH_TOKEN` | Autenticação `gh` (no Actions costuma ser `github.token`). |
| `GH_DEPENDABOT_ALERTS_TOKEN` | PAT opcional se o token padrão não ler alertas. |
| `SECURITY_PACKAGE_ROOT` | Caminho relativo ao `package.json` alvo (env no job ou variável de repositório). |
| `DEFAULT_BRANCH` | Definido pelo workflow a partir da default branch do repositório. |
| `CURSOR_TOKEN` | Opcional; reservado para integrações futuras com Cursor Cloud. |

### Validação manual (operador)

Independente da primeira linha do PR, o time deve:

- Alinhar **versão de Node** (`.nvmrc`, `.node-version`, documentação do produto).
- Rodar o mesmo **install** que o CI (`pnpm install`, `npm ci`, `yarn install`).
- Executar **testes e build** definidos no `package.json`.

### Reutilizar em outro repositório

1. Copie `.github/workflows/cursor-security-fix.yml` e o diretório `scripts/` para **dentro da raiz de pacotes** desejada **ou** ajuste `SECURITY_PACKAGE_ROOT` e mantenha o script em `<ROOT>/scripts/cursor-fixer.js`.
2. Garanta dependência **`semver`** em `package.json` da raiz onde o script roda (`npm install semver --save-exact`).
3. Configure permissões e secrets conforme a tabela acima.

### Cursor / IDE

- Regras globais: `.cursor/rules/security-automation.mdc`.
- **Triagem manual** (audit colado na conversa, Step 0, overrides, testes de impacto): [`docs/verify-issues-dependabot.md`](docs/verify-issues-dependabot.md). No chat, use **`@docs/verify-issues-dependabot.md`** para carregar o protocolo completo.

### Limitações explícitas

- Só ecosystem **npm** nos alertas.
- Não gera **overrides** automáticos (`pnpm.overrides` / npm `overrides`) quando o grafo exige pin cirúrgico ou majors conflitantes.
- Heurística “múltiplos consumidores” é baseada no tamanho/complexidade da saída de `pnpm why` / `npm ls`, não substitui revisão humana.

## Licença

Conforme o repositório pai.
