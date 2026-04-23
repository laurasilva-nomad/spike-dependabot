# Automação de correção Dependabot (npm — todas as severidades)

Automação em GitHub Actions que lista alertas **Dependabot** no ecosystem **npm** (severidades **Critical, High, Moderate, Low** com patch na API), aplica **um único PR** e documenta **estratégia** (bump direto, pin transitivo, override), **grafo** e **risco** (semver).

## O que é

- Workflow [`.github/workflows/cursor-security-fix.yml`](.github/workflows/cursor-security-fix.yml) executando `scripts/cursor-fixer.js` na raiz de pacotes configurada (`SECURITY_PACKAGE_ROOT`, padrão `javascript/`).
- Uso de **`gh`** com REST/GraphQL do GitHub para alertas abertos.
- **Branch fixa** `security/dependabot-remediation` e **um PR** por execução (reexecução pode só atualizar o corpo do PR se já existir head igual).

## O que resolve

- Reduz concorrência de PRs de segurança; consolida remediação.
- **Árvore de decisão (resumo):** dependência **direta** → `add` com versão fixa; **indireta** com profundidade **> 2** (heurística `npm ls` + fallback) ou **major** da versão resolvida para a corrigida → `pnpm.overrides` / `overrides` (npm) / `resolutions` (yarn); **indireta** rasa e sem salto major → pin do pacote na raiz; se o add falhar → override como fallback.
- Primeira linha do PR com **aviso de verificação manual** se algo falhar, o audit (`--audit-level low`) ainda acusar achados ou houver conflito de patches entre alertas do mesmo pacote.

## Como funciona

1. **Permissões:** `security-events: read`, `contents: write`, `pull-requests: write`. PAT opcional `GH_DEPENDABOT_ALERTS_TOKEN` se o `github.token` não enxergar alertas.
2. **Raiz de pacotes:** variável de repositório `SECURITY_PACKAGE_ROOT` ou input `package_root` no `workflow_dispatch`.
3. **Gerenciador:** detectado por lockfile (pnpm / yarn / npm) no passo de install do workflow.
4. **Script:** grupos por **nome de pacote**; **maior** semver entre patches retornados pela API, se **sem** conflito de major entre eles; filtra severidades abertas no conjunto `critical` / `high` / `moderate` / `low` (e `medium` vinda de mapeamentos GraphQL).
5. **Validação pós-mudança:** `pnpm audit` / `npm audit` com `--audit-level low` no diretório de pacotes.

### Variáveis e secrets

| Nome | Uso |
| --- | --- |
| `GH_REPO_TOKEN` / `GH_TOKEN` | `gh` e API. |
| `GH_DEPENDABOT_ALERTS_TOKEN` | PAT opcional. |
| `SECURITY_PACKAGE_ROOT` | Caminho do `package.json` alvo. |
| `DEFAULT_BRANCH` | Preenchido no workflow. |
| `CURSOR_TOKEN` | Opcional. |

### Validação manual

Node (`.nvmrc`), install alinhado ao lockfile, `audit --audit-level low`, testes/build do repositório.

### Reutilizar noutro repositório

1. Copiar workflow e manter `scripts/cursor-fixer.js` em `<ROOT>/scripts/`.
2. Dependência **`semver`** com versão exata no `package.json` da raiz onde o script roda.
3. Ajustar `SECURITY_PACKAGE_ROOT` e permissões.

### Cursor

- [`.cursor/rules/security-automation.mdc`](.cursor/rules/security-automation.mdc)
- Triagem manual: [`docs/verify-issues-dependabot.md`](docs/verify-issues-dependabot.md) — usar **`@docs/verify-issues-dependabot.md`** no chat.

### Limitações

- Só alerts **npm**. **Bump automático do “pai”** por registry não está implementado (apenas pin do vulnerável ou override); revisão humana para catalog/workspace e pins cirúrgicos `pai>filho`.
- Profundidade / versão resolvida dependem de `npm ls --json`; emlayouts só pnpm o fallback pode ser menos preciso.
- **Parent update** explícito (subir só o pacote pai quando ele ganha versão segura) segue recomendado no doc manual, não automatizado aqui.

## Licença

Conforme o repositório pai.
