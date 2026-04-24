# Automação de Correção Dependabot (pnpm, npm, yarn)

Este repositório implementa um modelo **Automated-Proactive** de remediação de segurança. O objetivo é transformar o processo manual de correção de vulnerabilidades em um fluxo de [Self-Healing PRs](https://dev.to/akhil_mittal/self-healing-architecture-aws-24ao), eliminando o [Toil manual](https://sre.google/sre-book/eliminating-toil/) (fluxo manual repetitivo) e reduzindo o gargalo de escala de prs abertos por alertas do dependabot entre múltiplos repositórios.

A premissa principsl é utilizar os alertas do dependabot para que o worflow analise e crie um PR com a melhor resolução possível com auxilio do Cursor, solicitando intervenção humana em casos necessários.

## O que é

- **Workflow:** [`.github/workflows/cursor-security-fix.yml`](.github/workflows/cursor-security-fix.yml) que orquestra a detecção e remediação.
- **Engine:** `scripts/cursor-fixer.js` para análise profunda de grafo e aplicação de patches inteligentes.
- **Estratégia:** Consolida múltiplos alertas (Critical a Low) em **um único PR** na branch fixa `security/dependabot-remediation`, evitando a fadiga de notificações e reduzindo a concorrência de PRs.

## O que resolve (Árvore de Decisão)

A automação segue princípios de **Shift-Left Security**, detectando o gerenciador local e aplicando a correção com base na estrutura do grafo de dependências:

1.  **Dependência direta:** Executa `add` com versão fixa (ex: `pnpm add -E`, `npm install --save-exact` ou `yarn add --exact`).
2.  **Indireta profunda (> 2 níveis) ou Major Leap:** Aplica automaticamente blocos de `overrides` (npm/pnpm) ou `resolutions` (yarn).
3.  **Indireta rasa:** Realiza o pin do pacote na raiz via comando de instalação do gerenciador.
4.  **Fallback:** Se o comando de `add` falhar, o script injeta o `override` no `package.json` como contingência de segurança.

---

## Configuração e Setup (Implementação)

Para que o workflow consiga ler os alertas de segurança e abrir Pull Requests, é necessário configurar as permissões de acesso via Secrets.

### 1. Gerar Personal Access Token (PAT)
O `GITHUB_TOKEN` padrão pode ter limitações para ler alertas de segurança. Utilize um **Fine-grained PAT**:
1.  Acesse [GitHub Settings > Personal Access Tokens](https://github.com/settings/personal-access-tokens).
2.  Configure as seguintes permissões para os repositórios alvo:
    - `Dependabot alerts`: **Read-only**.
    - `Pull requests`: **Write**.
    - `Contents`: **Write**.

### 2. Configurar Secrets no Repositório
No repositório do projeto, vá em **Settings > Secrets and variables > Actions** e adicione:

| Secret | Descrição |
| :--- | :--- |
| `GH_DEPENDABOT_ALERTS_TOKEN` | O PAT gerado no passo anterior (obrigatório para leitura via API). |
| `CURSOR_TOKEN` | Opcional (para integrações de IA com o Cursor). |

---

## Como funciona

1.  **Detecção de Raiz:** Utiliza a variável `SECURITY_PACKAGE_ROOT` (padrão `javascript/`) para localizar o `package.json`.
2.  **Detecção de Gerenciador:** Identifica automaticamente se o projeto usa `pnpm`, `yarn` ou `npm` através dos arquivos de lockfile.
3.  **Consolidação de Patches:** Agrupa alertas por pacote e seleciona a maior versão segura informada pela API do GitHub, validando conflitos de Major.
4.  **Validação de Audit:** Após a mudança, o workflow executa `audit --audit-level low`. Se ainda houver achados, o PR é marcado com um aviso de **verificação manual obrigatória**.

---

## Integração com Cursor

Para triagem manual ou casos onde a automação exige supervisão:
- **Regras de Contexto:** [`.cursor/rules/security-automation.mdc`](.cursor/rules/security-automation.mdc).
- **Guia Mestre:** [`docs/verify-issues-dependabot.md`](docs/verify-issues-dependabot.md).
- **Uso:** Invoque `@docs/verify-issues-dependabot.md` no chat do Cursor para seguir o runbook de remediação manual alinhado à política da empresa.

---

## Limitações
- **Parent Update:** A automação prioriza a segurança imediata via `overrides`; a atualização de pacotes "pais" para resolver transitivas de forma nativa ainda é recomendada via fluxo manual.

## Licença
Conforme o repositório pai.