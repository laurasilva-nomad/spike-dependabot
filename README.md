# Security Fixer Automation

> **Remediação Proativa de Vulnerabilidades com Self-Healing PRs.**

Este repositório implementa um modelo **Automated-Proactive** de remediação de segurança. O objetivo é transformar o processo manual de correção de vulnerabilidades num fluxo de [Self-Healing PRs](https://dev.to/akhil_mittal/self-healing-architecture-aws-24ao), eliminando o esforço manual repetitivo e reduzindo o volume de Pull Requests individuais abertos pelo Dependabot.

---

## Fluxo do Script

Para entender como a engine processa cada vulnerabilidade, consulte o diagrama abaixo:

![Fluxo do Script Cursor-fixer](Captura%20de%20tela%20de%202026-04-29%2012-43-15.png)

---

## O que este projeto resolve?

- **Consolidação Inteligente:** Agrupa múltiplos alertas (Critical a Low) num **único PR** na branch fixa `security/dependabot-remediation`.
- **Análise de Grafo:** Identifica se a vulnerabilidade é direta ou transitiva e escolhe a melhor estratégia de correção.
- **Validação de Integridade:** Diferente do Dependabot padrão, este script roda seus scripts de `build` e `test` antes de sugerir a correção.
- **Multi-Gerenciador:** Suporte nativo e automático para `npm`, `pnpm` e `yarn`.

---

## Estratégia de Remediação (Árvore de Decisão)

A engine `cursor-fixer.js` analisa o grafo de dependências e aplica o princípio de **Shift-Left Security**:

| Cenário                            | Ação Realizada             | Comando / Técnica                       |
| :--------------------------------- | :------------------------- | :-------------------------------------- |
| **Dependência Direta**             | Atualização de versão fixa | `add --save-exact`                      |
| **Indireta Rasa (≤ 2 níveis)**     | Pin do pacote na raiz      | `add` (transitivo)                      |
| **Indireta Profunda (> 2 níveis)** | Injeção de Resolução       | `overrides` ou `resolutions`            |
| **Major Leap (Salto de Versão)**   | Override de Segurança      | Força versão patchada no `package.json` |

> [!IMPORTANT]
> **Fallback de Segurança:** Se um comando de atualização falhar, o script injeta automaticamente o override como contingência para garantir a remediação.

---

## Configuração e Setup

### 1. Personal Access Token (PAT)

O `GITHUB_TOKEN` padrão tem limitações. Configure um **Fine-grained PAT** com as seguintes permissões:

- `Dependabot alerts`: **Read-only**
- `Contents`: **Write**
- `Pull requests`: **Write**

### 2. Secrets do Repositório

No GitHub, vá em _Settings > Secrets and variables > Actions_:

| Secret                       | Descrição                                             |
| :--------------------------- | :---------------------------------------------------- |
| `GH_DEPENDABOT_ALERTS_TOKEN` | O PAT gerado no passo anterior (Obrigatório).         |
| `SECURITY_PACKAGE_ROOT`      | Caminho do `package.json` (Ex: `javascript/` ou `.`). |

---

## Integração com Cursor AI

Para triagem manual ou casos onde a automação exige supervisão humana (ex: conflitos de build):

1. **Contexto de Segurança:** Use `@docs/verify-issues-dependabot.md` no chat do Cursor.
2. **Regras de Automação:** O ficheiro `.cursor/rules/security-automation.mdc` orienta a IA sobre as políticas da empresa.

---

## Como funciona o Workflow

1. **Deteção:** Identifica o gerenciador (`pnpm`, `npm`, `yarn`) e mapeia o grafo de dependências em cache.
2. **Consolidação:** Agrupa alertas por pacote e seleciona a maior versão segura da API.
3. **Aplicação:** Cria a branch e aplica as correções (Bumps ou Overrides).
4. **Validação Técnica:** Executa `npm run build` e `npm run test`.
5. **Audit Final:** Executa `audit --audit-level low`. Se persistirem vulnerabilidades ou o build falhar, o PR é marcado com um aviso de **verificação manual**.

---

## Licença

Conforme o repositório pai.
