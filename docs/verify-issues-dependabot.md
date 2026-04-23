# Guia: comando «Verify issues Dependabot»

Guia para o time usar análise de vulnerabilidades (**Dependabot** / audit local) no Cursor. Complementa a automação que abre **um único PR** (`security/dependabot-critical-high`) via Actions; este documento cobre **triagem manual**, quando você cola audit ou alertas na conversa.

---

## Relação com a automação (Actions)

| Automação (repo) | Análise manual (este guia) |
| --- | --- |
| Lê alertas Critical/High na API do GitHub, agrupa por pacote, tenta bumps no lock e abre **um PR** consolidado. | Você traz contexto (`pnpm audit` / alerta da UI), o Cursor sugere estratégia sem escrever no seu terminal sozinho. |
| Detecta gerenciador (pnpm / npm / yarn) no workflow. | Use na **raiz de pacotes** do repo (ex.: `javascript/` ou `.` conforme `SECURITY_PACKAGE_ROOT` no [`README.md`](../README.md)). |

Se o PR automático pedir **verificação manual** na primeira linha, siga este guia para validar antes do merge.

---

## Princípios

- **Comandos de audit são sempre do usuário:** o executor **não** roda `pnpm audit`, `npm audit` ou `install && audit` por conta própria na sua máquina. Você roda o audit na raiz correta do monorepo e cola a saída (ou o link/número do alerta Dependabot). Validação com install + audit fica com você.
- **Política de versões:** dependências diretas com **versão fixa** (sem `^`, `~`, ranges). Ver [README.md](../README.md). Exemplos: `pnpm add -E`, `npm install <pkg>@<versao> --save-exact`, `yarn add --exact`.
- **Escopo de severidade:** corrigir só **Critical** e **High**; **moderate** e **low** apenas listar, não priorizar correção neste fluxo.

---

## O que o comando / referência faz no Cursor

Orienta triagem técnica focada em Critical/High, em etapas:

1. **Step 0 — Ghost check:** confirmar se a lib ainda existe no grafo ou é resíduo no lockfile.
2. **Análise de grafo:** **bump** (versão fixa no manifest), **subdependência na raiz** (pin transitivo quando o fluxo do repo permitir) ou **override** (`pnpm.overrides` / `overrides` npm).
3. **Escopo:** definir se mexe em **workspace/catalog** (`pnpm-workspace.yaml`) ou só na **raiz** (`package.json`).
4. **Aplicar e validar:** você roda install + audit + testes conforme o tipo de mudança.
5. **Step 6 — Higiene:** revisar overrides antigos frente à `main` e limpar um a um se o audit não recriar a CVE.

**Bump:** resolver a versão segura (advisory «Patched versions», `npm view <pacote> version`, grafo). Use sempre pin explícito no comando de add — **não** `@latest` como única fonte de verdade em script reprodutível.

---

## Grafo e bump

Fontes úteis: página da versão no npm (`https://www.npmjs.com/package/<pacote>/v/<versão>`) e [npmgraph](https://npmgraph.js.org/) com o pacote.

---

## Como usar no Cursor

### 1. Rodar o audit

Na **raiz de pacotes** do projeto (mesma pasta do `package.json` que o time usa no dia a dia):

| Gerenciador | Comando típico |
| --- | --- |
| pnpm | `pnpm audit` |
| npm | `npm audit` |
| yarn | `yarn npm audit` ou equivalente da sua versão |

Copie os trechos **Critical** ou **High** (ou export JSON se preferir).

### 2. Contexto na conversa

- Referência: **`@docs/verify-issues-dependabot.md`** (este arquivo).
- Dados: saída do audit / texto do alerta Dependabot / número do alerta.

### 3. Step 0 (obrigatório)

Rodar na mesma raiz de pacotes:

| Gerenciador | Comando |
| --- | --- |
| pnpm | `pnpm why <pacote>` |
| npm | `npm ls <pacote> --all` |
| yarn | `yarn why <pacote>` (classic) ou `yarn npm why <pacote>` conforme Berry |

Se o pacote **não aparecer** no grafo como esperado, trate como **fantasma**: alinhar lock (`install`), não inventar bump em pacote órfão sem confirmar.

### 4. Aplicar e validar (sempre você)

1. Conforme o gerenciador: `pnpm install`, `npm install` ou `yarn install`, depois audit de novo na mesma raiz.
2. **Testes de impacto** (cruzar com o pacote alterado):

| Tipo de mudança | O que validar |
| --- | --- |
| Auth / HTTP client | Fluxos de login, chamadas ao BFF |
| Bundler / Vite / Nx | Build do app afetado |
| Test runner / DOM | Testes nos pacotes da cadeia |
| UI kit / formulários | Telas que usam esses componentes |
| Override ou subdependência opaca | Smoke na aplicação que puxa a cadeia + audit limpo |

Se nada disso se aplicar, pelo menos **build** ou **test** do workspace mais próximo no grafo.

---

## Onde aplicar a correção

| Local | Quando | Arquivo típico |
| --- | --- | --- |
| Workspace / catalog | Pacote versionado em workspace ou catalog em monorepo pnpm | `pnpm-workspace.yaml`, manifests dos pacotes |
| Raiz | Transitivo profundo; pin ou override na raiz | `package.json` (`pnpm.overrides` ou `overrides` npm) |

Regra prática: **preferir bump/subdep** antes de override permanente; override só quando o grafo não resolve só com bump.

---

## Step 6: overrides antigos (higiene)

Se houver overrides que já existiam na `main`:

1. O Cursor pode listar candidatos à remoção **um a um**.
2. Você remove a linha, roda install + audit.
3. Se a vulnerabilidade **não voltar**, mantém a remoção. Se voltar, restaura o override.

---

## Resumo de responsabilidades

| Quem | O quê |
| --- | --- |
| Você | Inclui `@docs/verify-issues-dependabot.md` + logs do audit ou alerta. |
| Você | Step 0: comando de grafo (`pnpm why` / equivalente) e resultado na conversa. |
| Cursor | Estratégia (bump / override / escopo), checklist de testes. |
| Você | Aplica mudanças, install, audit e testes de impacto. |
| Cursor (Step 6) | Quando aplicável, sugere experimentar remoção de overrides legados. |

**Atenção:** o Cursor **não substitui** sua execução local de comandos; sem Step 0 o risco é sugerir correção para pacote que não está mais no grafo.

---

_Dica: no VS Code / Cursor, `Ctrl+Shift+V` para preview Markdown._
