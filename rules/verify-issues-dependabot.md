# Análise de vulnerabilidades (Dependabot / pnpm audit) — bump vs override

**Comandos de audit são sempre do usuário:** o executor **não** roda `pnpm audit` nem `pnpm i && pnpm audit`. O usuário roda `pnpm audit` na raiz do monorepo e cola a saída (ou o alerta do Dependabot) na conversa para a análise. Qualquer validação com install + audit também fica a cargo do usuário.

Seguir [rules/dependencies.md](../rules/dependencies.md) (versão fixa, `pnpm add -E`). Escopo: só **crítica** e **alta**; moderate/low apenas listar, não corrigir.

**Ordem de decisão:**

1. **Grafo:** conferir a versão resolvida do vulnerável por pacote (npm package/v/versão ou npmgraph). Só recomendar bump se o grafo da versão mais nova mostrar a versão **corrigida**.
2. Preferir **patch/minor**; se só **major** resolver, descrever riscos antes.
3. Se bump não resolver (lockfile vulnerável ou outro pacote na cadeia sem update) → **aplicar só override** em `pnpm.overrides` e **explicar a motivação** ao usuário. **Não fazer bump** do pacote da cadeia quando o override for necessário: o bump pode quebrar outras libs que dependem desse pacote (ex.: bump do sass pode afetar swagger-ui-react). Aplicar apenas o override e **avisar o usuário** do risco de fazer o bump (pode quebrar lib que usa o pacote).
4. Subdep na raiz: tentar antes quando fizer sentido; senão override.
5. Validar: `pnpm run test` e `pnpm run start`.
6. **Step 6 obrigatório:** se existir qualquer override em `package.json` (raiz) ou `pnpm-workspace.yaml`, **executar a seção 6** (remover overrides antigos e validar com o usuário). Se não for possível executar, **avisar explicitamente o usuário** que ele precisa rodar o step 6 (ver seção 6).

---

## Premissas

- **Subdep (preferido a override):** `pnpm add -E <pacote>@<versão>` na raiz → `pnpm install` → remover a linha do package.json → `pnpm install` de novo (lockfile corrigido, package limpo).
- **Override:** `pnpm.overrides` na raiz, versão exata; só quando bump/subdep não resolver.
- Validação: `pnpm install` → `pnpm audit` → build → testes → (opcional) dev.

---

## 1. Contexto

- Nome do pacote vulnerável, versões afetadas e corrigidas (ex.: `serialize-javascript <=7.0.2` → `>=7.0.3`).
- Caminho completo (ex.: `nomad-backoffice > vite-plugin-pwa@1.0.3 > workbox-build@7.4.0 > serialize-javascript@6.0.2`).

---

## 2. Grafo e bump

**Fontes do grafo:** https://www.npmjs.com/package/<pacote>/v/<versão> ou https://npmgraph.js.org/?q=<pacote>.

Se uma versão patch/minor do pacote, no grafo, usar a versão **corrigida** do vulnerável → **bump resolve**. Preferir patch, depois minor; major só com riscos descritos. Se nenhuma usar a corrigida → subdep ou override.

---

## 3. Se bump não resolver

1. **Aplicar só override** em `pnpm.overrides` (ex.: `"rollup": "4.59.0"`). **Não fazer bump** do pacote da cadeia (ex.: não bumpar sass se for usar override de immutable): bump pode quebrar outras libs que usam esse pacote.
2. **Motivação no entregável:** frase clara do porquê do override. Se um bump foi **evitado** porque mesmo com bump seria necessário override: informar ao usuário que o bump **não foi aplicado** e que fazê-lo pode quebrar libs que dependem do pacote (ex.: “Bump do sass não foi aplicado: mesmo com bump seria necessário override de immutable; o bump pode quebrar libs que usam sass (ex.: swagger-ui-react). Aplicado apenas override de immutable.”).
3. Se viável, tentar antes subdep na raiz e remover; senão override.

---

## 4. Entregável

- **(a)** Pacote vulnerável e versões
- **(b)** Cadeia e versão resolvida por pacote (grafo)
- **(c)** Checagem no grafo (versões olhadas; bump patch/minor/major e riscos se major)
- **(d)** Conclusão: bump de X para Y | subdep na raiz e remover | override Z (aplicar já)
- **(e)** **Motivação** (obrigatório se override): por que bump não resolveu e por que override. Se um bump foi **evitado** (porque override já resolve e bump pode quebrar outras libs): avisar o usuário explicitamente — “Bump de X não foi aplicado: pode quebrar lib que usa X (ex.: Y). Aplicado apenas override de Z.”
- **(f)** Comando ou alteração (apenas override aplicado; **não** incluir bump quando override for a solução e bump puder quebrar dependentes)
- **(g)** O que testar (seção 5)

---

## 5. O que testar (mensagem para o usuário)

**Não use uma lista fixa.** Analise as **libs que foram alteradas** (bump, override ou subdep) e **redija para o usuário** o que ele deve testar, considerando o que pode ter sido impactado pelas alterações.

- **Sempre incluir:** `pnpm install`, `pnpm audit` (confirmar que crítica/alta sumiram).
- **Riscos por tipo de alteração:**
  - Bump/override de lib de **build** (vite, rollup, workbox, etc.) → build e, se aplicável, geração de PWA/service worker.
  - Bump/override de lib de **teste** (vitest, jest, etc.) → suíte de testes.
  - Bump/override de **runtime** (react, axios, etc.) → subir o app e checar fluxos principais.
  - Override que atinge **mais de uma cadeia** (ex.: rollup no vite e no workbox) → build completo + testes + dev; mencionar risco de quebra (ex.: PWA) e sugerir reverter o override se falhar.
- **Bump evitado (só override aplicado):** avisar o usuário que fazer o bump do pacote (ex.: sass) pode quebrar outras libs que o usam (ex.: swagger-ui-react); por isso foi aplicado apenas o override. Se o usuário quiser tentar o bump, avisar que deve testar as libs impactadas.
- **Subdep e remover:** incluir “após remover do package.json e `pnpm install`, rodar `pnpm audit` de novo”.
- **Se algo quebrar:** sugerir reverter e documentar.

Comandos como `pnpm run build`, `pnpm run test`, `pnpm run start` são **referência**; adapte a lista ao que faz sentido para as alterações feitas (ex.: se só override de serialize-javascript na cadeia do workbox, destacar build e PWA; se bump do vite, build + dev).

## 6. Após resolver criticidades: remover overrides antigos (executor faz)

**Branch de comparação:** `main`. Usar sempre essa base para identificar overrides antigos.

**Escopo:** só overrides que **não** foram introduzidos na branch atual. Comparar com `main`: overrides presentes em `main` (ou em arquivos não modificados nesta branch) ficam como candidatos a remoção; overrides que aparecem apenas nos arquivos alterados nesta branch **não** devem ser removidos.

**Passo (executor realiza):**

1. Listar overrides em `package.json` (`pnpm.overrides`).
2. Filtrar apenas os que já existiam em `main` (comparar com o estado desses arquivos em `main`).
3. Para cada override antigo: remover do arquivo correspondente e pedir ao usuário que rode `pnpm i && pnpm audit` e informe se a vulnerabilidade que esse override corrigia voltou a aparecer.
4. Se o usuário informar que **não** voltou → deixar removido. Se voltou → reverter (restaurar o override).
5. Repetir para o próximo até acabar a lista de overrides antigos.

Ao final, informar o usuário o que foi removido (e o que foi mantido porque o audit voltou a falhar). Lembrete: quem roda `pnpm i` e `pnpm audit` é sempre o usuário. Também informar onde a dependência é utilizada (caso seja uma dependência transitiva) e apontar alguns possíveis lugares para testar, exemplo: `charts.js` é uma dependência direta utilizada no componente `StatisticGraph`.

---

**Dados necessários:** saída do `pnpm audit` (rodado pelo usuário na raiz) ou alerta do Dependabot colada na conversa. Sem isso a análise não pode ser feita.
