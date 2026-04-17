# Dependências

Regras para declaração de dependências e resolução de vulnerabilidades (Dependabot / pnpm audit).

## Versões

### Versão fixa em dependências diretas

Usar sempre versão fixa (ex.: `1.2.3`), sem ranges como `^` ou `~`, ao declarar dependência direta no projeto.

Ao adicionar com CLI, usar a flag de versão exata:

- **pnpm:** `pnpm add -E <pacote>@<versão>` (ou `pnpm add --save-exact`)

Aplica-se a `dependencies`, `devDependencies` e a overrides (`pnpm.overrides`).

✅ `"minimatch": "10.2.3"` | ❌ `"minimatch": "^10.2.3"`
✅ `"rollup": "4.59.0"` | ❌ `"rollup": "~4.59.0"`

### Overrides

Em `pnpm.overrides`, usar sempre versão exata (ex.: `"pacote": "1.2.3"`).

## Bump de pacotes

Ao fazer bump de um pacote (ex.: para corrigir vulnerabilidade), seguir as regras deste documento: versão fixa no `package.json` e, ao rodar o comando de adição, usar a flag de exatidão (`-E` no pnpm).
