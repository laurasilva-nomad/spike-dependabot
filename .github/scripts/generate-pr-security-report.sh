#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
JS="${ROOT}/javascript"
OUT="${RUNNER_TEMP:-/tmp}/pr-security-report.md"

cd "$JS"

write_clean_report() {
  local base_sha="$1"
  local diff_tip="${PR_HEAD_SHA:-HEAD}"
  pnpm audit --json > audit-full.json 2>/dev/null || true

  local high_crit
  high_crit=$(jq '[ (.vulnerabilities // {}) | to_entries[] | .value | select(.severity == "high" or .severity == "critical") ] | length' audit-full.json 2>/dev/null || echo "0")

  {
    echo "### 1. Contexto (audit)"
    echo
    echo "**Estado neste commit:** \`pnpm audit --audit-level=high\` → **0** vulnerabilidades High/Critical no lockfile."
    echo
    echo "Isso é **esperado** quando o PR já trouxe a correção (Dependabot, merge anterior ou ajuste manual): o pnpm não lista mais CVE nesse nível. **Não** é o workflow “ignorando” severidade — ele **pula só a remediação automática** (Cursor) porque não há o que alterar localmente; alertas Critical/High no GitHub Security tendem a aparecer como **fechados** quando o lockfile fica limpo."
    echo
    echo "| Métrica | Valor |"
    echo "|---------|-------|"
    echo "| High/Critical no \`pnpm audit\` (local) | ${high_crit} |"
    echo "| Diff analisado | \`${base_sha:0:7}...\` → \`${diff_tip:0:7}...\` (tip do PR) |"
    echo
    echo "Escopo de correção automática no job: **High** e **Critical**; com 0 pendentes, não há passos de fix."
    echo

    echo "### 2. Cadeias (resumo)"
    echo
    echo "_Com audit já limpo, não há pacote alvo para \`pnpm why\` neste job. Use o grafo de dependências do PR ou o alerta original no GitHub Security._"
    echo

    echo "### 3. Grafo / bump"
    echo
    DIFF_PKG=$(git -C "$ROOT" diff --no-color "${base_sha}"..."${diff_tip}" -- "javascript/package.json" 2>/dev/null || true)
    DIFF_LOCK=$(git -C "$ROOT" diff --no-color "${base_sha}"..."${diff_tip}" -- "javascript/pnpm-lock.yaml" 2>/dev/null || true)
    DIFF_YARN=
    if [[ -f "${ROOT}/javascript/yarn.lock" ]]; then
      DIFF_YARN=$(git -C "$ROOT" diff --no-color "${base_sha}"..."${diff_tip}" -- "javascript/yarn.lock" 2>/dev/null || true)
    fi

    if [[ -z "$DIFF_PKG" && -z "$DIFF_LOCK" && -z "$DIFF_YARN" ]]; then
      echo "Sem diff de manifest/lock **entre base e HEAD** (alterações já na base ou só fora de \`javascript/\`)."
    elif echo "$DIFF_PKG" | grep -qE '"overrides"|pnpm\.overrides'; then
      echo "Neste PR há **overrides** (\`pnpm.overrides\` ou \`overrides\`) em \`package.json\` (diff vs base)."
    elif [[ -n "$DIFF_PKG" ]]; then
      echo "Há mudança em **dependências diretas** em \`package.json\` vs base."
    elif [[ -n "$DIFF_LOCK" || -n "$DIFF_YARN" ]]; then
      echo "Correção refletida em **lockfile(s)** vs base (bump transitivo / resolução)."
    fi
    echo

    echo "### 4. Conclusão"
    echo
    OVERRIDES=$(jq -c '(.pnpm.overrides // .overrides // empty)' package.json 2>/dev/null || echo "")
    if [[ -n "$OVERRIDES" && "$OVERRIDES" != "{}" && "$OVERRIDES" != "null" ]]; then
      echo "**Ação:** \`pnpm.overrides\` / \`overrides\` presentes em \`javascript/package.json\`."
      echo
      echo "**Trecho:**
\`\`\`json
$(jq '(.pnpm.overrides // .overrides)' package.json)
\`\`\`"
    else
      echo "**Ação:** correção via versões declaradas e/ou lockfile (sem overrides ou não aplicável neste diff)."
    fi
    echo

    if [[ -n "$DIFF_PKG" ]]; then
      echo "**Diff \`package.json\` vs base (trecho):**
\`\`\`diff
$(echo "$DIFF_PKG" | head -n 120)
\`\`\`"
    fi
    if [[ -n "$DIFF_LOCK" ]]; then
      echo
      echo "**Lockfile pnpm (stat vs base):**"
      echo
      echo "\`\`\`"
      git -C "$ROOT" diff --stat "${base_sha}"..."${diff_tip}" -- "javascript/pnpm-lock.yaml" 2>/dev/null || true
      echo "\`\`\`"
    fi
    if [[ -n "${DIFF_YARN:-}" ]]; then
      echo
      echo "**yarn.lock (stat vs base):**"
      echo
      echo "\`\`\`"
      git -C "$ROOT" diff --stat "${base_sha}"..."${diff_tip}" -- "javascript/yarn.lock" 2>/dev/null || true
      echo "\`\`\`"
    fi
  } > "$OUT"
}

if [[ "${SECURITY_REPORT_AUDIT_CLEAN:-}" == "true" ]]; then
  if [[ -z "${PR_BASE_SHA:-}" ]]; then
    echo "PR_BASE_SHA é obrigatório em modo audit limpo" >&2
    exit 1
  fi
  write_clean_report "$PR_BASE_SHA"
  echo "$OUT"
  exit 0
fi

if [[ ! -f audit-report.json ]] || [[ ! -f audit-after.json ]]; then
  echo "audit-report.json e audit-after.json são obrigatórios (modo remediação)" >&2
  exit 1
fi

{
  echo "### 1. Contexto (audit)"
  echo
  echo "| Severidade | Pacote | Afetado | Após correção |"
  echo "|------------|--------|---------|----------------|"
  jq -s -r '
    .[0] as $before | .[1] as $after
    | ($before.vulnerabilities // {}) as $bv
    | ($after.vulnerabilities // {}) as $av
    | $bv
    | to_entries[]
    | select(.value.severity == "high" or .value.severity == "critical")
    | .key as $pkg
    | .value.severity as $sev
    | (.value.range // "-") as $range
    | ($av[$pkg].severity // "none") as $as
    | (
        if $as == "none" then "Resolvido (sumiu do audit)"
        elif ($as != "high" and $as != "critical") then "High/Critical sanado (restante: \($as))"
        else "Ainda \($as) no relatório — revisar"
        end
      ) as $st
    | "| \($sev) | `\($pkg)` | \($range) | \($st) |"
  ' audit-report.json audit-after.json
  echo
  echo "Escopo: **High** e **Critical** (demais severidades fora do escopo de correção automática)."
  echo

  echo "### 2. Cadeias (resumo)"
  echo
  if [[ -f why-context.txt ]] && [[ -s why-context.txt ]]; then
    echo "\`\`\`"
    cat why-context.txt
    echo "\`\`\`"
  else
    echo "_Sem why-context (pacote alvo ausente ou \`pnpm why\` sem saída útil)._"
  fi
  echo

  echo "### 3. Grafo / bump"
  echo
  DIFF_PKG=$(git -C "$ROOT" diff --no-color -- "javascript/package.json" 2>/dev/null || true)
  DIFF_LOCK=$(git -C "$ROOT" diff --no-color -- "javascript/pnpm-lock.yaml" 2>/dev/null || true)
  if echo "$DIFF_PKG" | grep -qE '"overrides"|pnpm\.overrides'; then
    echo "Foi aplicada estratégia de **pnpm.overrides** / **overrides** em \`package.json\` para fixar versões corrigidas sem depender só de bump em cadeias longas."
  elif echo "$DIFF_PKG" | grep -qE '^\+\s*"[^"]+":\s*"[^"]+"'; then
    echo "Há **alteração de versões** em dependências diretas (bump) e/ou ajuste propagado ao lockfile."
  elif [[ -n "$DIFF_LOCK" ]]; then
    echo "Correção refletida principalmente no **lockfile** (árvore transitiva / resolução pnpm)."
  else
    echo "Sem diff local de \`package.json\` neste job (validar se alterações já estavam commitadas ou só no lock)."
  fi
  echo

  echo "### 4. Conclusão"
  echo
  OVERRIDES=$(jq -c '(.pnpm.overrides // .overrides // empty)' package.json 2>/dev/null || echo "{}")
  if [[ -n "$OVERRIDES" && "$OVERRIDES" != "{}" && "$OVERRIDES" != "null" ]]; then
    echo "**Ação:** \`pnpm.overrides\` / \`overrides\` em \`javascript/package.json\`."
    echo
    echo "**Motivação:** forçar versões corrigidas nas linhas necessárias sem bump agressivo de dependências de topo que poderiam quebrar outras cadeias."
    echo
    echo "**Trecho de overrides:**
\`\`\`json
$(jq '(.pnpm.overrides // .overrides)' package.json)
\`\`\`"
  else
    echo "**Ação:** bump / resolução via dependências e lockfile (sem overrides no \`package.json\` após a correção)."
    echo
    echo "**Motivação:** a resolução do pnpm passou a trazer versões seguras pela árvore declarada."
  fi
  echo

  if [[ -n "$DIFF_PKG" ]]; then
    echo "**Diff \`package.json\` (trecho):**
\`\`\`diff
$(echo "$DIFF_PKG" | head -n 120)
\`\`\`"
  fi
  if [[ -n "$DIFF_LOCK" ]]; then
    echo
    echo "**Lockfile:** alterações em \`pnpm-lock.yaml\`."
    echo
    echo "\`\`\`"
    git -C "$ROOT" diff --stat -- "javascript/pnpm-lock.yaml" 2>/dev/null || true
    echo "\`\`\`"
  fi
} > "$OUT"

echo "$OUT"
