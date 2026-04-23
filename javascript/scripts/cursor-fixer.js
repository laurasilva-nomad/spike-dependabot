const path = require('path');
const fs = require('fs');
const os = require('os');
const semver = require('semver');
const { execSync, execFileSync } = require('child_process');

const SEVERITY_ORDER = { critical: 0, high: 1 };
const REPO_ROOT = path.join(__dirname, '..', '..');
const PKG_ROOT = path.join(REPO_ROOT, 'javascript');
const RULES_MDC = path.join(
  REPO_ROOT,
  '.cursor',
  'rules',
  'verify-issues-dependabot.mdc'
);
const RULES_MD = path.join(REPO_ROOT, 'rules', 'verify-issues-dependabot.md');

function tokenFromEnv(env) {
  return (
    env.GH_DEPENDABOT_ALERTS_TOKEN ||
    env.GH_REPO_TOKEN ||
    env.GH_TOKEN ||
    env.GITHUB_TOKEN ||
    ''
  );
}

function resolveGhToken() {
  return tokenFromEnv(process.env);
}

function envWithGhCliAuth(env) {
  const out = { ...env };
  const token = tokenFromEnv(out);
  if (token) out.GH_TOKEN = token;
  return out;
}

function logPreflightAuth() {
  console.log(
    JSON.stringify({
      secrets_GH_DEPENDABOT_ALERTS_TOKEN_set: Boolean(process.env.GH_DEPENDABOT_ALERTS_TOKEN),
      GH_REPO_TOKEN_set: Boolean(process.env.GH_REPO_TOKEN),
      GH_TOKEN_set: Boolean(process.env.GH_TOKEN),
      GITHUB_TOKEN_set: Boolean(process.env.GITHUB_TOKEN),
    })
  );
}

function assertGhAuthOrExit() {
  if (!tokenFromEnv(process.env)) {
    console.error(
      'Sem token para gh: no Actions use job env GH_REPO_TOKEN e/ou step env GH_TOKEN (github.token); opcional PAT GH_DEPENDABOT_ALERTS_TOKEN.'
    );
    process.exit(1);
  }
}

function exec(cmd, options = {}) {
  const mergedEnv = envWithGhCliAuth({ ...process.env, ...(options.env || {}) });
  return execSync(cmd, {
    encoding: 'utf8',
    cwd: options.cwd ?? PKG_ROOT,
    env: mergedEnv,
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: true,
  });
}

function pnpmExec(args, cwd = PKG_ROOT) {
  return execFileSync('pnpm', args, {
    cwd,
    encoding: 'utf8',
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

function ghPrCreate(baseBranch, headBranch, title, body) {
  const mergedEnv = envWithGhCliAuth(process.env);
  execFileSync(
    'gh',
    ['pr', 'create', '--base', baseBranch, '--head', headBranch, '--title', title, '--body', body],
    {
      cwd: PKG_ROOT,
      env: mergedEnv,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }
  );
}

function readTextIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

function stripMdcFrontmatter(text) {
  if (!text.startsWith('---\n')) return text;
  const end = text.indexOf('\n---\n', 4);
  if (end === -1) return text;
  return text.slice(end + 5).trimStart();
}

function rulesContent() {
  if (fs.existsSync(RULES_MDC)) return stripMdcFrontmatter(readTextIfExists(RULES_MDC));
  return readTextIfExists(RULES_MD);
}

function ghRepoSlug() {
  const envRepo = process.env.GITHUB_REPOSITORY;
  if (envRepo && envRepo.includes('/')) return envRepo.trim();
  try {
    return exec('gh repo view --json nameWithOwner -q .nameWithOwner', {
      cwd: REPO_ROOT,
    }).trim();
  } catch {
    throw new Error(
      'Defina GITHUB_REPOSITORY (ex.: org/repo) ou use gh em um clone com remote origin.'
    );
  }
}

function ghApiVersion() {
  return process.env.GITHUB_API_VERSION || '2022-11-28';
}

function dependabotAlertsRestPath(slug, page) {
  const q = new URLSearchParams({
    state: 'open',
    per_page: '100',
    page: String(page),
  });
  return `/repos/${slug}/dependabot/alerts?${q.toString()}`;
}

function dependabotAlertsUiUrl(slug) {
  return `https://github.com/${slug}/security/dependabot`;
}

function dependabotAlertPermalink(alertNumber) {
  return `https://github.com/${ghRepoSlug()}/security/dependabot/${alertNumber}`;
}

function workspaceCatalogHint(workspaceYaml, pkgName) {
  if (!workspaceYaml || workspaceYaml.length === 0 || !pkgName) return false;
  if (!/\bcatalog\b/i.test(workspaceYaml)) return false;
  return workspaceYaml.includes(pkgName);
}

function vulnerableRangeFromAlert(alert) {
  const vr = alert.security_vulnerability?.vulnerable_version_range;
  if (vr) return String(vr);
  const vulns = alert.security_advisory?.vulnerabilities;
  if (Array.isArray(vulns) && vulns[0]?.vulnerable_version_range) {
    return String(vulns[0].vulnerable_version_range);
  }
  return '—';
}

function isDirectJsDependency(pkgName) {
  const raw = readTextIfExists(path.join(PKG_ROOT, 'package.json'));
  if (!raw) return false;
  try {
    const j = JSON.parse(raw);
    const keys = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
    for (const k of keys) {
      const block = j[k];
      if (block && Object.prototype.hasOwnProperty.call(block, pkgName)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

function pnpmWhySummary(pkgName) {
  try {
    const out = pnpmExec(['why', pkgName]);
    const lines = out
      .trim()
      .split(/\r?\n/)
      .filter((l) => {
        const t = l.trim();
        return t.length > 0 && !/^Legend:/i.test(t);
      })
      .slice(0, 28);
    if (lines.length === 0) return '_Sem saída útil do `pnpm why`._';
    return lines.map((l) => `- ${l.trim()}`).join('\n');
  } catch {
    return '_`pnpm why` falhou._';
  }
}

function pnpmOverridesSnippet() {
  const raw = readTextIfExists(path.join(PKG_ROOT, 'package.json'));
  if (!raw) return '';
  try {
    const j = JSON.parse(raw);
    const o = j.pnpm?.overrides;
    if (!o || typeof o !== 'object' || Object.keys(o).length === 0) return '';
    return ['', 'Trecho `pnpm.overrides` atual no manifest:', '', '```json', JSON.stringify({ pnpm: { overrides: o } }, null, 2), '```', ''].join('\n');
  } catch {
    return '';
  }
}

function mdEscapePipe(s) {
  return String(s).replace(/\|/g, '\\|');
}

function maxPatchedVersionStrings(ids) {
  const uniq = [...new Set(ids)].filter(Boolean);
  if (uniq.length === 0) return '';
  let best = uniq[0];
  for (let i = 1; i < uniq.length; i++) {
    const av = semver.coerce(best);
    const bv = semver.coerce(uniq[i]);
    if (av && bv) {
      if (semver.gt(bv, av)) best = uniq[i];
    } else if (!av && bv) best = uniq[i];
  }
  return best;
}

function formatSecurityPrBody(opts) {
  const alerts =
    opts.alerts && opts.alerts.length > 0 ? opts.alerts : opts.alert ? [opts.alert] : [];
  const lines = [
    '## Contexto',
    '',
    '**Um PR por pacote.** A versão aplicada é a **maior** (semver) entre os patches que a API do Dependabot devolve para cada alerta na tabela — um bump cobre todos quando a linha de versão é compatível.',
    '',
    '| Alerta | Sev | Intervalo (advisory) | Patch indicado (API) |',
    '| --- | --- | --- | --- |',
  ];
  for (const a of alerts) {
    const an = a.number ?? 0;
    const sev = a.security_advisory?.severity ?? '—';
    const vr = mdEscapePipe(vulnerableRangeFromAlert(a));
    const pv = patchedVersionFromAlert(a) || '—';
    lines.push(`| [#${an}](${dependabotAlertPermalink(an)}) | ${sev} | ${vr} | \`${pv}\` |`);
  }
  lines.push(
    '',
    `**Pacote:** \`${opts.pkgName}\` · **versão única neste PR:** \`${opts.targetVersion}\` · manifest \`javascript/package.json\` · lock \`javascript/pnpm-lock.yaml\`.`,
    '',
    '- Escopo do workflow: alertas **critical/high** (npm).',
    '',
    '## Cadeias (resumo)',
    '',
    opts.whySummary,
    '',
    '## Grafo / bump',
    '',
  );

  if (opts.ghost) {
    lines.push(
      '`pnpm why --json` não encontrou grafo estável (órfão / lock inconsistente). Foi rodado `pnpm install --no-frozen-lockfile` para alinhar lock ao manifest; revisar se ainda falta bump explícito ou override.'
    );
  } else if (opts.wasDirectBefore) {
    lines.push(
      `Dependência **direta** em \`javascript/package.json\` antes deste PR: bump com \`pnpm add -E ${opts.pkgName}@${opts.targetVersion}\` mantém pin exato (sem \`^\`).`
    );
  } else {
    lines.push(
      `Antes do PR o pacote **não** estava como dependência direta no manifest; veio como **transitivo**. Subir apenas pacotes “do topo” pode não corrigir todas as linhas — aqui \`pnpm add -E ${opts.pkgName}@${opts.targetVersion}\` fixa manifest + lock.`,
      '',
      'Duas linhas incompatíveis do mesmo pacote (ex. picomatch 2.x e 4.x) podem exigir **pnpm.overrides** cirúrgicos; este fluxo não gera overrides automáticos.'
    );
  }

  if (opts.catalogHint) {
    lines.push(
      '',
      '**Catalog:** workspace com **catalog** + nome no YAML — alinhar também no bloco `catalog` se for a fonte da verdade.'
    );
  }

  const conclusaoSteps = opts.ghost
    ? [
        '1. Branch a partir da default branch atualizada.',
        '2. `pnpm install --no-frozen-lockfile` após detecção de grafo instável.',
      ]
    : [
        '1. `git fetch` + reset para `origin/<default>`.',
        `2. \`pnpm add -E ${opts.pkgName}@${opts.targetVersion} --ignore-scripts\`.`,
        '3. `pnpm install --no-frozen-lockfile`.',
        '4. `pnpm audit --audit-level high` (checagem local; CI manda).',
      ];
  lines.push('', '## Conclusão', '', conclusaoSteps.join('\n'));
  if (opts.auditResidualHighGate && !opts.ghost) {
    lines.push(
      '',
      '`pnpm audit --audit-level high` ainda acusa algo após o bump: pode ser transitiva remanescente, outro CVE ou pacote fora deste PR.'
    );
  }
  const overSnip = pnpmOverridesSnippet();
  if (overSnip) lines.push(overSnip);
  lines.push('', '**Antes do merge:** changelog se não for só patch; CI verde.');
  return lines.join('\n');
}

function dependabotAlertsRestApiUrl(slug) {
  return `https://api.github.com/repos/${slug}/dependabot/alerts`;
}

function ghRestHeadersCmdPrefix() {
  return [
    'gh api',
    '-H',
    JSON.stringify('Accept: application/vnd.github+json'),
    '-H',
    JSON.stringify(`X-GitHub-Api-Version: ${ghApiVersion()}`),
  ].join(' ');
}

function fetchDependabotAlertsRest(slug) {
  const all = [];
  let page = 1;
  for (;;) {
    const pathAndQuery = dependabotAlertsRestPath(slug, page);
    const cmd = [ghRestHeadersCmdPrefix(), JSON.stringify(pathAndQuery)].join(' ');
    const chunk = exec(cmd);
    const arr = JSON.parse(chunk);
    if (!Array.isArray(arr) || arr.length === 0) break;
    all.push(...arr);
    if (arr.length < 100) break;
    page += 1;
  }
  return all;
}

function graphqlSeverityToRest(sev) {
  if (!sev) return 'unknown';
  const u = String(sev).toUpperCase();
  const map = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    MODERATE: 'medium',
    LOW: 'low',
    INFORMATIONAL: 'low',
  };
  return map[u] || String(sev).toLowerCase();
}

function graphqlEcosystemToRest(eco) {
  if (!eco) return 'npm';
  return String(eco).toLowerCase();
}

function mapGraphqlNodeToRestAlert(node) {
  const pkg = node.securityVulnerability?.package;
  const ident = node.securityVulnerability?.firstPatchedVersion?.identifier;
  const name = pkg?.name || '';
  const eco = graphqlEcosystemToRest(pkg?.ecosystem);
  const sev = graphqlSeverityToRest(node.securityAdvisory?.severity);
  return {
    number: node.number,
    dependency: {
      package: {
        ecosystem: eco,
        name,
      },
    },
    security_advisory: {
      severity: sev,
      vulnerabilities:
        name.length > 0
          ? [
              {
                package: { name },
                first_patched_version: ident ? { identifier: ident } : undefined,
              },
            ]
          : [],
    },
    security_vulnerability: ident
      ? {
          first_patched_version: { identifier: ident },
        }
      : undefined,
  };
}

function graphqlRequest(bodyObj) {
  const f = path.join(os.tmpdir(), `ghgql-${process.pid}-${Date.now()}.json`);
  fs.writeFileSync(f, JSON.stringify(bodyObj));
  try {
    return exec(`gh api graphql --input ${JSON.stringify(f)}`);
  } finally {
    fs.unlinkSync(f);
  }
}

function fetchDependabotAlertsGraphql(slug) {
  const slash = slug.indexOf('/');
  const owner = slash === -1 ? '' : slug.slice(0, slash);
  const name = slash === -1 ? '' : slug.slice(slash + 1);
  if (!owner || !name) throw new Error('GITHUB_REPOSITORY inválido (esperado owner/nome).');
  const query = `
query($owner:String!,$name:String!,$after:String){
  repository(owner:$owner,name:$name){
    vulnerabilityAlerts(first:100,states:[OPEN],after:$after){
      pageInfo{hasNextPage endCursor}
      nodes{
        number
        securityAdvisory{severity}
        securityVulnerability{
          package{name ecosystem}
          firstPatchedVersion{identifier}
        }
      }
    }
  }
}`.replace(/\s+/g, ' ');
  let after = null;
  const mapped = [];
  for (;;) {
    const raw = graphqlRequest({
      query,
      variables: { owner, name, after },
    });
    const parsed = JSON.parse(raw);
    if (parsed.errors?.length) {
      throw new Error(parsed.errors.map((e) => e.message).join('; '));
    }
    const repo = parsed.data?.repository;
    if (!repo?.vulnerabilityAlerts) break;
    const conn = repo.vulnerabilityAlerts;
    const nodes = conn.nodes || [];
    for (const n of nodes) {
      mapped.push(mapGraphqlNodeToRestAlert(n));
    }
    if (!conn.pageInfo?.hasNextPage || !conn.pageInfo?.endCursor) break;
    after = conn.pageInfo.endCursor;
  }
  return mapped;
}

function fetchDependabotAlerts() {
  const slug = ghRepoSlug();
  try {
    const rest = fetchDependabotAlertsRest(slug);
    console.log(`REST: ${rest.length} alerta(s) aberto(s).`);
    return rest;
  } catch (e) {
    const msg = String(e.stderr || e.message || e);
    console.warn('REST Dependabot alerts falhou:', msg.trim());
    console.warn('Tentando GraphQL (repository.vulnerabilityAlerts)…');
    try {
      const gql = fetchDependabotAlertsGraphql(slug);
      console.log(`GraphQL: ${gql.length} alerta(s) aberto(s).`);
      return gql;
    } catch (e2) {
      console.error('GraphQL falhou:', String(e2.stderr || e2.message || e2).trim());
      throw new Error(
        [
          'Não foi possível listar alertas via REST nem GraphQL.',
          `UI GitHub (sem /alerts no path): ${dependabotAlertsUiUrl(slug)}`,
          `REST gh api: GET ${dependabotAlertsRestApiUrl(slug)}?state=open`,
          'Confira: job.permissions.security-events: read;',
          'na org: Actions → General → Workflow permissions não pode remover security-events do GITHUB_TOKEN;',
          'ou GH_REPO_TOKEN / GH_DEPENDABOT_ALERTS_TOKEN no ambiente do job.',
          'Doc: https://docs.github.com/en/rest/dependabot/alerts',
        ].join(' ')
      );
    }
  }
}

function severityRank(sev) {
  return SEVERITY_ORDER[sev] ?? 99;
}

function patchedVersionFromAlert(alert) {
  const top = alert.security_vulnerability?.first_patched_version?.identifier;
  if (top) return String(top).trim();

  const pkg = alert.dependency?.package?.name;
  const vulns = alert.security_advisory?.vulnerabilities;
  if (Array.isArray(vulns) && pkg) {
    const v = vulns.find((x) => x?.package?.name === pkg);
    const id = v?.first_patched_version?.identifier;
    if (id) return String(id).trim();
    const anyId = vulns.find((x) => x?.first_patched_version?.identifier)?.first_patched_version
      ?.identifier;
    if (anyId) return String(anyId).trim();
  }
  const patched = alert.security_advisory?.patched_versions;
  if (typeof patched === 'string' && patched.trim()) {
    const parts = patched.split(',').map((p) => p.trim());
    const last = parts[parts.length - 1];
    const numeric = last.replace(/^[^0-9]*/, '').match(/[\d.]+[-\w.]*/);
    if (numeric) return numeric[0];
  }
  return '';
}

function branchSlugForPackage(pkgName) {
  const s = pkgName.replace(/^@/, '').replace(/\//g, '-');
  return `security/fix-${s}`;
}

function commitWithMessage(message) {
  const f = path.join(os.tmpdir(), `gitmsg-${process.pid}.txt`);
  fs.writeFileSync(f, message, 'utf8');
  try {
    exec(`git commit -F ${JSON.stringify(f)}`, { cwd: PKG_ROOT });
  } finally {
    fs.unlinkSync(f);
  }
}

function defaultBranch() {
  const b = process.env.DEFAULT_BRANCH;
  if (b) return b;
  try {
    return exec('gh repo view --json defaultBranchRef -q .defaultBranchRef.name', {
      cwd: PKG_ROOT,
    }).trim();
  } catch {
    return 'main';
  }
}

function syncDefaultBranch() {
  const base = defaultBranch();
  exec('git fetch origin', { cwd: PKG_ROOT });
  exec(`git checkout ${JSON.stringify(base)}`, { cwd: PKG_ROOT });
  exec(`git reset --hard ${JSON.stringify(`origin/${base}`)}`, { cwd: PKG_ROOT });
}

function gitPushAutomationBranch(slug) {
  exec(`git push -u origin HEAD:refs/heads/${slug} --force`, { cwd: PKG_ROOT });
}

function findOpenPrNumberForHead(slug) {
  try {
    const out = exec(
      `gh pr list --head ${JSON.stringify(slug)} --state open --json number -q '.[0].number'`,
      { cwd: PKG_ROOT }
    ).trim();
    if (!out || out === 'null') return null;
    const n = Number(out);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function ghPrEditBody(prNumber, body) {
  const f = path.join(os.tmpdir(), `gh-pr-edit-${process.pid}-${prNumber}.md`);
  fs.writeFileSync(f, body, 'utf8');
  try {
    execFileSync(
      'gh',
      ['pr', 'edit', String(prNumber), '--body-file', f],
      {
        cwd: PKG_ROOT,
        env: envWithGhCliAuth(process.env),
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );
  } finally {
    fs.unlinkSync(f);
  }
}

function createOrUpdateSecurityPR(params) {
  const { pkgName, targetVersion, alerts, bodyMarkdown } = params;
  const base = defaultBranch();
  const slug = branchSlugForPackage(pkgName);
  const nums = [...new Set(alerts.map((a) => a.number))].sort((x, y) => x - y);
  const title =
    nums.length <= 3
      ? `security: bump ${pkgName} to ${targetVersion} (Dependabot ${nums.map((n) => `#${n}`).join(' ')})`
      : `security: bump ${pkgName} to ${targetVersion} (${nums.length} alertas Dependabot)`;

  exec(`git checkout -B ${JSON.stringify(slug)}`, { cwd: PKG_ROOT });
  exec('git add .', { cwd: PKG_ROOT });
  const status = exec('git status --porcelain', { cwd: PKG_ROOT });
  const hasChanges = Boolean(status.trim());

  if (hasChanges) {
    commitWithMessage(`${title}\n`);
    gitPushAutomationBranch(slug);
  } else {
    console.warn(`Sem diff local para ${pkgName} — só atualiza descrição do PR se já existir.`);
  }

  const prNum = findOpenPrNumberForHead(slug);
  if (prNum) {
    ghPrEditBody(prNum, bodyMarkdown);
    console.log(
      `PR #${prNum} (${slug}): descrição atualizada${hasChanges ? '; branch enviada.' : ' (sem novo commit).'}`
    );
  } else if (hasChanges) {
    ghPrCreate(base, slug, title, bodyMarkdown);
    console.log(`PR criada: ${slug}`);
  } else {
    console.warn(
      `Nenhum PR aberto com head ${slug} e nenhum commit novo — confira se o bump já está na base ou se o PR usa outro nome de branch.`
    );
  }

  exec(`git checkout ${JSON.stringify(base)}`, { cwd: PKG_ROOT });
}

function run() {
  logPreflightAuth();
  assertGhAuthOrExit();
  console.log('Buscando alertas Dependabot (critical/high)...');

  if (process.env.CURSOR_TOKEN && !fs.existsSync(RULES_MDC) && !fs.existsSync(RULES_MD)) {
    console.warn('Nenhum arquivo de regras encontrado (.cursor/rules/*.mdc ou rules/*.md).');
  }

  const workspaceYaml = readTextIfExists(path.join(REPO_ROOT, 'pnpm-workspace.yaml'));
  const rootPackageJson = readTextIfExists(path.join(REPO_ROOT, 'package.json'));
  console.log(
    `Monorepo: workspace=${workspaceYaml.length > 0} rootPackage=${rootPackageJson.length > 0}`
  );

  let alerts;
  try {
    alerts = fetchDependabotAlerts();
  } catch (e) {
    console.error('Falha ao listar alertas:', e.message);
    process.exit(1);
    return;
  }

  console.log(`Alertas Dependabot retornados pela API: ${alerts.length}`);

  const filtered = alerts.filter((a) => {
    const sev = a.security_advisory?.severity;
    const eco = a.dependency?.package?.ecosystem;
    return (sev === 'critical' || sev === 'high') && eco === 'npm';
  });

  filtered.sort((a, b) => {
    const da = severityRank(a.security_advisory.severity);
    const db = severityRank(b.security_advisory.severity);
    if (da !== db) return da - db;
    return (a.number ?? 0) - (b.number ?? 0);
  });

  if (filtered.length === 0) {
    const bySev = {};
    const byEco = {};
    for (const a of alerts) {
      const s = a.security_advisory?.severity ?? 'unknown';
      bySev[s] = (bySev[s] ?? 0) + 1;
      const e = a.dependency?.package?.ecosystem ?? 'unknown';
      byEco[e] = (byEco[e] ?? 0) + 1;
    }
    console.log(
      'Nenhum alerta critical/high (npm) na fila. Distribuição severity (todos):',
      JSON.stringify(bySev)
    );
    console.log('Distribuição ecosystem (todos):', JSON.stringify(byEco));
    console.log(
      'Se existir alerta moderate/low ou outro ecosystem, não gera PR (filtro atual).'
    );
    return;
  }

  console.log(`Alertas critical/high npm na fila: ${filtered.length}`);

  const groups = new Map();
  let skippedNoPatch = 0;
  for (const alert of filtered) {
    const pkgName = alert.dependency.package.name;
    const pv = patchedVersionFromAlert(alert);
    if (!pv) {
      skippedNoPatch += 1;
      console.warn(`Sem versão patchada explícita para ${pkgName} (#${alert.number}), ignorado no grupo.`);
      continue;
    }
    if (!groups.has(pkgName)) groups.set(pkgName, []);
    groups.get(pkgName).push(alert);
  }

  for (const [pkgName, pkgAlerts] of groups) {
    const sortedAlerts = [...pkgAlerts].sort((a, b) => (a.number ?? 0) - (b.number ?? 0));
    const patches = sortedAlerts.map((a) => patchedVersionFromAlert(a)).filter(Boolean);
    const targetVersion = maxPatchedVersionStrings(patches);
    if (!targetVersion) {
      skippedNoPatch += sortedAlerts.length;
      console.warn(`Sem versão-alvo para ${pkgName}, pulando grupo.`);
      continue;
    }

    console.log(
      `\n=== ${pkgName}: ${sortedAlerts.length} alerta(s) consolidados → ${targetVersion} (alertas ${sortedAlerts.map((a) => a.number).join(', ')}) ===`
    );

    try {
      syncDefaultBranch();
      const wasDirectBefore = isDirectJsDependency(pkgName);

      let whyOutput = '';
      try {
        whyOutput = pnpmExec(['why', pkgName, '--json']);
      } catch {
        whyOutput = '';
      }
      const ghost =
        whyOutput.includes('"dependencies":{}') ||
        whyOutput.trim() === '[]' ||
        whyOutput.includes('"dependencies": []');

      if (ghost) {
        console.log(`Ghost/no dependents: ${pkgName}, refrescando lockfile`);
        pnpmExec(['install', '--no-frozen-lockfile']);
        const whySummary = pnpmWhySummary(pkgName);
        createOrUpdateSecurityPR({
          pkgName,
          targetVersion,
          alerts: sortedAlerts,
          bodyMarkdown: formatSecurityPrBody({
            alerts: sortedAlerts,
            pkgName,
            targetVersion,
            ghost: true,
            auditResidualHighGate: false,
            catalogHint: workspaceCatalogHint(workspaceYaml, pkgName),
            whySummary,
            wasDirectBefore,
          }),
        });
        continue;
      }

      if (workspaceYaml.length > 0 && workspaceYaml.includes(pkgName)) {
        console.log('Pacote mencionado no workspace/catalog (revisar manualmente se necessário).');
      }

      pnpmExec(['add', '-E', `${pkgName}@${targetVersion}`, '--ignore-scripts']);
      pnpmExec(['install', '--no-frozen-lockfile']);
      let auditResidualHighGate = false;
      try {
        pnpmExec(['audit', '--audit-level', 'high']);
      } catch {
        auditResidualHighGate = true;
      }

      const rc = rulesContent();
      if (process.env.CURSOR_TOKEN && rc.length > 0) {
        console.log('Regras carregadas para contexto do operador/Cursor:', rc.length, 'chars');
      }

      const whySummary = pnpmWhySummary(pkgName);
      createOrUpdateSecurityPR({
        pkgName,
        targetVersion,
        alerts: sortedAlerts,
        bodyMarkdown: formatSecurityPrBody({
          alerts: sortedAlerts,
          pkgName,
          targetVersion,
          ghost: false,
          auditResidualHighGate,
          catalogHint: workspaceCatalogHint(workspaceYaml, pkgName),
          whySummary,
          wasDirectBefore,
        }),
      });
    } catch (err) {
      console.error(`Falha em ${pkgName}:`, err.message);
      try {
        exec(`git checkout ${defaultBranch()}`, { cwd: PKG_ROOT });
      } catch {
        void 0;
      }
    }
  }
  if (skippedNoPatch > 0) {
    console.log(`Alertas ignorados sem versão patch na API: ${skippedNoPatch}`);
  }
}

run();
