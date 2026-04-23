const path = require('path');
const fs = require('fs');
const os = require('os');
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

function rulesContent() {
  if (fs.existsSync(RULES_MDC)) return readTextIfExists(RULES_MDC);
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

function branchSlug(pkgName, alertNumber) {
  const s = pkgName.replace(/^@/, '').replace(/\//g, '-');
  return `security/fix-${s}-${alertNumber}`;
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

function createPR(pkg, ver, alertId, customBody, auditNote) {
  const base = defaultBranch();
  const slug = branchSlug(pkg, alertId);
  const title = `security: bump ${pkg} to ${ver} (Dependabot #${alertId})`;
  const baseBody =
    customBody ||
    [
      `Correção automática para o alerta Dependabot **#${alertId}**.`,
      '',
      `- Pacote: \`${pkg}\``,
      `- Versão alvo (patch mínimo): \`${ver}\``,
      '',
      'Checklist:',
      '- [ ] CI verde',
      '- [ ] Revisar changelog se major/minor',
    ].join('\n');
  const body = auditNote ? `${baseBody}\n\n${auditNote}` : baseBody;

  exec(`git checkout -B ${JSON.stringify(slug)}`, { cwd: PKG_ROOT });
  exec('git add .', { cwd: PKG_ROOT });
  const status = exec('git status --porcelain', { cwd: PKG_ROOT });
  if (!status.trim()) {
    console.warn(`Sem alterações para ${pkg} (#${alertId}), PR não criada.`);
    exec(`git checkout ${JSON.stringify(base)}`, { cwd: PKG_ROOT });
    exec(`git branch -D ${JSON.stringify(slug)}`, { cwd: PKG_ROOT });
    return;
  }
  commitWithMessage(`${title}\n`);
  gitPushAutomationBranch(slug);
  ghPrCreate(base, slug, title, body);
  console.log(`PR criada: ${slug}`);
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

  let skippedNoPatch = 0;
  for (const alert of filtered) {
    const pkgName = alert.dependency.package.name;
    const alertId = alert.number;
    const safeVersion = patchedVersionFromAlert(alert);

    if (!safeVersion) {
      skippedNoPatch += 1;
      console.warn(`Sem versão patchada explícita para ${pkgName} (#${alertId}), pulando.`);
      continue;
    }

    console.log(`\n--- ${pkgName} (#${alertId}) [${alert.security_advisory.severity}] -> ${safeVersion} ---`);

    try {
      syncDefaultBranch();

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
        createPR(
          pkgName,
          safeVersion,
          alertId,
          `Limpeza pós-\`pnpm why\` (entrada órfã no grafo) para o alerta #${alertId}.\n\nPacote: \`${pkgName}\`\n`
        );
        continue;
      }

      if (workspaceYaml.length > 0 && workspaceYaml.includes(pkgName)) {
        console.log('Pacote mencionado no workspace/catalog (revisar manualmente se necessário).');
      }

      pnpmExec(['add', '-E', `${pkgName}@${safeVersion}`, '--ignore-scripts']);
      pnpmExec(['install', '--no-frozen-lockfile']);
      let auditNote = '';
      try {
        pnpmExec(['audit', '--audit-level', 'high']);
      } catch {
        auditNote =
          '**Aviso:** `pnpm audit --audit-level high` ainda reporta vulnerabilidades (possíveis transitivas ou outros alertas).';
      }

      const rc = rulesContent();
      if (process.env.CURSOR_TOKEN && rc.length > 0) {
        console.log('Regras carregadas para contexto do operador/Cursor:', rc.length, 'chars');
      }

      createPR(pkgName, safeVersion, alertId, undefined, auditNote);
    } catch (err) {
      console.error(`Falha em ${pkgName} (#${alertId}):`, err.message);
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
