const path = require('path');
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');

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

function exec(cmd, options = {}) {
  return execSync(cmd, {
    encoding: 'utf8',
    cwd: options.cwd ?? PKG_ROOT,
    env: { ...process.env, ...options.env },
    stdio: ['pipe', 'pipe', 'pipe'],
    ...options,
  });
}

function readTextIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

function rulesContent() {
  if (fs.existsSync(RULES_MDC)) return readTextIfExists(RULES_MDC);
  return readTextIfExists(RULES_MD);
}

function fetchDependabotAlerts() {
  const all = [];
  let page = 1;
  for (;;) {
    const cmd = `gh api "repos/:owner/:repo/dependabot/alerts?state=open&per_page=100&page=${page}"`;
    let chunk;
    try {
      chunk = exec(cmd);
    } catch (e) {
      console.error(e.stderr || e.message);
      throw e;
    }
    const arr = JSON.parse(chunk);
    if (!Array.isArray(arr) || arr.length === 0) break;
    all.push(...arr);
    if (arr.length < 100) break;
    page += 1;
  }
  return all;
}

function severityRank(sev) {
  return SEVERITY_ORDER[sev] ?? 99;
}

function patchedVersionFromAlert(alert) {
  const pkg = alert.dependency?.package?.name;
  const vulns = alert.security_advisory?.vulnerabilities;
  if (Array.isArray(vulns) && pkg) {
    const v = vulns.find((x) => x?.package?.name === pkg);
    const id = v?.first_patched_version?.identifier;
    if (id) return id.trim();
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

  exec(`git checkout -b ${JSON.stringify(slug)}`, { cwd: PKG_ROOT });
  exec('git add .', { cwd: PKG_ROOT });
  const status = exec('git status --porcelain', { cwd: PKG_ROOT });
  if (!status.trim()) {
    console.warn(`Sem alterações para ${pkg} (#${alertId}), PR não criada.`);
    exec(`git checkout ${JSON.stringify(base)}`, { cwd: PKG_ROOT });
    exec(`git branch -D ${JSON.stringify(slug)}`, { cwd: PKG_ROOT });
    return;
  }
  commitWithMessage(`${title}\n`);
  exec(`git push -u origin HEAD`, { cwd: PKG_ROOT });
  exec(
    [
      'gh pr create',
      `--base ${JSON.stringify(base)}`,
      `--head ${JSON.stringify(slug)}`,
      `--title ${JSON.stringify(title)}`,
      `--body ${JSON.stringify(body)}`,
    ].join(' '),
    { cwd: PKG_ROOT }
  );
  console.log(`PR criada: ${slug}`);
  exec(`git checkout ${JSON.stringify(base)}`, { cwd: PKG_ROOT });
}

function run() {
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
    console.log('Nenhum alerta critical/high (npm) aberto.');
    return;
  }

  console.log(`Total de alertas na fila: ${filtered.length}`);

  for (const alert of filtered) {
    const pkgName = alert.dependency.package.name;
    const alertId = alert.number;
    const safeVersion = patchedVersionFromAlert(alert);

    if (!safeVersion) {
      console.warn(`Sem versão patchada explícita para ${pkgName} (#${alertId}), pulando.`);
      continue;
    }

    console.log(`\n--- ${pkgName} (#${alertId}) [${alert.security_advisory.severity}] -> ${safeVersion} ---`);

    try {
      syncDefaultBranch();

      const whyOutput = exec(`pnpm why ${JSON.stringify(pkgName)} --json || true`);
      const ghost =
        whyOutput.includes('"dependencies":{}') ||
        whyOutput.trim() === '[]' ||
        whyOutput.includes('"dependencies": []');

      if (ghost) {
        console.log(`Ghost/no dependents: ${pkgName}, refrescando lockfile`);
        exec('pnpm install --no-frozen-lockfile');
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

      exec(`pnpm add -E ${JSON.stringify(`${pkgName}@${safeVersion}`)} --ignore-scripts`);
      exec('pnpm install --no-frozen-lockfile');
      let auditNote = '';
      try {
        exec('pnpm audit --audit-level high');
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
}

run();
