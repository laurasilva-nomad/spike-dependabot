const path = require('path');
const fs = require('fs');
const os = require('os');
const semver = require('semver');
const { execSync, execFileSync } = require('child_process');

function findRepoRootFrom(startDir) {
  let d = path.resolve(startDir);
  const { root } = path.parse(d);
  while (d !== root) {
    if (fs.existsSync(path.join(d, '.git'))) return d;
    d = path.dirname(d);
  }
  throw new Error('Raiz git não encontrada (subindo a partir do script).');
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const UNIFIED_BRANCH = 'security/dependabot-remediation';
const REPO_ROOT =
  process.env.GITHUB_WORKSPACE != null && String(process.env.GITHUB_WORKSPACE).length > 0
    ? path.resolve(process.env.GITHUB_WORKSPACE)
    : findRepoRootFrom(__dirname);
const GIT_CWD = REPO_ROOT;

let PKG_ROOT = null;
let PACKAGE_MANAGER = null;

function tokenFromEnv(env) {
  return (
    env.GH_DEPENDABOT_ALERTS_TOKEN ||
    env.GH_REPO_TOKEN ||
    env.GH_TOKEN ||
    env.GITHUB_TOKEN ||
    ''
  );
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
    cwd: options.cwd ?? GIT_CWD,
    env: mergedEnv,
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: true,
  });
}

function readTextIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

function detectPackageRoot() {
  const explicit = process.env.SECURITY_PACKAGE_ROOT || process.env.PACKAGE_ROOT;
  if (explicit) {
    const p = path.join(REPO_ROOT, explicit.replace(/^\//, ''));
    if (fs.existsSync(path.join(p, 'package.json'))) return path.resolve(p);
    throw new Error(`SECURITY_PACKAGE_ROOT=${explicit} sem package.json`);
  }
  const candidates = ['javascript', '.', 'frontend', 'web', 'apps/web', 'packages/app'];
  for (const c of candidates) {
    const p = c === '.' ? REPO_ROOT : path.join(REPO_ROOT, c);
    if (fs.existsSync(path.join(p, 'package.json'))) return path.resolve(p);
  }
  throw new Error('Nenhuma raiz com package.json encontrada; defina SECURITY_PACKAGE_ROOT.');
}

function detectPackageManager(pkgRoot) {
  const parent = path.dirname(pkgRoot);
  const hasPnpmLock = fs.existsSync(path.join(pkgRoot, 'pnpm-lock.yaml'));
  const hasYarnLock = fs.existsSync(path.join(pkgRoot, 'yarn.lock'));
  const hasNpmLock = fs.existsSync(path.join(pkgRoot, 'package-lock.json'));
  const wsPnpm = fs.existsSync(path.join(parent, 'pnpm-workspace.yaml'));
  const rootPnpm = fs.existsSync(path.join(REPO_ROOT, 'pnpm-lock.yaml'));
  if (hasPnpmLock || wsPnpm || rootPnpm) return 'pnpm';
  if (hasYarnLock) return 'yarn';
  if (hasNpmLock) return 'npm';
  if (fs.existsSync(path.join(pkgRoot, 'package.json'))) return 'npm';
  return 'npm';
}

function pmAdd(pkgName, version, cwd) {
  const spec = `${pkgName}@${version}`;
  const pm = PACKAGE_MANAGER;
  if (pm === 'pnpm') {
    execFileSync('pnpm', ['add', '-E', spec, '--ignore-scripts'], {
      cwd,
      encoding: 'utf8',
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return;
  }
  if (pm === 'yarn') {
    try {
      execFileSync('yarn', ['add', spec, '--exact'], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      execFileSync('yarn', ['add', spec, '--exact', '--ignore-scripts'], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    }
    return;
  }
  execFileSync('npm', ['install', spec, '--save-exact', '--ignore-scripts'], {
    cwd,
    encoding: 'utf8',
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

function pmInstall(cwd) {
  const pm = PACKAGE_MANAGER;
  if (pm === 'pnpm') {
    execFileSync('pnpm', ['install', '--no-frozen-lockfile'], {
      cwd,
      encoding: 'utf8',
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return;
  }
  if (pm === 'yarn') {
    execFileSync('yarn', ['install'], {
      cwd,
      encoding: 'utf8',
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return;
  }
  execFileSync('npm', ['install'], {
    cwd,
    encoding: 'utf8',
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

function whySummary(pkgName, cwd) {
  const pm = PACKAGE_MANAGER;
  try {
    let out = '';
    if (pm === 'pnpm') {
      out = execFileSync('pnpm', ['why', pkgName], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } else if (pm === 'yarn') {
      try {
        out = execFileSync('yarn', ['why', pkgName], {
          cwd,
          encoding: 'utf8',
          env: process.env,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch {
        out = execFileSync('npm', ['ls', pkgName, '--all'], {
          cwd,
          encoding: 'utf8',
          env: process.env,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }
    } else {
      out = execFileSync('npm', ['ls', pkgName, '--all'], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    }
    const lines = out
      .trim()
      .split(/\r?\n/)
      .filter((l) => {
        const t = l.trim();
        return t.length > 0 && !/^Legend:/i.test(t);
      })
      .slice(0, 36);
    if (lines.length === 0) return '_Sem saída útil do grafo local._';
    return lines.map((l) => `- ${l.trim()}`).join('\n');
  } catch {
    return '_Falha ao inspecionar cadeia de dependências (`pnpm why` / `npm ls`)._';
  }
}

function multiConsumerHeuristic(whyText) {
  const lines = whyText.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const depthOrBullet = lines.filter((l) => /^[\s│├└─\-*]/.test(l) || /^\d+\s+/.test(l));
  const n = Math.max(1, depthOrBullet.length > 3 ? Math.ceil(depthOrBullet.length / 4) : lines.length > 8 ? 2 : 1);
  const likelyMulti = lines.length > 12 || depthOrBullet.length > 6;
  return { likelyMulti, summary: likelyMulti ? 'provável (várias linhas no grafo)' : 'único ou poucos caminhos (heurística)' };
}

function pmAuditFailsAny(cwd) {
  try {
    if (PACKAGE_MANAGER === 'pnpm') {
      execFileSync('pnpm', ['audit', '--audit-level', 'low'], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } else {
      execFileSync('npm', ['audit', '--audit-level', 'low'], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    }
    return false;
  } catch {
    return true;
  }
}

function ghPrCreate(baseBranch, headBranch, title, body) {
  const mergedEnv = envWithGhCliAuth(process.env);
  execFileSync(
    'gh',
    ['pr', 'create', '--base', baseBranch, '--head', headBranch, '--title', title, '--body', body],
    {
      cwd: GIT_CWD,
      env: mergedEnv,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }
  );
}

function ghRepoSlug() {
  const envRepo = process.env.GITHUB_REPOSITORY;
  if (envRepo && envRepo.includes('/')) return envRepo.trim();
  try {
    return exec('gh repo view --json nameWithOwner -q .nameWithOwner', {
      cwd: GIT_CWD,
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

function overridesSnippet() {
  const raw = readTextIfExists(path.join(PKG_ROOT, 'package.json'));
  if (!raw) return '';
  try {
    const j = JSON.parse(raw);
    if (PACKAGE_MANAGER === 'pnpm') {
      const o = j.pnpm?.overrides;
      if (o && typeof o === 'object' && Object.keys(o).length > 0) {
        return ['', 'Trecho `pnpm.overrides` atual:', '', '```json', JSON.stringify({ pnpm: { overrides: o } }, null, 2), '```', ''].join('\n');
      }
    }
    if (PACKAGE_MANAGER === 'yarn') {
      const r = j.resolutions;
      if (r && typeof r === 'object' && Object.keys(r).length > 0) {
        return ['', 'Trecho `resolutions` (yarn) atual:', '', '```json', JSON.stringify({ resolutions: r }, null, 2), '```', ''].join('\n');
      }
    }
    const ov = j.overrides;
    if (ov && typeof ov === 'object' && Object.keys(ov).length > 0) {
      return ['', 'Trecho `overrides` (npm) atual:', '', '```json', JSON.stringify({ overrides: ov }, null, 2), '```', ''].join('\n');
    }
    return '';
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

function majorBumpRisk(currentHint, target) {
  const raw = typeof currentHint === 'string' ? currentHint.trim() : '';
  const a = semver.coerce(raw || undefined);
  const b = semver.coerce(target);
  if (!b) return 'desconhecido';
  if (!raw || !a) return 'transitiva ou não declarada diretamente — conferir grafo e semver resolvido';
  if (semver.major(b) > semver.major(a)) return 'alto (major)';
  if (semver.major(a) === semver.major(b) && semver.gt(b, a)) return 'médio/alto (minor ou patch grande)';
  return 'baixo (patch ou alinhado)';
}

function resolvedVersionHint(pkgName) {
  const raw = readTextIfExists(path.join(PKG_ROOT, 'package.json'));
  if (!raw) return '';
  try {
    const j = JSON.parse(raw);
    for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const v = j[k]?.[pkgName];
      if (typeof v === 'string') return v.replace(/^[\^~>=<]+\s*/, '').trim();
    }
  } catch {
    return '';
  }
  return '';
}

function versionVulnerableBeforeFix(pkgName, graph, sortedAlerts) {
  const fromGraph = graph.resolvedVersion?.trim();
  if (fromGraph) return fromGraph;
  const fromManifest = resolvedVersionHint(pkgName);
  if (fromManifest) return fromManifest;
  for (const a of sortedAlerts) {
    const dv = a.dependency?.version;
    if (typeof dv === 'string' && dv.trim()) return dv.trim();
    const sv = a.security_vulnerability?.package?.version;
    if (typeof sv === 'string' && sv.trim()) return sv.trim();
  }
  return '—';
}

function relFromRepo(absPath) {
  return path.relative(REPO_ROOT, absPath).replace(/\\/g, '/') || '.';
}

function npmLsAllJson(cwd, pkgName) {
  try {
    const out = execFileSync('npm', ['ls', pkgName, '--all', '--json'], {
      cwd,
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return JSON.parse(out);
  } catch (e) {
    const stdout = e.stdout;
    if (stdout) {
      try {
        const s = typeof stdout === 'string' ? stdout : stdout.toString();
        return JSON.parse(s);
      } catch {
        return null;
      }
    }
    return null;
  }
}

function maxDepthToPkg(deps, pkgName, currentDepth) {
  if (!deps || typeof deps !== 'object') return 0;
  let max = 0;
  for (const [name, meta] of Object.entries(deps)) {
    if (name === pkgName) max = Math.max(max, currentDepth);
    const sub = meta?.dependencies;
    if (sub && typeof sub === 'object') {
      max = Math.max(max, maxDepthToPkg(sub, pkgName, currentDepth + 1));
    }
  }
  return max;
}

function findPkgVersionDeep(root, pkgName) {
  let v = '';
  function walk(depObj) {
    if (!depObj || typeof depObj !== 'object') return;
    for (const [name, meta] of Object.entries(depObj)) {
      if (name === pkgName && typeof meta?.version === 'string') {
        v = meta.version;
        return;
      }
      if (meta?.dependencies) walk(meta.dependencies);
    }
  }
  if (root.dependencies) walk(root.dependencies);
  return v;
}

function chainsToPkg(deps, pkgName, chain) {
  const out = [];
  if (!deps || typeof deps !== 'object') return out;
  const base = chain ?? [];
  for (const [name, meta] of Object.entries(deps)) {
    const c = [...base, name];
    if (name === pkgName) out.push(c);
    if (meta?.dependencies) out.push(...chainsToPkg(meta.dependencies, pkgName, c));
  }
  return out;
}

function pnpmWhyDepthFallback(pkgName, cwd) {
  try {
    const text = execFileSync('pnpm', ['why', pkgName], {
      cwd,
      encoding: 'utf8',
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const lines = text.split(/\r?\n/).filter((l) => {
      const t = l.trim();
      return t.length > 0 && !/^Legend:/i.test(t);
    });
    const depthEst = Math.min(20, Math.max(1, Math.ceil(lines.length / 3)));
    return {
      maxDepth: depthEst,
      resolvedVersion: '',
      directParents: [],
    };
  } catch {
    return { maxDepth: 4, resolvedVersion: '', directParents: [] };
  }
}

function npmLsGraphInfo(pkgName, cwd) {
  const j = npmLsAllJson(cwd, pkgName);
  if (!j || typeof j !== 'object') {
    return pnpmWhyDepthFallback(pkgName, cwd);
  }
  const deps = j.dependencies;
  if (!deps || typeof deps !== 'object') {
    return pnpmWhyDepthFallback(pkgName, cwd);
  }
  const maxDepth = maxDepthToPkg(deps, pkgName, 1);
  const resolved = findPkgVersionDeep(j, pkgName);
  if (maxDepth === 0 && !resolved) {
    return pnpmWhyDepthFallback(pkgName, cwd);
  }
  const chains = chainsToPkg(deps, pkgName);
  const parents = new Set();
  for (const c of chains) {
    const idx = c.lastIndexOf(pkgName);
    if (idx > 0) parents.add(c[idx - 1]);
  }
  return {
    maxDepth: maxDepth || 0,
    resolvedVersion: resolved || '',
    directParents: [...parents],
  };
}

function dependencyRelationshipFromAlerts(alerts) {
  for (const a of alerts) {
    const r = a.dependency?.relationship;
    if (r === 'direct') return 'direct';
    if (r === 'indirect') return 'indirect';
  }
  return null;
}

function listTopLevelDepNames() {
  const raw = readTextIfExists(path.join(PKG_ROOT, 'package.json'));
  if (!raw) return [];
  try {
    const j = JSON.parse(raw);
    const s = new Set();
    for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const b = j[k];
      if (b && typeof b === 'object') Object.keys(b).forEach((x) => s.add(x));
    }
    return [...s];
  } catch {
    return [];
  }
}

function isMajorLeapResolvedToTarget(resolvedV, targetV) {
  const a = semver.coerce(resolvedV);
  const b = semver.coerce(targetV);
  if (!a || !b) return false;
  return semver.major(b) > semver.major(a);
}

function applyPackageJsonOverride(pkgName, version) {
  const p = path.join(PKG_ROOT, 'package.json');
  const raw = fs.readFileSync(p, 'utf8');
  const j = JSON.parse(raw);
  if (PACKAGE_MANAGER === 'pnpm') {
    if (!j.pnpm) j.pnpm = {};
    if (!j.pnpm.overrides) j.pnpm.overrides = {};
    j.pnpm.overrides[pkgName] = version;
  } else if (PACKAGE_MANAGER === 'yarn') {
    if (!j.resolutions) j.resolutions = {};
    const key = pkgName.startsWith('@') ? `**/${pkgName}` : `**/${pkgName}`;
    j.resolutions[key] = version;
  } else {
    if (!j.overrides) j.overrides = {};
    j.overrides[pkgName] = version;
  }
  fs.writeFileSync(p, `${JSON.stringify(j, null, 2)}\n`);
}

function formatUnifiedPrBody(opts) {
  const firstLineManual = opts.manualVerification
    ? '⚠️ **VERIFICAÇÃO MANUAL OBRIGATÓRIA ANTES DO MERGE** — falha em bump/override, audit local ainda com findings, conflito de semver entre patches da API ou revisão de workspace/catalog necessária; clone o branch, alinhe Node/Corepack, rode install + `audit --audit-level low` e testes antes do merge.'
    : '**Correção consolidada** — um único PR cobrindo alertas npm (Critical → Low) com patch na API quando disponível; rode CI e testes antes do merge.';

  const pkgs = opts.packages || [];
  const lines = [
    firstLineManual,
    '',
    '## Contexto',
    '',
    `**Um PR único** para alertas Dependabot npm (todas as severidades tratadas pelo filtro) com patch informado pela API. Raiz: \`${relFromRepo(PKG_ROOT)}\`. Gerenciador: **${opts.pmLabel}**. Estratégia: bump direto (save-exact) → transitivo raso (\`pnpm add -E\` / equivalente) → **override/resolution** se grafo **> 2 níveis** ou **salto major** na transitiva, conforme árvore do guia.`,
    '',
    'Coluna **versão anterior**: resolução no grafo (`npm ls`, antes do PR), senão manifest, senão campo da API quando existir.',
    '',
    '| Pacote | Versão anterior (vulnerável) | Versão corrigida | Estratégia | API rel. | Prof. grafo | Pais no topo | Risco | Consumidores (heurística) |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  ];

  for (const p of pkgs) {
    const prevCell =
      p.versionBeforeFix === '—' ? '—' : `\`${mdEscapePipe(p.versionBeforeFix)}\``;
    lines.push(
      `| \`${p.pkgName}\` | ${prevCell} | \`${mdEscapePipe(p.targetVersion)}\` | ${p.strategy} | ${p.apiRel} | ${p.graphDepth} | ${p.parentTopHint} | ${p.breakRisk} | ${p.multiConsumer} |`
    );
  }

  lines.push('', '## Onde cada pacote entra no grafo', '');
  for (const p of pkgs) {
    const prevDisp = p.versionBeforeFix === '—' ? '—' : `\`${mdEscapePipe(p.versionBeforeFix)}\``;
    lines.push(
      `### \`${p.pkgName}\` — ${prevDisp} → \`${mdEscapePipe(p.targetVersion)}\``,
      '',
      p.whySummary,
      ''
    );
  }

  lines.push(
    '## Tabela Dependabot (consolidada)',
    '',
    '| Alerta | Pacote | Sev | Intervalo (advisory) | Patch (API) |',
    '| --- | --- | --- | --- | --- |'
  );

  for (const a of opts.allAlerts) {
    const an = a.number ?? 0;
    const pkg = a.dependency?.package?.name ?? '—';
    const sev = a.security_advisory?.severity ?? '—';
    const vr = mdEscapePipe(vulnerableRangeFromAlert(a));
    const pv = patchedVersionFromAlert(a) || '—';
    lines.push(`| [#${an}](${dependabotAlertPermalink(an)}) | \`${pkg}\` | ${sev} | ${vr} | \`${pv}\` |`);
  }

  lines.push('', '## Validação manual recomendada', '');
  lines.push(
    `- **Node:** \`.nvmrc\` / \`.node-version\` quando existirem.`,
    `- **Install:** em \`${relFromRepo(PKG_ROOT)}\`: ${
      PACKAGE_MANAGER === 'pnpm'
        ? '`pnpm install`'
        : PACKAGE_MANAGER === 'yarn'
          ? '`yarn install`'
          : '`npm ci` ou `npm install`'
    }.`,
    `- **Audit:** \`${PACKAGE_MANAGER === 'pnpm' ? 'pnpm audit --audit-level low' : 'npm audit --audit-level low'}\` (meta: nenhum finding acima do limiar).`,
    `- **Testes:** scripts do \`package.json\` (\`test\`, \`build\`).`,
    ''
  );

  if (opts.failures.length > 0) {
    lines.push('## Falhas na automação', '', ...opts.failures.map((f) => `- ${f}`), '');
  }

  lines.push(
    '## Notas',
    '',
    '- Overrides/resolutions são aplicados só quando a árvore de decisão indica grafo profundo ou salto major na transitiva; bumps diretos usam sempre versão fixa.',
    '- Profundidade e versão resolvida vêm principalmente de `npm ls --all --json`; em layouts puramente pnpm pode haver fallback heurístico.',
    ''
  );

  const overSnip = overridesSnippet();
  if (overSnip) lines.push(overSnip);

  lines.push('', '**Antes do merge:** changelog se necessário; CI verde.');
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
          'GH_REPO_TOKEN / GH_DEPENDABOT_ALERTS_TOKEN no ambiente do job.',
          'Doc: https://docs.github.com/en/rest/dependabot/alerts',
        ].join(' ')
      );
    }
  }
}

function severityRank(sev) {
  let s = String(sev || '').toLowerCase();
  if (s === 'moderate') s = 'medium';
  return SEVERITY_ORDER[s] ?? 99;
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

function semverLineConflict(patchIds) {
  const majors = new Set();
  for (const p of patchIds) {
    const c = semver.coerce(p);
    if (c) majors.add(semver.major(c));
  }
  return majors.size > 1;
}

function commitWithMessage(message) {
  const f = path.join(os.tmpdir(), `gitmsg-${process.pid}.txt`);
  fs.writeFileSync(f, message, 'utf8');
  try {
    exec(`git commit -F ${JSON.stringify(f)}`, { cwd: GIT_CWD });
  } finally {
    fs.unlinkSync(f);
  }
}

function defaultBranch() {
  const b = process.env.DEFAULT_BRANCH;
  if (b) return b;
  try {
    return exec('gh repo view --json defaultBranchRef -q .defaultBranchRef.name', {
      cwd: GIT_CWD,
    }).trim();
  } catch {
    return 'main';
  }
}

function syncDefaultBranch() {
  const base = defaultBranch();
  exec('git fetch origin', { cwd: GIT_CWD });
  exec(`git checkout ${JSON.stringify(base)}`, { cwd: GIT_CWD });
  exec(`git reset --hard ${JSON.stringify(`origin/${base}`)}`, { cwd: GIT_CWD });
}

function gitPushAutomationBranch(slug) {
  exec(`git push -u origin HEAD:refs/heads/${slug} --force`, { cwd: GIT_CWD });
}

function findOpenPrNumberForHead(slug) {
  try {
    const out = exec(
      `gh pr list --head ${JSON.stringify(slug)} --state open --json number -q '.[0].number'`,
      { cwd: GIT_CWD }
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
        cwd: GIT_CWD,
        env: envWithGhCliAuth(process.env),
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );
  } finally {
    fs.unlinkSync(f);
  }
}

function gitAddPackageScope() {
  const rel = path.relative(REPO_ROOT, PKG_ROOT).replace(/\\/g, '/');
  if (!rel || rel === '.') {
    exec('git add -A', { cwd: GIT_CWD });
  } else {
    exec(`git add -- ${JSON.stringify(rel)}`, { cwd: GIT_CWD });
  }
}

function ghostPackage(pkgName, cwd) {
  try {
    if (PACKAGE_MANAGER === 'pnpm') {
      const whyOutput = execFileSync('pnpm', ['why', pkgName, '--json'], {
        cwd,
        encoding: 'utf8',
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return (
        whyOutput.includes('"dependencies":{}') ||
        whyOutput.trim() === '[]' ||
        whyOutput.includes('"dependencies": []')
      );
    }
    return false;
  } catch {
    return true;
  }
}

function run() {
  PKG_ROOT = detectPackageRoot();
  PACKAGE_MANAGER = detectPackageManager(PKG_ROOT);
  const pmLabel = `${PACKAGE_MANAGER} (${relFromRepo(PKG_ROOT)})`;

  logPreflightAuth();
  assertGhAuthOrExit();
  console.log(`PKG_ROOT=${relFromRepo(PKG_ROOT)} PM=${PACKAGE_MANAGER}`);

  console.log('Buscando alertas Dependabot (Critical / High / Moderate / Low, ecosystem npm)...');

  const workspaceYaml = readTextIfExists(path.join(REPO_ROOT, 'pnpm-workspace.yaml'));

  let alerts;
  try {
    alerts = fetchDependabotAlerts();
  } catch (e) {
    console.error('Falha ao listar alertas:', e.message);
    process.exit(1);
    return;
  }

  console.log(`Alertas Dependabot retornados pela API: ${alerts.length}`);

  const allowedSeverities = new Set(['critical', 'high', 'medium', 'moderate', 'low']);
  const filtered = alerts.filter((a) => {
    const sev = String(a.security_advisory?.severity || '').toLowerCase();
    const eco = a.dependency?.package?.ecosystem;
    return eco === 'npm' && allowedSeverities.has(sev);
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
    console.log('Nenhum alerta npm (Critical/High/Moderate/Low) na fila. Severities (todos):', JSON.stringify(bySev));
    console.log('Distribuição ecosystem (todos):', JSON.stringify(byEco));
    return;
  }

  console.log(`Alertas npm na fila (todas severidades): ${filtered.length}`);

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

  const packageRows = [];
  const failures = [];
  let manualVerification = false;
  const patchesByGroup = [];

  for (const [pkgName, pkgAlerts] of groups) {
    const sortedAlerts = [...pkgAlerts].sort((a, b) => (a.number ?? 0) - (b.number ?? 0));
    const patches = sortedAlerts.map((a) => patchedVersionFromAlert(a)).filter(Boolean);
    const targetVersion = maxPatchedVersionStrings(patches);
    if (!targetVersion) {
      skippedNoPatch += sortedAlerts.length;
      continue;
    }
    if (semverLineConflict(patches)) {
      manualVerification = true;
      failures.push(
        `\`${pkgName}\`: patches da API em linhas semver incompatíveis (${patches.join(', ')}) — revisar overrides manualmente.`
      );
      continue;
    }
    patchesByGroup.push({
      pkgName,
      sortedAlerts,
      targetVersion,
    });
  }

  if (patchesByGroup.length === 0) {
    console.warn('Nenhum pacote com bump automático possível.');
    if (skippedNoPatch > 0) console.log(`Alertas ignorados sem versão patch na API: ${skippedNoPatch}`);
    return;
  }

  try {
    syncDefaultBranch();
    exec(`git checkout -B ${JSON.stringify(UNIFIED_BRANCH)}`, { cwd: GIT_CWD });

    for (const g of patchesByGroup) {
      const { pkgName, targetVersion, sortedAlerts } = g;
      console.log(
        `\n>>> ${pkgName} → ${targetVersion} (alertas ${sortedAlerts.map((a) => a.number).join(', ')})`
      );

      try {
        const apiRelRaw = dependencyRelationshipFromAlerts(sortedAlerts);
        const manifestDirect = isDirectJsDependency(pkgName);
        const isDirect =
          apiRelRaw === 'direct' || (apiRelRaw !== 'indirect' && manifestDirect);
        const apiRelDisp = apiRelRaw ?? (manifestDirect ? 'direct (manifest)' : 'indirect (inferido)');

        const graph = npmLsGraphInfo(pkgName, PKG_ROOT);
        const versionBeforeFix = versionVulnerableBeforeFix(pkgName, graph, sortedAlerts);
        const majorLeap = isMajorLeapResolvedToTarget(graph.resolvedVersion, targetVersion);
        const topLevel = new Set(listTopLevelDepNames());
        const parentsTop = graph.directParents.filter((p) => topLevel.has(p));
        const parentTopHint = parentsTop.length > 0 ? parentsTop.map((x) => `\`${x}\``).join(', ') : '—';

        let strategy = '';

        if (ghostPackage(pkgName, PKG_ROOT)) {
          console.log(`Ghost/no dependents aparente: ${pkgName}, alinhando lock`);
          pmInstall(PKG_ROOT);
        }

        if (isDirect) {
          strategy = 'bump direto (save-exact)';
          pmAdd(pkgName, targetVersion, PKG_ROOT);
        } else if (graph.maxDepth > 2 || majorLeap) {
          strategy =
            graph.maxDepth > 2
              ? 'override (grafo > 2 níveis)'
              : 'override (salto major na transitiva vs patch)';
          applyPackageJsonOverride(pkgName, targetVersion);
        } else {
          strategy = 'bump transitivo (pin na raiz)';
          try {
            pmAdd(pkgName, targetVersion, PKG_ROOT);
          } catch (e1) {
            strategy = 'override (fallback após falha no add)';
            applyPackageJsonOverride(pkgName, targetVersion);
            manualVerification = true;
            failures.push(`\`${pkgName}\`: pin na raiz falhou — aplicado override. (${String(e1.message || e1)})`);
          }
        }

        pmInstall(PKG_ROOT);

        const ws = whySummary(pkgName, PKG_ROOT);
        const mc = multiConsumerHeuristic(ws);
        const curVer = resolvedVersionHint(pkgName);
        const breakRisk = majorBumpRisk(
          manifestDirect ? curVer : graph.resolvedVersion || curVer,
          targetVersion
        );

        packageRows.push({
          pkgName,
          versionBeforeFix,
          targetVersion,
          strategy,
          apiRel: apiRelDisp,
          graphDepth: String(graph.maxDepth),
          parentTopHint,
          whySummary: ws,
          multiConsumer: mc.summary,
          breakRisk,
          sortedAlerts,
        });

        if (workspaceYaml.length > 0 && workspaceYaml.includes(pkgName)) {
          manualVerification = true;
          failures.push(
            `\`${pkgName}\`: possível entrada em **pnpm catalog** / workspace — conferir YAML.`
          );
        }
      } catch (err) {
        manualVerification = true;
        failures.push(`\`${pkgName}\`@${targetVersion}: ${String(err.message || err)}`);
        console.error(`Falha ${pkgName}:`, err.message || err);
      }
    }

    if (pmAuditFailsAny(PKG_ROOT)) {
      manualVerification = true;
      failures.push('`audit --audit-level low` ainda reporta vulnerabilidades após remediação.');
    }

    const title = `security: Dependabot (${filtered.length} alertas, ${packageRows.length} pacotes)`;

    const bodyMarkdown = formatUnifiedPrBody({
      packages: packageRows.map((r) => ({
        pkgName: r.pkgName,
        versionBeforeFix: r.versionBeforeFix,
        targetVersion: r.targetVersion,
        strategy: r.strategy,
        apiRel: r.apiRel,
        graphDepth: r.graphDepth,
        parentTopHint: r.parentTopHint,
        whySummary: r.whySummary,
        multiConsumer: r.multiConsumer,
        breakRisk: r.breakRisk,
      })),
      allAlerts: filtered,
      manualVerification,
      failures,
      pmLabel,
    });

    gitAddPackageScope();
    const status = exec('git status --porcelain', { cwd: GIT_CWD });
    const hasChanges = Boolean(status.trim());

    if (hasChanges) {
      commitWithMessage(`${title}\n`);
      gitPushAutomationBranch(UNIFIED_BRANCH);
    } else {
      console.warn('Sem alterações no working tree após tentativas de bump.');
    }

    const prNum = findOpenPrNumberForHead(UNIFIED_BRANCH);
    if (prNum) {
      ghPrEditBody(prNum, bodyMarkdown);
      console.log(
        `PR #${prNum}: descrição atualizada${hasChanges ? '; branch enviada.' : ' (sem novo commit).'}`
      );
    } else if (hasChanges) {
      ghPrCreate(defaultBranch(), UNIFIED_BRANCH, title, bodyMarkdown);
      console.log(`PR criada: ${UNIFIED_BRANCH}`);
    } else {
      console.warn('Nenhum commit novo e nenhum PR para atualizar.');
    }

    exec(`git checkout ${JSON.stringify(defaultBranch())}`, { cwd: GIT_CWD });
  } catch (err) {
    console.error('Falha fluxo unificado:', err.message || err);
    try {
      exec(`git checkout ${JSON.stringify(defaultBranch())}`, { cwd: GIT_CWD });
    } catch {
      void 0;
    }
    process.exit(1);
  }

  if (skippedNoPatch > 0) {
    console.log(`Alertas ignorados sem versão patch na API: ${skippedNoPatch}`);
  }
}

run();
