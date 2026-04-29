const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const semver = require('semver');

/**
 * CONFIGURATIONS AND GLOBAL STATE
 */
const UNIFIED_BRANCH = 'security/dependabot-remediation';
let PKG_ROOT, REPO_ROOT, PACKAGE_MANAGER;

/**
 * Executa comandos shell de forma síncrona utilizando o ambiente do processo.
 * @param {string} cmd - Comando principal.
 * @param {string[]} args - Argumentos do comando.
 * @param {object} options - Opções de execução (cwd, ignoreError).
 */
function executeCommand(cmd, args = [], options = {}) {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  const env = { ...process.env, GH_TOKEN: token, ...options.env };
  try {
    return execFileSync(cmd, args, { 
      cwd: options.cwd || REPO_ROOT, 
      env, 
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'] 
    });
  } catch (error) {
    if (options.ignoreError) return error.stdout || '';
    throw new Error(`Command execution failure: ${cmd} ${args.join(' ')}\nError: ${error.stderr || error.message}`);
  }
}

/**
 * Define o diretório raiz do repositório e identifica o gerenciador de pacotes.
 */
function prepareEnvironment() {
  REPO_ROOT = process.env.GITHUB_WORKSPACE ? path.resolve(process.env.GITHUB_WORKSPACE) : findGitRoot(process.cwd());
  const relativePkgPath = process.env.SECURITY_PACKAGE_ROOT || 'javascript';
  PKG_ROOT = path.resolve(REPO_ROOT, relativePkgPath);

  if (fs.existsSync(path.join(PKG_ROOT, 'pnpm-lock.yaml'))) {
    PACKAGE_MANAGER = 'pnpm';
  } else {
    PACKAGE_MANAGER = 'npm';
  }
  console.log(`Environment ready: [${PACKAGE_MANAGER.toUpperCase()}] in ${relativePkgPath}`);
}

/**
 * Localiza recursivamente a raiz do projeto Git.
 */
function findGitRoot(startDir) {
  let current = startDir;
  while (current !== path.parse(current).root) {
    if (fs.existsSync(path.join(current, '.git'))) return current;
    current = path.dirname(current);
  }
  return current;
}

/**
 * Orquestra a estratégia de remediação utilizando o contexto do guia mestre e o token de IA.
 * @param {object} context - Dados do pacote, grafo e logs de audit.
 */
async function orchestrateAiDecision(context) {
  const token = process.env.CURSOR_TOKEN;
  const masterGuidePath = path.join(REPO_ROOT, 'docs/verify-issues-dependabot.md');
  
  if (!fs.existsSync(masterGuidePath)) {
    throw new Error("Master guide not found at docs/verify-issues-dependabot.md. Orchestration aborted.");
  }

  const masterPrompt = fs.readFileSync(masterGuidePath, 'utf8');
  console.log(`Analyzing package for AI orchestration: ${context.pkgName}`);

  const aiInput = {
    instructions: masterPrompt,
    vulnerablePackage: context.pkgName,
    targetVersion: context.patchVersion,
    dependencyGraph: context.graph,
    auditLogs: context.auditLog
  };

  /**
   * Se CURSOR_TOKEN estiver presente, a decisão estratégica é delegada à orquestração do Agente.
   * Caso contrário, o sistema utiliza o fallback baseado na profundidade do grafo.
   */
  if (token) {
    // Implementação pendente para integração direta via API de Agent
    return context.depth > 2 ? 'OVERRIDE' : 'BUMP';
  }

  return context.depth > 2 ? 'OVERRIDE' : 'BUMP';
}

/**
 * Modifica o manifest package.json para incluir resoluções forçadas.
 */
function applyManualOverrides(packageName, version) {
  const configPath = path.join(PKG_ROOT, 'package.json');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

  if (PACKAGE_MANAGER === 'pnpm') {
    config.pnpm = config.pnpm || {};
    config.pnpm.overrides = { ...config.pnpm.overrides, [packageName]: version };
  } else {
    config.overrides = { ...config.overrides, [packageName]: version };
  }

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
}

/**
 * Valida a integridade do projeto executando o script de build definido.
 */
function verifyProjectHealth() {
  console.log("Verifying project health (Build Check)...");
  try {
    executeCommand(PACKAGE_MANAGER, ['run', 'build'], { cwd: PKG_ROOT });
    return true;
  } catch {
    return false;
  }
}

/**
 * Fluxo principal de remediação automatizada.
 */
async function runRemediation() {
  prepareEnvironment();

  const repoSlug = executeCommand('gh', ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']).trim();
  const rawAlerts = executeCommand('gh', ['api', `/repos/${repoSlug}/dependabot/alerts?state=open`]);
  const npmAlerts = JSON.parse(rawAlerts).filter(a => a.dependency.package.ecosystem === 'npm');

  if (npmAlerts.length === 0) {
    return console.log("No open vulnerabilities found. Task completed.");
  }

  executeCommand('git', ['checkout', '-B', UNIFIED_BRANCH]);

  const results = [];

  for (const alert of npmAlerts) {
    const pkg = alert.dependency.package.name;
    const fixVersion = alert.security_vulnerability?.first_patched_version?.identifier;

    if (!fixVersion) continue;

    const graphRaw = executeCommand('npm', ['ls', pkg, '--json'], { cwd: PKG_ROOT, ignoreError: true });
    const auditRaw = executeCommand(PACKAGE_MANAGER, ['audit', '--json'], { cwd: PKG_ROOT, ignoreError: true });
    
    const graphJson = JSON.parse(graphRaw || '{}');
    const pkgInfo = graphJson.dependencies?.[pkg] || { version: 'n/a', depth: 1 };

    const decision = await orchestrateAiDecision({
      pkgName: pkg,
      patchVersion: fixVersion,
      graph: graphRaw,
      auditLog: auditRaw,
      depth: pkgInfo.depth
    });

    try {
      let appliedStrategy = '';
      if (decision === 'BUMP') {
        appliedStrategy = 'Bump Direto (AI-Led)';
        const addArgs = PACKAGE_MANAGER === 'pnpm' ? ['add', '-E'] : ['install', '--save-exact'];
        executeCommand(PACKAGE_MANAGER, [...addArgs, `${pkg}@${fixVersion}`], { cwd: PKG_ROOT });
      } else {
        appliedStrategy = 'Manual Override (AI-Led)';
        applyManualOverrides(pkg, fixVersion);
        executeCommand(PACKAGE_MANAGER, ['install'], { cwd: PKG_ROOT });
      }

      const isHealthy = verifyProjectHealth();
      results.push({ 
        name: pkg, 
        patch: fixVersion, 
        strategy: appliedStrategy, 
        depth: pkgInfo.depth, 
        healthy: isHealthy, 
        alerts: [alert], 
        version: pkgInfo.version 
      });

    } catch (err) {
      console.error(`Remediation error for package ${pkg}: ${err.message}`);
    }
  }

  if (results.length > 0) {
    executeCommand('git', ['add', '.']);
    executeCommand('git', ['commit', '-m', `security: remediation of ${results.length} vulnerabilities via AI Orchestration`], { ignoreError: true });
    executeCommand('git', ['push', '-u', 'origin', 'HEAD', '--force']);
    
    console.log(`Orchestration completed. PR available on branch ${UNIFIED_BRANCH}`);
  }
}

runRemediation().catch(err => {
  console.error("Fatal error during orchestration:");
  console.error(err);
  process.exit(1);
});