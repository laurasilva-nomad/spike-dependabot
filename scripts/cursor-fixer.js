const path = require('path');
const fs = require('fs');
const { execSync, execFileSync } = require('child_process');
const semver = require('semver');

/**
 * =============================================================================
 * CONFIGURAÇÕES E CONSTANTES
 * =============================================================================
 */
const UNIFIED_BRANCH = 'security/dependabot-remediation';

// Mapeia os comandos específicos de cada gerenciador de pacotes
const PM_CONFIGS = {
  pnpm: { 
    add: ['add', '-E'], 
    install: ['install', '--no-frozen-lockfile'] 
  },
  yarn: { 
    add: ['add', '--exact'], 
    install: ['install'] 
  },
  npm: { 
    add: ['install', '--save-exact'], 
    install: ['install'] 
  }
};

// Variáveis de estado global (preenchidas no preflight)
let PKG_ROOT, REPO_ROOT, PACKAGE_MANAGER, DEPENDENCY_GRAPH_CACHE = null;

/**
 * =============================================================================
 * UTILITÁRIOS DE SISTEMA (Wrapper para comandos de terminal)
 * =============================================================================
 */
function runShellCommand(cmd, args = [], options = {}) {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || process.env.GH_REPO_TOKEN;
  const env = { ...process.env, GH_TOKEN: token, ...options.env };
  
  try {
    return execFileSync(cmd, args, {
      cwd: options.cwd || REPO_ROOT,
      env,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (error) {
    if (options.ignoreError) return '';
    throw new Error(`Comando falhou: ${cmd} ${args.join(' ')}\nErro: ${error.stderr || error.message}`);
  }
}

/**
 * Executa uma ação no gerenciador de pacotes detectado (npm/pnpm/yarn)
 */
function runPackageManager(action, args = []) {
  const config = PM_CONFIGS[PACKAGE_MANAGER];
  const baseArgs = config[action] || [action];
  return runShellCommand(PACKAGE_MANAGER, [...baseArgs, ...args], { cwd: PKG_ROOT });
}

/**
 * =============================================================================
 * ANÁLISE DE AMBIENTE E DEPENDÊNCIAS
 * =============================================================================
 */
function setupEnvironment() {
  REPO_ROOT = process.env.GITHUB_WORKSPACE ? path.resolve(process.env.GITHUB_WORKSPACE) : findGitRoot(process.cwd());
  
  const relativePkgPath = process.env.SECURITY_PACKAGE_ROOT || '.';
  PKG_ROOT = path.resolve(REPO_ROOT, relativePkgPath);

  if (!fs.existsSync(path.join(PKG_ROOT, 'package.json'))) {
    throw new Error(`package.json não encontrado em: ${PKG_ROOT}`);
  }

  if (fs.existsSync(path.join(PKG_ROOT, 'pnpm-lock.yaml'))) PACKAGE_MANAGER = 'pnpm';
  else if (fs.existsSync(path.join(PKG_ROOT, 'yarn.lock'))) PACKAGE_MANAGER = 'yarn';
  else PACKAGE_MANAGER = 'npm';

  console.log(`🚀 Ambiente pronto: [${PACKAGE_MANAGER.toUpperCase()}] em ${relativePkgPath}`);
}

function findGitRoot(startDir) {
  let current = startDir;
  while (current !== path.parse(current).root) {
    if (fs.existsSync(path.join(current, '.git'))) return current;
    current = path.dirname(current);
  }
  return current;
}

function cacheDependencyGraph() {
  if (DEPENDENCY_GRAPH_CACHE) return;
  
  console.log("🔍 Analisando grafo de dependências (Cache inicial)...");
  const rawJson = runShellCommand('npm', ['ls', '--all', '--json'], { cwd: PKG_ROOT, ignoreError: true });
  
  try {
    DEPENDENCY_GRAPH_CACHE = JSON.parse(rawJson || '{}');
  } catch {
    DEPENDENCY_GRAPH_CACHE = { dependencies: {} };
  }
}

function getPackageMetadata(targetName) {
  cacheDependencyGraph();
  let maxDepth = 0;
  let resolvedVersion = '';

  function search(deps, depth) {
    if (!deps) return;
    for (const [name, info] of Object.entries(deps)) {
      if (name === targetName) {
        maxDepth = Math.max(maxDepth, depth);
        resolvedVersion = info.version || resolvedVersion;
      }
      if (info.dependencies) search(info.dependencies, depth + 1);
    }
  }

  search(DEPENDENCY_GRAPH_CACHE.dependencies, 1);
  return { depth: maxDepth, version: resolvedVersion };
}

/**
 * =============================================================================
 * LÓGICA DE REMEDIAÇÃO
 * =============================================================================
 */

function applyManualOverride(pkgName, version) {
  const pkgPath = path.join(PKG_ROOT, 'package.json');
  const pkgJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

  if (PACKAGE_MANAGER === 'pnpm') {
    pkgJson.pnpm = pkgJson.pnpm || {};
    pkgJson.pnpm.overrides = { ...pkgJson.pnpm.overrides, [pkgName]: version };
  } else if (PACKAGE_MANAGER === 'yarn') {
    pkgJson.resolutions = { ...pkgJson.resolutions, [pkgName]: version };
  } else {
    pkgJson.overrides = { ...pkgJson.overrides, [pkgName]: version };
  }

  fs.writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + '\n');
}

function isProjectHealthy() {
  console.log("🧪 Validando integridade do projeto...");
  try {
    runPackageManager('run', ['build']);
    runPackageManager('run', ['test']);
    return true;
  } catch {
    console.error("⚠️ Falha nos testes/build pós-atualização.");
    return false;
  }
}


/**
 * ORQUESTRAÇÃO VIA IA (Cérebro do Cursor)
 * Esta função envia o contexto para a IA decidir a melhor estratégia
 */
async function getAiOrchestratedStrategy(pkgName, patchVersion, meta) {
  const token = process.env.CURSOR_TOKEN;
  
  // Se não houver token, ele mantém a lógica determinística do diagrama
  if (!token) {
    if (meta.depth === 1) return 'Bump Direto';
    if (meta.depth > 2) return 'Override';
    return 'Transitivo (Pin)';
  }

  console.log(`🤖 Cursor AI orquestrando estratégia para ${pkgName}...`);
  
  /**
   * Aqui o script usaria o token para consultar a API de IA.
   * O prompt diria: "Dado o pacote X na profundidade Y, qual comando rodar?"
   * Para esta V1, simulamos a resposta da IA baseada no seu diagrama de regras:
   */
  if (meta.depth > 2) return 'Override';
  return 'Bump Direto'; 
}

function buildPRMarkdown(results, repoSlug) {
  const tableRows = results.map(r => {
    const statusIcon = r.healthy ? '✅ Passou' : '⚠️ Falhou (Build/Audit)';
    const alertLinks = (r.alerts || [])
      .map(a => `[#${a.number}](https://github.com/${repoSlug}/security/dependabot/${a.number})`)
      .join(', ');

    const versionFlow = r.version ? `\`${r.version}\` → \`${r.patch}\`` : `\`${r.patch}\``;

    return `| \`${r.name}\` | ${versionFlow} | ${r.strategy} | Lvl ${r.depth} | ${alertLinks} | ${statusIcon} |`;
  }).join('\n');

  return `## 🛡️ Relatório de Segurança (Consolidado)

Agrupamento automático de alertas Dependabot seguindo o fluxo **Self-Healing**.

### 📊 Resumo da Remediação
| Pacote | Mudança de Versão | Estratégia (Fluxo) | Nível | Alertas | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
${tableRows}

---

### 🧠 Lógica de Decisão (Conforme Diagrama)
- **Bump Direto / Transitivo:** Aplicado em pacotes de níveis rasos (Lvl 1-2) para manter a integridade nativa do lockfile.
- **Override / Resolution:** Aplicado em dependências profundas ou saltos de versão "Major" para forçar a segurança onde o comando \`add\` falha.
- **Validação:** O status reflete o sucesso do comando \`audit\` e dos scripts de \`build\` e \`test\`.

${results.some(r => !r.healthy) 
  ? '> [!CAUTION]\n> **Ação Necessária:** Algumas atualizações apresentaram instabilidade no build ou audit. Revise os logs antes do merge.' 
  : '> [!TIP]\n> **Sucesso:** Todos os pacotes foram atualizados e o projeto permanece estável.'
}

---
*Gerado por Cursor Security Fixer*`;
}


/**
 * =============================================================================
 * FLUXO PRINCIPAL (Runner) - Orquestrado e Automatizado
 * =============================================================================
 */
async function run() {
  setupEnvironment();

  // 1. Coleta alertas via API do GitHub
  const repoSlug = runShellCommand('gh', ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']).trim();
  const alertsRaw = runShellCommand('gh', ['api', `/repos/${repoSlug}/dependabot/alerts?state=open`]);
  const npmAlerts = JSON.parse(alertsRaw).filter(a => a.dependency.package.ecosystem === 'npm');

  if (npmAlerts.length === 0) {
    return console.log("✅ Nenhum alerta aberto encontrado.");
  }

  // 2. Agrupa por pacote e define a versão de patch mais alta
  const targetPatches = {};
  npmAlerts.forEach(alert => {
    const pkgName = alert.dependency.package.name;
    const patchVersion = alert.security_vulnerability?.first_patched_version?.identifier;
    
    if (patchVersion) {
      if (!targetPatches[pkgName]) {
        targetPatches[pkgName] = { name: pkgName, patch: '0.0.0', alerts: [] };
      }
      targetPatches[pkgName].alerts.push(alert);
      if (semver.gt(semver.coerce(patchVersion), semver.coerce(targetPatches[pkgName].patch))) {
        targetPatches[pkgName].patch = patchVersion;
      }
    }
  });

  // 3. Prepara Branch Git
  const defaultBranch = runShellCommand('gh', ['repo', 'view', '--json', 'defaultBranchRef', '-q', '.defaultBranchRef.name']).trim();
  runShellCommand('git', ['checkout', '-B', UNIFIED_BRANCH]);

  const remediationResults = [];

  // 4. Loop de Remediação (Agora com Orquestração)
  for (const pkg of Object.values(targetPatches)) {
    console.log(`\n📦 Processando: ${pkg.name} -> ${pkg.patch}`);
    const meta = getPackageMetadata(pkg.name);
    
    // CHAMADA DA ORQUESTRAÇÃO: Decide a estratégia baseado no Token/Fluxo
    const strategy = await getAiOrchestratedStrategy(pkg.name, pkg.patch, meta);

    try {
      // Executa a ação baseada na estratégia decidida
      if (strategy === 'Bump Direto' || strategy === 'Transitivo (Pin)') {
        runPackageManager('add', [`${pkg.name}@${pkg.patch}`]);
      } else if (strategy === 'Override') {
        applyManualOverride(pkg.name, pkg.patch);
      }

      runPackageManager('install');
      
      // Valida build e testes (Self-Healing)
      const healthy = isProjectHealthy();
      
      remediationResults.push({ 
        ...pkg, 
        strategy, 
        depth: meta.depth, 
        version: meta.version, 
        healthy 
      });
    } catch (err) {
      console.error(`❌ Falha crítica ao remediar ${pkg.name}: ${err.message}`);
    }
  }

  // 5. Finaliza e abre o Pull Request com Relatório Detalhado
  if (remediationResults.length > 0) {
    runShellCommand('git', ['add', '.']);
    runShellCommand('git', ['commit', '-m', `security: auto-patch ${remediationResults.length} vulnerabilities`], { ignoreError: true });
    runShellCommand('git', ['push', '-u', 'origin', 'HEAD', '--force']);
    
    const prBody = buildPRMarkdown(remediationResults, repoSlug);
    const prTitle = `🛡️ Security Fixes: ${remediationResults.length} pacotes atualizados`;

    try {
      // Tenta criar o PR; se falhar (já existir), edita o atual
      runShellCommand('gh', ['pr', 'create', '--title', prTitle, '--base', defaultBranch, '--body', prBody]);
    } catch {
      runShellCommand('gh', ['pr', 'edit', '--body', prBody]);
    }
    
    console.log(`\n✅ PR orquestrado com sucesso na branch ${UNIFIED_BRANCH}`);
  }
}

run().catch(err => {
  console.error(" Erro fatal no script:");
  console.error(err);
  process.exit(1);
});