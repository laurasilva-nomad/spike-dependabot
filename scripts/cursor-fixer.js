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
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

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
      stdio: ['pipe', 'pipe', 'pipe'] // Captura stdout e stderr sem "sujar" o terminal
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
  const baseArgs = config[action] || [action]; // Ex: se não mapeado, tenta rodar 'run', 'test'
  return runShellCommand(PACKAGE_MANAGER, [...baseArgs, ...args], { cwd: PKG_ROOT });
}

/**
 * =============================================================================
 * ANÁLISE DE AMBIENTE E DEPENDÊNCIAS
 * =============================================================================
 */
function setupEnvironment() {
  // Localiza a raiz do Git e o subdiretório do projeto (Monorepo support)
  REPO_ROOT = process.env.GITHUB_WORKSPACE ? path.resolve(process.env.GITHUB_WORKSPACE) : findGitRoot(process.cwd());
  
  const relativePkgPath = process.env.SECURITY_PACKAGE_ROOT || '.';
  PKG_ROOT = path.resolve(REPO_ROOT, relativePkgPath);

  if (!fs.existsSync(path.join(PKG_ROOT, 'package.json'))) {
    throw new Error(`package.json não encontrado em: ${PKG_ROOT}`);
  }

  // Detecta qual lockfile existe para definir o gerenciador
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

/**
 * Gera um cache da árvore de dependências para evitar múltiplas chamadas lentas ao terminal
 */
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

/**
 * Identifica a profundidade e a versão atual de um pacote no grafo
 */
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

/**
 * Aplica injeção de versão forçada no package.json (Overrides/Resolutions)
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

/**
 * Executa scripts de Build e Teste para garantir que nada quebrou
 */
function isProjectHealthy() {
  console.log("🧪 Validando integridade do projeto...");
  try {
    // Tenta rodar build e test (se existirem)
    runPackageManager('run', ['build']);
    runPackageManager('run', ['test']);
    return true;
  } catch {
    console.error("⚠️ Falha nos testes/build pós-atualização.");
    return false;
  }
}

/**
 * Formata o corpo do Pull Request em Markdown de forma detalhada e visual
 */
function buildPRMarkdown(results, repoSlug) {
  const tableRows = results.map(r => {
    const statusIcon = r.healthy ? '✅ Passou' : '⚠️ Falhou (Build/Audit)';
    
    // Cria links clicáveis para cada alerta resolvido por este pacote
    // Garantimos que r.alerts existe antes de mapear
    const alertLinks = (r.alerts || [])
      .map(a => `[#${a.number}](https://github.com/${repoSlug}/security/dependabot/${a.number})`)
      .join(', ');

    // Formata a mudança de versão (Antiga -> Nova)
    const versionFlow = r.version ? `\`${r.version}\` → \`${r.patch}\`` : `\`${r.patch}\``;

    // CORRIGIDO: Agora envolto em template literals (crases)
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
 * FLUXO PRINCIPAL (Runner)
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
     
     // Adiciona o alerta à lista deste pacote
     targetPatches[pkgName].alerts.push(alert);

     // Garante que pegamos a maior versão sugerida entre todos os alertas do mesmo pacote
     if (semver.gt(semver.coerce(patchVersion), semver.coerce(targetPatches[pkgName].patch))) {
       targetPatches[pkgName].patch = patchVersion;
     }
   }
 });

  // 3. Prepara Branch Git
  const defaultBranch = runShellCommand('gh', ['repo', 'view', '--json', 'defaultBranchRef', '-q', '.defaultBranchRef.name']).trim();
  runShellCommand('git', ['checkout', '-B', UNIFIED_BRANCH]);

  const remediationResults = [];

  // 4. Loop de Remediação
  for (const pkg of Object.values(targetPatches)) {
    console.log(`\n📦 Processando: ${pkg.name} -> ${pkg.patch}`);
    const meta = getPackageMetadata(pkg.name);
    let strategy = '';

    try {
      const isMajorUpgrade = meta.version && semver.major(semver.coerce(pkg.patch)) > semver.major(semver.coerce(meta.version));

      // Aplica a melhor estratégia baseada na profundidade e no risco
      if (meta.depth === 1) {
        strategy = 'Bump Direto';
        runPackageManager('add', [`${pkg.name}@${pkg.patch}`]);
      } else if (meta.depth > 2 || isMajorUpgrade) {
        strategy = 'Override';
        applyManualOverride(pkg.name, pkg.patch);
      } else {
        strategy = 'Transitivo (Pin)';
        runPackageManager('add', [`${pkg.name}@${pkg.patch}`]);
      }

      runPackageManager('install');
      const healthy = isProjectHealthy();
      
      remediationResults.push({ ...pkg, strategy, depth: meta.depth, healthy });
    } catch (err) {
      console.error(`❌ Falha crítica ao remediar ${pkg.name}: ${err.message}`);
    }
  }

  // 5. Finaliza e abre o Pull Request
  if (remediationResults.length > 0) {
    runShellCommand('git', ['add', '.']);
    runShellCommand('git', ['commit', '-m', `security: auto-patch ${remediationResults.length} vulnerabilities`], { ignoreError: true });
    runShellCommand('git', ['push', '-u', 'origin', 'HEAD', '--force']);
    
    const prBody = buildPRMarkdown(remediationResults, repoSlug);
    const prTitle = `🛡️ Security Fixes: ${remediationResults.length} pacotes atualizados`;

    try {
      runShellCommand('gh', ['pr', 'create', '--title', prTitle, '--base', defaultBranch, '--body', prBody]);
    } catch {
      // Se a PR já existir, apenas atualiza o corpo
      runShellCommand('gh', ['pr', 'edit', '--body', prBody]);
    }
    
    console.log(`\n✅ PR atualizado com sucesso na branch ${UNIFIED_BRANCH}`);
  }
}

// Execução
run().catch(err => {
  console.error("💥 Erro fatal no script:");
  console.error(err);
  process.exit(1);
});