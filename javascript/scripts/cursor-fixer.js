const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

const SEVERITIES = ['critical', 'high'];
const REPO_ROOT = path.join(__dirname, '..', '..');
const RULES_PATH = path.join(
  REPO_ROOT,
  '.cursor',
  'rules',
  'verify-issues-dependabot.mdc'
);

function readTextIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

async function run() {
  console.log("🔍 Buscando alertas de vulnerabilidade (Critical/High)...");

  try {
    if (process.env.CURSOR_TOKEN && !fs.existsSync(RULES_PATH)) {
      console.warn(`Rules file missing: ${RULES_PATH}`);
    }

    const workspaceYaml = readTextIfExists(
      path.join(REPO_ROOT, 'pnpm-workspace.yaml')
    );
    const rootPackageJson = readTextIfExists(
      path.join(REPO_ROOT, 'package.json')
    );
    console.log(
      `Monorepo hints: workspaceFile=${workspaceYaml.length > 0} rootPackageJson=${rootPackageJson.length > 0}`
    );
    const alertsJson = execSync(
      `gh api repos/:owner/:repo/dependabot/alerts?state=open --per-page 100`
    ).toString();
    
    const alerts = JSON.parse(alertsJson).filter(a => 
      SEVERITIES.includes(a.security_advisory.severity)
    );

    if (alerts.length === 0) {
      console.log("✅ Nenhuma vulnerabilidade crítica ou alta encontrada.");
      return;
    }

    console.log(`🚀 Encontradas ${alerts.length} vulnerabilidades. Iniciando triagem...`);

    for (const alert of alerts) {
      const pkgName = alert.dependency.package.name;
      const safeVersion = alert.security_advisory.patched_versions.split(',').pop().trim().replace(/[><=]/g, '');
      const alertId = alert.number;

      console.log(`\n--- Analisando: ${pkgName} (#${alertId}) ---`);

      // STEP 0: Ghost Check (Obrigatório conforme o guia)
      console.log(`👻 Step 0: pnpm why ${pkgName}`);
      const whyOutput = execSync(`pnpm why ${pkgName} --json || true`).toString();
      
      // Se não houver dependentes reais, é um "fantasma" no lockfile
      if (whyOutput.includes('"dependencies":{}') || whyOutput === '[]') {
        console.log(`✨ ${pkgName} é um fantasma. Limpando lockfile...`);
        execSync('pnpm install');
        createPR(pkgName, 'Ghost Cleanup', alertId, 'Remoção de dependência fantasma via Step 0.');
        continue;
      }

      // DECISÃO TÉCNICA E APLICAÇÃO
      // Conforme o guia: Sempre versão fixa (-E)
      try {
        console.log(`🛠️ Aplicando Bump: pnpm add -E ${pkgName}@${safeVersion}`);
        
        // Verifica se é Workspace (Catalog) ou Raiz (conforme seção 'Escopo' do seu guia)
        const isWorkspace =
          workspaceYaml.length > 0 && workspaceYaml.includes(pkgName);

        if (isWorkspace) {
          console.log("📍 Detectado no Workspace/Catalog.");
        }

        // Executa a instalação fixa
        execSync(`pnpm add -E ${pkgName}@${safeVersion} --ignore-scripts`);

        // VALIDAR (Step 4 do guia)
        console.log("🧪 Validando com pnpm audit...");
        execSync('pnpm install && pnpm audit --level high');

        // Se chegou aqui sem erro, abre a PR
        createPR(pkgName, safeVersion, alertId);
        
      } catch (error) {
        console.error(`⚠️ Falha ao corrigir ${pkgName} automaticamente. Verifique se é uma sub-dependência que exige Override.`);
        // Aqui o Cursor/LLM entraria para decidir por um Override no package.json
      }
    }
  } catch (err) {
    console.error("❌ Erro no processo:", err.message);
    process.exit(1);
  }
}

function createPR(pkg, ver, id, customMsg = '') {
  const branch = `security/fix-${pkg}-${id}`;
  const title = `🛡️ Security: Fix ${pkg} to ${ver}`;
  const body = customMsg || `Corrigindo vulnerabilidade detectada pelo Dependabot (#${id}).\n\n**Regras aplicadas:**\n- Versão Fixa (-E)\n- Step 0 (Ghost Check) concluído\n- Audit validado.`;

  try {
    execSync(`git checkout -b ${branch}`);
    execSync(`git add . && git commit -m "${title}"`);
    execSync(`git push origin ${branch} --force`);
    execSync(`gh pr create --title "${title}" --body "${body}" --base main --head ${branch}`);
    console.log(`✅ PR aberta para ${pkg}`);
    execSync(`git checkout main`);
  } catch (e) {
    console.log("⚠️ PR já existe ou erro ao subir branch.");
    execSync(`git checkout main`);
  }
}

run();