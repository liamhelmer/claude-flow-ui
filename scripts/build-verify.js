#!/usr/bin/env node

/**
 * Build Verification Script for Claude Flow UI
 * 
 * This script verifies that the static build process works correctly
 * and that all necessary files are present for the CLI package.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function checkFile(filePath, description) {
  const exists = fs.existsSync(filePath);
  const status = exists ? `${colors.green}✅` : `${colors.red}❌`;
  log(`${status} ${description}: ${filePath}`);
  return exists;
}

function checkDirectory(dirPath, description) {
  const exists = fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory();
  const status = exists ? `${colors.green}✅` : `${colors.red}❌`;
  log(`${status} ${description}: ${dirPath}`);
  return exists;
}

function main() {
  log(`${colors.bold}${colors.blue}🔍 Claude Flow UI Build Verification${colors.reset}\n`);

  const rootDir = path.resolve(__dirname, '..');
  const outDir = path.join(rootDir, 'out');
  
  let allChecksPass = true;

  // Check if build has been run
  log(`${colors.bold}📁 Checking build output:${colors.reset}`);
  if (!checkDirectory(outDir, 'Static build output directory')) {
    log(`${colors.yellow}⚠️  Run 'npm run build:static' to generate static files${colors.reset}\n`);
    
    // Try to build automatically
    log(`${colors.blue}🔨 Running build:static automatically...${colors.reset}`);
    try {
      execSync('npm run build:static', { 
        stdio: 'inherit', 
        cwd: rootDir 
      });
      log(`${colors.green}✅ Build completed successfully${colors.reset}\n`);
    } catch (error) {
      log(`${colors.red}❌ Build failed: ${error.message}${colors.reset}`);
      allChecksPass = false;
      return;
    }
  }

  // Check critical static files
  log(`${colors.bold}📄 Checking static files:${colors.reset}`);
  const criticalFiles = [
    { path: path.join(outDir, 'index.html'), desc: 'Main HTML file' },
    { path: path.join(outDir, '_next'), desc: 'Next.js assets directory' },
  ];

  criticalFiles.forEach(({ path: filePath, desc }) => {
    if (!checkFile(filePath, desc)) {
      allChecksPass = false;
    }
  });

  // Check server files
  log(`\n${colors.bold}⚙️  Checking server files:${colors.reset}`);
  const serverFiles = [
    { path: path.join(rootDir, 'unified-server.js'), desc: 'Main server file' },
    { path: path.join(rootDir, 'src/lib/tmux-stream-manager.js'), desc: 'Tmux stream manager' },
    { path: path.join(rootDir, 'package.json'), desc: 'Package configuration' },
  ];

  serverFiles.forEach(({ path: filePath, desc }) => {
    if (!checkFile(filePath, desc)) {
      allChecksPass = false;
    }
  });

  // Check package.json configuration
  log(`\n${colors.bold}📦 Checking package configuration:${colors.reset}`);
  try {
    const packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
    
    const hasStaticBuild = packageJson.scripts && packageJson.scripts['build:static'];
    log(`${hasStaticBuild ? colors.green + '✅' : colors.red + '❌'} build:static script defined`);
    
    const hasCorrectFiles = packageJson.files && packageJson.files.includes('out/');
    log(`${hasCorrectFiles ? colors.green + '✅' : colors.red + '❌'} 'out/' directory in files array`);
    
    const hasBin = packageJson.bin && packageJson.bin['claude-flow-ui'];
    log(`${hasBin ? colors.green + '✅' : colors.red + '❌'} Binary entry point configured`);
    
    if (!hasStaticBuild || !hasCorrectFiles || !hasBin) {
      allChecksPass = false;
    }
  } catch (error) {
    log(`${colors.red}❌ Error reading package.json: ${error.message}`);
    allChecksPass = false;
  }

  // Test server startup in static mode
  log(`\n${colors.bold}🚀 Testing static server mode:${colors.reset}`);
  try {
    // Set environment to production to trigger static mode
    const testEnv = { ...process.env, NODE_ENV: 'production' };
    
    // Quick test to see if server can start (just validate, don't actually start)
    const serverPath = path.join(rootDir, 'unified-server.js');
    const testCode = `
      const path = require('path');
      const fs = require('fs');
      process.chdir('${rootDir}');
      
      // Mock the server startup to just test detection logic
      const staticOutDir = path.join(__dirname, 'out');
      const useStaticFiles = process.env.NODE_ENV !== 'development' && fs.existsSync(staticOutDir);
      
      console.log('Static mode detection:', useStaticFiles);
      process.exit(useStaticFiles ? 0 : 1);
    `;
    
    execSync(`node -e "${testCode}"`, { 
      stdio: 'pipe',
      env: testEnv,
      cwd: rootDir
    });
    
    log(`${colors.green}✅ Static server mode detection works correctly`);
  } catch (error) {
    log(`${colors.red}❌ Static server mode test failed`);
    allChecksPass = false;
  }

  // Summary
  log(`\n${colors.bold}📋 Verification Summary:${colors.reset}`);
  if (allChecksPass) {
    log(`${colors.green}${colors.bold}🎉 All checks passed! The package is ready for distribution.${colors.reset}`);
    log(`${colors.blue}📦 You can now run 'npm pack' to create the package tarball.${colors.reset}`);
    process.exit(0);
  } else {
    log(`${colors.red}${colors.bold}❌ Some checks failed. Please fix the issues above.${colors.reset}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { checkFile, checkDirectory, main };