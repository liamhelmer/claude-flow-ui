#!/usr/bin/env node

/**
 * K6 Setup and Installation Script
 *
 * Installs k6 and sets up performance testing environment
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('🚀 Setting up K6 Performance Testing Environment...\n');

/**
 * Detect operating system and install k6 accordingly
 */
function installK6() {
  const platform = os.platform();
  const arch = os.arch();

  console.log(`Detected platform: ${platform} (${arch})`);

  try {
    // Check if k6 is already installed
    execSync('k6 version', { stdio: 'pipe' });
    console.log('✅ K6 is already installed');
    return;
  } catch (error) {
    console.log('📦 Installing K6...');
  }

  try {
    switch (platform) {
      case 'darwin': // macOS
        console.log('Installing k6 via Homebrew...');
        execSync('brew install k6', { stdio: 'inherit' });
        break;

      case 'linux':
        console.log('Installing k6 via package manager...');
        // Try different package managers
        try {
          execSync('sudo apt-get update && sudo apt-get install -y k6', { stdio: 'inherit' });
        } catch (aptError) {
          try {
            execSync('sudo yum install -y k6', { stdio: 'inherit' });
          } catch (yumError) {
            // Fallback to binary download
            console.log('Installing k6 via binary download...');
            installK6Binary(platform, arch);
          }
        }
        break;

      case 'win32': // Windows
        console.log('Installing k6 via Chocolatey...');
        try {
          execSync('choco install k6', { stdio: 'inherit' });
        } catch (chocoError) {
          console.log('Chocolatey not found, installing via binary download...');
          installK6Binary(platform, arch);
        }
        break;

      default:
        console.log('Installing k6 via binary download...');
        installK6Binary(platform, arch);
        break;
    }

    // Verify installation
    execSync('k6 version', { stdio: 'inherit' });
    console.log('✅ K6 installed successfully');

  } catch (error) {
    console.error('❌ Failed to install k6:', error.message);
    console.log('\nPlease install k6 manually:');
    console.log('https://k6.io/docs/getting-started/installation/');
    process.exit(1);
  }
}

/**
 * Install k6 binary directly
 */
function installK6Binary(platform, arch) {
  const version = 'v0.47.0';
  let downloadUrl;
  let fileName;

  switch (platform) {
    case 'darwin':
      fileName = `k6-${version}-macos-${arch === 'arm64' ? 'arm64' : 'amd64'}.zip`;
      break;
    case 'linux':
      fileName = `k6-${version}-linux-${arch === 'arm64' ? 'arm64' : 'amd64'}.tar.gz`;
      break;
    case 'win32':
      fileName = `k6-${version}-windows-${arch === 'x64' ? 'amd64' : 'amd64'}.zip`;
      break;
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }

  downloadUrl = `https://github.com/grafana/k6/releases/download/${version}/${fileName}`;

  console.log(`Downloading ${fileName}...`);
  console.log(`URL: ${downloadUrl}`);

  // This is a simplified implementation
  // In production, you'd want to handle the download and extraction properly
  console.log('Please download and install k6 manually from:');
  console.log('https://k6.io/docs/getting-started/installation/');

  throw new Error('Manual installation required');
}

/**
 * Create k6 configuration and test structure
 */
function setupK6Environment() {
  console.log('🏗️  Setting up K6 test environment...');

  const k6Dir = path.join(__dirname);
  const subdirs = [
    'tests',
    'scripts',
    'config',
    'reports',
    'utils'
  ];

  // Create directories
  subdirs.forEach(dir => {
    const dirPath = path.join(k6Dir, dir);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      console.log(`✅ Created directory: ${dir}/`);
    }
  });

  // Create package.json for k6 dependencies
  const packageJson = {
    name: "claude-flow-ui-k6-tests",
    version: "1.0.0",
    description: "K6 performance tests for Claude Flow UI",
    scripts: {
      "test:load": "k6 run tests/load-test.js",
      "test:stress": "k6 run tests/stress-test.js",
      "test:spike": "k6 run tests/spike-test.js",
      "test:soak": "k6 run tests/soak-test.js",
      "test:api": "k6 run tests/api-test.js",
      "test:websocket": "k6 run tests/websocket-test.js",
      "test:all": "npm run test:api && npm run test:load && npm run test:stress"
    },
    dependencies: {}
  };

  const packageJsonPath = path.join(k6Dir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
    console.log('✅ Created k6/package.json');
  }

  console.log('✅ K6 environment setup complete');
}

/**
 * Validate installation
 */
function validateSetup() {
  console.log('🔍 Validating K6 setup...');

  try {
    const output = execSync('k6 version', { encoding: 'utf8' });
    console.log('K6 Version:', output.trim());

    // Test basic k6 functionality
    const testScript = `
      export default function() {
        console.log('K6 test validation successful');
      }
    `;

    const tempFile = path.join(__dirname, 'temp-validation-test.js');
    fs.writeFileSync(tempFile, testScript);

    execSync(`k6 run --vus 1 --duration 1s ${tempFile}`, { stdio: 'pipe' });
    fs.unlinkSync(tempFile);

    console.log('✅ K6 validation successful');

  } catch (error) {
    console.error('❌ K6 validation failed:', error.message);
    process.exit(1);
  }
}

/**
 * Main setup function
 */
async function main() {
  try {
    console.log('='.repeat(60));
    console.log('📊 CLAUDE FLOW UI - K6 PERFORMANCE TESTING SETUP');
    console.log('='.repeat(60));

    installK6();
    setupK6Environment();
    validateSetup();

    console.log('\n' + '='.repeat(60));
    console.log('🎉 K6 SETUP COMPLETED SUCCESSFULLY!');
    console.log('='.repeat(60));

    console.log('\nNext steps:');
    console.log('1. Run performance tests: npm run test:performance:k6');
    console.log('2. Individual tests: npm run test:load, npm run test:stress, etc.');
    console.log('3. View test files in: tests/performance/k6/tests/');
    console.log('4. Customize configurations in: tests/performance/k6/config/');

  } catch (error) {
    console.error('\n💥 Setup failed:', error.message);
    process.exit(1);
  }
}

// Run setup if called directly
if (require.main === module) {
  main();
}

module.exports = {
  installK6,
  setupK6Environment,
  validateSetup
};