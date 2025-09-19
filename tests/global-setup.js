/**
 * Global setup for terminal regression tests
 */

async function globalSetup() {
  console.log('🏗️ Setting up global test environment...');

  // Ensure clean state
  process.env.NODE_ENV = 'production';

  // Create results directory
  const fs = require('fs');
  const path = require('path');

  const resultsDir = path.join(__dirname, 'results');
  if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir, { recursive: true });
  }

  console.log('✅ Global setup complete');
}

module.exports = globalSetup;