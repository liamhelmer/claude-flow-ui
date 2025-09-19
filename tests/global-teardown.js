/**
 * Global teardown for terminal regression tests
 */

async function globalTeardown() {
  console.log('🧹 Running global teardown...');

  // Kill any remaining processes
  const { execSync } = require('child_process');

  try {
    // Kill any remaining server processes on our test ports
    execSync('pkill -f "claude-flow-ui.*11242" || true', { stdio: 'ignore' });
    execSync('pkill -f "claude-flow-ui.*11243" || true', { stdio: 'ignore' });
    console.log('✅ Cleaned up server processes');
  } catch (error) {
    console.log('⚠️ No server processes to clean up');
  }

  console.log('✅ Global teardown complete');
}

module.exports = globalTeardown;