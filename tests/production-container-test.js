/**
 * Test container detection in production mode
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testProductionMode() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server...');

    // Start server in production mode
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11236',
      '--terminal-size', '120x40',
      'hive-mind', 'spawn', 'wait for instructions',
      '--claude'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => reject(new Error('Server timeout')), 30000);

      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        console.log('📊 Server output:', text.trim());

        if (output.includes('Running on:') || output.includes('localhost:11236')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.log('⚠️ Server stderr:', data.toString().trim());
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    console.log('🌐 Starting browser...');
    browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    const containerLogs = [];
    page.on('console', (msg) => {
      const text = msg.text();

      // Capture container-related logs
      if (text.includes('Container') || text.includes('Terminal Component')) {
        containerLogs.push(text);
        console.log(`🖥️ CONTAINER: ${text}`);
      }
    });

    console.log('📱 Navigating to production server...');
    const response = await page.goto('http://localhost:11236', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response.status()}`);

    // Wait for container detection
    console.log('⏳ Waiting for container detection in production...');
    await page.waitForTimeout(15000);

    // Analyze results
    const containerErrors = containerLogs.filter(log =>
      log.includes('Container not found') || log.includes('Container not ready yet')
    );

    const containerSuccess = containerLogs.filter(log =>
      log.includes('Container found') || log.includes('Container element detected')
    );

    console.log('\n📊 PRODUCTION TEST RESULTS:');
    console.log('='.repeat(50));
    console.log(`Container error logs: ${containerErrors.length}`);
    console.log(`Container success logs: ${containerSuccess.length}`);

    if (containerErrors.length === 0) {
      console.log('✅ SUCCESS: No container detection errors in production');
      return { success: true, errors: 0, successes: containerSuccess.length };
    } else {
      console.log('❌ ISSUES: Container detection problems in production');
      containerErrors.forEach((error, i) => console.log(`  ${i + 1}. ${error}`));
      return { success: false, errors: containerErrors.length, successes: containerSuccess.length };
    }

  } catch (error) {
    console.error('💥 Production test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

testProductionMode().then(result => {
  console.log('\n🎯 FINAL PRODUCTION RESULT:');
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.success ? 0 : 1);
});