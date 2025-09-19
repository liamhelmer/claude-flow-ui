/**
 * Simple production test - verify the terminal UI loads and is functional
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testProductionFunctionality() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server...');

    // Start the server
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11237', // Use different port to avoid conflicts
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
      const timeout = setTimeout(() => reject(new Error('Server timeout')), 20000);

      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;

        if (output.includes('Running on:') || output.includes('localhost:11237')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.log('Server stderr:', data.toString().trim());
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    console.log('🌐 Starting browser...');
    browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    console.log('📱 Navigating to production server...');
    const response = await page.goto('http://localhost:11237', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response.status()}`);

    // Test basic functionality
    console.log('🔍 Testing basic UI elements...');

    // Wait for page to load
    await page.waitForTimeout(3000);

    // Check if main terminal container exists
    const terminalContainer = await page.$('.terminal-outer-container');

    // Check if there are any visible elements
    const visibleElements = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('*'))
        .filter(el => {
          const style = window.getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
        }).length;
    });

    // Check page title
    const title = await page.title();

    console.log('\n📊 PRODUCTION FUNCTIONALITY TEST RESULTS:');
    console.log('='.repeat(50));
    console.log(`Response Status: ${response.status()}`);
    console.log(`Page Title: ${title}`);
    console.log(`Terminal Container Found: ${!!terminalContainer}`);
    console.log(`Visible Elements: ${visibleElements}`);

    // Success criteria
    const success = (
      response.status() === 200 &&
      visibleElements > 10 && // Should have plenty of UI elements
      (title.includes('Claude') || title.includes('Terminal') || title === 'Claude Flow UI')
    );

    if (success) {
      console.log('✅ SUCCESS: Production server is functional');
      console.log('   - Server responds with 200');
      console.log('   - Page has rendered content');
      console.log('   - Basic UI structure is present');
    } else {
      console.log('❌ ISSUES: Production server has problems');
      if (response.status() !== 200) console.log(`   - HTTP error: ${response.status()}`);
      if (visibleElements <= 10) console.log(`   - Too few visible elements: ${visibleElements}`);
      if (!title.includes('Claude') && !title.includes('Terminal')) console.log(`   - Unexpected title: ${title}`);
    }

    return { success, status: response.status(), title, visibleElements, hasTerminalContainer: !!terminalContainer };

  } catch (error) {
    console.error('💥 Production test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

testProductionFunctionality().then(result => {
  console.log('\n🎯 FINAL RESULT:');
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.success ? 0 : 1);
});