/**
 * Simple test to check if Terminal component ref callback is called
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testRefCallback() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting server...');

    // Start the server with the test command
    serverProcess = spawn('npm', ['run', 'claude-flow-ui', '--', '--port', '11236'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => reject(new Error('Server timeout')), 20000);

      serverProcess.stdout.on('data', (data) => {
        output += data.toString();
        if (output.includes('Running on:')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.log('Server stderr:', data.toString().trim());
      });
    });

    console.log('🌐 Starting browser...');
    browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    const logs = [];
    page.on('console', (msg) => {
      const text = msg.text();
      logs.push(text);

      // Log HomePage, Terminal, and Container related messages
      if (text.includes('HomePage') || text.includes('Terminal Component') || text.includes('Ref callback') || text.includes('Dynamic import') || text.includes('Container')) {
        console.log(`🖥️ DEBUG: ${text}`);
      }
    });

    console.log('📱 Navigating to page...');
    await page.goto('http://localhost:11236', { waitUntil: 'networkidle' });

    // Wait for a bit to see logs
    await page.waitForTimeout(10000);

    // Check if we saw any ref callbacks
    const refCallbacks = logs.filter(log => log.includes('[Terminal Component] 🔧 Ref callback'));
    const componentRenders = logs.filter(log => log.includes('[Terminal Component] 🔧 Rendering') || log.includes('[Terminal Component] 🔧 Component render'));

    console.log('\n📊 RESULTS:');
    console.log(`Component renders: ${componentRenders.length}`);
    console.log(`Ref callbacks: ${refCallbacks.length}`);

    if (componentRenders.length > 0) {
      console.log('\n🔍 Component render logs:');
      componentRenders.forEach(log => console.log(`  - ${log}`));
    }

    if (refCallbacks.length > 0) {
      console.log('\n🔍 Ref callback logs:');
      refCallbacks.forEach(log => console.log(`  - ${log}`));
    } else {
      console.log('\n❌ NO REF CALLBACKS DETECTED');
    }

    return { refCallbacks: refCallbacks.length, renders: componentRenders.length };

  } catch (error) {
    console.error('Test failed:', error);
    return { error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

testRefCallback().then(result => {
  console.log('\nFinal result:', result);
  process.exit(result.error ? 1 : 0);
});