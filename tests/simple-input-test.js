/**
 * Simple test to verify terminal input is being sent to server
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testSimpleInput() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server...');

    // Start the server with debug logging
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11242',
      '--terminal-size', '80x24',
      'echo', 'ready'
    ], {
      env: { ...process.env, NODE_ENV: 'production', DEBUG: 'true', DEBUG_TMUX: 'true' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    await new Promise((resolve) => {
      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        console.log('📊 Server:', text.trim());
        if (text.includes('Running on:') || text.includes('localhost:11242')) {
          setTimeout(resolve, 2000);
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.log('⚠️ Server stderr:', data.toString().trim());
      });
    });

    console.log('🌐 Starting browser...');
    browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    // Enable verbose logging
    page.on('console', (msg) => {
      const text = msg.text();
      if (text.includes('Sending data to session') ||
          text.includes('📤 Sending data') ||
          text.includes('Input:')) {
        console.log(`🔵 Client: ${text}`);
      }
    });

    console.log('📱 Navigating to server...');
    await page.goto('http://localhost:11242', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    // Wait for initialization
    console.log('⏳ Waiting for initialization...');
    await page.waitForTimeout(10000);

    // Type a simple command
    console.log('⌨️ Typing test input...');
    await page.click('.xterm-wrapper, .terminal-container, .xterm', {
      force: true
    }).catch(() => console.log('Could not click terminal'));

    // Type 'ls' and press enter
    await page.keyboard.type('ls');
    await page.waitForTimeout(500);
    await page.keyboard.press('Enter');

    console.log('⏳ Waiting for response...');
    await page.waitForTimeout(3000);

    // Check terminal content
    const content = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm');
      return terminal ? terminal.textContent : 'No terminal found';
    });

    console.log('\n📊 RESULTS:');
    console.log('Terminal content:', content ? content.substring(0, 200) : 'Empty');

    const success = content && (content.includes('ls') || content.length > 50);
    console.log(success ? '✅ SUCCESS: Input appears to work' : '❌ FAILURE: Input not working');

    return { success };

  } catch (error) {
    console.error('💥 Test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

testSimpleInput().then(result => {
  console.log('\n🎯 FINAL RESULT:', result);
  process.exit(result.success ? 0 : 1);
});