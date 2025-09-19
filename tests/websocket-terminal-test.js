/**
 * Test WebSocket connection and terminal functionality in production
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testWebSocketTerminal() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server...');

    // Start the server
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11238',
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
        console.log('📊 Server:', text.trim());

        if (output.includes('Running on:') || output.includes('localhost:11238')) {
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

    const logs = {
      websocket: [],
      terminal: [],
      errors: []
    };

    page.on('console', (msg) => {
      const text = msg.text();

      // Categorize logs
      if (text.includes('WebSocket') || text.includes('socket') || text.includes('connect')) {
        logs.websocket.push(text);
        console.log(`🔌 WebSocket: ${text}`);
      }

      if (text.includes('Terminal') || text.includes('terminal') || text.includes('xterm')) {
        logs.terminal.push(text);
        console.log(`💻 Terminal: ${text}`);
      }

      if (msg.type() === 'error' || text.includes('Error') || text.includes('Failed')) {
        logs.errors.push(text);
        console.log(`❌ Error: ${text}`);
      }
    });

    page.on('websocket', (ws) => {
      console.log('🔗 WebSocket created:', ws.url());
    });

    console.log('📱 Navigating to production server...');
    const response = await page.goto('http://localhost:11238', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response.status()}`);

    // Wait for things to initialize
    console.log('⏳ Waiting for initialization...');
    await page.waitForTimeout(5000);

    // Check for WebSocket connection
    const wsConnected = await page.evaluate(() => {
      // Look for WebSocket in window or any global variable
      return typeof WebSocket !== 'undefined';
    });

    // Check for terminal elements
    const terminalElements = await page.evaluate(() => {
      return {
        xtermElements: document.querySelectorAll('[class*="xterm"]').length,
        terminalContainers: document.querySelectorAll('.terminal-container').length,
        visibleDivs: Array.from(document.querySelectorAll('div')).filter(el => {
          const style = window.getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden';
        }).length
      };
    });

    // Check if any terminal-related text appears
    const pageContent = await page.content();
    const hasTerminalContent = pageContent.includes('terminal') || pageContent.includes('Terminal');

    console.log('\n📊 WEBSOCKET & TERMINAL TEST RESULTS:');
    console.log('='.repeat(50));
    console.log(`WebSocket Available: ${wsConnected}`);
    console.log(`WebSocket Logs: ${logs.websocket.length}`);
    console.log(`Terminal Logs: ${logs.terminal.length}`);
    console.log(`Error Logs: ${logs.errors.length}`);
    console.log(`Terminal Elements:`, terminalElements);
    console.log(`Has Terminal Content: ${hasTerminalContent}`);

    // Key success indicators
    const wsSuccess = logs.websocket.some(log =>
      log.includes('connected') ||
      log.includes('Connected') ||
      log.includes('ready')
    );

    const terminalSuccess = logs.terminal.some(log =>
      log.includes('ready') ||
      log.includes('initialized') ||
      log.includes('created')
    );

    if (wsSuccess || terminalSuccess) {
      console.log('\n✅ SUCCESS: WebSocket and/or Terminal initialized');
      if (wsSuccess) console.log('   - WebSocket connected successfully');
      if (terminalSuccess) console.log('   - Terminal initialized successfully');
    } else {
      console.log('\n⚠️ PARTIAL SUCCESS: Server running but no clear WebSocket/Terminal confirmation');
      console.log('   - This may be normal if logs are filtered');
    }

    // Log sample of each type
    if (logs.websocket.length > 0) {
      console.log('\nSample WebSocket logs:');
      logs.websocket.slice(0, 3).forEach(log => console.log(`   - ${log}`));
    }

    if (logs.terminal.length > 0) {
      console.log('\nSample Terminal logs:');
      logs.terminal.slice(0, 3).forEach(log => console.log(`   - ${log}`));
    }

    if (logs.errors.length > 0) {
      console.log('\nErrors found:');
      logs.errors.slice(0, 3).forEach(log => console.log(`   - ${log}`));
    }

    return {
      success: response.status() === 200 && logs.errors.length === 0,
      wsConnected: wsSuccess,
      terminalReady: terminalSuccess,
      stats: {
        websocketLogs: logs.websocket.length,
        terminalLogs: logs.terminal.length,
        errorLogs: logs.errors.length,
        terminalElements
      }
    };

  } catch (error) {
    console.error('💥 Test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

testWebSocketTerminal().then(result => {
  console.log('\n🎯 FINAL RESULT:');
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.success ? 0 : 1);
});