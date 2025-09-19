/**
 * Test WebSocket data transmission for terminal input
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testWebSocketData() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server for WebSocket test...');

    // Start the server
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11243',
      '--terminal-size', '80x24',
      '/bin/bash'  // Use bash directly
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    await new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';
      const timeout = setTimeout(() => {
        console.log('Server output so far:', output);
        console.log('Server error output:', errorOutput);
        reject(new Error('Server timeout'));
      }, 30000);

      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;

        // Look for WebSocket data events
        if (text.includes('📊 Data received from socket')) {
          console.log('🔥 WebSocket data received on server:', text.trim());
        }

        if (output.includes('Running on:') || output.includes('localhost:11243')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000); // Give server extra time to fully start
        }
      });

      serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        errorOutput += text;
        console.log('⚠️ Server stderr:', text.trim());

        // Still resolve if we see the server starting
        if (text.includes('Running on:') || text.includes('localhost:11243')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    console.log('🌐 Starting browser...');
    browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    // Track WebSocket events
    const websocketEvents = {
      dataEmitted: [],
      terminalDataReceived: []
    };

    page.on('console', (msg) => {
      const text = msg.text();

      // Track WebSocket emit events
      if (text.includes('[WebSocket] 📨 Emitting event')) {
        websocketEvents.dataEmitted.push({
          time: Date.now(),
          message: text
        });
        console.log(`📨 WebSocket emit detected: ${text}`);
      }

      if (text.includes('[WebSocket] 📤 Sending data to session')) {
        console.log(`📤 sendData called: ${text}`);
      }

      // Track terminal data received
      if (text.includes('terminal-data') && text.includes('Received')) {
        websocketEvents.terminalDataReceived.push({
          time: Date.now(),
          message: text
        });
        console.log(`📥 Terminal data received: ${text.substring(0, 100)}`);
      }
    });

    console.log('📱 Navigating to production server...');
    const response = await page.goto('http://localhost:11243', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response.status()}`);

    // Wait for terminal to be fully initialized
    console.log('⏳ Waiting for terminal initialization...');
    await page.waitForTimeout(10000);

    // Type test input
    const testInput = 'ls -la';
    console.log(`\n⌨️ Typing test input: "${testInput}"`);

    // Focus terminal and type
    await page.click('.xterm-wrapper, .terminal-container, .xterm', {
      force: true,
      timeout: 5000
    }).catch(() => {
      console.log('⚠️ Could not click terminal directly');
    });

    // Type the test command
    for (const char of testInput) {
      await page.keyboard.type(char);
      await page.waitForTimeout(100); // Small delay between characters
    }

    // Press Enter
    await page.keyboard.press('Enter');
    console.log('↩️ Pressed Enter');

    // Wait for output to appear
    console.log('⏳ Waiting for output...');
    await page.waitForTimeout(3000);

    // Analyze results
    console.log('\n📊 WEBSOCKET DATA FLOW TEST RESULTS:');
    console.log('='.repeat(60));
    console.log(`WebSocket Emit Events: ${websocketEvents.dataEmitted.length}`);
    console.log(`Terminal Data Received Events: ${websocketEvents.terminalDataReceived.length}`);

    // Log sample events for debugging
    if (websocketEvents.dataEmitted.length > 0) {
      console.log('\nWebSocket emit events (first 3):');
      websocketEvents.dataEmitted.slice(0, 3).forEach((e, i) => {
        console.log(`   ${i + 1}. ${e.message}`);
      });
    } else {
      console.log('\n❌ No WebSocket emit events detected!');
    }

    const success = websocketEvents.dataEmitted.length > 0;

    if (success) {
      console.log('\n✅ SUCCESS: WebSocket is emitting data');
    } else {
      console.log('\n❌ FAILURE: WebSocket is not emitting data');
    }

    return { success };

  } catch (error) {
    console.error('💥 Test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

// Run the test
testWebSocketData().then(result => {
  console.log('\n🎯 WEBSOCKET TEST FINAL RESULT:', result);
  process.exit(result.success ? 0 : 1);
});