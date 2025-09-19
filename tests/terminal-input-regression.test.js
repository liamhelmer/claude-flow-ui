/**
 * Regression test for terminal input functionality
 * Text typed in terminal should appear and be processed
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testTerminalInput() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server for input test...');

    // Start the server
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11241',
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
      let errorOutput = '';
      const timeout = setTimeout(() => {
        console.log('Server output so far:', output);
        console.log('Server error output:', errorOutput);
        reject(new Error('Server timeout'));
      }, 30000);

      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        console.log('📊 Server:', text.trim());

        if (output.includes('Running on:') || output.includes('localhost:11241')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000); // Give server extra time to fully start
        }
      });

      serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        errorOutput += text;
        console.log('⚠️ Server stderr:', text.trim());

        // Still resolve if we see the server starting
        if (text.includes('Running on:') || text.includes('localhost:11241')) {
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

    // Track terminal events
    const terminalEvents = {
      inputs: [],
      outputs: [],
      websocketConnected: false,
      terminalReady: false
    };

    page.on('console', (msg) => {
      const text = msg.text();

      // Track input events
      if (text.includes('Input:') || text.includes('onData') || text.includes('sendData')) {
        terminalEvents.inputs.push({
          time: Date.now(),
          message: text
        });
        console.log(`⌨️ Input event detected: ${text.substring(0, 100)}`);
      }

      // Track output events
      if (text.includes('Received data') || text.includes('terminal-data') || text.includes('Writing')) {
        terminalEvents.outputs.push({
          time: Date.now(),
          message: text
        });
        console.log(`📤 Output event detected: ${text.substring(0, 100)}`);
      }

      // Track WebSocket connection
      if (text.includes('WebSocket connected') || text.includes('Connected successfully')) {
        terminalEvents.websocketConnected = true;
        console.log('🔌 WebSocket connected');
      }

      // Track terminal readiness
      if (text.includes('Terminal marked as ready') || text.includes('Terminal initialized and ready')) {
        terminalEvents.terminalReady = true;
        console.log('✅ Terminal ready');
      }
    });

    console.log('📱 Navigating to production server...');
    const response = await page.goto('http://localhost:11241', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response.status()}`);

    // Wait for terminal to be fully initialized
    console.log('⏳ Waiting 20 seconds for terminal initialization...');
    await page.waitForTimeout(20000);

    // Check terminal state
    const terminalState = await page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      const terminalText = terminals.length > 0 ? terminals[0].textContent || '' : '';
      const hasCanvas = document.querySelectorAll('canvas').length > 0;
      const hasCursor = document.querySelectorAll('.xterm-cursor').length > 0;
      const textareas = document.querySelectorAll('textarea');

      return {
        terminalCount: terminals.length,
        hasVisibleTerminal: terminals.length > 0,
        terminalText: terminalText.substring(0, 500), // First 500 chars
        hasCanvas,
        hasCursor,
        textareaCount: textareas.length,
        hasTextarea: textareas.length > 0
      };
    });

    console.log('📊 Initial terminal state:', terminalState);

    // Type test input
    const testInput = 'echo "Hello Terminal Test"';
    console.log(`\n⌨️ Typing test input: "${testInput}"`);

    // Focus terminal and type
    await page.click('.xterm-wrapper, .terminal-container, .xterm', {
      force: true,
      timeout: 5000
    }).catch(() => {
      console.log('⚠️ Could not click terminal directly, trying keyboard focus...');
    });

    // Type the test command
    for (const char of testInput) {
      await page.keyboard.type(char);
      await page.waitForTimeout(50); // Small delay between characters
    }

    // Press Enter
    await page.keyboard.press('Enter');
    console.log('↩️ Pressed Enter');

    // Wait for output to appear
    console.log('⏳ Waiting 5 seconds for output...');
    await page.waitForTimeout(5000);

    // Check if input appeared in terminal
    const finalState = await page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      const terminalElement = terminals.length > 0 ? terminals[0] : null;

      // Try multiple ways to get terminal content
      let content = '';
      let bufferContent = '';

      // Method 1: Direct text content
      if (terminalElement) {
        content = terminalElement.textContent || '';
      }

      // Try to access terminal instance through window or element
      try {
        // Check if terminal instance is exposed
        const terminalInstances = window.terminals || window.terminalInstances || [];
        if (terminalInstances.length > 0 && terminalInstances[0]) {
          // Try to get buffer content using xterm API
          const term = terminalInstances[0];
          if (term.buffer && term.buffer.active) {
            for (let i = 0; i < term.buffer.active.length; i++) {
              const line = term.buffer.active.getLine(i);
              if (line) {
                bufferContent += line.translateToString(true) + '\n';
              }
            }
          }
        }
      } catch (e) {
        console.log('Could not access terminal buffer:', e.message);
      }

      // Method 2: Check all terminal rows
      const rows = document.querySelectorAll('.xterm-rows > div');
      const rowTexts = Array.from(rows).map(row => row.textContent || '').join('\n');

      // Method 3: Check screen text
      const screenText = document.querySelector('.xterm-screen')?.textContent || '';

      // Method 4: Check canvas accessibility text (if canvas is used)
      const canvas = document.querySelector('.xterm canvas');
      const canvasText = canvas ? (canvas.getAttribute('aria-label') || '') : '';

      return {
        terminalCount: terminals.length,
        hasVisibleTerminal: terminals.length > 0,
        directContent: content.substring(0, 1000),
        rowContent: rowTexts.substring(0, 1000),
        screenContent: screenText.substring(0, 1000),
        bufferContent: bufferContent.substring(0, 1000),
        canvasText: canvasText.substring(0, 1000),
        containsEcho: content.includes('echo') || rowTexts.includes('echo') || screenText.includes('echo') || bufferContent.includes('echo') || canvasText.includes('echo'),
        containsHello: content.includes('Hello') || rowTexts.includes('Hello') || screenText.includes('Hello') || bufferContent.includes('Hello') || canvasText.includes('Hello'),
        containsTestInput: content.includes('echo "Hello Terminal Test"') ||
                          rowTexts.includes('echo "Hello Terminal Test"') ||
                          screenText.includes('echo "Hello Terminal Test"') ||
                          bufferContent.includes('echo "Hello Terminal Test"') ||
                          canvasText.includes('echo "Hello Terminal Test"')
      };
    });

    // Analyze results
    console.log('\n📊 TERMINAL INPUT REGRESSION TEST RESULTS:');
    console.log('='.repeat(60));
    console.log(`Terminal Ready: ${terminalEvents.terminalReady}`);
    console.log(`WebSocket Connected: ${terminalEvents.websocketConnected}`);
    console.log(`Input Events Captured: ${terminalEvents.inputs.length}`);
    console.log(`Output Events Captured: ${terminalEvents.outputs.length}`);
    console.log(`Terminal Visible: ${finalState.hasVisibleTerminal}`);
    console.log(`Contains 'echo': ${finalState.containsEcho}`);
    console.log(`Contains 'Hello': ${finalState.containsHello}`);
    console.log(`Contains Full Test Input: ${finalState.containsTestInput}`);

    // Debug output
    if (!finalState.containsTestInput) {
      console.log('\n🔍 Terminal Content Debug:');
      console.log('Direct content:', finalState.directContent.substring(0, 200));
      console.log('Row content:', finalState.rowContent.substring(0, 200));
      console.log('Screen content:', finalState.screenContent.substring(0, 200));
      console.log('Buffer content:', finalState.bufferContent.substring(0, 200));
      console.log('Canvas text:', finalState.canvasText.substring(0, 200));
    }

    // Determine success
    const inputWorking = finalState.containsTestInput || finalState.containsEcho;
    const success = terminalEvents.terminalReady &&
                   terminalEvents.websocketConnected &&
                   finalState.hasVisibleTerminal &&
                   inputWorking;

    if (success) {
      console.log('\n✅ SUCCESS: Terminal input is working');
      console.log('   - Terminal initialized properly');
      console.log('   - WebSocket connected');
      console.log('   - Input text appears in terminal');
      console.log('   - Terminal is interactive');
    } else {
      console.log('\n❌ FAILURE: Terminal input not working');
      if (!terminalEvents.terminalReady) console.log('   - Terminal not ready');
      if (!terminalEvents.websocketConnected) console.log('   - WebSocket not connected');
      if (!finalState.hasVisibleTerminal) console.log('   - Terminal not visible');
      if (!inputWorking) console.log('   - Input text does not appear in terminal');
    }

    // Log sample events for debugging
    if (terminalEvents.inputs.length > 0) {
      console.log('\nInput events (first 3):');
      terminalEvents.inputs.slice(0, 3).forEach((e, i) => {
        console.log(`   ${i + 1}. ${e.message.substring(0, 80)}`);
      });
    }

    if (terminalEvents.outputs.length > 0) {
      console.log('\nOutput events (first 3):');
      terminalEvents.outputs.slice(0, 3).forEach((e, i) => {
        console.log(`   ${i + 1}. ${e.message.substring(0, 80)}`);
      });
    }

    return {
      success,
      stats: {
        terminalReady: terminalEvents.terminalReady,
        websocketConnected: terminalEvents.websocketConnected,
        inputEvents: terminalEvents.inputs.length,
        outputEvents: terminalEvents.outputs.length,
        inputVisible: inputWorking,
        terminalVisible: finalState.hasVisibleTerminal
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

// Run the test
testTerminalInput().then(result => {
  console.log('\n🎯 REGRESSION TEST FINAL RESULT:');
  console.log(JSON.stringify(result, null, 2));

  if (!result.success) {
    console.log('\n⚠️ TERMINAL INPUT NOT WORKING - FIX NEEDED!');
  }

  process.exit(result.success ? 0 : 1);
});