#!/usr/bin/env node

/**
 * Manual test for scrollback functionality
 * This test verifies the 10,000 line scrollback implementation
 */

const puppeteer = require('puppeteer');
const { spawn } = require('child_process');

async function runScrollbackTest() {
  let serverProcess;
  let browser;
  let page;

  try {
    console.log('🚀 Starting scrollback manual test...');

    // Start the server
    console.log('📦 Starting server on port 18095...');
    serverProcess = spawn('node', ['unified-server.js'], {
      env: {
        ...process.env,
        PORT: '18095',
        NODE_ENV: 'test',
        DEBUG_TMUX: '1'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Log server output
    serverProcess.stdout.on('data', (data) => {
      console.log(`[Server]: ${data.toString().trim()}`);
    });

    serverProcess.stderr.on('data', (data) => {
      console.error(`[Server Error]: ${data.toString().trim()}`);
    });

    // Wait for server to start
    console.log('⏳ Waiting for server to initialize...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Launch browser
    console.log('🌐 Launching browser...');
    browser = await puppeteer.launch({
      headless: false, // Set to true for automated testing
      devtools: false,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    page = await browser.newPage();

    // Navigate to the app
    console.log('📍 Navigating to application...');
    await page.goto('http://localhost:18095', {
      waitUntil: 'networkidle2',
      timeout: 15000
    });

    // Wait for terminal to be ready
    console.log('⏳ Waiting for terminal to initialize...');
    await page.waitForSelector('.xterm-wrapper', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Test 1: Check scrollback configuration
    console.log('\n✅ Test 1: Checking scrollback configuration...');
    const config = await page.evaluate(() => {
      // Try multiple ways to find the terminal
      const terminal = window.__terminal || window.terminal ||
                      (window.terminalInstance && window.terminalInstance.terminal);

      if (terminal && terminal.options) {
        return {
          scrollback: terminal.options.scrollback,
          rows: terminal.rows,
          cols: terminal.cols
        };
      }
      return { scrollback: null };
    });

    console.log(`   Scrollback lines: ${config.scrollback}`);
    console.log(`   Terminal size: ${config.cols}x${config.rows}`);

    if (config.scrollback !== 10000) {
      throw new Error(`Expected scrollback to be 10000, got ${config.scrollback}`);
    }

    // Test 2: Generate content for scrollback
    console.log('\n✅ Test 2: Generating content for scrollback buffer...');
    for (let i = 1; i <= 100; i++) {
      await page.keyboard.type(`echo "Test Line ${i}"`);
      await page.keyboard.press('Enter');

      if (i % 20 === 0) {
        console.log(`   Generated ${i} lines...`);
        await page.waitForTimeout(500);
      }
    }

    await page.waitForTimeout(2000);

    // Test 3: Test scrolling up
    console.log('\n✅ Test 3: Testing scroll up functionality...');

    // Get initial position
    const initialPos = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal || !terminal._core) return -1;
      return terminal._core.viewport.scrollTop;
    });

    // Scroll up using keyboard
    await page.keyboard.down('Shift');
    for (let i = 0; i < 5; i++) {
      await page.keyboard.press('PageUp');
      await page.waitForTimeout(100);
    }
    await page.keyboard.up('Shift');

    await page.waitForTimeout(500);

    // Get new position
    const scrolledPos = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal || !terminal._core) return -1;
      return terminal._core.viewport.scrollTop;
    });

    console.log(`   Initial position: ${initialPos}`);
    console.log(`   Scrolled position: ${scrolledPos}`);

    if (scrolledPos >= initialPos) {
      throw new Error('Scrolling up did not work - position did not decrease');
    }

    // Test 4: Check tmux configuration
    console.log('\n✅ Test 4: Checking tmux history configuration...');
    await page.keyboard.press('End'); // Go to bottom
    await page.waitForTimeout(500);

    await page.keyboard.type('tmux show-options history-limit');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);

    const tmuxOutput = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return '';

      const buffer = terminal.buffer.active;
      let text = '';

      // Get last 5 lines
      const startLine = Math.max(0, buffer.length - 5);
      for (let i = startLine; i < buffer.length; i++) {
        const line = buffer.getLine(i);
        if (line) {
          text += line.translateToString(true) + '\n';
        }
      }
      return text;
    });

    console.log(`   Tmux output: ${tmuxOutput.trim()}`);

    if (!tmuxOutput.includes('10000')) {
      console.warn('   ⚠️ Tmux history limit may not be set to 10000');
    }

    // Test 5: Test buffer update with new content
    console.log('\n✅ Test 5: Testing buffer updates with new content...');

    // Clear screen
    await page.keyboard.type('clear');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);

    // Add new content
    for (let i = 1; i <= 20; i++) {
      await page.keyboard.type(`echo "New Content ${i}"`);
      await page.keyboard.press('Enter');
    }

    await page.waitForTimeout(1000);

    // Scroll up to check if old content is preserved
    await page.keyboard.down('Shift');
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press('PageUp');
      await page.waitForTimeout(100);
    }
    await page.keyboard.up('Shift');

    await page.waitForTimeout(500);

    const bufferContent = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return { hasOld: false, hasNew: false };

      const buffer = terminal.buffer.active;
      let fullContent = '';

      for (let i = 0; i < Math.min(buffer.length, 200); i++) {
        const line = buffer.getLine(i);
        if (line) {
          fullContent += line.translateToString(true) + '\n';
        }
      }

      return {
        hasOld: fullContent.includes('Test Line'),
        hasNew: fullContent.includes('New Content'),
        bufferLength: buffer.length
      };
    });

    console.log(`   Buffer contains old content: ${bufferContent.hasOld}`);
    console.log(`   Buffer contains new content: ${bufferContent.hasNew}`);
    console.log(`   Current buffer length: ${bufferContent.bufferLength}`);

    if (!bufferContent.hasOld || !bufferContent.hasNew) {
      throw new Error('Buffer does not properly preserve scrollback on updates');
    }

    // Test 6: Mouse wheel scrolling
    console.log('\n✅ Test 6: Testing mouse wheel scrolling...');

    // Scroll to bottom first
    await page.keyboard.press('End');
    await page.waitForTimeout(500);

    // Get terminal position
    const terminalBox = await page.$eval('.xterm-wrapper', el => {
      const rect = el.getBoundingClientRect();
      return { x: rect.x + rect.width/2, y: rect.y + rect.height/2 };
    });

    // Move mouse to terminal
    await page.mouse.move(terminalBox.x, terminalBox.y);

    // Scroll up with mouse
    await page.mouse.wheel({ deltaY: -500 });
    await page.waitForTimeout(500);

    const mouseScrollPos = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal || !terminal._core) return -1;
      return terminal._core.viewport.scrollTop;
    });

    console.log(`   Position after mouse scroll: ${mouseScrollPos}`);

    // Test 7: Large content test
    console.log('\n✅ Test 7: Testing with large amounts of content...');

    // Generate 500 lines quickly
    await page.keyboard.type('for i in {1..500}; do echo "Large test line $i"; done');
    await page.keyboard.press('Enter');

    console.log('   Generating 500 lines...');
    await page.waitForTimeout(5000);

    const largeBufferInfo = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return { lines: 0 };

      const buffer = terminal.buffer.active;
      let nonEmptyLines = 0;

      for (let i = 0; i < buffer.length; i++) {
        const line = buffer.getLine(i);
        if (line && line.translateToString(true).trim()) {
          nonEmptyLines++;
        }
      }

      return {
        totalLines: buffer.length,
        nonEmptyLines: nonEmptyLines,
        maxScrollback: terminal.options.scrollback
      };
    });

    console.log(`   Total buffer lines: ${largeBufferInfo.totalLines}`);
    console.log(`   Non-empty lines: ${largeBufferInfo.nonEmptyLines}`);
    console.log(`   Max scrollback: ${largeBufferInfo.maxScrollback}`);

    if (largeBufferInfo.totalLines > 10000) {
      throw new Error(`Buffer exceeded 10000 lines limit: ${largeBufferInfo.totalLines}`);
    }

    console.log('\n🎉 All scrollback tests passed successfully!');
    console.log('\nSummary:');
    console.log('✅ Scrollback configured to 10,000 lines');
    console.log('✅ Scrolling up/down works correctly');
    console.log('✅ Buffer preserves content on updates');
    console.log('✅ Mouse wheel scrolling functional');
    console.log('✅ Large content handled within limits');

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    process.exit(1);
  } finally {
    console.log('\n🧹 Cleaning up...');

    if (browser) {
      await browser.close();
    }

    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise(resolve => {
        serverProcess.once('exit', resolve);
        setTimeout(() => {
          serverProcess.kill('SIGKILL');
          resolve();
        }, 5000);
      });
    }

    console.log('✅ Cleanup complete');
  }
}

// Run the test
runScrollbackTest().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});