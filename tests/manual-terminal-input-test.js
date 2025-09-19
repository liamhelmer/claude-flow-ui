#!/usr/bin/env node

/**
 * Manual Terminal Input Test
 *
 * This script tests the terminal input functionality by:
 * 1. Starting the application server
 * 2. Opening a browser to test terminal interactions
 * 3. Verifying that keyboard input reaches the terminal and produces output
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testTerminalInput() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting test server...');

    // Start the Next.js development server
    serverProcess = spawn('npm', ['run', 'dev'], {
      env: { ...process.env, NODE_ENV: 'development' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => {
        reject(new Error('Server timeout - could not start development server'));
      }, 60000);

      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        console.log('📊 Server:', text.trim());

        if (text.includes('Ready in') || text.includes('localhost:3000')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000); // Give server extra time
        }
      });

      serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        console.log('⚠️ Server stderr:', text.trim());

        if (text.includes('Ready in') || text.includes('localhost:3000')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    console.log('🌐 Starting browser for manual testing...');
    browser = await chromium.launch({
      headless: false,
      devtools: true // Open devtools for debugging
    });

    const page = await browser.newPage();

    // Enable console logging
    page.on('console', (msg) => {
      const text = msg.text();
      if (text.includes('Terminal') || text.includes('WebSocket') || text.includes('sendData') || text.includes('Input')) {
        console.log(`🖥️ Browser: ${text.substring(0, 150)}`);
      }
    });

    console.log('📱 Navigating to development server...');
    await page.goto('http://localhost:3000', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log('⏳ Waiting for terminal to initialize...');
    await page.waitForTimeout(10000);

    // Check if terminal is visible
    const terminalExists = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm, .terminal-container, .xterm-wrapper');
      return {
        hasTerminal: !!terminal,
        terminalVisible: terminal ? terminal.offsetHeight > 0 : false,
        terminalClasses: terminal ? terminal.className : 'none'
      };
    });

    console.log('📊 Terminal state:', terminalExists);

    if (!terminalExists.hasTerminal) {
      console.log('❌ No terminal found! Check the page layout.');
      return false;
    }

    console.log('\n🎯 Manual Testing Instructions:');
    console.log('='.repeat(50));
    console.log('1. Click on the terminal to focus it');
    console.log('2. Type some text (e.g., "echo hello world")');
    console.log('3. Press Enter');
    console.log('4. Check if the text appears in the terminal');
    console.log('5. Try typing more commands');
    console.log('\n📋 What to look for:');
    console.log('✅ Text appears as you type');
    console.log('✅ Commands execute when you press Enter');
    console.log('✅ Output appears in the terminal');
    console.log('✅ WebSocket messages in browser console');
    console.log('❌ No text appears (input not working)');
    console.log('❌ Text appears but no output (connection issue)');
    console.log('\n🔍 Browser DevTools Console is open for debugging');
    console.log('📝 Press Ctrl+C in this terminal when done testing');

    // Keep the test running until user stops it
    return new Promise((resolve) => {
      process.on('SIGINT', () => {
        console.log('\n🛑 Test stopped by user');
        resolve(true);
      });
    });

  } catch (error) {
    console.error('💥 Test setup failed:', error.message);
    return false;
  } finally {
    if (browser) {
      console.log('🧹 Closing browser...');
      await browser.close();
    }
    if (serverProcess) {
      console.log('🛑 Stopping server...');
      serverProcess.kill('SIGTERM');
    }
  }
}

// Run the test
console.log('🧪 Starting Manual Terminal Input Test');
console.log('This will open a browser for manual testing');

testTerminalInput().then(result => {
  console.log('\n🎯 Manual Test Complete');
  if (result) {
    console.log('ℹ️ Please verify that terminal input worked correctly');
  }
  process.exit(0);
}).catch(error => {
  console.error('💥 Test failed:', error);
  process.exit(1);
});