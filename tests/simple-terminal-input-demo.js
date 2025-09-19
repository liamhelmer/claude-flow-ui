#!/usr/bin/env node
/**
 * Simple Terminal Input Demonstration Test
 *
 * This script demonstrates the terminal input issue by:
 * 1. Starting the app in production mode
 * 2. Opening a browser to test input
 * 3. Showing detailed debugging info
 *
 * Usage: node tests/simple-terminal-input-demo.js
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

class TerminalInputDemo {
  constructor() {
    this.serverProcess = null;
    this.browser = null;
    this.events = [];
    this.port = 11243;
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = {
      'info': '📋',
      'success': '✅',
      'error': '❌',
      'warning': '⚠️',
      'debug': '🔍'
    }[type] || 'ℹ️';

    console.log(`${prefix} [${timestamp}] ${message}`);
  }

  async startServer() {
    this.log('Starting server for terminal input demonstration...', 'info');

    this.serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', this.port.toString(),
      '--terminal-size', '100x30',
      'echo', '"Terminal Input Test"'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    return new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => {
        reject(new Error(`Server failed to start within 30 seconds`));
      }, 30000);

      this.serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        this.log(`Server stdout: ${text.trim()}`, 'debug');

        if (output.includes('Running on:') || output.includes(`localhost:${this.port}`)) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });

      this.serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        this.log(`Server stderr: ${text.trim()}`, 'warning');

        if (text.includes('Running on:') || text.includes(`localhost:${this.port}`)) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });

      this.serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  async runTest() {
    try {
      await this.startServer();
      this.log('Server started successfully', 'success');

      this.log('Launching browser...', 'info');
      this.browser = await chromium.launch({
        headless: false,  // Keep visible for demonstration
        slowMo: 100       // Slow down for visibility
      });

      const page = await this.browser.newPage();

      // Monitor console for debugging
      page.on('console', (msg) => {
        const text = msg.text();
        this.events.push({ time: Date.now(), type: 'console', text });

        if (text.includes('Input') || text.includes('onData') || text.includes('sendData')) {
          this.log(`INPUT EVENT: ${text}`, 'debug');
        }

        if (text.includes('WebSocket') || text.includes('Connected')) {
          this.log(`WEBSOCKET: ${text}`, 'debug');
        }
      });

      this.log(`Navigating to http://localhost:${this.port}`, 'info');
      await page.goto(`http://localhost:${this.port}`, { waitUntil: 'networkidle' });

      this.log('Waiting for terminal to load...', 'info');
      await page.waitForSelector('.xterm, .terminal-container', { timeout: 15000 });
      await page.waitForTimeout(5000); // Extra time for initialization

      this.log('Getting terminal state...', 'info');
      const terminalState = await page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        const containers = document.querySelectorAll('.terminal-container');
        const canvas = document.querySelectorAll('canvas');
        const textareas = document.querySelectorAll('textarea');

        return {
          terminalCount: terminals.length,
          containerCount: containers.length,
          canvasCount: canvas.length,
          textareaCount: textareas.length,
          activeElement: document.activeElement?.tagName,
          terminalVisible: terminals.length > 0,
          terminalContent: terminals.length > 0 ? terminals[0].textContent?.substring(0, 200) : 'No terminal found'
        };
      });

      this.log(`Terminal state: ${JSON.stringify(terminalState, null, 2)}`, 'info');

      if (!terminalState.terminalVisible) {
        this.log('No terminal found on page!', 'error');
        return false;
      }

      this.log('Attempting to focus terminal...', 'info');
      // Try multiple focus methods
      const focusSelectors = ['.xterm-helper-textarea', '.xterm-screen', '.xterm', '.terminal-container'];

      for (const selector of focusSelectors) {
        try {
          await page.click(selector, { timeout: 2000 });
          this.log(`Successfully clicked ${selector}`, 'success');
          break;
        } catch (e) {
          this.log(`Failed to click ${selector}: ${e.message}`, 'warning');
        }
      }

      await page.waitForTimeout(1000);

      // Test 1: Simple typing
      this.log('TEST 1: Typing simple text...', 'info');
      const testText = 'hello world';

      await page.keyboard.type(testText, { delay: 100 });
      await page.waitForTimeout(2000);

      const simpleCheck = await this.checkInputVisibility(page, testText);
      this.log(`Simple typing result: ${simpleCheck.visible ? 'SUCCESS' : 'FAILED'}`, simpleCheck.visible ? 'success' : 'error');

      if (!simpleCheck.visible) {
        this.log(`Expected "${testText}" but found: ${simpleCheck.preview}`, 'debug');
      }

      // Test 2: Press Enter and check command execution
      this.log('TEST 2: Pressing Enter...', 'info');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(3000);

      const afterEnterState = await page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        return {
          content: terminal ? terminal.textContent?.substring(0, 500) : 'No content',
          hasHello: terminal ? terminal.textContent?.includes('hello') : false
        };
      });

      this.log(`After Enter - Content includes 'hello': ${afterEnterState.hasHello}`, afterEnterState.hasHello ? 'success' : 'error');

      // Test 3: Clear and try different input
      this.log('TEST 3: Clearing and trying command...', 'info');
      await page.keyboard.press('Control+C'); // Clear
      await page.waitForTimeout(1000);

      const command = 'echo "test123"';
      await page.keyboard.type(command, { delay: 100 });
      await page.waitForTimeout(2000);

      const commandCheck = await this.checkInputVisibility(page, command);
      this.log(`Command typing result: ${commandCheck.visible ? 'SUCCESS' : 'FAILED'}`, commandCheck.visible ? 'success' : 'error');

      // Summary
      this.log('\n' + '='.repeat(60), 'info');
      this.log('TERMINAL INPUT DEMONSTRATION RESULTS', 'info');
      this.log('='.repeat(60), 'info');
      this.log(`Simple text input visible: ${simpleCheck.visible}`, simpleCheck.visible ? 'success' : 'error');
      this.log(`Command input visible: ${commandCheck.visible}`, commandCheck.visible ? 'success' : 'error');
      this.log(`Total console events captured: ${this.events.length}`, 'info');

      const inputEvents = this.events.filter(e => e.text.toLowerCase().includes('input')).length;
      const outputEvents = this.events.filter(e => e.text.toLowerCase().includes('output') || e.text.toLowerCase().includes('data')).length;

      this.log(`Input events: ${inputEvents}`, 'debug');
      this.log(`Output events: ${outputEvents}`, 'debug');

      // Keep browser open for manual inspection
      this.log('\nBrowser will remain open for 30 seconds for manual inspection...', 'info');
      this.log('You can manually try typing in the terminal to test input visibility.', 'info');
      await page.waitForTimeout(30000);

      return simpleCheck.visible && commandCheck.visible;

    } catch (error) {
      this.log(`Test failed with error: ${error.message}`, 'error');
      return false;
    } finally {
      await this.cleanup();
    }
  }

  async checkInputVisibility(page, expectedText) {
    return await page.evaluate((expected) => {
      const terminals = document.querySelectorAll('.xterm');
      if (terminals.length === 0) {
        return { visible: false, preview: 'No terminals found' };
      }

      const terminal = terminals[0];
      const methods = {};

      // Try different methods to get content
      methods.textContent = terminal.textContent || '';

      const rows = terminal.querySelectorAll('.xterm-rows > div, .xterm-row');
      methods.rowContent = Array.from(rows).map(row => row.textContent || '').join(' ');

      const screen = terminal.querySelector('.xterm-screen');
      methods.screenContent = screen?.textContent || '';

      // Check all methods
      const allContent = Object.values(methods).join(' ').toLowerCase();
      const visible = allContent.includes(expected.toLowerCase());

      return {
        visible,
        preview: allContent.substring(0, 100),
        methods: Object.keys(methods).reduce((acc, key) => {
          acc[key] = methods[key].substring(0, 50);
          return acc;
        }, {})
      };
    }, expectedText);
  }

  async cleanup() {
    this.log('Cleaning up...', 'info');

    if (this.browser) {
      await this.browser.close();
    }

    if (this.serverProcess) {
      this.serverProcess.kill('SIGTERM');
    }
  }
}

// Run the demonstration
async function main() {
  const demo = new TerminalInputDemo();
  const success = await demo.runTest();

  console.log('\n' + '='.repeat(60));
  console.log(`FINAL RESULT: ${success ? 'INPUT WORKING' : 'INPUT ISSUE CONFIRMED'}`);
  console.log('='.repeat(60));

  process.exit(success ? 0 : 1);
}

if (require.main === module) {
  main().catch(error => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

module.exports = TerminalInputDemo;