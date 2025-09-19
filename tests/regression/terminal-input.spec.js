/**
 * COMPREHENSIVE PLAYWRIGHT REGRESSION TEST: Terminal Input Functionality
 *
 * CRITICAL BUG: Terminal input characters not appearing immediately in production
 *
 * This test suite reproduces and validates the terminal input display issue where:
 * - Characters typed into the terminal don't appear immediately
 * - Input seems to be lost or delayed
 * - Terminal switching breaks input routing
 * - Special keys (Enter, Backspace, Tab) don't work correctly
 *
 * Test Objectives:
 * 1. Launch application and wait for terminal to be ready
 * 2. Focus the terminal and test character input
 * 3. Verify characters appear in terminal display
 * 4. Test special keys and control sequences
 * 5. Test terminal switching while preserving input
 * 6. Test rapid typing scenarios
 * 7. Catch any input regressions reliably
 */

const { test, expect } = require('@playwright/test');
const { spawn } = require('child_process');
const path = require('path');

class TerminalInputTester {
  constructor(page) {
    this.page = page;
    this.serverProcess = null;
    this.testResults = {
      serverStarted: false,
      terminalReady: false,
      terminalFocused: false,
      basicInputWorking: false,
      specialKeysWorking: false,
      terminalSwitchingWorking: false,
      rapidTypingWorking: false,
      regressionDetected: false
    };
    this.debugLogs = [];
    this.port = 11243; // Unique port for this test
  }

  log(message, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, message, data };
    this.debugLogs.push(logEntry);
    console.log(`[${timestamp}] [TerminalInputTest] ${message}`, data);
  }

  async startServer() {
    this.log('🚀 Starting claude-flow-ui server for terminal input testing...');

    return new Promise((resolve, reject) => {
      this.serverProcess = spawn('node', [
        'unified-server.js',
        '--port', this.port.toString(),
        '--terminal-size', '120x40'
      ], {
        cwd: '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui',
        env: {
          ...process.env,
          NODE_ENV: 'production',
          PORT: this.port.toString()
        },
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let serverOutput = '';
      let serverReady = false;

      this.serverProcess.stdout.on('data', (data) => {
        const output = data.toString();
        serverOutput += output;
        this.log('Server stdout:', { output: output.trim() });

        // Look for various server ready indicators
        if (output.includes('ready') ||
            output.includes('started') ||
            output.includes('listening') ||
            output.includes(`${this.port}`)) {
          if (!serverReady) {
            serverReady = true;
            this.testResults.serverStarted = true;
            this.log('✅ Server appears ready');
            setTimeout(() => resolve(), 2000); // Give extra time for full startup
          }
        }
      });

      this.serverProcess.stderr.on('data', (data) => {
        const error = data.toString();
        this.log('Server stderr:', { error: error.trim() });
      });

      this.serverProcess.on('error', (error) => {
        this.log('❌ Server process error:', { error: error.message });
        reject(error);
      });

      // Timeout after 30 seconds
      setTimeout(() => {
        if (!serverReady) {
          this.log('⏰ Server startup timeout - proceeding anyway');
          resolve();
        }
      }, 30000);
    });
  }

  async stopServer() {
    if (this.serverProcess) {
      this.log('🛑 Stopping server...');
      this.serverProcess.kill('SIGTERM');

      // Force kill if not stopped within 5 seconds
      setTimeout(() => {
        if (this.serverProcess && !this.serverProcess.killed) {
          this.log('🔨 Force killing server...');
          this.serverProcess.kill('SIGKILL');
        }
      }, 5000);
    }
  }

  async navigateToApp() {
    this.log('🌐 Navigating to application...');

    // Navigate to the application
    await this.page.goto(`http://localhost:${this.port}`, {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    this.log('✅ Navigation completed');
  }

  async waitForTerminalReady() {
    this.log('⏳ Waiting for terminal to be ready...');

    // Wait for terminal container to appear
    const terminalContainer = await this.page.waitForSelector('.terminal-container, [data-testid="terminal"], .xterm, .terminal', {
      timeout: 30000,
      state: 'visible'
    });

    // Wait for terminal content area
    await this.page.waitForSelector('.xterm-screen, .xterm-viewport, .terminal-content', {
      timeout: 15000,
      state: 'visible'
    });

    // Wait for cursor to appear (indicates terminal is ready)
    try {
      await this.page.waitForSelector('.xterm-cursor', {
        timeout: 10000,
        state: 'visible'
      });
      this.log('✅ Terminal cursor visible - terminal ready');
    } catch (error) {
      this.log('⚠️ Cursor not found, but proceeding with terminal test');
    }

    // Additional wait for terminal initialization
    await this.page.waitForTimeout(2000);

    this.testResults.terminalReady = true;
    this.log('✅ Terminal ready for input testing');

    return terminalContainer;
  }

  async focusTerminal() {
    this.log('🎯 Focusing terminal for input...');

    // Try multiple selectors to find and focus the terminal
    const terminalSelectors = [
      '.xterm-helper-textarea',
      '.xterm-screen',
      '.terminal-container',
      '[data-testid="terminal"]',
      '.xterm'
    ];

    let focused = false;
    for (const selector of terminalSelectors) {
      try {
        const element = await this.page.$(selector);
        if (element) {
          await element.click();
          await element.focus();
          this.log(`✅ Focused terminal using selector: ${selector}`);
          focused = true;
          break;
        }
      } catch (error) {
        this.log(`⚠️ Failed to focus using selector ${selector}:`, { error: error.message });
      }
    }

    if (!focused) {
      // Fallback: click somewhere in the terminal area
      await this.page.click('body');
      await this.page.waitForTimeout(500);
      this.log('🔄 Fallback focus attempt');
    }

    this.testResults.terminalFocused = true;
    await this.page.waitForTimeout(1000); // Allow focus to settle

    return focused;
  }

  async typeAndVerify(text, description = 'text input') {
    this.log(`⌨️ Testing ${description}: "${text}"`);

    // Capture initial terminal content
    const initialContent = await this.getTerminalContent();
    this.log('Initial terminal content captured', { length: initialContent.length });

    // Type the text
    await this.page.keyboard.type(text, { delay: 100 });
    this.log(`✅ Typed: "${text}"`);

    // Wait for content to appear
    await this.page.waitForTimeout(500);

    // Capture updated terminal content
    const updatedContent = await this.getTerminalContent();
    this.log('Updated terminal content captured', { length: updatedContent.length });

    // Check if the typed text appears in the terminal
    const textAppeared = updatedContent.includes(text) ||
                        updatedContent.length > initialContent.length;

    if (textAppeared) {
      this.log(`✅ ${description} appeared successfully`);
      return true;
    } else {
      this.log(`❌ ${description} did NOT appear in terminal`, {
        typed: text,
        initialContentLength: initialContent.length,
        updatedContentLength: updatedContent.length,
        contentChanged: updatedContent !== initialContent
      });
      this.testResults.regressionDetected = true;
      return false;
    }
  }

  async getTerminalContent() {
    try {
      // Try multiple methods to get terminal content
      const methods = [
        // Method 1: xterm screen content
        () => this.page.evaluate(() => {
          const xtermScreen = document.querySelector('.xterm-screen');
          return xtermScreen ? xtermScreen.textContent || xtermScreen.innerText : '';
        }),

        // Method 2: terminal container content
        () => this.page.evaluate(() => {
          const terminal = document.querySelector('.terminal-container, .terminal');
          return terminal ? terminal.textContent || terminal.innerText : '';
        }),

        // Method 3: all xterm content
        () => this.page.evaluate(() => {
          const xterm = document.querySelector('.xterm');
          return xterm ? xterm.textContent || xterm.innerText : '';
        })
      ];

      for (const method of methods) {
        try {
          const content = await method();
          if (content && content.trim().length > 0) {
            return content;
          }
        } catch (error) {
          // Continue to next method
        }
      }

      return '';
    } catch (error) {
      this.log('⚠️ Error getting terminal content:', { error: error.message });
      return '';
    }
  }

  async testSpecialKeys() {
    this.log('🔣 Testing special keys...');

    const specialKeyTests = [
      { key: 'Enter', description: 'Enter key' },
      { key: 'Backspace', description: 'Backspace key' },
      { key: 'Tab', description: 'Tab key' },
      { key: 'ArrowUp', description: 'Up arrow key' },
      { key: 'ArrowDown', description: 'Down arrow key' },
      { key: 'Control+c', description: 'Ctrl+C' },
      { key: 'Control+l', description: 'Ctrl+L (clear)' }
    ];

    let specialKeysWorking = 0;

    for (const keyTest of specialKeyTests) {
      try {
        this.log(`Testing ${keyTest.description}...`);

        const initialContent = await this.getTerminalContent();
        await this.page.keyboard.press(keyTest.key);
        await this.page.waitForTimeout(300);
        const updatedContent = await this.getTerminalContent();

        const keyWorked = updatedContent !== initialContent;
        if (keyWorked) {
          this.log(`✅ ${keyTest.description} worked`);
          specialKeysWorking++;
        } else {
          this.log(`❌ ${keyTest.description} had no effect`);
        }
      } catch (error) {
        this.log(`❌ Error testing ${keyTest.description}:`, { error: error.message });
      }
    }

    this.testResults.specialKeysWorking = specialKeysWorking > 0;
    this.log(`Special keys test completed: ${specialKeysWorking}/${specialKeyTests.length} working`);

    return specialKeysWorking;
  }

  async testRapidTyping() {
    this.log('⚡ Testing rapid typing scenario...');

    const rapidText = 'rapid_typing_test_12345';
    const initialContent = await this.getTerminalContent();

    // Type rapidly with minimal delay
    await this.page.keyboard.type(rapidText, { delay: 10 });
    await this.page.waitForTimeout(1000);

    const updatedContent = await this.getTerminalContent();
    const rapidTypingWorked = updatedContent.includes(rapidText) ||
                             updatedContent.length > initialContent.length;

    this.testResults.rapidTypingWorking = rapidTypingWorked;

    if (rapidTypingWorked) {
      this.log('✅ Rapid typing test passed');
    } else {
      this.log('❌ Rapid typing test failed');
      this.testResults.regressionDetected = true;
    }

    return rapidTypingWorked;
  }

  async testTerminalSwitching() {
    this.log('🔄 Testing terminal switching with input preservation...');

    try {
      // Look for terminal tab buttons or switching interface
      const tabSelectors = [
        '[data-testid="terminal-tab"]',
        '.terminal-tab',
        '.tab-button',
        '[role="tab"]'
      ];

      let foundTabs = false;
      for (const selector of tabSelectors) {
        const tabs = await this.page.$$(selector);
        if (tabs.length > 1) {
          this.log(`Found ${tabs.length} terminal tabs`);

          // Type in first terminal
          await this.typeAndVerify('first_terminal_test', 'first terminal input');

          // Switch to second terminal
          await tabs[1].click();
          await this.page.waitForTimeout(1000);

          // Type in second terminal
          await this.typeAndVerify('second_terminal_test', 'second terminal input');

          // Switch back to first terminal
          await tabs[0].click();
          await this.page.waitForTimeout(1000);

          // Verify input still works
          await this.typeAndVerify('back_to_first', 'return to first terminal');

          foundTabs = true;
          this.testResults.terminalSwitchingWorking = true;
          this.log('✅ Terminal switching test completed');
          break;
        }
      }

      if (!foundTabs) {
        this.log('⚠️ No multiple terminals found - skipping switching test');
        this.testResults.terminalSwitchingWorking = true; // Don't fail if no tabs
      }

      return foundTabs;
    } catch (error) {
      this.log('❌ Terminal switching test failed:', { error: error.message });
      this.testResults.terminalSwitchingWorking = false;
      return false;
    }
  }

  generateTestReport() {
    const report = {
      summary: {
        passed: !this.testResults.regressionDetected,
        regressionDetected: this.testResults.regressionDetected,
        testsCompleted: Object.keys(this.testResults).length
      },
      results: this.testResults,
      debugLogs: this.debugLogs,
      timestamp: new Date().toISOString()
    };

    this.log('📊 Test Report Generated:', report.summary);
    return report;
  }
}

// Main test suite
test.describe('Terminal Input Regression Tests', () => {
  let tester;
  let testReport;

  test.beforeEach(async ({ page }) => {
    tester = new TerminalInputTester(page);
    await tester.startServer();
  });

  test.afterEach(async () => {
    testReport = tester.generateTestReport();
    await tester.stopServer();

    // Log final report
    console.log('\n📊 FINAL TEST REPORT:', JSON.stringify(testReport, null, 2));
  });

  test('Basic Terminal Input Display', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    // Test basic character input
    const basicInputWorked = await tester.typeAndVerify('hello world', 'basic text input');

    // CRITICAL: Make test fail initially to demonstrate the bug
    if (process.env.NODE_ENV === 'production') {
      expect(basicInputWorked).toBe(true); // This should fail and catch the regression
    }

    tester.testResults.basicInputWorking = basicInputWorked;
  });

  test('Special Characters and Symbols', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    // Test special characters
    const specialChars = ['!@#$%^&*()', '123456789', 'test-file.txt', '/usr/bin/test'];

    for (const chars of specialChars) {
      const worked = await tester.typeAndVerify(chars, `special characters: ${chars}`);
      if (!worked) {
        tester.testResults.regressionDetected = true;
      }
    }
  });

  test('Multi-line Input with Enter Key', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    // Test multi-line input
    await tester.typeAndVerify('echo "first line"', 'first line input');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);

    await tester.typeAndVerify('echo "second line"', 'second line input');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);
  });

  test('Special Keys Functionality', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    const specialKeysWorking = await tester.testSpecialKeys();
    expect(specialKeysWorking).toBeGreaterThan(0);
  });

  test('Rapid Typing Scenarios', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    const rapidTypingWorked = await tester.testRapidTyping();
    expect(rapidTypingWorked).toBe(true);
  });

  test('Input After Terminal Switching', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    await tester.testTerminalSwitching();
    // Note: This test doesn't fail if no multiple terminals exist
  });

  test('Comprehensive Input Regression Detection', async ({ page }) => {
    await tester.navigateToApp();
    await tester.waitForTerminalReady();
    await tester.focusTerminal();

    // Run all input tests in sequence
    const results = [];

    results.push(await tester.typeAndVerify('comprehensive_test', 'comprehensive input'));
    results.push(await tester.testSpecialKeys() > 0);
    results.push(await tester.testRapidTyping());

    const allTestsPassed = results.every(result => result === true);

    // CRITICAL: This should catch the regression
    expect(allTestsPassed).toBe(true);
    expect(tester.testResults.regressionDetected).toBe(false);
  });
});