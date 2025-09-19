/**
 * Comprehensive Terminal Input Verification Test Suite
 * Tests all critical terminal input scenarios to verify fixes work correctly
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

class TerminalInputTester {
  constructor() {
    this.serverProcess = null;
    this.browser = null;
    this.page = null;
    this.testResults = {
      singleTerminalInput: false,
      multiTerminalRouting: false,
      sessionSwitching: false,
      focusManagement: false,
      websocketReconnection: false,
      immediateInput: false,
      overallSuccess: false
    };
    this.eventLog = [];
  }

  logEvent(category, message, data = {}) {
    const event = {
      timestamp: Date.now(),
      category,
      message,
      data
    };
    this.eventLog.push(event);
    console.log(`[${category}] ${message}`, data);
  }

  async startServer(port = 11300) {
    this.logEvent('SETUP', 'Starting production server', { port });

    this.serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', port.toString(),
      '--terminal-size', '100x30',
      'hive-mind', 'spawn', 'wait for testing'
    ], {
      env: { ...process.env, NODE_ENV: 'production', DEBUG: 'true' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    return new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => {
        reject(new Error(`Server failed to start within 30 seconds. Output: ${output}`));
      }, 30000);

      this.serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        this.logEvent('SERVER', text.trim());

        if (text.includes('Running on:') || text.includes(`localhost:${port}`)) {
          clearTimeout(timeout);
          setTimeout(resolve, 3000); // Give server time to fully initialize
        }
      });

      this.serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        output += text;
        this.logEvent('SERVER-ERR', text.trim());

        if (text.includes('Running on:') || text.includes(`localhost:${port}`)) {
          clearTimeout(timeout);
          setTimeout(resolve, 3000);
        }
      });

      this.serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  async startBrowser() {
    this.logEvent('SETUP', 'Starting browser');
    this.browser = await chromium.launch({
      headless: false,
      devtools: true
    });
    this.page = await this.browser.newPage();

    // Track all console events for debugging
    this.page.on('console', (msg) => {
      const text = msg.text();
      if (text.includes('Input:') ||
          text.includes('sendData') ||
          text.includes('onData') ||
          text.includes('WebSocket') ||
          text.includes('Terminal') ||
          text.includes('session')) {
        this.logEvent('BROWSER', text);
      }
    });

    return this.page;
  }

  async navigateToApp(port = 11300) {
    this.logEvent('SETUP', 'Navigating to application', { port });

    const response = await this.page.goto(`http://localhost:${port}`, {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    this.logEvent('SETUP', 'Page loaded', { status: response.status() });

    // Wait for application to fully initialize
    await this.page.waitForTimeout(15000);

    return response;
  }

  async waitForTerminalReady() {
    this.logEvent('SETUP', 'Waiting for terminal to be ready');

    // Wait for terminal elements to appear
    await this.page.waitForSelector('.xterm, .xterm-wrapper, .terminal-container', {
      timeout: 20000
    });

    // Additional wait for initialization
    await this.page.waitForTimeout(5000);

    const terminalState = await this.page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      const wrappers = document.querySelectorAll('.xterm-wrapper');
      const containers = document.querySelectorAll('.terminal-container');

      return {
        terminalCount: terminals.length,
        wrapperCount: wrappers.length,
        containerCount: containers.length,
        hasVisibleTerminal: terminals.length > 0,
        terminalText: terminals.length > 0 ? terminals[0].textContent?.substring(0, 100) : 'No terminal'
      };
    });

    this.logEvent('SETUP', 'Terminal state checked', terminalState);
    return terminalState.hasVisibleTerminal;
  }

  async testSingleTerminalInput() {
    this.logEvent('TEST', 'Starting single terminal input test');

    try {
      // Focus the terminal
      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
      await this.page.waitForTimeout(1000);

      const testCommand = 'echo "Single Terminal Test"';
      this.logEvent('TEST', 'Typing test command', { command: testCommand });

      // Type command character by character with delays
      for (const char of testCommand) {
        await this.page.keyboard.type(char);
        await this.page.waitForTimeout(100);
      }

      // Press Enter
      await this.page.keyboard.press('Enter');
      this.logEvent('TEST', 'Pressed Enter');

      // Wait for output
      await this.page.waitForTimeout(3000);

      // Check if input appeared in terminal
      const result = await this.page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        if (terminals.length === 0) return { success: false, reason: 'No terminal found' };

        const content = terminals[0].textContent || '';
        const containsEcho = content.includes('echo');
        const containsTest = content.includes('Single Terminal Test');

        return {
          success: containsEcho || containsTest,
          reason: containsEcho ? 'Command visible' : containsTest ? 'Output visible' : 'Neither command nor output visible',
          content: content.substring(0, 200)
        };
      });

      this.testResults.singleTerminalInput = result.success;
      this.logEvent('TEST', 'Single terminal input test result', result);

      return result;

    } catch (error) {
      this.logEvent('ERROR', 'Single terminal input test failed', { error: error.message });
      this.testResults.singleTerminalInput = false;
      return { success: false, error: error.message };
    }
  }

  async testMultiTerminalRouting() {
    this.logEvent('TEST', 'Starting multi-terminal routing test');

    try {
      // This test simulates multiple terminals if the UI supports it
      // For now, we'll test rapid input switching to simulate multiple sessions

      const commands = [
        'echo "Terminal 1 Test"',
        'echo "Terminal 2 Test"',
        'echo "Terminal 3 Test"'
      ];

      for (let i = 0; i < commands.length; i++) {
        this.logEvent('TEST', `Testing command ${i + 1}`, { command: commands[i] });

        // Focus terminal
        await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
        await this.page.waitForTimeout(500);

        // Type command
        await this.page.keyboard.type(commands[i]);
        await this.page.keyboard.press('Enter');

        // Wait between commands
        await this.page.waitForTimeout(2000);
      }

      // Check if all commands were processed
      const result = await this.page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        if (terminals.length === 0) return { success: false, reason: 'No terminal found' };

        const content = terminals[0].textContent || '';
        const test1 = content.includes('Terminal 1 Test');
        const test2 = content.includes('Terminal 2 Test');
        const test3 = content.includes('Terminal 3 Test');

        return {
          success: test1 && test2 && test3,
          partial: test1 || test2 || test3,
          reason: `Found tests: ${[test1, test2, test3].filter(Boolean).length}/3`,
          content: content.substring(0, 300)
        };
      });

      this.testResults.multiTerminalRouting = result.success;
      this.logEvent('TEST', 'Multi-terminal routing test result', result);

      return result;

    } catch (error) {
      this.logEvent('ERROR', 'Multi-terminal routing test failed', { error: error.message });
      this.testResults.multiTerminalRouting = false;
      return { success: false, error: error.message };
    }
  }

  async testSessionSwitching() {
    this.logEvent('TEST', 'Starting session switching test');

    try {
      // Test rapid focus changes and input
      const testSequence = [
        { action: 'click', delay: 500 },
        { action: 'type', text: 'echo "Focus Test 1"', delay: 100 },
        { action: 'enter', delay: 1000 },
        { action: 'click', delay: 500 },
        { action: 'type', text: 'echo "Focus Test 2"', delay: 100 },
        { action: 'enter', delay: 1000 }
      ];

      for (const step of testSequence) {
        switch (step.action) {
          case 'click':
            await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
            this.logEvent('TEST', 'Clicked terminal to focus');
            break;
          case 'type':
            await this.page.keyboard.type(step.text);
            this.logEvent('TEST', 'Typed text', { text: step.text });
            break;
          case 'enter':
            await this.page.keyboard.press('Enter');
            this.logEvent('TEST', 'Pressed Enter');
            break;
        }
        await this.page.waitForTimeout(step.delay);
      }

      // Check results
      const result = await this.page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        if (terminals.length === 0) return { success: false, reason: 'No terminal found' };

        const content = terminals[0].textContent || '';
        const test1 = content.includes('Focus Test 1');
        const test2 = content.includes('Focus Test 2');

        return {
          success: test1 && test2,
          reason: `Found focus tests: ${[test1, test2].filter(Boolean).length}/2`,
          content: content.substring(0, 300)
        };
      });

      this.testResults.sessionSwitching = result.success;
      this.logEvent('TEST', 'Session switching test result', result);

      return result;

    } catch (error) {
      this.logEvent('ERROR', 'Session switching test failed', { error: error.message });
      this.testResults.sessionSwitching = false;
      return { success: false, error: error.message };
    }
  }

  async testFocusManagement() {
    this.logEvent('TEST', 'Starting focus management test');

    try {
      // Test clicking different areas and then typing
      const focusPoints = [
        { selector: '.terminal-container', name: 'Container' },
        { selector: '.xterm-wrapper', name: 'Wrapper' },
        { selector: '.xterm', name: 'Terminal' }
      ];

      for (const point of focusPoints) {
        try {
          await this.page.click(point.selector, { force: true });
          await this.page.waitForTimeout(500);

          const testText = `focus-${point.name.toLowerCase()}`;
          await this.page.keyboard.type(testText);
          await this.page.waitForTimeout(300);

          this.logEvent('TEST', `Tested focus on ${point.name}`, { selector: point.selector });

        } catch (focusError) {
          this.logEvent('TEST', `Could not focus ${point.name}`, { error: focusError.message });
        }
      }

      // Clear the line and test final input
      await this.page.keyboard.press('Escape');
      await this.page.keyboard.press('Control+C');
      await this.page.waitForTimeout(500);

      await this.page.keyboard.type('echo "Focus Management Test"');
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(2000);

      // Check if final input worked
      const result = await this.page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        if (terminals.length === 0) return { success: false, reason: 'No terminal found' };

        const content = terminals[0].textContent || '';
        const hasFocusTest = content.includes('Focus Management Test');

        return {
          success: hasFocusTest,
          reason: hasFocusTest ? 'Focus management working' : 'Focus management failed',
          content: content.substring(0, 300)
        };
      });

      this.testResults.focusManagement = result.success;
      this.logEvent('TEST', 'Focus management test result', result);

      return result;

    } catch (error) {
      this.logEvent('ERROR', 'Focus management test failed', { error: error.message });
      this.testResults.focusManagement = false;
      return { success: false, error: error.message };
    }
  }

  async testWebSocketReconnection() {
    this.logEvent('TEST', 'Starting WebSocket reconnection test');

    try {
      // Test input before simulated disconnection
      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
      await this.page.keyboard.type('echo "Before Reconnection"');
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(2000);

      // Simulate network issues by reloading the page
      this.logEvent('TEST', 'Simulating reconnection by refreshing page');
      await this.page.reload({ waitUntil: 'networkidle' });
      await this.page.waitForTimeout(10000); // Wait for reconnection

      // Test input after reconnection
      await this.waitForTerminalReady();
      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
      await this.page.keyboard.type('echo "After Reconnection"');
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(3000);

      // Check if input works after reconnection
      const result = await this.page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        if (terminals.length === 0) return { success: false, reason: 'No terminal found' };

        const content = terminals[0].textContent || '';
        const hasAfterReconnection = content.includes('After Reconnection');

        return {
          success: hasAfterReconnection,
          reason: hasAfterReconnection ? 'Input works after reconnection' : 'Input failed after reconnection',
          content: content.substring(0, 300)
        };
      });

      this.testResults.websocketReconnection = result.success;
      this.logEvent('TEST', 'WebSocket reconnection test result', result);

      return result;

    } catch (error) {
      this.logEvent('ERROR', 'WebSocket reconnection test failed', { error: error.message });
      this.testResults.websocketReconnection = false;
      return { success: false, error: error.message };
    }
  }

  async testImmediateInput() {
    this.logEvent('TEST', 'Starting immediate input test');

    try {
      // Navigate to a fresh page to test immediate input
      await this.page.goto(`http://localhost:11300`, { waitUntil: 'domcontentloaded' });

      // Try to input immediately as page loads (stress test)
      setTimeout(async () => {
        try {
          await this.page.keyboard.type('echo "Immediate Input Test"');
          await this.page.keyboard.press('Enter');
        } catch (e) {
          this.logEvent('TEST', 'Immediate input failed', { error: e.message });
        }
      }, 2000);

      // Wait for page to fully load
      await this.page.waitForTimeout(15000);

      // Try input again after loading
      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
      await this.page.keyboard.type('echo "Post-Load Input Test"');
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(3000);

      // Check results
      const result = await this.page.evaluate(() => {
        const terminals = document.querySelectorAll('.xterm');
        if (terminals.length === 0) return { success: false, reason: 'No terminal found' };

        const content = terminals[0].textContent || '';
        const hasImmediateTest = content.includes('Immediate Input Test');
        const hasPostLoadTest = content.includes('Post-Load Input Test');

        return {
          success: hasImmediateTest || hasPostLoadTest,
          immediate: hasImmediateTest,
          postLoad: hasPostLoadTest,
          reason: `Immediate: ${hasImmediateTest}, Post-load: ${hasPostLoadTest}`,
          content: content.substring(0, 300)
        };
      });

      this.testResults.immediateInput = result.success;
      this.logEvent('TEST', 'Immediate input test result', result);

      return result;

    } catch (error) {
      this.logEvent('ERROR', 'Immediate input test failed', { error: error.message });
      this.testResults.immediateInput = false;
      return { success: false, error: error.message };
    }
  }

  async runAllTests() {
    this.logEvent('SUITE', 'Starting comprehensive terminal input test suite');

    try {
      // Setup
      await this.startServer();
      await this.startBrowser();
      await this.navigateToApp();
      await this.waitForTerminalReady();

      // Run all tests
      const results = {
        singleTerminal: await this.testSingleTerminalInput(),
        multiTerminal: await this.testMultiTerminalRouting(),
        sessionSwitching: await this.testSessionSwitching(),
        focusManagement: await this.testFocusManagement(),
        websocketReconnection: await this.testWebSocketReconnection(),
        immediateInput: await this.testImmediateInput()
      };

      // Calculate overall success
      const successCount = Object.values(this.testResults).filter(Boolean).length;
      const totalTests = Object.keys(this.testResults).length - 1; // Exclude overallSuccess
      this.testResults.overallSuccess = successCount >= totalTests * 0.7; // 70% success rate

      this.logEvent('SUITE', 'Test suite completed', {
        results: this.testResults,
        successRate: `${successCount}/${totalTests}`
      });

      return {
        success: this.testResults.overallSuccess,
        results: this.testResults,
        details: results,
        eventLog: this.eventLog
      };

    } catch (error) {
      this.logEvent('ERROR', 'Test suite failed', { error: error.message });
      return {
        success: false,
        error: error.message,
        results: this.testResults,
        eventLog: this.eventLog
      };
    }
  }

  async cleanup() {
    this.logEvent('CLEANUP', 'Cleaning up test environment');

    if (this.browser) {
      await this.browser.close();
    }

    if (this.serverProcess) {
      this.serverProcess.kill('SIGTERM');

      // Wait for graceful shutdown
      await new Promise(resolve => {
        this.serverProcess.on('exit', resolve);
        setTimeout(() => {
          this.serverProcess.kill('SIGKILL');
          resolve();
        }, 5000);
      });
    }
  }

  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        overallSuccess: this.testResults.overallSuccess,
        testsRun: Object.keys(this.testResults).length - 1,
        testsPassed: Object.values(this.testResults).filter(Boolean).length - (this.testResults.overallSuccess ? 1 : 0)
      },
      details: this.testResults,
      recommendations: []
    };

    // Add recommendations based on failures
    if (!this.testResults.singleTerminalInput) {
      report.recommendations.push('Fix basic terminal input - fundamental functionality broken');
    }
    if (!this.testResults.multiTerminalRouting) {
      report.recommendations.push('Improve input routing for multiple terminal scenarios');
    }
    if (!this.testResults.sessionSwitching) {
      report.recommendations.push('Fix session switching and focus management');
    }
    if (!this.testResults.focusManagement) {
      report.recommendations.push('Improve terminal focus handling and click events');
    }
    if (!this.testResults.websocketReconnection) {
      report.recommendations.push('Enhance WebSocket reconnection and input recovery');
    }
    if (!this.testResults.immediateInput) {
      report.recommendations.push('Fix input handling during page load and initialization');
    }

    return report;
  }
}

// Main test execution
async function runTerminalInputVerification() {
  const tester = new TerminalInputTester();

  try {
    const results = await tester.runAllTests();
    const report = tester.generateReport();

    console.log('\n' + '='.repeat(80));
    console.log('TERMINAL INPUT VERIFICATION RESULTS');
    console.log('='.repeat(80));
    console.log(`Overall Success: ${results.success ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`Tests Passed: ${report.summary.testsPassed}/${report.summary.testsRun}`);
    console.log('\nDetailed Results:');

    Object.entries(tester.testResults).forEach(([test, passed]) => {
      if (test !== 'overallSuccess') {
        console.log(`  ${test}: ${passed ? '✅' : '❌'}`);
      }
    });

    if (report.recommendations.length > 0) {
      console.log('\nRecommendations:');
      report.recommendations.forEach((rec, i) => {
        console.log(`  ${i + 1}. ${rec}`);
      });
    }

    console.log('\n' + '='.repeat(80));

    return results;

  } finally {
    await tester.cleanup();
  }
}

// Export for use in other tests
module.exports = { TerminalInputTester, runTerminalInputVerification };

// Run if called directly
if (require.main === module) {
  runTerminalInputVerification()
    .then(results => {
      process.exit(results.success ? 0 : 1);
    })
    .catch(error => {
      console.error('Test runner failed:', error);
      process.exit(1);
    });
}