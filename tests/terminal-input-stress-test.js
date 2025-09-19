/**
 * Terminal Input Stress Test
 * Pushes terminal input system to its limits to identify potential issues
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

class TerminalStressTester {
  constructor() {
    this.serverProcess = null;
    this.browser = null;
    this.page = null;
    this.stressResults = {
      rapidTyping: false,
      massiveInput: false,
      concurrentInputs: false,
      memoryStress: false,
      reconnectionStress: false,
      focusStress: false
    };
    this.performanceMetrics = {
      avgResponseTime: 0,
      maxResponseTime: 0,
      inputDropRate: 0,
      memoryUsage: []
    };
  }

  async setup() {
    console.log('🚀 Setting up stress test environment...');

    // Start server
    this.serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11400',
      '--terminal-size', '120x40',
      'stress-test-session'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    await new Promise((resolve) => {
      this.serverProcess.stdout.on('data', (data) => {
        if (data.toString().includes('Running on:')) {
          setTimeout(resolve, 3000);
        }
      });
    });

    // Start browser
    this.browser = await chromium.launch({ headless: false });
    this.page = await this.browser.newPage();

    await this.page.goto('http://localhost:11400', { waitUntil: 'networkidle' });
    await this.page.waitForTimeout(15000);
  }

  async measurePerformance(testFunction, testName) {
    console.log(`📊 Running performance test: ${testName}`);

    const startTime = Date.now();
    const startMemory = await this.page.evaluate(() => performance.memory?.usedJSHeapSize || 0);

    const result = await testFunction();

    const endTime = Date.now();
    const endMemory = await this.page.evaluate(() => performance.memory?.usedJSHeapSize || 0);

    const responseTime = endTime - startTime;
    const memoryDelta = endMemory - startMemory;

    this.performanceMetrics.avgResponseTime =
      (this.performanceMetrics.avgResponseTime + responseTime) / 2;
    this.performanceMetrics.maxResponseTime =
      Math.max(this.performanceMetrics.maxResponseTime, responseTime);
    this.performanceMetrics.memoryUsage.push(memoryDelta);

    console.log(`⏱️ ${testName} took ${responseTime}ms, memory delta: ${memoryDelta} bytes`);

    return result;
  }

  async testRapidTyping() {
    return this.measurePerformance(async () => {
      console.log('🏃‍♂️ Testing rapid typing...');

      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });

      // Type 500 characters as fast as possible
      const rapidText = 'abcdefghijklmnopqrstuvwxyz0123456789'.repeat(14); // ~500 chars

      const startTime = Date.now();

      // Type character by character with minimal delay
      for (const char of rapidText) {
        await this.page.keyboard.type(char);
        await this.page.waitForTimeout(1); // Minimal delay
      }

      const typingTime = Date.now() - startTime;

      // Wait for all input to be processed
      await this.page.waitForTimeout(2000);

      // Check if all characters appeared
      const result = await this.page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        const content = terminal ? terminal.textContent || '' : '';
        return {
          contentLength: content.length,
          hasTypedContent: content.includes('abcdefghijklmnopqrstuvwxyz'),
          fullContent: content.substring(content.length - 100) // Last 100 chars
        };
      });

      const success = result.hasTypedContent && result.contentLength > 400;

      console.log(`📝 Rapid typing result:`, {
        typingTime: `${typingTime}ms`,
        success,
        contentLength: result.contentLength,
        hasExpectedContent: result.hasTypedContent
      });

      this.stressResults.rapidTyping = success;
      return success;

    }, 'Rapid Typing');
  }

  async testMassiveInput() {
    return this.measurePerformance(async () => {
      console.log('📄 Testing massive input handling...');

      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });

      // Clear any existing input
      await this.page.keyboard.press('Control+C');
      await this.page.waitForTimeout(500);

      // Create a very large command
      const baseCommand = 'echo "';
      const largeContent = 'A'.repeat(5000); // 5KB of content
      const endCommand = '"';
      const fullCommand = baseCommand + largeContent + endCommand;

      console.log(`📝 Typing massive command (${fullCommand.length} characters)...`);

      // Type the massive command
      await this.page.keyboard.type(fullCommand);
      await this.page.keyboard.press('Enter');

      // Wait for processing
      await this.page.waitForTimeout(5000);

      // Check if command was processed
      const result = await this.page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        const content = terminal ? terminal.textContent || '' : '';
        return {
          hasEcho: content.includes('echo'),
          hasLargeContent: content.includes('AAAAA'),
          contentLength: content.length,
          lastContent: content.substring(Math.max(0, content.length - 200))
        };
      });

      const success = result.hasEcho || result.hasLargeContent;

      console.log(`📋 Massive input result:`, {
        success,
        hasEcho: result.hasEcho,
        hasLargeContent: result.hasLargeContent,
        contentLength: result.contentLength
      });

      this.stressResults.massiveInput = success;
      return success;

    }, 'Massive Input');
  }

  async testConcurrentInputs() {
    return this.measurePerformance(async () => {
      console.log('🔄 Testing concurrent input handling...');

      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });

      // Simulate concurrent inputs by rapidly switching focus and typing
      const concurrentOperations = [];

      for (let i = 0; i < 10; i++) {
        concurrentOperations.push(
          (async () => {
            await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
            await this.page.keyboard.type(`concurrent${i} `);
            await this.page.waitForTimeout(Math.random() * 100);
          })()
        );
      }

      // Execute all concurrent operations
      await Promise.all(concurrentOperations);

      // Add final command to test
      await this.page.keyboard.type('echo "concurrent test done"');
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(3000);

      // Check results
      const result = await this.page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        const content = terminal ? terminal.textContent || '' : '';

        let concurrentCount = 0;
        for (let i = 0; i < 10; i++) {
          if (content.includes(`concurrent${i}`)) {
            concurrentCount++;
          }
        }

        return {
          concurrentInputsFound: concurrentCount,
          hasFinalTest: content.includes('concurrent test done'),
          contentLength: content.length,
          sample: content.substring(Math.max(0, content.length - 300))
        };
      });

      const success = result.concurrentInputsFound >= 7 || result.hasFinalTest;

      console.log(`🔀 Concurrent input result:`, {
        success,
        concurrentInputsFound: result.concurrentInputsFound,
        hasFinalTest: result.hasFinalTest
      });

      this.stressResults.concurrentInputs = success;
      return success;

    }, 'Concurrent Inputs');
  }

  async testMemoryStress() {
    return this.measurePerformance(async () => {
      console.log('🧠 Testing memory stress...');

      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });

      // Generate lots of output to stress memory
      const memoryStressCommands = [
        'for i in {1..100}; do echo "Memory stress test line $i with lots of content to fill up the terminal buffer"; done',
        'echo "Starting memory stress test"',
        'seq 1 500',
        'echo "Memory stress test complete"'
      ];

      for (const command of memoryStressCommands) {
        await this.page.keyboard.type(command);
        await this.page.keyboard.press('Enter');
        await this.page.waitForTimeout(1000);

        // Check memory usage
        const memoryUsage = await this.page.evaluate(() => ({
          used: performance.memory?.usedJSHeapSize || 0,
          total: performance.memory?.totalJSHeapSize || 0,
          limit: performance.memory?.jsHeapSizeLimit || 0
        }));

        console.log(`📊 Memory usage: ${Math.round(memoryUsage.used / 1024 / 1024)}MB`);

        // Check if memory usage is reasonable (less than 100MB)
        if (memoryUsage.used > 100 * 1024 * 1024) {
          console.warn('⚠️ High memory usage detected');
        }
      }

      // Final check
      const result = await this.page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        const content = terminal ? terminal.textContent || '' : '';
        return {
          hasStressContent: content.includes('Memory stress test'),
          hasSequenceNumbers: content.includes('100') || content.includes('500'),
          contentLength: content.length,
          finalMemory: performance.memory?.usedJSHeapSize || 0
        };
      });

      const success = result.hasStressContent && result.finalMemory < 150 * 1024 * 1024; // Less than 150MB

      console.log(`🧠 Memory stress result:`, {
        success,
        hasStressContent: result.hasStressContent,
        finalMemoryMB: Math.round(result.finalMemory / 1024 / 1024)
      });

      this.stressResults.memoryStress = success;
      return success;

    }, 'Memory Stress');
  }

  async testReconnectionStress() {
    return this.measurePerformance(async () => {
      console.log('🔌 Testing reconnection stress...');

      // Test multiple reconnections
      for (let i = 0; i < 3; i++) {
        console.log(`📡 Reconnection test ${i + 1}/3`);

        // Type before reconnection
        await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
        await this.page.keyboard.type(`echo "before reconnect ${i}"`);
        await this.page.keyboard.press('Enter');
        await this.page.waitForTimeout(1000);

        // Simulate reconnection by reloading
        await this.page.reload({ waitUntil: 'networkidle' });
        await this.page.waitForTimeout(10000);

        // Type after reconnection
        await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
        await this.page.keyboard.type(`echo "after reconnect ${i}"`);
        await this.page.keyboard.press('Enter');
        await this.page.waitForTimeout(2000);
      }

      // Check final result
      const result = await this.page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        const content = terminal ? terminal.textContent || '' : '';

        let reconnectCount = 0;
        for (let i = 0; i < 3; i++) {
          if (content.includes(`after reconnect ${i}`)) {
            reconnectCount++;
          }
        }

        return {
          reconnectionsSuccessful: reconnectCount,
          hasAnyReconnectContent: content.includes('after reconnect'),
          contentLength: content.length
        };
      });

      const success = result.reconnectionsSuccessful >= 2; // At least 2/3 should work

      console.log(`🔌 Reconnection stress result:`, {
        success,
        reconnectionsSuccessful: result.reconnectionsSuccessful,
        totalTests: 3
      });

      this.stressResults.reconnectionStress = success;
      return success;

    }, 'Reconnection Stress');
  }

  async testFocusStress() {
    return this.measurePerformance(async () => {
      console.log('🎯 Testing focus stress...');

      const focusTargets = [
        '.xterm',
        '.xterm-wrapper',
        '.terminal-container',
        'body'
      ];

      // Rapidly switch focus and test input
      for (let round = 0; round < 5; round++) {
        for (const target of focusTargets) {
          try {
            await this.page.click(target, { force: true });
            await this.page.waitForTimeout(50);

            if (target !== 'body') {
              await this.page.keyboard.type(`f${round}`);
              await this.page.waitForTimeout(50);
            }
          } catch (e) {
            console.log(`⚠️ Could not click ${target}`);
          }
        }
      }

      // Final test
      await this.page.click('.xterm, .xterm-wrapper, .terminal-container', { force: true });
      await this.page.keyboard.type(' echo "focus stress complete"');
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(2000);

      // Check results
      const result = await this.page.evaluate(() => {
        const terminal = document.querySelector('.xterm');
        const content = terminal ? terminal.textContent || '' : '';

        let focusCharCount = 0;
        for (let i = 0; i < 5; i++) {
          if (content.includes(`f${i}`)) {
            focusCharCount++;
          }
        }

        return {
          focusCharactersFound: focusCharCount,
          hasFinalTest: content.includes('focus stress complete'),
          contentLength: content.length
        };
      });

      const success = result.focusCharactersFound >= 3 || result.hasFinalTest;

      console.log(`🎯 Focus stress result:`, {
        success,
        focusCharactersFound: result.focusCharactersFound,
        hasFinalTest: result.hasFinalTest
      });

      this.stressResults.focusStress = success;
      return success;

    }, 'Focus Stress');
  }

  async runStressTests() {
    console.log('🚨 Starting Terminal Input Stress Test Suite');
    console.log('=' .repeat(60));

    try {
      await this.setup();

      // Run all stress tests
      await this.testRapidTyping();
      await this.testMassiveInput();
      await this.testConcurrentInputs();
      await this.testMemoryStress();
      await this.testReconnectionStress();
      await this.testFocusStress();

      // Calculate overall results
      const passedTests = Object.values(this.stressResults).filter(Boolean).length;
      const totalTests = Object.keys(this.stressResults).length;
      const successRate = (passedTests / totalTests) * 100;

      console.log('\n' + '🎯 STRESS TEST RESULTS'.padStart(40));
      console.log('=' .repeat(60));
      console.log(`Overall Success Rate: ${successRate.toFixed(1)}% (${passedTests}/${totalTests})`);
      console.log('');

      Object.entries(this.stressResults).forEach(([test, passed]) => {
        const status = passed ? '✅ PASS' : '❌ FAIL';
        console.log(`${test.padEnd(20)}: ${status}`);
      });

      console.log('\n📊 Performance Metrics:');
      console.log(`Average Response Time: ${this.performanceMetrics.avgResponseTime.toFixed(0)}ms`);
      console.log(`Max Response Time: ${this.performanceMetrics.maxResponseTime}ms`);
      console.log(`Memory Usage Range: ${Math.min(...this.performanceMetrics.memoryUsage)} to ${Math.max(...this.performanceMetrics.memoryUsage)} bytes`);

      // Stress test passes if 70% of tests pass and performance is reasonable
      const overallSuccess = successRate >= 70 && this.performanceMetrics.maxResponseTime < 30000;

      console.log(`\n🏁 OVERALL STRESS TEST: ${overallSuccess ? '✅ PASS' : '❌ FAIL'}`);

      if (!overallSuccess) {
        console.log('\n⚠️ ISSUES DETECTED:');
        if (successRate < 70) {
          console.log(`- Low success rate: ${successRate.toFixed(1)}% (need 70%)`);
        }
        if (this.performanceMetrics.maxResponseTime >= 30000) {
          console.log(`- Poor performance: ${this.performanceMetrics.maxResponseTime}ms max response time`);
        }
      }

      return {
        success: overallSuccess,
        successRate,
        results: this.stressResults,
        performance: this.performanceMetrics
      };

    } catch (error) {
      console.error('💥 Stress test failed:', error);
      return { success: false, error: error.message };
    }
  }

  async cleanup() {
    console.log('🧹 Cleaning up stress test environment...');

    if (this.browser) {
      await this.browser.close();
    }

    if (this.serverProcess) {
      this.serverProcess.kill('SIGTERM');
      setTimeout(() => {
        if (this.serverProcess && !this.serverProcess.killed) {
          this.serverProcess.kill('SIGKILL');
        }
      }, 5000);
    }
  }
}

// Run stress tests
async function runStressTests() {
  const tester = new TerminalStressTester();

  try {
    return await tester.runStressTests();
  } finally {
    await tester.cleanup();
  }
}

// Export for use in other tests
module.exports = { TerminalStressTester, runStressTests };

// Run if called directly
if (require.main === module) {
  runStressTests()
    .then(results => {
      process.exit(results.success ? 0 : 1);
    })
    .catch(error => {
      console.error('Stress test runner failed:', error);
      process.exit(1);
    });
}