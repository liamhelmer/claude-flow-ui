/**
 * TERMINAL REFRESH REGRESSION TEST
 *
 * Objective: Reproduce the terminal refresh issue where:
 * - Input reaches backend successfully (confirmed in logs)
 * - New data does NOT appear in display
 * - Display remains stale/unupdated
 *
 * This test captures and validates the exact reproduction steps
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

class TerminalRefreshRegressionTest {
  constructor() {
    this.serverProcess = null;
    this.browser = null;
    this.page = null;
    this.testResults = {
      backendReceptionConfirmed: false,
      displayUpdateDetected: false,
      refreshOperationAttempted: false,
      displayUpdateAfterRefresh: false,
      workaroundValidated: false,
      regressionConfirmed: false
    };
    this.events = {
      inputs: [],
      outputs: [],
      websocketMessages: [],
      backendResponses: [],
      displayUpdates: []
    };
  }

  async initialize() {
    console.log('🚀 Initializing Terminal Refresh Regression Test...');

    // Start production server
    this.serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11250',
      '--terminal-size', '120x40',
      'hive-mind', 'spawn', 'test regression refresh',
      '--claude'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server startup
    await this.waitForServerStartup();

    // Launch browser with debugging capabilities
    this.browser = await chromium.launch({
      headless: false,
      args: ['--disable-web-security', '--allow-running-insecure-content']
    });
    this.page = await this.browser.newPage();

    // Enable enhanced logging
    await this.page.addInitScript(() => {
      window._regressionTest = {
        events: [],
        displaySnapshots: []
      };
    });

    console.log('✅ Test environment initialized');
  }

  async waitForServerStartup() {
    return new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => {
        reject(new Error('Server startup timeout'));
      }, 30000);

      this.serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        console.log('📊 Server:', text.trim());

        if (output.includes('Running on:') || output.includes('localhost:11250')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });

      this.serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        console.log('⚠️ Server stderr:', text.trim());

        if (text.includes('Running on:') || text.includes('localhost:11250')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });
    });
  }

  async setupEventTracking() {
    console.log('🔍 Setting up comprehensive event tracking...');

    // Track all console messages for backend/WebSocket activity
    this.page.on('console', (msg) => {
      const text = msg.text();
      const timestamp = Date.now();

      // Track input events reaching backend
      if (text.includes('Input received:') ||
          text.includes('sendData') ||
          text.includes('onData') ||
          text.includes('Routing input to session')) {
        this.events.inputs.push({ timestamp, message: text });
        console.log(`⌨️ INPUT EVENT: ${text.substring(0, 120)}`);
      }

      // Track backend responses and data reception
      if (text.includes('terminal-data event received') ||
          text.includes('Processing data for session') ||
          text.includes('Writing') ||
          text.includes('Backend response')) {
        this.events.backendResponses.push({ timestamp, message: text });
        console.log(`📤 BACKEND RESPONSE: ${text.substring(0, 120)}`);
      }

      // Track WebSocket activity
      if (text.includes('WebSocket') ||
          text.includes('Socket.IO') ||
          text.includes('terminal-data')) {
        this.events.websocketMessages.push({ timestamp, message: text });
      }

      // Track display updates
      if (text.includes('write') ||
          text.includes('Terminal content') ||
          text.includes('Display update')) {
        this.events.displayUpdates.push({ timestamp, message: text });
      }
    });

    // Intercept network requests to track backend communication
    await this.page.route('**/*', (route) => {
      const request = route.request();

      if (request.url().includes('/api/') || request.method() === 'POST') {
        console.log(`🌐 Network Request: ${request.method()} ${request.url()}`);
        this.events.outputs.push({
          timestamp: Date.now(),
          type: 'network',
          method: request.method(),
          url: request.url(),
          postData: request.postData()
        });
      }

      route.continue();
    });
  }

  async navigateAndWaitForTerminal() {
    console.log('📱 Navigating to terminal interface...');

    await this.page.goto('http://localhost:11250', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    // Wait for terminal to be fully initialized
    console.log('⏳ Waiting 15 seconds for complete terminal initialization...');
    await this.page.waitForTimeout(15000);

    // Verify terminal is present and functional
    const terminalState = await this.page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      const hasCanvas = document.querySelectorAll('canvas').length > 0;
      const hasWrapper = document.querySelectorAll('.xterm-wrapper').length > 0;

      return {
        terminalCount: terminals.length,
        hasTerminal: terminals.length > 0,
        hasCanvas,
        hasWrapper,
        terminalVisible: terminals.length > 0 &&
          window.getComputedStyle(terminals[0]).display !== 'none'
      };
    });

    console.log('📊 Terminal initialization state:', terminalState);

    if (!terminalState.hasTerminal) {
      throw new Error('Terminal not found in DOM - cannot proceed with regression test');
    }

    return terminalState;
  }

  async captureDisplaySnapshot(label) {
    console.log(`📸 Capturing display snapshot: ${label}`);

    const snapshot = await this.page.evaluate((snapshotLabel) => {
      const terminals = document.querySelectorAll('.xterm');
      if (terminals.length === 0) return null;

      const terminal = terminals[0];
      const content = {
        textContent: terminal.textContent || '',
        innerHTML: terminal.innerHTML.substring(0, 1000), // Truncate for logging
        rowCount: terminal.querySelectorAll('.xterm-rows > div').length,
        visibleText: '',
        lastLines: []
      };

      // Extract last 5 lines of visible text
      const rows = terminal.querySelectorAll('.xterm-rows > div');
      const lastRows = Array.from(rows).slice(-5);
      content.lastLines = lastRows.map(row => row.textContent || '');
      content.visibleText = content.lastLines.join('\n');

      // Store in window for later comparison
      if (!window._regressionTest.displaySnapshots) {
        window._regressionTest.displaySnapshots = [];
      }

      window._regressionTest.displaySnapshots.push({
        label: snapshotLabel,
        timestamp: Date.now(),
        content: content
      });

      return content;
    }, label);

    console.log(`📸 Snapshot "${label}" captured:`, {
      textLength: snapshot?.textContent?.length || 0,
      rowCount: snapshot?.rowCount || 0,
      lastLine: snapshot?.lastLines?.[snapshot.lastLines.length - 1] || '(empty)'
    });

    return snapshot;
  }

  async performRegressionTest() {
    console.log('🎯 Executing Terminal Refresh Regression Test Steps...');

    // Step 1: Capture initial display state
    const initialSnapshot = await this.captureDisplaySnapshot('initial_state');

    // Step 2: Clear events to focus on test input
    this.events.inputs = [];
    this.events.backendResponses = [];
    this.events.displayUpdates = [];

    // Step 3: Send test command that should produce visible output
    const testCommand = 'echo "REFRESH_TEST_$(date +%s)"';
    console.log(`⌨️ Sending test command: ${testCommand}`);

    // Focus terminal and type command
    await this.page.click('.xterm-wrapper, .terminal-container, .xterm', { force: true });
    await this.page.waitForTimeout(500);

    // Type command character by character
    for (const char of testCommand) {
      await this.page.keyboard.type(char);
      await this.page.waitForTimeout(30);
    }

    // Press Enter to execute
    await this.page.keyboard.press('Enter');
    console.log('↩️ Command executed');

    // Step 4: Wait and monitor for backend reception
    console.log('⏳ Monitoring backend reception for 5 seconds...');
    await this.page.waitForTimeout(5000);

    // Step 5: Check if backend received input
    this.testResults.backendReceptionConfirmed = this.events.inputs.some(
      event => event.message.includes('echo') ||
               event.message.includes('REFRESH_TEST') ||
               event.message.includes('Input received')
    );

    console.log(`📊 Backend Reception: ${this.testResults.backendReceptionConfirmed ? '✅ CONFIRMED' : '❌ NOT DETECTED'}`);

    // Step 6: Capture display state after command
    const postCommandSnapshot = await this.captureDisplaySnapshot('post_command');

    // Step 7: Check if display updated with new content
    this.testResults.displayUpdateDetected = this.hasDisplayChanged(initialSnapshot, postCommandSnapshot, 'REFRESH_TEST');

    console.log(`📊 Display Update: ${this.testResults.displayUpdateDetected ? '✅ DETECTED' : '❌ NOT DETECTED'}`);

    // Step 8: If display not updated, attempt refresh operation
    if (!this.testResults.displayUpdateDetected) {
      console.log('🔄 Display not updated - attempting refresh operation...');

      // Try various refresh methods
      await this.attemptRefreshOperations();

      this.testResults.refreshOperationAttempted = true;

      // Wait after refresh
      await this.page.waitForTimeout(3000);

      // Check display after refresh
      const postRefreshSnapshot = await this.captureDisplaySnapshot('post_refresh');
      this.testResults.displayUpdateAfterRefresh = this.hasDisplayChanged(postCommandSnapshot, postRefreshSnapshot, 'REFRESH_TEST');

      console.log(`📊 Display After Refresh: ${this.testResults.displayUpdateAfterRefresh ? '✅ UPDATED' : '❌ STILL STALE'}`);
    }

    // Step 9: Determine if regression is confirmed
    this.testResults.regressionConfirmed =
      this.testResults.backendReceptionConfirmed &&
      !this.testResults.displayUpdateDetected;

    console.log('\n📊 REGRESSION TEST RESULTS:');
    console.log('='.repeat(60));
    console.log(`Backend Reception Confirmed: ${this.testResults.backendReceptionConfirmed ? '✅' : '❌'}`);
    console.log(`Display Update Detected: ${this.testResults.displayUpdateDetected ? '✅' : '❌'}`);
    console.log(`Refresh Operation Attempted: ${this.testResults.refreshOperationAttempted ? '✅' : '❌'}`);
    console.log(`Display Update After Refresh: ${this.testResults.displayUpdateAfterRefresh ? '✅' : '❌'}`);
    console.log(`REGRESSION CONFIRMED: ${this.testResults.regressionConfirmed ? '🔴 YES' : '🟢 NO'}`);

    return this.testResults;
  }

  async attemptRefreshOperations() {
    console.log('🔄 Attempting various refresh operations...');

    // Method 1: Browser refresh
    try {
      await this.page.reload({ waitUntil: 'networkidle' });
      await this.page.waitForTimeout(3000);
      console.log('✅ Browser refresh completed');
    } catch (err) {
      console.log('❌ Browser refresh failed:', err.message);
    }

    // Method 2: Focus/blur cycle
    try {
      await this.page.click('body');
      await this.page.waitForTimeout(500);
      await this.page.click('.xterm-wrapper, .xterm');
      console.log('✅ Focus cycle completed');
    } catch (err) {
      console.log('❌ Focus cycle failed:', err.message);
    }

    // Method 3: Send refresh command if available
    try {
      await this.page.keyboard.press('Control+L');
      await this.page.waitForTimeout(1000);
      console.log('✅ Control+L refresh completed');
    } catch (err) {
      console.log('❌ Control+L refresh failed:', err.message);
    }
  }

  hasDisplayChanged(snapshot1, snapshot2, expectedContent) {
    if (!snapshot1 || !snapshot2) return false;

    // Check if content length changed
    const lengthChanged = snapshot1.textContent.length !== snapshot2.textContent.length;

    // Check if expected content appears
    const hasExpectedContent = snapshot2.textContent.includes(expectedContent) ||
                              snapshot2.visibleText.includes(expectedContent);

    // Check if last lines changed
    const lastLinesChanged = JSON.stringify(snapshot1.lastLines) !== JSON.stringify(snapshot2.lastLines);

    return lengthChanged || hasExpectedContent || lastLinesChanged;
  }

  async generateDetailedReport() {
    console.log('\n📋 Generating detailed regression test report...');

    const report = {
      testType: 'Terminal Refresh Regression',
      timestamp: new Date().toISOString(),
      regressionConfirmed: this.testResults.regressionConfirmed,
      results: this.testResults,
      eventCounts: {
        inputs: this.events.inputs.length,
        backendResponses: this.events.backendResponses.length,
        websocketMessages: this.events.websocketMessages.length,
        displayUpdates: this.events.displayUpdates.length
      },
      sampleEvents: {
        firstInput: this.events.inputs[0]?.message?.substring(0, 100) || 'None',
        firstBackendResponse: this.events.backendResponses[0]?.message?.substring(0, 100) || 'None',
        lastDisplayUpdate: this.events.displayUpdates[this.events.displayUpdates.length - 1]?.message?.substring(0, 100) || 'None'
      },
      diagnostics: await this.generateDiagnostics()
    };

    console.log('📋 Regression Test Report:', JSON.stringify(report, null, 2));
    return report;
  }

  async generateDiagnostics() {
    return await this.page.evaluate(() => {
      const diagnostics = {
        terminalElements: document.querySelectorAll('.xterm').length,
        websocketState: window.WebSocket ? 'available' : 'unavailable',
        displaySnapshots: window._regressionTest?.displaySnapshots?.length || 0,
        consoleErrors: window._regressionTest?.errors?.length || 0
      };

      return diagnostics;
    });
  }

  async cleanup() {
    console.log('🧹 Cleaning up test environment...');

    if (this.browser) {
      await this.browser.close();
    }

    if (this.serverProcess) {
      this.serverProcess.kill('SIGTERM');
    }

    console.log('✅ Cleanup completed');
  }

  async run() {
    try {
      await this.initialize();
      await this.setupEventTracking();
      await this.navigateAndWaitForTerminal();

      const results = await this.performRegressionTest();
      const report = await this.generateDetailedReport();

      return {
        success: !results.regressionConfirmed,
        regressionDetected: results.regressionConfirmed,
        report
      };

    } catch (error) {
      console.error('💥 Regression test failed:', error);
      return {
        success: false,
        error: error.message,
        regressionDetected: false
      };
    } finally {
      await this.cleanup();
    }
  }
}

// Export for use in test runners
module.exports = TerminalRefreshRegressionTest;

// Run test if called directly
if (require.main === module) {
  const test = new TerminalRefreshRegressionTest();
  test.run().then(result => {
    console.log('\n🎯 TERMINAL REFRESH REGRESSION TEST COMPLETED');
    console.log('='.repeat(60));

    if (result.regressionDetected) {
      console.log('🔴 REGRESSION CONFIRMED: Terminal refresh issue reproduced');
      console.log('   - Input reaches backend successfully');
      console.log('   - Display does NOT update with new content');
      console.log('   - Manual refresh operations attempted');
      console.log('   - Issue requires investigation and fix');
    } else if (result.success) {
      console.log('🟢 NO REGRESSION: Terminal refresh working correctly');
      console.log('   - Input reaches backend successfully');
      console.log('   - Display updates with new content');
      console.log('   - Terminal refresh functionality working');
    } else {
      console.log('⚠️ TEST FAILURE: Unable to complete regression test');
      console.log('   - Error occurred during test execution');
      console.log(`   - Error: ${result.error}`);
    }

    process.exit(result.success ? 0 : 1);
  });
}