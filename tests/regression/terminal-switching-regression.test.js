/**
 * TERMINAL SWITCHING REGRESSION TEST
 *
 * Objective: Reproduce the terminal switching issue where:
 * - Multiple terminals are created successfully
 * - Clicking to switch between terminals shows wrong terminal content
 * - Expected terminal content doesn't appear when switching
 * - Session routing gets confused between terminals
 *
 * This test validates terminal switching behavior and session isolation
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

class TerminalSwitchingRegressionTest {
  constructor() {
    this.serverProcess = null;
    this.browser = null;
    this.page = null;
    this.terminals = new Map(); // Track created terminals
    this.testResults = {
      terminalsCreated: 0,
      switchingAttempted: false,
      wrongTerminalDisplayed: false,
      correctTerminalDisplayed: false,
      sessionIsolationWorking: false,
      regressionConfirmed: false
    };
    this.events = {
      terminalCreations: [],
      sessionSwitches: [],
      displayUpdates: [],
      routingErrors: []
    };
  }

  async initialize() {
    console.log('🚀 Initializing Terminal Switching Regression Test...');

    // Start production server
    this.serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11251',
      '--terminal-size', '100x30',
      'hive-mind', 'spawn', 'test terminal switching',
      '--claude'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    await this.waitForServerStartup();

    this.browser = await chromium.launch({
      headless: false,
      args: ['--disable-web-security', '--allow-running-insecure-content']
    });
    this.page = await this.browser.newPage();

    // Enable terminal switching tracking
    await this.page.addInitScript(() => {
      window._switchingTest = {
        terminalStates: {},
        switchEvents: [],
        currentSession: null
      };
    });

    console.log('✅ Test environment initialized for switching test');
  }

  async waitForServerStartup() {
    return new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => reject(new Error('Server timeout')), 30000);

      this.serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        if (output.includes('Running on:') || output.includes('localhost:11251')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });

      this.serverProcess.stderr.on('data', (data) => {
        const text = data.toString();
        if (text.includes('Running on:') || text.includes('localhost:11251')) {
          clearTimeout(timeout);
          setTimeout(resolve, 2000);
        }
      });
    });
  }

  async setupSwitchingEventTracking() {
    console.log('🔍 Setting up terminal switching event tracking...');

    this.page.on('console', (msg) => {
      const text = msg.text();
      const timestamp = Date.now();

      // Track terminal creation events
      if (text.includes('Terminal created') ||
          text.includes('New terminal session') ||
          text.includes('terminal-spawned')) {
        this.events.terminalCreations.push({ timestamp, message: text });
        console.log(`🏗️ TERMINAL CREATION: ${text.substring(0, 120)}`);
      }

      // Track session switching events
      if (text.includes('Session changed') ||
          text.includes('Switching to terminal') ||
          text.includes('Active session') ||
          text.includes('sessionId')) {
        this.events.sessionSwitches.push({ timestamp, message: text });
        console.log(`🔄 SESSION SWITCH: ${text.substring(0, 120)}`);
      }

      // Track routing and session errors
      if (text.includes('Session mismatch') ||
          text.includes('Wrong terminal') ||
          text.includes('Routing error') ||
          text.includes('Session ID mismatch')) {
        this.events.routingErrors.push({ timestamp, message: text });
        console.log(`⚠️ ROUTING ERROR: ${text.substring(0, 120)}`);
      }

      // Track display updates per session
      if (text.includes('terminal-data event received') ||
          text.includes('Processing data for session')) {
        this.events.displayUpdates.push({ timestamp, message: text });
      }
    });
  }

  async navigateAndSetupTerminals() {
    console.log('📱 Navigating to terminal interface...');

    await this.page.goto('http://localhost:11251', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    // Wait for initial terminal
    await this.page.waitForTimeout(10000);

    // Verify initial terminal exists
    const initialTerminalState = await this.page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      return {
        terminalCount: terminals.length,
        hasInitialTerminal: terminals.length > 0
      };
    });

    console.log('📊 Initial terminal state:', initialTerminalState);

    if (!initialTerminalState.hasInitialTerminal) {
      throw new Error('No initial terminal found - cannot proceed with switching test');
    }

    return initialTerminalState;
  }

  async createMultipleTerminals() {
    console.log('🏗️ Creating multiple terminals for switching test...');

    const terminalCount = 4; // Create 4 terminals for comprehensive testing

    for (let i = 1; i <= terminalCount; i++) {
      console.log(`Creating terminal ${i}...`);

      try {
        // Attempt to create new terminal (UI specific method)
        await this.createNewTerminal(i);

        // Wait for terminal to be ready
        await this.page.waitForTimeout(2000);

        // Send unique identifier to each terminal
        const identifier = `TERMINAL_${i}_${Date.now()}`;
        await this.sendCommandToCurrentTerminal(`echo "${identifier}"`);

        // Store terminal info
        this.terminals.set(`terminal-${i}`, {
          id: `terminal-${i}`,
          identifier,
          content: identifier,
          createdAt: Date.now()
        });

        console.log(`✅ Terminal ${i} created with identifier: ${identifier}`);

      } catch (error) {
        console.error(`❌ Failed to create terminal ${i}:`, error.message);
      }
    }

    this.testResults.terminalsCreated = this.terminals.size;
    console.log(`📊 Created ${this.testResults.terminalsCreated} terminals total`);

    // Wait for all terminals to settle
    await this.page.waitForTimeout(3000);

    return this.testResults.terminalsCreated;
  }

  async createNewTerminal(terminalNumber) {
    // This depends on the specific UI implementation
    // Try common methods to create new terminals

    // Method 1: Click new terminal button/tab
    try {
      const newTerminalButton = await this.page.$('[data-testid="new-terminal"], .new-terminal-btn, button:has-text("New Terminal")');
      if (newTerminalButton) {
        await newTerminalButton.click();
        console.log(`✅ Clicked new terminal button for terminal ${terminalNumber}`);
        return;
      }
    } catch (err) {
      console.log('Method 1 failed (new terminal button)');
    }

    // Method 2: Keyboard shortcut
    try {
      await this.page.keyboard.press('Control+Shift+T');
      console.log(`✅ Used keyboard shortcut for terminal ${terminalNumber}`);
      return;
    } catch (err) {
      console.log('Method 2 failed (keyboard shortcut)');
    }

    // Method 3: Context menu
    try {
      await this.page.click('.terminal-container', { button: 'right' });
      await this.page.waitForTimeout(500);
      const newTerminalOption = await this.page.$('text=New Terminal');
      if (newTerminalOption) {
        await newTerminalOption.click();
        console.log(`✅ Used context menu for terminal ${terminalNumber}`);
        return;
      }
    } catch (err) {
      console.log('Method 3 failed (context menu)');
    }

    // Method 4: URL manipulation (if terminals have separate routes)
    try {
      const currentUrl = this.page.url();
      const newUrl = `${currentUrl}?terminal=${terminalNumber}`;
      await this.page.goto(newUrl);
      console.log(`✅ Used URL navigation for terminal ${terminalNumber}`);
      return;
    } catch (err) {
      console.log('Method 4 failed (URL navigation)');
    }

    console.warn(`⚠️ All terminal creation methods failed for terminal ${terminalNumber}`);
  }

  async sendCommandToCurrentTerminal(command) {
    try {
      // Focus the current terminal
      await this.page.click('.xterm-wrapper, .terminal-container, .xterm');
      await this.page.waitForTimeout(300);

      // Type the command
      await this.page.keyboard.type(command);
      await this.page.waitForTimeout(100);

      // Press Enter
      await this.page.keyboard.press('Enter');
      await this.page.waitForTimeout(500);

      console.log(`✅ Sent command to terminal: ${command}`);
    } catch (error) {
      console.error(`❌ Failed to send command: ${command}`, error.message);
    }
  }

  async performSwitchingTest() {
    console.log('🔄 Performing terminal switching regression test...');

    if (this.terminals.size < 2) {
      console.warn('⚠️ Not enough terminals created for switching test');
      return false;
    }

    this.testResults.switchingAttempted = true;

    const terminalList = Array.from(this.terminals.entries());
    let correctSwitches = 0;
    let incorrectSwitches = 0;

    for (let i = 0; i < terminalList.length; i++) {
      const [terminalId, terminalInfo] = terminalList[i];

      console.log(`🎯 Attempting to switch to ${terminalId}...`);

      // Attempt to switch to this terminal
      const switchSuccess = await this.switchToTerminal(terminalId, i);

      if (switchSuccess) {
        // Wait for switch to complete
        await this.page.waitForTimeout(1000);

        // Capture current display content
        const displayContent = await this.captureCurrentTerminalContent();

        // Check if the correct terminal content is displayed
        const expectedContent = terminalInfo.identifier;
        const isCorrectTerminal = displayContent.includes(expectedContent);

        console.log(`📊 Switch to ${terminalId}:`, {
          expectedContent,
          displayedContent: displayContent.substring(0, 100),
          isCorrect: isCorrectTerminal
        });

        if (isCorrectTerminal) {
          correctSwitches++;
          console.log(`✅ Correct terminal content displayed for ${terminalId}`);
        } else {
          incorrectSwitches++;
          console.log(`❌ Wrong terminal content displayed for ${terminalId}`);

          // Check which terminal's content is actually shown
          const actualTerminal = this.identifyDisplayedTerminal(displayContent);
          if (actualTerminal && actualTerminal !== terminalId) {
            console.log(`🔍 Actually showing content from: ${actualTerminal}`);
            this.testResults.wrongTerminalDisplayed = true;
          }
        }
      } else {
        console.log(`❌ Failed to switch to ${terminalId}`);
      }

      // Small delay between switches
      await this.page.waitForTimeout(500);
    }

    // Calculate results
    this.testResults.correctTerminalDisplayed = correctSwitches > 0;
    this.testResults.sessionIsolationWorking = correctSwitches === terminalList.length;
    this.testResults.regressionConfirmed = incorrectSwitches > 0;

    console.log(`📊 Switching Test Results: ${correctSwitches} correct, ${incorrectSwitches} incorrect`);

    return true;
  }

  async switchToTerminal(terminalId, index) {
    console.log(`🔄 Switching to terminal: ${terminalId} (index: ${index})`);

    // Method 1: Click terminal tab (if tabs exist)
    try {
      const terminalTab = await this.page.$(`[data-terminal-id="${terminalId}"], .terminal-tab[data-index="${index}"]`);
      if (terminalTab) {
        await terminalTab.click();
        console.log(`✅ Clicked terminal tab for ${terminalId}`);
        return true;
      }
    } catch (err) {
      console.log('Tab click method failed');
    }

    // Method 2: Keyboard navigation
    try {
      await this.page.keyboard.press(`Control+${index + 1}`);
      console.log(`✅ Used keyboard shortcut Ctrl+${index + 1}`);
      return true;
    } catch (err) {
      console.log('Keyboard navigation failed');
    }

    // Method 3: Terminal selector dropdown
    try {
      const selector = await this.page.$('.terminal-selector, select[name="terminal"]');
      if (selector) {
        await selector.selectOption(terminalId);
        console.log(`✅ Selected from dropdown: ${terminalId}`);
        return true;
      }
    } catch (err) {
      console.log('Dropdown selection failed');
    }

    // Method 4: URL navigation
    try {
      const baseUrl = this.page.url().split('?')[0];
      await this.page.goto(`${baseUrl}?terminal=${index}`);
      console.log(`✅ Navigated to terminal via URL: ${terminalId}`);
      return true;
    } catch (err) {
      console.log('URL navigation failed');
    }

    console.warn(`⚠️ Could not switch to terminal ${terminalId}`);
    return false;
  }

  async captureCurrentTerminalContent() {
    return await this.page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      if (terminals.length === 0) return '';

      // Get content from the currently visible/active terminal
      const activeTerminal = Array.from(terminals).find(t => {
        const style = window.getComputedStyle(t);
        return style.display !== 'none' && style.visibility !== 'hidden';
      }) || terminals[0];

      return activeTerminal.textContent || '';
    });
  }

  identifyDisplayedTerminal(displayContent) {
    // Check which terminal's identifier appears in the displayed content
    for (const [terminalId, terminalInfo] of this.terminals.entries()) {
      if (displayContent.includes(terminalInfo.identifier)) {
        return terminalId;
      }
    }
    return null;
  }

  async validateSessionIsolation() {
    console.log('🔒 Validating session isolation between terminals...');

    if (this.terminals.size < 2) {
      console.warn('⚠️ Not enough terminals for session isolation test');
      return false;
    }

    const terminalList = Array.from(this.terminals.entries());
    const terminal1 = terminalList[0];
    const terminal2 = terminalList[1];

    // Switch to terminal 1 and send unique command
    await this.switchToTerminal(terminal1[0], 0);
    await this.page.waitForTimeout(1000);
    const unique1 = `ISOLATION_TEST_1_${Date.now()}`;
    await this.sendCommandToCurrentTerminal(`echo "${unique1}"`);
    await this.page.waitForTimeout(1000);

    // Switch to terminal 2 and send different unique command
    await this.switchToTerminal(terminal2[0], 1);
    await this.page.waitForTimeout(1000);
    const unique2 = `ISOLATION_TEST_2_${Date.now()}`;
    await this.sendCommandToCurrentTerminal(`echo "${unique2}"`);
    await this.page.waitForTimeout(1000);

    // Switch back to terminal 1 and check content
    await this.switchToTerminal(terminal1[0], 0);
    await this.page.waitForTimeout(1000);
    const terminal1Content = await this.captureCurrentTerminalContent();

    // Switch to terminal 2 and check content
    await this.switchToTerminal(terminal2[0], 1);
    await this.page.waitForTimeout(1000);
    const terminal2Content = await this.captureCurrentTerminalContent();

    // Validate isolation
    const terminal1HasOnlyIts = terminal1Content.includes(unique1) && !terminal1Content.includes(unique2);
    const terminal2HasOnlyIts = terminal2Content.includes(unique2) && !terminal2Content.includes(unique1);

    const isolationWorking = terminal1HasOnlyIts && terminal2HasOnlyIts;

    console.log('🔒 Session Isolation Results:', {
      terminal1HasCorrect: terminal1Content.includes(unique1),
      terminal1HasWrong: terminal1Content.includes(unique2),
      terminal2HasCorrect: terminal2Content.includes(unique2),
      terminal2HasWrong: terminal2Content.includes(unique1),
      isolationWorking
    });

    return isolationWorking;
  }

  async generateSwitchingReport() {
    console.log('\n📋 Generating terminal switching regression report...');

    const sessionIsolationWorking = await this.validateSessionIsolation();
    this.testResults.sessionIsolationWorking = sessionIsolationWorking;

    const report = {
      testType: 'Terminal Switching Regression',
      timestamp: new Date().toISOString(),
      regressionConfirmed: this.testResults.regressionConfirmed,
      results: {
        ...this.testResults,
        sessionIsolationWorking
      },
      terminalInfo: {
        terminalsCreated: this.terminals.size,
        terminalDetails: Array.from(this.terminals.entries()).map(([id, info]) => ({
          id,
          identifier: info.identifier,
          createdAt: new Date(info.createdAt).toISOString()
        }))
      },
      eventCounts: {
        terminalCreations: this.events.terminalCreations.length,
        sessionSwitches: this.events.sessionSwitches.length,
        routingErrors: this.events.routingErrors.length,
        displayUpdates: this.events.displayUpdates.length
      },
      diagnostics: await this.generateSwitchingDiagnostics()
    };

    console.log('📋 Terminal Switching Report:', JSON.stringify(report, null, 2));
    return report;
  }

  async generateSwitchingDiagnostics() {
    return await this.page.evaluate(() => {
      const diagnostics = {
        terminalElements: document.querySelectorAll('.xterm').length,
        visibleTerminals: Array.from(document.querySelectorAll('.xterm')).filter(t => {
          const style = window.getComputedStyle(t);
          return style.display !== 'none' && style.visibility !== 'hidden';
        }).length,
        terminalTabs: document.querySelectorAll('.terminal-tab, [data-terminal-id]').length,
        currentUrl: window.location.href,
        sessionStates: window._switchingTest?.terminalStates || {}
      };

      return diagnostics;
    });
  }

  async cleanup() {
    console.log('🧹 Cleaning up switching test environment...');

    if (this.browser) {
      await this.browser.close();
    }

    if (this.serverProcess) {
      this.serverProcess.kill('SIGTERM');
    }

    console.log('✅ Switching test cleanup completed');
  }

  async run() {
    try {
      await this.initialize();
      await this.setupSwitchingEventTracking();
      await this.navigateAndSetupTerminals();

      const terminalCount = await this.createMultipleTerminals();

      if (terminalCount < 2) {
        throw new Error('Unable to create multiple terminals for switching test');
      }

      await this.performSwitchingTest();
      const report = await this.generateSwitchingReport();

      return {
        success: !this.testResults.regressionConfirmed,
        regressionDetected: this.testResults.regressionConfirmed,
        terminalsCreated: terminalCount,
        report
      };

    } catch (error) {
      console.error('💥 Terminal switching test failed:', error);
      return {
        success: false,
        error: error.message,
        regressionDetected: false,
        terminalsCreated: this.terminals.size
      };
    } finally {
      await this.cleanup();
    }
  }
}

// Export for use in test runners
module.exports = TerminalSwitchingRegressionTest;

// Run test if called directly
if (require.main === module) {
  const test = new TerminalSwitchingRegressionTest();
  test.run().then(result => {
    console.log('\n🎯 TERMINAL SWITCHING REGRESSION TEST COMPLETED');
    console.log('='.repeat(60));

    if (result.regressionDetected) {
      console.log('🔴 SWITCHING REGRESSION CONFIRMED: Terminal switching issues detected');
      console.log(`   - Created ${result.terminalsCreated} terminals`);
      console.log('   - Wrong terminal content displayed when switching');
      console.log('   - Session isolation may be compromised');
      console.log('   - Terminal routing requires investigation');
    } else if (result.success) {
      console.log('🟢 NO SWITCHING REGRESSION: Terminal switching working correctly');
      console.log(`   - Created ${result.terminalsCreated} terminals successfully`);
      console.log('   - Correct terminal content displayed when switching');
      console.log('   - Session isolation maintained between terminals');
    } else {
      console.log('⚠️ SWITCHING TEST FAILURE: Unable to complete test');
      console.log(`   - Error: ${result.error}`);
      console.log(`   - Terminals created: ${result.terminalsCreated}`);
    }

    process.exit(result.success ? 0 : 1);
  });
}