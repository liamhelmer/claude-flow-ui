/**
 * Comprehensive Playwright Terminal Input Regression Test
 *
 * This test is designed to FAIL initially and demonstrate the terminal input bug.
 * It provides extensive debugging information to help identify where input is lost.
 *
 * CRITICAL: This test should fail until the terminal input issue is resolved.
 */

import { test, expect, Page, Browser } from '@playwright/test';
import { spawn, ChildProcess } from 'child_process';

interface TerminalEvent {
  time: number;
  type: 'input' | 'output' | 'websocket' | 'focus' | 'error';
  message: string;
  data?: any;
}

interface TerminalState {
  terminalCount: number;
  hasVisibleTerminal: boolean;
  hasCanvas: boolean;
  hasCursor: boolean;
  textareaCount: number;
  focusedElement: string;
  terminalContent: string;
  bufferContent: string;
  inputVisible: boolean;
  websocketConnected: boolean;
  terminalReady: boolean;
}

class TerminalTestRunner {
  private serverProcess: ChildProcess | null = null;
  private browser: Browser | null = null;
  private page: Page | null = null;
  private events: TerminalEvent[] = [];
  private readonly port = 11242;

  async startServer(): Promise<void> {
    console.log('🚀 Starting server for terminal input regression test...');

    this.serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', this.port.toString(),
      '--terminal-size', '120x40',
      'hive-mind', 'spawn', 'wait for instructions',
      '--claude'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    return new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => {
        reject(new Error(`Server failed to start within 30 seconds. Output: ${output}`));
      }, 30000);

      this.serverProcess!.stdout!.on('data', (data) => {
        const text = data.toString();
        output += text;
        console.log('📊 Server stdout:', text.trim());

        if (output.includes('Running on:') || output.includes(`localhost:${this.port}`)) {
          clearTimeout(timeout);
          setTimeout(resolve, 3000); // Extra time for full initialization
        }
      });

      this.serverProcess!.stderr!.on('data', (data) => {
        const text = data.toString();
        output += text;
        console.log('⚠️ Server stderr:', text.trim());

        if (text.includes('Running on:') || text.includes(`localhost:${this.port}`)) {
          clearTimeout(timeout);
          setTimeout(resolve, 3000);
        }
      });

      this.serverProcess!.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  async setupBrowser(): Promise<void> {
    this.browser = await test.devices['Desktop Chrome'];
    // Launch browser with debugging enabled
    this.page = await this.browser.newPage();

    // Enable comprehensive console logging
    this.page.on('console', (msg) => {
      const text = msg.text();
      this.captureEvent('output', `Console: ${text}`);

      // Track specific events we care about
      if (text.includes('Input') || text.includes('onData') || text.includes('sendData')) {
        this.captureEvent('input', text);
      }

      if (text.includes('WebSocket') || text.includes('Connected')) {
        this.captureEvent('websocket', text);
      }

      if (text.includes('focus') || text.includes('Focus')) {
        this.captureEvent('focus', text);
      }

      if (text.includes('error') || text.includes('Error')) {
        this.captureEvent('error', text);
      }
    });

    // Track page errors
    this.page.on('pageerror', (error) => {
      this.captureEvent('error', `Page error: ${error.message}`);
    });

    // Track network issues
    this.page.on('requestfailed', (request) => {
      this.captureEvent('error', `Request failed: ${request.url()} - ${request.failure()?.errorText}`);
    });
  }

  private captureEvent(type: TerminalEvent['type'], message: string, data?: any): void {
    this.events.push({
      time: Date.now(),
      type,
      message,
      data
    });
  }

  async navigateToApp(): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    console.log(`📱 Navigating to http://localhost:${this.port}...`);
    const response = await this.page.goto(`http://localhost:${this.port}`, {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response?.status()}`);
    expect(response?.status()).toBe(200);
  }

  async waitForTerminalInitialization(): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    console.log('⏳ Waiting for terminal initialization...');

    // Wait for terminal elements to appear
    await this.page.waitForSelector('.xterm, .terminal-container', { timeout: 20000 });

    // Wait for WebSocket connection
    await this.page.waitForFunction(() => {
      const logs = Array.from(document.querySelectorAll('*')).map(el => el.textContent).join(' ');
      return logs.includes('WebSocket connected') || logs.includes('Connected successfully');
    }, { timeout: 15000 }).catch(() => {
      console.warn('⚠️ WebSocket connection not detected in DOM, checking console...');
    });

    // Additional wait for terminal readiness
    await this.page.waitForTimeout(5000);
  }

  async getTerminalState(): Promise<TerminalState> {
    if (!this.page) throw new Error('Page not initialized');

    return await this.page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      const terminalContainers = document.querySelectorAll('.terminal-container');
      const canvas = document.querySelectorAll('canvas');
      const cursors = document.querySelectorAll('.xterm-cursor');
      const textareas = document.querySelectorAll('textarea');
      const focusedElement = document.activeElement?.tagName?.toLowerCase() || 'none';

      // Try multiple methods to get terminal content
      let terminalContent = '';
      let bufferContent = '';

      if (terminals.length > 0) {
        terminalContent = terminals[0].textContent || '';

        // Try to get row content
        const rows = terminals[0].querySelectorAll('.xterm-rows > div, .xterm-row');
        const rowTexts = Array.from(rows).map(row => row.textContent || '').join('\n');
        if (rowTexts) terminalContent = rowTexts;

        // Try screen content
        const screen = terminals[0].querySelector('.xterm-screen');
        if (screen?.textContent) terminalContent = screen.textContent;
      }

      // Try to access terminal instance buffer
      try {
        const windowAny = window as any;
        const terminalInstances = windowAny.terminals || windowAny.terminalInstances || [];
        if (terminalInstances.length > 0 && terminalInstances[0]) {
          const term = terminalInstances[0];
          if (term.buffer && term.buffer.active) {
            for (let i = 0; i < Math.min(term.buffer.active.length, 50); i++) {
              const line = term.buffer.active.getLine(i);
              if (line) {
                bufferContent += line.translateToString(true) + '\n';
              }
            }
          }
        }
      } catch (e) {
        console.warn('Could not access terminal buffer:', e);
      }

      return {
        terminalCount: terminals.length,
        hasVisibleTerminal: terminals.length > 0 || terminalContainers.length > 0,
        hasCanvas: canvas.length > 0,
        hasCursor: cursors.length > 0,
        textareaCount: textareas.length,
        focusedElement,
        terminalContent: terminalContent.substring(0, 2000),
        bufferContent: bufferContent.substring(0, 2000),
        inputVisible: false, // Will be updated by test
        websocketConnected: false, // Will be updated by test
        terminalReady: false // Will be updated by test
      };
    });
  }

  async focusTerminal(): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    console.log('🎯 Attempting to focus terminal...');

    // Try multiple focus strategies
    const selectors = [
      '.xterm-helper-textarea',
      '.xterm-screen',
      '.xterm',
      '.terminal-container',
      '.xterm-wrapper'
    ];

    for (const selector of selectors) {
      try {
        await this.page.click(selector, { timeout: 2000 });
        this.captureEvent('focus', `Clicked ${selector}`);
        break;
      } catch (e) {
        this.captureEvent('focus', `Failed to click ${selector}: ${e}`);
      }
    }

    // Additional focus attempts
    await this.page.keyboard.press('Tab');
    await this.page.waitForTimeout(100);
  }

  async typeInput(text: string, options: { slow?: boolean, waitBetween?: number } = {}): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    const { slow = false, waitBetween = 0 } = options;
    console.log(`⌨️ Typing: "${text}" ${slow ? '(slow mode)' : ''}`);

    this.captureEvent('input', `Starting to type: "${text}"`);

    if (slow) {
      // Type character by character with delays
      for (const char of text) {
        await this.page.keyboard.type(char);
        await this.page.waitForTimeout(waitBetween || 100);
        this.captureEvent('input', `Typed character: "${char}"`);
      }
    } else {
      await this.page.keyboard.type(text);
    }

    this.captureEvent('input', `Finished typing: "${text}"`);
  }

  async pressKey(key: string): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    console.log(`🔑 Pressing key: ${key}`);
    this.captureEvent('input', `Pressing key: ${key}`);
    await this.page.keyboard.press(key);
  }

  async checkInputVisibility(expectedText: string): Promise<{ visible: boolean, content: string, methods: Record<string, string> }> {
    if (!this.page) throw new Error('Page not initialized');

    return await this.page.evaluate((expected) => {
      const terminals = document.querySelectorAll('.xterm');
      const methods: Record<string, string> = {};

      if (terminals.length > 0) {
        const terminal = terminals[0];

        // Method 1: Direct text content
        methods.directText = terminal.textContent || '';

        // Method 2: Row content
        const rows = terminal.querySelectorAll('.xterm-rows > div, .xterm-row');
        methods.rowText = Array.from(rows).map(row => row.textContent || '').join('\n');

        // Method 3: Screen content
        const screen = terminal.querySelector('.xterm-screen');
        methods.screenText = screen?.textContent || '';

        // Method 4: Canvas accessibility
        const canvas = terminal.querySelector('canvas');
        methods.canvasText = canvas?.getAttribute('aria-label') || '';

        // Method 5: All text nodes
        const walker = document.createTreeWalker(
          terminal,
          NodeFilter.SHOW_TEXT,
          null,
          false
        );
        let allText = '';
        let node;
        while (node = walker.nextNode()) {
          allText += node.textContent;
        }
        methods.allTextNodes = allText;
      }

      // Check if any method contains the expected text
      const visible = Object.values(methods).some(content =>
        content.toLowerCase().includes(expected.toLowerCase())
      );

      const combinedContent = Object.values(methods).join('\n---\n');

      return {
        visible,
        content: combinedContent.substring(0, 3000),
        methods
      };
    }, expectedText);
  }

  getEventsSummary(): { [key: string]: number } {
    const summary: { [key: string]: number } = {
      total: this.events.length,
      input: 0,
      output: 0,
      websocket: 0,
      focus: 0,
      error: 0
    };

    this.events.forEach(event => {
      summary[event.type] = (summary[event.type] || 0) + 1;
    });

    return summary;
  }

  async cleanup(): Promise<void> {
    if (this.browser) await this.browser.close();
    if (this.serverProcess) {
      this.serverProcess.kill('SIGTERM');
      // Wait for process to exit
      await new Promise(resolve => {
        this.serverProcess!.on('exit', resolve);
        setTimeout(resolve, 2000); // Force timeout
      });
    }
  }
}

test.describe('Terminal Input Regression Tests', () => {
  let runner: TerminalTestRunner;

  test.beforeEach(async () => {
    runner = new TerminalTestRunner();
  });

  test.afterEach(async () => {
    await runner.cleanup();
  });

  test('Terminal Input Visibility - Basic Test (SHOULD FAIL)', async () => {
    console.log('\n🧪 Starting Terminal Input Visibility Test');
    console.log('⚠️ This test is EXPECTED TO FAIL until the input bug is fixed!');

    await runner.startServer();
    await runner.setupBrowser();
    await runner.navigateToApp();
    await runner.waitForTerminalInitialization();

    // Get initial state
    const initialState = await runner.getTerminalState();
    console.log('📊 Initial terminal state:', {
      visible: initialState.hasVisibleTerminal,
      terminalCount: initialState.terminalCount,
      hasCanvas: initialState.hasCanvas,
      hasCursor: initialState.hasCursor,
      focusedElement: initialState.focusedElement
    });

    // Focus terminal
    await runner.focusTerminal();
    await runner.page!.waitForTimeout(1000);

    // Type a simple command
    const testCommand = 'echo "Hello World"';
    await runner.typeInput(testCommand);
    await runner.page!.waitForTimeout(2000);

    // Check if input is visible
    const inputCheck = await runner.checkInputVisibility(testCommand);

    console.log('\n📊 INPUT VISIBILITY RESULTS:');
    console.log('='.repeat(50));
    console.log(`Input visible: ${inputCheck.visible}`);
    console.log(`Expected: "${testCommand}"`);
    console.log('\nContent methods:');
    Object.entries(inputCheck.methods).forEach(([method, content]) => {
      console.log(`${method}: ${content.substring(0, 100)}${content.length > 100 ? '...' : ''}`);
    });

    // Press Enter
    await runner.pressKey('Enter');
    await runner.page!.waitForTimeout(3000);

    // Check again after Enter
    const afterEnterCheck = await runner.checkInputVisibility('Hello World');
    console.log(`\nAfter Enter - Output visible: ${afterEnterCheck.visible}`);

    // Get events summary
    const eventsSummary = runner.getEventsSummary();
    console.log('\nEvents captured:', eventsSummary);

    // This test SHOULD FAIL until the bug is fixed
    expect(inputCheck.visible).toBe(true); // This will fail, demonstrating the bug
  });

  test('Rapid Typing Test (SHOULD FAIL)', async () => {
    console.log('\n🧪 Starting Rapid Typing Test');

    await runner.startServer();
    await runner.setupBrowser();
    await runner.navigateToApp();
    await runner.waitForTerminalInitialization();

    await runner.focusTerminal();

    // Test rapid typing of individual characters
    const rapidText = 'quick123';
    console.log(`⚡ Typing rapidly: "${rapidText}"`);

    for (const char of rapidText) {
      await runner.typeInput(char);
      await runner.page!.waitForTimeout(50); // Very fast typing
    }

    await runner.page!.waitForTimeout(1000);

    const check = await runner.checkInputVisibility(rapidText);

    console.log(`Rapid typing visibility: ${check.visible}`);
    console.log(`Characters missing: ${rapidText.length - (check.content.match(/[a-z0-9]/g) || []).length}`);

    expect(check.visible).toBe(true); // Expected to fail
  });

  test('Special Characters and Commands Test (SHOULD FAIL)', async () => {
    console.log('\n🧪 Starting Special Characters Test');

    await runner.startServer();
    await runner.setupBrowser();
    await runner.navigateToApp();
    await runner.waitForTerminalInitialization();

    await runner.focusTerminal();

    // Test various special characters
    const specialTests = [
      'ls -la',
      'echo $HOME',
      'pwd && echo "done"',
      'cat > test.txt',
      'grep -r "pattern" .',
      'find . -name "*.js"'
    ];

    for (const command of specialTests) {
      console.log(`Testing command: "${command}"`);

      await runner.typeInput(command, { slow: true, waitBetween: 100 });
      await runner.page!.waitForTimeout(1000);

      const check = await runner.checkInputVisibility(command);
      console.log(`Command "${command}" visible: ${check.visible}`);

      // Clear line for next test
      await runner.pressKey('Control+C');
      await runner.page!.waitForTimeout(500);

      expect(check.visible).toBe(true); // Expected to fail for some/all
    }
  });

  test('Multi-Terminal Switching Test (SHOULD FAIL)', async () => {
    console.log('\n🧪 Starting Multi-Terminal Switching Test');

    await runner.startServer();
    await runner.setupBrowser();
    await runner.navigateToApp();
    await runner.waitForTerminalInitialization();

    // This test would need terminal switching functionality
    // For now, test that input works after page refresh (simulating switch)

    await runner.focusTerminal();
    await runner.typeInput('echo "Terminal 1"');

    const beforeRefresh = await runner.checkInputVisibility('Terminal 1');
    console.log(`Before refresh: ${beforeRefresh.visible}`);

    // Simulate terminal switch by refreshing
    await runner.page!.reload({ waitUntil: 'networkidle' });
    await runner.waitForTerminalInitialization();

    await runner.focusTerminal();
    await runner.typeInput('echo "Terminal 2"');

    const afterRefresh = await runner.checkInputVisibility('Terminal 2');
    console.log(`After refresh: ${afterRefresh.visible}`);

    expect(beforeRefresh.visible && afterRefresh.visible).toBe(true); // Expected to fail
  });

  test('Copy-Paste Test (SHOULD FAIL)', async () => {
    console.log('\n🧪 Starting Copy-Paste Test');

    await runner.startServer();
    await runner.setupBrowser();
    await runner.navigateToApp();
    await runner.waitForTerminalInitialization();

    await runner.focusTerminal();

    // Test pasting text
    const pasteText = 'echo "This is pasted text with special chars: @#$%^&*()[]{}|;:,.<>?"';

    // Simulate paste operation
    await runner.page!.evaluate((text) => {
      navigator.clipboard.writeText(text);
    }, pasteText);

    await runner.page!.keyboard.press('Control+V');
    await runner.page!.waitForTimeout(2000);

    const pasteCheck = await runner.checkInputVisibility(pasteText);

    console.log(`Paste operation visible: ${pasteCheck.visible}`);
    console.log(`Paste content preview: ${pasteCheck.content.substring(0, 200)}`);

    expect(pasteCheck.visible).toBe(true); // Expected to fail
  });
});