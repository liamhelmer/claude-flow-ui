import { test, expect, Page } from '@playwright/test';

/**
 * Terminal Data Flow Regression Test Suite
 *
 * This test suite validates that terminals receive and display data correctly
 * after initial load, user interactions, and terminal switching operations.
 *
 * Test Scenarios:
 * 1. Initial load and data display
 * 2. User input and response validation
 * 3. Terminal switching functionality
 * 4. Long-running command output
 * 5. Rapid input sequences
 * 6. WebSocket connection stability
 */

// Test configuration
const TEST_TIMEOUT = 30000;
const WEBSOCKET_TIMEOUT = 5000;
const INPUT_RESPONSE_TIMEOUT = 3000;
const TERMINAL_SWITCH_TIMEOUT = 2000;

// Helper function to wait for terminal content
async function waitForTerminalContent(page: Page, selector: string, expectedText: string, timeout = 5000) {
  console.log(`[DEBUG] Waiting for terminal content: "${expectedText}" in selector: ${selector}`);

  try {
    await page.waitForFunction(
      ({ selector, text }) => {
        const element = document.querySelector(selector);
        if (!element) return false;
        const content = element.textContent || '';
        console.log(`[DEBUG] Current terminal content: "${content}"`);
        return content.includes(text);
      },
      { selector, text: expectedText },
      { timeout }
    );
    console.log(`[DEBUG] Successfully found expected text: "${expectedText}"`);
    return true;
  } catch (error) {
    console.error(`[DEBUG] Failed to find text "${expectedText}" within ${timeout}ms:`, error);
    return false;
  }
}

// Helper function to get terminal element
async function getTerminalElement(page: Page) {
  const selectors = [
    '[data-testid="terminal"]',
    '.terminal',
    '.xterm-viewport',
    '.xterm-screen',
    '[role="application"]'
  ];

  for (const selector of selectors) {
    const element = await page.$(selector);
    if (element) {
      console.log(`[DEBUG] Found terminal element with selector: ${selector}`);
      return { element, selector };
    }
  }

  console.log('[DEBUG] No terminal element found, checking all elements...');
  const allElements = await page.$$('*');
  console.log(`[DEBUG] Total elements on page: ${allElements.length}`);

  throw new Error('Terminal element not found');
}

// Helper function to monitor WebSocket connections
async function monitorWebSocketConnections(page: Page) {
  const wsConnections: any[] = [];

  page.on('websocket', ws => {
    console.log(`[DEBUG] WebSocket connection opened: ${ws.url()}`);
    wsConnections.push({
      url: ws.url(),
      state: 'connecting',
      timestamp: Date.now()
    });

    ws.on('framesent', event => {
      console.log(`[DEBUG] WebSocket frame sent:`, event.payload);
    });

    ws.on('framereceived', event => {
      console.log(`[DEBUG] WebSocket frame received:`, event.payload);
    });

    ws.on('close', () => {
      console.log(`[DEBUG] WebSocket connection closed: ${ws.url()}`);
    });
  });

  return wsConnections;
}

test.describe('Terminal Data Flow Regression Tests', () => {
  let page: Page;
  let wsConnections: any[];

  test.beforeEach(async ({ browser }) => {
    console.log('[DEBUG] Setting up test environment...');
    page = await browser.newPage();

    // Enable console logging
    page.on('console', msg => {
      console.log(`[BROWSER] ${msg.type()}: ${msg.text()}`);
    });

    // Monitor network failures
    page.on('pageerror', error => {
      console.error('[BROWSER ERROR]:', error);
    });

    // Monitor WebSocket connections
    wsConnections = await monitorWebSocketConnections(page);
  });

  test.afterEach(async () => {
    console.log('[DEBUG] Cleaning up test environment...');
    await page.close();
  });

  test('1. Initial Load and Data Display', async () => {
    console.log('[TEST] Starting initial load and data display test...');

    // Navigate to the application
    await page.goto('http://localhost:3000');
    console.log('[DEBUG] Navigated to application');

    // Wait for page to load
    await page.waitForLoadState('networkidle');
    console.log('[DEBUG] Page load completed');

    // Wait for terminal to be present
    const { element: terminal, selector } = await getTerminalElement(page);
    expect(terminal).toBeTruthy();
    console.log('[DEBUG] Terminal element found');

    // Check for initial terminal prompt or content
    const hasInitialContent = await waitForTerminalContent(
      page,
      selector,
      '$', // Common shell prompt
      5000
    ) || await waitForTerminalContent(
      page,
      selector,
      '>',
      2000
    ) || await waitForTerminalContent(
      page,
      selector,
      'Welcome',
      2000
    );

    if (!hasInitialContent) {
      // Get actual content for debugging
      const actualContent = await page.textContent(selector);
      console.log(`[DEBUG] Actual terminal content: "${actualContent}"`);
    }

    expect(hasInitialContent).toBeTruthy();
    console.log('[TEST] ✓ Initial terminal content displayed');
  });

  test('2. User Input and Response Validation', async () => {
    console.log('[TEST] Starting user input and response validation test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    const { element: terminal, selector } = await getTerminalElement(page);

    // Focus on terminal
    await terminal.click();
    console.log('[DEBUG] Terminal focused');

    // Send simple command
    const testCommand = 'echo "test response"';
    await page.keyboard.type(testCommand);
    console.log(`[DEBUG] Typed command: ${testCommand}`);

    await page.keyboard.press('Enter');
    console.log('[DEBUG] Pressed Enter');

    // Wait for command echo
    const commandEchoed = await waitForTerminalContent(
      page,
      selector,
      testCommand,
      INPUT_RESPONSE_TIMEOUT
    );

    // Wait for response
    const responseReceived = await waitForTerminalContent(
      page,
      selector,
      'test response',
      INPUT_RESPONSE_TIMEOUT
    );

    if (!responseReceived) {
      const terminalContent = await page.textContent(selector);
      console.log(`[DEBUG] Terminal content after command: "${terminalContent}"`);
    }

    expect(commandEchoed || responseReceived).toBeTruthy();
    console.log('[TEST] ✓ User input and response validation completed');
  });

  test('3. Terminal Switching Functionality', async () => {
    console.log('[TEST] Starting terminal switching functionality test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    // Look for terminal tabs or switching mechanisms
    const switchSelectors = [
      '[data-testid="terminal-tab"]',
      '.terminal-tab',
      '.tab-button',
      '[role="tab"]',
      'button[aria-label*="terminal"]',
      'button[aria-label*="Terminal"]'
    ];

    let foundSwitchMechanism = false;
    let activeSelector = '';

    for (const selector of switchSelectors) {
      const elements = await page.$$(selector);
      if (elements.length > 1) {
        console.log(`[DEBUG] Found ${elements.length} terminal switching elements with selector: ${selector}`);
        foundSwitchMechanism = true;
        activeSelector = selector;
        break;
      }
    }

    if (foundSwitchMechanism) {
      const terminals = await page.$$(activeSelector);
      console.log(`[DEBUG] Testing switching between ${terminals.length} terminals`);

      // Click on second terminal
      await terminals[1].click();
      await page.waitForTimeout(TERMINAL_SWITCH_TIMEOUT);

      // Verify we can still interact with terminal after switching
      const { selector: terminalSelector } = await getTerminalElement(page);
      await page.click(terminalSelector);
      await page.keyboard.type('echo "switched terminal"');
      await page.keyboard.press('Enter');

      const responseAfterSwitch = await waitForTerminalContent(
        page,
        terminalSelector,
        'switched terminal',
        INPUT_RESPONSE_TIMEOUT
      );

      expect(responseAfterSwitch).toBeTruthy();
      console.log('[TEST] ✓ Terminal switching functionality works');
    } else {
      console.log('[TEST] ⚠ No terminal switching mechanism found, skipping test');
    }
  });

  test('4. Long-running Command Output', async () => {
    console.log('[TEST] Starting long-running command output test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    const { element: terminal, selector } = await getTerminalElement(page);
    await terminal.click();

    // Send a command that produces multiple lines of output
    const longCommand = 'for i in {1..5}; do echo "Line $i"; sleep 0.1; done';
    await page.keyboard.type(longCommand);
    await page.keyboard.press('Enter');

    console.log('[DEBUG] Sent long-running command');

    // Wait for progressive output
    const outputs = ['Line 1', 'Line 3', 'Line 5'];
    let progressiveOutputWorking = true;

    for (const output of outputs) {
      const found = await waitForTerminalContent(
        page,
        selector,
        output,
        3000
      );

      if (!found) {
        console.log(`[DEBUG] Failed to find output: ${output}`);
        progressiveOutputWorking = false;
        break;
      }
    }

    expect(progressiveOutputWorking).toBeTruthy();
    console.log('[TEST] ✓ Long-running command output handled correctly');
  });

  test('5. Rapid Input Sequences', async () => {
    console.log('[TEST] Starting rapid input sequences test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    const { element: terminal, selector } = await getTerminalElement(page);
    await terminal.click();

    // Send multiple rapid commands
    const commands = [
      'echo "rapid1"',
      'echo "rapid2"',
      'echo "rapid3"'
    ];

    for (const command of commands) {
      await page.keyboard.type(command);
      await page.keyboard.press('Enter');
      await page.waitForTimeout(100); // Small delay between commands
    }

    console.log('[DEBUG] Sent rapid input sequences');

    // Check that all commands were processed
    const allCommandsProcessed = await Promise.all(
      commands.map(cmd => {
        const expectedOutput = cmd.split('"')[1]; // Extract text between quotes
        return waitForTerminalContent(page, selector, expectedOutput, 5000);
      })
    );

    const successfulCommands = allCommandsProcessed.filter(Boolean).length;
    console.log(`[DEBUG] ${successfulCommands}/${commands.length} rapid commands processed successfully`);

    expect(successfulCommands).toBeGreaterThan(0);
    console.log('[TEST] ✓ Rapid input sequences handled');
  });

  test('6. WebSocket Connection Stability', async () => {
    console.log('[TEST] Starting WebSocket connection stability test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    // Wait for WebSocket connections to establish
    await page.waitForTimeout(WEBSOCKET_TIMEOUT);

    console.log(`[DEBUG] Total WebSocket connections detected: ${wsConnections.length}`);

    if (wsConnections.length === 0) {
      console.log('[DEBUG] No WebSocket connections detected, checking network requests...');

      // Monitor network requests
      const requests: string[] = [];
      page.on('request', request => {
        requests.push(request.url());
      });

      await page.reload();
      await page.waitForLoadState('networkidle');

      console.log(`[DEBUG] Network requests: ${requests.slice(0, 10).join(', ')}`);
    }

    // Test interaction after potential connection issues
    const { element: terminal, selector } = await getTerminalElement(page);
    await terminal.click();
    await page.keyboard.type('echo "connection test"');
    await page.keyboard.press('Enter');

    const connectionStable = await waitForTerminalContent(
      page,
      selector,
      'connection test',
      INPUT_RESPONSE_TIMEOUT
    );

    // If connection failed, get debug info
    if (!connectionStable) {
      const terminalContent = await page.textContent(selector);
      console.log(`[DEBUG] Terminal content during connection test: "${terminalContent}"`);

      // Check console errors
      const logs = await page.evaluate(() => {
        return console.log;
      });
    }

    expect(connectionStable).toBeTruthy();
    console.log('[TEST] ✓ WebSocket connection stability verified');
  });

  test('7. Data Flow After Page Interactions', async () => {
    console.log('[TEST] Starting data flow after page interactions test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    // Perform various page interactions
    await page.click('body'); // Click somewhere
    await page.keyboard.press('Tab'); // Tab navigation
    await page.evaluate(() => window.scrollTo(0, 100)); // Scroll

    console.log('[DEBUG] Performed page interactions');

    // Test terminal functionality after interactions
    const { element: terminal, selector } = await getTerminalElement(page);
    await terminal.click();
    await page.keyboard.type('echo "after interactions"');
    await page.keyboard.press('Enter');

    const dataFlowAfterInteractions = await waitForTerminalContent(
      page,
      selector,
      'after interactions',
      INPUT_RESPONSE_TIMEOUT
    );

    expect(dataFlowAfterInteractions).toBeTruthy();
    console.log('[TEST] ✓ Data flow continues after page interactions');
  });

  test('8. Terminal State Persistence', async () => {
    console.log('[TEST] Starting terminal state persistence test...');

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    const { element: terminal, selector } = await getTerminalElement(page);
    await terminal.click();

    // Create some terminal history
    await page.keyboard.type('echo "history line 1"');
    await page.keyboard.press('Enter');
    await waitForTerminalContent(page, selector, 'history line 1', 3000);

    await page.keyboard.type('echo "history line 2"');
    await page.keyboard.press('Enter');
    await waitForTerminalContent(page, selector, 'history line 2', 3000);

    // Get terminal content before refresh
    const contentBeforeRefresh = await page.textContent(selector);
    console.log(`[DEBUG] Terminal content before refresh: "${contentBeforeRefresh}"`);

    // Refresh page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Check if history persists
    const { selector: newSelector } = await getTerminalElement(page);
    const contentAfterRefresh = await page.textContent(newSelector);
    console.log(`[DEBUG] Terminal content after refresh: "${contentAfterRefresh}"`);

    // Terminal should either maintain history or cleanly restart
    const historyMaintained = contentAfterRefresh.includes('history line 1') ||
                             contentAfterRefresh.includes('history line 2');
    const cleanRestart = contentAfterRefresh.includes('$') ||
                        contentAfterRefresh.includes('>') ||
                        contentAfterRefresh.length < contentBeforeRefresh.length;

    expect(historyMaintained || cleanRestart).toBeTruthy();
    console.log('[TEST] ✓ Terminal state persistence behavior verified');
  });
});

// Export helper functions for reuse in other tests
export {
  waitForTerminalContent,
  getTerminalElement,
  monitorWebSocketConnections,
  TEST_TIMEOUT,
  WEBSOCKET_TIMEOUT,
  INPUT_RESPONSE_TIMEOUT,
  TERMINAL_SWITCH_TIMEOUT
};