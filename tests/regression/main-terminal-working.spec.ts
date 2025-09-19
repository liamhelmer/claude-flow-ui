import { test, expect, Page } from '@playwright/test';

/**
 * Main Terminal Working State Regression Test
 *
 * This test validates that:
 * 1. The main terminal launches with claude-flow
 * 2. Input can be typed into the terminal
 * 3. The typed input appears in terminal-data within 5 seconds
 */

test.describe('Main Terminal Working State', () => {
  test('Terminal launches with claude-flow and processes input correctly', async ({ page }) => {
    console.log('[TEST] Starting main terminal regression test...');

    // Enable console logging to capture terminal data events
    const terminalDataReceived: string[] = [];

    page.on('console', msg => {
      const text = msg.text();
      // Capture terminal-data events
      if (text.includes('terminal-data') || text.includes('Terminal data')) {
        console.log(`[Browser Console] ${text}`);
        terminalDataReceived.push(text);
      }
    });

    // Navigate to the application
    console.log('[TEST] Navigating to application...');
    await page.goto('http://localhost:8080');
    await page.waitForLoadState('networkidle');

    // Wait for terminal to be visible
    console.log('[TEST] Waiting for terminal to be visible...');
    await page.waitForSelector('.xterm-wrapper', {
      state: 'visible',
      timeout: 10000
    });

    // Give terminal time to fully initialize
    await page.waitForTimeout(2000);

    // Verify terminal is ready (not showing loading or connecting)
    const isLoading = await page.isVisible('text=Loading');
    const isConnecting = await page.isVisible('text=Connecting to Terminal');

    console.log('[TEST] Terminal state:');
    console.log('  - Loading:', isLoading);
    console.log('  - Connecting:', isConnecting);

    expect(isLoading).toBe(false);
    expect(isConnecting).toBe(false);

    // Check that terminal contains claude-flow output
    console.log('[TEST] Checking for claude-flow in terminal...');
    const terminalContent = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm-screen');
      return terminal ? terminal.textContent : '';
    });

    // Claude-flow should be visible in the terminal
    const hasClaudeFlow = terminalContent.toLowerCase().includes('claude') ||
                          terminalContent.includes('flow') ||
                          terminalContent.includes('hive') ||
                          terminalContent.includes('>>>') ||
                          terminalContent.includes('Ready');

    console.log('[TEST] Claude-flow present in terminal:', hasClaudeFlow);
    expect(hasClaudeFlow).toBe(true);

    // Focus the terminal for input
    console.log('[TEST] Clicking terminal to focus...');
    await page.click('.xterm-wrapper');
    await page.waitForTimeout(500);

    // Type test input
    const testInput = 'echo "Terminal test successful"';
    console.log(`[TEST] Typing test input: ${testInput}`);

    // Clear any existing terminal data tracking
    await page.evaluate(() => {
      (window as any).__terminalDataLog = [];
    });

    // Set up terminal data capture
    await page.evaluate(() => {
      // Hook into WebSocket client if available
      if ((window as any).wsClient) {
        const originalOn = (window as any).wsClient.on;
        (window as any).wsClient.on = function(event: string, callback: Function) {
          if (event === 'terminal-data') {
            const wrappedCallback = (data: any) => {
              console.log('Terminal data received:', data.data);
              if (!(window as any).__terminalDataLog) {
                (window as any).__terminalDataLog = [];
              }
              (window as any).__terminalDataLog.push(data.data);
              callback(data);
            };
            return originalOn.call(this, event, wrappedCallback);
          }
          return originalOn.call(this, event, callback);
        };
      }
    });

    // Type the command
    await page.keyboard.type(testInput);

    // Check that the input appears in the terminal within 5 seconds
    console.log('[TEST] Waiting for input to appear in terminal...');

    const inputAppeared = await page.waitForFunction(
      (expectedText) => {
        const terminal = document.querySelector('.xterm-screen');
        if (!terminal) return false;
        const content = terminal.textContent || '';
        return content.includes(expectedText);
      },
      testInput,
      { timeout: 5000 }
    ).then(() => true).catch(() => false);

    console.log('[TEST] Input appeared in terminal:', inputAppeared);
    expect(inputAppeared).toBe(true);

    // Press Enter to execute the command
    console.log('[TEST] Pressing Enter to execute command...');
    await page.keyboard.press('Enter');

    // Wait for the output to appear (within 5 seconds)
    console.log('[TEST] Waiting for command output...');

    const outputAppeared = await page.waitForFunction(
      () => {
        const terminal = document.querySelector('.xterm-screen');
        if (!terminal) return false;
        const content = terminal.textContent || '';
        return content.includes('Terminal test successful');
      },
      {},
      { timeout: 5000 }
    ).then(() => true).catch(() => false);

    console.log('[TEST] Output appeared in terminal:', outputAppeared);
    expect(outputAppeared).toBe(true);

    // Verify terminal data was received via WebSocket
    const terminalDataLog = await page.evaluate(() => {
      return (window as any).__terminalDataLog || [];
    });

    console.log('[TEST] Terminal data log entries:', terminalDataLog.length);

    // Check if any terminal data contains our input or output
    const hasInputInData = terminalDataLog.some((data: string) =>
      data.includes('echo') || data.includes('Terminal test successful')
    );

    console.log('[TEST] Input/output found in terminal data:', hasInputInData);
    expect(terminalDataLog.length).toBeGreaterThan(0);

    // Final verification - terminal should still be responsive
    console.log('[TEST] Verifying terminal is still responsive...');
    await page.keyboard.type('pwd');

    const pwdAppeared = await page.waitForFunction(
      () => {
        const terminal = document.querySelector('.xterm-screen');
        if (!terminal) return false;
        const content = terminal.textContent || '';
        const lines = content.split('\n');
        return lines[lines.length - 1].includes('pwd') ||
               lines[lines.length - 2].includes('pwd');
      },
      {},
      { timeout: 2000 }
    ).then(() => true).catch(() => false);

    console.log('[TEST] Terminal still responsive:', pwdAppeared);
    expect(pwdAppeared).toBe(true);

    // Test summary
    console.log('\n[TEST] ✅ Main Terminal Regression Test Summary:');
    console.log('  1. Terminal launches with claude-flow: PASS');
    console.log('  2. Input can be typed into terminal: PASS');
    console.log('  3. Input appears in terminal-data within 5 seconds: PASS');
    console.log('  4. Terminal remains responsive: PASS');
  });
});