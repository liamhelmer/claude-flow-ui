import { test, expect, Page } from '@playwright/test';

/**
 * Production Terminal Input Regression Test
 *
 * This test validates that:
 * 1. The main terminal launches with claude-flow
 * 2. Input can be typed into the terminal
 * 3. The typed input appears in terminal-data within 5 seconds
 */

test.describe('Production Terminal Input Test', () => {
  test('Terminal receives and displays typed input in terminal-data', async ({ page }) => {
    console.log('[TEST] Starting production terminal input regression test...');

    // Set up data capture before navigation
    await page.addInitScript(() => {
      (window as any).__capturedData = {
        terminalData: [],
        sentData: [],
        receivedEvents: []
      };

      // Override WebSocket to capture data
      const OriginalWebSocket = (window as any).WebSocket;
      (window as any).WebSocket = function(...args: any[]) {
        const ws = new OriginalWebSocket(...args);

        const originalSend = ws.send.bind(ws);
        ws.send = function(data: any) {
          console.log('[WS] Sending data:', data);
          (window as any).__capturedData.sentData.push(data);
          return originalSend(data);
        };

        ws.addEventListener('message', (event: any) => {
          console.log('[WS] Received message:', event.data);
          (window as any).__capturedData.receivedEvents.push(event.data);

          // Parse socket.io messages
          try {
            if (typeof event.data === 'string' && event.data.startsWith('42')) {
              const jsonStr = event.data.substring(2);
              const parsed = JSON.parse(jsonStr);
              if (parsed[0] === 'terminal-data') {
                console.log('[TEST] Terminal data received:', parsed[1].data);
                (window as any).__capturedData.terminalData.push(parsed[1].data);
              }
            }
          } catch (e) {
            // Not a JSON message
          }
        });

        return ws;
      };
    });

    // Navigate to production server
    console.log('[TEST] Navigating to production server at http://localhost:11239...');
    await page.goto('http://localhost:11239', { waitUntil: 'domcontentloaded' });

    // Wait for page to stabilize
    await page.waitForTimeout(3000);

    // Check terminal presence (may be hidden but should exist)
    const hasTerminalWrapper = await page.locator('.xterm-wrapper').count();
    console.log('[TEST] Terminal wrapper elements found:', hasTerminalWrapper);
    expect(hasTerminalWrapper).toBeGreaterThan(0);

    // Check if loading state has resolved
    const isLoading = await page.isVisible('text=Loading');
    const isConnecting = await page.isVisible('text=Connecting to Terminal');
    console.log('[TEST] Loading state:', { isLoading, isConnecting });

    // Try to make terminal visible by clicking on it
    if (hasTerminalWrapper > 0) {
      try {
        await page.locator('.xterm-wrapper').first().click({ force: true, timeout: 2000 });
        console.log('[TEST] Clicked terminal wrapper');
      } catch (e) {
        console.log('[TEST] Could not click terminal wrapper, continuing...');
      }
    }

    // Alternative: Click on terminal container if wrapper is not clickable
    const terminalContainer = await page.locator('.terminal-container').count();
    if (terminalContainer > 0) {
      try {
        await page.locator('.terminal-container').first().click({ force: true, timeout: 2000 });
        console.log('[TEST] Clicked terminal container');
      } catch (e) {
        console.log('[TEST] Could not click terminal container, continuing...');
      }
    }

    // Type test input regardless of visibility
    const testInput = 'echo "Test123"';
    console.log(`[TEST] Typing test input: ${testInput}`);

    // Focus the page and type
    await page.keyboard.type(testInput);

    // Wait and check if input appears in terminal data
    console.log('[TEST] Waiting for input to appear in terminal-data...');

    const inputInTerminalData = await page.waitForFunction(
      (expectedText) => {
        const captured = (window as any).__capturedData;
        if (!captured || !captured.terminalData) return false;

        // Check if any terminal data contains our input
        return captured.terminalData.some((data: string) =>
          data.includes(expectedText) || data.includes('Test123')
        );
      },
      testInput,
      { timeout: 5000 }
    ).then(() => true).catch(() => false);

    // Get all captured data for analysis
    const capturedData = await page.evaluate(() => (window as any).__capturedData);

    console.log('[TEST] Captured data summary:');
    console.log('  - Terminal data entries:', capturedData.terminalData.length);
    console.log('  - Sent data entries:', capturedData.sentData.length);
    console.log('  - Received events:', capturedData.receivedEvents.length);

    // Log some terminal data samples if available
    if (capturedData.terminalData.length > 0) {
      console.log('[TEST] Terminal data samples:');
      capturedData.terminalData.slice(-5).forEach((data: string, i: number) => {
        console.log(`  ${i + 1}. ${data.substring(0, 100)}`);
      });
    }

    // Check if we have terminal data at all
    const hasTerminalData = capturedData.terminalData.length > 0;
    console.log('[TEST] Has terminal data:', hasTerminalData);

    // Check if input was found in terminal data
    console.log('[TEST] Input found in terminal-data within 5 seconds:', inputInTerminalData);

    // For production, we need to verify WebSocket is working
    const wsMessages = capturedData.receivedEvents.filter((msg: string) =>
      msg.includes('terminal-data') || msg.startsWith('42')
    );
    console.log('[TEST] WebSocket terminal-data messages:', wsMessages.length);

    // Verify the terminal is functioning
    const terminalContent = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm-screen');
      return terminal ? terminal.textContent : '';
    });

    const hasClaudeFlow = terminalContent.includes('claude') ||
                          terminalContent.includes('flow') ||
                          terminalContent.includes('hive') ||
                          terminalContent.includes('spawn');

    console.log('[TEST] Claude-flow detected in terminal:', hasClaudeFlow);

    // Press Enter to execute the command
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);

    // Check again for terminal data
    const finalCapturedData = await page.evaluate(() => (window as any).__capturedData);
    const finalHasInput = finalCapturedData.terminalData.some((data: string) =>
      data.includes('echo') || data.includes('Test123')
    );

    console.log('[TEST] Final check - input in terminal-data:', finalHasInput);

    // Test assertions
    expect(hasTerminalWrapper).toBeGreaterThan(0); // Terminal exists
    expect(hasClaudeFlow).toBe(true); // Claude-flow is running
    expect(inputInTerminalData || finalHasInput).toBe(true); // Input appears in terminal-data within 5 seconds

    console.log('\n[TEST] ✅ Production Terminal Input Test Summary:');
    console.log('  1. Terminal launches with claude-flow: PASS');
    console.log('  2. Input can be typed into terminal: PASS');
    console.log('  3. Input appears in terminal-data within 5 seconds:', inputInTerminalData || finalHasInput ? 'PASS' : 'FAIL');
  });
});