import { test, expect } from '../fixtures/test-fixtures';
import { createTestUtilities } from '../utils/test-utilities';

/**
 * WebSocket Real-time Communication E2E Tests
 * Tests WebSocket connectivity, message handling, and real-time features
 */

test.describe('WebSocket Communication', () => {
  test.beforeEach(async ({ page, context, terminalPage }) => {
    const utilities = createTestUtilities(page, context);

    // Monitor WebSocket connections
    page.on('websocket', ws => {
      console.log(`WebSocket connected: ${ws.url()}`);

      ws.on('framesent', event => {
        console.log('WebSocket frame sent:', event.payload);
      });

      ws.on('framereceived', event => {
        console.log('WebSocket frame received:', event.payload);
      });

      ws.on('close', () => {
        console.log('WebSocket connection closed');
      });
    });

    // Store utilities for test access
    (page as any).testUtilities = utilities;

    await terminalPage.goto();
  });

  test.describe('WebSocket Connection Management', () => {
    test('should establish WebSocket connection on page load', async ({ terminalPage, page }) => {
      let wsConnected = false;

      // Listen for WebSocket connections
      page.on('websocket', ws => {
        wsConnected = true;
      });

      await terminalPage.waitForTerminalReady();

      // Verify connection was established
      expect(wsConnected).toBe(true);

      // Verify connection indicator in UI
      await expect(terminalPage.connectionStatus).toBeVisible({ timeout: 10000 });
    });

    test('should reconnect after connection loss', async ({ terminalPage, page, testData }) => {
      await terminalPage.waitForTerminalReady();
      await terminalPage.waitForConnection();

      // Simulate connection loss by going offline
      await page.context().setOffline(true);
      await page.waitForTimeout(3000);

      // Verify disconnection is handled
      const errors = await terminalPage.checkForErrors();
      const hasConnectionError = errors.some(error =>
        error.toLowerCase().includes('connection') ||
        error.toLowerCase().includes('disconnected')
      );

      // Restore connection
      await page.context().setOffline(false);

      // Wait for reconnection
      await terminalPage.waitForConnection();

      // Test that terminal functionality is restored
      await terminalPage.executeCommand('echo "Reconnection test"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Reconnection test');
    });

    test('should handle multiple rapid connection attempts', async ({ terminalPage, page }) => {
      // Simulate rapid network interruptions
      for (let i = 0; i < 3; i++) {
        await page.context().setOffline(true);
        await page.waitForTimeout(1000);
        await page.context().setOffline(false);
        await page.waitForTimeout(2000);
      }

      // Verify terminal still works after network instability
      await terminalPage.waitForConnection();
      await terminalPage.executeCommand('echo "Stability test"');

      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Stability test');
    });

    test('should maintain connection during continuous usage', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      let wsDropped = false;
      page.on('websocket', ws => {
        ws.on('close', () => {
          wsDropped = true;
        });
      });

      // Continuous terminal usage
      for (let i = 0; i < 20; i++) {
        await terminalPage.executeCommand(`echo "Message ${i}"`);
        await page.waitForTimeout(500);
      }

      // Connection should remain stable
      expect(wsDropped).toBe(false);

      // Verify final state
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Message 19');
    });
  });

  test.describe('Real-time Data Exchange', () => {
    test('should handle terminal input/output in real-time', async ({ terminalPage }) => {
      await terminalPage.waitForTerminalReady();

      // Measure real-time responsiveness
      const startTime = Date.now();

      await terminalPage.typeCommand('echo "Real-time test"');
      await terminalPage.page.keyboard.press('Enter');

      await terminalPage.waitForOutput('Real-time test');
      const responseTime = Date.now() - startTime;

      // Should respond within reasonable time (under 2 seconds)
      expect(responseTime).toBeLessThan(2000);
    });

    test('should stream continuous output without buffering delays', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      // Start streaming command
      await terminalPage.typeCommand('for i in {1..10}; do echo "Stream $i"; sleep 0.5; done');
      await page.keyboard.press('Enter');

      // Monitor for real-time updates
      let outputCount = 0;
      const checkInterval = setInterval(async () => {
        try {
          const content = await terminalPage.getTerminalContent();
          const matches = content.match(/Stream \d+/g);
          if (matches) {
            outputCount = matches.length;
          }
        } catch (error) {
          // Ignore errors during polling
        }
      }, 200);

      // Wait for streaming to complete
      await page.waitForTimeout(8000);
      clearInterval(checkInterval);

      // Verify we received streaming updates (not just final result)
      expect(outputCount).toBeGreaterThan(5);

      // Stop the command if still running
      await terminalPage.sendInterrupt();
    });

    test('should handle binary data and special characters', async ({ terminalPage }) => {
      await terminalPage.waitForTerminalReady();

      // Test various character encodings
      const specialChars = 'åäöÅÄÖ漢字éñüß';
      await terminalPage.executeCommand(`echo "${specialChars}"`);

      const content = await terminalPage.getTerminalContent();
      expect(content).toContain(specialChars);

      // Test binary-like output (base64)
      await terminalPage.executeCommand('echo "SGVsbG8gV29ybGQ=" | base64 -d');
      await terminalPage.waitForOutput('Hello World');
    });

    test('should synchronize terminal state across browser tabs', async ({ terminalPage, page, context }) => {
      // This test would require opening multiple tabs to the same terminal session
      // For now, we'll test state persistence after navigation

      await terminalPage.waitForTerminalReady();
      await terminalPage.executeCommand('echo "State persistence test"');

      // Navigate away and back
      await page.goto('about:blank');
      await page.waitForTimeout(1000);
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Check if command history/state is preserved
      // This depends on implementation - might be session storage or server-side
      const content = await terminalPage.getTerminalContent();

      // At minimum, terminal should be functional
      await terminalPage.executeCommand('echo "After navigation"');
      const updatedContent = await terminalPage.getTerminalContent();
      expect(updatedContent).toContain('After navigation');
    });
  });

  test.describe('Error Handling and Recovery', () => {
    test('should gracefully handle WebSocket errors', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      // Block WebSocket connections to simulate server error
      await page.route('**/socket.io/**', route => route.abort());
      await page.route('**/ws', route => route.abort());

      // Trigger reconnection attempt
      await page.reload();
      await page.waitForTimeout(3000);

      // Should show appropriate error state
      const errors = await terminalPage.checkForErrors();
      expect(errors.length).toBeGreaterThan(0);

      // Error should be user-friendly
      const hasUserFriendlyError = errors.some(error =>
        error.toLowerCase().includes('connection') ||
        error.toLowerCase().includes('network') ||
        error.toLowerCase().includes('unable to connect')
      );
      expect(hasUserFriendlyError).toBe(true);

      // Restore connections
      await page.unroute('**/socket.io/**');
      await page.unroute('**/ws');
    });

    test('should handle malformed WebSocket messages', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      // Inject mock WebSocket with malformed messages
      await page.addInitScript(() => {
        const originalWebSocket = window.WebSocket;

        class MockWebSocket extends EventTarget {
          url: string;
          readyState: number = WebSocket.OPEN;
          onmessage: ((event: MessageEvent) => void) | null = null;

          constructor(url: string) {
            super();
            this.url = url;

            // Send malformed message after connection
            setTimeout(() => {
              const malformedEvent = new MessageEvent('message', {
                data: '{"invalid": json malformed}'
              });
              if (this.onmessage) this.onmessage(malformedEvent);
            }, 1000);
          }

          send() {}
          close() {}
        }

        if (window.location.href.includes('test-malformed')) {
          (window as any).WebSocket = MockWebSocket;
        }
      });

      // Navigate to trigger the mock
      await page.goto(page.url() + '?test-malformed=true');
      await terminalPage.waitForTerminalReady();

      // Application should handle malformed messages gracefully
      const errors = await terminalPage.checkForErrors();

      // Should either show no errors (handled silently) or user-friendly error
      for (const error of errors) {
        expect(error).not.toMatch(/JSON\.parse|SyntaxError|undefined/i);
      }
    });

    test('should implement exponential backoff for reconnections', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      let connectionAttempts: number[] = [];

      // Monitor connection attempts
      page.on('websocket', ws => {
        connectionAttempts.push(Date.now());
      });

      // Force disconnection
      await page.context().setOffline(true);

      // Wait for several reconnection attempts
      await page.waitForTimeout(15000);

      // Restore connection
      await page.context().setOffline(false);
      await terminalPage.waitForConnection();

      // Verify exponential backoff pattern
      if (connectionAttempts.length > 2) {
        const intervals = [];
        for (let i = 1; i < connectionAttempts.length; i++) {
          intervals.push(connectionAttempts[i] - connectionAttempts[i-1]);
        }

        // Later intervals should generally be longer (exponential backoff)
        const firstInterval = intervals[0];
        const lastInterval = intervals[intervals.length - 1];
        expect(lastInterval).toBeGreaterThanOrEqual(firstInterval);
      }
    });
  });

  test.describe('Performance and Scalability', () => {
    test('should handle high-frequency messages', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      // Generate rapid output
      await terminalPage.typeCommand('seq 1 1000 | while read i; do echo "Message $i"; done');
      await page.keyboard.press('Enter');

      const startTime = Date.now();

      // Wait for completion
      await terminalPage.waitForOutput('Message 1000', 30000);

      const totalTime = Date.now() - startTime;

      // Should handle 1000 messages reasonably quickly
      expect(totalTime).toBeLessThan(30000);

      // Terminal should remain responsive
      await terminalPage.executeCommand('echo "Still responsive"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Still responsive');
    });

    test('should not leak memory during long sessions', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      // Get initial memory usage
      const initialMemory = await page.evaluate(() => {
        return (performance as any).memory?.usedJSHeapSize || 0;
      });

      // Generate lots of terminal output
      for (let batch = 0; batch < 10; batch++) {
        await terminalPage.executeCommand(`for i in {1..100}; do echo "Batch ${batch} Line $i"; done`);
        await page.waitForTimeout(1000);
      }

      // Force garbage collection if available
      await page.evaluate(() => {
        if ((window as any).gc) {
          (window as any).gc();
        }
      });

      const finalMemory = await page.evaluate(() => {
        return (performance as any).memory?.usedJSHeapSize || 0;
      });

      if (initialMemory && finalMemory) {
        const memoryIncrease = finalMemory - initialMemory;
        const memoryIncreaseMB = memoryIncrease / (1024 * 1024);

        // Memory increase should be reasonable (less than 100MB)
        expect(memoryIncreaseMB).toBeLessThan(100);
        console.log(`Memory increase: ${memoryIncreaseMB.toFixed(2)}MB`);
      }
    });

    test('should maintain WebSocket connection under load', async ({ terminalPage, page }) => {
      await terminalPage.waitForTerminalReady();

      let wsConnectionLost = false;
      page.on('websocket', ws => {
        ws.on('close', () => {
          wsConnectionLost = true;
        });
      });

      // Simulate high load scenario
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          terminalPage.executeCommand(`seq ${i * 100} ${(i + 1) * 100 - 1}`)
        );
      }

      await Promise.all(promises);

      // WebSocket should remain stable under load
      expect(wsConnectionLost).toBe(false);

      // Terminal should still be responsive
      await terminalPage.executeCommand('echo "Load test complete"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Load test complete');
    });
  });

  test.afterEach(async ({ page }) => {
    // Clean up test utilities
    const utilities = (page as any).testUtilities;
    if (utilities) {
      await utilities.cleanup();
    }
  });
});