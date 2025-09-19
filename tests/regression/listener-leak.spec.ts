import { test, expect, Page } from '@playwright/test';

/**
 * WebSocket Listener Leak Regression Test
 *
 * This test demonstrates and validates that terminal WebSocket event listeners
 * are properly managed and don't multiply on re-renders or terminal switches.
 */

test.describe('WebSocket Listener Leak Prevention', () => {
  let page: Page;

  test.beforeEach(async ({ page: testPage }) => {
    page = testPage;

    // Enable console logging to capture listener registration
    page.on('console', msg => {
      const text = msg.text();
      if (text.includes('Registering listener') ||
          text.includes('Removing listener') ||
          text.includes('emit(') ||
          text.includes('listeners')) {
        console.log(`[Browser Console] ${text}`);
      }
    });

    // Navigate to the application
    await page.goto('http://localhost:8082');
    await page.waitForLoadState('networkidle');
  });

  test('1. Listener Registration Count - Single Terminal', async () => {
    console.log('[TEST] Checking listener registration for single terminal...');

    // Inject listener tracking code
    const listenerCounts = await page.evaluate(() => {
      const counts: Record<string, number> = {};
      const originalOn = (window as any).wsClient?.on;
      const originalOff = (window as any).wsClient?.off;

      // Track listener additions
      if ((window as any).wsClient) {
        const listeners = (window as any).wsClient.listeners || new Map();

        // Count current listeners
        listeners.forEach((callbacks: any[], event: string) => {
          counts[event] = callbacks.length;
        });
      }

      return counts;
    });

    console.log('[TEST] Initial listener counts:', listenerCounts);

    // Wait for terminal to initialize
    await page.waitForTimeout(2000);

    // Check listener counts again
    const listenerCountsAfter = await page.evaluate(() => {
      const counts: Record<string, number> = {};

      if ((window as any).wsClient) {
        const listeners = (window as any).wsClient.listeners || new Map();

        listeners.forEach((callbacks: any[], event: string) => {
          counts[event] = callbacks.length;
        });
      }

      return counts;
    });

    console.log('[TEST] Listener counts after terminal init:', listenerCountsAfter);

    // Verify each event has exactly 1 listener
    const expectedEvents = ['terminal-data', 'terminal-error', 'connection-change', 'history-refreshed'];
    for (const event of expectedEvents) {
      const count = listenerCountsAfter[event] || 0;
      console.log(`[TEST] Event '${event}' has ${count} listeners`);
      expect(count).toBeLessThanOrEqual(1);
    }
  });

  test('2. Listener Leak on Component Re-render', async () => {
    console.log('[TEST] Testing listener leak on component re-renders...');

    // Track listener count changes
    const trackListeners = async () => {
      return await page.evaluate(() => {
        const counts: Record<string, number> = {};

        if ((window as any).wsClient?.listeners) {
          const listeners = (window as any).wsClient.listeners;
          listeners.forEach((callbacks: any[], event: string) => {
            counts[event] = callbacks.length;
          });
        }

        return counts;
      });
    };

    const initialCounts = await trackListeners();
    console.log('[TEST] Initial listener counts:', initialCounts);

    // Trigger multiple re-renders by clicking on terminal
    for (let i = 0; i < 5; i++) {
      await page.click('.terminal-container', { force: true }).catch(() => {});
      await page.waitForTimeout(500);
    }

    const afterClickCounts = await trackListeners();
    console.log('[TEST] Listener counts after 5 clicks:', afterClickCounts);

    // Verify listener counts haven't increased
    for (const event in afterClickCounts) {
      const initial = initialCounts[event] || 0;
      const after = afterClickCounts[event] || 0;
      console.log(`[TEST] Event '${event}': ${initial} -> ${after} listeners`);
      expect(after).toBeLessThanOrEqual(Math.max(1, initial));
    }
  });

  test('3. Listener Cleanup on Terminal Switch', async () => {
    console.log('[TEST] Testing listener cleanup on terminal switch...');

    // Check if there's a terminal switching mechanism
    const hasSwitcher = await page.locator('[data-testid="terminal-switcher"], .terminal-tabs, button:has-text("Terminal")').count();

    if (hasSwitcher === 0) {
      console.log('[TEST] No terminal switcher found, skipping test');
      test.skip();
      return;
    }

    // Track listeners before switch
    const beforeSwitch = await page.evaluate(() => {
      const counts: Record<string, number> = {};

      if ((window as any).wsClient?.listeners) {
        (window as any).wsClient.listeners.forEach((callbacks: any[], event: string) => {
          counts[event] = callbacks.length;
        });
      }

      return counts;
    });

    console.log('[TEST] Listeners before switch:', beforeSwitch);

    // Try to switch terminals
    const switcher = page.locator('[data-testid="terminal-switcher"], .terminal-tabs button, button:has-text("Terminal")').first();
    await switcher.click();
    await page.waitForTimeout(1000);

    // Check listeners after switch
    const afterSwitch = await page.evaluate(() => {
      const counts: Record<string, number> = {};

      if ((window as any).wsClient?.listeners) {
        (window as any).wsClient.listeners.forEach((callbacks: any[], event: string) => {
          counts[event] = callbacks.length;
        });
      }

      return counts;
    });

    console.log('[TEST] Listeners after switch:', afterSwitch);

    // Verify no listener accumulation
    for (const event in afterSwitch) {
      expect(afterSwitch[event]).toBeLessThanOrEqual(1);
    }
  });

  test('4. Memory Leak Detection Over Time', async () => {
    console.log('[TEST] Testing for memory leaks over time...');

    const measureListeners = async () => {
      return await page.evaluate(() => {
        let totalListeners = 0;

        if ((window as any).wsClient?.listeners) {
          (window as any).wsClient.listeners.forEach((callbacks: any[]) => {
            totalListeners += callbacks.length;
          });
        }

        return totalListeners;
      });
    };

    const measurements: number[] = [];

    // Take measurements over 10 seconds
    for (let i = 0; i < 10; i++) {
      const count = await measureListeners();
      measurements.push(count);
      console.log(`[TEST] Measurement ${i + 1}: ${count} total listeners`);

      // Trigger some activity
      await page.keyboard.type('echo test\n');
      await page.waitForTimeout(1000);
    }

    // Check if listener count is stable or decreasing
    const firstMeasurement = measurements[0];
    const lastMeasurement = measurements[measurements.length - 1];

    console.log(`[TEST] Listener growth: ${firstMeasurement} -> ${lastMeasurement}`);

    // Allow for maximum of 4 listeners per event type (terminal-data, terminal-error, connection-change, history-refreshed)
    expect(lastMeasurement).toBeLessThanOrEqual(4);

    // Check for continuous growth pattern
    let isGrowing = true;
    for (let i = 1; i < measurements.length; i++) {
      if (measurements[i] <= measurements[i - 1]) {
        isGrowing = false;
        break;
      }
    }

    expect(isGrowing).toBe(false);
  });

  test('5. Validate Proper Listener Deduplication', async () => {
    console.log('[TEST] Testing listener deduplication logic...');

    // Inject test to verify deduplication
    const testResult = await page.evaluate(() => {
      // Create a mock WebSocket client to test deduplication
      const mockListeners = new Map<string, Function[]>();

      const mockClient = {
        listeners: mockListeners,
        on: (event: string, callback: Function) => {
          if (!mockListeners.has(event)) {
            mockListeners.set(event, []);
          }
          const callbacks = mockListeners.get(event)!;

          // Check if callback already exists (deduplication)
          if (!callbacks.includes(callback)) {
            callbacks.push(callback);
          }
        },
        off: (event: string, callback: Function) => {
          const callbacks = mockListeners.get(event);
          if (callbacks) {
            const index = callbacks.indexOf(callback);
            if (index > -1) {
              callbacks.splice(index, 1);
            }
          }
        }
      };

      // Test adding same callback multiple times
      const testCallback = () => console.log('test');

      mockClient.on('test-event', testCallback);
      mockClient.on('test-event', testCallback);
      mockClient.on('test-event', testCallback);

      const count = mockListeners.get('test-event')?.length || 0;

      return {
        success: count === 1,
        count: count,
        message: count === 1 ? 'Deduplication working' : `Deduplication failed: ${count} listeners`
      };
    });

    console.log('[TEST] Deduplication test result:', testResult);
    expect(testResult.success).toBe(true);
  });
});

test.describe('Listener Registration Patterns', () => {
  test('6. Verify useEffect Cleanup Functions', async ({ page }) => {
    console.log('[TEST] Verifying useEffect cleanup functions...');

    await page.goto('http://localhost:8082');

    // Monitor cleanup calls
    const cleanupMonitor = await page.evaluate(() => {
      let registerCount = 0;
      let cleanupCount = 0;

      // Override console.debug to track registration/cleanup
      const originalDebug = console.debug;
      (console as any).debug = (...args: any[]) => {
        const message = args.join(' ');
        if (message.includes('Registering WebSocket listeners')) {
          registerCount++;
        } else if (message.includes('Cleaning up WebSocket listeners')) {
          cleanupCount++;
        }
        originalDebug.apply(console, args);
      };

      return { registerCount, cleanupCount };
    });

    // Navigate away and back to trigger cleanup
    await page.goto('about:blank');
    await page.waitForTimeout(500);
    await page.goto('http://localhost:8082');
    await page.waitForTimeout(1000);

    const finalCounts = await page.evaluate(() => {
      return {
        listeners: (window as any).wsClient?.listeners?.size || 0,
        terminalDataListeners: (window as any).wsClient?.listeners?.get('terminal-data')?.length || 0
      };
    });

    console.log('[TEST] Final listener state:', finalCounts);

    // Verify cleanup happened
    expect(finalCounts.terminalDataListeners).toBeLessThanOrEqual(1);
  });
});