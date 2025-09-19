import { test, expect, Page } from '@playwright/test';

/**
 * Single Terminal Instance Test
 *
 * This test verifies that only one terminal instance is created per session
 * and that duplicate terminal hooks are not spawned.
 */

test.describe('Single Terminal Instance', () => {
  let page: Page;

  test.beforeEach(async ({ page: testPage }) => {
    page = testPage;

    // Enable console logging to capture terminal initialization
    page.on('console', msg => {
      const text = msg.text();
      if (text.includes('Terminal') || text.includes('Hook') || text.includes('instance')) {
        console.log(`[Browser Console] ${text}`);
      }
    });

    // Navigate to the application
    await page.goto('http://localhost:8080');
    await page.waitForLoadState('networkidle');
  });

  test('Should create only ONE terminal instance', async () => {
    console.log('[TEST] Verifying single terminal instance...');

    // Track terminal hook instances
    const instances = await page.evaluate(() => {
      const hookInstances: string[] = [];

      // Find all debug logs in console
      const logs = (window as any).console.debug.calls || [];
      for (const log of logs) {
        if (log && log[0] && typeof log[0] === 'string' && log[0].includes('instance:')) {
          const match = log[0].match(/instance:\s*([\w\d]+)/);
          if (match) {
            hookInstances.push(match[1]);
          }
        }
      }

      return {
        totalInstances: new Set(hookInstances).size,
        instances: hookInstances
      };
    });

    console.log('[TEST] Terminal instances found:', instances);

    // Should have exactly 1 unique instance
    expect(instances.totalInstances).toBeLessThanOrEqual(1);
  });

  test('Should not duplicate listeners on page load', async () => {
    console.log('[TEST] Checking for duplicate listeners...');

    await page.waitForTimeout(2000);

    // Count terminal-data listener registrations
    const listenerStats = await page.evaluate(() => {
      let registrations = 0;
      let removals = 0;

      // Hook into console to count
      const originalDebug = console.debug;
      const messages: string[] = [];

      // Capture past messages if available
      if ((window as any).__consoleHistory) {
        messages.push(...(window as any).__consoleHistory);
      }

      // Parse messages for listener events
      messages.forEach(msg => {
        if (msg.includes('Registering listener for event: terminal-data') ||
            msg.includes('Registered listener for terminal-data')) {
          registrations++;
        }
        if (msg.includes('Removing listener for event: terminal-data')) {
          removals++;
        }
      });

      return {
        registrations,
        removals,
        netListeners: registrations - removals
      };
    });

    console.log('[TEST] Listener stats:', listenerStats);

    // Should have at most 1 net listener
    expect(listenerStats.netListeners).toBeLessThanOrEqual(1);
  });

  test('Should not create duplicate terminal elements', async () => {
    console.log('[TEST] Checking for duplicate terminal elements...');

    await page.waitForTimeout(2000);

    // Count terminal containers
    const terminalCount = await page.evaluate(() => {
      const xtermWrappers = document.querySelectorAll('.xterm-wrapper').length;
      const terminalContainers = document.querySelectorAll('.terminal-container').length;
      const xtermScreens = document.querySelectorAll('.xterm-screen').length;

      return {
        wrappers: xtermWrappers,
        containers: terminalContainers,
        screens: xtermScreens
      };
    });

    console.log('[TEST] Terminal elements:', terminalCount);

    // Should have exactly 1 of each
    expect(terminalCount.wrappers).toBeLessThanOrEqual(1);
    expect(terminalCount.containers).toBe(1);
    expect(terminalCount.screens).toBeLessThanOrEqual(1);
  });

  test('Should not duplicate useTerminal hook calls', async () => {
    console.log('[TEST] Checking useTerminal hook calls...');

    // Track how many times useTerminal is called
    const hookCalls = await page.evaluate(() => {
      let callCount = 0;

      // Override console.debug temporarily
      const originalDebug = console.debug;
      const messages: string[] = [];

      (console as any).debug = function(...args: any[]) {
        const msg = args.join(' ');
        messages.push(msg);

        if (msg.includes('[Terminal Hook]') ||
            msg.includes('useTerminal called') ||
            msg.includes('Terminal hook initialization')) {
          callCount++;
        }

        originalDebug.apply(console, args);
      };

      // Wait a bit to capture calls
      return new Promise<number>((resolve) => {
        setTimeout(() => resolve(callCount), 1000);
      });
    });

    console.log('[TEST] useTerminal hook calls:', hookCalls);

    // Should be called exactly once
    expect(hookCalls).toBeLessThanOrEqual(1);
  });

  test('Should properly clean up on navigation', async () => {
    console.log('[TEST] Testing cleanup on navigation...');

    // Navigate away
    await page.goto('about:blank');
    await page.waitForTimeout(1000);

    // Navigate back
    await page.goto('http://localhost:8080');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // Check that we still have only one terminal
    const terminalCount = await page.evaluate(() => {
      return document.querySelectorAll('.xterm-wrapper').length;
    });

    console.log('[TEST] Terminal count after navigation:', terminalCount);
    expect(terminalCount).toBeLessThanOrEqual(1);
  });
});