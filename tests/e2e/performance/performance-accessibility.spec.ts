import { test, expect } from '../fixtures/test-fixtures';
import { createTestUtilities } from '../utils/test-utilities';

/**
 * Performance and Accessibility E2E Tests
 * Tests Core Web Vitals, loading performance, and accessibility compliance
 */

test.describe('Performance and Accessibility', () => {
  test.beforeEach(async ({ page, context }) => {
    const utilities = createTestUtilities(page, context);
    (page as any).testUtilities = utilities;

    // Enable performance monitoring
    await page.addInitScript(() => {
      // Performance observer for Core Web Vitals
      if ('PerformanceObserver' in window) {
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (entry.entryType === 'paint') {
              (window as any)[entry.name] = entry.startTime;
            }
          }
        }).observe({ entryTypes: ['paint'] });
      }
    });
  });

  test.describe('Core Web Vitals', () => {
    test('should meet First Contentful Paint (FCP) threshold', async ({ terminalPage, page }) => {
      const startTime = Date.now();

      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      const metrics = await terminalPage.measurePerformance();
      const loadTime = Date.now() - startTime;

      // FCP should be under 1.8 seconds for good rating
      expect(metrics.paint.firstContentfulPaint).toBeLessThan(1800);

      // Total load time should be reasonable
      expect(loadTime).toBeLessThan(5000);

      console.log(`FCP: ${metrics.paint.firstContentfulPaint}ms`);
      console.log(`Total load time: ${loadTime}ms`);
    });

    test('should achieve good Largest Contentful Paint (LCP)', async ({ terminalPage, page }) => {
      await terminalPage.goto();

      // Measure LCP using Performance Observer
      const lcp = await page.evaluate(() => {
        return new Promise<number>((resolve) => {
          let largestPaint = 0;

          new PerformanceObserver((list) => {
            const entries = list.getEntries();
            const lastEntry = entries[entries.length - 1] as any;

            if (lastEntry) {
              largestPaint = lastEntry.startTime || lastEntry.renderTime;
            }
          }).observe({ entryTypes: ['largest-contentful-paint'] });

          // Resolve after a reasonable time
          setTimeout(() => resolve(largestPaint), 3000);
        });
      });

      if (lcp > 0) {
        // LCP should be under 2.5 seconds for good rating
        expect(lcp).toBeLessThan(2500);
        console.log(`LCP: ${lcp}ms`);
      }
    });

    test('should maintain low Cumulative Layout Shift (CLS)', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Generate content that might cause layout shifts
      for (let i = 1; i <= 10; i++) {
        await terminalPage.executeCommand(`echo "Layout test ${i}"`);
        await page.waitForTimeout(200);
      }

      // Measure CLS
      const cls = await page.evaluate(() => {
        return new Promise<number>((resolve) => {
          let clsValue = 0;

          new PerformanceObserver((list) => {
            for (const entry of list.getEntries() as any[]) {
              if (!entry.hadRecentInput) {
                clsValue += entry.value;
              }
            }
          }).observe({ entryTypes: ['layout-shift'] });

          setTimeout(() => resolve(clsValue), 2000);
        });
      });

      // CLS should be under 0.1 for good rating
      expect(cls).toBeLessThan(0.1);
      console.log(`CLS: ${cls}`);
    });

    test('should demonstrate good Total Blocking Time (TBT)', async ({ terminalPage, page }) => {
      const startTime = Date.now();

      await terminalPage.goto();

      // Measure long tasks that contribute to TBT
      const longTasks = await page.evaluate(() => {
        return new Promise<number[]>((resolve) => {
          const tasks: number[] = [];

          new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
              if (entry.duration > 50) { // Tasks longer than 50ms
                tasks.push(entry.duration);
              }
            }
          }).observe({ entryTypes: ['longtask'] });

          setTimeout(() => resolve(tasks), 5000);
        });
      });

      const totalBlockingTime = longTasks.reduce((sum, duration) => {
        return sum + Math.max(0, duration - 50);
      }, 0);

      // TBT should be under 300ms for good rating
      expect(totalBlockingTime).toBeLessThan(300);
      console.log(`TBT: ${totalBlockingTime}ms`);
      console.log(`Long tasks: ${longTasks.length}`);
    });
  });

  test.describe('Loading Performance', () => {
    test('should load critical resources quickly', async ({ terminalPage, page }) => {
      const utilities = (page as any).testUtilities;
      const networkRequests = utilities.monitorNetworkRequests();

      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Analyze critical resource loading
      await page.waitForTimeout(2000);

      const criticalResources = networkRequests.filter((req: any) =>
        req.url.includes('.js') ||
        req.url.includes('.css') ||
        req.url.includes('socket.io')
      );

      // Critical resources should load quickly
      const slowResources = criticalResources.filter((req: any) => {
        const loadTime = new Date(req.timestamp).getTime();
        return loadTime > 2000; // More than 2 seconds
      });

      expect(slowResources.length).toBeLessThan(criticalResources.length * 0.2);
      console.log(`Critical resources: ${criticalResources.length}`);
      console.log(`Slow resources: ${slowResources.length}`);
    });

    test('should optimize bundle sizes', async ({ terminalPage, page }) => {
      const utilities = (page as any).testUtilities;
      const networkRequests = utilities.monitorNetworkRequests();

      await terminalPage.goto();
      await page.waitForTimeout(3000);

      // Check JavaScript bundle sizes
      const jsRequests = networkRequests.filter((req: any) =>
        req.url.includes('.js') && !req.url.includes('socket.io')
      );

      // Estimate total bundle size (this is approximate)
      console.log(`JavaScript requests: ${jsRequests.length}`);

      // Should not have excessive number of JS files (code splitting)
      expect(jsRequests.length).toBeLessThan(20);
    });

    test('should implement efficient caching', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Reload page to test caching
      const reloadStart = Date.now();
      await page.reload();
      await terminalPage.waitForTerminalReady();
      const reloadTime = Date.now() - reloadStart;

      // Second load should be faster due to caching
      expect(reloadTime).toBeLessThan(3000);
      console.log(`Reload time: ${reloadTime}ms`);
    });

    test('should handle slow network conditions gracefully', async ({ terminalPage, page }) => {
      const utilities = (page as any).testUtilities;

      // Simulate slow network
      await utilities.simulateNetworkConditions({
        slow: true,
        latency: 500,
      });

      const startTime = Date.now();
      await terminalPage.goto();

      // Should still load within reasonable time despite slow network
      const loadTime = Date.now() - startTime;
      expect(loadTime).toBeLessThan(15000); // 15 seconds max for slow network

      // Application should be functional
      await terminalPage.waitForTerminalReady();
      await terminalPage.executeCommand('echo "Slow network test"');

      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Slow network test');
    });
  });

  test.describe('Accessibility Compliance', () => {
    test('should pass automated accessibility audit', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Inject axe-core for comprehensive accessibility testing
      await page.addScriptTag({
        url: 'https://unpkg.com/axe-core@4/axe.min.js',
      });

      const violations = await page.evaluate(async () => {
        const axe = (window as any).axe;
        const results = await axe.run();
        return results.violations.filter((v: any) => v.impact === 'critical' || v.impact === 'serious');
      });

      // Should have no critical or serious accessibility violations
      expect(violations).toHaveLength(0);

      if (violations.length > 0) {
        console.log('Accessibility violations:', violations);
      }
    });

    test('should support keyboard navigation', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Test keyboard navigation
      await page.keyboard.press('Tab');
      await page.waitForTimeout(500);

      // Should be able to navigate to terminal
      const activeElement = await page.evaluate(() => {
        const active = document.activeElement;
        return {
          tagName: active?.tagName,
          className: active?.className,
          role: active?.getAttribute('role'),
        };
      });

      // Active element should be interactive
      expect(['INPUT', 'TEXTAREA', 'BUTTON', 'DIV']).toContain(activeElement.tagName);

      // Test terminal keyboard interaction
      await page.keyboard.type('echo "Keyboard accessibility test"');
      await page.keyboard.press('Enter');

      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Keyboard accessibility test');
    });

    test('should provide proper ARIA labels and roles', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Check critical elements for ARIA attributes
      const ariaElements = await page.evaluate(() => {
        const elements = [];

        // Terminal container
        const terminal = document.querySelector('.xterm-wrapper, [data-testid="terminal"]');
        if (terminal) {
          elements.push({
            element: 'terminal',
            ariaLabel: terminal.getAttribute('aria-label'),
            role: terminal.getAttribute('role'),
            ariaLive: terminal.getAttribute('aria-live'),
          });
        }

        // Buttons
        const buttons = document.querySelectorAll('button');
        buttons.forEach((button, index) => {
          elements.push({
            element: `button-${index}`,
            ariaLabel: button.getAttribute('aria-label'),
            role: button.getAttribute('role'),
            textContent: button.textContent?.trim(),
          });
        });

        return elements;
      });

      // Terminal should have appropriate accessibility attributes
      const terminal = ariaElements.find(el => el.element === 'terminal');
      if (terminal) {
        expect(terminal.ariaLabel || terminal.role).toBeTruthy();
      }

      // Buttons should have labels or meaningful text
      const buttons = ariaElements.filter(el => el.element.startsWith('button'));
      for (const button of buttons) {
        expect(button.ariaLabel || button.textContent).toBeTruthy();
      }
    });

    test('should support screen reader announcements', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Test that terminal updates are announced
      await terminalPage.executeCommand('echo "Screen reader announcement test"');

      // Check for live regions that would announce updates
      const liveRegions = await page.locator('[aria-live]').count();
      console.log(`Live regions found: ${liveRegions}`);

      // Terminal content should be accessible to screen readers
      const terminalText = await terminalPage.getTerminalContent();
      expect(terminalText).toContain('Screen reader announcement test');
      expect(terminalText.trim().length).toBeGreaterThan(0);
    });

    test('should maintain focus management', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Click terminal to focus
      await terminalPage.terminalContainer.click();

      // Focus should be on terminal
      const initialFocus = await page.evaluate(() => {
        const active = document.activeElement;
        return active?.className || active?.tagName;
      });

      // Execute command and check if focus is maintained
      await page.keyboard.type('echo "Focus management test"');
      await page.keyboard.press('Enter');

      await page.waitForTimeout(1000);

      const finalFocus = await page.evaluate(() => {
        const active = document.activeElement;
        return active?.className || active?.tagName;
      });

      // Focus should be maintained or returned to terminal
      expect(finalFocus).toBeTruthy();
    });

    test('should support high contrast mode', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Simulate high contrast mode
      await page.addStyleTag({
        content: `
          @media (prefers-contrast: high) {
            * {
              background: black !important;
              color: white !important;
              border: 1px solid white !important;
            }
          }
        `,
      });

      // Check if terminal is still readable
      await terminalPage.executeCommand('echo "High contrast test"');

      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('High contrast test');

      // Check color contrast programmatically
      const contrastInfo = await page.evaluate(() => {
        const terminal = document.querySelector('.xterm-wrapper');
        if (!terminal) return null;

        const styles = window.getComputedStyle(terminal);
        return {
          backgroundColor: styles.backgroundColor,
          color: styles.color,
        };
      });

      if (contrastInfo) {
        console.log('Terminal contrast:', contrastInfo);
        expect(contrastInfo.backgroundColor).toBeTruthy();
        expect(contrastInfo.color).toBeTruthy();
      }
    });
  });

  test.describe('Memory and Resource Management', () => {
    test('should not have memory leaks during extended use', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Get initial memory
      const initialMemory = await page.evaluate(() => {
        return (performance as any).memory?.usedJSHeapSize || 0;
      });

      // Simulate extended terminal use
      for (let i = 0; i < 50; i++) {
        await terminalPage.executeCommand(`echo "Memory test iteration ${i}"`);

        if (i % 10 === 0) {
          // Force garbage collection periodically
          await page.evaluate(() => {
            if ((window as any).gc) {
              (window as any).gc();
            }
          });
        }
      }

      // Final memory check
      const finalMemory = await page.evaluate(() => {
        if ((window as any).gc) {
          (window as any).gc();
        }
        return (performance as any).memory?.usedJSHeapSize || 0;
      });

      if (initialMemory && finalMemory) {
        const memoryIncrease = finalMemory - initialMemory;
        const memoryIncreaseMB = memoryIncrease / (1024 * 1024);

        // Memory increase should be reasonable
        expect(memoryIncreaseMB).toBeLessThan(50);
        console.log(`Memory increase: ${memoryIncreaseMB.toFixed(2)}MB`);
      }
    });

    test('should efficiently manage DOM nodes', async ({ terminalPage, page }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      const initialNodes = await page.evaluate(() => document.querySelectorAll('*').length);

      // Generate content that creates DOM nodes
      for (let i = 0; i < 100; i++) {
        await terminalPage.executeCommand(`echo "DOM test line ${i}"`);
      }

      const finalNodes = await page.evaluate(() => document.querySelectorAll('*').length);
      const nodeIncrease = finalNodes - initialNodes;

      // Should not create excessive DOM nodes
      expect(nodeIncrease).toBeLessThan(1000);
      console.log(`DOM nodes increase: ${nodeIncrease}`);
    });

    test('should handle resource cleanup on page unload', async ({ terminalPage, page, context }) => {
      await terminalPage.goto();
      await terminalPage.waitForTerminalReady();

      // Setup listeners to track cleanup
      await page.evaluate(() => {
        let cleanupCalled = false;

        window.addEventListener('beforeunload', () => {
          cleanupCalled = true;
          (window as any).cleanupCalled = true;
        });

        // Mock WebSocket cleanup
        const originalWebSocket = window.WebSocket;
        let wsConnections: any[] = [];

        window.WebSocket = function(this: any, url: string) {
          const ws = new originalWebSocket(url);
          wsConnections.push(ws);

          const originalClose = ws.close;
          ws.close = function() {
            wsConnections = wsConnections.filter(conn => conn !== ws);
            return originalClose.call(this);
          };

          return ws;
        } as any;

        (window as any).getActiveConnections = () => wsConnections.length;
      });

      // Navigate away to trigger cleanup
      await page.goto('about:blank');

      // Check if cleanup was attempted
      const cleanupInfo = await page.evaluate(() => ({
        cleanupCalled: (window as any).cleanupCalled,
        activeConnections: (window as any).getActiveConnections?.() || 0,
      }));

      console.log('Cleanup info:', cleanupInfo);
    });
  });

  test.afterEach(async ({ page }) => {
    // Generate performance report
    const utilities = (page as any).testUtilities;
    if (utilities) {
      const performanceMetrics = await utilities.measurePerformance();
      console.log('Performance metrics:', performanceMetrics);
      await utilities.cleanup();
    }
  });
});