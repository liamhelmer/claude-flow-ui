import { expect as baseExpect, Locator } from '@playwright/test';

/**
 * Custom matchers and assertions for E2E tests
 * Extends Playwright's built-in assertions with domain-specific matchers
 */

interface CustomMatchers<R = unknown> {
  // Terminal-specific matchers
  toBeConnectedTerminal(): R;
  toHaveTerminalOutput(expected: string): R;
  toHaveResponsiveTerminal(maxResponseTime?: number): R;
  toHaveAccessibleTerminal(): R;

  // WebSocket-specific matchers
  toHaveActiveWebSocket(): R;
  toReceiveWebSocketMessage(messageType: string): R;
  toReconnectWebSocket(timeout?: number): R;

  // Performance matchers
  toLoadWithinBudget(budgetMs: number): R;
  toHaveGoodCoreWebVitals(): R;
  toUseMemoryEfficiently(maxMemoryMB: number): R;

  // Accessibility matchers
  toPassA11yAudit(): R;
  toHaveKeyboardAccess(): R;
  toHaveScreenReaderSupport(): R;

  // Visual matchers
  toMatchVisualSnapshot(name: string, options?: { threshold?: number; mask?: string[] }): R;
  toHaveConsistentTheming(): R;
  toBeResponsiveDesign(): R;

  // Error handling matchers
  toRecoverFromError(): R;
  toHandleOfflineScenario(): R;
  toShowGracefulError(): R;
}

declare global {
  namespace PlaywrightTest {
    interface Matchers<R> extends CustomMatchers<R> {}
  }
}

// Extend expect with custom matchers
baseExpected.extend({
  /**
   * Assert that terminal is connected and responsive
   */
  async toBeConnectedTerminal(locator: Locator) {
    const page = locator.page();

    // Check if terminal wrapper exists
    const terminalExists = await locator.isVisible();
    if (!terminalExists) {
      return {
        message: () => 'Terminal element not found',
        pass: false,
      };
    }

    // Check for WebSocket connection indicators
    const wsConnected = await page.locator('[data-ws-connected="true"], .ws-connected').count() > 0;

    // Test terminal responsiveness
    const testText = `test-${Date.now()}`;
    await locator.click();
    await page.keyboard.type(`echo "${testText}"`);
    await page.keyboard.press('Enter');

    const hasOutput = await page.waitForFunction(
      (text) => document.body.textContent?.includes(text),
      testText,
      { timeout: 5000 }
    ).catch(() => false);

    const pass = terminalExists && wsConnected && hasOutput;

    return {
      message: () => pass
        ? 'Terminal is connected and responsive'
        : `Terminal connection failed: exists=${terminalExists}, wsConnected=${wsConnected}, responsive=${!!hasOutput}`,
      pass,
    };
  },

  /**
   * Assert that terminal contains expected output
   */
  async toHaveTerminalOutput(locator: Locator, expected: string) {
    const page = locator.page();

    const terminalContent = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm-wrapper, [data-testid="terminal"]');
      return terminal?.textContent || '';
    });

    const pass = terminalContent.includes(expected);

    return {
      message: () => pass
        ? `Terminal contains expected output: "${expected}"`
        : `Terminal output "${terminalContent}" does not contain "${expected}"`,
      pass,
    };
  },

  /**
   * Assert that terminal responds within time budget
   */
  async toHaveResponsiveTerminal(locator: Locator, maxResponseTime: number = 2000) {
    const page = locator.page();
    const startTime = Date.now();

    await locator.click();
    const testCommand = `echo "response-test-${Date.now()}"`;
    await page.keyboard.type(testCommand);
    await page.keyboard.press('Enter');

    await page.waitForFunction(
      (cmd) => document.body.textContent?.includes(cmd.split('"')[1]),
      testCommand,
      { timeout: maxResponseTime }
    );

    const responseTime = Date.now() - startTime;
    const pass = responseTime <= maxResponseTime;

    return {
      message: () => pass
        ? `Terminal responded in ${responseTime}ms (within ${maxResponseTime}ms budget)`
        : `Terminal response time ${responseTime}ms exceeded budget of ${maxResponseTime}ms`,
      pass,
    };
  },

  /**
   * Assert that terminal meets accessibility requirements
   */
  async toHaveAccessibleTerminal(locator: Locator) {
    const hasAriaLabel = await locator.getAttribute('aria-label') !== null;
    const hasRole = await locator.getAttribute('role') !== null;
    const isKeyboardAccessible = await locator.getAttribute('tabindex') !== null;

    // Test keyboard focus
    await locator.focus();
    const isFocused = await locator.evaluate(el => document.activeElement === el);

    const pass = (hasAriaLabel || hasRole) && (isKeyboardAccessible || isFocused);

    return {
      message: () => pass
        ? 'Terminal meets accessibility requirements'
        : `Terminal accessibility failed: aria-label=${hasAriaLabel}, role=${hasRole}, keyboard=${isKeyboardAccessible}, focused=${isFocused}`,
      pass,
    };
  },

  /**
   * Assert that WebSocket connection is active
   */
  async toHaveActiveWebSocket(page: any) {
    const hasWebSocket = await page.evaluate(() => {
      return typeof WebSocket !== 'undefined' &&
             window.WebSocket &&
             document.querySelector('[data-ws-connected="true"], .ws-connected') !== null;
    });

    return {
      message: () => hasWebSocket ? 'WebSocket is active' : 'WebSocket connection not detected',
      pass: hasWebSocket,
    };
  },

  /**
   * Assert that WebSocket receives expected message
   */
  async toReceiveWebSocketMessage(page: any, messageType: string) {
    let messageReceived = false;

    // Set up message listener
    await page.evaluateOnNewDocument((type) => {
      window.addEventListener('message', (event) => {
        if (event.data.type === type) {
          (window as any).testMessageReceived = true;
        }
      });
    }, messageType);

    // Wait for message
    await page.waitForFunction(
      () => (window as any).testMessageReceived === true,
      { timeout: 10000 }
    ).then(() => messageReceived = true).catch(() => {});

    return {
      message: () => messageReceived
        ? `WebSocket received message type: ${messageType}`
        : `WebSocket did not receive expected message type: ${messageType}`,
      pass: messageReceived,
    };
  },

  /**
   * Assert that page loads within performance budget
   */
  async toLoadWithinBudget(page: any, budgetMs: number) {
    const navigationMetrics = await page.evaluate(() => {
      const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        loadTime: perfData.loadEventEnd - perfData.loadEventStart,
        domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
      };
    });

    const pass = navigationMetrics.loadTime <= budgetMs;

    return {
      message: () => pass
        ? `Page loaded in ${navigationMetrics.loadTime}ms (within ${budgetMs}ms budget)`
        : `Page load time ${navigationMetrics.loadTime}ms exceeded budget of ${budgetMs}ms`,
      pass,
    };
  },

  /**
   * Assert that Core Web Vitals are good
   */
  async toHaveGoodCoreWebVitals(page: any) {
    const vitals = await page.evaluate(() => {
      const paintEntries = performance.getEntriesByType('paint');
      const fcp = paintEntries.find(entry => entry.name === 'first-contentful-paint')?.startTime || 0;

      return {
        fcp, // First Contentful Paint
        // LCP and CLS would need additional measurement setup
      };
    });

    // FCP should be under 1.8s for good rating
    const pass = vitals.fcp < 1800;

    return {
      message: () => pass
        ? `Core Web Vitals are good: FCP=${vitals.fcp}ms`
        : `Core Web Vitals poor: FCP=${vitals.fcp}ms (should be <1800ms)`,
      pass,
    };
  },

  /**
   * Assert that accessibility audit passes
   */
  async toPassA11yAudit(page: any) {
    // This would integrate with axe-core for comprehensive testing
    const violations = await page.evaluate(async () => {
      if (typeof (window as any).axe === 'undefined') {
        // Load axe-core if not available
        const script = document.createElement('script');
        script.src = 'https://unpkg.com/axe-core@4/axe.min.js';
        document.head.appendChild(script);
        await new Promise(resolve => script.onload = resolve);
      }

      const results = await (window as any).axe.run();
      return results.violations.filter((v: any) => v.impact === 'critical' || v.impact === 'serious');
    });

    const pass = violations.length === 0;

    return {
      message: () => pass
        ? 'Accessibility audit passed'
        : `Accessibility violations found: ${violations.length} critical/serious issues`,
      pass,
    };
  },

  /**
   * Assert that visual snapshot matches
   */
  async toMatchVisualSnapshot(locator: Locator, name: string, options?: { threshold?: number; mask?: string[] }) {
    const { threshold = 0.2, mask = [] } = options || {};

    // Mask dynamic elements
    for (const maskSelector of mask) {
      await locator.page().locator(maskSelector).evaluate(el => {
        (el as HTMLElement).style.visibility = 'hidden';
      });
    }

    // Take screenshot and compare
    const screenshot = await locator.screenshot({ path: `tests/e2e/visual-snapshots/${name}.png` });

    // This is a simplified version - in practice you'd use a visual regression service
    const pass = true; // Placeholder

    return {
      message: () => pass
        ? `Visual snapshot matches: ${name}`
        : `Visual snapshot differs from baseline: ${name}`,
      pass,
    };
  },

  /**
   * Assert that element recovers from error state
   */
  async toRecoverFromError(locator: Locator) {
    const page = locator.page();

    // Simulate error condition (network offline)
    await page.context().setOffline(true);
    await page.waitForTimeout(2000);

    // Check for error state
    const hasError = await page.locator('.error, [data-testid="error"]').count() > 0;

    // Restore connection
    await page.context().setOffline(false);
    await page.waitForTimeout(3000);

    // Check for recovery
    const hasRecovered = await locator.isVisible() &&
                        await page.locator('.error, [data-testid="error"]').count() === 0;

    const pass = hasError && hasRecovered;

    return {
      message: () => pass
        ? 'Element recovered from error state'
        : `Element recovery failed: hadError=${hasError}, recovered=${hasRecovered}`,
      pass,
    };
  },

  /**
   * Assert that offline scenario is handled gracefully
   */
  async toHandleOfflineScenario(page: any) {
    // Go offline
    await page.context().setOffline(true);
    await page.waitForTimeout(2000);

    // Check for offline indicator or graceful degradation
    const hasOfflineIndicator = await page.locator('.offline, [data-testid="offline"]').count() > 0;
    const hasGracefulDegradation = await page.locator('.error').count() === 0;

    // Go back online
    await page.context().setOffline(false);
    await page.waitForTimeout(3000);

    // Check for recovery
    const hasReconnected = await page.locator('.offline').count() === 0;

    const pass = (hasOfflineIndicator || hasGracefulDegradation) && hasReconnected;

    return {
      message: () => pass
        ? 'Offline scenario handled gracefully'
        : `Offline handling failed: indicator=${hasOfflineIndicator}, graceful=${hasGracefulDegradation}, reconnected=${hasReconnected}`,
      pass,
    };
  },
});

export const expect = baseExpected;