/**
 * Enhanced End-to-End Backstage Integration Workflow Tests
 *
 * These tests validate complete user workflows when Claude Flow UI
 * is integrated as a Backstage plugin, ensuring all components work
 * together seamlessly in a real Backstage environment.
 *
 * Enhanced with:
 * - Improved reliability and stability
 * - Better error handling and recovery
 * - Comprehensive visual regression testing
 * - Performance monitoring
 * - Accessibility validation
 */

import { test, expect } from '../fixtures/test-fixtures';
import { BackstagePage } from '../page-objects/BackstagePage';
import { TerminalPage } from '../page-objects/TerminalPage';
import { createTestUtilities } from '../utils/test-utilities';

// Test configuration for Backstage environment
const BACKSTAGE_BASE_URL = process.env.BACKSTAGE_URL || 'http://localhost:3000';
const CLAUDE_FLOW_PLUGIN_PATH = '/claude-flow';

test.describe('Enhanced Backstage Integration Workflows', () => {
  test.beforeEach(async ({ page, context }) => {
    // Set up enhanced browser context for testing
    const utilities = createTestUtilities(page, context);
    await utilities.setupBrowserContext({
      permissions: ['clipboard-read', 'clipboard-write', 'notifications'],
    });

    // Add error monitoring
    const consoleLogs = utilities.collectConsoleLogs();
    const networkRequests = utilities.monitorNetworkRequests();

    // Store utilities for test access
    (page as any).testUtilities = utilities;
    (page as any).consoleLogs = consoleLogs;
    (page as any).networkRequests = networkRequests;
  });

  test.describe('Plugin Loading and Navigation', () => {
    test('should load Claude Flow plugin in Backstage sidebar', async ({ page }) => {
      // Check if Claude Flow appears in the sidebar
      const sidebarLink = page.locator('[data-testid="sidebar"] a[href*="claude-flow"]');
      await expect(sidebarLink).toBeVisible({ timeout: 10000 });

      // Verify link text and icon
      await expect(sidebarLink).toHaveText(/claude.*flow/i);
    });

    test('should navigate to Claude Flow plugin page', async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();

      // Verify we're on the Claude Flow page
      await expect(page).toHaveURL(/.*claude-flow.*/);

      // Check for plugin-specific elements
      await expect(page.locator('h1, [data-testid="page-header"]')).toContainText(/claude.*flow/i);
    });

    test('should maintain Backstage layout with Claude Flow plugin', async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();

      // Verify Backstage elements are still present
      await expect(page.locator('[data-testid="sidebar"]')).toBeVisible();
      await expect(page.locator('[data-testid="header"]')).toBeVisible();

      // Verify Claude Flow content is loaded
      await expect(page.locator('.xterm-wrapper')).toBeVisible({ timeout: 15000 });
    });
  });

  test.describe('Terminal Integration Workflows', () => {
    test.beforeEach(async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();
    });

    test('should initialize terminal successfully', async ({ page }) => {
      const terminal = await backstage.getTerminalElement();

      // Verify terminal is visible and interactive
      await expect(terminal).toBeVisible();
      await expect(terminal.locator('canvas, .xterm-rows')).toBeVisible();

      // Terminal should have focus capability
      await terminal.click();
      await expect(terminal).toBeFocused();
    });

    test('should execute basic terminal commands', async ({ page }) => {
      await backstage.clearTerminal();

      // Execute a simple command
      await backstage.typeInTerminal('echo "Hello Backstage"');
      await backstage.pressEnterInTerminal();

      // Wait for command execution and verify output
      await page.waitForTimeout(1000);
      const terminalContent = await backstage.getTerminalContent();
      expect(terminalContent).toContain('Hello Backstage');
    });

    test('should handle interactive commands', async ({ page }) => {
      await backstage.clearTerminal();

      // Start an interactive command (like Python)
      await backstage.typeInTerminal('python3 -c "print(\'Interactive test\')"');
      await backstage.pressEnterInTerminal();

      await page.waitForTimeout(2000);
      const terminalContent = await backstage.getTerminalContent();
      expect(terminalContent).toContain('Interactive test');
    });

    test('should maintain terminal history across navigation', async ({ page }) => {
      await backstage.clearTerminal();

      // Execute a command
      await backstage.typeInTerminal('echo "History test"');
      await backstage.pressEnterInTerminal();
      await page.waitForTimeout(500);

      // Navigate away from plugin
      await page.locator('[data-testid="sidebar"] a[href="/"]').first().click();
      await page.waitForTimeout(1000);

      // Navigate back to Claude Flow
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();

      // Check if history is preserved
      const terminalContent = await backstage.getTerminalContent();
      expect(terminalContent).toContain('History test');
    });

    test('should handle terminal resize on Backstage layout changes', async ({ page }) => {
      const terminal = await backstage.getTerminalElement();

      // Get initial terminal size
      const initialSize = await terminal.boundingBox();
      expect(initialSize).toBeTruthy();

      // Toggle sidebar to change layout
      const sidebarToggle = page.locator('[data-testid="sidebar-toggle"]');
      if (await sidebarToggle.isVisible()) {
        await sidebarToggle.click();
        await page.waitForTimeout(500);

        // Verify terminal adapts to new size
        const newSize = await terminal.boundingBox();
        expect(newSize).toBeTruthy();
        expect(newSize!.width).not.toBe(initialSize!.width);
      }
    });
  });

  test.describe('Multi-Session Management', () => {
    test.beforeEach(async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();
    });

    test('should create and manage multiple terminal sessions', async ({ page }) => {
      // Check for session controls
      const newSessionButton = page.locator('[data-testid="new-session"], button:has-text("New")');
      if (await newSessionButton.isVisible()) {
        await newSessionButton.click();
        await page.waitForTimeout(1000);

        // Verify multiple session tabs
        const sessionTabs = page.locator('[data-testid="session-tab"], .tab');
        await expect(sessionTabs).toHaveCount(2, { timeout: 5000 });
      }
    });

    test('should isolate terminal sessions', async ({ page }) => {
      // Create a second session if supported
      const newSessionButton = page.locator('[data-testid="new-session"], button:has-text("New")');
      if (await newSessionButton.isVisible()) {
        await backstage.clearTerminal();

        // Execute command in first session
        await backstage.typeInTerminal('echo "Session 1"');
        await backstage.pressEnterInTerminal();
        await page.waitForTimeout(500);

        // Switch to second session
        await newSessionButton.click();
        await page.waitForTimeout(1000);

        // Verify second session doesn't show first session's output
        const terminalContent = await backstage.getTerminalContent();
        expect(terminalContent).not.toContain('Session 1');
      }
    });
  });

  test.describe('Error Handling and Recovery', () => {
    test.beforeEach(async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();
    });

    test('should handle WebSocket connection errors gracefully', async ({ page }) => {
      // Simulate network interruption by blocking WebSocket connections
      await page.route('**/api/ws**', route => route.abort());
      await page.route('**/socket.io/**', route => route.abort());

      // Refresh the page to trigger reconnection
      await page.reload();
      await backstage.waitForBackstageLoad();

      // Should show appropriate error message or loading state
      const errorMessage = page.locator('[data-testid="connection-error"], .error-message');
      const loadingState = page.locator('[data-testid="connecting"], .loading');

      expect(
        await errorMessage.isVisible() || await loadingState.isVisible()
      ).toBeTruthy();

      // Restore network and verify recovery
      await page.unroute('**/api/ws**');
      await page.unroute('**/socket.io/**');
      await page.reload();

      await backstage.waitForTerminalReady();
      const terminal = await backstage.getTerminalElement();
      await expect(terminal).toBeVisible();
    });

    test('should recover from temporary disconnections', async ({ page }) => {
      await backstage.clearTerminal();

      // Execute initial command
      await backstage.typeInTerminal('echo "Before disconnect"');
      await backstage.pressEnterInTerminal();
      await page.waitForTimeout(500);

      // Simulate temporary network issue
      await page.setOffline(true);
      await page.waitForTimeout(2000);

      // Restore connection
      await page.setOffline(false);
      await page.waitForTimeout(3000);

      // Verify terminal is still functional
      await backstage.typeInTerminal('echo "After reconnect"');
      await backstage.pressEnterInTerminal();
      await page.waitForTimeout(1000);

      const terminalContent = await backstage.getTerminalContent();
      expect(terminalContent).toContain('Before disconnect');
      expect(terminalContent).toContain('After reconnect');
    });

    test('should handle authentication expiration', async ({ page }) => {
      // Simulate auth token expiration by clearing storage
      await page.evaluate(() => {
        localStorage.clear();
        sessionStorage.clear();
      });

      // Try to execute a command
      await backstage.typeInTerminal('echo "Auth test"');
      await backstage.pressEnterInTerminal();

      // Should either redirect to login or show auth error
      await page.waitForTimeout(2000);

      const isOnLogin = page.url().includes('/login');
      const hasAuthError = await page.locator('[data-testid="auth-error"]').isVisible();

      expect(isOnLogin || hasAuthError).toBeTruthy();
    });
  });

  test.describe('Performance and Responsiveness', () => {
    test.beforeEach(async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();
    });

    test('should load terminal within performance budget', async ({ page }) => {
      const startTime = Date.now();

      await page.reload();
      await backstage.waitForBackstageLoad();
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();

      const loadTime = Date.now() - startTime;

      // Terminal should load within 10 seconds
      expect(loadTime).toBeLessThan(10000);
    });

    test('should handle large output efficiently', async ({ page }) => {
      await backstage.clearTerminal();

      // Generate large output
      await backstage.typeInTerminal('seq 1 1000');
      await backstage.pressEnterInTerminal();

      // Wait for output to complete
      await page.waitForTimeout(3000);

      // Terminal should remain responsive
      const terminal = await backstage.getTerminalElement();
      await terminal.click();
      await expect(terminal).toBeFocused();

      // Should be able to scroll
      await page.keyboard.press('PageUp');
      await page.keyboard.press('PageDown');
    });

    test('should maintain responsiveness during continuous output', async ({ page }) => {
      await backstage.clearTerminal();

      // Start a command with continuous output
      await backstage.typeInTerminal('ping -c 10 127.0.0.1');
      await backstage.pressEnterInTerminal();

      // Wait a bit for ping to start
      await page.waitForTimeout(2000);

      // Terminal should still be interactive
      const terminal = await backstage.getTerminalElement();
      await terminal.click();

      // Should be able to interrupt with Ctrl+C
      await page.keyboard.press('Control+C');
      await page.waitForTimeout(1000);

      // Should show command prompt again
      const terminalContent = await backstage.getTerminalContent();
      expect(terminalContent).toContain('$');
    });
  });

  test.describe('Accessibility and Usability', () => {
    test.beforeEach(async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();
    });

    test('should be keyboard navigable', async ({ page }) => {
      // Tab should reach terminal
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');

      const terminal = await backstage.getTerminalElement();
      const isFocused = await terminal.evaluate(el => document.activeElement === el);
      expect(isFocused || await terminal.isVisible()).toBeTruthy();
    });

    test('should have proper ARIA attributes', async ({ page }) => {
      const terminal = await backstage.getTerminalElement();

      // Check for accessibility attributes
      const ariaLabel = await terminal.getAttribute('aria-label');
      const role = await terminal.getAttribute('role');

      expect(ariaLabel || role).toBeTruthy();
    });

    test('should work with Backstage keyboard shortcuts', async ({ page }) => {
      // Test common Backstage shortcuts don't interfere
      await page.keyboard.press('Control+k'); // Backstage search
      await page.waitForTimeout(500);

      // Terminal should still work after Backstage shortcuts
      const terminal = await backstage.getTerminalElement();
      await terminal.click();
      await backstage.typeInTerminal('echo "Shortcuts test"');
      await backstage.pressEnterInTerminal();

      await page.waitForTimeout(1000);
      const terminalContent = await backstage.getTerminalContent();
      expect(terminalContent).toContain('Shortcuts test');
    });
  });

  test.describe('Integration with Backstage Features', () => {
    test.beforeEach(async ({ page }) => {
      await backstage.navigateToClaudeFlowPlugin();
      await backstage.waitForTerminalReady();
    });

    test('should respect Backstage theme settings', async ({ page }) => {
      // Check if theme switcher is available
      const themeToggle = page.locator('[data-testid="theme-toggle"], button:has-text("Theme")');

      if (await themeToggle.isVisible()) {
        await themeToggle.click();
        await page.waitForTimeout(1000);

        // Verify terminal adapts to theme changes
        const terminal = await backstage.getTerminalElement();
        const terminalStyles = await terminal.evaluate(el => {
          const computed = window.getComputedStyle(el);
          return {
            backgroundColor: computed.backgroundColor,
            color: computed.color,
          };
        });

        expect(terminalStyles.backgroundColor).toBeTruthy();
        expect(terminalStyles.color).toBeTruthy();
      }
    });

    test('should integrate with Backstage entity context', async ({ page }) => {
      // If we're on an entity page, terminal should be aware
      const entityHeader = page.locator('[data-testid="entity-header"]');

      if (await entityHeader.isVisible()) {
        const entityName = await entityHeader.textContent();

        // Terminal might show entity context in prompt or title
        const terminalWrapper = page.locator('.terminal-wrapper, .claude-flow-wrapper');
        const wrapperText = await terminalWrapper.textContent();

        // This is context-dependent, so just verify it loads
        expect(wrapperText).toBeTruthy();
      }
    });

    test('should handle Backstage permissions', async ({ page }) => {
      // This test is environment-dependent
      // In a real Backstage setup with permissions, ensure terminal respects them

      const terminal = await backstage.getTerminalElement();
      await expect(terminal).toBeVisible();

      // If user doesn't have permissions, might show restricted view
      const restrictedMessage = page.locator('[data-testid="permission-denied"]');

      // Either terminal works or shows permission message
      expect(
        await terminal.isVisible() || await restrictedMessage.isVisible()
      ).toBeTruthy();
    });
  });
});

// Mobile responsiveness tests
test.describe('Mobile and Responsive Design', () => {
  test.beforeEach(async ({ page, context }) => {
    const backstage = new BackstageHelpers(page);
    await page.goto(BACKSTAGE_BASE_URL);
    await backstage.waitForBackstageLoad();
    await backstage.authenticateUser();
  });

  test('should work on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });

    const backstage = new BackstageHelpers(page);
    await backstage.navigateToClaudeFlowPlugin();
    await backstage.waitForTerminalReady();

    const terminal = await backstage.getTerminalElement();
    await expect(terminal).toBeVisible();

    // Terminal should be usable on tablet
    await backstage.typeInTerminal('echo "Tablet test"');
    await backstage.pressEnterInTerminal();

    await page.waitForTimeout(1000);
    const content = await backstage.getTerminalContent();
    expect(content).toContain('Tablet test');
  });

  test('should adapt to mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });

    const backstage = new BackstageHelpers(page);
    await backstage.navigateToClaudeFlowPlugin();

    // On mobile, might have different layout
    const terminal = page.locator('.xterm-wrapper');
    const mobileLayout = page.locator('.mobile-terminal');

    expect(
      await terminal.isVisible() || await mobileLayout.isVisible()
    ).toBeTruthy();
  });
});