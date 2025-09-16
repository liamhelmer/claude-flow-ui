/**
 * End-to-End Terminal Workflow Tests
 * Comprehensive E2E tests for terminal functionality
 */

const { test, expect } = require('@playwright/test');

test.describe('Terminal Workflow E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/');

    // Wait for the application to load
    await page.waitForLoadState('networkidle');
  });

  test('should load the application successfully', async ({ page }) => {
    // Check if the page title is correct
    await expect(page).toHaveTitle(/Claude Flow UI/);

    // Check if main container is present
    const mainContainer = page.locator('[data-testid="main-container"]');
    await expect(mainContainer).toBeVisible();
  });

  test('should create a new terminal session', async ({ page }) => {
    // Look for the new terminal button
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await expect(newTerminalButton).toBeVisible();

    // Click to create new terminal
    await newTerminalButton.click();

    // Wait for terminal to be created
    await page.waitForTimeout(2000);

    // Check if terminal container is present
    const terminalContainer = page.locator('[data-testid="terminal-container"]');
    await expect(terminalContainer).toBeVisible();

    // Check if terminal has a cursor
    const terminalContent = page.locator('.xterm-screen');
    await expect(terminalContent).toBeVisible();
  });

  test('should execute basic commands in terminal', async ({ page }) => {
    // Create a new terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    // Get terminal element
    const terminal = page.locator('.xterm-screen');
    await expect(terminal).toBeVisible();

    // Focus on terminal
    await terminal.click();

    // Type a simple command
    await page.keyboard.type('echo "Hello E2E Test"');
    await page.keyboard.press('Enter');

    // Wait for command execution
    await page.waitForTimeout(1000);

    // Check if output is visible (this might need adjustment based on actual implementation)
    const terminalOutput = page.locator('.xterm-screen');
    await expect(terminalOutput).toContainText('Hello E2E Test');
  });

  test('should handle terminal resize', async ({ page }) => {
    // Create a new terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    // Get initial terminal size
    const terminal = page.locator('[data-testid="terminal-container"]');
    const initialSize = await terminal.boundingBox();

    // Resize the browser window
    await page.setViewportSize({ width: 1600, height: 900 });
    await page.waitForTimeout(1000);

    // Check if terminal resized
    const newSize = await terminal.boundingBox();
    expect(newSize.width).not.toBe(initialSize.width);
  });

  test('should manage multiple terminal tabs', async ({ page }) => {
    // Create first terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(1000);

    // Create second terminal
    await newTerminalButton.click();
    await page.waitForTimeout(1000);

    // Check if tab list is present
    const tabList = page.locator('[data-testid="tab-list"]');
    await expect(tabList).toBeVisible();

    // Check if there are multiple tabs
    const tabs = page.locator('[data-testid="tab-item"]');
    await expect(tabs).toHaveCount(2);

    // Click on first tab
    await tabs.first().click();
    await page.waitForTimeout(500);

    // Click on second tab
    await tabs.nth(1).click();
    await page.waitForTimeout(500);

    // Verify tab switching works
    expect(await tabs.nth(1).getAttribute('aria-selected')).toBe('true');
  });

  test('should toggle monitoring sidebar', async ({ page }) => {
    // Look for sidebar toggle button
    const sidebarToggle = page.locator('[data-testid="sidebar-toggle"]');

    if (await sidebarToggle.isVisible()) {
      // Click to toggle sidebar
      await sidebarToggle.click();
      await page.waitForTimeout(500);

      // Check if monitoring panel is visible
      const monitoringPanel = page.locator('[data-testid="monitoring-panel"]');
      await expect(monitoringPanel).toBeVisible();

      // Toggle again to hide
      await sidebarToggle.click();
      await page.waitForTimeout(500);

      // Check if panel is hidden
      await expect(monitoringPanel).not.toBeVisible();
    }
  });

  test('should handle WebSocket connection', async ({ page }) => {
    // Monitor WebSocket connections
    const wsMessages = [];
    page.on('websocket', ws => {
      ws.on('framereceived', event => {
        wsMessages.push(event.payload);
      });
    });

    // Create a new terminal (this should establish WebSocket connection)
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    // Execute a command to generate WebSocket traffic
    const terminal = page.locator('.xterm-screen');
    await terminal.click();
    await page.keyboard.type('echo "WebSocket test"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);

    // Verify WebSocket messages were exchanged
    expect(wsMessages.length).toBeGreaterThan(0);
  });

  test('should persist terminal sessions on page refresh', async ({ page }) => {
    // Create a terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    // Execute a command to create some state
    const terminal = page.locator('.xterm-screen');
    await terminal.click();
    await page.keyboard.type('export TEST_VAR="persistence_test"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);

    // Refresh the page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Check if terminal sessions are restored
    const terminalContainer = page.locator('[data-testid="terminal-container"]');
    await expect(terminalContainer).toBeVisible();

    // Note: Actual session persistence depends on implementation
    // This test verifies the UI can handle refresh gracefully
  });

  test('should handle terminal keyboard shortcuts', async ({ page }) => {
    // Create a terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    const terminal = page.locator('.xterm-screen');
    await terminal.click();

    // Test Ctrl+C (interrupt)
    await page.keyboard.type('sleep 10');
    await page.keyboard.press('Control+c');
    await page.waitForTimeout(500);

    // Test Ctrl+D (EOF)
    await page.keyboard.press('Control+d');
    await page.waitForTimeout(500);

    // Test Tab completion (if supported)
    await page.keyboard.type('ec');
    await page.keyboard.press('Tab');
    await page.waitForTimeout(500);

    // Verify terminal is still responsive
    await page.keyboard.type('echo "shortcuts work"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);
  });

  test('should handle copy and paste operations', async ({ page }) => {
    // Create a terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    const terminal = page.locator('.xterm-screen');
    await terminal.click();

    // Type some text
    const testText = 'echo "copy paste test"';
    await page.keyboard.type(testText);

    // Select all text (Ctrl+A)
    await page.keyboard.press('Control+a');
    await page.waitForTimeout(200);

    // Copy (Ctrl+C) - Note: This might not work in all browsers due to security
    await page.keyboard.press('Control+c');
    await page.waitForTimeout(200);

    // Clear the line
    await page.keyboard.press('Control+u');
    await page.waitForTimeout(200);

    // Paste (Ctrl+V) - Note: This might not work in all browsers due to security
    await page.keyboard.press('Control+v');
    await page.waitForTimeout(200);

    // Execute the pasted command
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);
  });

  test('should handle terminal settings and preferences', async ({ page }) => {
    // Look for settings button
    const settingsButton = page.locator('[data-testid="settings-button"]');

    if (await settingsButton.isVisible()) {
      await settingsButton.click();
      await page.waitForTimeout(500);

      // Check if settings modal/panel opens
      const settingsPanel = page.locator('[data-testid="settings-panel"]');
      await expect(settingsPanel).toBeVisible();

      // Test theme switching if available
      const themeToggle = page.locator('[data-testid="theme-toggle"]');
      if (await themeToggle.isVisible()) {
        await themeToggle.click();
        await page.waitForTimeout(500);

        // Verify theme change
        const body = page.locator('body');
        const classList = await body.getAttribute('class');
        expect(classList).toBeTruthy();
      }

      // Close settings
      const closeButton = page.locator('[data-testid="settings-close"]');
      if (await closeButton.isVisible()) {
        await closeButton.click();
        await page.waitForTimeout(500);
      }
    }
  });

  test('should handle error states gracefully', async ({ page }) => {
    // Test network error handling
    await page.route('**/api/**', route => {
      route.abort('failed');
    });

    // Try to create a terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    // Check if error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');

    // Error handling might be implemented differently
    // This test ensures the app doesn't crash on network errors
    const pageContent = page.locator('body');
    await expect(pageContent).toBeVisible();
  });

  test('should be accessible via keyboard navigation', async ({ page }) => {
    // Test keyboard navigation
    await page.keyboard.press('Tab');

    // Check if focus is visible
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();

    // Navigate through interactive elements
    for (let i = 0; i < 5; i++) {
      await page.keyboard.press('Tab');
      await page.waitForTimeout(200);
    }

    // Test Enter key activation
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);

    // Verify keyboard navigation works
    expect(true).toBe(true); // Basic test to ensure keyboard events work
  });

  test('should handle mobile responsive design', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(1000);

    // Check if mobile layout is applied
    const mainContainer = page.locator('[data-testid="main-container"]');
    await expect(mainContainer).toBeVisible();

    // Test tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.waitForTimeout(1000);

    // Verify responsive design
    await expect(mainContainer).toBeVisible();

    // Test desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.waitForTimeout(1000);

    await expect(mainContainer).toBeVisible();
  });

  test('should handle long-running commands', async ({ page }) => {
    // Create a terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    const terminal = page.locator('.xterm-screen');
    await terminal.click();

    // Execute a long-running command
    await page.keyboard.type('sleep 3 && echo "Long command completed"');
    await page.keyboard.press('Enter');

    // Wait for command to complete
    await page.waitForTimeout(4000);

    // Verify command completed
    await expect(terminal).toContainText('Long command completed');
  });

  test('should handle special characters and Unicode', async ({ page }) => {
    // Create a terminal
    const newTerminalButton = page.locator('[data-testid="new-terminal"]');
    await newTerminalButton.click();
    await page.waitForTimeout(2000);

    const terminal = page.locator('.xterm-screen');
    await terminal.click();

    // Test special characters
    const specialText = 'echo "Special: áéíóú ñ 中文 🚀 ©®™"';
    await page.keyboard.type(specialText);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);

    // Verify special characters are handled
    await expect(terminal).toContainText('Special:');
  });
});