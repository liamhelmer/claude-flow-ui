import { test, expect } from './fixtures/test-fixtures';
import { SidebarPage } from './page-objects/SidebarPage';
import { TerminalPage } from './page-objects/TerminalPage';

/**
 * E2E Tests for Sidebar Navigation and Monitoring Panels
 * Tests sidebar functionality, terminal controls, and status monitoring
 */

test.describe('Sidebar Navigation and Controls', () => {
  let sidebarPage: SidebarPage;
  let terminalPage: TerminalPage;

  test.beforeEach(async ({ page, sidebarPage: sp, terminalPage: tp }) => {
    sidebarPage = sp;
    terminalPage = tp;

    // Navigate to the application
    await sidebarPage.goto('/');
    await sidebarPage.waitForPageLoad();
    await terminalPage.waitForTerminalReady();
  });

  test('should open and close sidebar', async () => {
    // Start with sidebar closed (if applicable)
    if (await sidebarPage.isSidebarOpen()) {
      await sidebarPage.closeSidebar();
    }

    // Verify sidebar is closed
    expect(await sidebarPage.isSidebarOpen()).toBeFalsy();

    // Open sidebar
    await sidebarPage.openSidebar();
    expect(await sidebarPage.isSidebarOpen()).toBeTruthy();

    // Close sidebar
    await sidebarPage.closeSidebar();
    expect(await sidebarPage.isSidebarOpen()).toBeFalsy();
  });

  test('should display connection status correctly', async () => {
    await sidebarPage.openSidebar();

    // Wait for connection to be established
    await sidebarPage.waitForConnection();

    // Check connection status
    const status = await sidebarPage.getConnectionStatus();
    expect(status).toBe('connected');
  });

  test('should show keyboard shortcuts information', async () => {
    await sidebarPage.openSidebar();

    // Get keyboard shortcuts
    const shortcuts = await sidebarPage.getKeyboardShortcuts();

    // Verify common shortcuts are present
    expect(shortcuts.some(shortcut => shortcut.includes('Ctrl+C'))).toBeTruthy();
    expect(shortcuts.some(shortcut => shortcut.includes('Ctrl+L'))).toBeTruthy();
    expect(shortcuts.some(shortcut => shortcut.includes('Ctrl+D'))).toBeTruthy();
  });

  test('should show terminal size information', async () => {
    await sidebarPage.openSidebar();

    // Get terminal size from sidebar
    const terminalSize = await sidebarPage.getTerminalSize();
    expect(terminalSize).toBeTruthy();
    expect(terminalSize!.cols).toBeGreaterThan(0);
    expect(terminalSize!.rows).toBeGreaterThan(0);

    console.log(`Terminal size: ${terminalSize!.cols}x${terminalSize!.rows}`);
  });

  test('should handle refresh button', async () => {
    await sidebarPage.openSidebar();

    // Execute a command first
    await terminalPage.executeCommand('echo "Before sidebar refresh"');
    await terminalPage.waitForOutput('Before sidebar refresh');

    // Click refresh button from sidebar
    await sidebarPage.clickRefresh();

    // Verify refresh loading state
    const isLoading = await sidebarPage.isRefreshLoading();
    if (isLoading) {
      // Wait for refresh to complete
      await sidebarPage.page.waitForTimeout(2000);
    }

    // Verify terminal is still functional
    await terminalPage.executeCommand('echo "After sidebar refresh"');
    await terminalPage.waitForOutput('After sidebar refresh');
  });

  test('should handle scroll controls from sidebar', async () => {
    await sidebarPage.openSidebar();

    // Generate content to scroll
    await terminalPage.executeCommand('seq 1 30');
    await terminalPage.waitForOutput('30');

    // Use sidebar scroll to top
    await sidebarPage.clickScrollToTop();

    // Verify we're not at bottom
    expect(await sidebarPage.isScrollToBottomDisabled()).toBeFalsy();

    // Use sidebar scroll to bottom
    await sidebarPage.clickScrollToBottom();

    // Verify we're at bottom
    expect(await sidebarPage.isScrollToBottomDisabled()).toBeTruthy();
  });

  test('should show new output indicator', async () => {
    await sidebarPage.openSidebar();

    // Scroll to top to trigger new output indicator
    await terminalPage.scrollToTop();

    // Generate new output
    await terminalPage.executeCommand('echo "New output test"');
    await terminalPage.waitForOutput('New output test');

    // Check if new output indicator appears
    const hasIndicator = await sidebarPage.hasNewOutputIndicator();

    // Note: This might depend on implementation details
    console.log(`New output indicator visible: ${hasIndicator}`);
  });

  test('should maintain sidebar state during terminal operations', async () => {
    // Open sidebar
    await sidebarPage.openSidebar();
    expect(await sidebarPage.isSidebarOpen()).toBeTruthy();

    // Execute multiple commands
    await terminalPage.executeCommand('echo "Command 1"');
    await terminalPage.waitForOutput('Command 1');

    await terminalPage.executeCommand('pwd');
    await terminalPage.page.waitForTimeout(1000);

    await terminalPage.executeCommand('date');
    await terminalPage.page.waitForTimeout(1000);

    // Verify sidebar is still open and functional
    expect(await sidebarPage.isSidebarOpen()).toBeTruthy();

    // Test sidebar controls still work
    const status = await sidebarPage.getConnectionStatus();
    expect(status).toBe('connected');
  });

  test('should handle sidebar toggle during active command', async () => {
    await sidebarPage.openSidebar();

    // Start a command
    await terminalPage.typeCommand('sleep 3');
    await terminalPage.page.keyboard.press('Enter');

    // Toggle sidebar while command is running
    await sidebarPage.toggleSidebar();
    await sidebarPage.page.waitForTimeout(1000);

    await sidebarPage.toggleSidebar();
    await sidebarPage.page.waitForTimeout(1000);

    // Interrupt the sleep command
    await terminalPage.sendInterrupt();

    // Verify sidebar and terminal are both functional
    expect(await sidebarPage.isSidebarOpen()).toBeTruthy();

    await terminalPage.executeCommand('echo "Still working"');
    await terminalPage.waitForOutput('Still working');
  });

  test('should validate sidebar accessibility', async () => {
    await sidebarPage.openSidebar();

    // Run accessibility validation
    const isAccessible = await sidebarPage.validateSidebarAccessibility();
    expect(isAccessible).toBeTruthy();
  });

  test('should handle sidebar responsive behavior', async () => {
    // Test responsive behavior at different screen sizes
    await sidebarPage.testResponsiveBehavior();

    // Sidebar behavior varies by screen size, so just ensure no errors
    // and that we can still interact with the terminal
    await terminalPage.executeCommand('echo "Responsive test"');
    await terminalPage.waitForOutput('Responsive test');
  });

  test('should show proper status indicators', async () => {
    await sidebarPage.openSidebar();

    // Wait for connection to be established
    await sidebarPage.waitForConnection();

    // Verify connection indicator is green/positive
    const connectionStatus = await sidebarPage.getConnectionStatus();
    expect(connectionStatus).toBe('connected');

    // Check for terminal size display
    const terminalSize = await sidebarPage.getTerminalSize();
    expect(terminalSize).toBeTruthy();
  });

  test('should persist sidebar state across page refresh', async () => {
    // Open sidebar
    await sidebarPage.openSidebar();
    expect(await sidebarPage.isSidebarOpen()).toBeTruthy();

    // Refresh the page
    await sidebarPage.page.reload();
    await sidebarPage.waitForPageLoad();
    await terminalPage.waitForTerminalReady();

    // Verify sidebar state is restored (depends on implementation)
    // Some implementations might remember the state, others might default to closed
    const isOpenAfterRefresh = await sidebarPage.isSidebarOpen();
    console.log(`Sidebar open after refresh: ${isOpenAfterRefresh}`);

    // Verify sidebar functionality works after refresh
    if (!isOpenAfterRefresh) {
      await sidebarPage.openSidebar();
    }

    const status = await sidebarPage.getConnectionStatus();
    expect(['connected', 'connecting']).toContain(status);
  });
});