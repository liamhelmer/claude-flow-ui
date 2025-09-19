import { test, expect } from '@playwright/test';

/**
 * Sidebar Visibility Test
 *
 * This test validates that:
 * 1. The sidebar starts in minimal mode (hamburger menu visible)
 * 2. Clicking hamburger menu expands the sidebar
 * 3. The "New Terminal" button is accessible when expanded
 * 4. The X button closes the sidebar back to minimal mode
 */

test.describe('Sidebar Functionality', () => {
  test('Sidebar shows minimal hamburger menu and can be expanded', async ({ page }) => {
    console.log('[TEST] Starting sidebar functionality test...');

    // Navigate to server
    console.log('[TEST] Navigating to server at http://localhost:9001...');
    await page.goto('http://localhost:9001', { waitUntil: 'networkidle' });

    // Wait for initial load
    await page.waitForTimeout(2000);

    // Check if hamburger menu is visible (sidebar starts collapsed)
    const hamburgerButton = page.locator('button[title="Open Sidebar"]');
    const hamburgerVisible = await hamburgerButton.isVisible();
    console.log('[TEST] Hamburger menu visible:', hamburgerVisible);
    expect(hamburgerVisible).toBe(true);

    // Click hamburger to open sidebar
    console.log('[TEST] Clicking hamburger menu to open sidebar...');
    await hamburgerButton.click();
    await page.waitForTimeout(500);

    // Check if sidebar is now expanded
    const sidebar = page.locator('h2:has-text("Terminals")');
    const sidebarVisible = await sidebar.isVisible();
    console.log('[TEST] Sidebar expanded:', sidebarVisible);
    expect(sidebarVisible).toBe(true);

    // Check for X button
    const closeButton = page.locator('button[title="Close Sidebar"]');
    const closeButtonVisible = await closeButton.isVisible();
    console.log('[TEST] X button visible:', closeButtonVisible);
    expect(closeButtonVisible).toBe(true);

    // Check for "New Terminal" button
    const newTerminalButton = page.locator('button:has-text("New Terminal")');
    const newTerminalVisible = await newTerminalButton.isVisible();
    console.log('[TEST] New Terminal button visible:', newTerminalVisible);
    expect(newTerminalVisible).toBe(true);

    // Verify we can see terminal list or empty state
    const terminalList = page.locator('text=/Claude Flow|No terminals yet/');
    const hasTerminalContent = await terminalList.isVisible();
    console.log('[TEST] Terminal list/empty state visible:', hasTerminalContent);
    expect(hasTerminalContent).toBe(true);

    // Click X button to close sidebar
    console.log('[TEST] Clicking X button to close sidebar...');
    await closeButton.click();
    await page.waitForTimeout(500);

    // Verify sidebar is closed and hamburger menu is visible again
    const hamburgerVisibleAgain = await hamburgerButton.isVisible();
    const sidebarHidden = await sidebar.isVisible().catch(() => false);
    console.log('[TEST] Hamburger menu visible again:', hamburgerVisibleAgain);
    console.log('[TEST] Sidebar hidden:', !sidebarHidden);
    expect(hamburgerVisibleAgain).toBe(true);
    expect(sidebarHidden).toBe(false);

    console.log('\n[TEST] ✅ Sidebar Functionality Test: PASSED');
    console.log('  - Minimal mode: Shows hamburger menu');
    console.log('  - Hamburger click: Expands sidebar');
    console.log('  - X button: Closes sidebar back to minimal');
    console.log('  - New Terminal button: Available when expanded');
    console.log('  - Terminal list: Displayed when expanded');
  });
});