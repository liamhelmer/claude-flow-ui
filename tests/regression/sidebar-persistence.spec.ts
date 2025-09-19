import { test, expect } from '@playwright/test';

/**
 * Sidebar Persistence Test
 *
 * This test validates that:
 * 1. The sidebar is always visible even during loading
 * 2. The sidebar persists through page reload
 * 3. The hamburger menu is accessible at all times
 */

test.describe('Sidebar Persistence', () => {
  test('Sidebar remains visible during loading and reload', async ({ page }) => {
    console.log('[TEST] Starting sidebar persistence test...');

    // Navigate to server
    console.log('[TEST] Navigating to server at http://localhost:8080...');
    await page.goto('http://localhost:8080', { waitUntil: 'domcontentloaded' });

    // Check immediately - sidebar should be visible even during loading
    const hamburgerButton = page.locator('button[title="Open Sidebar"]');
    const hamburgerVisibleDuringLoad = await hamburgerButton.isVisible().catch(() => false);
    console.log('[TEST] Hamburger visible during initial load:', hamburgerVisibleDuringLoad);
    expect(hamburgerVisibleDuringLoad).toBe(true);

    // Wait for page to stabilize
    await page.waitForTimeout(2000);

    // Check hamburger is still visible after load
    const hamburgerVisibleAfterLoad = await hamburgerButton.isVisible();
    console.log('[TEST] Hamburger visible after load:', hamburgerVisibleAfterLoad);
    expect(hamburgerVisibleAfterLoad).toBe(true);

    // Test reload - sidebar should remain visible
    console.log('[TEST] Reloading page...');
    const reloadPromise = page.reload({ waitUntil: 'domcontentloaded' });

    // Check immediately after reload starts
    await page.waitForTimeout(100);
    const hamburgerVisibleDuringReload = await hamburgerButton.isVisible().catch(() => false);
    console.log('[TEST] Hamburger visible during reload:', hamburgerVisibleDuringReload);

    // Wait for reload to complete
    await reloadPromise;
    await page.waitForTimeout(2000);

    // Check after reload completes
    const hamburgerVisibleAfterReload = await hamburgerButton.isVisible();
    console.log('[TEST] Hamburger visible after reload:', hamburgerVisibleAfterReload);
    expect(hamburgerVisibleAfterReload).toBe(true);

    // Verify we can still interact with the sidebar
    console.log('[TEST] Testing sidebar interaction after reload...');
    await hamburgerButton.click();
    await page.waitForTimeout(500);

    const sidebarExpanded = await page.locator('h2:has-text("Terminals")').isVisible();
    console.log('[TEST] Sidebar can be expanded:', sidebarExpanded);
    expect(sidebarExpanded).toBe(true);

    console.log('\n[TEST] ✅ Sidebar Persistence Test: PASSED');
    console.log('  - Sidebar visible during initial load: Yes');
    console.log('  - Sidebar visible after load: Yes');
    console.log('  - Sidebar persists through reload: Yes');
    console.log('  - Sidebar remains interactive: Yes');
  });
});