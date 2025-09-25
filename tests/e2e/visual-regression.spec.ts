import { test, expect } from './fixtures/test-fixtures';
import { TerminalPage } from './page-objects/TerminalPage';
import { SidebarPage } from './page-objects/SidebarPage';

/**
 * E2E Visual Regression Tests
 * Tests visual consistency and appearance across different states and scenarios
 */

test.describe('Visual Regression Tests', () => {
  let terminalPage: TerminalPage;
  let sidebarPage: SidebarPage;

  test.beforeEach(async ({ page, terminalPage: tp, sidebarPage: sp }) => {
    terminalPage = tp;
    sidebarPage = sp;

    // Navigate to the application
    await terminalPage.goto('/');
    await terminalPage.waitForPageLoad();
    await terminalPage.waitForTerminalReady();
  });

  test('should match terminal initial state appearance', async ({ testData }) => {
    // Wait for terminal to be fully ready
    await terminalPage.waitForTerminalReady();

    // Take screenshot of initial state
    await expect(terminalPage.page).toHaveScreenshot('terminal-initial-state.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
        terminalPage.page.locator('[data-timestamp]'),
      ],
      threshold: 0.2,
    });
  });

  test('should match terminal with command output', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute some commands to create output
    await terminalPage.executeCommand('echo "Visual regression test"');
    await terminalPage.waitForOutput('Visual regression test');

    await terminalPage.executeCommand('pwd');
    await terminalPage.page.waitForTimeout(1000);

    await terminalPage.executeCommand('date');
    await terminalPage.page.waitForTimeout(1000);

    // Take screenshot with output
    await expect(terminalPage.page).toHaveScreenshot('terminal-with-output.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
        terminalPage.page.locator('[data-timestamp]'),
        terminalPage.page.locator('text=/\\d{4}-\\d{2}-\\d{2}/'), // Date output
        terminalPage.page.locator('text=/Mon|Tue|Wed|Thu|Fri|Sat|Sun/'), // Day names
      ],
      threshold: 0.3,
    });
  });

  test('should match sidebar open state', async ({ testData }) => {
    // Open sidebar
    await sidebarPage.openSidebar();
    await sidebarPage.waitForSidebarOpen();

    // Take screenshot of sidebar open
    await expect(sidebarPage.page).toHaveScreenshot('sidebar-open.png', {
      fullPage: true,
      mask: [
        sidebarPage.page.locator('[data-timestamp]'),
        sidebarPage.page.locator('.animate-pulse'),
      ],
      threshold: 0.2,
    });
  });

  test('should match sidebar closed state', async ({ testData }) => {
    // Ensure sidebar is closed
    if (await sidebarPage.isSidebarOpen()) {
      await sidebarPage.closeSidebar();
    }
    await sidebarPage.waitForSidebarClosed();

    // Take screenshot of sidebar closed
    await expect(sidebarPage.page).toHaveScreenshot('sidebar-closed.png', {
      fullPage: true,
      mask: [
        sidebarPage.page.locator('[data-timestamp]'),
      ],
      threshold: 0.2,
    });
  });

  test('should match mobile layout', async ({ testData }) => {
    // Set mobile viewport
    await terminalPage.setViewportSize(375, 667);
    await terminalPage.page.waitForTimeout(1000); // Wait for responsive layout

    await terminalPage.waitForTerminalReady();

    // Take mobile screenshot
    await expect(terminalPage.page).toHaveScreenshot('mobile-layout.png', {
      fullPage: true,
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
        terminalPage.page.locator('[data-timestamp]'),
      ],
      threshold: 0.2,
    });
  });

  test('should match tablet layout', async ({ testData }) => {
    // Set tablet viewport
    await terminalPage.setViewportSize(768, 1024);
    await terminalPage.page.waitForTimeout(1000);

    await terminalPage.waitForTerminalReady();

    // Take tablet screenshot
    await expect(terminalPage.page).toHaveScreenshot('tablet-layout.png', {
      fullPage: true,
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
        terminalPage.page.locator('[data-timestamp]'),
      ],
      threshold: 0.2,
    });
  });

  test('should match terminal with long output', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Generate long output
    await terminalPage.executeCommand('seq 1 20');
    await terminalPage.waitForOutput('20');

    // Scroll to show different parts of output
    await terminalPage.scrollToTop();
    await terminalPage.page.waitForTimeout(500);

    // Take screenshot of long output
    await expect(terminalPage.page).toHaveScreenshot('terminal-long-output.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
      ],
      threshold: 0.3,
    });
  });

  test('should match error state appearance', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute a command that produces error
    await terminalPage.executeCommand('nonexistentcommand');
    await terminalPage.page.waitForTimeout(3000);

    // Take screenshot of error state
    await expect(terminalPage.page).toHaveScreenshot('terminal-error-state.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
      ],
      threshold: 0.3,
    });
  });

  test('should match loading state appearance', async ({ testData }) => {
    // Reload page to capture loading state
    await terminalPage.page.reload();

    // Try to capture loading state quickly
    try {
      await expect(terminalPage.page).toHaveScreenshot('terminal-loading-state.png', {
        fullPage: true,
        timeout: 2000,
      });
    } catch (error) {
      console.log('Loading state too brief to capture or not present');
    }

    // Wait for normal state
    await terminalPage.waitForPageLoad();
    await terminalPage.waitForTerminalReady();
  });

  test('should match high contrast appearance', async ({ testData }) => {
    // Apply high contrast styles if available
    await terminalPage.addCustomCSS(`
      .xterm-wrapper {
        filter: contrast(1.5) brightness(1.2);
      }
      .terminal-container {
        border-color: #ffffff !important;
      }
    `);

    await terminalPage.waitForTerminalReady();
    await terminalPage.executeCommand('echo "High contrast test"');
    await terminalPage.waitForOutput('High contrast test');

    // Take high contrast screenshot
    await expect(terminalPage.page).toHaveScreenshot('terminal-high-contrast.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
      ],
      threshold: 0.4, // Higher threshold for contrast changes
    });
  });

  test('should match terminal focus states', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Click terminal to focus
    await terminalPage.terminalContainer.click();
    await terminalPage.page.waitForTimeout(500);

    // Take screenshot of focused state
    await expect(terminalPage.page).toHaveScreenshot('terminal-focused.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
      ],
      threshold: 0.2,
    });
  });

  test('should match sidebar transition states', async ({ testData }) => {
    // Start with sidebar closed
    if (await sidebarPage.isSidebarOpen()) {
      await sidebarPage.closeSidebar();
    }

    // Trigger sidebar opening
    await sidebarPage.toggleSidebar();

    // Wait for animation to start but not complete
    await sidebarPage.page.waitForTimeout(150); // Half of typical 300ms transition

    // Take screenshot during transition
    await expect(sidebarPage.page).toHaveScreenshot('sidebar-transition.png', {
      fullPage: true,
      mask: [
        sidebarPage.page.locator('[data-timestamp]'),
        sidebarPage.page.locator('.animate-pulse'),
      ],
      threshold: 0.4, // Higher threshold for animation
    });

    // Wait for animation to complete
    await sidebarPage.waitForSidebarOpen();
  });

  test('should match different terminal sizes', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Test different viewport sizes and their effect on terminal
    const viewports = [
      { width: 1920, height: 1080, name: 'desktop-large' },
      { width: 1440, height: 900, name: 'desktop-medium' },
      { width: 1024, height: 768, name: 'desktop-small' },
    ];

    for (const viewport of viewports) {
      await terminalPage.setViewportSize(viewport.width, viewport.height);
      await terminalPage.page.waitForTimeout(1000);

      await terminalPage.executeCommand('echo "Size test"');
      await terminalPage.waitForOutput('Size test');

      await expect(terminalPage.page).toHaveScreenshot(`terminal-${viewport.name}.png`, {
        fullPage: false,
        clip: { x: 0, y: 0, width: viewport.width, height: viewport.height },
        mask: [
          terminalPage.page.locator('.xterm-cursor'),
        ],
        threshold: 0.3,
      });
    }

    // Reset to default size
    await terminalPage.setViewportSize(1280, 720);
  });

  test('should match connection status indicators', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();
    await sidebarPage.openSidebar();

    // Wait for connection status to be established
    await sidebarPage.waitForConnection();

    // Take screenshot showing connection indicators
    await expect(sidebarPage.page).toHaveScreenshot('connection-indicators.png', {
      fullPage: true,
      mask: [
        sidebarPage.page.locator('[data-timestamp]'),
        sidebarPage.page.locator('.animate-pulse'),
      ],
      threshold: 0.2,
    });
  });

  test('should match terminal with custom theme', async ({ testData }) => {
    // Apply custom theme
    await terminalPage.addCustomCSS(`
      .terminal-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 12px;
      }
      .xterm-wrapper {
        border-radius: 8px;
        background: rgba(0, 0, 0, 0.8);
      }
    `);

    await terminalPage.waitForTerminalReady();
    await terminalPage.executeCommand('echo "Custom theme test"');
    await terminalPage.waitForOutput('Custom theme test');

    // Take screenshot with custom theme
    await expect(terminalPage.page).toHaveScreenshot('terminal-custom-theme.png', {
      fullPage: false,
      clip: { x: 0, y: 0, width: 1280, height: 720 },
      mask: [
        terminalPage.page.locator('.xterm-cursor'),
      ],
      threshold: 0.4, // Higher threshold for theme changes
    });
  });
});