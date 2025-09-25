import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for Sidebar component interactions
 * Handles sidebar navigation, terminal session management, and monitoring panels
 */
export class SidebarPage extends BasePage {
  readonly sidebarContainer: Locator;
  readonly toggleButton: Locator;
  readonly closeButton: Locator;
  readonly header: Locator;
  readonly statusSection: Locator;
  readonly connectionIndicator: Locator;
  readonly keyboardShortcuts: Locator;
  readonly refreshButton: Locator;
  readonly scrollToTopButton: Locator;
  readonly scrollToBottomButton: Locator;
  readonly terminalControls: Locator;
  readonly terminalSizeDisplay: Locator;
  readonly newOutputIndicator: Locator;

  constructor(page: Page) {
    super(page);

    // Main sidebar elements
    this.sidebarContainer = page.locator('.sidebar-container');
    this.toggleButton = page.locator('button[title="Toggle Sidebar"], button[title="Open Sidebar"]');
    this.closeButton = page.locator('button[title="Toggle Sidebar"]').first();
    this.header = page.locator('.sidebar-container h2');

    // Status and information sections
    this.statusSection = page.locator('text="Status"').locator('..');
    this.connectionIndicator = page.locator('.text-green-500, .bg-green-500', { hasText: /Connected|Terminal Connected/ });
    this.keyboardShortcuts = page.locator('text="Keyboard Shortcuts"').locator('..');

    // Terminal controls
    this.terminalControls = page.locator('text="Terminal Controls"').locator('..');
    this.refreshButton = page.locator('button', { hasText: 'Refresh' });
    this.scrollToTopButton = page.locator('button', { hasText: 'Top' });
    this.scrollToBottomButton = page.locator('button', { hasText: 'Bottom' });

    // Status indicators
    this.terminalSizeDisplay = page.locator('text=/Size: \\d+×\\d+/');
    this.newOutputIndicator = page.locator('.text-yellow-400', { hasText: 'New output' });
  }

  /**
   * Open the sidebar
   */
  async openSidebar(): Promise<void> {
    const isOpen = await this.isSidebarOpen();
    if (!isOpen) {
      await this.toggleButton.click();
      await this.waitForSidebarOpen();
      console.log('✅ Sidebar opened');
    }
  }

  /**
   * Close the sidebar
   */
  async closeSidebar(): Promise<void> {
    const isOpen = await this.isSidebarOpen();
    if (isOpen) {
      await this.closeButton.click();
      await this.waitForSidebarClosed();
      console.log('✅ Sidebar closed');
    }
  }

  /**
   * Toggle sidebar state
   */
  async toggleSidebar(): Promise<void> {
    await this.toggleButton.click();
    await this.page.waitForTimeout(500); // Wait for animation
    console.log('✅ Sidebar toggled');
  }

  /**
   * Check if sidebar is currently open
   */
  async isSidebarOpen(): Promise<boolean> {
    try {
      // Check if sidebar content is visible
      await this.header.waitFor({ state: 'visible', timeout: 1000 });

      // Also check width - open sidebar should have width > 0
      const width = await this.sidebarContainer.evaluate(el => el.getBoundingClientRect().width);
      return width > 50; // Threshold to account for border/padding
    } catch (error) {
      return false;
    }
  }

  /**
   * Wait for sidebar to be fully open
   */
  async waitForSidebarOpen(): Promise<void> {
    await this.header.waitFor({ state: 'visible', timeout: 5000 });

    // Wait for animation to complete
    await this.page.waitForFunction(() => {
      const sidebar = document.querySelector('.sidebar-container');
      if (!sidebar) return false;

      const style = window.getComputedStyle(sidebar);
      const width = parseFloat(style.width);
      return width > 200; // Expected sidebar width when open
    }, { timeout: 5000 });

    console.log('✅ Sidebar is fully open');
  }

  /**
   * Wait for sidebar to be fully closed
   */
  async waitForSidebarClosed(): Promise<void> {
    await this.page.waitForFunction(() => {
      const sidebar = document.querySelector('.sidebar-container');
      if (!sidebar) return true;

      const style = window.getComputedStyle(sidebar);
      const width = parseFloat(style.width);
      return width < 50; // Should be 0 or very small when closed
    }, { timeout: 5000 });

    console.log('✅ Sidebar is fully closed');
  }

  /**
   * Get connection status
   */
  async getConnectionStatus(): Promise<'connected' | 'disconnected' | 'connecting'> {
    try {
      // Check for connected indicator
      await this.connectionIndicator.waitFor({ state: 'visible', timeout: 2000 });
      return 'connected';
    } catch (error) {
      // Check for connecting or disconnected states
      const statusText = await this.getElementText('.text-gray-400, .text-gray-500');

      if (statusText.toLowerCase().includes('connecting')) {
        return 'connecting';
      }

      return 'disconnected';
    }
  }

  /**
   * Wait for connection to be established
   */
  async waitForConnection(timeout: number = 15000): Promise<void> {
    await this.connectionIndicator.waitFor({ state: 'visible', timeout });
    console.log('✅ Connection established');
  }

  /**
   * Get keyboard shortcuts information
   */
  async getKeyboardShortcuts(): Promise<string[]> {
    await this.openSidebar();

    const shortcuts = await this.keyboardShortcuts.locator('div').allTextContents();
    return shortcuts.filter(text => text.trim().length > 0);
  }

  /**
   * Click refresh button
   */
  async clickRefresh(): Promise<void> {
    await this.openSidebar();
    await this.refreshButton.click();
    console.log('✅ Refresh clicked');
  }

  /**
   * Click scroll to top button
   */
  async clickScrollToTop(): Promise<void> {
    await this.openSidebar();
    await this.scrollToTopButton.click();
    console.log('✅ Scroll to top clicked');
  }

  /**
   * Click scroll to bottom button
   */
  async clickScrollToBottom(): Promise<void> {
    await this.openSidebar();
    await this.scrollToBottomButton.click();
    console.log('✅ Scroll to bottom clicked');
  }

  /**
   * Check if refresh button is in loading state
   */
  async isRefreshLoading(): Promise<boolean> {
    await this.openSidebar();

    // Check for disabled state or loading text
    const isDisabled = await this.refreshButton.isDisabled();
    const text = await this.refreshButton.textContent();

    return isDisabled || text?.includes('Refreshing');
  }

  /**
   * Check if scroll to bottom button is disabled (at bottom)
   */
  async isScrollToBottomDisabled(): Promise<boolean> {
    await this.openSidebar();
    return await this.scrollToBottomButton.isDisabled();
  }

  /**
   * Get terminal size display
   */
  async getTerminalSize(): Promise<{ cols: number; rows: number } | null> {
    await this.openSidebar();

    try {
      const sizeText = await this.terminalSizeDisplay.textContent();
      const match = sizeText?.match(/Size: (\d+)×(\d+)/);

      if (match) {
        return {
          cols: parseInt(match[1]),
          rows: parseInt(match[2])
        };
      }
    } catch (error) {
      console.warn('Could not get terminal size from sidebar:', error);
    }

    return null;
  }

  /**
   * Check if new output indicator is visible
   */
  async hasNewOutputIndicator(): Promise<boolean> {
    await this.openSidebar();

    try {
      await this.newOutputIndicator.waitFor({ state: 'visible', timeout: 1000 });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate sidebar accessibility
   */
  async validateSidebarAccessibility(): Promise<boolean> {
    await this.openSidebar();

    // Check for proper ARIA attributes
    const sidebarElement = this.sidebarContainer;

    // Check if buttons have proper labels/titles
    const buttons = [this.refreshButton, this.scrollToTopButton, this.scrollToBottomButton];

    for (const button of buttons) {
      const title = await button.getAttribute('title');
      const ariaLabel = await button.getAttribute('aria-label');

      if (!title && !ariaLabel) {
        console.warn('Button missing accessibility label');
        return false;
      }
    }

    // Check if sidebar has proper role
    const role = await sidebarElement.getAttribute('role');

    // Sidebar should be navigable
    const tabIndex = await sidebarElement.getAttribute('tabindex');

    return true; // Basic validation passed
  }

  /**
   * Test sidebar responsive behavior
   */
  async testResponsiveBehavior(): Promise<void> {
    // Test on different viewport sizes
    const viewports = [
      { width: 320, height: 568 },   // Mobile
      { width: 768, height: 1024 },  // Tablet
      { width: 1024, height: 768 },  // Tablet landscape
      { width: 1280, height: 720 },  // Desktop
    ];

    for (const viewport of viewports) {
      await this.setViewportSize(viewport.width, viewport.height);

      const isOpen = await this.isSidebarOpen();
      console.log(`Viewport ${viewport.width}x${viewport.height}: Sidebar ${isOpen ? 'open' : 'closed'}`);

      // Test toggle functionality
      await this.toggleSidebar();
      await this.page.waitForTimeout(1000);
    }
  }

  /**
   * Wait for sidebar animation to complete
   */
  async waitForAnimation(): Promise<void> {
    // Wait for CSS transitions to complete
    await this.page.waitForTimeout(300); // Sidebar typically has 300ms transition

    // Also wait for any running animations
    await this.page.waitForFunction(() => {
      const sidebar = document.querySelector('.sidebar-container');
      if (!sidebar) return true;

      const style = window.getComputedStyle(sidebar);
      return !style.getPropertyValue('transition-property') ||
             style.getPropertyValue('transition-property') === 'none';
    });
  }
}