import { Page, Locator } from '@playwright/test';
import { BasePage } from './BasePage';
import { TerminalPage } from './TerminalPage';

/**
 * Backstage Integration Page Object Model
 * Handles Backstage-specific interactions and navigation patterns
 */
export class BackstagePage extends BasePage {
  private readonly terminalPage: TerminalPage;

  // Backstage-specific selectors
  private readonly sidebar = '[data-testid="sidebar"], .MuiDrawer-root, .backstage-sidebar';
  private readonly sidebarToggle = '[data-testid="sidebar-toggle"], button[aria-label*="menu"], .sidebar-toggle';
  private readonly header = '[data-testid="header"], .MuiAppBar-root, .backstage-header';
  private readonly pageHeader = '[data-testid="page-header"], .backstage-page-header';
  private readonly signInButton = '[data-testid="sign-in"], button:has-text("Sign In")';
  private readonly userMenu = '[data-testid="user-menu"], .user-menu, .MuiAvatar-root';

  // Claude Flow plugin selectors
  private readonly claudeFlowSidebarLink = 'a[href*="claude-flow"], a:has-text("Claude Flow")';
  private readonly claudeFlowPage = '.claude-flow-page, [data-plugin="claude-flow"]';

  // Theme and settings
  private readonly themeToggle = '[data-testid="theme-toggle"], button:has-text("Theme")';
  private readonly settingsMenu = '[data-testid="settings"], .settings-menu';

  // Entity and context selectors
  private readonly entityHeader = '[data-testid="entity-header"], .entity-header';
  private readonly entityTabs = '[data-testid="entity-tabs"], .entity-tabs';
  private readonly breadcrumbs = '[data-testid="breadcrumbs"], .backstage-breadcrumbs';

  // Permission and access control
  private readonly permissionDenied = '[data-testid="permission-denied"], .permission-denied';
  private readonly accessError = '[data-testid="access-error"], .access-error';

  constructor(page: Page) {
    super(page);
    this.terminalPage = new TerminalPage(page);
  }

  /**
   * Navigate to Backstage root
   */
  async navigateToBackstage(): Promise<void> {
    await this.goto();
    await this.waitForBackstageLoad();
  }

  /**
   * Wait for Backstage core components to load
   */
  async waitForBackstageLoad(): Promise<void> {
    // Wait for core Backstage components
    await this.waitForElement(this.sidebar, 15000);
    await this.waitForNetworkIdle();

    // Ensure page is fully interactive
    await this.page.waitForFunction(() => {
      return document.readyState === 'complete' &&
             !document.querySelector('.loading, .spinner, [data-testid="loading"]');
    }, { timeout: 10000 });
  }

  /**
   * Authenticate user if login is required
   */
  async authenticateUser(username: string = 'test-user', password: string = 'test-password'): Promise<void> {
    // Check if already authenticated
    if (await this.isElementVisible(this.userMenu, 2000)) {
      return; // Already logged in
    }

    // Look for sign-in button
    if (await this.isElementVisible(this.signInButton, 5000)) {
      await this.clickElement(this.signInButton);

      // Handle different authentication flows
      await this.handleAuthenticationFlow(username, password);
    }
  }

  /**
   * Handle various authentication flows
   */
  private async handleAuthenticationFlow(username: string, password: string): Promise<void> {
    // Wait for auth form or redirect
    await this.page.waitForTimeout(2000);

    // Check for username field (form auth)
    const usernameField = 'input[name="username"], input[type="email"], input[placeholder*="username"], input[placeholder*="email"]';
    if (await this.isElementVisible(usernameField, 3000)) {
      await this.typeText(usernameField, username);

      const passwordField = 'input[name="password"], input[type="password"], input[placeholder*="password"]';
      if (await this.isElementVisible(passwordField, 2000)) {
        await this.typeText(passwordField, password);

        // Submit form
        const submitButton = 'button[type="submit"], button:has-text("Sign In"), button:has-text("Login")';
        if (await this.isElementVisible(submitButton)) {
          await this.clickElement(submitButton);
        } else {
          await this.page.keyboard.press('Enter');
        }
      }
    }

    // Wait for authentication to complete
    await this.waitForBackstageLoad();
  }

  /**
   * Navigate to Claude Flow plugin
   */
  async navigateToClaudeFlowPlugin(): Promise<void> {
    // First try clicking sidebar link
    if (await this.isElementVisible(this.claudeFlowSidebarLink, 3000)) {
      await this.clickElement(this.claudeFlowSidebarLink);
    } else {
      // Direct navigation as fallback
      await this.goto('/claude-flow');
    }

    // Wait for plugin page to load
    await this.page.waitForURL('**/claude-flow**', { timeout: 10000 });
    await this.waitForNetworkIdle();

    // Wait for terminal to be ready
    await this.terminalPage.waitForTerminalReady();
  }

  /**
   * Check if Claude Flow plugin is available in sidebar
   */
  async isClaudeFlowPluginAvailable(): Promise<boolean> {
    return await this.isElementVisible(this.claudeFlowSidebarLink, 5000);
  }

  /**
   * Get sidebar navigation links
   */
  async getSidebarLinks(): Promise<Array<{ text: string; href: string }>> {
    const sidebarElement = this.page.locator(this.sidebar);
    const links = sidebarElement.locator('a');
    const linkCount = await links.count();

    const linkData: Array<{ text: string; href: string }> = [];

    for (let i = 0; i < linkCount; i++) {
      const link = links.nth(i);
      const text = (await link.textContent()) || '';
      const href = (await link.getAttribute('href')) || '';

      if (text.trim() && href) {
        linkData.push({ text: text.trim(), href });
      }
    }

    return linkData;
  }

  /**
   * Toggle sidebar visibility
   */
  async toggleSidebar(): Promise<void> {
    if (await this.isElementVisible(this.sidebarToggle)) {
      await this.clickElement(this.sidebarToggle);
      await this.page.waitForTimeout(500);
    }
  }

  /**
   * Check if sidebar is visible
   */
  async isSidebarVisible(): Promise<boolean> {
    return await this.isElementVisible(this.sidebar, 2000);
  }

  /**
   * Switch theme (if available)
   */
  async switchTheme(): Promise<void> {
    if (await this.isElementVisible(this.themeToggle)) {
      await this.clickElement(this.themeToggle);
      await this.page.waitForTimeout(1000); // Allow theme to apply
    }
  }

  /**
   * Get current theme
   */
  async getCurrentTheme(): Promise<'light' | 'dark' | 'unknown'> {
    const bodyClass = await this.page.getAttribute('body', 'class') || '';
    const htmlClass = await this.page.getAttribute('html', 'class') || '';
    const classes = `${bodyClass} ${htmlClass}`.toLowerCase();

    if (classes.includes('dark')) return 'dark';
    if (classes.includes('light')) return 'light';
    return 'unknown';
  }

  /**
   * Get page breadcrumbs
   */
  async getBreadcrumbs(): Promise<string[]> {
    if (await this.isElementVisible(this.breadcrumbs)) {
      const breadcrumbText = await this.getElementText(this.breadcrumbs);
      return breadcrumbText.split('/').map(crumb => crumb.trim()).filter(Boolean);
    }
    return [];
  }

  /**
   * Check if user has permissions for current page
   */
  async hasPagePermissions(): Promise<boolean> {
    // Check for permission denied messages
    const hasPermissionError = await this.isElementVisible(this.permissionDenied, 2000) ||
                              await this.isElementVisible(this.accessError, 2000);

    return !hasPermissionError;
  }

  /**
   * Get entity context (if on entity page)
   */
  async getEntityContext(): Promise<{ name: string; kind: string; namespace: string } | null> {
    if (await this.isElementVisible(this.entityHeader, 3000)) {
      const headerText = await this.getElementText(this.entityHeader);

      // Try to extract entity information from header
      // This is context-dependent and may need adjustment based on Backstage setup
      const nameMatch = headerText.match(/([^\/\s]+)$/);
      const name = nameMatch ? nameMatch[1] : '';

      return {
        name,
        kind: 'component', // Default, could be extracted from URL or other elements
        namespace: 'default',
      };
    }

    return null;
  }

  /**
   * Navigate to entity page
   */
  async navigateToEntity(kind: string, namespace: string, name: string): Promise<void> {
    const entityUrl = `/catalog/${namespace}/${kind}/${name}`;
    await this.goto(entityUrl);
    await this.waitForBackstageLoad();
  }

  /**
   * Get available entity tabs
   */
  async getEntityTabs(): Promise<string[]> {
    if (await this.isElementVisible(this.entityTabs)) {
      const tabs = this.page.locator(`${this.entityTabs} a, ${this.entityTabs} button`);
      const tabCount = await tabs.count();
      const tabTexts: string[] = [];

      for (let i = 0; i < tabCount; i++) {
        const text = await tabs.nth(i).textContent();
        if (text?.trim()) {
          tabTexts.push(text.trim());
        }
      }

      return tabTexts;
    }

    return [];
  }

  /**
   * Click entity tab
   */
  async clickEntityTab(tabName: string): Promise<void> {
    const tabSelector = `${this.entityTabs} a:has-text("${tabName}"), ${this.entityTabs} button:has-text("${tabName}")`;
    if (await this.isElementVisible(tabSelector)) {
      await this.clickElement(tabSelector);
      await this.page.waitForTimeout(1000);
    }
  }

  /**
   * Check Backstage keyboard shortcuts
   */
  async testKeyboardShortcuts(): Promise<{ search: boolean; help: boolean }> {
    const results = { search: false, help: false };

    // Test search shortcut (usually Ctrl+K or Cmd+K)
    await this.page.keyboard.press('Control+k');
    await this.page.waitForTimeout(500);

    // Check if search modal or input appeared
    const searchVisible = await this.isElementVisible(
      '[data-testid="search"], .search-modal, input[placeholder*="search"]',
      2000
    );
    results.search = searchVisible;

    // Close search if it opened
    if (searchVisible) {
      await this.page.keyboard.press('Escape');
      await this.page.waitForTimeout(300);
    }

    // Test help shortcut (usually ? key)
    await this.page.keyboard.press('?');
    await this.page.waitForTimeout(500);

    const helpVisible = await this.isElementVisible(
      '[data-testid="help"], .help-modal, .shortcuts-modal',
      2000
    );
    results.help = helpVisible;

    // Close help if it opened
    if (helpVisible) {
      await this.page.keyboard.press('Escape');
      await this.page.waitForTimeout(300);
    }

    return results;
  }

  /**
   * Validate Backstage layout integrity
   */
  async validateLayoutIntegrity(): Promise<{
    hasSidebar: boolean;
    hasHeader: boolean;
    hasContent: boolean;
    isResponsive: boolean;
  }> {
    const hasSidebar = await this.isSidebarVisible();
    const hasHeader = await this.isElementVisible(this.header);
    const hasContent = await this.isElementVisible('main, .content, [role="main"]');

    // Test responsive behavior
    const originalSize = this.page.viewportSize();
    await this.setViewportSize(768, 1024); // Tablet size
    await this.page.waitForTimeout(500);

    const isResponsiveTablet = await this.page.evaluate(() => {
      const sidebar = document.querySelector('[data-testid="sidebar"], .MuiDrawer-root');
      if (!sidebar) return true; // No sidebar to test

      const sidebarStyles = window.getComputedStyle(sidebar as Element);
      return sidebarStyles.transform.includes('translate') || sidebarStyles.display === 'none';
    });

    // Restore original viewport
    if (originalSize) {
      await this.setViewportSize(originalSize.width, originalSize.height);
    }

    return {
      hasSidebar,
      hasHeader,
      hasContent,
      isResponsive: isResponsiveTablet,
    };
  }

  /**
   * Get terminal page instance for terminal-specific operations
   */
  getTerminalPage(): TerminalPage {
    return this.terminalPage;
  }

  /**
   * Wait for Claude Flow plugin to load completely
   */
  async waitForClaudeFlowPluginLoad(): Promise<void> {
    // Wait for plugin container
    await this.waitForElement(this.claudeFlowPage);

    // Wait for terminal to be ready
    await this.terminalPage.waitForTerminalReady();

    // Ensure WebSocket connection is established
    await this.waitForWebSocketConnection();
  }

  /**
   * Test plugin integration stability
   */
  async testPluginStability(): Promise<{
    initialLoad: boolean;
    navigation: boolean;
    refresh: boolean;
    backNavigation: boolean;
  }> {
    const results = {
      initialLoad: false,
      navigation: false,
      refresh: false,
      backNavigation: false,
    };

    try {
      // Test initial load
      await this.navigateToClaudeFlowPlugin();
      results.initialLoad = await this.terminalPage.isConnected();

      // Test navigation away and back
      await this.goto('/');
      await this.waitForBackstageLoad();
      await this.navigateToClaudeFlowPlugin();
      results.navigation = await this.terminalPage.isConnected();

      // Test page refresh
      await this.page.reload();
      await this.waitForBackstageLoad();
      await this.terminalPage.waitForTerminalReady();
      results.refresh = await this.terminalPage.isConnected();

      // Test browser back button
      await this.goto('/');
      await this.waitForBackstageLoad();
      await this.page.goBack();
      await this.terminalPage.waitForTerminalReady();
      results.backNavigation = await this.terminalPage.isConnected();

    } catch (error) {
      console.error('Plugin stability test failed:', error);
    }

    return results;
  }
}