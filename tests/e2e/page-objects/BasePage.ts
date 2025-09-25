import { Page, Locator, expect } from '@playwright/test';

/**
 * Base Page Object Model class
 * Provides common functionality and patterns for all page objects
 */
export abstract class BasePage {
  protected readonly page: Page;
  protected readonly baseURL: string;

  constructor(page: Page) {
    this.page = page;
    this.baseURL = process.env.BASE_URL || 'http://localhost:11235';
  }

  /**
   * Navigate to a specific path
   */
  async goto(path: string = '') {
    const url = `${this.baseURL}${path}`;
    await this.page.goto(url, { waitUntil: 'networkidle' });
    await this.waitForPageLoad();
  }

  /**
   * Wait for page to be fully loaded
   */
  async waitForPageLoad() {
    await this.page.waitForLoadState('networkidle');
    await this.page.waitForLoadState('domcontentloaded');
  }

  /**
   * Get page title
   */
  async getTitle(): Promise<string> {
    return await this.page.title();
  }

  /**
   * Get current URL
   */
  getCurrentURL(): string {
    return this.page.url();
  }

  /**
   * Wait for element to be visible
   */
  async waitForElement(selector: string, timeout: number = 10000): Promise<Locator> {
    const element = this.page.locator(selector);
    await element.waitFor({ state: 'visible', timeout });
    return element;
  }

  /**
   * Wait for element to be hidden
   */
  async waitForElementHidden(selector: string, timeout: number = 10000) {
    const element = this.page.locator(selector);
    await element.waitFor({ state: 'hidden', timeout });
  }

  /**
   * Click element with retry logic
   */
  async clickElement(selector: string, options?: { timeout?: number; retries?: number }) {
    const { timeout = 10000, retries = 3 } = options || {};
    let lastError: Error;

    for (let i = 0; i < retries; i++) {
      try {
        const element = await this.waitForElement(selector, timeout);
        await element.click({ timeout });
        return;
      } catch (error) {
        lastError = error as Error;
        if (i < retries - 1) {
          await this.page.waitForTimeout(1000); // Wait before retry
        }
      }
    }

    throw new Error(`Failed to click element ${selector} after ${retries} retries. Last error: ${lastError!.message}`);
  }

  /**
   * Type text with clear and retry logic
   */
  async typeText(selector: string, text: string, options?: { timeout?: number; clear?: boolean }) {
    const { timeout = 10000, clear = true } = options || {};
    const element = await this.waitForElement(selector, timeout);

    if (clear) {
      await element.clear({ timeout });
    }

    await element.fill(text, { timeout });
  }

  /**
   * Get text content of element
   */
  async getElementText(selector: string): Promise<string> {
    const element = await this.waitForElement(selector);
    return (await element.textContent()) || '';
  }

  /**
   * Check if element is visible
   */
  async isElementVisible(selector: string, timeout: number = 5000): Promise<boolean> {
    try {
      await this.waitForElement(selector, timeout);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if element is enabled
   */
  async isElementEnabled(selector: string): Promise<boolean> {
    const element = this.page.locator(selector);
    return await element.isEnabled();
  }

  /**
   * Get element attribute
   */
  async getElementAttribute(selector: string, attribute: string): Promise<string | null> {
    const element = await this.waitForElement(selector);
    return await element.getAttribute(attribute);
  }

  /**
   * Take screenshot with custom name
   */
  async takeScreenshot(name: string) {
    await this.page.screenshot({
      path: `tests/e2e/screenshots/${name}-${Date.now()}.png`,
      fullPage: true,
    });
  }

  /**
   * Wait for network to be idle
   */
  async waitForNetworkIdle(timeout: number = 30000) {
    await this.page.waitForLoadState('networkidle', { timeout });
  }

  /**
   * Wait for WebSocket connection to be established
   */
  async waitForWebSocketConnection(timeout: number = 15000): Promise<boolean> {
    try {
      await this.page.waitForFunction(() => {
        return window.WebSocket &&
               document.querySelector('[data-ws-connected="true"], .ws-connected') !== null;
      }, { timeout });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Execute JavaScript in page context
   */
  async executeScript<T>(script: string): Promise<T> {
    return await this.page.evaluate(script);
  }

  /**
   * Get console messages
   */
  getConsoleMessages(): Array<{ type: string; text: string }> {
    const messages: Array<{ type: string; text: string }> = [];

    this.page.on('console', msg => {
      messages.push({
        type: msg.type(),
        text: msg.text(),
      });
    });

    return messages;
  }

  /**
   * Handle JavaScript errors
   */
  handlePageErrors(): Array<Error> {
    const errors: Array<Error> = [];

    this.page.on('pageerror', error => {
      errors.push(error);
    });

    return errors;
  }

  /**
   * Simulate offline/online scenarios
   */
  async setNetworkConditions(offline: boolean) {
    await this.page.context().setOffline(offline);
  }

  /**
   * Add custom CSS to page for testing
   */
  async addCustomCSS(css: string) {
    await this.page.addStyleTag({ content: css });
  }

  /**
   * Add custom JavaScript to page
   */
  async addCustomJS(js: string) {
    await this.page.addScriptTag({ content: js });
  }

  /**
   * Clear browser storage
   */
  async clearStorage() {
    await this.page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  }

  /**
   * Set viewport size
   */
  async setViewportSize(width: number, height: number) {
    await this.page.setViewportSize({ width, height });
  }

  /**
   * Validate page accessibility
   */
  async validateAccessibility() {
    // This would integrate with axe-core for comprehensive a11y testing
    const violations = await this.page.evaluate(async () => {
      if (typeof (window as any).axe !== 'undefined') {
        const results = await (window as any).axe.run();
        return results.violations;
      }
      return [];
    });

    return violations;
  }

  /**
   * Measure page performance metrics
   */
  async measurePerformance() {
    const metrics = await this.page.evaluate(() => {
      const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      const paintData = performance.getEntriesByType('paint');

      return {
        loadTime: perfData.loadEventEnd - perfData.loadEventStart,
        domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
        firstContentfulPaint: paintData.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
        largestContentfulPaint: paintData.find(p => p.name === 'largest-contentful-paint')?.startTime || 0,
      };
    });

    return metrics;
  }
}

/**
 * Interface for page object constructors
 */
export interface PageObjectConstructor<T extends BasePage> {
  new (page: Page): T;
}