import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for Terminal component interactions
 * Handles terminal input/output, command execution, and terminal-specific operations
 */
export class TerminalPage extends BasePage {
  readonly terminalContainer: Locator;
  readonly terminalWrapper: Locator;
  readonly xtermViewport: Locator;
  readonly refreshButton: Locator;
  readonly scrollToTopButton: Locator;
  readonly scrollToBottomButton: Locator;
  readonly newOutputIndicator: Locator;
  readonly terminalSizeInfo: Locator;
  readonly connectionStatus: Locator;
  readonly loadingSpinner: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Terminal elements
    this.terminalContainer = page.locator('.terminal-container');
    this.terminalWrapper = page.locator('.xterm-wrapper');
    this.xtermViewport = page.locator('.xterm-viewport');

    // Terminal controls
    this.refreshButton = page.locator('button', { hasText: 'Refresh' });
    this.scrollToTopButton = page.locator('button', { hasText: 'Top' });
    this.scrollToBottomButton = page.locator('button', { hasText: 'Bottom' });

    // Status indicators
    this.newOutputIndicator = page.locator('[data-testid="new-output-indicator"], .text-yellow-400:has-text("New output")');
    this.terminalSizeInfo = page.locator('text=/Size: \\d+×\\d+/');
    this.connectionStatus = page.locator('.text-green-500, .bg-green-500', { hasText: 'Connected' });
    this.loadingSpinner = page.locator('.animate-spin, [data-testid="loading-spinner"]');
    this.errorMessage = page.locator('.text-red-400, .text-red-500, .bg-red-600');
  }

  /**
   * Wait for terminal to be ready and connected
   */
  async waitForTerminalReady(): Promise<void> {
    // Wait for terminal container to be visible
    await this.terminalContainer.waitFor({ state: 'visible', timeout: 15000 });

    // Wait for xterm to be initialized
    await this.xtermViewport.waitFor({ state: 'visible', timeout: 10000 });

    // Wait for loading to complete
    await this.waitForLoadingComplete();

    console.log('✅ Terminal ready');
  }

  /**
   * Wait for loading states to complete
   */
  async waitForLoadingComplete(): Promise<void> {
    // Wait for loading spinners to disappear
    try {
      await this.loadingSpinner.waitFor({ state: 'hidden', timeout: 5000 });
    } catch (error) {
      // Spinner might not exist, which is fine
    }

    // Wait for network to be idle
    await this.waitForNetworkIdle();
  }

  /**
   * Type a command in the terminal
   */
  async typeCommand(command: string): Promise<void> {
    await this.waitForTerminalReady();

    // Click on terminal to ensure focus
    await this.terminalContainer.click();

    // Wait a moment for focus
    await this.page.waitForTimeout(500);

    // Type the command
    await this.page.keyboard.type(command);

    console.log(`✅ Typed command: ${command}`);
  }

  /**
   * Execute a command (type + press Enter)
   */
  async executeCommand(command: string): Promise<void> {
    await this.typeCommand(command);
    await this.page.keyboard.press('Enter');

    // Wait for command to process
    await this.page.waitForTimeout(1000);

    console.log(`✅ Executed command: ${command}`);
  }

  /**
   * Wait for specific output to appear in terminal
   */
  async waitForOutput(text: string, timeout: number = 10000): Promise<void> {
    await this.page.waitForFunction(
      (searchText) => {
        const terminal = document.querySelector('.xterm-screen');
        return terminal?.textContent?.includes(searchText);
      },
      text,
      { timeout }
    );

    console.log(`✅ Found output: ${text}`);
  }

  /**
   * Get current terminal output content
   */
  async getTerminalContent(): Promise<string> {
    await this.waitForTerminalReady();

    const content = await this.page.evaluate(() => {
      const screen = document.querySelector('.xterm-screen');
      return screen?.textContent || '';
    });

    return content;
  }

  /**
   * Clear terminal using Ctrl+L
   */
  async clearTerminal(): Promise<void> {
    await this.terminalContainer.click();
    await this.page.keyboard.press('Control+l');
    await this.page.waitForTimeout(500);

    console.log('✅ Terminal cleared');
  }

  /**
   * Send interrupt signal (Ctrl+C)
   */
  async sendInterrupt(): Promise<void> {
    await this.terminalContainer.click();
    await this.page.keyboard.press('Control+c');
    await this.page.waitForTimeout(500);

    console.log('✅ Interrupt signal sent');
  }

  /**
   * Scroll terminal to top
   */
  async scrollToTop(): Promise<void> {
    await this.scrollToTopButton.click();
    await this.page.waitForTimeout(500);

    console.log('✅ Scrolled to top');
  }

  /**
   * Scroll terminal to bottom
   */
  async scrollToBottom(): Promise<void> {
    await this.scrollToBottomButton.click();
    await this.page.waitForTimeout(500);

    console.log('✅ Scrolled to bottom');
  }

  /**
   * Refresh terminal
   */
  async refreshTerminal(): Promise<void> {
    await this.refreshButton.click();

    // Wait for refresh to complete
    await this.page.waitForTimeout(2000);
    await this.waitForTerminalReady();

    console.log('✅ Terminal refreshed');
  }

  /**
   * Check if terminal is at bottom
   */
  async isAtBottom(): Promise<boolean> {
    const isDisabled = await this.scrollToBottomButton.isDisabled();
    return isDisabled;
  }

  /**
   * Check if new output indicator is visible
   */
  async hasNewOutput(): Promise<boolean> {
    try {
      await this.newOutputIndicator.waitFor({ state: 'visible', timeout: 1000 });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get terminal size information
   */
  async getTerminalSize(): Promise<{ cols: number; rows: number } | null> {
    try {
      const sizeText = await this.terminalSizeInfo.textContent();
      const match = sizeText?.match(/Size: (\d+)×(\d+)/);

      if (match) {
        return {
          cols: parseInt(match[1]),
          rows: parseInt(match[2])
        };
      }
    } catch (error) {
      console.warn('Could not get terminal size:', error);
    }

    return null;
  }

  /**
   * Wait for terminal to show connection status
   */
  async waitForConnection(): Promise<void> {
    await this.page.waitForFunction(
      () => {
        const statusElements = document.querySelectorAll('.text-green-500, .bg-green-500');
        return Array.from(statusElements).some(el =>
          el.textContent?.includes('Connected') ||
          el.textContent?.includes('Terminal Connected')
        );
      },
      { timeout: 15000 }
    );

    console.log('✅ Terminal connected');
  }

  /**
   * Check for terminal error states
   */
  async checkForErrors(): Promise<string[]> {
    const errors: string[] = [];

    // Check for error messages in the UI
    const errorElements = await this.errorMessage.all();

    for (const element of errorElements) {
      try {
        const text = await element.textContent();
        if (text && text.trim()) {
          errors.push(text.trim());
        }
      } catch (error) {
        // Element might be detached
      }
    }

    return errors;
  }

  /**
   * Measure input delay
   */
  async measureInputDelay(testCommand: string = 'echo test'): Promise<number> {
    await this.waitForTerminalReady();

    const startTime = Date.now();
    await this.typeCommand(testCommand);
    await this.page.keyboard.press('Enter');

    // Wait for output to appear
    await this.waitForOutput('test');
    const endTime = Date.now();

    return endTime - startTime;
  }

  /**
   * Get terminal scroll position
   */
  async getScrollPosition(): Promise<{ scrollTop: number; scrollHeight: number }> {
    return await this.page.evaluate(() => {
      const viewport = document.querySelector('.xterm-viewport') as HTMLElement;
      if (viewport) {
        return {
          scrollTop: viewport.scrollTop,
          scrollHeight: viewport.scrollHeight
        };
      }
      return { scrollTop: 0, scrollHeight: 0 };
    });
  }

  /**
   * Simulate terminal resize
   */
  async resizeTerminal(cols: number, rows: number): Promise<void> {
    await this.page.evaluate(({ cols, rows }) => {
      window.dispatchEvent(new Event('resize'));
      // If terminal has resize method exposed globally
      if ('terminal' in window && typeof (window as any).terminal?.resize === 'function') {
        (window as any).terminal.resize(cols, rows);
      }
    }, { cols, rows });

    await this.page.waitForTimeout(1000);

    console.log(`✅ Terminal resized to ${cols}×${rows}`);
  }

  /**
   * Test command history navigation
   */
  async testCommandHistory(commands: string[]): Promise<void> {
    // Execute commands to build history
    for (const command of commands) {
      await this.executeCommand(command);
    }

    // Test arrow up navigation
    await this.terminalContainer.click();

    // Go through history backwards
    for (let i = commands.length - 1; i >= 0; i--) {
      await this.page.keyboard.press('ArrowUp');
      await this.page.waitForTimeout(200);

      // Get current line content
      const currentLine = await this.page.evaluate(() => {
        const activeElement = document.querySelector('.xterm-cursor-layer .xterm-cursor-block');
        const line = activeElement?.closest('.xterm-row');
        return line?.textContent || '';
      });

      expect(currentLine).toContain(commands[i]);
    }

    console.log('✅ Command history tested');
  }
}