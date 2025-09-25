import { test, expect } from '../fixtures/test-fixtures';
import { retryOperation } from '../utils/test-utilities';

/**
 * Comprehensive Terminal Functionality E2E Tests
 * Tests core terminal operations, command execution, and user interactions
 */

test.describe('Terminal Functionality', () => {
  test.beforeEach(async ({ terminalPage, testData }) => {
    await terminalPage.goto();
    await terminalPage.waitForTerminalReady();
  });

  test.describe('Basic Terminal Operations', () => {
    test('should execute basic commands successfully', async ({ terminalPage, testData }) => {
      const commands = testData.getTestCommands();

      for (const { command, expectedOutput, timeout, description, skipOn } of commands) {
        // Skip platform-specific commands
        if (skipOn?.includes(process.platform)) {
          test.skip();
        }

        test.step(`Execute: ${description}`, async () => {
          await terminalPage.executeCommand(command);
          await terminalPage.waitForOutput(expectedOutput, timeout);

          const content = await terminalPage.getTerminalContent();
          expect(content).toContain(expectedOutput);
        });
      }
    });

    test('should handle interactive commands', async ({ terminalPage, testData }) => {
      const interactiveCommands = testData.getInteractiveCommands();

      for (const { command, inputs, expectedOutput, timeout, description, skipOn } of interactiveCommands) {
        if (skipOn?.includes(process.platform)) {
          test.skip();
        }

        test.step(`Interactive: ${description}`, async () => {
          await terminalPage.typeCommand(command);
          await terminalPage.page.keyboard.press('Enter');

          // Provide inputs when prompted
          for (const input of inputs) {
            await terminalPage.page.waitForTimeout(1000); // Wait for prompt
            await terminalPage.page.keyboard.type(input);
            await terminalPage.page.keyboard.press('Enter');
          }

          await terminalPage.waitForOutput(expectedOutput, timeout);
        });
      }
    });

    test('should maintain command history', async ({ terminalPage }) => {
      const testCommands = ['echo "command 1"', 'pwd', 'echo "command 3"'];

      // Execute commands to build history
      for (const command of testCommands) {
        await terminalPage.executeCommand(command);
      }

      // Test history navigation
      await terminalPage.testCommandHistory(testCommands);
    });

    test('should handle terminal interruption (Ctrl+C)', async ({ terminalPage }) => {
      // Start a long-running command
      await terminalPage.typeCommand('ping -c 100 127.0.0.1');
      await terminalPage.page.keyboard.press('Enter');

      // Wait for command to start
      await terminalPage.page.waitForTimeout(2000);

      // Interrupt the command
      await terminalPage.sendInterrupt();

      // Verify command was interrupted
      await terminalPage.page.waitForTimeout(1000);
      const content = await terminalPage.getTerminalContent();
      expect(content).toMatch(/\^C|interrupt/i);
    });

    test('should clear terminal content', async ({ terminalPage }) => {
      // Add some content
      await terminalPage.executeCommand('echo "This will be cleared"');
      await terminalPage.executeCommand('ls -la');

      // Clear terminal
      await terminalPage.clearTerminal();

      // Verify terminal is clear
      const content = await terminalPage.getTerminalContent();
      expect(content).not.toContain('This will be cleared');
    });
  });

  test.describe('Terminal UI Controls', () => {
    test('should scroll to top and bottom', async ({ terminalPage }) => {
      // Generate enough content to require scrolling
      for (let i = 0; i < 50; i++) {
        await terminalPage.executeCommand(`echo "Line ${i}"`);
      }

      // Test scroll to top
      await terminalPage.scrollToTop();
      const isAtTop = await terminalPage.getScrollPosition();
      expect(isAtTop.scrollTop).toBe(0);

      // Test scroll to bottom
      await terminalPage.scrollToBottom();
      const isAtBottom = await terminalPage.isAtBottom();
      expect(isAtBottom).toBe(true);
    });

    test('should refresh terminal connection', async ({ terminalPage }) => {
      // Execute a command first
      await terminalPage.executeCommand('echo "Before refresh"');

      // Refresh terminal
      await terminalPage.refreshTerminal();

      // Verify terminal is still functional
      await terminalPage.executeCommand('echo "After refresh"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('After refresh');
    });

    test('should show new output indicator when scrolled up', async ({ terminalPage }) => {
      // Generate content and scroll up
      for (let i = 0; i < 30; i++) {
        await terminalPage.executeCommand(`echo "Initial line ${i}"`);
      }

      await terminalPage.scrollToTop();

      // Add new content (should trigger indicator)
      await terminalPage.executeCommand('echo "New output"');

      // Check for new output indicator
      const hasIndicator = await terminalPage.hasNewOutput();
      expect(hasIndicator).toBe(true);

      // Scroll to bottom should hide indicator
      await terminalPage.scrollToBottom();
      const indicatorHidden = await terminalPage.hasNewOutput();
      expect(indicatorHidden).toBe(false);
    });

    test('should display terminal size information', async ({ terminalPage }) => {
      const sizeInfo = await terminalPage.getTerminalSize();
      expect(sizeInfo).toBeTruthy();
      expect(sizeInfo?.cols).toBeGreaterThan(0);
      expect(sizeInfo?.rows).toBeGreaterThan(0);
    });
  });

  test.describe('Terminal Error Handling', () => {
    test('should handle command not found errors', async ({ terminalPage, testData }) => {
      const errorScenarios = testData.getErrorScenarios();

      for (const { command, expectedErrorType, expectedErrorText, description } of errorScenarios) {
        test.step(`Error handling: ${description}`, async () => {
          await terminalPage.executeCommand(command);
          await terminalPage.page.waitForTimeout(2000);

          const content = await terminalPage.getTerminalContent();
          expect(content.toLowerCase()).toContain(expectedErrorText.toLowerCase());
        });
      }
    });

    test('should recover from terminal disconnection', async ({ terminalPage, page }) => {
      // Verify initial connection
      await terminalPage.waitForConnection();

      // Simulate network disconnection
      await page.context().setOffline(true);
      await page.waitForTimeout(3000);

      // Restore connection
      await page.context().setOffline(false);

      // Verify reconnection
      await retryOperation(async () => {
        await terminalPage.waitForConnection();
        return true;
      }, 5, 2000);

      // Test terminal functionality after reconnection
      await terminalPage.executeCommand('echo "Reconnection test"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Reconnection test');
    });

    test('should display connection errors gracefully', async ({ terminalPage }) => {
      const errors = await terminalPage.checkForErrors();

      // If errors are present, they should be user-friendly
      for (const error of errors) {
        expect(error).not.toMatch(/undefined|null|error.*error|stack trace/i);
        expect(error.length).toBeGreaterThan(10); // Should have meaningful content
      }
    });
  });

  test.describe('Terminal Performance', () => {
    test('should handle large output efficiently', async ({ terminalPage, testData }) => {
      const performanceScenarios = testData.getPerformanceScenarios();

      for (const { name, command, metrics, description, skipOn } of performanceScenarios) {
        if (skipOn?.includes(process.platform)) {
          test.skip();
        }

        test.step(`Performance: ${description}`, async () => {
          const startTime = Date.now();
          await terminalPage.executeCommand(command);

          // Wait for command completion with timeout
          await terminalPage.page.waitForTimeout(metrics.maxExecutionTime);

          const executionTime = Date.now() - startTime;
          expect(executionTime).toBeLessThan(metrics.maxExecutionTime);

          // Test terminal responsiveness after large output
          const responsiveTime = await terminalPage.measureInputDelay();
          expect(responsiveTime).toBeLessThan(metrics.minScrollResponsiveness);
        });
      }
    });

    test('should maintain performance during continuous output', async ({ terminalPage, page }) => {
      // Start continuous output command
      await terminalPage.typeCommand('for i in {1..100}; do echo "Line $i"; sleep 0.1; done');
      await page.keyboard.press('Enter');

      // Wait for some output
      await page.waitForTimeout(2000);

      // Test responsiveness during continuous output
      const scrollPosition = await terminalPage.getScrollPosition();
      expect(scrollPosition.scrollHeight).toBeGreaterThan(0);

      // Terminal should still respond to interactions
      await terminalPage.terminalContainer.click();
      await terminalPage.sendInterrupt(); // Stop the loop

      // Verify interruption worked
      await page.waitForTimeout(1000);
      const finalContent = await terminalPage.getTerminalContent();
      expect(finalContent).toMatch(/\^C|interrupt/i);
    });

    test('should handle rapid command execution', async ({ terminalPage }) => {
      const commands = [
        'echo "cmd1"',
        'pwd',
        'whoami',
        'date',
        'echo "cmd5"',
      ];

      const startTime = Date.now();

      // Execute commands rapidly
      for (const command of commands) {
        await terminalPage.typeCommand(command);
        await terminalPage.page.keyboard.press('Enter');
        await terminalPage.page.waitForTimeout(200); // Minimal delay
      }

      // Wait for all commands to complete
      await terminalPage.waitForOutput('cmd5', 10000);

      const totalTime = Date.now() - startTime;
      expect(totalTime).toBeLessThan(15000); // Should complete within reasonable time

      // Verify all commands executed
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('cmd1');
      expect(content).toContain('cmd5');
    });
  });

  test.describe('Terminal Accessibility', () => {
    test('should be keyboard accessible', async ({ terminalPage, page }) => {
      // Test keyboard navigation to terminal
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');

      // Terminal should be focusable
      const activeElement = await page.evaluate(() => document.activeElement?.tagName);
      expect(['DIV', 'TEXTAREA', 'INPUT']).toContain(activeElement);

      // Test keyboard shortcuts
      await terminalPage.terminalContainer.click();
      await page.keyboard.press('Control+l'); // Clear terminal
      await page.waitForTimeout(500);

      const content = await terminalPage.getTerminalContent();
      expect(content.trim().length).toBeLessThan(100); // Should be mostly cleared
    });

    test('should have proper ARIA attributes', async ({ terminalPage }) => {
      const ariaLabel = await terminalPage.terminalContainer.getAttribute('aria-label');
      const role = await terminalPage.terminalContainer.getAttribute('role');

      expect(ariaLabel || role).toBeTruthy();

      if (role) {
        expect(['textbox', 'application', 'log']).toContain(role);
      }
    });

    test('should support screen readers', async ({ terminalPage }) => {
      // Test that terminal content is accessible to screen readers
      const terminalText = await terminalPage.getTerminalContent();

      // Execute a command and verify accessibility
      await terminalPage.executeCommand('echo "Screen reader test"');
      await terminalPage.waitForOutput('Screen reader test');

      const updatedText = await terminalPage.getTerminalContent();
      expect(updatedText).toContain('Screen reader test');
      expect(updatedText.length).toBeGreaterThan(terminalText.length);
    });
  });

  test.describe('Terminal Resize and Responsiveness', () => {
    test('should adapt to viewport changes', async ({ terminalPage, page }) => {
      // Get initial size
      const initialSize = await terminalPage.getTerminalSize();

      // Resize viewport
      await page.setViewportSize({ width: 800, height: 600 });
      await page.waitForTimeout(1000);

      // Check if terminal adapted
      const newSize = await terminalPage.getTerminalSize();
      expect(newSize).toBeTruthy();

      // Terminal should still be functional after resize
      await terminalPage.executeCommand('echo "Resize test"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Resize test');
    });

    test('should handle programmatic resize', async ({ terminalPage }) => {
      const originalSize = await terminalPage.getTerminalSize();

      // Trigger resize
      await terminalPage.resizeTerminal(100, 30);

      // Verify resize worked
      const newSize = await terminalPage.getTerminalSize();
      if (newSize && originalSize) {
        expect(newSize.cols).not.toBe(originalSize.cols);
      }

      // Terminal should remain functional
      await terminalPage.executeCommand('echo "After resize"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('After resize');
    });
  });

  test.afterEach(async ({ page }) => {
    // Clean up any test utilities
    const utilities = (page as any).testUtilities;
    if (utilities) {
      await utilities.cleanup();
    }
  });
});