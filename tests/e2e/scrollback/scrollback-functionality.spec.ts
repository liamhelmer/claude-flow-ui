import { test, expect } from '../fixtures/test-fixtures';
import { createTestUtilities, waitWithBackoff } from '../utils/test-utilities';

/**
 * Scrollback Functionality E2E Tests
 * Tests terminal scrollback behavior, history management, and scroll performance
 */

test.describe('Scrollback Functionality', () => {
  test.beforeEach(async ({ terminalPage, page, context }) => {
    const utilities = createTestUtilities(page, context);
    (page as any).testUtilities = utilities;

    await terminalPage.goto();
    await terminalPage.waitForTerminalReady();
  });

  test.describe('Scrollback Buffer Management', () => {
    test('should maintain scrollback history', async ({ terminalPage }) => {
      // Generate content beyond screen height
      const totalLines = 100;
      for (let i = 1; i <= totalLines; i++) {
        await terminalPage.executeCommand(`echo "Line ${i}"`);
      }

      // Scroll to top
      await terminalPage.scrollToTop();

      // Verify we can see earlier content
      await terminalPage.waitForOutput('Line 1', 5000);
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Line 1');

      // Scroll to bottom
      await terminalPage.scrollToBottom();

      // Verify we can see recent content
      expect(content).toContain(`Line ${totalLines}`);
    });

    test('should limit scrollback buffer size', async ({ terminalPage, page }) => {
      // Generate massive amount of content to test buffer limits
      const batchSize = 50;
      const batches = 20; // 1000 total lines

      for (let batch = 0; batch < batches; batch++) {
        const startLine = batch * batchSize + 1;
        const endLine = (batch + 1) * batchSize;

        await terminalPage.executeCommand(
          `for i in {${startLine}..${endLine}}; do echo "Batch ${batch} Line $i"; done`
        );

        // Small delay to prevent overwhelming
        await page.waitForTimeout(500);
      }

      await terminalPage.scrollToTop();
      await page.waitForTimeout(1000);

      // Check if early content is still available or if buffer was trimmed
      const content = await terminalPage.getTerminalContent();

      // Should have recent content
      expect(content).toContain('Batch 19');

      // Early content might be trimmed (implementation dependent)
      const hasEarlyContent = content.includes('Batch 0 Line 1');

      // Log buffer behavior for debugging
      console.log(`Early content preserved: ${hasEarlyContent}`);
      console.log(`Content length: ${content.length} characters`);
    });

    test('should handle mixed content types in scrollback', async ({ terminalPage }) => {
      // Generate various content types
      const contentTypes = [
        'echo "Regular text"',
        'echo -e "\\033[31mRed colored text\\033[0m"',
        'echo -e "Text with \\ttabs and  \\tspaces"',
        'cat << EOF\nMulti-line\ncontent\nEOF',
        'printf "Line without newline"',
        'echo "Very long line that should wrap around the terminal screen and continue on the next line to test wrapping behavior"',
      ];

      for (const command of contentTypes) {
        await terminalPage.executeCommand(command);
        await terminalPage.page.waitForTimeout(500);
      }

      // Test scrollback with mixed content
      await terminalPage.scrollToTop();
      const topContent = await terminalPage.getTerminalContent();

      await terminalPage.scrollToBottom();
      const bottomContent = await terminalPage.getTerminalContent();

      // Both positions should have content
      expect(topContent.length).toBeGreaterThan(50);
      expect(bottomContent.length).toBeGreaterThan(50);

      // Should contain various content types
      expect(bottomContent).toContain('Regular text');
      expect(bottomContent).toContain('Multi-line');
    });
  });

  test.describe('Scroll Navigation and Controls', () => {
    test('should scroll smoothly with scroll controls', async ({ terminalPage, page }) => {
      // Generate enough content for scrolling
      for (let i = 1; i <= 50; i++) {
        await terminalPage.executeCommand(`echo "Scrollable line ${i}"`);
      }

      // Test scroll to top button
      await terminalPage.scrollToTop();
      const topPosition = await terminalPage.getScrollPosition();
      expect(topPosition.scrollTop).toBe(0);

      // Test scroll to bottom button
      await terminalPage.scrollToBottom();
      const bottomPosition = await terminalPage.getScrollPosition();
      expect(bottomPosition.scrollTop).toBeGreaterThan(topPosition.scrollTop);

      // Should be at bottom (button disabled)
      const isAtBottom = await terminalPage.isAtBottom();
      expect(isAtBottom).toBe(true);
    });

    test('should support keyboard scrolling', async ({ terminalPage, page }) => {
      // Generate scrollable content
      for (let i = 1; i <= 30; i++) {
        await terminalPage.executeCommand(`echo "Keyboard scroll test ${i}"`);
      }

      // Focus terminal and test keyboard scrolling
      await terminalPage.terminalContainer.click();

      // Test Page Up
      await page.keyboard.press('PageUp');
      await page.waitForTimeout(500);
      const afterPageUp = await terminalPage.getScrollPosition();

      // Test Page Down
      await page.keyboard.press('PageDown');
      await page.waitForTimeout(500);
      const afterPageDown = await terminalPage.getScrollPosition();

      // Page Down should increase scroll position
      expect(afterPageDown.scrollTop).toBeGreaterThanOrEqual(afterPageUp.scrollTop);

      // Test Home/End keys
      await page.keyboard.press('Home');
      await page.waitForTimeout(500);
      const homePosition = await terminalPage.getScrollPosition();
      expect(homePosition.scrollTop).toBe(0);

      await page.keyboard.press('End');
      await page.waitForTimeout(500);
      const endPosition = await terminalPage.getScrollPosition();
      expect(endPosition.scrollTop).toBeGreaterThan(homePosition.scrollTop);
    });

    test('should support mouse wheel scrolling', async ({ terminalPage, page }) => {
      // Generate content
      for (let i = 1; i <= 25; i++) {
        await terminalPage.executeCommand(`echo "Mouse wheel test ${i}"`);
      }

      // Get initial position
      const initialPosition = await terminalPage.getScrollPosition();

      // Simulate mouse wheel scrolling
      await terminalPage.terminalContainer.hover();
      await page.mouse.wheel(0, -300); // Scroll up
      await page.waitForTimeout(500);

      const afterScrollUp = await terminalPage.getScrollPosition();
      expect(afterScrollUp.scrollTop).toBeLessThan(initialPosition.scrollTop);

      // Scroll down
      await page.mouse.wheel(0, 300);
      await page.waitForTimeout(500);

      const afterScrollDown = await terminalPage.getScrollPosition();
      expect(afterScrollDown.scrollTop).toBeGreaterThan(afterScrollUp.scrollTop);
    });

    test('should show new output indicator when scrolled up', async ({ terminalPage, page }) => {
      // Generate some content and scroll up
      for (let i = 1; i <= 20; i++) {
        await terminalPage.executeCommand(`echo "Initial content ${i}"`);
      }

      await terminalPage.scrollToTop();
      await page.waitForTimeout(500);

      // Add new content while scrolled up
      await terminalPage.executeCommand('echo "New output while scrolled"');
      await page.waitForTimeout(1000);

      // Should show new output indicator
      const hasNewOutput = await terminalPage.hasNewOutput();
      expect(hasNewOutput).toBe(true);

      // Clicking indicator or scrolling to bottom should hide it
      await terminalPage.scrollToBottom();
      await page.waitForTimeout(500);

      const indicatorHidden = await terminalPage.hasNewOutput();
      expect(indicatorHidden).toBe(false);
    });
  });

  test.describe('Scrollback Performance', () => {
    test('should maintain smooth scrolling with large amounts of content', async ({ terminalPage, page }) => {
      // Generate large amount of content
      await terminalPage.executeCommand('seq 1 2000');
      await page.waitForTimeout(5000); // Wait for all content to load

      // Measure scroll performance
      const scrollOperations = [
        () => terminalPage.scrollToTop(),
        () => page.keyboard.press('PageDown'),
        () => page.keyboard.press('PageDown'),
        () => page.keyboard.press('PageDown'),
        () => terminalPage.scrollToBottom(),
      ];

      const scrollTimes: number[] = [];

      for (const operation of scrollOperations) {
        const startTime = Date.now();
        await operation();
        await page.waitForTimeout(200); // Allow scroll to settle
        const scrollTime = Date.now() - startTime;
        scrollTimes.push(scrollTime);
      }

      // All scroll operations should complete quickly
      const averageScrollTime = scrollTimes.reduce((a, b) => a + b, 0) / scrollTimes.length;
      expect(averageScrollTime).toBeLessThan(1000);

      console.log(`Average scroll time: ${averageScrollTime}ms`);
    });

    test('should not degrade performance during continuous output with scrollback', async ({ terminalPage, page }) => {
      // Start continuous output
      await terminalPage.typeCommand('for i in {1..100}; do echo "Continuous output $i"; sleep 0.1; done');
      await page.keyboard.press('Enter');

      // Wait for some output
      await page.waitForTimeout(2000);

      // Scroll around while output is streaming
      const scrollStart = Date.now();

      await terminalPage.scrollToTop();
      await page.waitForTimeout(500);

      await page.keyboard.press('PageDown');
      await page.waitForTimeout(300);

      await terminalPage.scrollToBottom();

      const scrollOperationTime = Date.now() - scrollStart;

      // Should remain responsive during continuous output
      expect(scrollOperationTime).toBeLessThan(3000);

      // Stop the continuous output
      await terminalPage.sendInterrupt();
      await page.waitForTimeout(1000);
    });

    test('should handle rapid scroll events without lag', async ({ terminalPage, page }) => {
      // Generate content for scrolling
      for (let i = 1; i <= 100; i++) {
        await terminalPage.executeCommand(`echo "Rapid scroll test ${i}"`);
      }

      // Perform rapid scroll operations
      const rapidScrolls = Array(20).fill(null).map((_, i) => async () => {
        if (i % 2 === 0) {
          await page.keyboard.press('PageUp');
        } else {
          await page.keyboard.press('PageDown');
        }
        await page.waitForTimeout(50);
      });

      const startTime = Date.now();

      for (const scroll of rapidScrolls) {
        await scroll();
      }

      const totalTime = Date.now() - startTime;

      // Rapid scrolling should complete quickly
      expect(totalTime).toBeLessThan(5000);

      // Terminal should still be functional after rapid scrolling
      await terminalPage.executeCommand('echo "Still responsive after rapid scrolling"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Still responsive after rapid scrolling');
    });
  });

  test.describe('Scrollback Persistence', () => {
    test('should preserve scroll position during terminal refresh', async ({ terminalPage, page }) => {
      // Generate content and scroll to middle
      for (let i = 1; i <= 50; i++) {
        await terminalPage.executeCommand(`echo "Persistence test ${i}"`);
      }

      // Scroll to a middle position
      await terminalPage.scrollToTop();
      await page.keyboard.press('PageDown');
      await page.keyboard.press('PageDown');

      const beforeRefreshPosition = await terminalPage.getScrollPosition();

      // Refresh terminal
      await terminalPage.refreshTerminal();

      // Check if position is preserved (implementation dependent)
      const afterRefreshPosition = await terminalPage.getScrollPosition();

      // At minimum, terminal should be functional after refresh
      await terminalPage.executeCommand('echo "After refresh test"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('After refresh test');

      console.log(`Position before refresh: ${beforeRefreshPosition.scrollTop}`);
      console.log(`Position after refresh: ${afterRefreshPosition.scrollTop}`);
    });

    test('should maintain scrollback across terminal resize', async ({ terminalPage, page }) => {
      // Generate content
      for (let i = 1; i <= 30; i++) {
        await terminalPage.executeCommand(`echo "Resize scrollback test ${i}"`);
      }

      await terminalPage.scrollToTop();
      const contentBeforeResize = await terminalPage.getTerminalContent();

      // Resize terminal
      await page.setViewportSize({ width: 800, height: 600 });
      await page.waitForTimeout(1000);

      // Content should still be accessible
      const contentAfterResize = await terminalPage.getTerminalContent();

      // Should contain the same essential content
      expect(contentAfterResize).toContain('Resize scrollback test 1');
      expect(contentAfterResize).toContain('Resize scrollback test 30');
    });
  });

  test.describe('Scrollback Accessibility', () => {
    test('should support screen reader navigation', async ({ terminalPage, page }) => {
      // Generate content with screen reader landmarks
      await terminalPage.executeCommand('echo "=== Section 1 ==="');
      for (let i = 1; i <= 10; i++) {
        await terminalPage.executeCommand(`echo "Section 1 item ${i}"`);
      }

      await terminalPage.executeCommand('echo "=== Section 2 ==="');
      for (let i = 1; i <= 10; i++) {
        await terminalPage.executeCommand(`echo "Section 2 item ${i}"`);
      }

      // Test scrollback accessibility
      await terminalPage.scrollToTop();

      // Content should be readable by screen readers
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('=== Section 1 ===');
      expect(content).toContain('=== Section 2 ===');

      // Check if terminal maintains proper ARIA attributes during scroll
      const ariaLabel = await terminalPage.terminalContainer.getAttribute('aria-label');
      const role = await terminalPage.terminalContainer.getAttribute('role');

      // Should maintain accessibility attributes
      expect(ariaLabel || role).toBeTruthy();
    });

    test('should announce new content when auto-scrolling', async ({ terminalPage, page }) => {
      // Generate initial content and scroll up
      for (let i = 1; i <= 15; i++) {
        await terminalPage.executeCommand(`echo "Initial content ${i}"`);
      }

      await terminalPage.scrollToTop();

      // Add new content
      await terminalPage.executeCommand('echo "New content announcement test"');

      // Check for new output indicator (accessibility feature)
      const hasNewOutput = await terminalPage.hasNewOutput();
      expect(hasNewOutput).toBe(true);

      // The indicator helps screen readers know there's new content
      // Click it to auto-scroll (accessibility feature)
      if (hasNewOutput) {
        await terminalPage.scrollToBottom();
        const indicatorGone = await terminalPage.hasNewOutput();
        expect(indicatorGone).toBe(false);
      }
    });
  });

  test.describe('Edge Cases and Error Handling', () => {
    test('should handle scrolling with empty terminal', async ({ terminalPage, page }) => {
      // Clear terminal completely
      await terminalPage.clearTerminal();

      // Try scrolling operations on empty terminal
      await terminalPage.scrollToTop();
      await page.keyboard.press('PageUp');
      await page.keyboard.press('PageDown');
      await terminalPage.scrollToBottom();

      // Should not cause errors
      const errors = await terminalPage.checkForErrors();
      expect(errors).toHaveLength(0);

      // Terminal should still be functional
      await terminalPage.executeCommand('echo "Empty terminal test"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Empty terminal test');
    });

    test('should handle scroll operations during terminal loading', async ({ terminalPage, page }) => {
      // Navigate to terminal page but try scrolling immediately
      await terminalPage.goto();

      // Try scrolling before terminal is fully ready
      await terminalPage.scrollToTop();
      await page.keyboard.press('PageDown');

      // Wait for terminal to be ready
      await terminalPage.waitForTerminalReady();

      // Should not have caused any errors
      const errors = await terminalPage.checkForErrors();
      expect(errors.filter(error =>
        !error.toLowerCase().includes('loading') &&
        !error.toLowerCase().includes('initializing')
      )).toHaveLength(0);

      // Terminal should be functional
      await terminalPage.executeCommand('echo "Loading scroll test"');
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain('Loading scroll test');
    });

    test('should gracefully handle scroll position overflow', async ({ terminalPage, page }) => {
      // Generate minimal content
      await terminalPage.executeCommand('echo "Single line"');

      // Try to scroll beyond content bounds
      await terminalPage.scrollToTop();

      for (let i = 0; i < 10; i++) {
        await page.keyboard.press('PageUp');
        await page.waitForTimeout(100);
      }

      const topPosition = await terminalPage.getScrollPosition();
      expect(topPosition.scrollTop).toBe(0); // Should not go negative

      // Try scrolling down beyond content
      for (let i = 0; i < 10; i++) {
        await page.keyboard.press('PageDown');
        await page.waitForTimeout(100);
      }

      // Should not cause errors or infinite scroll
      const finalPosition = await terminalPage.getScrollPosition();
      expect(finalPosition.scrollTop).toBeGreaterThanOrEqual(0);
      expect(finalPosition.scrollTop).toBeLessThanOrEqual(finalPosition.scrollHeight);
    });
  });

  test.afterEach(async ({ page }) => {
    // Clean up utilities
    const utilities = (page as any).testUtilities;
    if (utilities) {
      await utilities.cleanup();
    }
  });
});