import { test, expect } from './fixtures/test-fixtures';
import { TerminalPage } from './page-objects/TerminalPage';
import { SidebarPage } from './page-objects/SidebarPage';

/**
 * E2E Tests for Terminal Creation and Command Execution
 * Tests core terminal functionality, command execution, and user interactions
 */

test.describe('Terminal Creation and Command Execution', () => {
  let terminalPage: TerminalPage;
  let sidebarPage: SidebarPage;

  test.beforeEach(async ({ page, terminalPage: tp, sidebarPage: sp }) => {
    terminalPage = tp;
    sidebarPage = sp;

    // Navigate to the application
    await terminalPage.goto('/');
    await terminalPage.waitForPageLoad();
  });

  test('should create terminal and establish connection', async ({ testData }) => {
    // Wait for terminal to be ready
    await terminalPage.waitForTerminalReady();

    // Verify terminal connection
    await terminalPage.waitForConnection();

    // Check that terminal is properly sized
    const terminalSize = await terminalPage.getTerminalSize();
    expect(terminalSize).toBeTruthy();
    expect(terminalSize!.cols).toBeGreaterThan(0);
    expect(terminalSize!.rows).toBeGreaterThan(0);

    // Verify no error states
    const errors = await terminalPage.checkForErrors();
    expect(errors).toHaveLength(0);
  });

  test('should execute basic commands successfully', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    const commands = testData.getTestCommands();

    // Test each command
    for (const testCommand of commands.slice(0, 3)) { // Test first 3 commands
      // Skip commands that shouldn't run on current platform
      if (testCommand.skipOn?.includes(process.platform)) {
        continue;
      }

      // Execute the command
      await terminalPage.executeCommand(testCommand.command);

      // Wait for expected output
      await terminalPage.waitForOutput(testCommand.expectedOutput, testCommand.timeout);

      // Verify command executed successfully
      const content = await terminalPage.getTerminalContent();
      expect(content).toContain(testCommand.expectedOutput);
    }
  });

  test('should handle command history navigation', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    const commands = [
      'echo "command 1"',
      'echo "command 2"',
      'echo "command 3"'
    ];

    // Execute commands to build history
    for (const command of commands) {
      await terminalPage.executeCommand(command);
    }

    // Test history navigation
    await terminalPage.testCommandHistory(commands);
  });

  test('should handle terminal clearing', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute a command to generate output
    await terminalPage.executeCommand('echo "This will be cleared"');
    await terminalPage.waitForOutput('This will be cleared');

    // Clear the terminal
    await terminalPage.clearTerminal();

    // Verify terminal is cleared (content should be minimal)
    const content = await terminalPage.getTerminalContent();
    expect(content.trim().length).toBeLessThan(50); // Should be mostly empty
  });

  test('should handle command interruption', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Start a long-running command (simulate with sleep)
    await terminalPage.typeCommand('sleep 10');
    await terminalPage.page.keyboard.press('Enter');

    // Wait a moment for command to start
    await terminalPage.page.waitForTimeout(1000);

    // Send interrupt signal
    await terminalPage.sendInterrupt();

    // Verify command was interrupted (should see prompt again)
    await terminalPage.page.waitForTimeout(2000);
    const content = await terminalPage.getTerminalContent();
    expect(content).toMatch(/\$|\#|>|%/); // Should see some kind of prompt
  });

  test('should handle scroll operations', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Generate enough output to require scrolling
    await terminalPage.executeCommand('seq 1 50');
    await terminalPage.waitForOutput('50');

    // Test scroll to top
    await terminalPage.scrollToTop();

    // Verify we're not at bottom
    const isAtBottom = await terminalPage.isAtBottom();
    expect(isAtBottom).toBeFalsy();

    // Test scroll to bottom
    await terminalPage.scrollToBottom();

    // Verify we're at bottom
    const isAtBottomAfter = await terminalPage.isAtBottom();
    expect(isAtBottomAfter).toBeTruthy();
  });

  test('should handle terminal refresh', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute a command
    await terminalPage.executeCommand('echo "Before refresh"');
    await terminalPage.waitForOutput('Before refresh');

    // Refresh terminal
    await terminalPage.refreshTerminal();

    // Verify terminal is still functional
    await terminalPage.executeCommand('echo "After refresh"');
    await terminalPage.waitForOutput('After refresh');

    const content = await terminalPage.getTerminalContent();
    expect(content).toContain('After refresh');
  });

  test('should measure input delay performance', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    const performanceScenarios = testData.getPerformanceScenarios();
    const basicScenario = performanceScenarios.find(s => s.name === 'Large Output');

    if (basicScenario) {
      // Measure input delay
      const delay = await terminalPage.measureInputDelay('echo "performance test"');

      // Verify delay is within acceptable limits (2 seconds)
      expect(delay).toBeLessThan(2000);

      console.log(`Input delay: ${delay}ms`);
    }
  });

  test('should handle error commands gracefully', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    const errorScenarios = testData.getErrorScenarios();

    // Test first error scenario
    const errorTest = errorScenarios[0];

    // Execute invalid command
    await terminalPage.executeCommand(errorTest.command);

    // Wait for error output
    await terminalPage.page.waitForTimeout(3000);

    // Verify error message appears
    const content = await terminalPage.getTerminalContent();
    expect(content.toLowerCase()).toContain(errorTest.expectedErrorText.toLowerCase());

    // Verify terminal is still functional after error
    await terminalPage.executeCommand('echo "Still working"');
    await terminalPage.waitForOutput('Still working');
  });

  test('should handle rapid command execution', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute multiple commands rapidly
    const rapidCommands = ['echo "1"', 'echo "2"', 'echo "3"', 'echo "4"', 'echo "5"'];

    for (const command of rapidCommands) {
      await terminalPage.executeCommand(command);
      // Small delay to prevent overwhelming
      await terminalPage.page.waitForTimeout(200);
    }

    // Verify all commands executed
    const content = await terminalPage.getTerminalContent();
    for (let i = 1; i <= 5; i++) {
      expect(content).toContain(i.toString());
    }
  });

  test('should maintain terminal state across page interactions', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute a command
    await terminalPage.executeCommand('echo "State test"');
    await terminalPage.waitForOutput('State test');

    // Open and close sidebar
    await sidebarPage.openSidebar();
    await sidebarPage.closeSidebar();

    // Verify terminal is still functional
    await terminalPage.executeCommand('echo "Still here"');
    await terminalPage.waitForOutput('Still here');

    // Verify previous output is still there
    const content = await terminalPage.getTerminalContent();
    expect(content).toContain('State test');
    expect(content).toContain('Still here');
  });
});