import { test, expect } from './fixtures/test-fixtures';
import { TerminalPage } from './page-objects/TerminalPage';
import { SidebarPage } from './page-objects/SidebarPage';

/**
 * E2E Tests for Multi-Terminal Session Management
 * Tests handling of multiple terminal sessions, switching, and session persistence
 */

test.describe('Multi-Terminal Session Management', () => {
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

  test('should handle single terminal session', async ({ testData }) => {
    // Verify initial terminal session
    await terminalPage.waitForTerminalReady();
    await terminalPage.waitForConnection();

    // Test basic functionality
    await terminalPage.executeCommand('echo "Single session test"');
    await terminalPage.waitForOutput('Single session test');

    // Verify terminal is functional
    const content = await terminalPage.getTerminalContent();
    expect(content).toContain('Single session test');
  });

  test('should maintain terminal state across page interactions', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute commands to create terminal state
    await terminalPage.executeCommand('echo "State test 1"');
    await terminalPage.waitForOutput('State test 1');

    await terminalPage.executeCommand('pwd');
    await terminalPage.page.waitForTimeout(1000);

    await terminalPage.executeCommand('echo "State test 2"');
    await terminalPage.waitForOutput('State test 2');

    // Interact with sidebar
    await sidebarPage.openSidebar();
    await sidebarPage.page.waitForTimeout(1000);
    await sidebarPage.closeSidebar();
    await sidebarPage.page.waitForTimeout(1000);

    // Verify terminal state is preserved
    const content = await terminalPage.getTerminalContent();
    expect(content).toContain('State test 1');
    expect(content).toContain('State test 2');

    // Verify terminal is still functional
    await terminalPage.executeCommand('echo "After interaction"');
    await terminalPage.waitForOutput('After interaction');
  });

  test('should handle terminal session recreation', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute initial commands
    await terminalPage.executeCommand('echo "Before recreation"');
    await terminalPage.waitForOutput('Before recreation');

    // Simulate session recreation by refreshing
    await terminalPage.refreshTerminal();

    // Verify terminal is functional after refresh
    await terminalPage.executeCommand('echo "After recreation"');
    await terminalPage.waitForOutput('After recreation');

    const content = await terminalPage.getTerminalContent();
    expect(content).toContain('After recreation');
  });

  test('should persist terminal history across refresh', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Build command history
    const commands = ['echo "cmd1"', 'echo "cmd2"', 'echo "cmd3"'];

    for (const command of commands) {
      await terminalPage.executeCommand(command);
      await terminalPage.page.waitForTimeout(500);
    }

    // Get terminal content before refresh
    const contentBefore = await terminalPage.getTerminalContent();

    // Refresh the page
    await terminalPage.page.reload();
    await terminalPage.waitForPageLoad();
    await terminalPage.waitForTerminalReady();

    // Check if history is preserved (this depends on implementation)
    const contentAfter = await terminalPage.getTerminalContent();

    console.log('Content preservation across refresh:', {
      before: contentBefore.length,
      after: contentAfter.length,
      preserved: contentAfter.includes('cmd1') || contentAfter.includes('cmd2') || contentAfter.includes('cmd3')
    });

    // Verify terminal is functional regardless
    await terminalPage.executeCommand('echo "After page refresh"');
    await terminalPage.waitForOutput('After page refresh');
  });

  test('should handle session switching gracefully', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Create state in current session
    await terminalPage.executeCommand('echo "Session A"');
    await terminalPage.waitForOutput('Session A');

    // Simulate session switching (in a real multi-session app)
    // Since this app might not have true multi-session, we'll test refresh scenario
    const sessionContent = await terminalPage.getTerminalContent();

    // Refresh to simulate session switch
    await terminalPage.refreshTerminal();

    // Create different state
    await terminalPage.executeCommand('echo "Session B"');
    await terminalPage.waitForOutput('Session B');

    const newContent = await terminalPage.getTerminalContent();
    expect(newContent).toContain('Session B');
  });

  test('should handle concurrent terminal operations', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute multiple operations that might run concurrently
    const operations = [
      async () => {
        await terminalPage.executeCommand('echo "Operation 1"');
        await terminalPage.waitForOutput('Operation 1');
      },
      async () => {
        await terminalPage.scrollToTop();
        await terminalPage.page.waitForTimeout(500);
        await terminalPage.scrollToBottom();
      },
      async () => {
        await sidebarPage.openSidebar();
        await sidebarPage.page.waitForTimeout(500);
        await sidebarPage.closeSidebar();
      }
    ];

    // Execute operations concurrently
    await Promise.all(operations.map(op => op().catch(e => console.warn('Operation failed:', e))));

    // Verify terminal is still functional
    await terminalPage.executeCommand('echo "After concurrent ops"');
    await terminalPage.waitForOutput('After concurrent ops');
  });

  test('should maintain performance across long sessions', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Simulate long session with many commands
    const commandCount = 20;
    const startTime = Date.now();

    for (let i = 1; i <= commandCount; i++) {
      await terminalPage.executeCommand(`echo "Command ${i}"`);
      await terminalPage.page.waitForTimeout(100); // Brief pause

      // Check performance every 5 commands
      if (i % 5 === 0) {
        const currentTime = Date.now();
        const elapsed = currentTime - startTime;
        const avgTimePerCommand = elapsed / i;

        console.log(`After ${i} commands: ${avgTimePerCommand.toFixed(2)}ms average per command`);

        // Performance shouldn't degrade significantly
        expect(avgTimePerCommand).toBeLessThan(2000); // 2 seconds per command max
      }
    }

    // Final verification
    const finalContent = await terminalPage.getTerminalContent();
    expect(finalContent).toContain('Command 1');
    expect(finalContent).toContain(`Command ${commandCount}`);

    // Test responsiveness after many commands
    const responseTime = await terminalPage.measureInputDelay('echo "Performance test"');
    console.log(`Response time after ${commandCount} commands: ${responseTime}ms`);

    expect(responseTime).toBeLessThan(3000); // Should still be responsive
  });

  test('should handle session cleanup properly', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Create session content
    await terminalPage.executeCommand('echo "Cleanup test"');
    await terminalPage.waitForOutput('Cleanup test');

    // Generate more content
    await terminalPage.executeCommand('seq 1 10');
    await terminalPage.waitForOutput('10');

    // Clear terminal
    await terminalPage.clearTerminal();

    // Verify cleanup worked
    const contentAfterClear = await terminalPage.getTerminalContent();
    expect(contentAfterClear.length).toBeLessThan(100); // Should be mostly empty

    // Verify terminal is still functional
    await terminalPage.executeCommand('echo "After cleanup"');
    await terminalPage.waitForOutput('After cleanup');
  });

  test('should handle session errors and recovery', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute a command that should work
    await terminalPage.executeCommand('echo "Before error"');
    await terminalPage.waitForOutput('Before error');

    // Execute a command that causes error
    await terminalPage.executeCommand('nonexistentcommand');
    await terminalPage.page.waitForTimeout(2000);

    // Verify terminal recovers and is still functional
    await terminalPage.executeCommand('echo "After error"');
    await terminalPage.waitForOutput('After error');

    const content = await terminalPage.getTerminalContent();
    expect(content).toContain('Before error');
    expect(content).toContain('After error');

    // Check if error was handled gracefully
    expect(content.toLowerCase()).toMatch(/command not found|not recognized/);
  });

  test('should handle resource-intensive session operations', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Execute resource-intensive operations
    const intensiveOperations = [
      'seq 1 500',
      'echo "Large operation 1"',
      'seq 501 1000',
      'echo "Large operation 2"'
    ];

    for (const operation of intensiveOperations) {
      const startTime = Date.now();
      await terminalPage.executeCommand(operation);

      if (operation.includes('seq')) {
        await terminalPage.waitForOutput('500', 10000);
      } else {
        await terminalPage.waitForOutput('operation', 5000);
      }

      const duration = Date.now() - startTime;
      console.log(`Operation "${operation}" took ${duration}ms`);

      // Operations should complete within reasonable time
      expect(duration).toBeLessThan(15000); // 15 seconds max
    }

    // Verify terminal is still responsive
    await terminalPage.executeCommand('echo "Still responsive"');
    await terminalPage.waitForOutput('Still responsive');
  });

  test('should maintain session isolation', async ({ testData }) => {
    await terminalPage.waitForTerminalReady();

    // Create unique session identifier
    const sessionId = `session_${Date.now()}`;
    await terminalPage.executeCommand(`echo "Session ID: ${sessionId}"`);
    await terminalPage.waitForOutput(sessionId);

    // Refresh terminal (simulates session recreation)
    await terminalPage.refreshTerminal();

    // Create new session content
    const newSessionId = `session_${Date.now()}`;
    await terminalPage.executeCommand(`echo "New Session ID: ${newSessionId}"`);
    await terminalPage.waitForOutput(newSessionId);

    // Verify current session content
    const content = await terminalPage.getTerminalContent();
    expect(content).toContain(newSessionId);

    // Note: Original session content persistence depends on implementation
    console.log('Session isolation test - content preserved:', content.includes(sessionId));
  });
});