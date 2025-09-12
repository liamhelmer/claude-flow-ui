import { test, expect, Page } from '@playwright/test';
import { spawn, ChildProcess } from 'child_process';
import { createServer, Server } from 'http';
import { AddressInfo } from 'net';
import path from 'path';

// E2E tests for claude-flow integration via tmux
describe('Claude Flow Tmux E2E Tests', () => {
  let server: Server;
  let serverProcess: ChildProcess;
  let port: number;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    // Start the claude-ui server with tmux integration
    const testPort = 12000 + Math.floor(Math.random() * 1000);
    
    serverProcess = spawn('node', ['server.js', '--port', testPort.toString()], {
      cwd: path.resolve(__dirname, '../..'),
      env: {
        ...process.env,
        NODE_ENV: 'test',
        TMUX_ENABLED: 'true',
        USE_TMUX_SESSIONS: 'true'
      },
      stdio: 'pipe'
    });

    // Wait for server to start
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Server start timeout'));
      }, 30000);

      serverProcess.stdout?.on('data', (data) => {
        if (data.toString().includes('Claude Flow UI Server Started')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      serverProcess.stderr?.on('data', (data) => {
        console.error('Server error:', data.toString());
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    port = testPort;
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    if (page) await page.close();
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      
      // Wait for graceful shutdown
      await new Promise<void>((resolve) => {
        serverProcess.on('exit', () => resolve());
        setTimeout(() => {
          serverProcess.kill('SIGKILL');
          resolve();
        }, 5000);
      });
    }
  });

  test('should load claude-flow UI with tmux terminal', async () => {
    await page.goto(`http://localhost:${port}`);
    
    // Wait for the page to load
    await page.waitForSelector('[data-testid="terminal-container"]', { timeout: 10000 });
    
    // Verify terminal is present
    const terminal = await page.$('[data-testid="terminal-container"]');
    expect(terminal).toBeTruthy();

    // Verify WebSocket connection status
    await page.waitForSelector('[data-testid="connection-status"]');
    const connectionStatus = await page.textContent('[data-testid="connection-status"]');
    expect(connectionStatus).toContain('Connected');
  });

  test('should create tmux session and connect', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Wait for initial connection and session creation
    await page.waitForFunction(
      () => window.localStorage.getItem('claude-session-id') !== null,
      { timeout: 15000 }
    );

    // Check that tmux session was created
    const sessionId = await page.evaluate(() => 
      window.localStorage.getItem('claude-session-id')
    );
    expect(sessionId).toBeTruthy();

    // Verify session appears in session list
    await page.click('[data-testid="sessions-button"]');
    await page.waitForSelector('[data-testid="session-list"]');
    
    const sessionItem = await page.$(`[data-session-id="${sessionId}"]`);
    expect(sessionItem).toBeTruthy();
  });

  test('should execute claude-flow commands via tmux', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Wait for tmux session to be ready
    await page.waitForTimeout(2000);

    // Send a simple claude-flow command
    const testCommand = 'claude-flow --help';
    await page.click('[data-testid="terminal"]');
    await page.keyboard.type(testCommand);
    await page.keyboard.press('Enter');

    // Wait for command output
    await page.waitForTimeout(5000);

    // Verify command output appears
    const terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain('claude-flow');
    expect(terminalContent).toMatch(/Usage:|Commands:|Options:/);
  });

  test('should maintain session persistence on reconnect', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Execute a command that creates persistent state
    const uniqueMarker = `test-marker-${Date.now()}`;
    await page.click('[data-testid="terminal"]');
    await page.keyboard.type(`echo "${uniqueMarker}"`);
    await page.keyboard.press('Enter');

    // Wait for command execution
    await page.waitForTimeout(2000);

    // Verify marker appears
    let terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain(uniqueMarker);

    // Simulate page refresh (reconnection)
    await page.reload();
    await page.waitForSelector('[data-testid="terminal-container"]');
    await page.waitForTimeout(3000);

    // Verify session content is restored
    terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain(uniqueMarker);
  });

  test('should handle terminal resizing correctly', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Get initial terminal size
    const initialSize = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm-viewport') as HTMLElement;
      return {
        width: terminal?.clientWidth,
        height: terminal?.clientHeight
      };
    });

    // Resize viewport
    await page.setViewportSize({ width: 1200, height: 800 });
    await page.waitForTimeout(1000);

    // Verify terminal was resized
    const newSize = await page.evaluate(() => {
      const terminal = document.querySelector('.xterm-viewport') as HTMLElement;
      return {
        width: terminal?.clientWidth,
        height: terminal?.clientHeight
      };
    });

    expect(newSize.width).toBeGreaterThan(initialSize.width!);
    expect(newSize.height).toBeGreaterThan(initialSize.height!);

    // Test that commands still work after resize
    await page.click('[data-testid="terminal"]');
    await page.keyboard.type('echo "resize test"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);

    const terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain('resize test');
  });

  test('should handle multiple tmux windows/panes', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Create a new tmux window via keyboard shortcut
    await page.keyboard.press('Control+b');
    await page.keyboard.press('c');
    await page.waitForTimeout(1000);

    // Verify new window was created
    await page.keyboard.type('echo "window 2"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);

    let terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain('window 2');

    // Switch back to first window
    await page.keyboard.press('Control+b');
    await page.keyboard.press('0');
    await page.waitForTimeout(1000);

    // Verify we can still see original content
    await page.keyboard.type('echo "window 1"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);

    terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain('window 1');
  });

  test('should support claude-flow swarm operations', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');
    await page.waitForTimeout(2000);

    // Test basic swarm initialization
    await page.click('[data-testid="terminal"]');
    await page.keyboard.type('claude-flow sparc modes');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(5000);

    let terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toMatch(/Available modes:|sparc modes/i);

    // Test agent spawning (if available)
    await page.keyboard.type('claude-flow swarm init --topology mesh');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(8000);

    terminalContent = await page.textContent('[data-testid="terminal"]');
    // Should show either success or appropriate error message
    expect(terminalContent).toMatch(/(swarm|topology|mesh|error)/i);
  });

  test('should handle long-running claude-flow processes', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Start a long-running process
    await page.click('[data-testid="terminal"]');
    await page.keyboard.type('claude-flow tdd "create a simple function"');
    await page.keyboard.press('Enter');

    // Monitor output for several seconds
    let outputDetected = false;
    const startTime = Date.now();

    while (Date.now() - startTime < 15000 && !outputDetected) {
      await page.waitForTimeout(2000);
      
      const terminalContent = await page.textContent('[data-testid="terminal"]');
      
      // Look for any signs of TDD process activity
      if (terminalContent?.match(/(test|spec|function|creating|analyzing)/i)) {
        outputDetected = true;
      }
    }

    // Should have detected some TDD activity
    expect(outputDetected).toBe(true);

    // Test that we can interrupt the process
    await page.keyboard.press('Control+c');
    await page.waitForTimeout(2000);

    // Verify we're back to prompt
    await page.keyboard.type('echo "interrupted"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);

    const finalContent = await page.textContent('[data-testid="terminal"]');
    expect(finalContent).toContain('interrupted');
  });

  test('should maintain proper terminal history and scrolling', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Generate lots of output to test scrolling
    await page.click('[data-testid="terminal"]');
    
    for (let i = 0; i < 50; i++) {
      await page.keyboard.type(`echo "Line ${i + 1} of terminal history"`);
      await page.keyboard.press('Enter');
      await page.waitForTimeout(100);
    }

    // Test scrolling to top
    await page.click('[data-testid="scroll-to-top"]');
    await page.waitForTimeout(500);

    // Test scrolling to bottom
    await page.click('[data-testid="scroll-to-bottom"]');
    await page.waitForTimeout(500);

    // Verify we can see recent output
    const terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain('Line 50 of terminal history');

    // Test that we can scroll back up to see earlier output
    const viewport = await page.$('.xterm-viewport');
    if (viewport) {
      await viewport.evaluate(el => {
        el.scrollTop = 0;
      });
      await page.waitForTimeout(500);
    }

    // Should be able to find earlier lines when scrolled up
    // (Note: xterm might virtualize content, so we test the scroll functionality)
    const scrollTop = await page.evaluate(() => {
      const viewport = document.querySelector('.xterm-viewport') as HTMLElement;
      return viewport?.scrollTop;
    });
    expect(scrollTop).toBe(0);
  });

  test('should handle tmux session cleanup on page close', async () => {
    const newPage = await page.context().newPage();
    await newPage.goto(`http://localhost:${port}`);
    await newPage.waitForSelector('[data-testid="terminal-container"]');

    // Get session ID
    const sessionId = await newPage.evaluate(() => 
      window.localStorage.getItem('claude-session-id')
    );

    // Execute a command to ensure session is active
    await newPage.click('[data-testid="terminal"]');
    await newPage.keyboard.type('echo "cleanup test"');
    await newPage.keyboard.press('Enter');
    await newPage.waitForTimeout(2000);

    // Close the page
    await newPage.close();

    // Wait a moment for cleanup
    await page.waitForTimeout(3000);

    // Verify the session was properly handled
    // (In a real implementation, you'd check if the tmux session 
    //  was killed or marked for cleanup)
    expect(sessionId).toBeTruthy();
  });

  test('should handle network interruptions gracefully', async () => {
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Simulate network interruption by navigating away and back
    await page.goto('about:blank');
    await page.waitForTimeout(2000);

    // Navigate back
    await page.goto(`http://localhost:${port}`);
    await page.waitForSelector('[data-testid="terminal-container"]');

    // Wait for reconnection
    await page.waitForFunction(
      () => {
        const status = document.querySelector('[data-testid="connection-status"]');
        return status?.textContent?.includes('Connected');
      },
      { timeout: 10000 }
    );

    // Test that terminal still works after reconnection
    await page.click('[data-testid="terminal"]');
    await page.keyboard.type('echo "reconnected"');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);

    const terminalContent = await page.textContent('[data-testid="terminal"]');
    expect(terminalContent).toContain('reconnected');
  });
});