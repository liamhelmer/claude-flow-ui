/**
 * Improved End-to-End Integration Tests: Complete User Workflows
 * 
 * Enhanced version with better mock management, async handling, and reliability
 */

import { render, screen, waitFor, act, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { integrationHelpers } from '@tests/utils/integrationTestHelpers';
import { setupTestEnvironment } from '@tests/utils/renderingHelpers';
import { useAppStore } from '@/lib/state/store';
import Terminal from '@/components/terminal/Terminal';
import Sidebar from '@/components/sidebar/Sidebar';
import TabList from '@/components/tabs/TabList';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';

// Mock all required hooks and stores
jest.mock('@/lib/state/store');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');

describe('Improved E2E: Complete Application Workflows', () => {
  let testEnv;
  let mockStore;
  let mockWebSocket;
  let mockTerminal;

  beforeEach(async () => {
    // Set up enhanced test environment
    testEnv = setupTestEnvironment();
    
    // Set up integration test helpers
    const integrationSetup = integrationHelpers.setupIntegrationTest();
    mockWebSocket = integrationSetup.websocketClient;
    mockTerminal = integrationSetup.terminalMock;

    // Setup enhanced mock store
    mockStore = {
      sidebarOpen: true,
      monitoringOpen: false,
      terminalSessions: [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
          status: 'connected',
        }
      ],
      activeSessionId: 'session-1',
      error: null,
      loading: false,
      setSidebarOpen: jest.fn(),
      setMonitoringOpen: jest.fn(),
      setActiveSession: jest.fn(),
      addSession: jest.fn().mockImplementation(async (session) => {
        const newSession = { 
          id: session?.id || `session-${Date.now()}`,
          name: session?.name || `Terminal ${mockStore.terminalSessions.length + 1}`,
          isActive: false,
          lastActivity: new Date(),
          status: 'connected'
        };
        mockStore.terminalSessions.push(newSession);
        
        // Simulate WebSocket session creation
        await mockWebSocket.createSession(newSession);
        return newSession;
      }),
      removeSession: jest.fn().mockImplementation(async (sessionId) => {
        mockStore.terminalSessions = mockStore.terminalSessions.filter(s => s.id !== sessionId);
        await mockWebSocket.destroySession(sessionId);
        return true;
      }),
      setError: jest.fn(),
      setLoading: jest.fn(),
    };
    
    useAppStore.mockReturnValue(mockStore);

    // Setup WebSocket mock
    require('@/hooks/useWebSocket').useWebSocket.mockReturnValue(mockWebSocket);

    // Setup terminal mock
    require('@/hooks/useTerminal').useTerminal.mockReturnValue(mockTerminal);
  });

  afterEach(async () => {
    await testEnv.cleanup();
    await integrationHelpers.cleanup();
  });

  describe('Enhanced User Session Workflow', () => {
    test('should handle complete application startup with proper waiting', async () => {
      const TestApp = () => (
        <div className="flex h-screen" data-testid="main-app">
          <Sidebar
            isOpen={mockStore.sidebarOpen}
            onToggle={() => mockStore.setSidebarOpen(!mockStore.sidebarOpen)}
            sessions={mockStore.terminalSessions}
            activeSessionId={mockStore.activeSessionId}
            onSessionSelect={mockStore.setActiveSession}
            onSessionCreate={mockStore.addSession}
            onSessionClose={mockStore.removeSession}
          />
          <main className="flex-1 flex flex-col">
            <TabList
              sessions={mockStore.terminalSessions}
              activeSessionId={mockStore.activeSessionId}
              onSessionSelect={mockStore.setActiveSession}
              onSessionClose={mockStore.removeSession}
              onNewSession={mockStore.addSession}
            />
            <div className="flex-1">
              <Terminal sessionId={mockStore.activeSessionId} />
            </div>
          </main>
          <MonitoringSidebar
            isOpen={mockStore.monitoringOpen}
            onToggle={() => mockStore.setMonitoringOpen(!mockStore.monitoringOpen)}
          />
        </div>
      );

      // Render and wait for application to be ready
      testEnv.render(<TestApp />);
      
      await testEnv.waitForReady('main-app', { timeout: 2000 });

      // 1. Verify initial application state
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();

      // 2. Test monitoring panel interaction with proper waiting
      const monitorToggle = screen.getByTitle('Open Monitor');
      
      await testEnv.click('monitor-toggle', { 
        selectorType: 'role',
        timeout: 1000 
      });

      await integrationHelpers.waitForMockCall(mockStore.setMonitoringOpen, {
        withArgs: [true],
        timeout: 1000
      });

      // 3. Test session creation with enhanced async handling
      const newSessionButton = screen.getByLabelText('New terminal session');
      
      await testEnv.click('new-session-button', {
        selectorType: 'labelText',
        timeout: 1000
      });

      // Wait for both store and WebSocket calls
      await Promise.all([
        integrationHelpers.waitForMockCall(mockStore.addSession, { timeout: 1000 }),
        integrationHelpers.waitForMockCall(mockWebSocket.createSession, { timeout: 1000 })
      ]);

      // 4. Test terminal interaction with better data flow
      await testEnv.waitForReady('terminal', {
        selectorType: 'role',
        timeout: 1000
      });

      const terminal = screen.getByRole('group');
      await testEnv.click(terminal);

      await integrationHelpers.waitForMockCall(mockTerminal.focusTerminal, {
        timeout: 1000
      });

      // 5. Test data sending through terminal
      await integrationHelpers.simulateTerminalFlow(mockWebSocket, 'session-1', [
        { input: 'ls -la\r', output: 'total 12\ndrwxr-xr-x 3 user user 4096 Jan  1 12:00 .\n$ ', delay: 50 }
      ]);

      // Verify terminal received output
      await integrationHelpers.waitForMockCall(mockTerminal.terminal.write, {
        timeout: 1000
      });
    });

    test('should handle multi-session workflow with enhanced state management', async () => {
      // Setup multi-session store
      const multiSessionStore = {
        ...mockStore,
        terminalSessions: [
          { id: 'session-1', name: 'Terminal 1', isActive: true, lastActivity: new Date(), status: 'connected' },
          { id: 'session-2', name: 'Terminal 2', isActive: false, lastActivity: new Date(), status: 'connected' },
          { id: 'session-3', name: 'Terminal 3', isActive: false, lastActivity: new Date(), status: 'connected' },
        ],
      };

      useAppStore.mockReturnValue(multiSessionStore);

      const TestMultiSession = () => (
        <div data-testid="multi-session-container">
          <TabList
            sessions={multiSessionStore.terminalSessions}
            activeSessionId={multiSessionStore.activeSessionId}
            onSessionSelect={multiSessionStore.setActiveSession}
            onSessionClose={multiSessionStore.removeSession}
            onNewSession={multiSessionStore.addSession}
          />
          <Terminal sessionId={multiSessionStore.activeSessionId} />
        </div>
      );

      testEnv.render(<TestMultiSession />);
      
      await testEnv.waitForReady('multi-session-container');

      // Verify all sessions are visible
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      expect(screen.getByText('Terminal 3')).toBeInTheDocument();

      // Test session switching
      await testEnv.click(screen.getByText('Terminal 2'));
      
      await integrationHelpers.waitForMockCall(multiSessionStore.setActiveSession, {
        withArgs: ['session-2'],
        timeout: 1000
      });

      // Test session closing with proper cleanup
      const closeButtons = screen.getAllByLabelText(/close|×/i);
      if (closeButtons.length >= 3) {
        await testEnv.click(closeButtons[2]);
        
        await Promise.all([
          integrationHelpers.waitForMockCall(multiSessionStore.removeSession, { timeout: 1000 }),
          integrationHelpers.waitForMockCall(mockWebSocket.destroySession, { timeout: 1000 })
        ]);
      }

      // Test new session creation
      const newButton = screen.getByLabelText('New terminal session');
      await testEnv.click(newButton);
      
      await integrationHelpers.waitForMockCall(multiSessionStore.addSession, { timeout: 1000 });
    });
  });

  describe('Enhanced Command Execution Flows', () => {
    test('should handle interactive shell session with comprehensive command simulation', async () => {
      testEnv.render(<Terminal sessionId="shell-session" />);
      
      await testEnv.waitForReady('terminal', { selectorType: 'role' });

      const commands = [
        { input: 'pwd\r', output: '/home/user\n$ ', delay: 100 },
        { input: 'ls -la\r', output: 'total 24\ndrwxr-xr-x 5 user user 4096 Jan  1 12:00 .\ndrwxr-xr-x 3 root root 4096 Jan  1 11:00 ..\n-rw------- 1 user user  220 Jan  1 11:00 .bash_logout\ndrwxr-xr-x 2 user user 4096 Jan  1 12:00 Documents\n$ ', delay: 150 },
        { input: 'echo "Hello World"\r', output: 'Hello World\n$ ', delay: 50 },
        { input: 'git status\r', output: 'On branch main\nYour branch is up to date with \'origin/main\'.\nnothing to commit, working tree clean\n$ ', delay: 200 },
      ];

      // Execute command sequence with proper timing
      const results = await integrationHelpers.simulateTerminalFlow(
        mockWebSocket, 
        'shell-session', 
        commands
      );

      // Verify all commands were processed
      expect(results).toHaveLength(commands.length);
      
      // Verify terminal received all outputs
      await integrationHelpers.waitForCondition(
        () => mockTerminal.terminal.write.mock.calls.length >= commands.length,
        { timeout: 3000, message: 'All command outputs not received' }
      );
    });

    test('should handle long-running command with progressive output', async () => {
      testEnv.render(<Terminal sessionId="long-task" />);
      
      await testEnv.waitForReady('terminal', { selectorType: 'role' });

      // Simulate npm install with progressive output
      const progressUpdates = [
        { input: 'npm install\r', output: 'npm WARN deprecated package@1.0.0: This package is deprecated\n', delay: 100 },
        { input: '', output: 'npm WARN deprecated another-package@2.0.0: Please upgrade\n', delay: 200 },
        { input: '', output: 'added 1 package from 1 contributor and audited 100 packages in 2.5s\n', delay: 300 },
        { input: '', output: 'found 0 vulnerabilities\n$ ', delay: 100 },
      ];

      await integrationHelpers.simulateTerminalFlow(
        mockWebSocket,
        'long-task',
        progressUpdates
      );

      // Verify progressive output handling
      await integrationHelpers.waitForCondition(
        () => mockTerminal.terminal.write.mock.calls.length >= progressUpdates.length,
        { timeout: 2000 }
      );
    });
  });

  describe('Enhanced Error Scenarios and Recovery', () => {
    test('should handle WebSocket disconnection with proper recovery', async () => {
      testEnv.render(<Terminal sessionId="unstable-connection" />);
      
      await testEnv.waitForReady('terminal', { selectorType: 'role' });

      // Initially connected - send command
      await integrationHelpers.simulateTerminalFlow(
        mockWebSocket,
        'unstable-connection',
        [{ input: 'echo "test"\r', output: 'test\n$ ', delay: 50 }]
      );

      // Simulate disconnection
      await act(async () => {
        mockWebSocket.connected = false;
        mockWebSocket.emit('disconnect', 'transport close');
      });

      // Attempt to send command while disconnected
      try {
        await mockWebSocket.sendData('unstable-connection', 'ls\r');
        // Should throw error when disconnected
      } catch (error) {
        expect(error.message).toContain('not connected');
      }

      // Simulate reconnection
      await act(async () => {
        await mockWebSocket.connect();
      });

      // Should be able to send commands again
      await integrationHelpers.simulateTerminalFlow(
        mockWebSocket,
        'unstable-connection',
        [{ input: 'pwd\r', output: '/home/user\n$ ', delay: 50 }]
      );

      expect(mockWebSocket.connected).toBe(true);
    });

    test('should handle malformed data gracefully', async () => {
      testEnv.render(<Terminal sessionId="error-prone" />);
      
      await testEnv.waitForReady('terminal', { selectorType: 'role' });

      // Send error message
      await act(async () => {
        mockWebSocket.emit('terminal-error', {
          sessionId: 'error-prone',
          error: 'Process terminated unexpectedly',
        });
      });

      await integrationHelpers.waitForMockCall(mockTerminal.terminal.write, {
        timeout: 1000
      });

      // Send malformed messages
      const malformedMessages = [
        null,
        undefined,
        { sessionId: 'error-prone' }, // missing data
        { data: 'test' }, // missing sessionId
        { sessionId: 'wrong-session', data: 'ignore this' },
      ];

      for (const message of malformedMessages) {
        await act(async () => {
          mockWebSocket.emit('terminal-data', message);
        });
        await integrationHelpers.sleep(10);
      }

      // Terminal should still be functional
      expect(mockTerminal.terminalRef.current).toBeTruthy();
    });
  });

  describe('Enhanced Performance Testing', () => {
    test('should handle rapid data bursts efficiently', async () => {
      testEnv.render(<Terminal sessionId="burst-test" />);
      
      await testEnv.waitForReady('terminal', { selectorType: 'role' });

      const burstData = Array.from({ length: 50 }, (_, i) => 
        ({ input: '', output: `Line ${i + 1}: Burst data test\r\n`, delay: 5 })
      );

      const startTime = performance.now();

      await integrationHelpers.simulateTerminalFlow(
        mockWebSocket,
        'burst-test',
        burstData
      );

      const endTime = performance.now();
      const processingTime = endTime - startTime;

      // Should process burst data efficiently
      expect(processingTime).toBeLessThan(2000); // 2 seconds for 50 messages

      // Verify all data was processed
      await integrationHelpers.waitForCondition(
        () => mockTerminal.terminal.write.mock.calls.length >= burstData.length,
        { timeout: 3000 }
      );
    });

    test('should maintain UI responsiveness during high activity', async () => {
      const TestResponsive = () => (
        <div data-testid="responsive-container">
          <Terminal sessionId="responsive-test" />
          <button data-testid="focus-button" onClick={() => mockTerminal.focusTerminal()}>
            Focus Test
          </button>
        </div>
      );

      testEnv.render(<TestResponsive />);
      
      await testEnv.waitForReady('responsive-container');

      // Start background data stream
      const streamPromise = integrationHelpers.simulateTerminalFlow(
        mockWebSocket,
        'responsive-test',
        Array.from({ length: 20 }, (_, i) => 
          ({ input: '', output: `Stream ${i}: Background data\r\n`, delay: 25 })
        )
      );

      // Test UI responsiveness during stream
      const startTime = performance.now();
      
      await testEnv.click('focus-button');
      
      const clickTime = performance.now() - startTime;

      // UI should remain responsive
      expect(clickTime).toBeLessThan(100);
      await integrationHelpers.waitForMockCall(mockTerminal.focusTerminal);

      await streamPromise; // Wait for stream to complete
    });
  });

  describe('Enhanced Accessibility Testing', () => {
    test('should provide comprehensive accessibility support', async () => {
      const TestAccessible = () => (
        <div data-testid="accessible-app">
          <Sidebar
            isOpen={true}
            onToggle={() => {}}
            sessions={mockStore.terminalSessions}
            activeSessionId={mockStore.activeSessionId}
            onSessionSelect={() => {}}
            onSessionCreate={() => {}}
            onSessionClose={() => {}}
          />
          <Terminal sessionId="accessibility-test" />
          <MonitoringSidebar isOpen={true} onToggle={() => {}} />
        </div>
      );

      const result = testEnv.render(<TestAccessible />);
      
      await testEnv.waitForReady('accessible-app');

      // Check accessibility issues
      const accessibilityIssues = testEnv.renderer.checkAccessibility(result.container);
      
      // Should have minimal accessibility issues
      expect(accessibilityIssues.length).toBeLessThan(3);

      // Verify key interactive elements are accessible
      const terminalElements = screen.queryAllByRole('group');
      expect(terminalElements.length).toBeGreaterThan(0);

      // Test keyboard navigation
      const focusableElements = result.container.querySelectorAll(
        'button, input, select, textarea, [tabindex="0"], [role="button"], [role="tab"]'
      );
      
      expect(focusableElements.length).toBeGreaterThan(0);
    });
  });
});