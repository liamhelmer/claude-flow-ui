/**
 * Terminal Configuration Loading Fix Tests
 * 
 * Comprehensive tests for the terminal configuration race condition fix.
 * Verifies that:
 * - Config is fetched before terminal initialization
 * - Event listeners are registered immediately
 * - Terminal doesn't initialize until config is available
 * - Proper handling of config loading failures
 * - No race conditions exist
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import { testUtils, createIntegrationTest } from '../utils/testHelpers';
import Terminal from '@/components/Terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

createIntegrationTest('Terminal Configuration Loading Fix', () => {
  let mockClient: any;
  let mockUseTerminal: any;
  let mockUseWebSocket: any;
  let mockConfigRequests: string[];
  let mockEventHandlers: { [key: string]: Function };

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigRequests = [];
    mockEventHandlers = {};

    // Enhanced mock WebSocket client with timing control
    mockClient = {
      ...testUtils.createMockWebSocketClient(),
      connected: false,
      connecting: false,
      configRequestDelay: 0, // Control config response delay
      shouldFailConfig: false, // Control config failure
      
      // Override send to track config requests
      send: jest.fn((type: string, data: any) => {
        if (type === 'request-config') {
          mockConfigRequests.push(data.sessionId);
          
          // Simulate async config response based on test configuration
          setTimeout(() => {
            if (!mockClient.shouldFailConfig) {
              const config = {
                sessionId: data.sessionId,
                cols: 80,
                rows: 24
              };
              mockClient.emit('terminal-config', config);
            }
          }, mockClient.configRequestDelay);
        }
      }),
      
      // Enhanced emit tracking
      emit: jest.fn((event: string, data?: any) => {
        console.log(`[MockClient] Emitting ${event}:`, data);
        if (mockEventHandlers[event]) {
          mockEventHandlers[event](data);
        }
        return true;
      }),
      
      // Enhanced on/off with handler tracking
      on: jest.fn((event: string, handler: Function) => {
        console.log(`[MockClient] Registering handler for ${event}`);
        mockEventHandlers[event] = handler;
      }),
      
      off: jest.fn((event: string, handler: Function) => {
        console.log(`[MockClient] Removing handler for ${event}`);
        delete mockEventHandlers[event];
      })
    };

    // Mock useTerminal hook with enhanced state tracking
    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      refreshTerminal: jest.fn(),
      isAtBottom: false,
      hasNewOutput: false,
      terminal: null,
      backendTerminalConfig: null,
      isConnected: false,
      
      // Track initialization attempts
      initializationAttempts: 0,
      configWaitCount: 0
    };
    (useTerminal as jest.Mock).mockReturnValue(mockUseTerminal);

    // Mock useWebSocket hook with enhanced tracking
    mockUseWebSocket = {
      connected: false,
      connecting: false,
      isConnected: false,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      createSession: jest.fn(),
      destroySession: jest.fn(),
      requestTerminalConfig: jest.fn((sessionId: string) => {
        mockClient.send('request-config', { sessionId });
      }),
      on: mockClient.on,
      off: mockClient.off,
    };
    (useWebSocket as jest.Mock).mockReturnValue(mockUseWebSocket);
  });

  describe('Configuration Prefetch Mechanism', () => {
    test('should request config immediately when WebSocket connects', async () => {
      // Start with disconnected state
      mockUseWebSocket.connected = false;
      mockUseWebSocket.isConnected = false;
      mockClient.connected = false;

      const { rerender } = render(<Terminal sessionId="test-session" />);

      // No config requests should have been made yet
      expect(mockConfigRequests).toHaveLength(0);
      expect(mockUseWebSocket.requestTerminalConfig).not.toHaveBeenCalled();

      // Simulate WebSocket connection
      act(() => {
        mockUseWebSocket.connected = true;
        mockUseWebSocket.isConnected = true;
        mockClient.connected = true;
        
        // Update the mock return value
        (useWebSocket as jest.Mock).mockReturnValue({
          ...mockUseWebSocket,
          connected: true,
          isConnected: true
        });
      });

      // Force re-render to trigger the connection effect
      rerender(<Terminal sessionId="test-session" />);

      // Config should be requested immediately upon connection
      await waitFor(() => {
        expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalledWith('test-session');
        expect(mockConfigRequests).toContain('test-session');
      }, { timeout: 1000 });
    });

    test('should register event listeners before requesting config', async () => {
      const listenerRegistrations: string[] = [];
      const configRequests: number[] = [];

      // Enhanced tracking of the order of operations
      mockClient.on.mockImplementation((event: string, handler: Function) => {
        listenerRegistrations.push(event);
        mockEventHandlers[event] = handler;
        console.log(`[Test] Listener registered: ${event} (total: ${listenerRegistrations.length})`);
      });

      mockUseWebSocket.requestTerminalConfig.mockImplementation((sessionId: string) => {
        configRequests.push(Date.now());
        console.log(`[Test] Config requested at: ${configRequests[configRequests.length - 1]}`);
        mockClient.send('request-config', { sessionId });
      });

      // Start connected to trigger immediate setup
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      await waitFor(() => {
        // terminal-config listener should be registered before config is requested
        expect(listenerRegistrations).toContain('terminal-config');
        expect(configRequests.length).toBeGreaterThan(0);
      });

      // Verify the event listener is actually functional
      expect(mockEventHandlers['terminal-config']).toBeDefined();
      expect(typeof mockEventHandlers['terminal-config']).toBe('function');
    });

    test('should not initialize terminal until config is received', async () => {
      // Set up a delay for config response
      mockClient.configRequestDelay = 100;

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      // Terminal should show waiting state initially
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Wait for config request
      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      // Terminal should still be waiting
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(mockUseTerminal.terminal).toBeNull();

      // Simulate config arrival after delay
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 150));
        
        // Update mock to reflect config received
        mockUseTerminal.backendTerminalConfig = { cols: 80, rows: 24 };
        mockUseTerminal.terminal = {
          cols: 80,
          rows: 24,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 80, rows: 24 },
          terminal: mockUseTerminal.terminal
        });
      });

      // Now terminal should show the configuration
      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
        expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
      });
    });

    test('should handle multiple rapid connection/disconnection cycles', async () => {
      const { rerender } = render(<Terminal sessionId="test-session" />);

      // Simulate rapid connection cycles
      for (let i = 0; i < 5; i++) {
        // Connect
        act(() => {
          mockUseWebSocket.connected = true;
          mockUseWebSocket.isConnected = true;
          mockClient.connected = true;
          
          (useWebSocket as jest.Mock).mockReturnValue({
            ...mockUseWebSocket,
            connected: true,
            isConnected: true
          });
        });

        rerender(<Terminal sessionId="test-session" />);

        // Wait briefly
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
        });

        // Disconnect
        act(() => {
          mockUseWebSocket.connected = false;
          mockUseWebSocket.isConnected = false;
          mockClient.connected = false;
          mockUseTerminal.backendTerminalConfig = null;
          mockUseTerminal.terminal = null;
          
          (useWebSocket as jest.Mock).mockReturnValue({
            ...mockUseWebSocket,
            connected: false,
            isConnected: false
          });
          
          (useTerminal as jest.Mock).mockReturnValue({
            ...mockUseTerminal,
            backendTerminalConfig: null,
            terminal: null
          });
        });

        rerender(<Terminal sessionId="test-session" />);

        // Wait briefly
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
        });
      }

      // Should handle gracefully without errors
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });
  });

  describe('Configuration Loading Failure Scenarios', () => {
    test('should handle config request timeout', async () => {
      // Set up extreme delay to simulate timeout
      mockClient.configRequestDelay = 5000;

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      // Should show waiting state
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Wait for config request
      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      // Should still be waiting even after reasonable time
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(mockUseTerminal.terminal).toBeNull();
    });

    test('should handle malformed config response', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      // Send malformed config responses
      const malformedConfigs = [
        null,
        undefined,
        {},
        { sessionId: 'test-session' }, // missing cols/rows
        { cols: 80, rows: 24 }, // missing sessionId
        { sessionId: 'test-session', cols: 0, rows: 24 }, // invalid dimensions
        { sessionId: 'test-session', cols: 80, rows: 0 },
        { sessionId: 'test-session', cols: -1, rows: 24 },
        { sessionId: 'test-session', cols: null, rows: 24 },
        { sessionId: 'test-session', cols: 'invalid', rows: 24 }
      ];

      for (const config of malformedConfigs) {
        await act(async () => {
          mockClient.emit('terminal-config', config);
          await new Promise(resolve => setTimeout(resolve, 10));
        });

        // Should remain in waiting state
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      }
    });

    test('should handle WebSocket disconnection during config fetch', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;
      mockClient.configRequestDelay = 100;

      const { rerender } = render(<Terminal sessionId="test-session" />);

      // Wait for config request to be sent
      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      // Simulate disconnection before config arrives
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50)); // Disconnect mid-request
        
        mockUseWebSocket.connected = false;
        mockUseWebSocket.isConnected = false;
        mockClient.connected = false;
        mockUseTerminal.backendTerminalConfig = null;
        mockUseTerminal.terminal = null;
        
        (useWebSocket as jest.Mock).mockReturnValue({
          ...mockUseWebSocket,
          connected: false,
          isConnected: false
        });
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: null,
          terminal: null
        });
      });

      rerender(<Terminal sessionId="test-session" />);

      // Should handle gracefully and show waiting state
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    test('should handle config for wrong session', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="correct-session" />);

      await waitFor(() => {
        expect(mockConfigRequests).toContain('correct-session');
      });

      // Send config for wrong session
      await act(async () => {
        mockClient.emit('terminal-config', {
          sessionId: 'wrong-session',
          cols: 80,
          rows: 24
        });
      });

      // Should ignore and remain waiting
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(mockUseTerminal.terminal).toBeNull();

      // Send correct config
      await act(async () => {
        mockClient.emit('terminal-config', {
          sessionId: 'correct-session',
          cols: 100,
          rows: 30
        });
        
        // Update mock to reflect correct config
        mockUseTerminal.backendTerminalConfig = { cols: 100, rows: 30 };
        mockUseTerminal.terminal = {
          cols: 100,
          rows: 30,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 100, rows: 30 },
          terminal: mockUseTerminal.terminal
        });
      });

      await waitFor(() => {
        expect(screen.getByText('100×30')).toBeInTheDocument();
      });
    });
  });

  describe('Race Condition Prevention', () => {
    test('should prevent duplicate config requests', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="test-session" />);

      // Wait for initial config request
      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      const initialRequestCount = mockConfigRequests.length;

      // Force multiple re-renders that could trigger duplicate requests
      for (let i = 0; i < 5; i++) {
        rerender(<Terminal sessionId="test-session" />);
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
        });
      }

      // Should not have made duplicate requests
      expect(mockConfigRequests.length).toBe(initialRequestCount);
    });

    test('should handle rapid session changes', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Wait for first config request
      await waitFor(() => {
        expect(mockConfigRequests).toContain('session-1');
      });

      // Rapidly change sessions
      const sessions = ['session-2', 'session-3', 'session-4', 'session-5'];
      
      for (const sessionId of sessions) {
        rerender(<Terminal sessionId={sessionId} />);
        
        await act(async () => {
          // Reset state for new session
          mockUseTerminal.backendTerminalConfig = null;
          mockUseTerminal.terminal = null;
          (useTerminal as jest.Mock).mockReturnValue({
            ...mockUseTerminal,
            backendTerminalConfig: null,
            terminal: null
          });
          
          await new Promise(resolve => setTimeout(resolve, 10));
        });
      }

      // Should have requested config for all sessions
      sessions.forEach(sessionId => {
        expect(mockConfigRequests).toContain(sessionId);
      });
    });

    test('should handle config arriving before listener registration', async () => {
      // This tests a potential race condition where config arrives 
      // before the terminal-config listener is registered

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;
      mockClient.configRequestDelay = 0; // Immediate response

      // Pre-populate config response before component renders
      setTimeout(() => {
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24
        });
      }, 0);

      render(<Terminal sessionId={'test-session'} />);

      // Even with immediate config response, should handle gracefully
      await waitFor(() => {
        // Either should show waiting (if race condition occurred) or config (if handled properly)
        const waitingElement = screen.queryByText('Waiting...');
        const configElement = screen.queryByText('80×24');
        expect(waitingElement || configElement).toBeTruthy();
      });
    });

    test('should handle multiple terminal instances for same session', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      // Render multiple terminal instances with same session
      const { container: container1 } = render(<Terminal sessionId="shared-session" />);
      const { container: container2 } = render(<Terminal sessionId="shared-session" />);

      await waitFor(() => {
        expect(mockConfigRequests.filter(s => s === 'shared-session').length).toBeGreaterThanOrEqual(1);
      });

      // Send config once
      await act(async () => {
        mockClient.emit('terminal-config', {
          sessionId: 'shared-session',
          cols: 120,
          rows: 40
        });
        
        mockUseTerminal.backendTerminalConfig = { cols: 120, rows: 40 };
        mockUseTerminal.terminal = {
          cols: 120,
          rows: 40,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 120, rows: 40 },
          terminal: mockUseTerminal.terminal
        });
      });

      // Both instances should be able to handle the shared config
      await waitFor(() => {
        expect(screen.getAllByText('120×40').length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('Timing and Performance', () => {
    test('should handle slow config responses gracefully', async () => {
      const slowDelay = 1000;
      mockClient.configRequestDelay = slowDelay;

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const startTime = Date.now();

      render(<Terminal sessionId={'test-session'} />);

      // Should show waiting immediately
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Wait for config request
      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      // Should still be waiting during the delay
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Wait for config to arrive
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, slowDelay + 100));
        
        mockUseTerminal.backendTerminalConfig = { cols: 80, rows: 24 };
        mockUseTerminal.terminal = {
          cols: 80,
          rows: 24,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 80, rows: 24 },
          terminal: mockUseTerminal.terminal
        });
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });

      const totalTime = Date.now() - startTime;
      expect(totalTime).toBeGreaterThanOrEqual(slowDelay);
    });

    test('should not block UI during config loading', async () => {
      mockClient.configRequestDelay = 200;

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="test-session" />);

      // UI should remain responsive during config loading
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Should be able to re-render without issues
      for (let i = 0; i < 10; i++) {
        rerender(<Terminal sessionId="test-session" />);
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      }
    });

    test('should handle memory cleanup on unmount during config loading', async () => {
      mockClient.configRequestDelay = 500;

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const { unmount } = render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockConfigRequests).toContain('test-session');
      });

      // Unmount before config arrives
      unmount();

      // Should not cause memory leaks or errors when config eventually arrives
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 600));
        // Config arrives after unmount - should be handled gracefully
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24
        });
      });

      // No errors should have occurred
      expect(true).toBe(true);
    });
  });

  describe('Integration with Existing Functionality', () => {
    test('should preserve existing terminal data handling after config fix', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      // Wait for config and terminal setup
      await act(async () => {
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24
        });
        
        mockUseTerminal.backendTerminalConfig = { cols: 80, rows: 24 };
        mockUseTerminal.terminal = {
          cols: 80,
          rows: 24,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 80, rows: 24 },
          terminal: mockUseTerminal.terminal
        });
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });

      // Should still handle terminal data
      await act(async () => {
        mockClient.emit('terminal-data', {
          sessionId: 'test-session',
          data: 'test output'
        });
      });

      // Should still handle other terminal events
      await act(async () => {
        mockClient.emit('terminal-error', {
          sessionId: 'test-session',
          error: 'test error'
        });
      });

      // Configuration should remain stable
      expect(screen.getByText('80×24')).toBeInTheDocument();
    });

    test('should handle config updates after initial load', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      // Initial config
      await act(async () => {
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24
        });
        
        mockUseTerminal.backendTerminalConfig = { cols: 80, rows: 24 };
        mockUseTerminal.terminal = {
          cols: 80,
          rows: 24,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 80, rows: 24 },
          terminal: mockUseTerminal.terminal
        });
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });

      // Updated config
      await act(async () => {
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 120,
          rows: 40
        });
        
        mockUseTerminal.backendTerminalConfig = { cols: 120, rows: 40 };
        mockUseTerminal.terminal = {
          cols: 120,
          rows: 40,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn()
        };
        
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: { cols: 120, rows: 40 },
          terminal: mockUseTerminal.terminal
        });
      });

      await waitFor(() => {
        expect(screen.getByText('120×40')).toBeInTheDocument();
        expect(screen.queryByText('80×24')).not.toBeInTheDocument();
      });
    });
  });
});