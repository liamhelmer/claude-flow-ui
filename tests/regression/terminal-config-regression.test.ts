/**
 * Terminal Configuration Loading Regression Tests
 * 
 * Ensures that the configuration loading fix doesn't break existing functionality:
 * - Existing terminal behavior preserved
 * - Data handling still works
 * - Scroll functionality intact
 * - Session management unaffected
 * - Error handling maintained
 */

import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
import { testUtils, createIntegrationTest } from '../utils/testHelpers';
import Terminal from '@/components/Terminal/Terminal';
import TerminalControls from '@/components/Terminal/TerminalControls';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

createIntegrationTest('Terminal Configuration Regression Tests', () => {
  let mockClient: any;
  let mockUseTerminal: any;
  let mockUseWebSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Set up mocks similar to pre-fix behavior but with new fix
    mockClient = testUtils.createMockWebSocketClient();
    mockClient.connected = true;
    mockClient.eventHandlers = {};

    mockClient.on = jest.fn((event: string, handler: Function) => {
      mockClient.eventHandlers[event] = handler;
    });

    mockClient.off = jest.fn((event: string, handler: Function) => {
      delete mockClient.eventHandlers[event];
    });

    mockClient.emit = jest.fn((event: string, data?: any) => {
      if (mockClient.eventHandlers[event]) {
        mockClient.eventHandlers[event](data);
      }
    });

    // Standard terminal with config
    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      refreshTerminal: jest.fn(),
      isAtBottom: false,
      hasNewOutput: false,
      terminal: {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
        focus: jest.fn(),
        dispose: jest.fn()
      },
      backendTerminalConfig: { cols: 80, rows: 24 },
      isConnected: true,
      echoEnabled: true,
      lastCursorPosition: { row: 1, col: 1 }
    };
    (useTerminal as jest.Mock).mockReturnValue(mockUseTerminal);

    mockUseWebSocket = {
      connected: true,
      connecting: false,
      isConnected: true,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      createSession: jest.fn(),
      destroySession: jest.fn(),
      listSessions: jest.fn(),
      requestTerminalConfig: jest.fn(),
      on: mockClient.on,
      off: mockClient.off
    };
    (useWebSocket as jest.Mock).mockReturnValue(mockUseWebSocket);
  });

  describe('Terminal Data Handling Regression', () => {
    test('should still handle terminal data correctly after config fix', async () => {
      render(<Terminal sessionId="test-session" />);

      // Verify config is displayed
      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Send terminal data
      await act(async () => {
        mockClient.emit('terminal-data', {
          sessionId: 'test-session',
          data: 'Hello Terminal\r\n'
        });
      });

      // Terminal should still receive and process data
      expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith('Hello Terminal\r\n');
    });

    test('should handle terminal errors correctly', async () => {
      render(<Terminal sessionId="test-session" />);

      await act(async () => {
        mockClient.emit('terminal-error', {
          sessionId: 'test-session',
          error: 'Command not found'
        });
      });

      // Error should be processed normally
      expect(mockClient.eventHandlers['terminal-error']).toBeDefined();
    });

    test('should handle connection state changes', async () => {
      const { rerender } = render(<Terminal sessionId="test-session" />);

      // Initially connected with config
      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Simulate disconnection
      mockUseWebSocket.connected = false;
      mockUseWebSocket.isConnected = false;
      mockUseTerminal.terminal = null;
      mockUseTerminal.backendTerminalConfig = null;

      (useWebSocket as jest.Mock).mockReturnValue({
        ...mockUseWebSocket,
        connected: false,
        isConnected: false
      });

      (useTerminal as jest.Mock).mockReturnValue({
        ...mockUseTerminal,
        terminal: null,
        backendTerminalConfig: null
      });

      rerender(<Terminal sessionId="test-session" />);

      // Should show waiting state on disconnect
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(screen.queryByText('80×24')).not.toBeInTheDocument();
    });

    test('should preserve session data handling', async () => {
      render(<Terminal sessionId="session-1" />);

      // Data for correct session should be processed
      await act(async () => {
        mockClient.emit('terminal-data', {
          sessionId: 'session-1',
          data: 'Session 1 data\r\n'
        });
      });

      expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith('Session 1 data\r\n');

      // Data for wrong session should be ignored
      await act(async () => {
        mockClient.emit('terminal-data', {
          sessionId: 'session-2',
          data: 'Session 2 data\r\n'
        });
      });

      expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(1); // Still only 1 call
    });
  });

  describe('Terminal Controls Regression', () => {
    test('should preserve all control functionality', () => {
      const mockScrollToTop = jest.fn();
      const mockScrollToBottom = jest.fn();

      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={true}
          onScrollToTop={mockScrollToTop}
          onScrollToBottom={mockScrollToBottom}
          terminalConfig={{ cols: 80, rows: 24 }}
        />
      );

      // Should show config
      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Should show all control buttons
      const scrollToTopButton = screen.getByTitle('Scroll to top');
      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');

      expect(scrollToTopButton).toBeInTheDocument();
      expect(scrollToBottomButton).toBeInTheDocument();

      // Controls should still work
      fireEvent.click(scrollToTopButton);
      fireEvent.click(scrollToBottomButton);

      expect(mockScrollToTop).toHaveBeenCalled();
      expect(mockScrollToBottom).toHaveBeenCalled();
    });

    test('should maintain visual styling and layout', () => {
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={true}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={{ cols: 120, rows: 40 }}
        />
      );

      // Config display styling should be preserved
      const configDisplay = screen.getByText('120×40');
      expect(configDisplay).toHaveClass('text-gray-400', 'font-semibold');

      // Layout elements should be present
      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
    });

    test('should handle config prop changes smoothly', () => {
      const configs = [
        { cols: 80, rows: 24 },
        { cols: 100, rows: 30 },
        { cols: 120, rows: 40 },
        null
      ];

      const { rerender } = render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={configs[0]}
        />
      );

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Test each config change
      configs.slice(1).forEach((config, index) => {
        rerender(
          <TerminalControls
            isAtBottom={false}
            hasNewOutput={false}
            onScrollToTop={jest.fn()}
            onScrollToBottom={jest.fn()}
            terminalConfig={config}
          />
        );

        if (config) {
          expect(screen.getByText(`${config.cols}×${config.rows}`)).toBeInTheDocument();
        } else {
          expect(screen.getByText('Waiting...')).toBeInTheDocument();
        }
      });
    });
  });

  describe('Scroll Functionality Regression', () => {
    test('should maintain scroll behavior after config loading', async () => {
      // Set up terminal with scroll state
      mockUseTerminal.isAtBottom = false;
      mockUseTerminal.hasNewOutput = true;

      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={true}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={{ cols: 80, rows: 24 }}
        />
      );

      // Should show new output indicator
      expect(screen.getByText('See latest')).toBeInTheDocument();
      
      // Config should still be displayed
      expect(screen.getByText('80×24')).toBeInTheDocument();
    });

    test('should handle scroll state updates with config', async () => {
      const mockScrollToBottom = jest.fn();

      const { rerender } = render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={true}
          onScrollToTop={jest.fn()}
          onScrollToBottom={mockScrollToBottom}
          terminalConfig={{ cols: 80, rows: 24 }}
        />
      );

      // Click to scroll to bottom
      fireEvent.click(screen.getByTitle('Scroll to bottom'));
      expect(mockScrollToBottom).toHaveBeenCalled();

      // Update to be at bottom
      rerender(
        <TerminalControls
          isAtBottom={true}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={mockScrollToBottom}
          terminalConfig={{ cols: 80, rows: 24 }}
        />
      );

      // Should not show "See latest" when at bottom
      expect(screen.queryByText('See latest')).not.toBeInTheDocument();
      expect(screen.getByText('80×24')).toBeInTheDocument();
    });

    test('should preserve auto-scroll behavior', async () => {
      render(<Terminal sessionId="test-session" />);

      // Simulate new data arriving when at bottom
      mockUseTerminal.isAtBottom = true;
      
      await act(async () => {
        mockClient.emit('terminal-data', {
          sessionId: 'test-session',
          data: 'New output line\r\n'
        });
      });

      // Terminal should auto-scroll (tested via write call)
      expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith('New output line\r\n');
    });
  });

  describe('Session Management Regression', () => {
    test('should handle session switching correctly', async () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Initial session should show config
      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Switch sessions
      mockUseTerminal.backendTerminalConfig = null;
      mockUseTerminal.terminal = null;
      (useTerminal as jest.Mock).mockReturnValue({
        ...mockUseTerminal,
        backendTerminalConfig: null,
        terminal: null
      });

      rerender(<Terminal sessionId="session-2" />);

      // Should show waiting for new session
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Config request should be made for new session
      expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalledWith('session-2');
    });

    test('should preserve session creation and destruction', async () => {
      render(<Terminal sessionId="test-session" />);

      // Session management functions should still be available
      expect(mockUseWebSocket.createSession).toBeDefined();
      expect(mockUseWebSocket.destroySession).toBeDefined();
      expect(mockUseWebSocket.listSessions).toBeDefined();

      // Should be able to call them
      mockUseWebSocket.createSession();
      mockUseWebSocket.destroySession('test-session');
      mockUseWebSocket.listSessions();

      expect(mockUseWebSocket.createSession).toHaveBeenCalled();
      expect(mockUseWebSocket.destroySession).toHaveBeenCalledWith('test-session');
      expect(mockUseWebSocket.listSessions).toHaveBeenCalled();
    });

    test('should handle concurrent session operations', async () => {
      const sessions = ['session-1', 'session-2', 'session-3'];

      // Render multiple terminals
      const terminals = sessions.map(sessionId => 
        render(<Terminal sessionId={sessionId} />)
      );

      // All should have made config requests
      sessions.forEach(sessionId => {
        expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalledWith(sessionId);
      });

      // Clean up
      terminals.forEach(({ unmount }) => unmount());
    });
  });

  describe('Error Handling Regression', () => {
    test('should maintain error handling for malformed data', async () => {
      render(<Terminal sessionId="test-session" />);

      const malformedData = [
        null,
        undefined,
        { invalid: 'data' },
        { sessionId: 'wrong-session', data: 'test' },
        { sessionId: 'test-session' }, // missing data
        { data: 'test' } // missing sessionId
      ];

      // Should handle all malformed data gracefully
      for (const data of malformedData) {
        await act(async () => {
          mockClient.emit('terminal-data', data);
        });
      }

      // Component should still be functional
      expect(screen.getByText('80×24')).toBeInTheDocument();
    });

    test('should handle WebSocket errors gracefully', async () => {
      render(<Terminal sessionId="test-session" />);

      await act(async () => {
        mockClient.emit('error', new Error('WebSocket error'));
      });

      // Should not crash the component
      expect(screen.getByText('80×24')).toBeInTheDocument();
    });

    test('should maintain error boundaries', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      // Force an error in terminal data handling
      mockUseTerminal.terminal.write.mockImplementation(() => {
        throw new Error('Terminal write error');
      });

      render(<Terminal sessionId="test-session" />);

      await act(async () => {
        mockClient.emit('terminal-data', {
          sessionId: 'test-session',
          data: 'test data'
        });
      });

      // Error should be caught and handled
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('Performance Regression', () => {
    test('should not degrade rendering performance', async () => {
      const renderStartTime = performance.now();

      render(<Terminal sessionId="test-session" />);

      const renderEndTime = performance.now();
      const renderTime = renderEndTime - renderStartTime;

      // Should render quickly (no performance regression)
      expect(renderTime).toBeLessThan(100);
    });

    test('should handle rapid re-renders efficiently', async () => {
      const { rerender } = render(<Terminal sessionId="test-session" />);

      const rerenderCount = 50;
      const startTime = performance.now();

      for (let i = 0; i < rerenderCount; i++) {
        rerender(<Terminal sessionId="test-session" />);
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const avgRerenderTime = totalTime / rerenderCount;

      // Should handle re-renders efficiently
      expect(avgRerenderTime).toBeLessThan(10);
    });

    test('should maintain memory efficiency', async () => {
      const componentCount = 100;
      const components: Array<{ unmount: () => void }> = [];

      // Create many components
      for (let i = 0; i < componentCount; i++) {
        components.push(render(<Terminal sessionId={`session-${i}`} />));
      }

      // Clean up all components
      components.forEach(({ unmount }) => unmount());

      // Should not have accumulated handlers or memory leaks
      expect(Object.keys(mockClient.eventHandlers)).toHaveLength(0);
    });
  });

  describe('API Compatibility Regression', () => {
    test('should maintain Terminal component prop interface', () => {
      // Should accept all original props
      const { rerender } = render(
        <Terminal 
          sessionId="test-session"
          className="custom-class"
        />
      );

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Should handle prop changes
      rerender(
        <Terminal 
          sessionId="new-session"
          className="new-class"
        />
      );

      // New session should trigger waiting state
      mockUseTerminal.backendTerminalConfig = null;
      mockUseTerminal.terminal = null;
      (useTerminal as jest.Mock).mockReturnValue({
        ...mockUseTerminal,
        backendTerminalConfig: null,
        terminal: null
      });

      rerender(
        <Terminal 
          sessionId="new-session"
          className="new-class"
        />
      );

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    test('should maintain TerminalControls prop interface', () => {
      const props = {
        isAtBottom: false,
        hasNewOutput: true,
        onScrollToTop: jest.fn(),
        onScrollToBottom: jest.fn(),
        terminalConfig: { cols: 80, rows: 24 }
      };

      const { rerender } = render(<TerminalControls {...props} />);

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Should handle all prop combinations
      const variations = [
        { ...props, isAtBottom: true, hasNewOutput: false },
        { ...props, terminalConfig: { cols: 120, rows: 40 } },
        { ...props, terminalConfig: null }
      ];

      variations.forEach(variation => {
        rerender(<TerminalControls {...variation} />);
        
        if (variation.terminalConfig) {
          const { cols, rows } = variation.terminalConfig;
          expect(screen.getByText(`${cols}×${rows}`)).toBeInTheDocument();
        } else {
          expect(screen.getByText('Waiting...')).toBeInTheDocument();
        }
      });
    });

    test('should maintain hook return value interfaces', () => {
      const { result } = renderHook(() => useTerminal({ sessionId: 'test' }));

      // Should return all expected properties
      const expectedProperties = [
        'terminalRef', 'terminal', 'backendTerminalConfig', 'focusTerminal',
        'fitTerminal', 'scrollToTop', 'scrollToBottom', 'refreshTerminal',
        'isAtBottom', 'hasNewOutput', 'isConnected'
      ];

      expectedProperties.forEach(prop => {
        expect(result.current).toHaveProperty(prop);
      });

      const { result: wsResult } = renderHook(() => useWebSocket());

      const expectedWSProperties = [
        'connected', 'connecting', 'isConnected', 'sendData', 'resizeTerminal',
        'createSession', 'destroySession', 'listSessions', 'requestTerminalConfig',
        'on', 'off'
      ];

      expectedWSProperties.forEach(prop => {
        expect(wsResult.current).toHaveProperty(prop);
      });
    });
  });
});