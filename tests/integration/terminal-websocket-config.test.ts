/**
 * WebSocket Terminal Configuration Tests
 * 
 * Tests the WebSocket terminal-config event handling and integration
 * with the Terminal component configuration display.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import { testUtils, createIntegrationTest } from '../utils/testHelpers';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

createIntegrationTest('WebSocket Terminal Configuration', () => {
  let mockClient: any;
  let mockUseTerminal: any;
  let mockUseWebSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock useTerminal hook with dynamic terminal state
    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      isAtBottom: false,
      hasNewOutput: false,
      terminal: null, // Will be updated during tests
    };
    (useTerminal as jest.Mock).mockReturnValue(mockUseTerminal);

    // Create mock WebSocket client
    mockClient = testUtils.createMockWebSocketClient();
    
    // Mock useWebSocket hook
    mockUseWebSocket = {
      connected: false,
      connecting: false,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: mockClient.on.bind(mockClient),
      off: mockClient.off.bind(mockClient),
    };
    (useWebSocket as jest.Mock).mockReturnValue(mockUseWebSocket);
  });

  describe('Terminal Config WebSocket Events', () => {
    test('should handle terminal-config event and update display', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Initially no config
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Simulate terminal-config WebSocket event
      act(() => {
        // Update mock terminal with new config
        mockUseTerminal.terminal = {
          cols: 120,
          rows: 40,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
          focus: jest.fn(),
          resize: jest.fn(),
        };

        // Trigger re-render by mocking the hook return value
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('120×40')).toBeInTheDocument();
        expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
      });
    });

    test('should handle standard 80x24 terminal config', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      act(() => {
        mockUseTerminal.terminal = {
          cols: 80,
          rows: 24,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });
    });

    test('should handle wide terminal config 132x50', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      act(() => {
        mockUseTerminal.terminal = {
          cols: 132,
          rows: 50,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 132,
          rows: 50,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('132×50')).toBeInTheDocument();
      });
    });

    test('should ignore terminal-config from wrong session', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="current-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Send config for different session
      act(() => {
        mockClient.emit('terminal-config', {
          sessionId: 'other-session',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
        expect(screen.queryByText('120×40')).not.toBeInTheDocument();
      });
    });

    test('should handle multiple terminal-config updates in sequence', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // First config: 80x24
      act(() => {
        mockUseTerminal.terminal = {
          cols: 80,
          rows: 24,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });

      // Second config: 120x40
      act(() => {
        mockUseTerminal.terminal = {
          cols: 120,
          rows: 40,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('120×40')).toBeInTheDocument();
        expect(screen.queryByText('80×24')).not.toBeInTheDocument();
      });

      // Third config: 132x50
      act(() => {
        mockUseTerminal.terminal = {
          cols: 132,
          rows: 50,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 132,
          rows: 50,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('132×50')).toBeInTheDocument();
        expect(screen.queryByText('120×40')).not.toBeInTheDocument();
      });
    });

    test('should handle rapid terminal-config updates', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      const configs = [
        { cols: 80, rows: 24 },
        { cols: 100, rows: 30 },
        { cols: 120, rows: 40 },
        { cols: 132, rows: 50 },
      ];

      // Send rapid config updates
      configs.forEach((config, index) => {
        setTimeout(() => {
          act(() => {
            mockUseTerminal.terminal = {
              cols: config.cols,
              rows: config.rows,
              write: jest.fn(),
              onData: jest.fn(),
              onResize: jest.fn(),
            };

            (useTerminal as jest.Mock).mockReturnValue({
              ...mockUseTerminal,
              terminal: mockUseTerminal.terminal,
            });

            mockClient.emit('terminal-config', {
              sessionId: 'test-session',
              cols: config.cols,
              rows: config.rows,
            });
          });
        }, index * 10);
      });

      // Should end up with the last config
      await waitFor(() => {
        expect(screen.getByText('132×50')).toBeInTheDocument();
      }, { timeout: 1000 });
    });
  });

  describe('WebSocket Connection Lifecycle with Config', () => {
    test('should show "Waiting..." when not connected', () => {
      mockUseWebSocket.connected = false;
      mockClient.connected = false;
      mockUseTerminal.terminal = null;

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    test('should handle disconnect and lose config', async () => {
      // Start connected with config
      mockUseWebSocket.connected = true;
      mockClient.connected = true;
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Simulate disconnection
      act(() => {
        mockUseWebSocket.connected = false;
        mockClient.connected = false;
        mockUseTerminal.terminal = null;

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: null,
        });

        mockClient.emit('disconnect');
      });

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
        expect(screen.queryByText('80×24')).not.toBeInTheDocument();
      });
    });

    test('should restore config on reconnection', async () => {
      // Start disconnected
      mockUseWebSocket.connected = false;
      mockClient.connected = false;
      mockUseTerminal.terminal = null;

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Simulate reconnection with config restore
      act(() => {
        mockUseWebSocket.connected = true;
        mockClient.connected = true;
        mockUseTerminal.terminal = {
          cols: 100,
          rows: 30,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('connect');
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 100,
          rows: 30,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('100×30')).toBeInTheDocument();
        expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
      });
    });
  });

  describe('Malformed WebSocket Messages', () => {
    test('should handle null terminal-config event', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      act(() => {
        mockClient.emit('terminal-config', null);
      });

      // Should remain in waiting state
      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });
    });

    test('should handle terminal-config with missing sessionId', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      act(() => {
        mockClient.emit('terminal-config', {
          cols: 80,
          rows: 24,
          // missing sessionId
        });
      });

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });
    });

    test('should handle terminal-config with missing dimensions', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      act(() => {
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          // missing cols and rows
        });
      });

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });
    });

    test('should handle terminal-config with invalid dimensions', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      const invalidConfigs = [
        { sessionId: 'test-session', cols: 0, rows: 24 },
        { sessionId: 'test-session', cols: 80, rows: 0 },
        { sessionId: 'test-session', cols: -1, rows: 24 },
        { sessionId: 'test-session', cols: 80, rows: -1 },
        { sessionId: 'test-session', cols: null, rows: 24 },
        { sessionId: 'test-session', cols: 80, rows: null },
        { sessionId: 'test-session', cols: 'invalid', rows: 24 },
        { sessionId: 'test-session', cols: 80, rows: 'invalid' },
      ];

      for (const config of invalidConfigs) {
        act(() => {
          mockClient.emit('terminal-config', config);
        });
      }

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });
    });

    test('should handle terminal-config event without crashing on errors', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      // Mock console.error to suppress error logs during testing
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      render(<Terminal sessionId="test-session" />);

      // Send various malformed messages
      const malformedMessages = [
        undefined,
        {},
        { invalid: 'data' },
        { sessionId: 'test-session', cols: NaN, rows: NaN },
        { sessionId: 'test-session', cols: Infinity, rows: Infinity },
      ];

      for (const message of malformedMessages) {
        act(() => {
          mockClient.emit('terminal-config', message);
        });
      }

      // Component should still be functional
      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });

      consoleSpy.mockRestore();
    });
  });

  describe('Session Switching with Config', () => {
    test('should reset config when switching sessions', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      // Start with session 1 and config
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { rerender } = render(<Terminal sessionId="session-1" />);

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Switch to session 2 - should reset to waiting
      act(() => {
        mockUseTerminal.terminal = null;
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: null,
        });
      });

      rerender(<Terminal sessionId="session-2" />);

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
        expect(screen.queryByText('80×24')).not.toBeInTheDocument();
      });
    });

    test('should get new config for new session', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="session-1" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Switch sessions and receive config for new session
      rerender(<Terminal sessionId="session-2" />);

      act(() => {
        mockUseTerminal.terminal = {
          cols: 120,
          rows: 40,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        mockClient.emit('terminal-config', {
          sessionId: 'session-2',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('120×40')).toBeInTheDocument();
      });
    });
  });
});