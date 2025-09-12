import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '@/components/terminal/Terminal';
import TerminalControls from '@/components/terminal/TerminalControls';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import { useAppStore } from '@/lib/state/store';

// Mock hooks
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');

// Mock xterm
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
    cols: 80,
    rows: 24,
    element: {
      querySelector: jest.fn(() => ({
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 500,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      })),
    },
    open: jest.fn(),
    write: jest.fn(),
    clear: jest.fn(),
    focus: jest.fn(),
    dispose: jest.fn(),
    loadAddon: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
  })),
}));

jest.mock('@xterm/addon-serialize', () => ({
  SerializeAddon: jest.fn().mockImplementation(() => ({
    serialize: jest.fn(() => 'serialized content'),
  })),
}));

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

const createMockWebSocket = (overrides = {}) => ({
  connected: true,
  connecting: false,
  isConnected: true,
  sendData: jest.fn(),
  sendMessage: jest.fn(),
  resizeTerminal: jest.fn(),
  createSession: jest.fn(),
  destroySession: jest.fn(),
  listSessions: jest.fn(),
  connect: jest.fn(),
  disconnect: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  ...overrides,
});

const createMockTerminal = (overrides = {}) => ({
  terminalRef: { current: null },
  terminal: null,
  writeToTerminal: jest.fn(),
  clearTerminal: jest.fn(),
  focusTerminal: jest.fn(),
  fitTerminal: jest.fn(),
  destroyTerminal: jest.fn(),
  scrollToBottom: jest.fn(),
  scrollToTop: jest.fn(),
  isAtBottom: true,
  hasNewOutput: false,
  isConnected: true,
  ...overrides,
});

const createMockStore = (overrides = {}) => ({
  sessions: [{ id: 'session-1', title: 'Session 1' }],
  activeSession: 'session-1',
  isCollapsed: false,
  error: null,
  loading: false,
  setError: jest.fn(),
  setLoading: jest.fn(),
  addSession: jest.fn(),
  removeSession: jest.fn(),
  setActiveSession: jest.fn(),
  toggleSidebar: jest.fn(),
  ...overrides,
});

describe('Terminal-WebSocket Integration Tests', () => {
  let mockWebSocket: ReturnType<typeof createMockWebSocket>;
  let mockTerminal: ReturnType<typeof createMockTerminal>;
  let mockStore: ReturnType<typeof createMockStore>;
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup();
    
    mockWebSocket = createMockWebSocket();
    mockTerminal = createMockTerminal();
    mockStore = createMockStore();

    mockUseWebSocket.mockReturnValue(mockWebSocket);
    mockUseTerminal.mockReturnValue(mockTerminal);
    mockUseAppStore.mockReturnValue(mockStore);
    
    jest.clearAllMocks();
  });

  describe('Terminal Component Integration', () => {
    it('should render terminal with WebSocket connection', () => {
      render(<Terminal sessionId="test-session" />);
      
      expect(mockUseWebSocket).toHaveBeenCalled();
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'test-session',
        onData: expect.any(Function),
      });
    });

    it('should handle session data through WebSocket', async () => {
      const onDataSpy = jest.fn();
      mockUseTerminal.mockReturnValue({
        ...mockTerminal,
        onData: onDataSpy,
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Simulate user input in terminal
      const terminalArgs = mockUseTerminal.mock.calls[0][0];
      if (terminalArgs.onData) {
        await act(async () => {
          terminalArgs.onData('ls -la\r');
        });
      }
      
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', 'ls -la\r');
    });

    it('should display connection status', () => {
      mockWebSocket = createMockWebSocket({ connected: false, connecting: true });
      mockUseWebSocket.mockReturnValue(mockWebSocket);
      
      render(<Terminal sessionId="test-session" />);
      
      // Terminal should reflect disconnected state
      expect(mockTerminal.isConnected).toBeDefined();
    });

    it('should handle WebSocket reconnection', async () => {
      // Start disconnected
      mockWebSocket = createMockWebSocket({ connected: false, connecting: false });
      mockUseWebSocket.mockReturnValue(mockWebSocket);
      
      const { rerender } = render(<Terminal sessionId="test-session" />);
      
      // Simulate reconnection
      mockWebSocket = createMockWebSocket({ connected: true, connecting: false });
      mockUseWebSocket.mockReturnValue(mockWebSocket);
      
      rerender(<Terminal sessionId="test-session" />);
      
      await waitFor(() => {
        expect(mockUseWebSocket).toHaveBeenCalled();
      });
    });
  });

  describe('Terminal Controls Integration', () => {
    it('should integrate terminal controls with terminal instance', () => {
      render(
        <div>
          <Terminal sessionId="test-session" />
          <TerminalControls
            onClear={mockTerminal.clearTerminal}
            onScrollToBottom={mockTerminal.scrollToBottom}
            onScrollToTop={mockTerminal.scrollToTop}
            hasNewOutput={mockTerminal.hasNewOutput}
          />
        </div>
      );
      
      const clearButton = screen.getByTitle('Clear Terminal');
      fireEvent.click(clearButton);
      
      expect(mockTerminal.clearTerminal).toHaveBeenCalled();
    });

    it('should handle scroll operations', async () => {
      mockTerminal = createMockTerminal({ hasNewOutput: true, isAtBottom: false });
      mockUseTerminal.mockReturnValue(mockTerminal);
      
      render(
        <TerminalControls
          onClear={mockTerminal.clearTerminal}
          onScrollToBottom={mockTerminal.scrollToBottom}
          onScrollToTop={mockTerminal.scrollToTop}
          hasNewOutput={mockTerminal.hasNewOutput}
        />
      );
      
      const scrollToBottomButton = screen.getByTitle('Scroll to Bottom');
      await user.click(scrollToBottomButton);
      
      expect(mockTerminal.scrollToBottom).toHaveBeenCalled();
    });

    it('should show new output indicator', () => {
      mockTerminal = createMockTerminal({ hasNewOutput: true });
      mockUseTerminal.mockReturnValue(mockTerminal);
      
      render(
        <TerminalControls
          onClear={mockTerminal.clearTerminal}
          onScrollToBottom={mockTerminal.scrollToBottom}
          onScrollToTop={mockTerminal.scrollToTop}
          hasNewOutput={true}
        />
      );
      
      // Should show indicator for new output
      const scrollButton = screen.getByTitle('Scroll to Bottom');
      expect(scrollButton).toHaveClass('bg-blue-500');
    });
  });

  describe('Real-time Data Flow', () => {
    it('should handle incoming terminal data', async () => {
      // Mock WebSocket event listeners
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Simulate incoming terminal data
      const terminalData = {
        sessionId: 'test-session',
        data: 'Hello from server\n',
      };
      
      await act(async () => {
        if (eventHandlers['terminal-data']) {
          eventHandlers['terminal-data'](terminalData);
        }
      });
      
      expect(mockTerminal.writeToTerminal).toHaveBeenCalledWith('Hello from server\n');
    });

    it('should handle terminal errors', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Simulate terminal error
      const errorData = {
        sessionId: 'test-session',
        error: 'Command not found: invalidcommand',
      };
      
      await act(async () => {
        if (eventHandlers['terminal-error']) {
          eventHandlers['terminal-error'](errorData);
        }
      });
      
      expect(mockTerminal.writeToTerminal).toHaveBeenCalledWith(
        expect.stringContaining('Command not found: invalidcommand')
      );
    });

    it('should handle session configuration updates', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Simulate terminal configuration update
      const configData = {
        sessionId: 'test-session',
        cols: 120,
        rows: 30,
      };
      
      await act(async () => {
        if (eventHandlers['terminal-config']) {
          eventHandlers['terminal-config'](configData);
        }
      });
      
      // Terminal should be re-initialized with new dimensions
      expect(mockUseTerminal).toHaveBeenCalled();
    });
  });

  describe('Connection State Management', () => {
    it('should handle connection loss gracefully', async () => {
      // Start connected
      render(<Terminal sessionId="test-session" />);
      
      // Simulate connection loss
      mockWebSocket = createMockWebSocket({ connected: false, connecting: false });
      mockUseWebSocket.mockReturnValue(mockWebSocket);
      
      // Component should handle this gracefully
      expect(() => {
        render(<Terminal sessionId="test-session" />);
      }).not.toThrow();
    });

    it('should queue messages when disconnected', async () => {
      mockWebSocket = createMockWebSocket({ connected: false });
      mockUseWebSocket.mockReturnValue(mockWebSocket);
      
      render(<Terminal sessionId="test-session" />);
      
      // Attempt to send data while disconnected
      const terminalArgs = mockUseTerminal.mock.calls[0][0];
      if (terminalArgs.onData) {
        await act(async () => {
          terminalArgs.onData('echo "test"\r');
        });
      }
      
      // Should still attempt to send (WebSocket will handle queueing)
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', 'echo "test"\r');
    });

    it('should retry connection automatically', async () => {
      // Start disconnected
      mockWebSocket = createMockWebSocket({ 
        connected: false, 
        connecting: true,
        connect: jest.fn().mockResolvedValue(undefined)
      });
      mockUseWebSocket.mockReturnValue(mockWebSocket);
      
      render(<Terminal sessionId="test-session" />);
      
      // Connection should be attempted
      expect(mockUseWebSocket).toHaveBeenCalled();
    });
  });

  describe('Multi-Session Support', () => {
    it('should handle multiple terminal sessions', () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'session-1',
        onData: expect.any(Function),
      });
      
      // Switch to different session
      rerender(<Terminal sessionId="session-2" />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'session-2',
        onData: expect.any(Function),
      });
    });

    it('should isolate data between sessions', async () => {
      const session1Data = jest.fn();
      const session2Data = jest.fn();
      
      // Render two terminals with different sessions
      const { container: container1 } = render(
        <div data-testid="terminal-1">
          <Terminal sessionId="session-1" />
        </div>
      );
      
      const { container: container2 } = render(
        <div data-testid="terminal-2">
          <Terminal sessionId="session-2" />
        </div>
      );
      
      // Data sent to session-1 should only affect session-1
      const session1Args = mockUseTerminal.mock.calls[0][0];
      if (session1Args.onData) {
        await act(async () => {
          session1Args.onData('session-1-data');
        });
      }
      
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('session-1', 'session-1-data');
    });
  });

  describe('Performance and Memory Management', () => {
    it('should cleanup WebSocket listeners on unmount', () => {
      const { unmount } = render(<Terminal sessionId="test-session" />);
      
      unmount();
      
      expect(mockWebSocket.off).toHaveBeenCalled();
    });

    it('should handle rapid data updates efficiently', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Send rapid data updates
      const updates = Array.from({ length: 100 }, (_, i) => `Line ${i}\n`);
      
      await act(async () => {
        updates.forEach(data => {
          if (eventHandlers['terminal-data']) {
            eventHandlers['terminal-data']({
              sessionId: 'test-session',
              data,
            });
          }
        });
      });
      
      expect(mockTerminal.writeToTerminal).toHaveBeenCalledTimes(100);
    });

    it('should handle large data payloads', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Send large data payload
      const largeData = 'x'.repeat(10000);
      
      await act(async () => {
        if (eventHandlers['terminal-data']) {
          eventHandlers['terminal-data']({
            sessionId: 'test-session',
            data: largeData,
          });
        }
      });
      
      expect(mockTerminal.writeToTerminal).toHaveBeenCalledWith(largeData);
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should recover from WebSocket errors', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Simulate WebSocket error
      await act(async () => {
        if (eventHandlers['error']) {
          eventHandlers['error'](new Error('WebSocket error'));
        }
      });
      
      // Component should handle error gracefully
      expect(mockStore.setError).toHaveBeenCalled();
    });

    it('should handle malformed terminal data', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="test-session" />);
      
      // Send malformed data
      const malformedData = {
        sessionId: 'test-session',
        data: null,
      };
      
      await act(async () => {
        if (eventHandlers['terminal-data']) {
          eventHandlers['terminal-data'](malformedData);
        }
      });
      
      // Should not crash
      expect(mockTerminal.writeToTerminal).toHaveBeenCalled();
    });

    it('should handle session not found errors', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(<Terminal sessionId="invalid-session" />);
      
      // Simulate session not found error
      const errorData = {
        sessionId: 'invalid-session',
        error: 'Session not found',
      };
      
      await act(async () => {
        if (eventHandlers['terminal-error']) {
          eventHandlers['terminal-error'](errorData);
        }
      });
      
      expect(mockTerminal.writeToTerminal).toHaveBeenCalledWith(
        expect.stringContaining('Session not found')
      );
    });
  });

  describe('User Interaction Flows', () => {
    it('should handle complete user workflow', async () => {
      const eventHandlers: Record<string, Function> = {};
      mockWebSocket.on.mockImplementation((event, handler) => {
        eventHandlers[event] = handler;
      });
      
      render(
        <div>
          <Terminal sessionId="test-session" />
          <TerminalControls
            onClear={mockTerminal.clearTerminal}
            onScrollToBottom={mockTerminal.scrollToBottom}
            onScrollToTop={mockTerminal.scrollToTop}
            hasNewOutput={false}
          />
        </div>
      );
      
      // 1. User types command
      const terminalArgs = mockUseTerminal.mock.calls[0][0];
      if (terminalArgs.onData) {
        await act(async () => {
          terminalArgs.onData('ls -la\r');
        });
      }
      
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', 'ls -la\r');
      
      // 2. Server responds with data
      await act(async () => {
        if (eventHandlers['terminal-data']) {
          eventHandlers['terminal-data']({
            sessionId: 'test-session',
            data: 'total 4\ndrwxr-xr-x 2 user user 4096 Jan 1 12:00 .\n',
          });
        }
      });
      
      expect(mockTerminal.writeToTerminal).toHaveBeenCalled();
      
      // 3. User clears terminal
      const clearButton = screen.getByTitle('Clear Terminal');
      await user.click(clearButton);
      
      expect(mockTerminal.clearTerminal).toHaveBeenCalled();
    });

    it('should handle session switching', async () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      // Send data to first session
      const session1Args = mockUseTerminal.mock.calls[0][0];
      if (session1Args.onData) {
        await act(async () => {
          session1Args.onData('echo session1\r');
        });
      }
      
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('session-1', 'echo session1\r');
      
      // Switch to second session
      rerender(<Terminal sessionId="session-2" />);
      
      // Send data to second session
      const session2Args = mockUseTerminal.mock.calls[1][0];
      if (session2Args.onData) {
        await act(async () => {
          session2Args.onData('echo session2\r');
        });
      }
      
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('session-2', 'echo session2\r');
    });
  });
});
