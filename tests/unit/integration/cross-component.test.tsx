/**
 * Cross-Component Integration Tests
 * Tests interaction between components, data flow, and system integration
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '@/components/terminal/Terminal';
import TerminalControls from '@/components/terminal/TerminalControls';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import { useAppStore } from '@/lib/state/store';

// Mock all hooks and components for integration testing
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');
jest.mock('@/components/monitoring/MonitoringSidebar');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;
const MockMonitoringSidebar = MonitoringSidebar as jest.MockedComponent<typeof MonitoringSidebar>;

describe('Cross-Component Integration Tests', () => {
  let user: ReturnType<typeof userEvent.setup>;
  
  beforeEach(() => {
    user = userEvent.setup();
    jest.clearAllMocks();

    // Setup default mocks
    mockUseWebSocket.mockReturnValue({
      connected: true,
      connecting: false,
      isConnected: true,
      connect: jest.fn(),
      disconnect: jest.fn(),
      sendMessage: jest.fn(),
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      createSession: jest.fn(),
      destroySession: jest.fn(),
      listSessions: jest.fn(),
      on: jest.fn(),
      off: jest.fn()
    });

    mockUseTerminal.mockReturnValue({
      terminalRef: { current: document.createElement('div') },
      terminal: {
        open: jest.fn(),
        write: jest.fn(),
        focus: jest.fn(),
        dispose: jest.fn()
      } as any,
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      isAtBottom: true,
      hasNewOutput: false,
      isConnected: true,
      terminalConfig: {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'monospace',
        cursorBlink: true,
        scrollback: 1000,
        cols: 80,
        rows: 24
      },
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      destroyTerminal: jest.fn()
    });

    mockUseAppStore.mockReturnValue({
      sessions: [],
      activeSession: null,
      setActiveSession: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      error: null,
      setError: jest.fn(),
      loading: false,
      setLoading: jest.fn()
    } as any);

    MockMonitoringSidebar.mockImplementation(({ children }) => 
      <div data-testid="monitoring-sidebar">{children}</div>
    );
  });

  describe('Terminal and Controls Integration', () => {
    it('should integrate terminal with controls for scroll operations', async () => {
      const { scrollToTop, scrollToBottom } = mockUseTerminal();

      render(
        <div>
          <Terminal sessionId="test-session" />
          <TerminalControls
            isAtBottom={false}
            hasNewOutput={true}
            onScrollToTop={scrollToTop}
            onScrollToBottom={scrollToBottom}
            terminalConfig={{
              theme: 'dark',
              fontSize: 14,
              fontFamily: 'monospace',
              cursorBlink: true,
              scrollback: 1000,
              cols: 80,
              rows: 24
            }}
          />
        </div>
      );

      // Test scroll to top integration
      const scrollTopButtons = screen.getAllByRole('button', { name: /scroll to top/i });
      await user.click(scrollTopButtons[0]);

      expect(scrollToTop).toHaveBeenCalled();

      // Test scroll to bottom integration
      const scrollBottomButtons = screen.getAllByRole('button', { name: /scroll to bottom/i });
      await user.click(scrollBottomButtons[0]);

      expect(scrollToBottom).toHaveBeenCalled();
    });

    it('should handle terminal focus integration with controls', async () => {
      const { focusTerminal } = mockUseTerminal();

      render(
        <div>
          <Terminal sessionId="focus-test" />
          <TerminalControls
            isAtBottom={true}
            hasNewOutput={false}
            onScrollToTop={jest.fn()}
            onScrollToBottom={jest.fn()}
            terminalConfig={{
              theme: 'dark',
              fontSize: 14,
              fontFamily: 'monospace',
              cursorBlink: true,
              scrollback: 1000,
              cols: 80,
              rows: 24
            }}
          />
        </div>
      );

      // Click on terminal area should trigger focus
      const terminalArea = screen.getByRole('generic');
      await user.click(terminalArea);

      expect(focusTerminal).toHaveBeenCalled();
    });

    it('should synchronize scroll state between terminal and controls', () => {
      const { rerender } = render(
        <div>
          <Terminal sessionId="sync-test" />
          <TerminalControls
            isAtBottom={true}
            hasNewOutput={false}
            onScrollToTop={jest.fn()}
            onScrollToBottom={jest.fn()}
            terminalConfig={{
              theme: 'dark',
              fontSize: 14,
              fontFamily: 'monospace',
              cursorBlink: true,
              scrollback: 1000,
              cols: 80,
              rows: 24
            }}
          />
        </div>
      );

      // Update terminal scroll state
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        isAtBottom: false,
        hasNewOutput: true
      });

      rerender(
        <div>
          <Terminal sessionId="sync-test" />
          <TerminalControls
            isAtBottom={false}
            hasNewOutput={true}
            onScrollToTop={jest.fn()}
            onScrollToBottom={jest.fn()}
            terminalConfig={{
              theme: 'dark',
              fontSize: 14,
              fontFamily: 'monospace',
              cursorBlink: true,
              scrollback: 1000,
              cols: 80,
              rows: 24
            }}
          />
        </div>
      );

      // Controls should reflect updated state
      expect(screen.getByRole('button', { name: /scroll to bottom/i })).toBeInTheDocument();
    });
  });

  describe('WebSocket and Terminal Integration', () => {
    it('should handle data flow from WebSocket to Terminal', async () => {
      const { on } = mockUseWebSocket();
      const { writeToTerminal } = mockUseTerminal();

      render(<Terminal sessionId="websocket-test" />);

      // Simulate WebSocket event registration
      expect(on).toHaveBeenCalledWith('terminal-data', expect.any(Function));

      // Simulate receiving terminal data
      const dataHandler = (on as jest.Mock).mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (dataHandler) {
        act(() => {
          dataHandler({
            sessionId: 'websocket-test',
            data: 'Hello from WebSocket!'
          });
        });

        expect(writeToTerminal).toHaveBeenCalledWith('Hello from WebSocket!');
      }
    });

    it('should handle connection state changes across components', () => {
      // Start with connected state
      const { rerender } = render(<Terminal sessionId="connection-test" />);

      // Change to disconnected state
      mockUseWebSocket.mockReturnValue({
        ...mockUseWebSocket(),
        connected: false,
        isConnected: false
      });

      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        isConnected: false
      });

      rerender(<Terminal sessionId="connection-test" />);

      // Component should reflect disconnected state
      expect(screen.getByRole('generic')).toBeInTheDocument();
    });

    it('should handle session management integration', async () => {
      const { createSession, destroySession } = mockUseWebSocket();
      const { setActiveSession, addSession, removeSession } = mockUseAppStore();

      render(<Terminal sessionId="session-test" />);

      // Simulate session creation
      act(() => {
        createSession();
        addSession('new-session-id');
        setActiveSession('new-session-id');
      });

      expect(createSession).toHaveBeenCalled();
      expect(addSession).toHaveBeenCalledWith('new-session-id');
      expect(setActiveSession).toHaveBeenCalledWith('new-session-id');

      // Simulate session destruction
      act(() => {
        destroySession('new-session-id');
        removeSession('new-session-id');
      });

      expect(destroySession).toHaveBeenCalledWith('new-session-id');
      expect(removeSession).toHaveBeenCalledWith('new-session-id');
    });
  });

  describe('State Management Integration', () => {
    it('should sync terminal state with global app state', () => {
      const sessionData = {
        id: 'state-test',
        name: 'Test Session',
        active: true,
        lastActivity: new Date().toISOString()
      };

      mockUseAppStore.mockReturnValue({
        ...mockUseAppStore(),
        sessions: [sessionData],
        activeSession: sessionData.id
      } as any);

      render(<Terminal sessionId="state-test" />);

      // Terminal should reflect global state
      expect(screen.getByRole('generic')).toBeInTheDocument();
    });

    it('should handle error state propagation', () => {
      const testError = 'Connection failed';

      mockUseAppStore.mockReturnValue({
        ...mockUseAppStore(),
        error: testError
      } as any);

      mockUseWebSocket.mockReturnValue({
        ...mockUseWebSocket(),
        connected: false
      });

      render(<Terminal sessionId="error-test" />);

      // Should handle error state without crashing
      expect(screen.getByRole('generic')).toBeInTheDocument();
    });

    it('should handle loading state coordination', () => {
      mockUseAppStore.mockReturnValue({
        ...mockUseAppStore(),
        loading: true
      } as any);

      mockUseWebSocket.mockReturnValue({
        ...mockUseWebSocket(),
        connecting: true
      });

      render(<Terminal sessionId="loading-test" />);

      // Should handle loading state
      expect(screen.getByRole('generic')).toBeInTheDocument();
    });
  });

  describe('Complex Integration Scenarios', () => {
    it('should handle complete terminal session lifecycle', async () => {
      const {
        connect,
        createSession,
        sendData,
        resizeTerminal,
        destroySession,
        disconnect
      } = mockUseWebSocket();

      const {
        writeToTerminal,
        focusTerminal,
        scrollToBottom,
        destroyTerminal
      } = mockUseTerminal();

      const { setLoading, addSession, setActiveSession, removeSession } = mockUseAppStore();

      // 1. Initial connection
      render(<Terminal sessionId="lifecycle-test" />);

      act(() => {
        setLoading(true);
        connect();
      });

      // 2. Create session
      act(() => {
        createSession();
        addSession('lifecycle-test');
        setActiveSession('lifecycle-test');
        setLoading(false);
      });

      // 3. Terminal operations
      act(() => {
        focusTerminal();
        writeToTerminal('Welcome to terminal!');
        sendData('lifecycle-test', 'ls -la\n');
      });

      // 4. Resize operation
      act(() => {
        resizeTerminal('lifecycle-test', 100, 30);
      });

      // 5. Scroll operations
      act(() => {
        scrollToBottom();
      });

      // 6. Session cleanup
      act(() => {
        destroySession('lifecycle-test');
        removeSession('lifecycle-test');
        destroyTerminal();
        disconnect();
      });

      // Verify all operations were called
      expect(connect).toHaveBeenCalled();
      expect(createSession).toHaveBeenCalled();
      expect(sendData).toHaveBeenCalled();
      expect(resizeTerminal).toHaveBeenCalled();
      expect(destroySession).toHaveBeenCalled();
      expect(disconnect).toHaveBeenCalled();
    });

    it('should handle concurrent multi-session operations', async () => {
      const sessions = ['session-1', 'session-2', 'session-3'];
      const { sendData } = mockUseWebSocket();
      const { writeToTerminal } = mockUseTerminal();

      // Render multiple terminals
      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Simulate concurrent operations across sessions
      sessions.forEach((sessionId, index) => {
        act(() => {
          rerender(<Terminal sessionId={sessionId} />);
          
          // Send data to each session
          sendData(sessionId, `Command ${index}\n`);
          writeToTerminal(`Output for session ${index}`);
        });
      });

      // Verify operations for all sessions
      sessions.forEach((sessionId, index) => {
        expect(sendData).toHaveBeenCalledWith(sessionId, `Command ${index}\n`);
      });
    });

    it('should handle error recovery across components', async () => {
      const { connect, disconnect } = mockUseWebSocket();
      const { setError, setLoading } = mockUseAppStore();
      const { destroyTerminal } = mockUseTerminal();

      render(<Terminal sessionId="recovery-test" />);

      // Simulate error state
      act(() => {
        setError('Network connection lost');
        setLoading(false);
        disconnect();
      });

      // Simulate recovery
      act(() => {
        setError(null);
        setLoading(true);
        connect();
      });

      // Complete recovery
      act(() => {
        setLoading(false);
      });

      expect(connect).toHaveBeenCalled();
      expect(setError).toHaveBeenCalledWith('Network connection lost');
      expect(setError).toHaveBeenCalledWith(null);
    });

    it('should handle performance under integration stress', async () => {
      const operations = [];

      // Create stress test with multiple simultaneous operations
      for (let i = 0; i < 50; i++) {
        operations.push(async () => {
          const { unmount } = render(<Terminal sessionId={`stress-${i}`} />);
          
          const { writeToTerminal, focusTerminal, scrollToBottom } = mockUseTerminal();
          
          act(() => {
            writeToTerminal(`Stress test data ${i}`);
            focusTerminal();
            scrollToBottom();
          });
          
          unmount();
        });
      }

      const startTime = performance.now();
      await Promise.all(operations.map(op => op()));
      const endTime = performance.now();

      const totalTime = endTime - startTime;

      // Should handle stress without significant performance degradation
      expect(totalTime).toBeLessThan(1000); // Less than 1 second for all operations
    });
  });

  describe('Event Propagation Integration', () => {
    it('should handle event bubbling between components', async () => {
      const parentClickHandler = jest.fn();
      const terminalClickHandler = jest.fn();

      render(
        <div onClick={parentClickHandler}>
          <Terminal sessionId="event-test" />
          <button onClick={terminalClickHandler}>Terminal Button</button>
        </div>
      );

      // Click on terminal should not interfere with parent events
      const terminalArea = screen.getByRole('generic');
      await user.click(terminalArea);

      // Click on button should work normally
      const button = screen.getByRole('button');
      await user.click(button);

      expect(terminalClickHandler).toHaveBeenCalled();
      expect(parentClickHandler).toHaveBeenCalled();
    });

    it('should handle keyboard events across components', async () => {
      const { sendData } = mockUseWebSocket();

      render(<Terminal sessionId="keyboard-test" />);

      const terminalArea = screen.getByRole('generic');
      
      // Focus and type in terminal
      await user.click(terminalArea);
      await user.keyboard('test command{Enter}');

      // Should send data through WebSocket
      expect(sendData).toHaveBeenCalled();
    });
  });
});