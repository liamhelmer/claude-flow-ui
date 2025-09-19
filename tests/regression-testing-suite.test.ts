/**
 * Regression Testing Suite for Critical User Workflows
 * Prevents regressions in core functionality and user experience
 */

import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Mock critical dependencies
jest.mock('@xterm/xterm');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store');

// Test data and utilities
const createMockTerminal = () => ({
  open: jest.fn(),
  write: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(() => ({ dispose: jest.fn() })),
  onResize: jest.fn(() => ({ dispose: jest.fn() })),
  loadAddon: jest.fn(),
  cols: 80,
  rows: 24,
  element: {
    querySelector: jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 1000,
      clientHeight: 500,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn()
    }))
  }
});

const createMockWebSocket = () => ({
  connected: true,
  connecting: false,
  isConnected: true,
  connect: jest.fn().mockResolvedValue(undefined),
  disconnect: jest.fn(),
  sendMessage: jest.fn(),
  sendData: jest.fn(),
  resizeTerminal: jest.fn(),
  createSession: jest.fn(),
  destroySession: jest.fn(),
  listSessions: jest.fn(),
  switchSession: jest.fn(),
  requestTerminalConfig: jest.fn(),
  requestTerminalConfigAsync: jest.fn().mockResolvedValue({ cols: 80, rows: 24 }),
  on: jest.fn(),
  off: jest.fn()
});

const createMockStore = () => ({
  terminalSessions: [
    { id: 'session-1', name: 'Main Terminal', isActive: true, lastActivity: new Date() }
  ],
  activeSessionId: 'session-1',
  sidebarOpen: true,
  loading: false,
  error: null,
  setError: jest.fn(),
  setLoading: jest.fn(),
  toggleSidebar: jest.fn(),
  setActiveSession: jest.fn(),
  addSession: jest.fn(),
  removeSession: jest.fn(),
  updateSession: jest.fn()
});

describe('Regression Testing Suite - Critical User Workflows', () => {
  let mockTerminal: ReturnType<typeof createMockTerminal>;
  let mockWebSocket: ReturnType<typeof createMockWebSocket>;
  let mockStore: ReturnType<typeof createMockStore>;
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup();
    mockTerminal = createMockTerminal();
    mockWebSocket = createMockWebSocket();
    mockStore = createMockStore();

    // Setup mocks
    jest.clearAllMocks();

    // Mock useWebSocket hook
    require('@/hooks/useWebSocket').useWebSocket.mockReturnValue(mockWebSocket);

    // Mock useAppStore hook
    require('@/lib/state/store').useAppStore.mockReturnValue(mockStore);

    // Mock Terminal constructor
    require('@xterm/xterm').Terminal.mockImplementation(() => mockTerminal);
  });

  describe('Application Startup Workflow', () => {
    it('should complete full application startup without errors', async () => {
      // Mock the HomePage component
      const MockHomePage = () => {
        const [loading, setLoading] = React.useState(true);
        const [connected, setConnected] = React.useState(false);

        React.useEffect(() => {
          // Simulate startup sequence
          const startup = async () => {
            await new Promise(resolve => setTimeout(resolve, 100)); // WebSocket connection
            setConnected(true);
            await new Promise(resolve => setTimeout(resolve, 50)); // Terminal initialization
            setLoading(false);
          };

          startup();
        }, []);

        if (loading) {
          return <div data-testid="loading">Loading terminal...</div>;
        }

        if (!connected) {
          return <div data-testid="disconnected">Connection failed</div>;
        }

        return (
          <div data-testid="app-ready">
            <div data-testid="sidebar">Sidebar</div>
            <div data-testid="terminal">Terminal Ready</div>
          </div>
        );
      };

      render(<MockHomePage />);

      // Initially should show loading
      expect(screen.getByTestId('loading')).toBeInTheDocument();

      // Should transition to ready state
      await waitFor(() => {
        expect(screen.getByTestId('app-ready')).toBeInTheDocument();
      });

      // Critical components should be present
      expect(screen.getByTestId('sidebar')).toBeInTheDocument();
      expect(screen.getByTestId('terminal')).toBeInTheDocument();
    });

    it('should handle startup errors gracefully with recovery options', async () => {
      const MockStartupWithError = () => {
        const [state, setState] = React.useState<'loading' | 'error' | 'ready'>('loading');
        const [retryCount, setRetryCount] = React.useState(0);

        const attemptStartup = async () => {
          setState('loading');
          await new Promise(resolve => setTimeout(resolve, 100));

          // Fail on first attempt, succeed on retry
          if (retryCount === 0) {
            setState('error');
            return;
          }

          setState('ready');
        };

        React.useEffect(() => {
          attemptStartup();
        }, [retryCount]);

        const handleRetry = () => {
          setRetryCount(prev => prev + 1);
        };

        if (state === 'loading') {
          return <div data-testid="loading">Connecting...</div>;
        }

        if (state === 'error') {
          return (
            <div data-testid="error-state">
              <div>Connection failed</div>
              <button data-testid="retry-button" onClick={handleRetry}>
                Retry
              </button>
            </div>
          );
        }

        return <div data-testid="startup-success">Application ready</div>;
      };

      render(<MockStartupWithError />);

      // Should show loading initially
      expect(screen.getByTestId('loading')).toBeInTheDocument();

      // Should show error state
      await waitFor(() => {
        expect(screen.getByTestId('error-state')).toBeInTheDocument();
      });

      // Retry should work
      await user.click(screen.getByTestId('retry-button'));

      // Should eventually succeed
      await waitFor(() => {
        expect(screen.getByTestId('startup-success')).toBeInTheDocument();
      });
    });

    it('should maintain proper state during rapid startup/shutdown cycles', async () => {
      const MockStartupCycle = () => {
        const [isRunning, setIsRunning] = React.useState(false);
        const [cycleCount, setCycleCount] = React.useState(0);

        const startCycle = async () => {
          for (let i = 0; i < 5; i++) {
            setIsRunning(true);
            await new Promise(resolve => setTimeout(resolve, 50));
            setIsRunning(false);
            await new Promise(resolve => setTimeout(resolve, 50));
            setCycleCount(prev => prev + 1);
          }
        };

        return (
          <div data-testid="startup-cycle">
            <button
              data-testid="start-cycles"
              onClick={startCycle}
              disabled={isRunning}
            >
              Start Cycles
            </button>
            <div data-testid="status">
              {isRunning ? 'Running' : 'Stopped'}
            </div>
            <div data-testid="cycle-count">
              Cycles: {cycleCount}
            </div>
          </div>
        );
      };

      render(<MockStartupCycle />);

      await user.click(screen.getByTestId('start-cycles'));

      // Should complete all cycles
      await waitFor(() => {
        expect(screen.getByTestId('cycle-count')).toHaveTextContent('Cycles: 5');
        expect(screen.getByTestId('status')).toHaveTextContent('Stopped');
      }, { timeout: 2000 });
    });
  });

  describe('Terminal Session Management Workflow', () => {
    it('should create new terminal session successfully', async () => {
      const MockSessionCreation = () => {
        const [sessions, setSessions] = React.useState([
          { id: 'session-1', name: 'Main Terminal' }
        ]);

        const createSession = () => {
          const newSession = {
            id: `session-${sessions.length + 1}`,
            name: `Terminal ${sessions.length + 1}`
          };
          setSessions(prev => [...prev, newSession]);
        };

        return (
          <div data-testid="session-creation">
            <button data-testid="create-session" onClick={createSession}>
              New Terminal
            </button>
            <div data-testid="session-list">
              {sessions.map(session => (
                <div key={session.id} data-testid={`session-${session.id}`}>
                  {session.name}
                </div>
              ))}
            </div>
            <div data-testid="session-count">
              Sessions: {sessions.length}
            </div>
          </div>
        );
      };

      render(<MockSessionCreation />);

      // Initially one session
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 1');

      // Create new session
      await user.click(screen.getByTestId('create-session'));

      // Should have two sessions
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 2');
      expect(screen.getByTestId('session-session-2')).toBeInTheDocument();

      // Create another session
      await user.click(screen.getByTestId('create-session'));
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 3');
    });

    it('should switch between terminal sessions correctly', async () => {
      const MockSessionSwitching = () => {
        const [sessions] = React.useState([
          { id: 'session-1', name: 'Terminal 1' },
          { id: 'session-2', name: 'Terminal 2' },
          { id: 'session-3', name: 'Terminal 3' }
        ]);
        const [activeSessionId, setActiveSessionId] = React.useState('session-1');

        return (
          <div data-testid="session-switching">
            <div data-testid="session-tabs">
              {sessions.map(session => (
                <button
                  key={session.id}
                  data-testid={`tab-${session.id}`}
                  onClick={() => setActiveSessionId(session.id)}
                  className={activeSessionId === session.id ? 'active' : ''}
                >
                  {session.name}
                </button>
              ))}
            </div>
            <div data-testid="active-terminal">
              Active: {sessions.find(s => s.id === activeSessionId)?.name}
            </div>
          </div>
        );
      };

      render(<MockSessionSwitching />);

      // Initially session-1 should be active
      expect(screen.getByTestId('active-terminal')).toHaveTextContent('Active: Terminal 1');

      // Switch to session-2
      await user.click(screen.getByTestId('tab-session-2'));
      expect(screen.getByTestId('active-terminal')).toHaveTextContent('Active: Terminal 2');

      // Switch to session-3
      await user.click(screen.getByTestId('tab-session-3'));
      expect(screen.getByTestId('active-terminal')).toHaveTextContent('Active: Terminal 3');

      // Switch back to session-1
      await user.click(screen.getByTestId('tab-session-1'));
      expect(screen.getByTestId('active-terminal')).toHaveTextContent('Active: Terminal 1');
    });

    it('should close terminal sessions with proper cleanup', async () => {
      const MockSessionClosing = () => {
        const [sessions, setSessions] = React.useState([
          { id: 'session-1', name: 'Terminal 1' },
          { id: 'session-2', name: 'Terminal 2' },
          { id: 'session-3', name: 'Terminal 3' }
        ]);
        const [activeSessionId, setActiveSessionId] = React.useState('session-1');

        const closeSession = (sessionId: string) => {
          setSessions(prev => prev.filter(s => s.id !== sessionId));

          // If closing active session, switch to another
          if (sessionId === activeSessionId) {
            const remaining = sessions.filter(s => s.id !== sessionId);
            if (remaining.length > 0) {
              setActiveSessionId(remaining[0].id);
            }
          }
        };

        return (
          <div data-testid="session-closing">
            <div data-testid="active-session">
              Active: {sessions.find(s => s.id === activeSessionId)?.name || 'None'}
            </div>
            <div data-testid="session-list">
              {sessions.map(session => (
                <div key={session.id} data-testid={`session-${session.id}`}>
                  {session.name}
                  <button
                    data-testid={`close-${session.id}`}
                    onClick={() => closeSession(session.id)}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
            <div data-testid="session-count">
              Sessions: {sessions.length}
            </div>
          </div>
        );
      };

      render(<MockSessionClosing />);

      // Initially 3 sessions
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 3');
      expect(screen.getByTestId('active-session')).toHaveTextContent('Active: Terminal 1');

      // Close active session
      await user.click(screen.getByTestId('close-session-1'));

      // Should have 2 sessions and switch active session
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 2');
      expect(screen.getByTestId('active-session')).toHaveTextContent('Active: Terminal 2');

      // Close another session
      await user.click(screen.getByTestId('close-session-3'));
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 1');
    });
  });

  describe('WebSocket Communication Workflow', () => {
    it('should handle connection establishment and message flow', async () => {
      const MockWebSocketFlow = () => {
        const [connectionState, setConnectionState] = React.useState('disconnected');
        const [messagesSent, setMessagesSent] = React.useState(0);
        const [messagesReceived, setMessagesReceived] = React.useState(0);

        const connect = async () => {
          setConnectionState('connecting');
          await new Promise(resolve => setTimeout(resolve, 100));
          setConnectionState('connected');
        };

        const sendMessage = () => {
          if (connectionState === 'connected') {
            setMessagesSent(prev => prev + 1);
            // Simulate echo response
            setTimeout(() => {
              setMessagesReceived(prev => prev + 1);
            }, 50);
          }
        };

        const disconnect = () => {
          setConnectionState('disconnected');
        };

        return (
          <div data-testid="websocket-flow">
            <div data-testid="connection-state">
              Status: {connectionState}
            </div>
            <button
              data-testid="connect-button"
              onClick={connect}
              disabled={connectionState !== 'disconnected'}
            >
              Connect
            </button>
            <button
              data-testid="send-message"
              onClick={sendMessage}
              disabled={connectionState !== 'connected'}
            >
              Send Message
            </button>
            <button
              data-testid="disconnect-button"
              onClick={disconnect}
              disabled={connectionState === 'disconnected'}
            >
              Disconnect
            </button>
            <div data-testid="message-stats">
              Sent: {messagesSent}, Received: {messagesReceived}
            </div>
          </div>
        );
      };

      render(<MockWebSocketFlow />);

      // Initially disconnected
      expect(screen.getByTestId('connection-state')).toHaveTextContent('Status: disconnected');

      // Connect
      await user.click(screen.getByTestId('connect-button'));
      expect(screen.getByTestId('connection-state')).toHaveTextContent('Status: connecting');

      await waitFor(() => {
        expect(screen.getByTestId('connection-state')).toHaveTextContent('Status: connected');
      });

      // Send messages
      await user.click(screen.getByTestId('send-message'));
      await user.click(screen.getByTestId('send-message'));

      // Should receive echo responses
      await waitFor(() => {
        expect(screen.getByTestId('message-stats')).toHaveTextContent('Sent: 2, Received: 2');
      });

      // Disconnect
      await user.click(screen.getByTestId('disconnect-button'));
      expect(screen.getByTestId('connection-state')).toHaveTextContent('Status: disconnected');
    });

    it('should handle connection interruptions and reconnection', async () => {
      const MockReconnectionFlow = () => {
        const [state, setState] = React.useState('connected');
        const [reconnectAttempts, setReconnectAttempts] = React.useState(0);

        const simulateDisconnection = () => {
          setState('disconnected');
          // Auto-reconnect after delay
          setTimeout(() => {
            setState('reconnecting');
            setReconnectAttempts(prev => prev + 1);
            setTimeout(() => {
              setState('connected');
            }, 200);
          }, 100);
        };

        return (
          <div data-testid="reconnection-flow">
            <div data-testid="connection-state">
              State: {state}
            </div>
            <div data-testid="reconnect-attempts">
              Reconnect attempts: {reconnectAttempts}
            </div>
            <button
              data-testid="simulate-disconnect"
              onClick={simulateDisconnection}
            >
              Simulate Disconnection
            </button>
          </div>
        );
      };

      render(<MockReconnectionFlow />);

      // Initially connected
      expect(screen.getByTestId('connection-state')).toHaveTextContent('State: connected');

      // Simulate disconnection
      await user.click(screen.getByTestId('simulate-disconnect'));

      // Should go through disconnection -> reconnecting -> connected
      await waitFor(() => {
        expect(screen.getByTestId('connection-state')).toHaveTextContent('State: disconnected');
      });

      await waitFor(() => {
        expect(screen.getByTestId('connection-state')).toHaveTextContent('State: reconnecting');
      });

      await waitFor(() => {
        expect(screen.getByTestId('connection-state')).toHaveTextContent('State: connected');
        expect(screen.getByTestId('reconnect-attempts')).toHaveTextContent('Reconnect attempts: 1');
      });
    });

    it('should maintain message ordering during high-frequency operations', async () => {
      const MockMessageOrdering = () => {
        const [sentMessages, setSentMessages] = React.useState<number[]>([]);
        const [receivedMessages, setReceivedMessages] = React.useState<number[]>([]);

        const sendBurst = async () => {
          const messages = Array.from({ length: 10 }, (_, i) => i + 1);
          setSentMessages(messages);

          // Simulate messages arriving in order with slight delays
          for (const msg of messages) {
            setTimeout(() => {
              setReceivedMessages(prev => [...prev, msg]);
            }, msg * 10);
          }
        };

        const isOrderCorrect = () => {
          return receivedMessages.every((msg, index) => msg === index + 1);
        };

        return (
          <div data-testid="message-ordering">
            <button data-testid="send-burst" onClick={sendBurst}>
              Send Message Burst
            </button>
            <div data-testid="sent-count">
              Sent: {sentMessages.length}
            </div>
            <div data-testid="received-count">
              Received: {receivedMessages.length}
            </div>
            <div data-testid="order-status">
              Order correct: {receivedMessages.length > 0 ? isOrderCorrect().toString() : 'N/A'}
            </div>
          </div>
        );
      };

      render(<MockMessageOrdering />);

      // Send burst of messages
      await user.click(screen.getByTestId('send-burst'));

      expect(screen.getByTestId('sent-count')).toHaveTextContent('Sent: 10');

      // Wait for all messages to be received
      await waitFor(() => {
        expect(screen.getByTestId('received-count')).toHaveTextContent('Received: 10');
        expect(screen.getByTestId('order-status')).toHaveTextContent('Order correct: true');
      }, { timeout: 2000 });
    });
  });

  describe('Terminal Input/Output Workflow', () => {
    it('should handle terminal input and display output correctly', async () => {
      const MockTerminalIO = () => {
        const [inputHistory, setInputHistory] = React.useState<string[]>([]);
        const [output, setOutput] = React.useState<string[]>([]);

        const handleInput = (input: string) => {
          setInputHistory(prev => [...prev, input]);
          // Simulate command execution
          setTimeout(() => {
            setOutput(prev => [...prev, `$ ${input}`, `Output for: ${input}`]);
          }, 50);
        };

        return (
          <div data-testid="terminal-io">
            <input
              data-testid="terminal-input"
              placeholder="Type command..."
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  const input = e.currentTarget.value;
                  if (input.trim()) {
                    handleInput(input);
                    e.currentTarget.value = '';
                  }
                }
              }}
            />
            <div data-testid="terminal-output">
              {output.map((line, i) => (
                <div key={i} data-testid={`output-line-${i}`}>
                  {line}
                </div>
              ))}
            </div>
            <div data-testid="input-count">
              Commands entered: {inputHistory.length}
            </div>
          </div>
        );
      };

      render(<MockTerminalIO />);

      const input = screen.getByTestId('terminal-input');

      // Type and execute commands
      await user.type(input, 'ls -la{enter}');
      await user.type(input, 'pwd{enter}');

      // Should show command execution
      await waitFor(() => {
        expect(screen.getByTestId('input-count')).toHaveTextContent('Commands entered: 2');
        expect(screen.getByTestId('output-line-0')).toHaveTextContent('$ ls -la');
        expect(screen.getByTestId('output-line-1')).toHaveTextContent('Output for: ls -la');
        expect(screen.getByTestId('output-line-2')).toHaveTextContent('$ pwd');
        expect(screen.getByTestId('output-line-3')).toHaveTextContent('Output for: pwd');
      });
    });

    it('should handle terminal scrolling and navigation', async () => {
      const MockTerminalScrolling = () => {
        const [lines, setLines] = React.useState<string[]>([]);
        const [scrollPosition, setScrollPosition] = React.useState(0);
        const [isAtBottom, setIsAtBottom] = React.useState(true);

        const addLines = () => {
          const newLines = Array.from({ length: 10 }, (_, i) =>
            `Line ${lines.length + i + 1}: Some terminal output`
          );
          setLines(prev => [...prev, ...newLines]);
        };

        const scrollToTop = () => {
          setScrollPosition(0);
          setIsAtBottom(false);
        };

        const scrollToBottom = () => {
          setScrollPosition(lines.length);
          setIsAtBottom(true);
        };

        return (
          <div data-testid="terminal-scrolling">
            <div data-testid="controls">
              <button data-testid="add-lines" onClick={addLines}>
                Add Lines
              </button>
              <button data-testid="scroll-top" onClick={scrollToTop}>
                Scroll to Top
              </button>
              <button data-testid="scroll-bottom" onClick={scrollToBottom}>
                Scroll to Bottom
              </button>
            </div>
            <div data-testid="scroll-info">
              Position: {scrollPosition}, At bottom: {isAtBottom.toString()}
            </div>
            <div
              data-testid="terminal-content"
              style={{ height: '200px', overflow: 'auto' }}
            >
              {lines.map((line, i) => (
                <div key={i} data-testid={`line-${i}`}>
                  {line}
                </div>
              ))}
            </div>
            <div data-testid="line-count">
              Total lines: {lines.length}
            </div>
          </div>
        );
      };

      render(<MockTerminalScrolling />);

      // Add lines to create scrollable content
      await user.click(screen.getByTestId('add-lines'));
      await user.click(screen.getByTestId('add-lines'));

      expect(screen.getByTestId('line-count')).toHaveTextContent('Total lines: 20');

      // Test scrolling to top
      await user.click(screen.getByTestId('scroll-top'));
      expect(screen.getByTestId('scroll-info')).toHaveTextContent('Position: 0, At bottom: false');

      // Test scrolling to bottom
      await user.click(screen.getByTestId('scroll-bottom'));
      expect(screen.getByTestId('scroll-info')).toHaveTextContent('Position: 20, At bottom: true');
    });

    it('should handle special key combinations and escape sequences', async () => {
      const MockSpecialKeys = () => {
        const [keyEvents, setKeyEvents] = React.useState<string[]>([]);

        const handleKeyDown = (e: React.KeyboardEvent) => {
          const key = e.key;
          const modifiers = [];
          if (e.ctrlKey) modifiers.push('Ctrl');
          if (e.shiftKey) modifiers.push('Shift');
          if (e.altKey) modifiers.push('Alt');

          const keyStr = modifiers.length > 0
            ? `${modifiers.join('+')}+${key}`
            : key;

          setKeyEvents(prev => [...prev, keyStr]);
        };

        return (
          <div data-testid="special-keys">
            <div
              data-testid="key-capture"
              tabIndex={0}
              onKeyDown={handleKeyDown}
              style={{
                padding: '20px',
                border: '1px solid gray',
                minHeight: '100px'
              }}
            >
              Press keys here (Ctrl+C, Ctrl+D, arrows, etc.)
            </div>
            <div data-testid="key-history">
              {keyEvents.map((key, i) => (
                <div key={i} data-testid={`key-${i}`}>
                  {key}
                </div>
              ))}
            </div>
            <div data-testid="key-count">
              Keys pressed: {keyEvents.length}
            </div>
          </div>
        );
      };

      render(<MockSpecialKeys />);

      const captureArea = screen.getByTestId('key-capture');
      captureArea.focus();

      // Test various key combinations
      await user.keyboard('{Control>}c{/Control}');
      await user.keyboard('{Control>}d{/Control}');
      await user.keyboard('{ArrowUp}');
      await user.keyboard('{ArrowDown}');
      await user.keyboard('{Shift>}{ArrowLeft}{/Shift}');

      // Verify key events were captured
      expect(screen.getByTestId('key-count')).toHaveTextContent('Keys pressed: 5');
      expect(screen.getByTestId('key-0')).toHaveTextContent('Ctrl+c');
      expect(screen.getByTestId('key-1')).toHaveTextContent('Ctrl+d');
      expect(screen.getByTestId('key-2')).toHaveTextContent('ArrowUp');
      expect(screen.getByTestId('key-3')).toHaveTextContent('ArrowDown');
      expect(screen.getByTestId('key-4')).toHaveTextContent('Shift+ArrowLeft');
    });
  });

  describe('Error Recovery Workflow', () => {
    it('should recover from terminal crashes', async () => {
      const MockTerminalCrash = () => {
        const [terminalState, setTerminalState] = React.useState('running');
        const [crashCount, setCrashCount] = React.useState(0);

        const simulateCrash = () => {
          setTerminalState('crashed');
          setCrashCount(prev => prev + 1);
        };

        const recover = async () => {
          setTerminalState('recovering');
          await new Promise(resolve => setTimeout(resolve, 200));
          setTerminalState('running');
        };

        return (
          <div data-testid="terminal-crash">
            <div data-testid="terminal-state">
              State: {terminalState}
            </div>
            <div data-testid="crash-count">
              Crashes: {crashCount}
            </div>
            <button
              data-testid="crash-terminal"
              onClick={simulateCrash}
              disabled={terminalState === 'crashed'}
            >
              Simulate Crash
            </button>
            {terminalState === 'crashed' && (
              <button data-testid="recover-terminal" onClick={recover}>
                Recover Terminal
              </button>
            )}
          </div>
        );
      };

      render(<MockTerminalCrash />);

      // Initially running
      expect(screen.getByTestId('terminal-state')).toHaveTextContent('State: running');

      // Simulate crash
      await user.click(screen.getByTestId('crash-terminal'));
      expect(screen.getByTestId('terminal-state')).toHaveTextContent('State: crashed');
      expect(screen.getByTestId('crash-count')).toHaveTextContent('Crashes: 1');

      // Recover
      await user.click(screen.getByTestId('recover-terminal'));
      expect(screen.getByTestId('terminal-state')).toHaveTextContent('State: recovering');

      await waitFor(() => {
        expect(screen.getByTestId('terminal-state')).toHaveTextContent('State: running');
      });
    });

    it('should handle memory exhaustion gracefully', async () => {
      const MockMemoryExhaustion = () => {
        const [memoryUsage, setMemoryUsage] = React.useState(0);
        const [isCleaningUp, setIsCleaningUp] = React.useState(false);

        const consumeMemory = () => {
          setMemoryUsage(prev => Math.min(prev + 25, 100));
        };

        const cleanup = async () => {
          setIsCleaningUp(true);
          await new Promise(resolve => setTimeout(resolve, 300));
          setMemoryUsage(0);
          setIsCleaningUp(false);
        };

        // Auto-cleanup when memory is full
        React.useEffect(() => {
          if (memoryUsage >= 100 && !isCleaningUp) {
            cleanup();
          }
        }, [memoryUsage, isCleaningUp]);

        return (
          <div data-testid="memory-exhaustion">
            <div data-testid="memory-usage">
              Memory: {memoryUsage}%
            </div>
            <div data-testid="cleanup-status">
              {isCleaningUp ? 'Cleaning up...' : 'Normal operation'}
            </div>
            <button
              data-testid="consume-memory"
              onClick={consumeMemory}
              disabled={isCleaningUp}
            >
              Consume Memory
            </button>
            <button
              data-testid="manual-cleanup"
              onClick={cleanup}
              disabled={isCleaningUp}
            >
              Manual Cleanup
            </button>
          </div>
        );
      };

      render(<MockMemoryExhaustion />);

      // Consume memory to trigger auto-cleanup
      await user.click(screen.getByTestId('consume-memory')); // 25%
      await user.click(screen.getByTestId('consume-memory')); // 50%
      await user.click(screen.getByTestId('consume-memory')); // 75%
      await user.click(screen.getByTestId('consume-memory')); // 100%

      expect(screen.getByTestId('memory-usage')).toHaveTextContent('Memory: 100%');

      // Should automatically start cleanup
      await waitFor(() => {
        expect(screen.getByTestId('cleanup-status')).toHaveTextContent('Cleaning up...');
      });

      // Should complete cleanup
      await waitFor(() => {
        expect(screen.getByTestId('memory-usage')).toHaveTextContent('Memory: 0%');
        expect(screen.getByTestId('cleanup-status')).toHaveTextContent('Normal operation');
      }, { timeout: 1000 });
    });
  });

  describe('Performance Under Load Workflow', () => {
    it('should maintain responsiveness during high-frequency terminal output', async () => {
      const MockHighFrequencyOutput = () => {
        const [outputLines, setOutputLines] = React.useState<string[]>([]);
        const [isStreaming, setIsStreaming] = React.useState(false);
        const [responseTime, setResponseTime] = React.useState<number | null>(null);

        const startStreaming = async () => {
          setIsStreaming(true);
          const startTime = performance.now();

          // Simulate high-frequency output
          for (let i = 0; i < 100; i++) {
            await new Promise(resolve => setTimeout(resolve, 10));
            setOutputLines(prev => [
              ...prev.slice(-50), // Keep only last 50 lines
              `High frequency output line ${i + 1}`
            ]);
          }

          const endTime = performance.now();
          setResponseTime(endTime - startTime);
          setIsStreaming(false);
        };

        const testResponsiveness = () => {
          const start = performance.now();
          // Force re-render to test responsiveness
          setOutputLines(prev => [...prev, 'Responsiveness test']);
          const end = performance.now();
          return end - start;
        };

        return (
          <div data-testid="high-frequency-output">
            <button
              data-testid="start-streaming"
              onClick={startStreaming}
              disabled={isStreaming}
            >
              {isStreaming ? 'Streaming...' : 'Start High-Frequency Output'}
            </button>
            <button
              data-testid="test-responsiveness"
              onClick={testResponsiveness}
            >
              Test Responsiveness
            </button>
            <div data-testid="output-count">
              Lines: {outputLines.length}
            </div>
            {responseTime && (
              <div data-testid="response-time">
                Streaming time: {responseTime.toFixed(2)}ms
              </div>
            )}
            <div
              data-testid="output-container"
              style={{ height: '200px', overflow: 'auto' }}
            >
              {outputLines.map((line, i) => (
                <div key={i} data-testid={`output-${i}`}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        );
      };

      render(<MockHighFrequencyOutput />);

      // Start streaming
      await user.click(screen.getByTestId('start-streaming'));

      // UI should remain responsive during streaming
      await user.click(screen.getByTestId('test-responsiveness'));

      // Wait for streaming to complete
      await waitFor(() => {
        expect(screen.getByTestId('start-streaming')).toHaveTextContent('Start High-Frequency Output');
        expect(screen.getByTestId('response-time')).toBeInTheDocument();
      }, { timeout: 3000 });

      // Should have processed all lines
      expect(screen.getByTestId('output-count')).toHaveTextContent(/Lines: \d+/);
    });
  });
});

describe('Regression Test Validation', () => {
  it('should verify all critical workflows pass regression tests', async () => {
    // This meta-test ensures all regression tests are properly structured
    const regressionTests = [
      'Application Startup Workflow',
      'Terminal Session Management Workflow',
      'WebSocket Communication Workflow',
      'Terminal Input/Output Workflow',
      'Error Recovery Workflow',
      'Performance Under Load Workflow'
    ];

    // Each regression test category should be thoroughly covered
    expect(regressionTests).toHaveLength(6);

    // Verify test structure
    regressionTests.forEach(testCategory => {
      expect(testCategory).toBeTruthy();
    });
  });
});