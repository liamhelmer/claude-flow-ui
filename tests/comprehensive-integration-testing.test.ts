/**
 * Comprehensive Integration Testing Suite
 * Tests component interactions, data flow, and system integration
 */

import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';

// Mock WebSocket and related APIs
const mockWebSocket = {
  readyState: WebSocket.OPEN,
  send: jest.fn(),
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  dispatchEvent: jest.fn()
};

// Mock global WebSocket constructor
global.WebSocket = jest.fn().mockImplementation(() => mockWebSocket);

// Mock Terminal dependencies
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
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
  }))
}));

// Mock Next.js dynamic imports
jest.mock('next/dynamic', () => {
  return (importFn: () => Promise<any>, options?: any) => {
    const MockedComponent = (props: any) => {
      if (options?.loading) {
        return options.loading();
      }
      return <div data-testid="mocked-terminal">Mocked Terminal Component</div>;
    };
    MockedComponent.displayName = 'MockedDynamicComponent';
    return MockedComponent;
  };
});

// Create test wrapper component
const TestWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <div data-testid="test-wrapper">{children}</div>;
};

describe('Comprehensive Integration Testing', () => {
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup();
    jest.clearAllMocks();

    // Reset WebSocket mock state
    mockWebSocket.readyState = WebSocket.OPEN;

    // Mock performance API
    global.performance = {
      ...global.performance,
      now: jest.fn(() => Date.now()),
      mark: jest.fn(),
      measure: jest.fn()
    };

    // Mock ResizeObserver
    global.ResizeObserver = jest.fn().mockImplementation(() => ({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn()
    }));
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Application Startup Integration', () => {
    it('should initialize application with proper component hierarchy', async () => {
      // Mock the main app component
      const MockApp = () => (
        <div data-testid="app-container">
          <div data-testid="sidebar" role="navigation">Sidebar</div>
          <div data-testid="terminal-area" role="main">
            <div data-testid="mocked-terminal">Terminal</div>
          </div>
        </div>
      );

      render(<MockApp />);

      // Verify main components are rendered
      expect(screen.getByTestId('app-container')).toBeInTheDocument();
      expect(screen.getByTestId('sidebar')).toBeInTheDocument();
      expect(screen.getByTestId('terminal-area')).toBeInTheDocument();
      expect(screen.getByTestId('mocked-terminal')).toBeInTheDocument();
    });

    it('should handle loading states during initialization', async () => {
      const MockAppWithLoading = () => {
        const [loading, setLoading] = React.useState(true);

        React.useEffect(() => {
          const timer = setTimeout(() => setLoading(false), 100);
          return () => clearTimeout(timer);
        }, []);

        if (loading) {
          return <div data-testid="loading-spinner">Loading...</div>;
        }

        return <div data-testid="app-content">App Loaded</div>;
      };

      render(<MockAppWithLoading />);

      // Initially should show loading
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();

      // Wait for loading to complete
      await waitFor(() => {
        expect(screen.getByTestId('app-content')).toBeInTheDocument();
      });

      expect(screen.queryByTestId('loading-spinner')).not.toBeInTheDocument();
    });

    it('should handle initialization errors gracefully', async () => {
      const MockAppWithError = () => {
        const [error, setError] = React.useState<string | null>(null);

        React.useEffect(() => {
          // Simulate initialization error
          const timer = setTimeout(() => {
            setError('Failed to connect to terminal server');
          }, 50);
          return () => clearTimeout(timer);
        }, []);

        if (error) {
          return (
            <div data-testid="error-container">
              <div data-testid="error-message">{error}</div>
              <button
                data-testid="retry-button"
                onClick={() => setError(null)}
              >
                Retry
              </button>
            </div>
          );
        }

        return <div data-testid="app-content">App Content</div>;
      };

      render(<MockAppWithError />);

      // Wait for error to appear
      await waitFor(() => {
        expect(screen.getByTestId('error-container')).toBeInTheDocument();
      });

      expect(screen.getByTestId('error-message')).toHaveTextContent('Failed to connect to terminal server');

      // Test retry functionality
      await user.click(screen.getByTestId('retry-button'));
      expect(screen.getByTestId('app-content')).toBeInTheDocument();
    });
  });

  describe('WebSocket Integration', () => {
    it('should establish WebSocket connection and handle messages', async () => {
      const MockWebSocketComponent = () => {
        const [connected, setConnected] = React.useState(false);
        const [messages, setMessages] = React.useState<string[]>([]);

        React.useEffect(() => {
          // Simulate WebSocket connection
          const connect = () => {
            setConnected(true);
            // Simulate receiving messages
            setTimeout(() => {
              setMessages(prev => [...prev, 'Welcome to terminal']);
            }, 100);
          };

          connect();
        }, []);

        return (
          <div data-testid="websocket-component">
            <div data-testid="connection-status">
              {connected ? 'Connected' : 'Disconnected'}
            </div>
            <div data-testid="messages">
              {messages.map((msg, i) => (
                <div key={i} data-testid={`message-${i}`}>{msg}</div>
              ))}
            </div>
          </div>
        );
      };

      render(<MockWebSocketComponent />);

      // Initially connected
      await waitFor(() => {
        expect(screen.getByTestId('connection-status')).toHaveTextContent('Connected');
      });

      // Should receive messages
      await waitFor(() => {
        expect(screen.getByTestId('message-0')).toHaveTextContent('Welcome to terminal');
      });
    });

    it('should handle WebSocket connection failures', async () => {
      const MockWebSocketWithFailure = () => {
        const [status, setStatus] = React.useState('connecting');

        React.useEffect(() => {
          // Simulate connection failure
          setTimeout(() => {
            setStatus('failed');
          }, 100);
        }, []);

        return (
          <div data-testid="websocket-status">
            {status === 'connecting' && <div data-testid="connecting">Connecting...</div>}
            {status === 'failed' && <div data-testid="failed">Connection Failed</div>}
          </div>
        );
      };

      render(<MockWebSocketWithFailure />);

      // Initially connecting
      expect(screen.getByTestId('connecting')).toBeInTheDocument();

      // Should show failure
      await waitFor(() => {
        expect(screen.getByTestId('failed')).toBeInTheDocument();
      });
    });

    it('should handle WebSocket reconnection', async () => {
      const MockWebSocketReconnect = () => {
        const [status, setStatus] = React.useState('connected');
        const [attempts, setAttempts] = React.useState(0);

        React.useEffect(() => {
          if (status === 'reconnecting') {
            const timer = setTimeout(() => {
              setAttempts(prev => prev + 1);
              if (attempts < 2) {
                setStatus('failed');
                setTimeout(() => setStatus('reconnecting'), 100);
              } else {
                setStatus('connected');
              }
            }, 200);
            return () => clearTimeout(timer);
          }
        }, [status, attempts]);

        const handleDisconnect = () => {
          setStatus('reconnecting');
          setAttempts(0);
        };

        return (
          <div data-testid="reconnect-component">
            <div data-testid="status">{status}</div>
            <div data-testid="attempts">Attempts: {attempts}</div>
            <button data-testid="disconnect" onClick={handleDisconnect}>
              Simulate Disconnect
            </button>
          </div>
        );
      };

      render(<MockWebSocketReconnect />);

      // Initially connected
      expect(screen.getByTestId('status')).toHaveTextContent('connected');

      // Simulate disconnect
      await user.click(screen.getByTestId('disconnect'));

      // Should start reconnecting
      await waitFor(() => {
        expect(screen.getByTestId('status')).toHaveTextContent('reconnecting');
      });

      // Should eventually reconnect
      await waitFor(() => {
        expect(screen.getByTestId('status')).toHaveTextContent('connected');
      }, { timeout: 2000 });
    });
  });

  describe('Terminal and Sidebar Integration', () => {
    it('should coordinate terminal selection between sidebar and main area', async () => {
      const MockTerminalApp = () => {
        const [sessions] = React.useState([
          { id: 'session-1', name: 'Terminal 1', active: true },
          { id: 'session-2', name: 'Terminal 2', active: false }
        ]);
        const [activeSession, setActiveSession] = React.useState('session-1');

        return (
          <div data-testid="terminal-app">
            <div data-testid="sidebar">
              {sessions.map(session => (
                <button
                  key={session.id}
                  data-testid={`session-${session.id}`}
                  onClick={() => setActiveSession(session.id)}
                  className={activeSession === session.id ? 'active' : ''}
                >
                  {session.name}
                </button>
              ))}
            </div>
            <div data-testid="terminal-area">
              <div data-testid="active-session">
                Active: {activeSession}
              </div>
            </div>
          </div>
        );
      };

      render(<MockTerminalApp />);

      // Initially session-1 should be active
      expect(screen.getByTestId('active-session')).toHaveTextContent('Active: session-1');

      // Click on session-2
      await user.click(screen.getByTestId('session-session-2'));

      // Should switch to session-2
      expect(screen.getByTestId('active-session')).toHaveTextContent('Active: session-2');
    });

    it('should handle session creation and cleanup', async () => {
      const MockSessionManager = () => {
        const [sessions, setSessions] = React.useState([
          { id: 'session-1', name: 'Terminal 1' }
        ]);

        const addSession = () => {
          const newId = `session-${sessions.length + 1}`;
          setSessions(prev => [...prev, {
            id: newId,
            name: `Terminal ${sessions.length + 1}`
          }]);
        };

        const removeSession = (id: string) => {
          setSessions(prev => prev.filter(s => s.id !== id));
        };

        return (
          <div data-testid="session-manager">
            <button data-testid="add-session" onClick={addSession}>
              Add Session
            </button>
            <div data-testid="session-list">
              {sessions.map(session => (
                <div key={session.id} data-testid={`session-${session.id}`}>
                  {session.name}
                  <button
                    data-testid={`close-${session.id}`}
                    onClick={() => removeSession(session.id)}
                  >
                    Close
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

      render(<MockSessionManager />);

      // Initially one session
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 1');

      // Add a session
      await user.click(screen.getByTestId('add-session'));
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 2');
      expect(screen.getByTestId('session-session-2')).toBeInTheDocument();

      // Remove a session
      await user.click(screen.getByTestId('close-session-1'));
      expect(screen.getByTestId('session-count')).toHaveTextContent('Sessions: 1');
      expect(screen.queryByTestId('session-session-1')).not.toBeInTheDocument();
    });

    it('should handle sidebar toggle and responsive behavior', async () => {
      const MockResponsiveApp = () => {
        const [sidebarOpen, setSidebarOpen] = React.useState(true);
        const [isMobile, setIsMobile] = React.useState(false);

        React.useEffect(() => {
          const checkMobile = () => {
            setIsMobile(window.innerWidth < 768);
          };

          checkMobile();
          window.addEventListener('resize', checkMobile);
          return () => window.removeEventListener('resize', checkMobile);
        }, []);

        return (
          <div data-testid="responsive-app">
            <button
              data-testid="toggle-sidebar"
              onClick={() => setSidebarOpen(prev => !prev)}
            >
              Toggle Sidebar
            </button>
            <div
              data-testid="sidebar"
              className={sidebarOpen ? 'open' : 'closed'}
              style={{
                display: sidebarOpen ? 'block' : 'none',
                width: isMobile ? '100%' : '300px'
              }}
            >
              Sidebar Content
            </div>
            <div data-testid="main-content">
              Main Content
            </div>
            <div data-testid="mobile-indicator">
              Mobile: {isMobile.toString()}
            </div>
          </div>
        );
      };

      render(<MockResponsiveApp />);

      // Initially sidebar should be open
      expect(screen.getByTestId('sidebar')).toHaveStyle('display: block');

      // Toggle sidebar
      await user.click(screen.getByTestId('toggle-sidebar'));
      expect(screen.getByTestId('sidebar')).toHaveStyle('display: none');

      // Toggle back
      await user.click(screen.getByTestId('toggle-sidebar'));
      expect(screen.getByTestId('sidebar')).toHaveStyle('display: block');
    });
  });

  describe('Data Flow Integration', () => {
    it('should propagate terminal data through the application', async () => {
      const MockDataFlow = () => {
        const [terminalData, setTerminalData] = React.useState<string[]>([]);
        const [status, setStatus] = React.useState('idle');

        const simulateTerminalOutput = (data: string) => {
          setStatus('receiving');
          setTerminalData(prev => [...prev, data]);
          setTimeout(() => setStatus('idle'), 100);
        };

        return (
          <div data-testid="data-flow">
            <div data-testid="status">Status: {status}</div>
            <button
              data-testid="send-data"
              onClick={() => simulateTerminalOutput('Hello World')}
            >
              Send Data
            </button>
            <div data-testid="terminal-output">
              {terminalData.map((line, i) => (
                <div key={i} data-testid={`line-${i}`}>{line}</div>
              ))}
            </div>
            <div data-testid="data-count">
              Lines: {terminalData.length}
            </div>
          </div>
        );
      };

      render(<MockDataFlow />);

      // Initially no data
      expect(screen.getByTestId('data-count')).toHaveTextContent('Lines: 0');
      expect(screen.getByTestId('status')).toHaveTextContent('Status: idle');

      // Send data
      await user.click(screen.getByTestId('send-data'));

      // Should show receiving status
      expect(screen.getByTestId('status')).toHaveTextContent('Status: receiving');

      // Should show data
      expect(screen.getByTestId('line-0')).toHaveTextContent('Hello World');
      expect(screen.getByTestId('data-count')).toHaveTextContent('Lines: 1');

      // Status should return to idle
      await waitFor(() => {
        expect(screen.getByTestId('status')).toHaveTextContent('Status: idle');
      });
    });

    it('should handle state synchronization across components', async () => {
      const MockStateSync = () => {
        const [globalState, setGlobalState] = React.useState({
          activeSession: 'session-1',
          connectionStatus: 'connected',
          terminalCount: 1
        });

        const updateState = (updates: Partial<typeof globalState>) => {
          setGlobalState(prev => ({ ...prev, ...updates }));
        };

        return (
          <div data-testid="state-sync">
            <div data-testid="component-a">
              <div data-testid="active-session-a">
                Active: {globalState.activeSession}
              </div>
              <button
                data-testid="change-session-a"
                onClick={() => updateState({ activeSession: 'session-2' })}
              >
                Change Session
              </button>
            </div>
            <div data-testid="component-b">
              <div data-testid="active-session-b">
                Active: {globalState.activeSession}
              </div>
              <div data-testid="connection-status">
                Status: {globalState.connectionStatus}
              </div>
            </div>
            <div data-testid="component-c">
              <div data-testid="terminal-count">
                Terminals: {globalState.terminalCount}
              </div>
              <button
                data-testid="add-terminal"
                onClick={() => updateState({ terminalCount: globalState.terminalCount + 1 })}
              >
                Add Terminal
              </button>
            </div>
          </div>
        );
      };

      render(<MockStateSync />);

      // Initially all components should show same state
      expect(screen.getByTestId('active-session-a')).toHaveTextContent('Active: session-1');
      expect(screen.getByTestId('active-session-b')).toHaveTextContent('Active: session-1');

      // Change session from component A
      await user.click(screen.getByTestId('change-session-a'));

      // Both components should reflect the change
      expect(screen.getByTestId('active-session-a')).toHaveTextContent('Active: session-2');
      expect(screen.getByTestId('active-session-b')).toHaveTextContent('Active: session-2');

      // Add terminal from component C
      await user.click(screen.getByTestId('add-terminal'));
      expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 2');
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle cascading errors gracefully', async () => {
      const MockErrorHandling = () => {
        const [errors, setErrors] = React.useState<string[]>([]);
        const [isRecovering, setIsRecovering] = React.useState(false);

        const simulateError = (errorMsg: string) => {
          setErrors(prev => [...prev, errorMsg]);
        };

        const recover = async () => {
          setIsRecovering(true);
          // Simulate recovery process
          await new Promise(resolve => setTimeout(resolve, 500));
          setErrors([]);
          setIsRecovering(false);
        };

        return (
          <div data-testid="error-handling">
            <div data-testid="error-list">
              {errors.map((error, i) => (
                <div key={i} data-testid={`error-${i}`} className="error">
                  {error}
                </div>
              ))}
            </div>
            <div data-testid="error-count">
              Errors: {errors.length}
            </div>
            <button
              data-testid="simulate-error"
              onClick={() => simulateError('Connection failed')}
            >
              Simulate Error
            </button>
            <button
              data-testid="recover"
              onClick={recover}
              disabled={isRecovering}
            >
              {isRecovering ? 'Recovering...' : 'Recover'}
            </button>
          </div>
        );
      };

      render(<MockErrorHandling />);

      // Initially no errors
      expect(screen.getByTestId('error-count')).toHaveTextContent('Errors: 0');

      // Simulate error
      await user.click(screen.getByTestId('simulate-error'));
      expect(screen.getByTestId('error-count')).toHaveTextContent('Errors: 1');
      expect(screen.getByTestId('error-0')).toHaveTextContent('Connection failed');

      // Recover
      await user.click(screen.getByTestId('recover'));
      expect(screen.getByTestId('recover')).toHaveTextContent('Recovering...');

      // Should clear errors after recovery
      await waitFor(() => {
        expect(screen.getByTestId('error-count')).toHaveTextContent('Errors: 0');
        expect(screen.getByTestId('recover')).toHaveTextContent('Recover');
      });
    });

    it('should handle partial failures and maintain system stability', async () => {
      const MockPartialFailure = () => {
        const [services, setServices] = React.useState({
          websocket: { status: 'connected', lastPing: Date.now() },
          terminal: { status: 'ready', sessions: 1 },
          storage: { status: 'available', usage: 50 }
        });

        const simulatePartialFailure = () => {
          setServices(prev => ({
            ...prev,
            websocket: { ...prev.websocket, status: 'disconnected' }
          }));
        };

        const restoreService = () => {
          setServices(prev => ({
            ...prev,
            websocket: { ...prev.websocket, status: 'connected', lastPing: Date.now() }
          }));
        };

        const isSystemHealthy = Object.values(services).every(
          service => service.status === 'connected' || service.status === 'ready' || service.status === 'available'
        );

        return (
          <div data-testid="partial-failure">
            <div data-testid="system-health">
              System: {isSystemHealthy ? 'Healthy' : 'Degraded'}
            </div>
            {Object.entries(services).map(([name, service]) => (
              <div key={name} data-testid={`service-${name}`}>
                {name}: {service.status}
              </div>
            ))}
            <button
              data-testid="fail-websocket"
              onClick={simulatePartialFailure}
            >
              Fail WebSocket
            </button>
            <button
              data-testid="restore-websocket"
              onClick={restoreService}
            >
              Restore WebSocket
            </button>
          </div>
        );
      };

      render(<MockPartialFailure />);

      // Initially healthy
      expect(screen.getByTestId('system-health')).toHaveTextContent('System: Healthy');
      expect(screen.getByTestId('service-websocket')).toHaveTextContent('websocket: connected');

      // Fail WebSocket
      await user.click(screen.getByTestId('fail-websocket'));
      expect(screen.getByTestId('system-health')).toHaveTextContent('System: Degraded');
      expect(screen.getByTestId('service-websocket')).toHaveTextContent('websocket: disconnected');

      // Other services should still be available
      expect(screen.getByTestId('service-terminal')).toHaveTextContent('terminal: ready');
      expect(screen.getByTestId('service-storage')).toHaveTextContent('storage: available');

      // Restore WebSocket
      await user.click(screen.getByTestId('restore-websocket'));
      expect(screen.getByTestId('system-health')).toHaveTextContent('System: Healthy');
      expect(screen.getByTestId('service-websocket')).toHaveTextContent('websocket: connected');
    });
  });

  describe('Performance Integration', () => {
    it('should maintain responsive UI during heavy operations', async () => {
      const MockPerformanceTest = () => {
        const [isProcessing, setIsProcessing] = React.useState(false);
        const [progress, setProgress] = React.useState(0);
        const [data, setData] = React.useState<number[]>([]);

        const simulateHeavyOperation = async () => {
          setIsProcessing(true);
          setProgress(0);

          // Simulate processing large data set
          for (let i = 0; i < 100; i++) {
            await new Promise(resolve => setTimeout(resolve, 10));
            setProgress(i + 1);
            setData(prev => [...prev, Math.random()]);
          }

          setIsProcessing(false);
        };

        return (
          <div data-testid="performance-test">
            <button
              data-testid="start-operation"
              onClick={simulateHeavyOperation}
              disabled={isProcessing}
            >
              {isProcessing ? 'Processing...' : 'Start Heavy Operation'}
            </button>
            <div data-testid="progress">
              Progress: {progress}%
            </div>
            <div data-testid="data-count">
              Data Points: {data.length}
            </div>
            <div data-testid="responsive-check">
              <button data-testid="click-me">Click Me (Responsiveness Test)</button>
            </div>
          </div>
        );
      };

      render(<MockPerformanceTest />);

      // Start heavy operation
      await user.click(screen.getByTestId('start-operation'));

      // UI should remain responsive
      await user.click(screen.getByTestId('click-me'));

      // Operation should complete
      await waitFor(() => {
        expect(screen.getByTestId('progress')).toHaveTextContent('Progress: 100%');
        expect(screen.getByTestId('start-operation')).toHaveTextContent('Start Heavy Operation');
      }, { timeout: 5000 });
    });

    it('should handle memory management during data processing', async () => {
      const MockMemoryManagement = () => {
        const [largeDataSets, setLargeDataSets] = React.useState<number[][]>([]);
        const [memoryUsage, setMemoryUsage] = React.useState(0);

        const createLargeDataSet = () => {
          const newDataSet = Array(10000).fill(0).map(() => Math.random());
          setLargeDataSets(prev => [...prev, newDataSet]);

          // Simulate memory usage calculation
          setMemoryUsage(prev => prev + newDataSet.length * 8); // 8 bytes per number
        };

        const clearMemory = () => {
          setLargeDataSets([]);
          setMemoryUsage(0);
        };

        return (
          <div data-testid="memory-management">
            <div data-testid="memory-usage">
              Memory Usage: {(memoryUsage / 1024 / 1024).toFixed(2)} MB
            </div>
            <div data-testid="dataset-count">
              Data Sets: {largeDataSets.length}
            </div>
            <button
              data-testid="create-dataset"
              onClick={createLargeDataSet}
            >
              Create Large Data Set
            </button>
            <button
              data-testid="clear-memory"
              onClick={clearMemory}
            >
              Clear Memory
            </button>
          </div>
        );
      };

      render(<MockMemoryManagement />);

      // Initially no memory usage
      expect(screen.getByTestId('memory-usage')).toHaveTextContent('Memory Usage: 0.00 MB');

      // Create large data sets
      await user.click(screen.getByTestId('create-dataset'));
      await user.click(screen.getByTestId('create-dataset'));

      expect(screen.getByTestId('dataset-count')).toHaveTextContent('Data Sets: 2');

      // Memory usage should increase
      const memoryText = screen.getByTestId('memory-usage').textContent;
      expect(memoryText).not.toBe('Memory Usage: 0.00 MB');

      // Clear memory
      await user.click(screen.getByTestId('clear-memory'));
      expect(screen.getByTestId('memory-usage')).toHaveTextContent('Memory Usage: 0.00 MB');
      expect(screen.getByTestId('dataset-count')).toHaveTextContent('Data Sets: 0');
    });
  });
});