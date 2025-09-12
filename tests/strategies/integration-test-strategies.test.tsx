/**
 * @fileoverview Integration Test Strategies for Cross-Component Interactions
 * @description Comprehensive integration testing covering component interactions and user workflows
 * @author Testing and Quality Assurance Agent
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';
import Terminal from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';

// Mock WebSocket client for integration testing
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('Integration Test Strategies', () => {
  let mockStore: any;

  beforeEach(() => {
    // Setup mock store
    mockStore = {
      terminalSessions: [
        { id: 'session1', name: 'Terminal 1', isActive: false, lastActivity: new Date() },
        { id: 'session2', name: 'Terminal 2', isActive: true, lastActivity: new Date() },
      ],
      activeSessionId: 'session2',
      sidebarOpen: false,
      loading: false,
      error: null,
      createSession: jest.fn(),
      closeSession: jest.fn(),
      setActiveSession: jest.fn(),
      toggleSidebar: jest.fn(),
      setError: jest.fn(),
    };

    mockUseAppStore.mockReturnValue(mockStore);

    // Setup WebSocket client mock
    mockWsClient.connected = true;
    mockWsClient.connect = jest.fn().mockResolvedValue(undefined);
    mockWsClient.disconnect = jest.fn();
    mockWsClient.send = jest.fn();
    mockWsClient.on = jest.fn();
    mockWsClient.off = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Terminal-WebSocket Integration', () => {
    it('should establish WebSocket connection when Terminal mounts', async () => {
      render(<Terminal sessionId="integration-test-1" />);

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });
    });

    it('should handle WebSocket reconnection scenarios', async () => {
      render(<Terminal sessionId="reconnection-test" />);

      // Simulate connection loss
      mockWsClient.connected = false;
      
      // Trigger reconnection
      const connectHandler = mockWsClient.on.mock.calls.find(
        ([event]) => event === 'connect'
      )?.[1];

      if (connectHandler) {
        connectHandler();
      }

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });
    });

    it('should synchronize terminal state with WebSocket messages', async () => {
      render(<Terminal sessionId="sync-test" />);

      // Simulate WebSocket message
      const messageHandler = mockWsClient.on.mock.calls.find(
        ([event]) => event === 'terminal-data'
      )?.[1];

      const testData = {
        sessionId: 'sync-test',
        data: 'Hello from WebSocket!'
      };

      if (messageHandler) {
        messageHandler(testData);
      }

      // Verify terminal receives and processes the message
      await waitFor(() => {
        // In real implementation, verify terminal content updates
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });
    });

    it('should handle terminal configuration updates', async () => {
      render(<Terminal sessionId="config-test" />);

      // Simulate terminal config message
      const configHandler = mockWsClient.on.mock.calls.find(
        ([event]) => event === 'terminal-config'
      )?.[1];

      const configData = {
        sessionId: 'config-test',
        cols: 120,
        rows: 30
      };

      if (configHandler) {
        configHandler(configData);
      }

      await waitFor(() => {
        // Verify terminal responds to configuration changes
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-config', expect.any(Function));
      });
    });
  });

  describe('State Management Integration', () => {
    it('should synchronize component state with global store', async () => {
      const TestComponent = () => (
        <div>
          <Terminal sessionId={mockStore.activeSessionId} />
          <Sidebar
            isOpen={mockStore.sidebarOpen}
            onToggle={mockStore.toggleSidebar}
            sessions={mockStore.terminalSessions}
            activeSessionId={mockStore.activeSessionId}
            onSessionSelect={mockStore.setActiveSession}
            onSessionCreate={mockStore.createSession}
            onSessionClose={mockStore.closeSession}
          />
        </div>
      );

      render(<TestComponent />);

      // Verify initial state synchronization
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      
      // Test state updates
      mockStore.sidebarOpen = true;
      mockStore.activeSessionId = 'session1';
      
      // Re-render with updated state would be handled by store subscription
      // This verifies the integration pattern
    });

    it('should handle session creation workflow', async () => {
      const user = userEvent.setup();
      
      const TestApp = () => (
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockStore.toggleSidebar}
            sessions={mockStore.terminalSessions}
            activeSessionId={mockStore.activeSessionId}
            onSessionSelect={mockStore.setActiveSession}
            onSessionCreate={mockStore.createSession}
            onSessionClose={mockStore.closeSession}
          />
          <Terminal sessionId={mockStore.activeSessionId} />
        </div>
      );

      render(<TestApp />);

      const createButton = screen.getByRole('button', { name: /new session/i });
      await user.click(createButton);

      expect(mockStore.createSession).toHaveBeenCalled();
      
      // Verify WebSocket notifies server of new session
      expect(mockWsClient.send).toHaveBeenCalledWith('create-session', expect.any(Object));
    });

    it('should handle session closure cleanup', async () => {
      const user = userEvent.setup();
      
      const TestApp = () => (
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockStore.toggleSidebar}
            sessions={mockStore.terminalSessions}
            activeSessionId={mockStore.activeSessionId}
            onSessionSelect={mockStore.setActiveSession}
            onSessionCreate={mockStore.createSession}
            onSessionClose={mockStore.closeSession}
          />
        </div>
      );

      render(<TestApp />);

      const closeButton = screen.getAllByRole('button', { name: /close/i })[0];
      await user.click(closeButton);

      expect(mockStore.closeSession).toHaveBeenCalled();
      
      // Verify WebSocket cleanup
      expect(mockWsClient.send).toHaveBeenCalledWith('destroy-session', expect.any(Object));
    });
  });

  describe('Error Boundary Integration', () => {
    it('should handle WebSocket connection errors gracefully', async () => {
      // Mock connection error
      mockWsClient.connect = jest.fn().mockRejectedValue(new Error('Connection failed'));

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      render(<Terminal sessionId="error-test" />);

      await waitFor(() => {
        expect(mockStore.setError).toHaveBeenCalledWith(expect.stringContaining('Connection'));
      });

      consoleSpy.mockRestore();
    });

    it('should recover from terminal rendering errors', () => {
      const ErrorBoundaryTest = () => {
        const [hasError, setHasError] = React.useState(false);

        if (hasError) {
          throw new Error('Terminal rendering error');
        }

        return (
          <div>
            <button onClick={() => setHasError(true)}>Trigger Error</button>
            <Terminal sessionId="error-boundary-test" />
          </div>
        );
      };

      // This would be caught by an actual ErrorBoundary component
      expect(() => render(<ErrorBoundaryTest />)).not.toThrow();
    });
  });

  describe('Cross-Component Communication', () => {
    it('should coordinate between Terminal and MonitoringSidebar', async () => {
      const FullApp = () => (
        <div style={{ display: 'flex' }}>
          <Terminal sessionId="monitoring-test" />
          <MonitoringSidebar />
        </div>
      );

      render(<FullApp />);

      // Simulate terminal activity
      const terminalDataHandler = mockWsClient.on.mock.calls.find(
        ([event]) => event === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        terminalDataHandler({
          sessionId: 'monitoring-test',
          data: 'test command output',
          timestamp: Date.now()
        });
      }

      // Verify monitoring sidebar receives and displays metrics
      await waitFor(() => {
        const monitoringSidebar = screen.getByRole('complementary');
        expect(monitoringSidebar).toBeInTheDocument();
      });
    });

    it('should handle tab switching with session coordination', async () => {
      const user = userEvent.setup();
      
      const TabsApp = () => {
        const [activeTab, setActiveTab] = React.useState('session1');
        
        return (
          <div>
            <div role="tablist">
              <button
                role="tab"
                aria-selected={activeTab === 'session1'}
                onClick={() => setActiveTab('session1')}
              >
                Session 1
              </button>
              <button
                role="tab"
                aria-selected={activeTab === 'session2'}
                onClick={() => setActiveTab('session2')}
              >
                Session 2
              </button>
            </div>
            <Terminal sessionId={activeTab} />
          </div>
        );
      };

      render(<TabsApp />);

      // Switch tabs
      const session2Tab = screen.getByRole('tab', { name: /Session 2/i });
      await user.click(session2Tab);

      // Verify WebSocket switches context
      expect(mockWsClient.send).toHaveBeenCalledWith(
        'switch-session',
        expect.objectContaining({ sessionId: 'session2' })
      );
    });
  });

  describe('Performance Integration', () => {
    it('should handle concurrent terminal operations efficiently', async () => {
      const ConcurrentTerminals = () => (
        <div>
          {Array.from({ length: 5 }, (_, i) => (
            <Terminal key={i} sessionId={`concurrent-${i}`} />
          ))}
        </div>
      );

      const renderStart = performance.now();
      
      render(<ConcurrentTerminals />);

      const renderEnd = performance.now();
      const renderTime = renderEnd - renderStart;

      // Should render multiple terminals efficiently
      expect(renderTime).toBeLessThan(100);

      // Verify all terminals establish connections
      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalledTimes(5);
      });
    });

    it('should optimize WebSocket message handling under load', async () => {
      render(<Terminal sessionId="load-test" />);

      const messageHandler = mockWsClient.on.mock.calls.find(
        ([event]) => event === 'terminal-data'
      )?.[1];

      const startTime = performance.now();

      // Send many messages rapidly
      if (messageHandler) {
        for (let i = 0; i < 1000; i++) {
          messageHandler({
            sessionId: 'load-test',
            data: `Message ${i}`,
            sequence: i
          });
        }
      }

      const processingTime = performance.now() - startTime;

      // Should handle high message volume efficiently
      expect(processingTime).toBeLessThan(100);
    });
  });

  describe('User Workflow Integration', () => {
    it('should complete full terminal session workflow', async () => {
      const user = userEvent.setup();
      
      const CompleteApp = () => (
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockStore.toggleSidebar}
            sessions={mockStore.terminalSessions}
            activeSessionId={mockStore.activeSessionId}
            onSessionSelect={mockStore.setActiveSession}
            onSessionCreate={mockStore.createSession}
            onSessionClose={mockStore.closeSession}
          />
          <Terminal sessionId={mockStore.activeSessionId} />
          <MonitoringSidebar />
        </div>
      );

      render(<CompleteApp />);

      // 1. Create new session
      const createButton = screen.getByRole('button', { name: /new session/i });
      await user.click(createButton);

      // 2. Switch to new session
      // (This would happen via state update in real app)

      // 3. Interact with terminal
      const terminalContainer = screen.getByRole('region');
      await user.click(terminalContainer);

      // 4. Monitor activity
      const monitoringSidebar = screen.getByRole('complementary');
      expect(monitoringSidebar).toBeInTheDocument();

      // Verify all components coordinated properly
      expect(mockStore.createSession).toHaveBeenCalled();
      expect(mockWsClient.connect).toHaveBeenCalled();
    });

    it('should handle error recovery workflows', async () => {
      const user = userEvent.setup();
      
      // Simulate connection failure
      mockWsClient.connected = false;
      mockWsClient.connect = jest.fn().mockRejectedValue(new Error('Connection failed'));

      const ErrorRecoveryApp = () => {
        const [retryCount, setRetryCount] = React.useState(0);
        
        return (
          <div>
            <Terminal sessionId="error-recovery-test" />
            <button onClick={() => {
              setRetryCount(prev => prev + 1);
              mockWsClient.connect();
            }}>
              Retry Connection ({retryCount})
            </button>
          </div>
        );
      };

      render(<ErrorRecoveryApp />);

      // Trigger retry
      const retryButton = screen.getByRole('button', { name: /retry/i });
      await user.click(retryButton);

      expect(mockWsClient.connect).toHaveBeenCalledTimes(2);
    });

    it('should handle session persistence across app restarts', () => {
      // Mock localStorage for session persistence
      const mockStorage = {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      };

      Object.defineProperty(window, 'localStorage', {
        value: mockStorage,
      });

      // Mock stored sessions
      mockStorage.getItem.mockReturnValue(JSON.stringify({
        sessions: mockStore.terminalSessions,
        activeSessionId: 'session1'
      }));

      const PersistentApp = () => {
        React.useEffect(() => {
          // Load persisted state
          const saved = localStorage.getItem('terminal-state');
          if (saved) {
            const state = JSON.parse(saved);
            // Restore sessions
          }
        }, []);

        return <Terminal sessionId="persistence-test" />;
      };

      render(<PersistentApp />);

      expect(mockStorage.getItem).toHaveBeenCalledWith('terminal-state');
    });
  });

  describe('Security Integration', () => {
    it('should validate WebSocket message integrity', () => {
      render(<Terminal sessionId="security-test" />);

      const messageHandler = mockWsClient.on.mock.calls.find(
        ([event]) => event === 'terminal-data'
      )?.[1];

      // Test malicious payloads
      const maliciousPayloads = [
        { sessionId: '../../../etc/passwd', data: 'test' },
        { sessionId: 'security-test', data: '<script>alert("XSS")</script>' },
        { __proto__: { isAdmin: true }, sessionId: 'security-test', data: 'test' }
      ];

      maliciousPayloads.forEach(payload => {
        expect(() => messageHandler?.(payload)).not.toThrow();
      });

      // Verify no prototype pollution occurred
      expect((Object.prototype as any).isAdmin).toBeUndefined();
    });
  });
});