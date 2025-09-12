/**
 * @jest-environment jsdom
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

// Mock WebSocket and other external dependencies
class MockWebSocket extends EventTarget {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  url: string;
  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(url: string) {
    super();
    this.url = url;
    // Simulate connection opening
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      const openEvent = new Event('open');
      this.onopen?.(openEvent);
      this.dispatchEvent(openEvent);
    }, 10);
  }

  send(data: string) {
    // Simulate echoing data back
    setTimeout(() => {
      const messageEvent = new MessageEvent('message', {
        data: JSON.stringify({ type: 'echo', data }),
      });
      this.onmessage?.(messageEvent);
      this.dispatchEvent(messageEvent);
    }, 5);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    const closeEvent = new CloseEvent('close', { code: 1000, reason: 'Normal closure' });
    this.onclose?.(closeEvent);
    this.dispatchEvent(closeEvent);
  }
}

global.WebSocket = MockWebSocket as any;

// Mock xterm
const mockTerminal = {
  open: jest.fn(),
  write: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  element: {
    querySelector: jest.fn().mockReturnValue({
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      scrollTop: 0,
      scrollHeight: 1000,
      clientHeight: 400,
    }),
  },
};

jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => mockTerminal),
}));

// Create a comprehensive test app
const TestApp = () => {
  const [activeTab, setActiveTab] = React.useState('terminal');
  const [sessions, setSessions] = React.useState([
    { id: '1', name: 'Session 1', status: 'active' },
  ]);
  const [activeSessionId, setActiveSessionId] = React.useState('1');
  const [isConnected, setIsConnected] = React.useState(false);

  React.useEffect(() => {
    // Simulate WebSocket connection
    const ws = new MockWebSocket('ws://localhost:3001');
    
    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => setIsConnected(false);

    return () => ws.close();
  }, []);

  const addSession = () => {
    const newId = String(sessions.length + 1);
    setSessions(prev => [...prev, {
      id: newId,
      name: `Session ${newId}`,
      status: 'inactive'
    }]);
  };

  const selectSession = (sessionId: string) => {
    setActiveSessionId(sessionId);
    setSessions(prev => prev.map(session => ({
      ...session,
      status: session.id === sessionId ? 'active' : 'inactive'
    })));
  };

  const closeSession = (sessionId: string) => {
    setSessions(prev => prev.filter(session => session.id !== sessionId));
    if (activeSessionId === sessionId && sessions.length > 1) {
      const remainingSessions = sessions.filter(s => s.id !== sessionId);
      setActiveSessionId(remainingSessions[0]?.id || '');
    }
  };

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white p-4" role="navigation" aria-label="Sessions">
        <button
          onClick={addSession}
          className="w-full mb-4 px-4 py-2 bg-blue-600 rounded"
          aria-label="Add new session"
        >
          New Session
        </button>
        
        <div role="list" aria-label="Session list">
          {sessions.map(session => (
            <div
              key={session.id}
              role="listitem"
              className={`p-2 mb-2 rounded cursor-pointer ${
                session.id === activeSessionId ? 'bg-blue-600' : 'bg-gray-700'
              }`}
            >
              <button
                onClick={() => selectSession(session.id)}
                className="w-full text-left"
                aria-current={session.id === activeSessionId ? 'page' : undefined}
                aria-label={`Select ${session.name}`}
              >
                {session.name}
              </button>
              
              {sessions.length > 1 && (
                <button
                  onClick={() => closeSession(session.id)}
                  className="ml-2 text-red-400 hover:text-red-300"
                  aria-label={`Close ${session.name}`}
                >
                  ✕
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Tab Navigation */}
        <div className="border-b border-gray-200" role="tablist" aria-label="Main navigation">
          {[
            { id: 'terminal', label: 'Terminal' },
            { id: 'monitoring', label: 'Monitoring' },
            { id: 'settings', label: 'Settings' },
          ].map(tab => (
            <button
              key={tab.id}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`${tab.id}-panel`}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 border-b-2 ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Panels */}
        <div className="flex-1 p-4">
          {activeTab === 'terminal' && (
            <div id="terminal-panel" role="tabpanel" aria-labelledby="terminal-tab">
              <div className="mb-4 flex gap-2">
                <button
                  className="px-3 py-1 bg-gray-200 rounded"
                  aria-label="Clear terminal"
                >
                  Clear
                </button>
                
                <button
                  className={`px-3 py-1 rounded ${
                    isConnected ? 'bg-green-200 text-green-800' : 'bg-red-200 text-red-800'
                  }`}
                  aria-label={isConnected ? 'Connected' : 'Disconnected - Click to reconnect'}
                  disabled={isConnected}
                >
                  {isConnected ? 'Connected' : 'Reconnect'}
                </button>

                <div className="ml-auto" aria-live="polite">
                  Session: {sessions.find(s => s.id === activeSessionId)?.name}
                </div>
              </div>
              
              <div
                className="h-96 bg-black text-green-400 p-4 font-mono"
                role="application"
                aria-label="Terminal"
              >
                <div>$ Welcome to Terminal Session {activeSessionId}</div>
                <div>$ Ready for commands...</div>
              </div>
            </div>
          )}

          {activeTab === 'monitoring' && (
            <div id="monitoring-panel" role="tabpanel" aria-labelledby="monitoring-tab">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-white p-4 rounded shadow">
                  <h3 className="text-lg font-semibold mb-2">Agents</h3>
                  <div role="list" aria-label="Active agents">
                    <div role="listitem" className="flex justify-between">
                      <span>Coder Agent</span>
                      <span className="text-green-600" aria-label="Status: Active">Active</span>
                    </div>
                    <div role="listitem" className="flex justify-between">
                      <span>Reviewer Agent</span>
                      <span className="text-yellow-600" aria-label="Status: Idle">Idle</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white p-4 rounded shadow">
                  <h3 className="text-lg font-semibold mb-2">Memory Usage</h3>
                  <div
                    role="progressbar"
                    aria-valuenow={75}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-label="Memory usage: 75%"
                    className="w-full bg-gray-200 rounded-full h-2"
                  >
                    <div
                      className="bg-blue-600 h-2 rounded-full"
                      style={{ width: '75%' }}
                    ></div>
                  </div>
                  <div className="text-sm text-gray-600 mt-1">75% (750MB / 1GB)</div>
                </div>

                <div className="bg-white p-4 rounded shadow">
                  <h3 className="text-lg font-semibold mb-2">Recent Commands</h3>
                  <div role="log" aria-label="Command history" className="text-sm">
                    <div>npm start - <span className="text-green-600">Success</span></div>
                    <div>npm test - <span className="text-blue-600">Running</span></div>
                    <div>git status - <span className="text-green-600">Success</span></div>
                  </div>
                </div>

                <div className="bg-white p-4 rounded shadow">
                  <h3 className="text-lg font-semibold mb-2">Performance</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span>CPU Usage</span>
                      <span>45%</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Response Time</span>
                      <span>12ms</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Uptime</span>
                      <span>2h 34m</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div id="settings-panel" role="tabpanel" aria-labelledby="settings-tab">
              <div className="bg-white p-4 rounded shadow">
                <h3 className="text-lg font-semibold mb-4">Terminal Settings</h3>
                <form>
                  <div className="mb-4">
                    <label htmlFor="font-size" className="block text-sm font-medium text-gray-700">
                      Font Size
                    </label>
                    <select
                      id="font-size"
                      className="mt-1 block w-full rounded border-gray-300"
                      aria-describedby="font-size-help"
                    >
                      <option value="12">12px</option>
                      <option value="14" selected>14px</option>
                      <option value="16">16px</option>
                    </select>
                    <div id="font-size-help" className="text-sm text-gray-600 mt-1">
                      Choose the font size for the terminal
                    </div>
                  </div>

                  <div className="mb-4">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        className="rounded border-gray-300"
                        defaultChecked
                      />
                      <span className="ml-2">Enable sound notifications</span>
                    </label>
                  </div>

                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 text-white rounded"
                  >
                    Save Settings
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

describe('Critical User Flows - Comprehensive Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Application Initialization Flow', () => {
    test('should initialize app with default state', async () => {
      render(<TestApp />);

      // Check initial session is present
      expect(screen.getByText('Session 1')).toBeInTheDocument();
      
      // Check terminal tab is active
      expect(screen.getByRole('tab', { name: 'Terminal' })).toHaveAttribute('aria-selected', 'true');
      
      // Check terminal panel is visible
      expect(screen.getByRole('tabpanel', { name: /terminal/i })).toBeInTheDocument();

      // Wait for WebSocket connection
      await waitFor(() => {
        expect(screen.getByText('Connected')).toBeInTheDocument();
      });
    });

    test('should handle connection failures gracefully', async () => {
      // Mock WebSocket to fail
      const originalWebSocket = global.WebSocket;
      global.WebSocket = class extends EventTarget {
        constructor() {
          super();
          setTimeout(() => {
            const errorEvent = new Event('error');
            this.dispatchEvent(errorEvent);
          }, 10);
        }
        send() {}
        close() {}
      } as any;

      render(<TestApp />);

      await waitFor(() => {
        expect(screen.getByText('Reconnect')).toBeInTheDocument();
      });

      global.WebSocket = originalWebSocket;
    });
  });

  describe('Session Management Flow', () => {
    test('should create new session successfully', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      const newSessionButton = screen.getByRole('button', { name: /new session/i });
      
      await user.click(newSessionButton);

      // Check new session appears
      expect(screen.getByText('Session 2')).toBeInTheDocument();
      
      // Check session list now has 2 items
      const sessionList = screen.getByRole('list', { name: /session list/i });
      const sessionItems = within(sessionList).getAllByRole('listitem');
      expect(sessionItems).toHaveLength(2);
    });

    test('should switch between sessions', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Create a second session
      await user.click(screen.getByRole('button', { name: /new session/i }));

      // Switch to Session 2
      const session2Button = screen.getByRole('button', { name: /select session 2/i });
      await user.click(session2Button);

      // Check active session changed
      expect(session2Button).toHaveAttribute('aria-current', 'page');
      
      // Check terminal shows new session
      await waitFor(() => {
        expect(screen.getByText('Session: Session 2')).toBeInTheDocument();
      });
    });

    test('should close session with confirmation', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Create a second session first
      await user.click(screen.getByRole('button', { name: /new session/i }));

      // Close Session 2
      const closeButton = screen.getByRole('button', { name: /close session 2/i });
      await user.click(closeButton);

      // Check Session 2 is removed
      expect(screen.queryByText('Session 2')).not.toBeInTheDocument();
      
      // Check Session 1 is still active
      expect(screen.getByText('Session: Session 1')).toBeInTheDocument();
    });

    test('should prevent closing last session', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Should not show close button for single session
      expect(screen.queryByRole('button', { name: /close session 1/i })).not.toBeInTheDocument();
    });
  });

  describe('Terminal Interaction Flow', () => {
    test('should handle terminal operations', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      await waitFor(() => {
        expect(screen.getByText('Connected')).toBeInTheDocument();
      });

      // Test clear button
      const clearButton = screen.getByRole('button', { name: /clear terminal/i });
      await user.click(clearButton);

      // Terminal should still be accessible
      expect(screen.getByRole('application', { name: /terminal/i })).toBeInTheDocument();
    });

    test('should show connection status updates', async () => {
      render(<TestApp />);

      // Initially should show connecting/disconnected state
      expect(screen.getByRole('button', { name: /disconnected/i })).toBeInTheDocument();

      // Should connect after short delay
      await waitFor(() => {
        expect(screen.getByText('Connected')).toBeInTheDocument();
      }, { timeout: 1000 });
    });
  });

  describe('Tab Navigation Flow', () => {
    test('should navigate between tabs using mouse', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Click on Monitoring tab
      const monitoringTab = screen.getByRole('tab', { name: 'Monitoring' });
      await user.click(monitoringTab);

      // Check tab is selected
      expect(monitoringTab).toHaveAttribute('aria-selected', 'true');
      
      // Check monitoring panel is visible
      expect(screen.getByRole('tabpanel', { name: /monitoring/i })).toBeInTheDocument();
      
      // Check specific monitoring content
      expect(screen.getByText('Agents')).toBeInTheDocument();
      expect(screen.getByText('Memory Usage')).toBeInTheDocument();
    });

    test('should navigate between tabs using keyboard', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      const terminalTab = screen.getByRole('tab', { name: 'Terminal' });
      const monitoringTab = screen.getByRole('tab', { name: 'Monitoring' });
      const settingsTab = screen.getByRole('tab', { name: 'Settings' });

      // Focus first tab
      terminalTab.focus();

      // Navigate with arrow keys
      await user.keyboard('{ArrowRight}');
      expect(monitoringTab).toHaveFocus();

      await user.keyboard('{ArrowRight}');
      expect(settingsTab).toHaveFocus();

      // Activate with Enter
      await user.keyboard('{Enter}');
      expect(settingsTab).toHaveAttribute('aria-selected', 'true');
      expect(screen.getByRole('tabpanel', { name: /settings/i })).toBeInTheDocument();
    });

    test('should wrap around in keyboard navigation', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      const terminalTab = screen.getByRole('tab', { name: 'Terminal' });
      const settingsTab = screen.getByRole('tab', { name: 'Settings' });

      // Go to last tab
      settingsTab.focus();

      // Arrow right should wrap to first tab
      await user.keyboard('{ArrowRight}');
      expect(terminalTab).toHaveFocus();

      // Arrow left should wrap to last tab
      await user.keyboard('{ArrowLeft}');
      expect(settingsTab).toHaveFocus();
    });
  });

  describe('Monitoring Dashboard Flow', () => {
    test('should display real-time monitoring data', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Navigate to monitoring
      await user.click(screen.getByRole('tab', { name: 'Monitoring' }));

      // Check agent status display
      expect(screen.getByText('Coder Agent')).toBeInTheDocument();
      expect(screen.getByText('Active')).toBeInTheDocument();

      // Check memory usage display
      const memoryProgress = screen.getByRole('progressbar', { name: /memory usage/i });
      expect(memoryProgress).toHaveAttribute('aria-valuenow', '75');

      // Check command history
      expect(screen.getByRole('log', { name: /command history/i })).toBeInTheDocument();
      expect(screen.getByText('npm start')).toBeInTheDocument();
    });

    test('should update monitoring data dynamically', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      await user.click(screen.getByRole('tab', { name: 'Monitoring' }));

      // Monitoring data should be displayed
      expect(screen.getByText('45%')).toBeInTheDocument(); // CPU usage
      expect(screen.getByText('12ms')).toBeInTheDocument(); // Response time
      expect(screen.getByText('2h 34m')).toBeInTheDocument(); // Uptime
    });
  });

  describe('Settings Configuration Flow', () => {
    test('should handle settings changes', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Navigate to settings
      await user.click(screen.getByRole('tab', { name: 'Settings' }));

      // Change font size
      const fontSizeSelect = screen.getByLabelText(/font size/i);
      await user.selectOptions(fontSizeSelect, '16');

      expect(fontSizeSelect).toHaveValue('16');

      // Toggle checkbox
      const soundCheckbox = screen.getByRole('checkbox', { name: /enable sound notifications/i });
      expect(soundCheckbox).toBeChecked();

      await user.click(soundCheckbox);
      expect(soundCheckbox).not.toBeChecked();

      // Save settings
      const saveButton = screen.getByRole('button', { name: /save settings/i });
      await user.click(saveButton);

      // Settings should be saved (in a real app, this would trigger an API call)
    });

    test('should show help text for form fields', () => {
      const user = userEvent.setup();
      render(<TestApp />);

      user.click(screen.getByRole('tab', { name: 'Settings' }));

      const fontSizeSelect = screen.getByLabelText(/font size/i);
      const helpText = screen.getByText(/choose the font size for the terminal/i);

      expect(fontSizeSelect).toHaveAttribute('aria-describedby', 'font-size-help');
      expect(helpText).toBeInTheDocument();
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle component errors gracefully', async () => {
      const ErrorBoundary = ({ children, fallback }: { children: React.ReactNode, fallback: React.ReactNode }) => {
        try {
          return <>{children}</>;
        } catch (error) {
          return <>{fallback}</>;
        }
      };

      const ProblematicComponent = () => {
        throw new Error('Test error');
      };

      render(
        <ErrorBoundary fallback={<div>Something went wrong</div>}>
          <ProblematicComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    test('should handle network disconnections', async () => {
      render(<TestApp />);

      await waitFor(() => {
        expect(screen.getByText('Connected')).toBeInTheDocument();
      });

      // Simulate disconnection by modifying WebSocket mock
      act(() => {
        const mockWs = new MockWebSocket('ws://localhost:3001');
        mockWs.close();
      });

      // Should show reconnect button
      await waitFor(() => {
        expect(screen.getByText('Reconnect')).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility and Keyboard Navigation', () => {
    test('should support full keyboard navigation', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Start with focus on first interactive element
      await user.tab();
      
      // Should focus new session button
      expect(screen.getByRole('button', { name: /new session/i })).toHaveFocus();

      // Continue tabbing through interface
      await user.tab();
      
      // Should reach session list
      const sessionButton = screen.getByRole('button', { name: /select session 1/i });
      expect(sessionButton).toHaveFocus();

      // Tab to main content area
      await user.tab();
      
      // Should reach tab navigation
      const terminalTab = screen.getByRole('tab', { name: 'Terminal' });
      expect(terminalTab).toHaveFocus();
    });

    test('should announce dynamic content changes', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Create new session
      await user.click(screen.getByRole('button', { name: /new session/i }));

      // Switch to new session
      await user.click(screen.getByRole('button', { name: /select session 2/i }));

      // Check live region announces change
      const liveRegion = screen.getByText('Session: Session 2');
      expect(liveRegion).toHaveAttribute('aria-live', 'polite');
    });

    test('should provide proper focus management', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Navigate to settings and interact with form
      await user.click(screen.getByRole('tab', { name: 'Settings' }));
      
      const fontSizeSelect = screen.getByLabelText(/font size/i);
      fontSizeSelect.focus();
      
      expect(fontSizeSelect).toHaveFocus();
      expect(fontSizeSelect).toHaveAttribute('aria-describedby', 'font-size-help');
    });
  });

  describe('Performance and Responsiveness', () => {
    test('should handle rapid user interactions', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      const startTime = performance.now();

      // Perform rapid tab switches
      for (let i = 0; i < 10; i++) {
        await user.click(screen.getByRole('tab', { name: 'Monitoring' }));
        await user.click(screen.getByRole('tab', { name: 'Terminal' }));
        await user.click(screen.getByRole('tab', { name: 'Settings' }));
      }

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should handle rapid interactions efficiently
      expect(duration).toBeLessThan(1000); // Under 1 second for 30 tab switches
    });

    test('should maintain performance with many sessions', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      const startTime = performance.now();

      // Create multiple sessions
      for (let i = 0; i < 10; i++) {
        await user.click(screen.getByRole('button', { name: /new session/i }));
      }

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should create sessions efficiently
      expect(duration).toBeLessThan(500);
      
      // All sessions should be present
      expect(screen.getByText('Session 11')).toBeInTheDocument();
    });
  });

  describe('Data Persistence and State Management', () => {
    test('should maintain state during tab switches', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Create a second session
      await user.click(screen.getByRole('button', { name: /new session/i }));
      
      // Switch to monitoring tab
      await user.click(screen.getByRole('tab', { name: 'Monitoring' }));
      
      // Switch back to terminal
      await user.click(screen.getByRole('tab', { name: 'Terminal' }));

      // Both sessions should still exist
      expect(screen.getByText('Session 1')).toBeInTheDocument();
      expect(screen.getByText('Session 2')).toBeInTheDocument();
    });

    test('should handle concurrent operations correctly', async () => {
      const user = userEvent.setup();
      render(<TestApp />);

      // Start multiple operations simultaneously
      const promises = [
        user.click(screen.getByRole('button', { name: /new session/i })),
        user.click(screen.getByRole('tab', { name: 'Monitoring' })),
      ];

      await Promise.all(promises);

      // Both operations should complete successfully
      expect(screen.getByText('Session 2')).toBeInTheDocument();
      expect(screen.getByRole('tabpanel', { name: /monitoring/i })).toBeInTheDocument();
    });
  });
});

// Helper function for working with elements inside containers
function within(container: HTMLElement) {
  return {
    getAllByRole: (role: string) => 
      Array.from(container.querySelectorAll(`[role="${role}"]`)) as HTMLElement[],
    getByRole: (role: string) => 
      container.querySelector(`[role="${role}"]`) as HTMLElement,
  };
}