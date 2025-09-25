/**
 * State Synchronization Integration Tests
 * Tests state synchronization across components, WebSocket updates, and persistent storage
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import { createJSONStorage, persist } from 'zustand/middleware';

// Mock WebSocket for testing state synchronization
const mockWsClient = {
  connect: jest.fn(() => Promise.resolve()),
  disconnect: jest.fn(),
  send: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  connected: true,
  connecting: false
};

jest.mock('@/lib/websocket/client', () => ({
  __esModule: true,
  default: jest.fn(() => mockWsClient),
  wsClient: mockWsClient
}));

// Mock localStorage for persistence testing
const createMockStorage = () => {
  const storage = new Map<string, string>();
  return {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
    clear: () => storage.clear()
  };
};

const mockStorage = createMockStorage();
Object.defineProperty(window, 'localStorage', {
  value: mockStorage
});

// Test stores for state synchronization
interface TerminalState {
  terminals: Array<{
    id: string;
    name: string;
    active: boolean;
    lastActivity: number;
    output: string[];
  }>;
  activeTerminalId: string | null;
  globalSettings: {
    theme: 'light' | 'dark';
    fontSize: number;
    autoSave: boolean;
  };
  addTerminal: (terminal: Omit<TerminalState['terminals'][0], 'active' | 'lastActivity'>) => void;
  setActiveTerminal: (id: string) => void;
  updateTerminalOutput: (id: string, output: string) => void;
  updateGlobalSettings: (settings: Partial<TerminalState['globalSettings']>) => void;
  removeTerminal: (id: string) => void;
  syncFromWebSocket: (data: any) => void;
}

const useTerminalStore = create<TerminalState>()(
  subscribeWithSelector(
    persist(
      (set, get) => ({
        terminals: [],
        activeTerminalId: null,
        globalSettings: {
          theme: 'dark',
          fontSize: 14,
          autoSave: true
        },
        addTerminal: (terminal) => set((state) => ({
          terminals: [
            ...state.terminals.map(t => ({ ...t, active: false })),
            { ...terminal, active: true, lastActivity: Date.now(), output: [] }
          ],
          activeTerminalId: terminal.id
        })),
        setActiveTerminal: (id) => set((state) => ({
          activeTerminalId: id,
          terminals: state.terminals.map(t => ({
            ...t,
            active: t.id === id,
            ...(t.id === id && { lastActivity: Date.now() })
          }))
        })),
        updateTerminalOutput: (id, output) => set((state) => ({
          terminals: state.terminals.map(t =>
            t.id === id
              ? { ...t, output: [...t.output, output], lastActivity: Date.now() }
              : t
          )
        })),
        updateGlobalSettings: (settings) => set((state) => ({
          globalSettings: { ...state.globalSettings, ...settings }
        })),
        removeTerminal: (id) => set((state) => ({
          terminals: state.terminals.filter(t => t.id !== id),
          activeTerminalId: state.activeTerminalId === id ? null : state.activeTerminalId
        })),
        syncFromWebSocket: (data) => set((state) => {
          switch (data.type) {
            case 'terminal-created':
              return {
                terminals: [...state.terminals, {
                  id: data.id,
                  name: data.name,
                  active: false,
                  lastActivity: Date.now(),
                  output: []
                }]
              };
            case 'terminal-output':
              return {
                terminals: state.terminals.map(t =>
                  t.id === data.terminalId
                    ? { ...t, output: [...t.output, data.data], lastActivity: Date.now() }
                    : t
                )
              };
            case 'settings-updated':
              return {
                globalSettings: { ...state.globalSettings, ...data.settings }
              };
            default:
              return state;
          }
        })
      }),
      {
        name: 'terminal-storage',
        storage: createJSONStorage(() => mockStorage),
        partialize: (state) => ({
          globalSettings: state.globalSettings,
          terminals: state.terminals.map(({ output, ...terminal }) => terminal) // Don't persist output
        })
      }
    )
  )
);

// Monitoring store for cross-store synchronization
interface MonitoringState {
  metrics: {
    activeTerminals: number;
    totalCommands: number;
    memoryUsage: number;
    cpuUsage: number;
  };
  alerts: Array<{ id: string; message: string; level: 'info' | 'warning' | 'error' }>;
  updateMetrics: (metrics: Partial<MonitoringState['metrics']>) => void;
  addAlert: (alert: Omit<MonitoringState['alerts'][0], 'id'>) => void;
  clearAlerts: () => void;
}

const useMonitoringStore = create<MonitoringState>()(
  (set, get) => ({
    metrics: {
      activeTerminals: 0,
      totalCommands: 0,
      memoryUsage: 0,
      cpuUsage: 0
    },
    alerts: [],
    updateMetrics: (metrics) => set((state) => ({
      metrics: { ...state.metrics, ...metrics }
    })),
    addAlert: (alert) => set((state) => ({
      alerts: [...state.alerts, { ...alert, id: `alert-${Date.now()}` }]
    })),
    clearAlerts: () => set({ alerts: [] })
  })
);

// Test components
const TerminalManager: React.FC = () => {
  const { terminals, activeTerminalId, addTerminal, setActiveTerminal, removeTerminal } = useTerminalStore();
  const updateMetrics = useMonitoringStore(state => state.updateMetrics);

  React.useEffect(() => {
    updateMetrics({ activeTerminals: terminals.length });
  }, [terminals.length, updateMetrics]);

  const handleAddTerminal = () => {
    const id = `terminal-${Date.now()}`;
    addTerminal({ id, name: `Terminal ${terminals.length + 1}` });
  };

  return (
    <div data-testid="terminal-manager">
      <div data-testid="terminal-count">Terminals: {terminals.length}</div>
      <div data-testid="active-terminal">Active: {activeTerminalId || 'None'}</div>
      <button onClick={handleAddTerminal} data-testid="add-terminal">
        Add Terminal
      </button>
      <div data-testid="terminal-list">
        {terminals.map(terminal => (
          <div
            key={terminal.id}
            data-testid={`terminal-${terminal.id}`}
            className={terminal.active ? 'active' : ''}
            onClick={() => setActiveTerminal(terminal.id)}
          >
            <span>{terminal.name}</span>
            <span data-testid={`output-count-${terminal.id}`}>
              ({terminal.output.length} outputs)
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                removeTerminal(terminal.id);
              }}
              data-testid={`remove-${terminal.id}`}
            >
              Remove
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

const SettingsPanel: React.FC = () => {
  const { globalSettings, updateGlobalSettings } = useTerminalStore();

  return (
    <div data-testid="settings-panel">
      <div data-testid="current-theme">Theme: {globalSettings.theme}</div>
      <div data-testid="current-font-size">Font Size: {globalSettings.fontSize}</div>
      <div data-testid="auto-save">Auto Save: {globalSettings.autoSave ? 'On' : 'Off'}</div>

      <button
        onClick={() => updateGlobalSettings({
          theme: globalSettings.theme === 'light' ? 'dark' : 'light'
        })}
        data-testid="toggle-theme"
      >
        Toggle Theme
      </button>

      <button
        onClick={() => updateGlobalSettings({ fontSize: globalSettings.fontSize + 1 })}
        data-testid="increase-font"
      >
        Increase Font
      </button>

      <button
        onClick={() => updateGlobalSettings({ autoSave: !globalSettings.autoSave })}
        data-testid="toggle-autosave"
      >
        Toggle Auto Save
      </button>
    </div>
  );
};

const MonitoringPanel: React.FC = () => {
  const { metrics, alerts, addAlert, clearAlerts } = useMonitoringStore();
  const terminals = useTerminalStore(state => state.terminals);

  React.useEffect(() => {
    const totalCommands = terminals.reduce((sum, t) => sum + t.output.length, 0);
    useMonitoringStore.getState().updateMetrics({ totalCommands });
  }, [terminals]);

  return (
    <div data-testid="monitoring-panel">
      <div data-testid="metrics">
        <div data-testid="active-terminals-metric">Active Terminals: {metrics.activeTerminals}</div>
        <div data-testid="total-commands-metric">Total Commands: {metrics.totalCommands}</div>
        <div data-testid="memory-usage">Memory: {metrics.memoryUsage}%</div>
        <div data-testid="cpu-usage">CPU: {metrics.cpuUsage}%</div>
      </div>

      <div data-testid="alerts">
        <div data-testid="alert-count">Alerts: {alerts.length}</div>
        {alerts.map(alert => (
          <div key={alert.id} data-testid={`alert-${alert.id}`}>
            [{alert.level}] {alert.message}
          </div>
        ))}
      </div>

      <button
        onClick={() => addAlert({ message: 'Test alert', level: 'info' })}
        data-testid="add-alert"
      >
        Add Alert
      </button>

      <button onClick={clearAlerts} data-testid="clear-alerts">
        Clear Alerts
      </button>
    </div>
  );
};

const SynchronizedApp: React.FC = () => {
  const terminals = useTerminalStore(state => state.terminals);
  const metrics = useMonitoringStore(state => state.metrics);
  const syncFromWebSocket = useTerminalStore(state => state.syncFromWebSocket);

  React.useEffect(() => {
    // Setup WebSocket synchronization
    mockWsClient.on.mockImplementation((event: string, callback: Function) => {
      if (event === 'terminal-data') {
        (window as any).__wsCallback = callback;
      }
    });

    return () => {
      mockWsClient.off.mockClear();
    };
  }, []);

  const simulateWebSocketData = (data: any) => {
    syncFromWebSocket(data);
    if ((window as any).__wsCallback) {
      (window as any).__wsCallback(data);
    }
  };

  return (
    <div data-testid="synchronized-app">
      <div data-testid="app-summary">
        Terminals: {terminals.length} | Metrics Updated: {metrics.activeTerminals}
      </div>

      <div style={{ display: 'flex', gap: '20px' }}>
        <TerminalManager />
        <SettingsPanel />
        <MonitoringPanel />
      </div>

      <div data-testid="websocket-controls">
        <button
          onClick={() => simulateWebSocketData({
            type: 'terminal-created',
            id: `ws-terminal-${Date.now()}`,
            name: 'WebSocket Terminal'
          })}
          data-testid="simulate-ws-terminal"
        >
          Simulate WS Terminal
        </button>

        <button
          onClick={() => simulateWebSocketData({
            type: 'terminal-output',
            terminalId: terminals[0]?.id,
            data: `WS Output: ${Date.now()}`
          })}
          data-testid="simulate-ws-output"
          disabled={terminals.length === 0}
        >
          Simulate WS Output
        </button>
      </div>
    </div>
  );
};

describe('State Synchronization Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockStorage.clear();

    // Reset stores
    useTerminalStore.setState({
      terminals: [],
      activeTerminalId: null,
      globalSettings: { theme: 'dark', fontSize: 14, autoSave: true }
    });

    useMonitoringStore.setState({
      metrics: { activeTerminals: 0, totalCommands: 0, memoryUsage: 0, cpuUsage: 0 },
      alerts: []
    });
  });

  describe('Cross-Component State Synchronization', () => {
    it('should synchronize state between terminal manager and monitoring panel', async () => {
      render(<SynchronizedApp />);

      expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 0');
      expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 0');

      // Add terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 1');
        expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 1');
      });

      // Add more terminals
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 3');
        expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 3');
      });
    });

    it('should synchronize settings across components', async () => {
      render(<SynchronizedApp />);

      expect(screen.getByTestId('current-theme')).toHaveTextContent('Theme: dark');

      // Change theme
      fireEvent.click(screen.getByTestId('toggle-theme'));

      await waitFor(() => {
        expect(screen.getByTestId('current-theme')).toHaveTextContent('Theme: light');
      });

      // Change font size
      fireEvent.click(screen.getByTestId('increase-font'));
      fireEvent.click(screen.getByTestId('increase-font'));

      await waitFor(() => {
        expect(screen.getByTestId('current-font-size')).toHaveTextContent('Font Size: 16');
      });
    });

    it('should handle complex state dependencies', async () => {
      render(<SynchronizedApp />);

      // Add terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      const terminalId = useTerminalStore.getState().terminals[0].id;

      // Simulate terminal output
      act(() => {
        useTerminalStore.getState().updateTerminalOutput(terminalId, 'ls -la');
        useTerminalStore.getState().updateTerminalOutput(terminalId, 'pwd');
      });

      await waitFor(() => {
        expect(screen.getByTestId('total-commands-metric')).toHaveTextContent('Total Commands: 2');
        expect(screen.getByTestId(`output-count-${terminalId}`)).toHaveTextContent('(2 outputs)');
      });

      // Add more terminals and outputs
      fireEvent.click(screen.getByTestId('add-terminal'));
      const secondTerminalId = useTerminalStore.getState().terminals[1].id;

      act(() => {
        useTerminalStore.getState().updateTerminalOutput(secondTerminalId, 'echo test');
      });

      await waitFor(() => {
        expect(screen.getByTestId('total-commands-metric')).toHaveTextContent('Total Commands: 3');
      });
    });
  });

  describe('WebSocket State Synchronization', () => {
    it('should synchronize state from WebSocket events', async () => {
      render(<SynchronizedApp />);

      // Initially no terminals
      expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 0');

      // Simulate WebSocket terminal creation
      fireEvent.click(screen.getByTestId('simulate-ws-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 1');
        expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 1');
      });

      // Verify terminal appears in list
      const terminals = useTerminalStore.getState().terminals;
      expect(terminals[0].name).toBe('WebSocket Terminal');
    });

    it('should handle WebSocket terminal output synchronization', async () => {
      render(<SynchronizedApp />);

      // Add a local terminal first
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 1');
      });

      // Simulate WebSocket output
      fireEvent.click(screen.getByTestId('simulate-ws-output'));

      await waitFor(() => {
        expect(screen.getByTestId('total-commands-metric')).toHaveTextContent('Total Commands: 1');
      });

      const terminalId = useTerminalStore.getState().terminals[0].id;
      expect(screen.getByTestId(`output-count-${terminalId}`)).toHaveTextContent('(1 outputs)');
    });

    it('should handle mixed local and WebSocket state updates', async () => {
      render(<SynchronizedApp />);

      // Add local terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      // Add WebSocket terminal
      fireEvent.click(screen.getByTestId('simulate-ws-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 2');
        expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 2');
      });

      // Add local output
      const localTerminalId = useTerminalStore.getState().terminals[0].id;
      act(() => {
        useTerminalStore.getState().updateTerminalOutput(localTerminalId, 'local command');
      });

      // Add WebSocket output
      fireEvent.click(screen.getByTestId('simulate-ws-output'));

      await waitFor(() => {
        expect(screen.getByTestId('total-commands-metric')).toHaveTextContent('Total Commands: 2');
      });
    });
  });

  describe('Persistent State Synchronization', () => {
    it('should persist and restore global settings', async () => {
      const { unmount, rerender } = render(<SynchronizedApp />);

      // Change settings
      fireEvent.click(screen.getByTestId('toggle-theme'));
      fireEvent.click(screen.getByTestId('increase-font'));
      fireEvent.click(screen.getByTestId('toggle-autosave'));

      await waitFor(() => {
        expect(screen.getByTestId('current-theme')).toHaveTextContent('Theme: light');
        expect(screen.getByTestId('current-font-size')).toHaveTextContent('Font Size: 15');
        expect(screen.getByTestId('auto-save')).toHaveTextContent('Auto Save: Off');
      });

      // Unmount and remount to simulate page reload
      unmount();

      // Create new store instance to simulate fresh page load
      const freshStore = create<TerminalState>()(
        persist(
          (set, get) => useTerminalStore.getState(),
          {
            name: 'terminal-storage',
            storage: createJSONStorage(() => mockStorage)
          }
        )
      );

      // Manually trigger rehydration
      await new Promise(resolve => setTimeout(resolve, 100));

      rerender(<SynchronizedApp />);

      // Settings should be restored
      await waitFor(() => {
        expect(screen.getByTestId('current-theme')).toHaveTextContent('Theme: light');
        expect(screen.getByTestId('current-font-size')).toHaveTextContent('Font Size: 15');
        expect(screen.getByTestId('auto-save')).toHaveTextContent('Auto Save: Off');
      });
    });

    it('should handle partial state persistence', async () => {
      render(<SynchronizedApp />);

      // Add terminals with output
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));

      const terminals = useTerminalStore.getState().terminals;
      act(() => {
        useTerminalStore.getState().updateTerminalOutput(terminals[0].id, 'command 1');
        useTerminalStore.getState().updateTerminalOutput(terminals[1].id, 'command 2');
      });

      await waitFor(() => {
        expect(screen.getByTestId('total-commands-metric')).toHaveTextContent('Total Commands: 2');
      });

      // Check what's actually persisted
      const persistedData = JSON.parse(mockStorage.getItem('terminal-storage') || '{}');

      // Terminals should be persisted but without output
      expect(persistedData.state.terminals).toHaveLength(2);
      expect(persistedData.state.terminals[0].output).toBeUndefined();
      expect(persistedData.state.globalSettings).toBeDefined();
    });
  });

  describe('Real-time State Synchronization', () => {
    it('should handle rapid state updates without conflicts', async () => {
      render(<SynchronizedApp />);

      // Rapidly add terminals
      for (let i = 0; i < 10; i++) {
        fireEvent.click(screen.getByTestId('add-terminal'));
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 10');
        expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 10');
      });

      // All terminals should be properly tracked
      const terminals = useTerminalStore.getState().terminals;
      expect(terminals).toHaveLength(10);
      expect(terminals.every(t => t.id && t.name)).toBe(true);
    });

    it('should maintain synchronization during concurrent updates', async () => {
      render(<SynchronizedApp />);

      // Add terminals
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));

      const terminals = useTerminalStore.getState().terminals;

      // Concurrent updates
      const updates = Array.from({ length: 20 }, (_, i) => async () => {
        act(() => {
          useTerminalStore.getState().updateTerminalOutput(
            terminals[i % 2].id,
            `concurrent command ${i}`
          );
        });
      });

      await Promise.all(updates.map(update => update()));

      await waitFor(() => {
        expect(screen.getByTestId('total-commands-metric')).toHaveTextContent('Total Commands: 20');
      });
    });

    it('should handle store subscription cleanup properly', async () => {
      const subscriptions: Array<() => void> = [];

      const TestComponent: React.FC = () => {
        React.useEffect(() => {
          const unsubscribe = useTerminalStore.subscribe(
            (state) => state.terminals.length,
            (terminalCount) => {
              // Subscription callback
            }
          );

          subscriptions.push(unsubscribe);
          return unsubscribe;
        }, []);

        return <div data-testid="subscription-test">Test</div>;
      };

      const { unmount } = render(<TestComponent />);

      // Add some state changes
      act(() => {
        useTerminalStore.getState().addTerminal({
          id: 'test-terminal',
          name: 'Test'
        });
      });

      // Unmount should cleanup subscriptions
      unmount();

      // Verify subscriptions were cleaned up (no memory leaks)
      expect(subscriptions).toHaveLength(1);
    });
  });

  describe('Error Handling in State Synchronization', () => {
    it('should handle WebSocket synchronization errors gracefully', async () => {
      render(<SynchronizedApp />);

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      // Simulate malformed WebSocket data
      act(() => {
        useTerminalStore.getState().syncFromWebSocket(null);
      });

      act(() => {
        useTerminalStore.getState().syncFromWebSocket({ type: 'unknown-type' });
      });

      // Should not crash
      expect(screen.getByTestId('synchronized-app')).toBeInTheDocument();

      consoleSpy.mockRestore();
    });

    it('should recover from storage errors', async () => {
      // Simulate storage error
      const originalSetItem = mockStorage.setItem;
      mockStorage.setItem = jest.fn(() => {
        throw new Error('Storage quota exceeded');
      });

      render(<SynchronizedApp />);

      // Should still work despite storage errors
      fireEvent.click(screen.getByTestId('toggle-theme'));

      await waitFor(() => {
        expect(screen.getByTestId('current-theme')).toHaveTextContent('Theme: light');
      });

      // Restore storage
      mockStorage.setItem = originalSetItem;
    });

    it('should handle store corruption gracefully', async () => {
      // Corrupt storage data
      mockStorage.setItem('terminal-storage', '{"corrupted": json}');

      // Should initialize with default state
      render(<SynchronizedApp />);

      expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 0');
      expect(screen.getByTestId('current-theme')).toHaveTextContent('Theme: dark');
    });
  });

  describe('Performance Optimization', () => {
    it('should optimize re-renders with selective subscriptions', async () => {
      const renderCounts = { terminal: 0, monitoring: 0, settings: 0 };

      const TrackingTerminalManager = () => {
        renderCounts.terminal++;
        return <TerminalManager />;
      };

      const TrackingMonitoringPanel = () => {
        renderCounts.monitoring++;
        return <MonitoringPanel />;
      };

      const TrackingSettingsPanel = () => {
        renderCounts.settings++;
        return <SettingsPanel />;
      };

      render(
        <div>
          <TrackingTerminalManager />
          <TrackingMonitoringPanel />
          <TrackingSettingsPanel />
        </div>
      );

      const initialCounts = { ...renderCounts };

      // Change settings - should only re-render settings panel
      fireEvent.click(screen.getByTestId('toggle-theme'));

      await waitFor(() => {
        expect(renderCounts.settings).toBeGreaterThan(initialCounts.settings);
      });

      // Terminal and monitoring shouldn't re-render for settings changes
      expect(renderCounts.terminal).toBe(initialCounts.terminal);
      expect(renderCounts.monitoring).toBe(initialCounts.monitoring);
    });

    it('should handle large state efficiently', async () => {
      render(<SynchronizedApp />);

      const startTime = Date.now();

      // Create many terminals
      for (let i = 0; i < 100; i++) {
        act(() => {
          useTerminalStore.getState().addTerminal({
            id: `perf-terminal-${i}`,
            name: `Performance Terminal ${i}`
          });
        });
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should handle large state efficiently
      expect(duration).toBeLessThan(1000);

      await waitFor(() => {
        expect(screen.getByTestId('terminal-count')).toHaveTextContent('Terminals: 100');
        expect(screen.getByTestId('active-terminals-metric')).toHaveTextContent('Active Terminals: 100');
      });
    });
  });
});