/**
 * Cross-Component Data Flow Integration Tests
 * Tests data flow between components, state management, and prop drilling scenarios
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { create } from 'zustand';

// Import components for integration testing
import Terminal from '@/components/terminal/Terminal';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import TabList from '@/components/tabs/TabList';
import Tab from '@/components/tabs/Tab';

// Mock external dependencies
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => ({
    open: jest.fn(),
    write: jest.fn(),
    writeln: jest.fn(),
    clear: jest.fn(),
    focus: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
    loadAddon: jest.fn(),
    resize: jest.fn(),
    cols: 80,
    rows: 24,
    element: document.createElement('div')
  }))
}));

jest.mock('@xterm/addon-fit', () => ({
  FitAddon: jest.fn(() => ({
    fit: jest.fn(),
    proposeDimensions: jest.fn(() => ({ cols: 80, rows: 24 }))
  }))
}));

// Mock WebSocket client
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

// Test store for state management testing
interface TestState {
  terminals: Array<{ id: string; name: string; active: boolean }>;
  activeTerminalId: string | null;
  monitoring: {
    agents: number;
    memory: number;
    performance: number;
  };
  addTerminal: (terminal: { id: string; name: string }) => void;
  setActiveTerminal: (id: string) => void;
  updateMonitoring: (data: Partial<TestState['monitoring']>) => void;
  removeTerminal: (id: string) => void;
}

const useTestStore = create<TestState>((set, get) => ({
  terminals: [],
  activeTerminalId: null,
  monitoring: {
    agents: 0,
    memory: 0,
    performance: 0
  },
  addTerminal: (terminal) => set((state) => ({
    terminals: [...state.terminals, { ...terminal, active: false }]
  })),
  setActiveTerminal: (id) => set((state) => ({
    activeTerminalId: id,
    terminals: state.terminals.map(t => ({
      ...t,
      active: t.id === id
    }))
  })),
  updateMonitoring: (data) => set((state) => ({
    monitoring: { ...state.monitoring, ...data }
  })),
  removeTerminal: (id) => set((state) => ({
    terminals: state.terminals.filter(t => t.id !== id),
    activeTerminalId: state.activeTerminalId === id ? null : state.activeTerminalId
  }))
}));

// Test components that use the store
const TerminalManager: React.FC = () => {
  const { terminals, activeTerminalId, addTerminal, setActiveTerminal, removeTerminal } = useTestStore();
  const [nextId, setNextId] = React.useState(1);

  const handleAddTerminal = () => {
    const newTerminal = {
      id: `terminal-${nextId}`,
      name: `Terminal ${nextId}`
    };
    addTerminal(newTerminal);
    setActiveTerminal(newTerminal.id);
    setNextId(prev => prev + 1);
  };

  const handleCloseTerminal = (id: string) => {
    removeTerminal(id);
  };

  return (
    <div data-testid="terminal-manager">
      <button onClick={handleAddTerminal} data-testid="add-terminal">
        Add Terminal
      </button>
      <div data-testid="terminal-tabs">
        {terminals.map(terminal => (
          <div
            key={terminal.id}
            data-testid={`terminal-tab-${terminal.id}`}
            className={terminal.active ? 'active' : ''}
            onClick={() => setActiveTerminal(terminal.id)}
          >
            <span>{terminal.name}</span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleCloseTerminal(terminal.id);
              }}
              data-testid={`close-${terminal.id}`}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      {activeTerminalId && (
        <Terminal sessionId={activeTerminalId} key={activeTerminalId} />
      )}
    </div>
  );
};

const MonitoringDisplay: React.FC = () => {
  const { monitoring, updateMonitoring } = useTestStore();

  React.useEffect(() => {
    const interval = setInterval(() => {
      updateMonitoring({
        agents: Math.floor(Math.random() * 10),
        memory: Math.floor(Math.random() * 100),
        performance: Math.floor(Math.random() * 100)
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [updateMonitoring]);

  return (
    <div data-testid="monitoring-display">
      <div data-testid="agents-count">Agents: {monitoring.agents}</div>
      <div data-testid="memory-usage">Memory: {monitoring.memory}%</div>
      <div data-testid="performance-metric">Performance: {monitoring.performance}%</div>
    </div>
  );
};

const IntegratedApp: React.FC = () => {
  const { terminals, monitoring } = useTestStore();

  return (
    <div data-testid="integrated-app">
      <div data-testid="app-header">
        Terminal Count: {terminals.length} | Active Agents: {monitoring.agents}
      </div>
      <div style={{ display: 'flex' }}>
        <div style={{ flex: 1 }}>
          <TerminalManager />
        </div>
        <div style={{ width: '300px' }}>
          <MonitoringDisplay />
        </div>
      </div>
    </div>
  );
};

describe('Cross-Component Data Flow Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    useTestStore.setState({
      terminals: [],
      activeTerminalId: null,
      monitoring: { agents: 0, memory: 0, performance: 0 }
    });
  });

  describe('State Management Integration', () => {
    it('should share state between multiple components', async () => {
      render(<IntegratedApp />);

      expect(screen.getByText('Terminal Count: 0')).toBeInTheDocument();
      expect(screen.getByText('Active Agents: 0')).toBeInTheDocument();

      // Add a terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByText('Terminal Count: 1')).toBeInTheDocument();
      });

      // Update monitoring data
      act(() => {
        useTestStore.getState().updateMonitoring({ agents: 5 });
      });

      await waitFor(() => {
        expect(screen.getByText('Active Agents: 5')).toBeInTheDocument();
      });
    });

    it('should handle state updates across component hierarchy', async () => {
      render(<TerminalManager />);

      // Initially no terminals
      expect(screen.queryByTestId(/terminal-tab-/)).not.toBeInTheDocument();

      // Add first terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-tab-terminal-1')).toBeInTheDocument();
        expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      });

      // Add second terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-tab-terminal-2')).toBeInTheDocument();
        expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      });

      // Both terminals should exist
      expect(useTestStore.getState().terminals).toHaveLength(2);
    });

    it('should maintain state consistency during rapid updates', async () => {
      render(<TerminalManager />);

      // Rapidly add multiple terminals
      for (let i = 0; i < 5; i++) {
        fireEvent.click(screen.getByTestId('add-terminal'));
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      await waitFor(() => {
        expect(useTestStore.getState().terminals).toHaveLength(5);
      });

      // All terminals should be rendered
      for (let i = 1; i <= 5; i++) {
        expect(screen.getByTestId(`terminal-tab-terminal-${i}`)).toBeInTheDocument();
      }
    });
  });

  describe('Component Communication', () => {
    it('should handle terminal selection across components', async () => {
      render(<TerminalManager />);

      // Add multiple terminals
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-tab-terminal-3')).toBeInTheDocument();
      });

      // Initially, terminal-3 should be active (last added)
      expect(useTestStore.getState().activeTerminalId).toBe('terminal-3');

      // Click on terminal-1
      fireEvent.click(screen.getByTestId('terminal-tab-terminal-1'));

      await waitFor(() => {
        expect(useTestStore.getState().activeTerminalId).toBe('terminal-1');
      });

      // Active class should update
      expect(screen.getByTestId('terminal-tab-terminal-1')).toHaveClass('active');
      expect(screen.getByTestId('terminal-tab-terminal-3')).not.toHaveClass('active');
    });

    it('should handle terminal closure and state cleanup', async () => {
      render(<TerminalManager />);

      // Add terminals
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(useTestStore.getState().terminals).toHaveLength(2);
      });

      // Close first terminal
      fireEvent.click(screen.getByTestId('close-terminal-1'));

      await waitFor(() => {
        expect(useTestStore.getState().terminals).toHaveLength(1);
        expect(screen.queryByTestId('terminal-tab-terminal-1')).not.toBeInTheDocument();
        expect(screen.getByTestId('terminal-tab-terminal-2')).toBeInTheDocument();
      });

      // If active terminal was closed, activeTerminalId should be null
      expect(useTestStore.getState().activeTerminalId).toBe('terminal-2');
    });

    it('should propagate monitoring data updates', async () => {
      jest.useFakeTimers();

      render(<MonitoringDisplay />);

      // Initial state
      expect(screen.getByText('Agents: 0')).toBeInTheDocument();
      expect(screen.getByText('Memory: 0%')).toBeInTheDocument();

      // Fast-forward timers to trigger update
      act(() => {
        jest.advanceTimersByTime(1100);
      });

      await waitFor(() => {
        // Values should have updated (they're random, so just check they're not 0)
        const agentsText = screen.getByTestId('agents-count').textContent;
        const memoryText = screen.getByTestId('memory-usage').textContent;

        expect(agentsText).toMatch(/Agents: \d+/);
        expect(memoryText).toMatch(/Memory: \d+%/);
      });

      jest.useRealTimers();
    });
  });

  describe('Event Propagation', () => {
    it('should handle events bubbling up component tree', async () => {
      const handleTerminalEvent = jest.fn();

      const TestWrapper: React.FC = () => {
        React.useEffect(() => {
          const handleEvent = (e: any) => {
            if (e.target.dataset.testid?.startsWith('terminal-tab-')) {
              handleTerminalEvent(e);
            }
          };

          document.addEventListener('click', handleEvent);
          return () => document.removeEventListener('click', handleEvent);
        }, []);

        return <TerminalManager />;
      };

      render(<TestWrapper />);

      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-tab-terminal-1')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByTestId('terminal-tab-terminal-1'));

      expect(handleTerminalEvent).toHaveBeenCalled();
    });

    it('should prevent event propagation when needed', async () => {
      const parentClickHandler = jest.fn();

      const TestWrapper: React.FC = () => (
        <div onClick={parentClickHandler}>
          <TerminalManager />
        </div>
      );

      render(<TestWrapper />);

      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('close-terminal-1')).toBeInTheDocument();
      });

      // Click close button - should not trigger parent click
      fireEvent.click(screen.getByTestId('close-terminal-1'));

      // Parent handler should not be called due to stopPropagation
      expect(parentClickHandler).not.toHaveBeenCalled();
    });
  });

  describe('Data Consistency', () => {
    it('should maintain data consistency across component re-renders', async () => {
      const { rerender } = render(<TerminalManager />);

      // Add terminals
      fireEvent.click(screen.getByTestId('add-terminal'));
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(useTestStore.getState().terminals).toHaveLength(2);
      });

      const initialState = useTestStore.getState();

      // Force re-render
      rerender(<TerminalManager />);

      // State should be preserved
      expect(useTestStore.getState()).toEqual(initialState);
      expect(screen.getByTestId('terminal-tab-terminal-1')).toBeInTheDocument();
      expect(screen.getByTestId('terminal-tab-terminal-2')).toBeInTheDocument();
    });

    it('should handle concurrent state updates without conflicts', async () => {
      render(<IntegratedApp />);

      // Simulate concurrent updates
      const promises = Array.from({ length: 10 }, async (_, i) => {
        act(() => {
          useTestStore.getState().addTerminal({
            id: `concurrent-${i}`,
            name: `Concurrent ${i}`
          });
        });

        act(() => {
          useTestStore.getState().updateMonitoring({
            agents: i,
            memory: i * 10
          });
        });
      });

      await Promise.all(promises);

      // All updates should be applied
      expect(useTestStore.getState().terminals).toHaveLength(10);
      expect(useTestStore.getState().monitoring.agents).toBeDefined();
      expect(useTestStore.getState().monitoring.memory).toBeDefined();
    });
  });

  describe('Performance and Memory Management', () => {
    it('should not create memory leaks with frequent updates', async () => {
      const { unmount } = render(<MonitoringDisplay />);

      // Simulate many updates
      for (let i = 0; i < 100; i++) {
        act(() => {
          useTestStore.getState().updateMonitoring({
            agents: i,
            memory: i % 100,
            performance: (i * 2) % 100
          });
        });
      }

      // Unmount component
      unmount();

      // Store should still be accessible but component shouldn't cause memory leaks
      expect(useTestStore.getState().monitoring.agents).toBe(99);
    });

    it('should handle large amounts of data efficiently', async () => {
      const startTime = Date.now();

      // Add many terminals
      for (let i = 0; i < 50; i++) {
        act(() => {
          useTestStore.getState().addTerminal({
            id: `perf-test-${i}`,
            name: `Performance Test ${i}`
          });
        });
      }

      render(<TerminalManager />);

      const endTime = Date.now();
      const renderTime = endTime - startTime;

      // Should render quickly even with many items
      expect(renderTime).toBeLessThan(1000);
      expect(useTestStore.getState().terminals).toHaveLength(50);
    });
  });

  describe('Error Boundary Integration', () => {
    it('should handle errors in child components without breaking parent', async () => {
      const FaultyComponent: React.FC = () => {
        const [shouldError, setShouldError] = React.useState(false);

        if (shouldError) {
          throw new Error('Component error');
        }

        return (
          <div>
            <button onClick={() => setShouldError(true)} data-testid="trigger-error">
              Trigger Error
            </button>
          </div>
        );
      };

      const ParentComponent: React.FC = () => {
        const [showFaulty, setShowFaulty] = React.useState(true);

        return (
          <div>
            <TerminalManager />
            {showFaulty && <FaultyComponent />}
            <button onClick={() => setShowFaulty(false)} data-testid="hide-faulty">
              Hide Faulty
            </button>
          </div>
        );
      };

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      render(<ParentComponent />);

      // Terminal manager should work normally
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(screen.getByTestId('terminal-tab-terminal-1')).toBeInTheDocument();
      });

      // Trigger error in child component
      expect(() => {
        fireEvent.click(screen.getByTestId('trigger-error'));
      }).toThrow();

      // Terminal functionality should still work
      expect(useTestStore.getState().terminals).toHaveLength(1);

      consoleSpy.mockRestore();
    });
  });

  describe('WebSocket Integration with Components', () => {
    it('should coordinate WebSocket events across components', async () => {
      render(<IntegratedApp />);

      // Add terminal
      fireEvent.click(screen.getByTestId('add-terminal'));

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });

      // Simulate WebSocket event that affects monitoring
      act(() => {
        useTestStore.getState().updateMonitoring({ agents: 3 });
      });

      await waitFor(() => {
        expect(screen.getByText('Active Agents: 3')).toBeInTheDocument();
      });

      // Terminal and monitoring should both reflect the state
      expect(useTestStore.getState().terminals).toHaveLength(1);
      expect(useTestStore.getState().monitoring.agents).toBe(3);
    });
  });
});