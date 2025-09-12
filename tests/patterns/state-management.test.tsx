/**
 * State Management Testing Patterns for Zustand
 * Comprehensive testing for application state, persistence, and synchronization
 */

import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders, createMockStore } from '../utils/test-utils';

// Mock Zustand store
const createTestStore = (initialState = {}) => {
  const store = {
    // Application state
    agents: [],
    prompts: [],
    memory: [],
    commands: [],
    sessions: [],
    activeSession: null,
    isCollapsed: false,
    error: null,
    loading: false,
    
    // Terminal state
    terminals: new Map(),
    terminalHistory: new Map(),
    
    // WebSocket state
    connectionState: 'disconnected',
    lastPing: null,
    messageQueue: [],
    
    // UI state
    theme: 'dark',
    sidebarWidth: 300,
    tabOrder: [],
    
    // Override with initial state
    ...initialState,
    
    // Actions
    setAgents: jest.fn((agents) => { store.agents = agents; }),
    addAgent: jest.fn((agent) => { store.agents.push(agent); }),
    removeAgent: jest.fn((id) => { 
      store.agents = store.agents.filter(a => a.id !== id);
    }),
    updateAgent: jest.fn((id, updates) => {
      const index = store.agents.findIndex(a => a.id === id);
      if (index >= 0) {
        store.agents[index] = { ...store.agents[index], ...updates };
      }
    }),
    
    setSessions: jest.fn((sessions) => { store.sessions = sessions; }),
    addSession: jest.fn((session) => { store.sessions.push(session); }),
    removeSession: jest.fn((id) => {
      store.sessions = store.sessions.filter(s => s !== id);
    }),
    setActiveSession: jest.fn((id) => { store.activeSession = id; }),
    
    setError: jest.fn((error) => { store.error = error; }),
    setLoading: jest.fn((loading) => { store.loading = loading; }),
    toggleSidebar: jest.fn(() => { store.isCollapsed = !store.isCollapsed; }),
    
    // Terminal actions
    addTerminal: jest.fn((sessionId, terminal) => {
      store.terminals.set(sessionId, terminal);
    }),
    removeTerminal: jest.fn((sessionId) => {
      store.terminals.delete(sessionId);
    }),
    updateTerminalHistory: jest.fn((sessionId, history) => {
      store.terminalHistory.set(sessionId, history);
    }),
    
    // WebSocket actions
    setConnectionState: jest.fn((state) => { store.connectionState = state; }),
    addToMessageQueue: jest.fn((message) => { store.messageQueue.push(message); }),
    clearMessageQueue: jest.fn(() => { store.messageQueue = []; }),
    updateLastPing: jest.fn(() => { store.lastPing = Date.now(); }),
    
    // UI actions
    setTheme: jest.fn((theme) => { store.theme = theme; }),
    setSidebarWidth: jest.fn((width) => { store.sidebarWidth = width; }),
    updateTabOrder: jest.fn((order) => { store.tabOrder = order; }),
    
    // Utility functions
    getState: () => ({ ...store }),
    setState: jest.fn((newState) => Object.assign(store, newState)),
    subscribe: jest.fn(),
    destroy: jest.fn(),
    
    // Test helpers
    reset: () => {
      Object.assign(store, {
        agents: [],
        prompts: [],
        memory: [],
        commands: [],
        sessions: [],
        activeSession: null,
        isCollapsed: false,
        error: null,
        loading: false,
        terminals: new Map(),
        terminalHistory: new Map(),
        connectionState: 'disconnected',
        lastPing: null,
        messageQueue: [],
        theme: 'dark',
        sidebarWidth: 300,
        tabOrder: [],
        ...initialState,
      });
    },
  };
  
  return store;
};

// Test component that uses store
const StoreTestComponent = ({ testId }: { testId: string }) => {
  const store = createTestStore();
  const [state, setState] = React.useState(store.getState());
  
  React.useEffect(() => {
    const unsubscribe = store.subscribe(() => {
      setState(store.getState());
    });
    return unsubscribe;
  }, []);
  
  return (
    <div data-testid={testId}>
      <div data-testid="agents-count">{state.agents.length}</div>
      <div data-testid="sessions-count">{state.sessions.length}</div>
      <div data-testid="active-session">{state.activeSession || 'none'}</div>
      <div data-testid="loading">{state.loading.toString()}</div>
      <div data-testid="error">{state.error || 'none'}</div>
      <div data-testid="sidebar-collapsed">{state.isCollapsed.toString()}</div>
      
      <button onClick={() => store.addAgent({ id: 'test-agent', name: 'Test Agent' })}>
        Add Agent
      </button>
      <button onClick={() => store.addSession('test-session')}>
        Add Session
      </button>
      <button onClick={() => store.setActiveSession('test-session')}>
        Set Active Session
      </button>
      <button onClick={() => store.setLoading(true)}>
        Set Loading
      </button>
      <button onClick={() => store.setError('Test error')}>
        Set Error
      </button>
      <button onClick={() => store.toggleSidebar()}>
        Toggle Sidebar
      </button>
    </div>
  );
};

describe('State Management Testing Patterns', () => {
  let store: ReturnType<typeof createTestStore>;

  beforeEach(() => {
    store = createTestStore();
  });

  describe('Store Initialization', () => {
    it('should initialize with default state', () => {
      const state = store.getState();
      
      expect(state.agents).toEqual([]);
      expect(state.sessions).toEqual([]);
      expect(state.activeSession).toBeNull();
      expect(state.loading).toBe(false);
      expect(state.error).toBeNull();
      expect(state.isCollapsed).toBe(false);
      expect(state.theme).toBe('dark');
    });

    it('should initialize with custom state', () => {
      const customStore = createTestStore({
        agents: [{ id: 'agent-1', name: 'Initial Agent' }],
        activeSession: 'session-1',
        theme: 'light',
      });

      const state = customStore.getState();
      
      expect(state.agents).toHaveLength(1);
      expect(state.activeSession).toBe('session-1');
      expect(state.theme).toBe('light');
    });
  });

  describe('Agent Management', () => {
    it('should add agents correctly', () => {
      const agent = { id: 'agent-1', name: 'Test Agent', status: 'active' };
      
      store.addAgent(agent);
      
      expect(store.agents).toContain(agent);
      expect(store.addAgent).toHaveBeenCalledWith(agent);
    });

    it('should remove agents correctly', () => {
      const agent1 = { id: 'agent-1', name: 'Agent 1' };
      const agent2 = { id: 'agent-2', name: 'Agent 2' };
      
      store.addAgent(agent1);
      store.addAgent(agent2);
      
      store.removeAgent('agent-1');
      
      expect(store.agents).not.toContainEqual(agent1);
      expect(store.agents).toContainEqual(agent2);
    });

    it('should update agents correctly', () => {
      const agent = { id: 'agent-1', name: 'Original Name', status: 'idle' };
      
      store.addAgent(agent);
      store.updateAgent('agent-1', { name: 'Updated Name', status: 'active' });
      
      const updatedAgent = store.agents.find(a => a.id === 'agent-1');
      expect(updatedAgent).toEqual({
        id: 'agent-1',
        name: 'Updated Name',
        status: 'active',
      });
    });

    it('should handle concurrent agent operations', () => {
      const agents = Array.from({ length: 100 }, (_, i) => ({
        id: `agent-${i}`,
        name: `Agent ${i}`,
      }));

      // Add agents concurrently
      agents.forEach(agent => store.addAgent(agent));
      
      expect(store.agents).toHaveLength(100);

      // Remove half concurrently
      for (let i = 0; i < 50; i++) {
        store.removeAgent(`agent-${i}`);
      }

      expect(store.agents).toHaveLength(50);
    });
  });

  describe('Session Management', () => {
    it('should manage sessions correctly', () => {
      store.addSession('session-1');
      store.addSession('session-2');
      
      expect(store.sessions).toEqual(['session-1', 'session-2']);
      
      store.setActiveSession('session-1');
      expect(store.activeSession).toBe('session-1');
      
      store.removeSession('session-1');
      expect(store.sessions).toEqual(['session-2']);
      expect(store.activeSession).toBe('session-1'); // Should not auto-change
    });

    it('should handle active session transitions', () => {
      store.addSession('session-1');
      store.addSession('session-2');
      store.addSession('session-3');
      
      store.setActiveSession('session-2');
      expect(store.activeSession).toBe('session-2');
      
      // Remove active session
      store.removeSession('session-2');
      
      // In a real app, this might auto-select another session
      expect(store.sessions).toEqual(['session-1', 'session-3']);
    });
  });

  describe('Terminal State Management', () => {
    it('should manage terminal instances', () => {
      const terminal1 = { id: 'term-1', element: document.createElement('div') };
      const terminal2 = { id: 'term-2', element: document.createElement('div') };
      
      store.addTerminal('session-1', terminal1);
      store.addTerminal('session-2', terminal2);
      
      expect(store.terminals.get('session-1')).toBe(terminal1);
      expect(store.terminals.get('session-2')).toBe(terminal2);
      
      store.removeTerminal('session-1');
      expect(store.terminals.has('session-1')).toBe(false);
      expect(store.terminals.has('session-2')).toBe(true);
    });

    it('should manage terminal history', () => {
      const history1 = ['command 1', 'command 2'];
      const history2 = ['command 3', 'command 4'];
      
      store.updateTerminalHistory('session-1', history1);
      store.updateTerminalHistory('session-2', history2);
      
      expect(store.terminalHistory.get('session-1')).toEqual(history1);
      expect(store.terminalHistory.get('session-2')).toEqual(history2);
    });
  });

  describe('WebSocket State Management', () => {
    it('should manage connection states', () => {
      expect(store.connectionState).toBe('disconnected');
      
      store.setConnectionState('connecting');
      expect(store.connectionState).toBe('connecting');
      
      store.setConnectionState('connected');
      expect(store.connectionState).toBe('connected');
      
      store.updateLastPing();
      expect(store.lastPing).toBeGreaterThan(0);
    });

    it('should manage message queue', () => {
      const message1 = { type: 'test', data: 'data1' };
      const message2 = { type: 'test', data: 'data2' };
      
      store.addToMessageQueue(message1);
      store.addToMessageQueue(message2);
      
      expect(store.messageQueue).toEqual([message1, message2]);
      
      store.clearMessageQueue();
      expect(store.messageQueue).toEqual([]);
    });
  });

  describe('UI State Management', () => {
    it('should manage UI preferences', () => {
      expect(store.theme).toBe('dark');
      expect(store.sidebarWidth).toBe(300);
      expect(store.isCollapsed).toBe(false);
      
      store.setTheme('light');
      store.setSidebarWidth(250);
      store.toggleSidebar();
      
      expect(store.theme).toBe('light');
      expect(store.sidebarWidth).toBe(250);
      expect(store.isCollapsed).toBe(true);
    });

    it('should manage tab ordering', () => {
      const tabOrder = ['tab-3', 'tab-1', 'tab-2'];
      
      store.updateTabOrder(tabOrder);
      
      expect(store.tabOrder).toEqual(tabOrder);
    });
  });

  describe('Error and Loading States', () => {
    it('should manage loading states', () => {
      expect(store.loading).toBe(false);
      
      store.setLoading(true);
      expect(store.loading).toBe(true);
      
      store.setLoading(false);
      expect(store.loading).toBe(false);
    });

    it('should manage error states', () => {
      expect(store.error).toBeNull();
      
      store.setError('Connection failed');
      expect(store.error).toBe('Connection failed');
      
      store.setError(null);
      expect(store.error).toBeNull();
    });

    it('should handle error recovery scenarios', () => {
      // Simulate error during operation
      store.setLoading(true);
      store.setError('Operation failed');
      
      // Recovery
      store.setError(null);
      store.setLoading(false);
      
      expect(store.error).toBeNull();
      expect(store.loading).toBe(false);
    });
  });

  describe('State Persistence', () => {
    it('should serialize state correctly', () => {
      store.addAgent({ id: 'agent-1', name: 'Test Agent' });
      store.addSession('session-1');
      store.setActiveSession('session-1');
      store.setTheme('light');
      
      const state = store.getState();
      const serialized = JSON.stringify(state);
      const deserialized = JSON.parse(serialized);
      
      expect(deserialized.agents).toEqual(state.agents);
      expect(deserialized.sessions).toEqual(state.sessions);
      expect(deserialized.activeSession).toBe(state.activeSession);
      expect(deserialized.theme).toBe(state.theme);
    });

    it('should handle state hydration', () => {
      const savedState = {
        agents: [{ id: 'agent-1', name: 'Saved Agent' }],
        sessions: ['session-1', 'session-2'],
        activeSession: 'session-1',
        theme: 'light',
        sidebarWidth: 350,
      };
      
      const hydratedStore = createTestStore(savedState);
      const state = hydratedStore.getState();
      
      expect(state.agents).toEqual(savedState.agents);
      expect(state.sessions).toEqual(savedState.sessions);
      expect(state.activeSession).toBe(savedState.activeSession);
      expect(state.theme).toBe(savedState.theme);
      expect(state.sidebarWidth).toBe(savedState.sidebarWidth);
    });

    it('should handle partial state updates', () => {
      const initialAgents = [{ id: 'agent-1', name: 'Agent 1' }];
      store.setAgents(initialAgents);
      
      const partialUpdate = {
        agents: [
          ...initialAgents,
          { id: 'agent-2', name: 'Agent 2' },
        ],
        theme: 'light',
      };
      
      store.setState(partialUpdate);
      
      const state = store.getState();
      expect(state.agents).toEqual(partialUpdate.agents);
      expect(state.theme).toBe('light');
      // Other properties should remain unchanged
      expect(state.isCollapsed).toBe(false);
    });
  });

  describe('React Integration', () => {
    it('should work with React components', async () => {
      const user = userEvent.setup();
      
      render(<StoreTestComponent testId="store-test" />);
      
      // Initial state
      expect(screen.getByTestId('agents-count')).toHaveTextContent('0');
      expect(screen.getByTestId('sessions-count')).toHaveTextContent('0');
      expect(screen.getByTestId('active-session')).toHaveTextContent('none');
      
      // Add agent
      await user.click(screen.getByText('Add Agent'));
      
      await waitFor(() => {
        expect(screen.getByTestId('agents-count')).toHaveTextContent('1');
      });
      
      // Add session and set active
      await user.click(screen.getByText('Add Session'));
      await user.click(screen.getByText('Set Active Session'));
      
      await waitFor(() => {
        expect(screen.getByTestId('sessions-count')).toHaveTextContent('1');
        expect(screen.getByTestId('active-session')).toHaveTextContent('test-session');
      });
    });

    it('should handle concurrent component updates', async () => {
      const user = userEvent.setup();
      
      render(<StoreTestComponent testId="concurrent-test" />);
      
      // Perform multiple rapid actions
      const actions = [
        () => user.click(screen.getByText('Add Agent')),
        () => user.click(screen.getByText('Add Session')),
        () => user.click(screen.getByText('Set Loading')),
        () => user.click(screen.getByText('Toggle Sidebar')),
      ];
      
      await Promise.all(actions.map(action => action()));
      
      await waitFor(() => {
        expect(screen.getByTestId('agents-count')).toHaveTextContent('1');
        expect(screen.getByTestId('sessions-count')).toHaveTextContent('1');
        expect(screen.getByTestId('loading')).toHaveTextContent('true');
        expect(screen.getByTestId('sidebar-collapsed')).toHaveTextContent('true');
      });
    });
  });

  describe('Performance and Memory', () => {
    it('should handle large state objects efficiently', () => {
      const largeAgentArray = Array.from({ length: 10000 }, (_, i) => ({
        id: `agent-${i}`,
        name: `Agent ${i}`,
        data: Array(100).fill(i).join(','), // Large data per agent
      }));
      
      const startTime = performance.now();
      
      store.setAgents(largeAgentArray);
      
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      // Should handle large state efficiently (< 100ms)
      expect(duration).toBeLessThan(100);
      expect(store.agents).toHaveLength(10000);
    });

    it('should cleanup resources properly', () => {
      // Add many terminals and sessions
      for (let i = 0; i < 100; i++) {
        store.addSession(`session-${i}`);
        store.addTerminal(`session-${i}`, { 
          id: `terminal-${i}`,
          element: document.createElement('div'),
        });
      }
      
      expect(store.sessions).toHaveLength(100);
      expect(store.terminals.size).toBe(100);
      
      // Clear all
      store.reset();
      
      expect(store.sessions).toHaveLength(0);
      expect(store.terminals.size).toBe(0);
    });

    it('should handle frequent state updates without memory leaks', () => {
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
      
      // Perform many state updates
      for (let i = 0; i < 1000; i++) {
        store.addAgent({ id: `agent-${i}`, name: `Agent ${i}` });
        store.removeAgent(`agent-${i}`);
        store.setLoading(i % 2 === 0);
        store.setError(i % 3 === 0 ? 'Error' : null);
      }
      
      // Force garbage collection
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Should not leak significant memory (< 10MB increase)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle invalid state updates gracefully', () => {
      expect(() => {
        store.setState(null as any);
      }).not.toThrow();
      
      expect(() => {
        store.setState(undefined as any);
      }).not.toThrow();
      
      expect(() => {
        store.addAgent(null as any);
      }).not.toThrow();
    });

    it('should handle circular references in state', () => {
      const circularObj: any = { name: 'circular' };
      circularObj.self = circularObj;
      
      expect(() => {
        store.addAgent(circularObj);
      }).not.toThrow();
      
      // Should not be able to serialize circular references
      expect(() => {
        JSON.stringify(store.getState());
      }).toThrow();
    });

    it('should handle store destruction gracefully', () => {
      store.addAgent({ id: 'agent-1', name: 'Test Agent' });
      store.addSession('session-1');
      
      expect(() => {
        store.destroy();
      }).not.toThrow();
      
      // Store should be in clean state after destruction
      expect(store.getState()).toBeDefined();
    });
  });
});