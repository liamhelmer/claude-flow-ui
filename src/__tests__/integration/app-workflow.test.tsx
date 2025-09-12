import React from 'react';
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import HomePage from '../../app/page';

// Mock dynamic imports with more realistic behavior
jest.mock('next/dynamic', () => {
  return (importFunction: any, options: any) => {
    const ComponentToMock = ({ sessionId, className, ...props }: any) => {
      // Simulate loading delay
      const [isLoading, setIsLoading] = React.useState(true);
      
      React.useEffect(() => {
        const timer = setTimeout(() => setIsLoading(false), 100);
        return () => clearTimeout(timer);
      }, []);
      
      if (isLoading && options.loading) {
        return options.loading();
      }
      
      return (
        <div 
          data-testid="mocked-terminal" 
          data-session-id={sessionId} 
          className={className}
          {...props}
        >
          Mocked Terminal Component - Session: {sessionId}
        </div>
      );
    };
    ComponentToMock.displayName = 'MockedTerminal';
    return ComponentToMock;
  };
});

// Enhanced store mock with realistic state management
const createMockStore = (initialState = {}) => {
  const state = {
    terminalSessions: [],
    activeSessionId: null,
    sidebarOpen: false,
    loading: false,
    error: null,
    ...initialState,
  };
  
  return {
    ...state,
    toggleSidebar: jest.fn(() => {
      state.sidebarOpen = !state.sidebarOpen;
    }),
    setActiveSession: jest.fn((id) => {
      state.activeSessionId = id;
    }),
    addSession: jest.fn((session) => {
      state.terminalSessions.push(session);
    }),
    removeSession: jest.fn((id) => {
      state.terminalSessions = state.terminalSessions.filter(s => s.id !== id);
    }),
    updateSession: jest.fn((id, updates) => {
      const index = state.terminalSessions.findIndex(s => s.id === id);
      if (index >= 0) {
        state.terminalSessions[index] = { ...state.terminalSessions[index], ...updates };
      }
    }),
  };
};

// Enhanced WebSocket mock with event simulation
const createMockWebSocket = (initialState = {}) => {
  const eventHandlers = new Map();
  
  const mockWebSocket = {
    connected: true,
    connecting: false,
    createSession: jest.fn(),
    destroySession: jest.fn(),
    on: jest.fn((event, handler) => {
      eventHandlers.set(event, handler);
    }),
    off: jest.fn((event, handler) => {
      eventHandlers.delete(event);
    }),
    // Helper to simulate events
    _emit: (event: string, data: any) => {
      const handler = eventHandlers.get(event);
      if (handler) handler(data);
    },
    ...initialState,
  };
  
  return mockWebSocket;
};

// Mock Sidebar with realistic behavior
jest.mock('../../components/sidebar/Sidebar', () => {
  return function MockSidebar({ 
    isOpen, 
    onToggle, 
    sessions, 
    activeSessionId, 
    onSessionSelect, 
    onSessionCreate, 
    onSessionClose 
  }: any) {
    return (
      <div 
        data-testid="sidebar" 
        data-is-open={isOpen}
        className={isOpen ? 'sidebar-open' : 'sidebar-closed'}
      >
        <div data-testid="sidebar-header">
          <h2>Terminal Sessions</h2>
          <button onClick={onToggle} data-testid="sidebar-toggle">
            {isOpen ? 'Close' : 'Open'}
          </button>
        </div>
        
        <div data-testid="sessions-list">
          {sessions.map((session: any) => (
            <div
              key={session.id}
              data-testid={`session-${session.id}`}
              className={session.id === activeSessionId ? 'session-active' : 'session-inactive'}
            >
              <span>{session.name}</span>
              <button onClick={() => onSessionSelect(session.id)}>Select</button>
              <button onClick={() => onSessionClose(session.id)}>Close</button>
            </div>
          ))}
        </div>
        
        <button onClick={onSessionCreate} data-testid="create-session">
          New Session
        </button>
      </div>
    );
  };
});

describe('App Workflow Integration Tests', () => {
  let mockStore: any;
  let mockWebSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockStore = createMockStore();
    mockWebSocket = createMockWebSocket();

    jest.doMock('../../lib/state/store', () => ({
      useAppStore: () => mockStore,
    }));

    jest.doMock('../../hooks/useWebSocket', () => ({
      useWebSocket: () => mockWebSocket,
    }));
  });

  afterEach(() => {
    jest.resetModules();
  });

  describe('Complete Application Workflow', () => {
    it('should handle complete session lifecycle', async () => {
      render(<HomePage />);

      // Initial state - no sessions
      expect(screen.getByText('Connecting to Terminal...')).toBeInTheDocument();

      // Simulate session creation
      act(() => {
        mockWebSocket._emit('session-created', { sessionId: 'session-123' });
      });

      // Wait for session to be added and UI to update
      await waitFor(() => {
        expect(mockStore.addSession).toHaveBeenCalledWith(
          expect.objectContaining({
            id: 'session-123',
            name: 'Claude Flow Terminal',
            isActive: true,
          })
        );
      });

      // Update store state to reflect the session
      mockStore.terminalSessions = [{
        id: 'session-123',
        name: 'Claude Flow Terminal',
        isActive: true,
        lastActivity: new Date(),
      }];
      mockStore.activeSessionId = 'session-123';

      // Re-render to see the terminal
      render(<HomePage />);

      await waitFor(() => {
        expect(screen.getByTestId('mocked-terminal')).toBeInTheDocument();
        expect(screen.getByTestId('mocked-terminal')).toHaveAttribute('data-session-id', 'session-123');
      });

      // Simulate session destruction
      act(() => {
        mockWebSocket._emit('session-destroyed', { 
          sessionId: 'session-123',
          reason: 'user-closed',
          exitCode: 0 
        });
      });

      expect(mockStore.removeSession).toHaveBeenCalledWith('session-123');
    });

    it('should handle error states and recovery', async () => {
      // Start with error state
      mockStore.error = 'Connection failed';
      mockStore.connected = false;

      render(<HomePage />);

      expect(screen.getByText('Connection Error')).toBeInTheDocument();
      expect(screen.getByText('Connection failed')).toBeInTheDocument();

      // Simulate recovery by clicking retry
      const retryButton = screen.getByRole('button', { name: /retry/i });
      
      // Mock window.location.reload
      const reloadSpy = jest.spyOn(window.location, 'reload').mockImplementation(() => {});
      
      fireEvent.click(retryButton);
      expect(reloadSpy).toHaveBeenCalled();
      
      reloadSpy.mockRestore();
    });

    it('should handle loading states throughout the workflow', async () => {
      // Start with loading
      mockStore.loading = true;

      render(<HomePage />);

      expect(screen.getByText('Loading...')).toBeInTheDocument();

      // Clear loading state
      mockStore.loading = false;
      mockWebSocket.connected = true;

      render(<HomePage />);

      // Should show connection message
      expect(screen.getByText('Connecting to Terminal...')).toBeInTheDocument();
    });

    it('should handle sidebar interactions during session management', async () => {
      // Set up with active session
      mockStore.terminalSessions = [{
        id: 'session-123',
        name: 'Claude Flow Terminal',
        isActive: true,
        lastActivity: new Date(),
      }];
      mockStore.activeSessionId = 'session-123';

      render(<HomePage />);

      // Toggle sidebar
      const sidebarToggle = screen.getByTestId('sidebar-toggle');
      fireEvent.click(sidebarToggle);

      expect(mockStore.toggleSidebar).toHaveBeenCalled();

      // Interact with session in sidebar
      const sessionElement = screen.getByTestId('session-session-123');
      expect(sessionElement).toHaveClass('session-active');

      const selectButton = sessionElement.querySelector('button');
      if (selectButton) {
        fireEvent.click(selectButton);
        expect(mockStore.setActiveSession).toHaveBeenCalledWith('session-123');
      }
    });

    it('should handle WebSocket reconnection workflow', async () => {
      // Start connected with session
      mockStore.terminalSessions = [{
        id: 'session-123',
        name: 'Claude Flow Terminal',
        isActive: true,
        lastActivity: new Date(),
      }];
      mockStore.activeSessionId = 'session-123';
      mockWebSocket.connected = true;

      render(<HomePage />);

      // Simulate disconnection
      mockWebSocket.connected = false;
      
      render(<HomePage />);
      expect(screen.getByText('Disconnected')).toBeInTheDocument();

      // Simulate reconnection
      mockWebSocket.connected = true;
      mockWebSocket.connecting = false;

      render(<HomePage />);

      // Should automatically try to create session when reconnected
      await waitFor(() => {
        expect(mockWebSocket.createSession).toHaveBeenCalled();
      });
    });

    it('should handle rapid state changes gracefully', async () => {
      render(<HomePage />);

      // Rapidly change states
      const states = [
        { loading: true },
        { loading: false, error: 'Connection failed' },
        { error: null, connecting: true },
        { connecting: false, connected: true },
        { connected: false },
        { connected: true, activeSessionId: 'session-123' },
      ];

      for (const state of states) {
        Object.assign(mockStore, state);
        Object.assign(mockWebSocket, state);
        
        // Re-render with new state
        render(<HomePage />);
        
        // Should not crash
        expect(document.body).toBeInTheDocument();
      }
    });

    it('should handle multiple session events in sequence', async () => {
      render(<HomePage />);

      const sessionEvents = [
        { type: 'session-created', data: { sessionId: 'session-1' } },
        { type: 'session-created', data: { sessionId: 'session-2' } },
        { type: 'session-destroyed', data: { sessionId: 'session-1', reason: 'timeout' } },
        { type: 'session-created', data: { sessionId: 'session-3' } },
        { type: 'session-destroyed', data: { sessionId: 'session-2', reason: 'user-closed' } },
      ];

      for (const event of sessionEvents) {
        act(() => {
          mockWebSocket._emit(event.type, event.data);
        });
      }

      // Should handle all events without crashing
      expect(mockStore.addSession).toHaveBeenCalledTimes(3);
      expect(mockStore.removeSession).toHaveBeenCalledTimes(2);
    });
  });

  describe('Edge Case Workflows', () => {
    it('should handle component unmounting during async operations', async () => {
      const { unmount } = render(<HomePage />);

      // Start async operation
      act(() => {
        mockWebSocket._emit('session-created', { sessionId: 'session-123' });
      });

      // Unmount before operation completes
      expect(() => unmount()).not.toThrow();
    });

    it('should handle missing dependencies gracefully', async () => {
      // Mock missing store methods
      mockStore.addSession = undefined;
      mockStore.removeSession = undefined;

      render(<HomePage />);

      // Should not crash when events are emitted
      expect(() => {
        act(() => {
          mockWebSocket._emit('session-created', { sessionId: 'session-123' });
          mockWebSocket._emit('session-destroyed', { sessionId: 'session-123' });
        });
      }).not.toThrow();
    });

    it('should handle malformed WebSocket events', async () => {
      render(<HomePage />);

      const malformedEvents = [
        { type: 'session-created', data: null },
        { type: 'session-created', data: {} },
        { type: 'session-destroyed', data: { sessionId: null } },
        { type: 'session-destroyed', data: { reason: 'test' } }, // missing sessionId
      ];

      for (const event of malformedEvents) {
        expect(() => {
          act(() => {
            mockWebSocket._emit(event.type, event.data);
          });
        }).not.toThrow();
      }
    });

    it('should handle concurrent session operations', async () => {
      render(<HomePage />);

      // Simulate concurrent operations
      const concurrentOperations = Promise.all([
        new Promise(resolve => {
          act(() => {
            mockWebSocket._emit('session-created', { sessionId: 'session-1' });
            resolve(null);
          });
        }),
        new Promise(resolve => {
          act(() => {
            mockWebSocket._emit('session-created', { sessionId: 'session-2' });
            resolve(null);
          });
        }),
        new Promise(resolve => {
          act(() => {
            mockWebSocket._emit('session-destroyed', { sessionId: 'session-1' });
            resolve(null);
          });
        }),
      ]);

      await expect(concurrentOperations).resolves.toBeDefined();
    });
  });
});