import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import HomePage from '../page';

// Mock dynamic imports
jest.mock('next/dynamic', () => {
  return (importFunction: any, options: any) => {
    const ComponentToMock = ({ sessionId, ...props }: any) => (
      <div data-testid="mocked-terminal" data-session-id={sessionId} {...props}>
        {options.loading ? options.loading() : 'Mocked Terminal Component'}
      </div>
    );
    ComponentToMock.displayName = 'MockedTerminal';
    return ComponentToMock;
  };
});

// Mock the store
const mockUseAppStore = {
  terminalSessions: [],
  activeSessionId: null,
  sidebarOpen: false,
  loading: false,
  error: null,
  toggleSidebar: jest.fn(),
  setActiveSession: jest.fn(),
  addSession: jest.fn(),
  removeSession: jest.fn(),
  updateSession: jest.fn(),
};

// Mock the WebSocket hook
const mockUseWebSocket = {
  connected: true,
  connecting: false,
  createSession: jest.fn(),
  destroySession: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
};

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => mockUseAppStore,
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => mockUseWebSocket,
}));

// Mock Sidebar component
jest.mock('@/components/sidebar/Sidebar', () => {
  return function MockSidebar({ isOpen, onToggle, sessions, activeSessionId, onSessionSelect, onSessionCreate, onSessionClose }: any) {
    return (
      <div data-testid="sidebar" data-is-open={isOpen}>
        <button onClick={onToggle} data-testid="sidebar-toggle">Toggle</button>
        <div data-testid="sessions-count">{sessions.length}</div>
        <div data-testid="active-session">{activeSessionId}</div>
        <button onClick={onSessionCreate} data-testid="create-session">Create</button>
        <button onClick={() => onSessionClose('test-session')} data-testid="close-session">Close</button>
        <button onClick={() => onSessionSelect('test-session')} data-testid="select-session">Select</button>
      </div>
    );
  };
});

describe('HomePage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset mock state
    Object.assign(mockUseAppStore, {
      terminalSessions: [],
      activeSessionId: null,
      sidebarOpen: false,
      loading: false,
      error: null,
    });
    Object.assign(mockUseWebSocket, {
      connected: true,
      connecting: false,
    });
  });

  describe('Loading States', () => {
    it('should show loading spinner when loading', () => {
      mockUseAppStore.loading = true;
      
      render(<HomePage />);
      
      expect(screen.getByText('Loading...')).toBeInTheDocument();
      expect(screen.getByRole('status', { name: /loading/i })).toBeInTheDocument();
    });

    it('should show connecting state when WebSocket is connecting', () => {
      mockUseWebSocket.connecting = true;
      
      render(<HomePage />);
      
      expect(screen.getByText('Connecting to terminal server...')).toBeInTheDocument();
    });
  });

  describe('Error States', () => {
    it('should show error message when there is an error', () => {
      mockUseAppStore.error = 'Connection failed';
      
      render(<HomePage />);
      
      expect(screen.getByText('Connection Error')).toBeInTheDocument();
      expect(screen.getByText('Connection failed')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    });

    it('should reload page when retry button is clicked', () => {
      mockUseAppStore.error = 'Test error';
      const reloadSpy = jest.spyOn(window.location, 'reload').mockImplementation(() => {});
      
      render(<HomePage />);
      
      const retryButton = screen.getByRole('button', { name: /retry/i });
      fireEvent.click(retryButton);
      
      expect(reloadSpy).toHaveBeenCalled();
      
      reloadSpy.mockRestore();
    });

    it('should show disconnected state when not connected', () => {
      mockUseWebSocket.connected = false;
      mockUseWebSocket.connecting = false;
      
      render(<HomePage />);
      
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
      expect(screen.getByText('Unable to connect to terminal server')).toBeInTheDocument();
    });
  });

  describe('Session Management', () => {
    beforeEach(() => {
      mockUseAppStore.terminalSessions = [];
      mockUseAppStore.activeSessionId = null;
    });

    it('should create session when connected and no sessions exist', async () => {
      mockUseWebSocket.connected = true;
      
      render(<HomePage />);
      
      await waitFor(() => {
        expect(mockUseWebSocket.createSession).toHaveBeenCalled();
      });
    });

    it('should handle session creation event', async () => {
      const sessionData = { sessionId: 'test-session-123' };
      
      render(<HomePage />);
      
      // Simulate session created event
      const sessionCreatedHandler = mockUseWebSocket.on.mock.calls
        .find(call => call[0] === 'session-created')?.[1];
      
      expect(sessionCreatedHandler).toBeDefined();
      
      sessionCreatedHandler(sessionData);
      
      expect(mockUseAppStore.addSession).toHaveBeenCalledWith({
        id: 'test-session-123',
        name: 'Claude Flow Terminal',
        isActive: true,
        lastActivity: expect.any(Date),
      });
      expect(mockUseAppStore.setActiveSession).toHaveBeenCalledWith('test-session-123');
    });

    it('should handle session destruction event', () => {
      const sessionData = { 
        sessionId: 'test-session-123',
        reason: 'user-closed',
        exitCode: 0 
      };
      
      render(<HomePage />);
      
      const sessionDestroyedHandler = mockUseWebSocket.on.mock.calls
        .find(call => call[0] === 'session-destroyed')?.[1];
      
      expect(sessionDestroyedHandler).toBeDefined();
      
      sessionDestroyedHandler(sessionData);
      
      expect(mockUseAppStore.removeSession).toHaveBeenCalledWith('test-session-123');
    });

    it('should handle claude-flow exit reason', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const sessionData = { 
        sessionId: 'test-session-123',
        reason: 'claude-flow-exited',
        exitCode: 1 
      };
      
      render(<HomePage />);
      
      const sessionDestroyedHandler = mockUseWebSocket.on.mock.calls
        .find(call => call[0] === 'session-destroyed')?.[1];
      
      sessionDestroyedHandler(sessionData);
      
      expect(consoleSpy).toHaveBeenCalledWith('Claude Flow exited with code 1');
      
      consoleSpy.mockRestore();
    });
  });

  describe('UI Interactions', () => {
    beforeEach(() => {
      mockUseAppStore.terminalSessions = [
        {
          id: 'test-session',
          name: 'Test Terminal',
          isActive: true,
          lastActivity: new Date(),
        }
      ];
      mockUseAppStore.activeSessionId = 'test-session';
    });

    it('should render terminal when active session exists', () => {
      render(<HomePage />);
      
      expect(screen.getByTestId('mocked-terminal')).toBeInTheDocument();
      expect(screen.getByTestId('mocked-terminal')).toHaveAttribute('data-session-id', 'test-session');
    });

    it('should show connecting message when no active session', () => {
      mockUseAppStore.activeSessionId = null;
      
      render(<HomePage />);
      
      expect(screen.getByText('Connecting to Terminal...')).toBeInTheDocument();
      expect(screen.getByText('Waiting for claude-flow process')).toBeInTheDocument();
    });

    it('should handle session selection', () => {
      render(<HomePage />);
      
      const selectButton = screen.getByTestId('select-session');
      fireEvent.click(selectButton);
      
      expect(mockUseAppStore.setActiveSession).toHaveBeenCalledWith('test-session');
    });

    it('should handle new session creation (no-op)', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      render(<HomePage />);
      
      const createButton = screen.getByTestId('create-session');
      fireEvent.click(createButton);
      
      expect(consoleSpy).toHaveBeenCalledWith('Only one terminal per claude-flow process');
      
      consoleSpy.mockRestore();
    });

    it('should handle session close (no-op)', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      render(<HomePage />);
      
      const closeButton = screen.getByTestId('close-session');
      fireEvent.click(closeButton);
      
      expect(consoleSpy).toHaveBeenCalledWith('Terminal lifecycle managed by claude-flow process');
      
      consoleSpy.mockRestore();
    });
  });

  describe('Sidebar Integration', () => {
    it('should pass correct props to Sidebar', () => {
      mockUseAppStore.sidebarOpen = true;
      mockUseAppStore.terminalSessions = [{ id: 'test', name: 'Test', isActive: true, lastActivity: new Date() }];
      mockUseAppStore.activeSessionId = 'test';
      
      render(<HomePage />);
      
      const sidebar = screen.getByTestId('sidebar');
      expect(sidebar).toHaveAttribute('data-is-open', 'true');
      expect(screen.getByTestId('sessions-count')).toHaveTextContent('1');
      expect(screen.getByTestId('active-session')).toHaveTextContent('test');
    });

    it('should handle sidebar toggle', () => {
      render(<HomePage />);
      
      const toggleButton = screen.getByTestId('sidebar-toggle');
      fireEvent.click(toggleButton);
      
      expect(mockUseAppStore.toggleSidebar).toHaveBeenCalled();
    });
  });

  describe('Event Listener Cleanup', () => {
    it('should cleanup event listeners on unmount', () => {
      const { unmount } = render(<HomePage />);
      
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('session-created', expect.any(Function));
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('session-destroyed', expect.any(Function));
      
      unmount();
      
      expect(mockUseWebSocket.off).toHaveBeenCalledWith('session-created', expect.any(Function));
      expect(mockUseWebSocket.off).toHaveBeenCalledWith('session-destroyed', expect.any(Function));
    });
  });

  describe('Console Logging', () => {
    it('should log connection state changes', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      mockUseWebSocket.connected = false;
      mockUseWebSocket.connecting = true;
      
      render(<HomePage />);
      
      expect(consoleSpy).toHaveBeenCalledWith('[HomePage] Connection state:', {
        connected: false,
        connecting: true
      });
      
      consoleSpy.mockRestore();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes and roles', () => {
      mockUseAppStore.loading = true;
      
      render(<HomePage />);
      
      // Loading spinner should have status role
      const loadingElement = screen.getByRole('status', { name: /loading/i });
      expect(loadingElement).toBeInTheDocument();
    });

    it('should have proper error state accessibility', () => {
      mockUseAppStore.error = 'Test error';
      
      render(<HomePage />);
      
      // Error should be announced
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
      expect(screen.getByText('Connection Error')).toBeInTheDocument();
    });
  });
});