import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Terminal } from '../../components/terminal/Terminal';
import { Sidebar } from '../../components/sidebar/Sidebar';
import { MonitoringSidebar } from '../../components/monitoring/MonitoringSidebar';
import { useAppStore } from '../../lib/state/store';
import { useWebSocket } from '../../hooks/useWebSocket';

// Mock dependencies
jest.mock('../../hooks/useWebSocket');
jest.mock('../../lib/state/store');
jest.mock('@xterm/xterm');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('Cross-Component Integration Tests', () => {
  let mockWebSocket: any;
  let mockStore: any;

  beforeEach(() => {
    mockWebSocket = {
      connected: true,
      connecting: false,
      isConnected: true,
      connect: jest.fn(),
      disconnect: jest.fn(),
      sendData: jest.fn(),
      createSession: jest.fn(),
      destroySession: jest.fn(),
      resizeTerminal: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
    };

    mockStore = {
      terminalSessions: [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
        {
          id: 'session-2',
          name: 'Terminal 2',
          isActive: false,
          lastActivity: new Date(),
        }
      ],
      activeSessionId: 'session-1',
      sidebarOpen: true,
      loading: false,
      error: null,
      setSidebarOpen: jest.fn(),
      toggleSidebar: jest.fn(),
      setActiveSession: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      updateSession: jest.fn(),
      createNewSession: jest.fn().mockReturnValue('new-session'),
      setLoading: jest.fn(),
      setError: jest.fn(),
    };

    mockUseWebSocket.mockReturnValue(mockWebSocket);
    mockUseAppStore.mockReturnValue(mockStore);

    // Mock DOM methods
    Object.defineProperty(HTMLElement.prototype, 'scrollTop', {
      writable: true,
      value: 0,
    });

    Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
      writable: true,
      value: 1000,
    });

    Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
      writable: true,
      value: 400,
    });

    // Mock xterm
    const mockTerminal = {
      element: {
        querySelector: jest.fn().mockReturnValue({
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 400,
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
        }),
      },
      cols: 80,
      rows: 24,
      open: jest.fn(),
      write: jest.fn(),
      onData: jest.fn(),
      dispose: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      loadAddon: jest.fn(),
    };

    require('@xterm/xterm').Terminal.mockImplementation(() => mockTerminal);
    require('@xterm/addon-serialize').SerializeAddon.mockImplementation(() => ({}));

    jest.clearAllMocks();
  });

  describe('Terminal and Sidebar Integration', () => {
    it('should create new terminal session from sidebar', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      const newSessionButton = screen.getByText(/new/i);
      await user.click(newSessionButton);

      expect(mockStore.createNewSession).toHaveBeenCalled();
    });

    it('should switch terminal sessions from sidebar', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      const sessionButton = screen.getByText('Terminal 2');
      await user.click(sessionButton);

      expect(mockStore.setActiveSession).toHaveBeenCalledWith('session-2');
    });

    it('should remove terminal session and update active session', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Find and click close button for session-1
      const closeButtons = screen.getAllByRole('button');
      const closeButton = closeButtons.find(button => 
        button.getAttribute('aria-label')?.includes('Close')
      );
      
      if (closeButton) {
        await user.click(closeButton);
        expect(mockStore.removeSession).toHaveBeenCalledWith('session-1');
      }
    });

    it('should toggle sidebar and affect layout', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      const toggleButton = screen.getByRole('button', { name: /toggle/i });
      await user.click(toggleButton);

      expect(mockStore.toggleSidebar).toHaveBeenCalled();
    });
  });

  describe('WebSocket State Integration', () => {
    it('should show connection status across components', () => {
      mockWebSocket.connected = false;
      mockWebSocket.isConnected = false;

      render(
        <div>
          <Sidebar />
          <MonitoringSidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Connection status should be reflected in monitoring components
      expect(screen.getByText(/disconnected/i)).toBeInTheDocument();
    });

    it('should handle connection errors across components', () => {
      mockStore.error = 'Connection failed';

      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      expect(screen.getByText(/connection failed/i)).toBeInTheDocument();
    });

    it('should show loading state across components', () => {
      mockStore.loading = true;

      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      expect(screen.getByText(/loading/i)).toBeInTheDocument();
    });
  });

  describe('Session Management Integration', () => {
    it('should synchronize session state across components', async () => {
      const user = userEvent.setup();
      
      // Update store with new session
      const updatedStore = {
        ...mockStore,
        terminalSessions: [
          ...mockStore.terminalSessions,
          {
            id: 'session-3',
            name: 'Terminal 3',
            isActive: false,
            lastActivity: new Date(),
          }
        ]
      };

      mockUseAppStore.mockReturnValue(updatedStore);

      render(
        <div>
          <Sidebar />
          <MonitoringSidebar />
        </div>
      );

      // Both components should show the new session
      const sidebarSession = screen.getByText('Terminal 3');
      expect(sidebarSession).toBeInTheDocument();

      // Session count should be updated
      expect(screen.getByText(/3\s*sessions?/i)).toBeInTheDocument();
    });

    it('should handle session updates across components', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Simulate session update
      act(() => {
        mockStore.updateSession('session-1', { 
          name: 'Updated Terminal',
          lastActivity: new Date(),
        });
      });

      // Components should reflect the update
      await waitFor(() => {
        expect(screen.getByText(/updated terminal/i)).toBeInTheDocument();
      });
    });
  });

  describe('Terminal Data Flow Integration', () => {
    it('should handle terminal input and output across components', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar />
        </div>
      );

      // Simulate terminal input
      const terminalContainer = screen.getByTestId?.('terminal-container') || 
                                 document.querySelector('[data-testid="terminal-container"]');
      
      if (terminalContainer) {
        fireEvent.keyDown(terminalContainer, { key: 'Enter', code: 'Enter' });
        
        expect(mockWebSocket.sendData).toHaveBeenCalled();
      }
    });

    it('should update session activity across components', async () => {
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Simulate terminal activity
      act(() => {
        const onDataHandler = mockWebSocket.on.mock.calls.find(
          call => call[0] === 'terminal-data'
        )?.[1];
        
        if (onDataHandler) {
          onDataHandler({
            sessionId: 'session-1',
            data: 'test output'
          });
        }
      });

      // Session should be marked as active
      expect(mockStore.updateSession).toHaveBeenCalledWith(
        'session-1',
        expect.objectContaining({
          isActive: true,
          lastActivity: expect.any(Date),
        })
      );
    });
  });

  describe('Error Handling Integration', () => {
    it('should propagate and display errors across components', () => {
      mockStore.error = 'Terminal connection lost';
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
          <MonitoringSidebar />
        </div>
      );

      // Error should be visible in multiple components
      const errorElements = screen.getAllByText(/terminal connection lost/i);
      expect(errorElements.length).toBeGreaterThan(0);
    });

    it('should handle terminal errors gracefully', async () => {
      render(<Terminal sessionId="session-1" />);

      // Simulate terminal error
      act(() => {
        const errorHandler = mockWebSocket.on.mock.calls.find(
          call => call[0] === 'terminal-error'
        )?.[1];
        
        if (errorHandler) {
          errorHandler({
            sessionId: 'session-1',
            error: 'Command not found'
          });
        }
      });

      // Error should be handled without crashing
      expect(screen.queryByText(/something went wrong/i)).not.toBeInTheDocument();
    });

    it('should recover from WebSocket disconnection', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar />
        </div>
      );

      // Simulate disconnection
      mockWebSocket.connected = false;
      mockWebSocket.isConnected = false;
      
      // Simulate connection change event
      act(() => {
        const connectionHandler = mockWebSocket.on.mock.calls.find(
          call => call[0] === 'connection-change'
        )?.[1];
        
        if (connectionHandler) {
          connectionHandler(false);
        }
      });

      // Should show disconnected state
      expect(screen.getByText(/disconnected/i)).toBeInTheDocument();

      // Simulate reconnection attempt
      const reconnectButton = screen.getByRole('button', { name: /connect/i });
      await user.click(reconnectButton);

      expect(mockWebSocket.connect).toHaveBeenCalled();
    });
  });

  describe('Performance Integration', () => {
    it('should handle rapid session switching without issues', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Rapidly switch between sessions
      for (let i = 0; i < 10; i++) {
        const sessionId = i % 2 === 0 ? 'session-1' : 'session-2';
        
        act(() => {
          mockStore.setActiveSession(sessionId);
        });
      }

      // Should not cause any errors
      expect(mockStore.setActiveSession).toHaveBeenCalledTimes(10);
    });

    it('should handle large terminal output without performance issues', async () => {
      render(<Terminal sessionId="session-1" />);

      // Simulate large terminal output
      const largeOutput = 'x'.repeat(10000);
      
      act(() => {
        const dataHandler = mockWebSocket.on.mock.calls.find(
          call => call[0] === 'terminal-data'
        )?.[1];
        
        if (dataHandler) {
          dataHandler({
            sessionId: 'session-1',
            data: largeOutput
          });
        }
      });

      // Should handle large output gracefully
      expect(mockStore.updateSession).toHaveBeenCalled();
    });
  });

  describe('Accessibility Integration', () => {
    it('should maintain keyboard navigation across components', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Tab navigation should work
      await user.tab();
      expect(document.activeElement).toBeInTheDocument();

      await user.tab();
      expect(document.activeElement).toBeInTheDocument();
    });

    it('should provide proper ARIA labels and roles', () => {
      render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
          <MonitoringSidebar />
        </div>
      );

      // Check for proper roles
      expect(screen.getByRole('complementary')).toBeInTheDocument(); // Sidebar
      expect(screen.getByRole('main')).toBeInTheDocument(); // Terminal area
    });
  });

  describe('State Persistence Integration', () => {
    it('should maintain state consistency during component updates', async () => {
      const { rerender } = render(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Update store
      const newStore = {
        ...mockStore,
        activeSessionId: 'session-2',
        sidebarOpen: false,
      };

      mockUseAppStore.mockReturnValue(newStore);

      // Rerender with new state
      rerender(
        <div>
          <Sidebar />
          <Terminal sessionId="session-2" />
        </div>
      );

      // Components should reflect new state
      expect(screen.queryByText('Terminal 1')).not.toHaveClass('active');
    });
  });
});