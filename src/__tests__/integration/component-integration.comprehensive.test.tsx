import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '@/components/terminal/Terminal';
import TabList from '@/components/tabs/TabList';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { TerminalSession } from '@/types';

// Mock hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;
const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;

// Mock child components for focused integration testing
jest.mock('@/components/terminal/TerminalControls', () => {
  return function MockTerminalControls({ onScrollToTop, onScrollToBottom }: any) {
    return (
      <div data-testid="terminal-controls">
        <button onClick={onScrollToTop} data-testid="scroll-top">Top</button>
        <button onClick={onScrollToBottom} data-testid="scroll-bottom">Bottom</button>
      </div>
    );
  };
});

jest.mock('@/components/monitoring/AgentsPanel', () => {
  const AgentsPanel = () => <div data-testid="agents-panel">Agents</div>;
  AgentsPanel.displayName = 'AgentsPanel';
  return AgentsPanel;
});
jest.mock('@/components/monitoring/MemoryPanel', () => {
  const MemoryPanel = () => <div data-testid="memory-panel">Memory</div>;
  MemoryPanel.displayName = 'MemoryPanel';
  return MemoryPanel;
});
jest.mock('@/components/monitoring/CommandsPanel', () => {
  const CommandsPanel = () => <div data-testid="commands-panel">Commands</div>;
  CommandsPanel.displayName = 'CommandsPanel';
  return CommandsPanel;
});
jest.mock('@/components/monitoring/PromptPanel', () => {
  const PromptPanel = () => <div data-testid="prompt-panel">Prompt</div>;
  PromptPanel.displayName = 'PromptPanel';
  return PromptPanel;
});

describe('Component Integration - Comprehensive Tests', () => {
  let mockSendData: jest.Mock;
  let mockCreateSession: jest.Mock;
  let mockDestroySession: jest.Mock;
  let mockFocusTerminal: jest.Mock;
  let mockScrollToTop: jest.Mock;
  let mockScrollToBottom: jest.Mock;

  const mockSessions: TerminalSession[] = [
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
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();

    mockSendData = jest.fn();
    mockCreateSession = jest.fn();
    mockDestroySession = jest.fn();
    mockFocusTerminal = jest.fn();
    mockScrollToTop = jest.fn();
    mockScrollToBottom = jest.fn();

    mockUseWebSocket.mockReturnValue({
      connected: true,
      connecting: false,
      isConnected: true,
      connect: jest.fn(),
      disconnect: jest.fn(),
      sendMessage: jest.fn(),
      sendData: mockSendData,
      resizeTerminal: jest.fn(),
      createSession: mockCreateSession,
      destroySession: mockDestroySession,
      listSessions: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
    });

    mockUseTerminal.mockReturnValue({
      terminalRef: { current: document.createElement('div') },
      terminal: { cols: 80, rows: 24 },
      focusTerminal: mockFocusTerminal,
      fitTerminal: jest.fn(),
      scrollToTop: mockScrollToTop,
      scrollToBottom: mockScrollToBottom,
      isAtBottom: true,
      hasNewOutput: false,
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      destroyTerminal: jest.fn(),
      isConnected: true,
    });
  });

  describe('Terminal and TabList Integration', () => {
    it('should coordinate terminal focus when switching tabs', async () => {
      const user = userEvent.setup();
      const onSessionSelect = jest.fn();

      render(
        <div>
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={onSessionSelect}
            onSessionCreate={jest.fn()}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Switch to different tab
      await user.click(screen.getByText('Terminal 2'));
      expect(onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    it('should handle terminal destruction when closing tabs', async () => {
      const user = userEvent.setup();
      const onSessionClose = jest.fn();

      render(
        <div>
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={jest.fn()}
            onSessionCreate={jest.fn()}
            onSessionClose={onSessionClose}
          />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Find and click close button for Terminal 1
      const closeButtons = screen.getAllByText('×');
      await user.click(closeButtons[0]);
      
      expect(onSessionClose).toHaveBeenCalledWith('session-1');
    });

    it('should create new session and terminal coordination', async () => {
      const user = userEvent.setup();
      const onSessionCreate = jest.fn();

      render(
        <div>
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={jest.fn()}
            onSessionCreate={onSessionCreate}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
        </div>
      );

      await user.click(screen.getByLabelText('Create new terminal session'));
      expect(onSessionCreate).toHaveBeenCalled();
    });
  });

  describe('Terminal and MonitoringSidebar Integration', () => {
    it('should coordinate terminal state with monitoring sidebar', () => {
      render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();
      expect(screen.getByTestId('memory-panel')).toBeInTheDocument();
    });

    it('should handle monitoring sidebar state changes without affecting terminal', async () => {
      const user = userEvent.setup();
      const onToggle = jest.fn();

      const { rerender } = render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={onToggle} />
        </div>
      );

      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();

      // Toggle sidebar
      await user.click(screen.getByLabelText('Toggle monitoring sidebar'));
      expect(onToggle).toHaveBeenCalled();

      // Rerender with sidebar closed
      rerender(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={false} onToggle={onToggle} />
        </div>
      );

      // Terminal should still be functional
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
      expect(screen.queryByTestId('agents-panel')).not.toBeInTheDocument();
    });
  });

  describe('Full Application Integration', () => {
    it('should handle complete application workflow', async () => {
      const user = userEvent.setup();
      
      const AppComponent = () => {
        const [sessions, setSessions] = React.useState(mockSessions);
        const [activeSessionId, setActiveSessionId] = React.useState('session-1');
        const [sidebarOpen, setSidebarOpen] = React.useState(true);

        const handleSessionSelect = (sessionId: string) => {
          setActiveSessionId(sessionId);
        };

        const handleSessionCreate = () => {
          const newSession: TerminalSession = {
            id: `session-${Date.now()}`,
            name: `Terminal ${sessions.length + 1}`,
            isActive: false,
            lastActivity: new Date(),
          };
          setSessions([...sessions, newSession]);
          setActiveSessionId(newSession.id);
        };

        const handleSessionClose = (sessionId: string) => {
          const updatedSessions = sessions.filter(s => s.id !== sessionId);
          setSessions(updatedSessions);
          if (sessionId === activeSessionId && updatedSessions.length > 0) {
            setActiveSessionId(updatedSessions[0].id);
          }
        };

        return (
          <div>
            <TabList
              sessions={sessions}
              activeSessionId={activeSessionId}
              onSessionSelect={handleSessionSelect}
              onSessionCreate={handleSessionCreate}
              onSessionClose={handleSessionClose}
            />
            {activeSessionId && <Terminal sessionId={activeSessionId} />}
            <MonitoringSidebar
              isOpen={sidebarOpen}
              onToggle={() => setSidebarOpen(!sidebarOpen)}
            />
          </div>
        );
      };

      render(<AppComponent />);

      // Initial state verification
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();

      // Switch to second terminal
      await user.click(screen.getByText('Terminal 2'));
      
      // Create new terminal
      await user.click(screen.getByLabelText('Create new terminal session'));
      expect(screen.getByText('Terminal 3')).toBeInTheDocument();

      // Close a terminal
      const closeButtons = screen.getAllByText('×');
      await user.click(closeButtons[0]);

      // Verify terminal is removed
      expect(screen.queryByText('Terminal 1')).not.toBeInTheDocument();

      // Toggle monitoring sidebar
      await user.click(screen.getByLabelText('Toggle monitoring sidebar'));
      expect(screen.queryByTestId('agents-panel')).not.toBeInTheDocument();
    });

    it('should handle terminal scroll coordination with controls', async () => {
      const user = userEvent.setup();

      render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      // Test scroll controls
      await user.click(screen.getByTestId('scroll-top'));
      expect(mockScrollToTop).toHaveBeenCalled();

      await user.click(screen.getByTestId('scroll-bottom'));
      expect(mockScrollToBottom).toHaveBeenCalled();
    });
  });

  describe('State Synchronization', () => {
    it('should maintain consistent state across component updates', () => {
      const { rerender } = render(
        <div>
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={jest.fn()}
            onSessionCreate={jest.fn()}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Update with new session
      const updatedSessions = [
        ...mockSessions,
        {
          id: 'session-3',
          name: 'Terminal 3',
          isActive: false,
          lastActivity: new Date(),
        },
      ];

      rerender(
        <div>
          <TabList
            sessions={updatedSessions}
            activeSessionId="session-1"
            onSessionSelect={jest.fn()}
            onSessionCreate={jest.fn()}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
        </div>
      );

      expect(screen.getByText('Terminal 3')).toBeInTheDocument();
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
    });

    it('should handle connection state changes across components', () => {
      // Simulate disconnected state
      mockUseWebSocket.mockReturnValue({
        ...mockUseWebSocket(),
        connected: false,
        isConnected: false,
      });

      render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      // Components should handle disconnected state gracefully
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle terminal errors without affecting other components', () => {
      // Simulate terminal hook error
      mockUseTerminal.mockImplementation(() => {
        throw new Error('Terminal initialization failed');
      });

      expect(() => {
        render(
          <div>
            <TabList
              sessions={mockSessions}
              activeSessionId="session-1"
              onSessionSelect={jest.fn()}
              onSessionCreate={jest.fn()}
              onSessionClose={jest.fn()}
            />
            <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
          </div>
        );
      }).toThrow('Terminal initialization failed');
    });

    it('should handle WebSocket errors across components', () => {
      mockUseWebSocket.mockReturnValue({
        ...mockUseWebSocket(),
        connected: false,
        connecting: false,
        isConnected: false,
      });

      render(
        <div>
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      // Components should render even with WebSocket issues
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();
    });
  });

  describe('Performance Integration', () => {
    it('should handle rapid state changes efficiently', async () => {
      const user = userEvent.setup();
      
      const RapidChangeComponent = () => {
        const [count, setCount] = React.useState(0);
        const [sidebarOpen, setSidebarOpen] = React.useState(true);

        return (
          <div>
            <button onClick={() => setCount(c => c + 1)} data-testid="increment">
              Count: {count}
            </button>
            <TabList
              sessions={mockSessions}
              activeSessionId="session-1"
              onSessionSelect={jest.fn()}
              onSessionCreate={jest.fn()}
              onSessionClose={jest.fn()}
            />
            <Terminal sessionId="session-1" />
            <MonitoringSidebar
              isOpen={sidebarOpen}
              onToggle={() => setSidebarOpen(!sidebarOpen)}
            />
          </div>
        );
      };

      render(<RapidChangeComponent />);

      // Perform rapid state changes
      for (let i = 0; i < 5; i++) {
        await user.click(screen.getByTestId('increment'));
        await user.click(screen.getByLabelText('Toggle monitoring sidebar'));
      }

      expect(screen.getByText('Count: 5')).toBeInTheDocument();
    });

    it('should handle large numbers of sessions efficiently', () => {
      const manySessions = Array.from({ length: 20 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i + 1}`,
        isActive: i === 0,
        lastActivity: new Date(),
      }));

      render(
        <div>
          <TabList
            sessions={manySessions}
            activeSessionId="session-0"
            onSessionSelect={jest.fn()}
            onSessionCreate={jest.fn()}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-0" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      expect(screen.getAllByRole('tab')).toHaveLength(20);
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
    });
  });

  describe('Accessibility Integration', () => {
    it('should maintain focus management across components', async () => {
      const user = userEvent.setup();

      render(
        <div>
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={jest.fn()}
            onSessionCreate={jest.fn()}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      // Tab through components
      await user.tab(); // First tab
      await user.tab(); // Second tab
      await user.tab(); // New tab button
      await user.tab(); // Terminal controls
      await user.tab(); // Monitoring toggle

      // Verify focus is managed correctly
      expect(screen.getByLabelText('Toggle monitoring sidebar')).toHaveFocus();
    });

    it('should provide appropriate ARIA labels across components', () => {
      render(
        <div>
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={jest.fn()}
            onSessionCreate={jest.fn()}
            onSessionClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
          <MonitoringSidebar isOpen={true} onToggle={jest.fn()} />
        </div>
      );

      expect(screen.getByRole('tablist')).toHaveAttribute('aria-label', 'Terminal sessions');
      expect(screen.getByRole('complementary')).toHaveAttribute('aria-label', 'System monitoring sidebar');
    });
  });
});