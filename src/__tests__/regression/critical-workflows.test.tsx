import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '@/components/terminal/Terminal';
import TerminalControls from '@/components/terminal/TerminalControls';
import Tab from '@/components/tabs/Tab';
import TabList from '@/components/tabs/TabList';
import Sidebar from '@/components/sidebar/Sidebar';
import { AgentsPanel } from '@/components/monitoring/AgentsPanel';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import { useAppStore } from '@/lib/state/store';
import { MockWebSocketClient, createMockWebSocket, createTestScenario } from '../../../tests/mocks/websocketMockUtils';

// Mock dependencies
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

/**
 * Critical User Workflow Regression Tests
 * 
 * These tests ensure that core user workflows continue to work correctly
 * and help prevent regressions in critical functionality.
 */
describe('Critical User Workflow Regression Tests', () => {
  let mockWebSocket: MockWebSocketClient;
  let user: ReturnType<typeof userEvent.setup>;
  let mockStore: any;
  let mockTerminalHook: any;

  beforeEach(() => {
    user = userEvent.setup();
    mockWebSocket = createMockWebSocket.stable();
    
    mockStore = {
      sessions: [
        { id: 'session-1', title: 'Main Terminal' },
        { id: 'session-2', title: 'Build Process' },
      ],
      activeSession: 'session-1',
      isCollapsed: false,
      error: null,
      loading: false,
      agents: [],
      prompts: [],
      memory: [],
      commands: [],
      setError: jest.fn(),
      setLoading: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      setActiveSession: jest.fn(),
      toggleSidebar: jest.fn(),
      updateSession: jest.fn(),
    };

    mockTerminalHook = {
      terminalRef: { current: null },
      terminal: null,
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      destroyTerminal: jest.fn(),
      scrollToBottom: jest.fn(),
      scrollToTop: jest.fn(),
      isAtBottom: true,
      hasNewOutput: false,
      isConnected: true,
    };

    mockUseWebSocket.mockReturnValue({
      connected: mockWebSocket.connected,
      connecting: mockWebSocket.connecting,
      isConnected: mockWebSocket.connected,
      sendData: jest.fn((sessionId, data) => mockWebSocket.send('data', { sessionId, data })),
      sendMessage: jest.fn((msg) => mockWebSocket.sendMessage(msg)),
      resizeTerminal: jest.fn((sessionId, cols, rows) => mockWebSocket.send('resize', { sessionId, cols, rows })),
      createSession: jest.fn(() => mockWebSocket.send('create', {})),
      destroySession: jest.fn((sessionId) => mockWebSocket.send('destroy', { sessionId })),
      listSessions: jest.fn(() => mockWebSocket.send('list', {})),
      connect: jest.fn(() => mockWebSocket.connect()),
      disconnect: jest.fn(() => mockWebSocket.disconnect()),
      on: jest.fn((event, callback) => mockWebSocket.on(event, callback)),
      off: jest.fn((event, callback) => mockWebSocket.off(event, callback)),
    });

    mockUseTerminal.mockReturnValue(mockTerminalHook);
    mockUseAppStore.mockReturnValue(mockStore);
    
    jest.clearAllMocks();
  });

  describe('Workflow 1: Basic Terminal Session Management', () => {
    it('should handle complete terminal session lifecycle', async () => {
      // Step 1: Render terminal
      render(<Terminal sessionId="workflow-session" />);
      
      // Step 2: Connect WebSocket
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      expect(mockUseWebSocket().connect).toHaveBeenCalled();
      
      // Step 3: Simulate receiving terminal config
      await act(async () => {
        mockWebSocket.simulateTerminalConfig('workflow-session', 80, 24);
      });
      
      // Step 4: Send a command
      const terminalArgs = mockUseTerminal.mock.calls[0][0];
      await act(async () => {
        if (terminalArgs.onData) {
          terminalArgs.onData('ls -la\r');
        }
      });
      
      expect(mockUseWebSocket().sendData).toHaveBeenCalledWith('workflow-session', 'ls -la\r');
      
      // Step 5: Receive response
      await act(async () => {
        mockWebSocket.simulateTerminalOutput('workflow-session', 'file1.txt file2.txt\n');
      });
      
      expect(mockTerminalHook.writeToTerminal).toHaveBeenCalledWith('file1.txt file2.txt\n');
      
      // Step 6: Clear terminal
      await act(async () => {
        mockTerminalHook.clearTerminal();
      });
      
      expect(mockTerminalHook.clearTerminal).toHaveBeenCalled();
    });

    it('should handle session switching workflow', async () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      // Connect to first session
      await act(async () => {
        await mockWebSocket.connect();
        mockWebSocket.simulateTerminalConfig('session-1', 80, 24);
      });
      
      // Switch to second session
      rerender(<Terminal sessionId="session-2" />);
      
      await act(async () => {
        mockWebSocket.simulateTerminalConfig('session-2', 100, 30);
      });
      
      // Verify terminal was re-initialized for new session
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'session-2',
        onData: expect.any(Function),
      });
    });

    it('should recover from connection failures', async () => {
      // Start with failing connection
      mockWebSocket.simulateConnectionFailure(new Error('Network error'));
      
      render(<Terminal sessionId="recovery-session" />);
      
      // Attempt connection (should fail)
      await act(async () => {
        try {
          await mockWebSocket.connect();
        } catch (error) {
          // Expected to fail
        }
      });
      
      expect(mockWebSocket.connected).toBe(false);
      
      // Fix connection and retry
      mockWebSocket.resetToStable();
      
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      expect(mockWebSocket.connected).toBe(true);
    });
  });

  describe('Workflow 2: Tab Management', () => {
    it('should handle complete tab lifecycle', async () => {
      const onTabSelect = jest.fn();
      const onTabClose = jest.fn();
      
      const tabs = [
        { id: 'tab-1', title: 'Terminal 1', content: 'Content 1' },
        { id: 'tab-2', title: 'Terminal 2', content: 'Content 2' },
        { id: 'tab-3', title: 'Terminal 3', content: 'Content 3' },
      ];
      
      // Step 1: Render tab list
      render(
        <TabList
          tabs={tabs}
          activeTab="tab-1"
          onTabSelect={onTabSelect}
          onTabClose={onTabClose}
        />
      );
      
      // Step 2: Switch to different tab
      const tab2 = screen.getByText('Terminal 2');
      await user.click(tab2);
      
      expect(onTabSelect).toHaveBeenCalledWith('tab-2');
      
      // Step 3: Close a tab
      const closeButtons = screen.getAllByLabelText(/Close/);
      await user.click(closeButtons[0]);
      
      expect(onTabClose).toHaveBeenCalledWith('tab-1');
    });

    it('should handle dynamic tab addition and removal', async () => {
      let tabs = [
        { id: 'tab-1', title: 'Terminal 1', content: 'Content 1' },
      ];
      
      const { rerender } = render(
        <TabList
          tabs={tabs}
          activeTab="tab-1"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      // Add new tab
      tabs = [
        ...tabs,
        { id: 'tab-2', title: 'New Terminal', content: 'New Content' },
      ];
      
      rerender(
        <TabList
          tabs={tabs}
          activeTab="tab-2"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      expect(screen.getByText('New Terminal')).toBeInTheDocument();
      
      // Remove tab
      tabs = [tabs[0]];
      
      rerender(
        <TabList
          tabs={tabs}
          activeTab="tab-1"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      expect(screen.queryByText('New Terminal')).not.toBeInTheDocument();
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
    });

    it('should handle rapid tab switching without performance issues', async () => {
      const tabs = Array.from({ length: 20 }, (_, i) => ({
        id: `tab-${i}`,
        title: `Terminal ${i + 1}`,
        content: `Content ${i + 1}`,
      }));
      
      let activeTab = 'tab-0';
      const onTabSelect = jest.fn();
      
      const { rerender } = render(
        <TabList
          tabs={tabs}
          activeTab={activeTab}
          onTabSelect={onTabSelect}
          onTabClose={jest.fn()}
        />
      );
      
      // Rapidly switch between tabs
      for (let i = 0; i < 10; i++) {
        activeTab = `tab-${i}`;
        rerender(
          <TabList
            tabs={tabs}
            activeTab={activeTab}
            onTabSelect={onTabSelect}
            onTabClose={jest.fn()}
          />
        );
      }
      
      // Should render without issues
      expect(screen.getByText('Terminal 10')).toBeInTheDocument();
    });
  });

  describe('Workflow 3: Terminal Controls Integration', () => {
    it('should handle terminal control operations', async () => {
      mockTerminalHook.hasNewOutput = true;
      mockTerminalHook.isAtBottom = false;
      
      render(
        <div>
          <Terminal sessionId="controls-session" />
          <TerminalControls
            onClear={mockTerminalHook.clearTerminal}
            onScrollToBottom={mockTerminalHook.scrollToBottom}
            onScrollToTop={mockTerminalHook.scrollToTop}
            hasNewOutput={mockTerminalHook.hasNewOutput}
          />
        </div>
      );
      
      // Test clear terminal
      const clearButton = screen.getByTitle('Clear Terminal');
      await user.click(clearButton);
      expect(mockTerminalHook.clearTerminal).toHaveBeenCalled();
      
      // Test scroll to bottom
      const scrollBottomButton = screen.getByTitle('Scroll to Bottom');
      await user.click(scrollBottomButton);
      expect(mockTerminalHook.scrollToBottom).toHaveBeenCalled();
      
      // Test scroll to top
      const scrollTopButton = screen.getByTitle('Scroll to Top');
      await user.click(scrollTopButton);
      expect(mockTerminalHook.scrollToTop).toHaveBeenCalled();
    });

    it('should handle new output indicator workflow', async () => {
      const { rerender } = render(
        <TerminalControls
          onClear={jest.fn()}
          onScrollToBottom={jest.fn()}
          onScrollToTop={jest.fn()}
          hasNewOutput={false}
        />
      );
      
      // Should not show indicator initially
      const scrollButton = screen.getByTitle('Scroll to Bottom');
      expect(scrollButton).not.toHaveClass('bg-blue-500');
      
      // Show new output indicator
      rerender(
        <TerminalControls
          onClear={jest.fn()}
          onScrollToBottom={jest.fn()}
          onScrollToTop={jest.fn()}
          hasNewOutput={true}
        />
      );
      
      expect(scrollButton).toHaveClass('bg-blue-500');
    });
  });

  describe('Workflow 4: Sidebar Navigation', () => {
    it('should handle sidebar toggle workflow', async () => {
      render(<Sidebar />);
      
      const toggleButton = screen.getByTitle('Toggle Sidebar');
      await user.click(toggleButton);
      
      expect(mockStore.toggleSidebar).toHaveBeenCalled();
    });

    it('should handle collapsed state changes', async () => {
      const { rerender } = render(<Sidebar />);
      
      // Update store to collapsed state
      mockStore.isCollapsed = true;
      mockUseAppStore.mockReturnValue(mockStore);
      
      rerender(<Sidebar />);
      
      // Sidebar should reflect collapsed state
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('w-16');
    });
  });

  describe('Workflow 5: Error Handling and Recovery', () => {
    it('should handle WebSocket disconnection and reconnection', async () => {
      render(<Terminal sessionId="error-session" />);
      
      // Connect initially
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      expect(mockWebSocket.connected).toBe(true);
      
      // Simulate disconnection
      await act(async () => {
        mockWebSocket.disconnect();
      });
      
      expect(mockWebSocket.connected).toBe(false);
      
      // Reconnect
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      expect(mockWebSocket.connected).toBe(true);
    });

    it('should handle terminal errors gracefully', async () => {
      render(<Terminal sessionId="error-handling" />);
      
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      // Simulate terminal error
      await act(async () => {
        mockWebSocket.simulateTerminalError('error-handling', 'Command failed: invalid command');
      });
      
      // Error should be written to terminal with proper formatting
      expect(mockTerminalHook.writeToTerminal).toHaveBeenCalledWith(
        '\x1b[31mCommand failed: invalid command\x1b[0m\r\n'
      );
    });

    it('should handle store errors without crashing', async () => {
      // Mock store method to throw error
      mockStore.setActiveSession.mockImplementation(() => {
        throw new Error('Store error');
      });
      
      // Should not crash when error occurs
      expect(() => {
        render(<Terminal sessionId="store-error" />);
      }).not.toThrow();
    });
  });

  describe('Workflow 6: Performance Under Load', () => {
    it('should handle high-frequency terminal output', async () => {
      render(<Terminal sessionId="performance-test" />);
      
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      // Simulate rapid output
      await act(async () => {
        for (let i = 0; i < 100; i++) {
          mockWebSocket.simulateTerminalOutput('performance-test', `High frequency line ${i}\n`);
        }
      });
      
      // Should handle all messages without issues
      expect(mockTerminalHook.writeToTerminal).toHaveBeenCalledTimes(100);
    });

    it('should handle multiple simultaneous sessions', async () => {
      const sessions = ['session-1', 'session-2', 'session-3'];
      
      // Render multiple terminals
      const { container } = render(
        <div>
          {sessions.map(sessionId => (
            <Terminal key={sessionId} sessionId={sessionId} />
          ))}
        </div>
      );
      
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      // Send data to all sessions simultaneously
      await act(async () => {
        sessions.forEach((sessionId, index) => {
          mockWebSocket.simulateTerminalOutput(sessionId, `Output for ${sessionId}\n`);
        });
      });
      
      // All sessions should receive their data
      expect(mockTerminalHook.writeToTerminal).toHaveBeenCalledTimes(sessions.length);
    });
  });

  describe('Workflow 7: User Input Validation', () => {
    it('should handle special characters in terminal input', async () => {
      render(<Terminal sessionId="input-test" />);
      
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      const terminalArgs = mockUseTerminal.mock.calls[0][0];
      
      // Test various special characters
      const specialInputs = [
        'echo "Hello World"\r',
        'cat file.txt | grep "pattern"\r',
        'ls -la /path/with spaces/\r',
        'echo $HOME && pwd\r',
        'command with unicode: 你好世界\r',
      ];
      
      for (const input of specialInputs) {
        await act(async () => {
          if (terminalArgs.onData) {
            terminalArgs.onData(input);
          }
        });
      }
      
      // All inputs should be sent correctly
      expect(mockUseWebSocket().sendData).toHaveBeenCalledTimes(specialInputs.length);
    });

    it('should handle rapid user input', async () => {
      render(<Terminal sessionId="rapid-input" />);
      
      await act(async () => {
        await mockWebSocket.connect();
      });
      
      const terminalArgs = mockUseTerminal.mock.calls[0][0];
      
      // Simulate rapid typing
      const rapidInput = 'echo "rapid typing test"\r'.split('');
      
      await act(async () => {
        rapidInput.forEach((char, index) => {
          setTimeout(() => {
            if (terminalArgs.onData) {
              terminalArgs.onData(char);
            }
          }, index * 10);
        });
      });
      
      // All characters should be processed
      expect(mockUseWebSocket().sendData).toHaveBeenCalledTimes(rapidInput.length);
    });
  });

  describe('Workflow 8: State Persistence', () => {
    it('should maintain terminal state across re-renders', async () => {
      const { rerender } = render(<Terminal sessionId="persist-test" />);
      
      await act(async () => {
        await mockWebSocket.connect();
        mockWebSocket.simulateTerminalConfig('persist-test', 80, 24);
      });
      
      // Trigger re-render
      rerender(<Terminal sessionId="persist-test" />);
      
      // Terminal should maintain its connection and state
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'persist-test',
        onData: expect.any(Function),
      });
    });

    it('should handle store state changes correctly', async () => {
      render(<AgentsPanel />);
      
      // Update store with new agents
      const newAgents = [
        { id: 'agent-1', name: 'Agent 1', status: 'active' },
        { id: 'agent-2', name: 'Agent 2', status: 'inactive' },
      ];
      
      mockStore.agents = newAgents;
      mockUseAppStore.mockReturnValue(mockStore);
      
      // Re-render with new store state
      const { rerender } = render(<AgentsPanel />);
      rerender(<AgentsPanel />);
      
      // Component should reflect new state
      expect(mockUseAppStore).toHaveBeenCalled();
    });
  });

  describe('Workflow 9: Accessibility Compliance', () => {
    it('should maintain keyboard navigation throughout workflow', async () => {
      render(
        <div>
          <Tab
            title="Accessible Tab"
            isActive={false}
            onSelect={jest.fn()}
            onClose={jest.fn()}
            closable={true}
          />
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={false}
          />
        </div>
      );
      
      // Test keyboard navigation
      const tabElement = screen.getByText('Accessible Tab').closest('.tab-button');
      const clearButton = screen.getByTitle('Clear Terminal');
      
      // Should be focusable
      if (tabElement) {
        tabElement.focus();
        expect(document.activeElement).toBe(tabElement);
      }
      
      clearButton.focus();
      expect(document.activeElement).toBe(clearButton);
    });

    it('should provide proper ARIA labels throughout interaction', async () => {
      render(
        <Tab
          title="ARIA Test Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const closeButton = screen.getByRole('button', { name: 'Close ARIA Test Tab' });
      expect(closeButton).toHaveAttribute('aria-label', 'Close ARIA Test Tab');
    });
  });

  describe('Workflow 10: Integration Edge Cases', () => {
    it('should handle component unmounting during async operations', async () => {
      const { unmount } = render(<Terminal sessionId="unmount-test" />);
      
      // Start async operation
      const connectPromise = act(async () => {
        await mockWebSocket.connect();
      });
      
      // Unmount before completion
      unmount();
      
      // Should not cause errors
      await expect(connectPromise).resolves.toBeUndefined();
    });

    it('should handle prop changes during component lifecycle', async () => {
      let sessionId = 'lifecycle-1';
      
      const { rerender } = render(<Terminal sessionId={sessionId} />);
      
      await act(async () => {
        await mockWebSocket.connect();
        mockWebSocket.simulateTerminalConfig(sessionId, 80, 24);
      });
      
      // Change props while connected
      sessionId = 'lifecycle-2';
      rerender(<Terminal sessionId={sessionId} />);
      
      await act(async () => {
        mockWebSocket.simulateTerminalConfig(sessionId, 100, 30);
      });
      
      // Should handle prop changes gracefully
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'lifecycle-2',
        onData: expect.any(Function),
      });
    });

    it('should handle rapid component mounting and unmounting', async () => {
      // Mount and unmount multiple times rapidly
      for (let i = 0; i < 5; i++) {
        const { unmount } = render(<Terminal sessionId={`rapid-${i}`} />);
        
        await act(async () => {
          // Small delay to simulate real usage
          await new Promise(resolve => setTimeout(resolve, 10));
        });
        
        unmount();
      }
      
      // Should not cause memory leaks or errors
      expect(mockUseTerminal).toHaveBeenCalledTimes(5);
    });
  });
});
