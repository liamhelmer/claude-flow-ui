/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import React from 'react';

// Import components to test
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { Tab } from '@/components/tabs/Tab';
import { Terminal } from '@/components/terminal/Terminal';
import { TerminalControls } from '@/components/terminal/TerminalControls';
import { AgentsPanel } from '@/components/monitoring/AgentsPanel';
import { MemoryPanel } from '@/components/monitoring/MemoryPanel';
import { CommandsPanel } from '@/components/monitoring/CommandsPanel';
import { PromptPanel } from '@/components/monitoring/PromptPanel';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

// Mock dependencies
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => ({
    terminalRef: { current: null },
    terminal: null,
    writeToTerminal: jest.fn(),
    clearTerminal: jest.fn(),
    focusTerminal: jest.fn(),
    fitTerminal: jest.fn(),
    isConnected: true,
    isAtBottom: true,
    hasNewOutput: false,
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
  }),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    isConnected: true,
    on: jest.fn(),
    off: jest.fn(),
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({
    sessions: [],
    activeSession: null,
    isLoading: false,
    error: null,
    agents: [],
    memory: { usage: 50, limit: 100 },
    commands: [],
    prompts: [],
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
  }),
}));

// Mock xterm
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
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
  })),
}));

describe('Comprehensive Accessibility Tests', () => {
  describe('Sidebar Component', () => {
    const mockSessions = [
      { id: '1', name: 'Session 1', status: 'active' },
      { id: '2', name: 'Session 2', status: 'inactive' },
    ];

    test('should have no accessibility violations', async () => {
      const { container } = render(
        <Sidebar 
          sessions={mockSessions}
          activeSessionId="1"
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    test('should have proper ARIA labels and roles', () => {
      render(
        <Sidebar 
          sessions={mockSessions}
          activeSessionId="1"
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      // Check for proper navigation landmarks
      const navigation = screen.getByRole('navigation', { name: /sessions/i });
      expect(navigation).toBeInTheDocument();

      // Check for proper list structure
      const sessionList = screen.getByRole('list');
      expect(sessionList).toBeInTheDocument();

      // Check for proper button labels
      const newSessionButton = screen.getByRole('button', { name: /new session/i });
      expect(newSessionButton).toBeInTheDocument();
    });

    test('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      const mockOnSessionSelect = jest.fn();

      render(
        <Sidebar 
          sessions={mockSessions}
          activeSessionId="1"
          onSessionSelect={mockOnSessionSelect}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const firstSession = screen.getAllByRole('button')[0];
      
      // Test keyboard navigation
      await user.tab();
      expect(firstSession).toHaveFocus();

      await user.keyboard('{Enter}');
      expect(mockOnSessionSelect).toHaveBeenCalled();
    });

    test('should have proper focus management', async () => {
      const user = userEvent.setup();
      
      render(
        <Sidebar 
          sessions={mockSessions}
          activeSessionId="1"
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      // Test tab order
      await user.tab();
      const focusedElement = document.activeElement;
      expect(focusedElement).toBeVisible();
      expect(focusedElement?.getAttribute('role')).toBe('button');
    });

    test('should provide proper screen reader announcements', () => {
      render(
        <Sidebar 
          sessions={mockSessions}
          activeSessionId="1"
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      // Check for aria-current on active session
      const activeSession = screen.getByText('Session 1').closest('button');
      expect(activeSession).toHaveAttribute('aria-current', 'page');
    });
  });

  describe('TabList Component', () => {
    const mockTabs = [
      { id: 'terminal', title: 'Terminal', isActive: true },
      { id: 'monitoring', title: 'Monitoring', isActive: false },
    ];

    test('should have no accessibility violations', async () => {
      const { container } = render(
        <TabList 
          tabs={mockTabs}
          onTabChange={jest.fn()}
        />
      );

      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    test('should implement proper ARIA tablist pattern', () => {
      render(
        <TabList 
          tabs={mockTabs}
          onTabChange={jest.fn()}
        />
      );

      // Check tablist role
      const tablist = screen.getByRole('tablist');
      expect(tablist).toBeInTheDocument();

      // Check tab roles
      const tabs = screen.getAllByRole('tab');
      expect(tabs).toHaveLength(2);

      // Check aria-selected
      expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
      expect(tabs[1]).toHaveAttribute('aria-selected', 'false');
    });

    test('should support arrow key navigation', async () => {
      const user = userEvent.setup();
      const mockOnTabChange = jest.fn();

      render(
        <TabList 
          tabs={mockTabs}
          onTabChange={mockOnTabChange}
        />
      );

      const firstTab = screen.getAllByRole('tab')[0];
      firstTab.focus();

      // Test arrow key navigation
      await user.keyboard('{ArrowRight}');
      expect(document.activeElement).toBe(screen.getAllByRole('tab')[1]);

      await user.keyboard('{ArrowLeft}');
      expect(document.activeElement).toBe(firstTab);
    });

    test('should support Home/End key navigation', async () => {
      const user = userEvent.setup();

      render(
        <TabList 
          tabs={mockTabs}
          onTabChange={jest.fn()}
        />
      );

      const firstTab = screen.getAllByRole('tab')[0];
      const lastTab = screen.getAllByRole('tab')[1];

      firstTab.focus();

      await user.keyboard('{End}');
      expect(document.activeElement).toBe(lastTab);

      await user.keyboard('{Home}');
      expect(document.activeElement).toBe(firstTab);
    });
  });

  describe('Terminal Component', () => {
    test('should have no accessibility violations', async () => {
      const { container } = render(
        <Terminal sessionId="test-session" />
      );

      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    test('should have proper terminal labeling', () => {
      render(<Terminal sessionId="test-session" />);

      // Should have proper application role for terminal
      const terminal = screen.getByRole('application', { name: /terminal/i });
      expect(terminal).toBeInTheDocument();
    });

    test('should provide screen reader announcements for connection status', () => {
      render(<Terminal sessionId="test-session" />);

      // Check for status announcements
      const statusRegion = screen.getByRole('status');
      expect(statusRegion).toBeInTheDocument();
    });
  });

  describe('TerminalControls Component', () => {
    test('should have no accessibility violations', async () => {
      const { container } = render(
        <TerminalControls 
          onClear={jest.fn()}
          onReconnect={jest.fn()}
          onScrollTop={jest.fn()}
          onScrollBottom={jest.fn()}
          isConnected={true}
          hasNewOutput={false}
          isAtBottom={true}
        />
      );

      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    test('should have proper button labels and descriptions', () => {
      render(
        <TerminalControls 
          onClear={jest.fn()}
          onReconnect={jest.fn()}
          onScrollTop={jest.fn()}
          onScrollBottom={jest.fn()}
          isConnected={true}
          hasNewOutput={false}
          isAtBottom={true}
        />
      );

      // Check for descriptive button labels
      expect(screen.getByRole('button', { name: /clear terminal/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /scroll to top/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /scroll to bottom/i })).toBeInTheDocument();
    });

    test('should provide connection status information', () => {
      render(
        <TerminalControls 
          onClear={jest.fn()}
          onReconnect={jest.fn()}
          onScrollTop={jest.fn()}
          onScrollBottom={jest.fn()}
          isConnected={false}
          hasNewOutput={false}
          isAtBottom={true}
        />
      );

      // Should indicate disconnected state
      const reconnectButton = screen.getByRole('button', { name: /reconnect/i });
      expect(reconnectButton).toBeInTheDocument();
    });

    test('should support keyboard interaction', async () => {
      const user = userEvent.setup();
      const mockOnClear = jest.fn();

      render(
        <TerminalControls 
          onClear={mockOnClear}
          onReconnect={jest.fn()}
          onScrollTop={jest.fn()}
          onScrollBottom={jest.fn()}
          isConnected={true}
          hasNewOutput={false}
          isAtBottom={true}
        />
      );

      const clearButton = screen.getByRole('button', { name: /clear/i });
      
      await user.tab();
      expect(clearButton).toHaveFocus();

      await user.keyboard('{Enter}');
      expect(mockOnClear).toHaveBeenCalled();
    });
  });

  describe('Monitoring Components', () => {
    describe('AgentsPanel', () => {
      test('should have no accessibility violations', async () => {
        const mockAgents = [
          { id: '1', name: 'Agent 1', status: 'active', type: 'coder' },
          { id: '2', name: 'Agent 2', status: 'idle', type: 'reviewer' },
        ];

        const { container } = render(<AgentsPanel agents={mockAgents} />);

        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      test('should provide proper agent status information', () => {
        const mockAgents = [
          { id: '1', name: 'Agent 1', status: 'active', type: 'coder' },
        ];

        render(<AgentsPanel agents={mockAgents} />);

        // Should provide status information
        const agentStatus = screen.getByText(/active/i);
        expect(agentStatus).toBeInTheDocument();
        expect(agentStatus).toHaveAttribute('aria-label', expect.stringMatching(/agent.*status/i));
      });
    });

    describe('MemoryPanel', () => {
      test('should have no accessibility violations', async () => {
        const mockMemoryData = {
          usage: 50,
          limit: 100,
          items: [
            { key: 'session-1', size: 25, type: 'session' },
            { key: 'cache-1', size: 15, type: 'cache' },
          ]
        };

        const { container } = render(<MemoryPanel data={mockMemoryData} />);

        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      test('should provide memory usage as accessible progress bar', () => {
        const mockMemoryData = {
          usage: 75,
          limit: 100,
          items: []
        };

        render(<MemoryPanel data={mockMemoryData} />);

        const progressBar = screen.getByRole('progressbar');
        expect(progressBar).toBeInTheDocument();
        expect(progressBar).toHaveAttribute('aria-valuenow', '75');
        expect(progressBar).toHaveAttribute('aria-valuemax', '100');
        expect(progressBar).toHaveAttribute('aria-label', expect.stringMatching(/memory usage/i));
      });
    });

    describe('CommandsPanel', () => {
      test('should have no accessibility violations', async () => {
        const mockCommands = [
          { id: '1', command: 'npm start', timestamp: Date.now(), status: 'success' },
          { id: '2', command: 'npm test', timestamp: Date.now() - 1000, status: 'running' },
        ];

        const { container } = render(<CommandsPanel commands={mockCommands} />);

        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      test('should provide command history as accessible list', () => {
        const mockCommands = [
          { id: '1', command: 'npm start', timestamp: Date.now(), status: 'success' },
        ];

        render(<CommandsPanel commands={mockCommands} />);

        const commandList = screen.getByRole('list');
        expect(commandList).toBeInTheDocument();
        expect(commandList).toHaveAttribute('aria-label', expect.stringMatching(/command history/i));

        const commandItems = screen.getAllByRole('listitem');
        expect(commandItems).toHaveLength(1);
      });
    });

    describe('PromptPanel', () => {
      test('should have no accessibility violations', async () => {
        const mockPrompts = [
          { id: '1', text: 'Hello AI', response: 'Hello Human', timestamp: Date.now() },
        ];

        const { container } = render(<PromptPanel prompts={mockPrompts} />);

        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      test('should provide conversation as accessible chat log', () => {
        const mockPrompts = [
          { id: '1', text: 'Hello AI', response: 'Hello Human', timestamp: Date.now() },
        ];

        render(<PromptPanel prompts={mockPrompts} />);

        const chatLog = screen.getByRole('log');
        expect(chatLog).toBeInTheDocument();
        expect(chatLog).toHaveAttribute('aria-label', expect.stringMatching(/conversation/i));
      });
    });
  });

  describe('Color Contrast and Visual Accessibility', () => {
    test('should meet WCAG color contrast requirements', async () => {
      const { container } = render(
        <div className="bg-gray-900 text-white p-4">
          <button className="bg-blue-600 text-white px-4 py-2 rounded">
            Test Button
          </button>
        </div>
      );

      const results = await axe(container, {
        rules: {
          'color-contrast': { enabled: true },
        },
      });

      expect(results).toHaveNoViolations();
    });

    test('should not rely solely on color for information', () => {
      render(
        <div>
          <span className="text-red-500" aria-label="Error: Invalid input">
            ⚠️ Invalid input
          </span>
          <span className="text-green-500" aria-label="Success: Operation completed">
            ✅ Success
          </span>
        </div>
      );

      // Icons and text provide information beyond just color
      expect(screen.getByLabelText(/error/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/success/i)).toBeInTheDocument();
    });
  });

  describe('Focus Management', () => {
    test('should manage focus properly on modal open/close', async () => {
      const user = userEvent.setup();

      const ModalComponent = () => {
        const [isOpen, setIsOpen] = React.useState(false);

        return (
          <div>
            <button onClick={() => setIsOpen(true)}>Open Modal</button>
            {isOpen && (
              <div
                role="dialog"
                aria-modal="true"
                aria-labelledby="modal-title"
              >
                <h2 id="modal-title">Modal Title</h2>
                <button onClick={() => setIsOpen(false)}>Close</button>
              </div>
            )}
          </div>
        );
      };

      render(<ModalComponent />);

      const openButton = screen.getByText('Open Modal');
      await user.click(openButton);

      // Focus should move to modal
      const modal = screen.getByRole('dialog');
      expect(modal).toBeInTheDocument();

      const closeButton = screen.getByText('Close');
      await user.click(closeButton);

      // Focus should return to trigger button
      expect(openButton).toHaveFocus();
    });

    test('should trap focus within modal dialogs', async () => {
      const user = userEvent.setup();

      const ModalComponent = () => (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-title"
        >
          <h2 id="modal-title">Modal Title</h2>
          <button>First Button</button>
          <button>Last Button</button>
        </div>
      );

      render(<ModalComponent />);

      const firstButton = screen.getByText('First Button');
      const lastButton = screen.getByText('Last Button');

      firstButton.focus();
      
      // Tab should cycle within modal
      await user.tab();
      expect(lastButton).toHaveFocus();

      await user.tab();
      expect(firstButton).toHaveFocus();
    });
  });

  describe('Screen Reader Support', () => {
    test('should provide live regions for dynamic content', () => {
      const LiveRegionComponent = ({ status }: { status: string }) => (
        <div>
          <div aria-live="polite" aria-atomic="true">
            Status: {status}
          </div>
          <div aria-live="assertive">
            {status === 'error' && 'Critical error occurred!'}
          </div>
        </div>
      );

      const { rerender } = render(<LiveRegionComponent status="idle" />);

      const politeRegion = screen.getByText(/status: idle/i);
      expect(politeRegion).toHaveAttribute('aria-live', 'polite');

      rerender(<LiveRegionComponent status="error" />);

      const assertiveRegion = screen.getByText(/critical error/i);
      expect(assertiveRegion).toHaveAttribute('aria-live', 'assertive');
    });

    test('should provide proper form labels and descriptions', () => {
      render(
        <form>
          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            aria-describedby="username-help"
            required
          />
          <div id="username-help">
            Enter your username (3-20 characters)
          </div>
          
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            aria-describedby="password-help"
            required
          />
          <div id="password-help">
            Password must be at least 8 characters
          </div>
        </form>
      );

      const usernameInput = screen.getByLabelText(/username/i);
      expect(usernameInput).toHaveAttribute('aria-describedby', 'username-help');
      expect(usernameInput).toHaveAttribute('required');

      const passwordInput = screen.getByLabelText(/password/i);
      expect(passwordInput).toHaveAttribute('aria-describedby', 'password-help');
    });
  });

  describe('High Contrast Mode Support', () => {
    test('should work properly in high contrast mode', async () => {
      // Simulate high contrast mode
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('forced-colors'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      const { container } = render(
        <button className="border border-current">
          High Contrast Button
        </button>
      );

      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Reduced Motion Support', () => {
    test('should respect prefers-reduced-motion', () => {
      // Mock reduced motion preference
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('prefers-reduced-motion'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      render(
        <div className="motion-reduce:animate-none animate-pulse">
          Animated Content
        </div>
      );

      // Component should render without animations when reduced motion is preferred
      expect(screen.getByText('Animated Content')).toBeInTheDocument();
    });
  });
});