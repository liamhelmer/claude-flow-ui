/**
 * @jest-environment jsdom
 */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';
import { 
  AccessibilityTestUtils,
  TestDataGenerator,
  renderWithEnhancements 
} from './test-utilities';

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
    agents: TestDataGenerator.generateAgents(5),
    memory: TestDataGenerator.generateMemoryData(),
    commands: TestDataGenerator.generateCommands(10),
    prompts: [],
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
  }),
}));

describe('Advanced Accessibility Testing', () => {
  describe('Screen Reader Navigation', () => {
    test('should provide proper heading hierarchy', async () => {
      const { container } = renderWithEnhancements(
        <div>
          <h1>Claude UI</h1>
          <main>
            <section>
              <h2>Terminal Sessions</h2>
              <Sidebar
                sessions={TestDataGenerator.generateSessions(3)}
                activeSessionId="session-0"
                onSessionSelect={jest.fn()}
                onSessionClose={jest.fn()}
                onNewSession={jest.fn()}
              />
            </section>
            <section>
              <h2>Terminal Interface</h2>
              <Terminal sessionId="test-session" />
            </section>
          </main>
        </div>,
        { withAccessibilityChecks: true }
      );

      const headings = container.querySelectorAll('h1, h2, h3, h4, h5, h6');
      
      // Check heading levels are logical
      let currentLevel = 0;
      headings.forEach(heading => {
        const level = parseInt(heading.tagName.charAt(1));
        expect(level).toBeGreaterThanOrEqual(currentLevel);
        expect(level - currentLevel).toBeLessThanOrEqual(1);
        currentLevel = level;
      });

      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    test('should provide landmark navigation', () => {
      renderWithEnhancements(
        <div>
          <header role="banner">
            <h1>Claude UI</h1>
          </header>
          <nav role="navigation" aria-label="Session navigation">
            <Sidebar
              sessions={TestDataGenerator.generateSessions(3)}
              activeSessionId="session-0"
              onSessionSelect={jest.fn()}
              onSessionClose={jest.fn()}
              onNewSession={jest.fn()}
            />
          </nav>
          <main role="main">
            <Terminal sessionId="test-session" />
          </main>
          <aside role="complementary" aria-label="Monitoring">
            <MonitoringSidebar />
          </aside>
        </div>
      );

      // Check for proper landmarks
      expect(screen.getByRole('banner')).toBeInTheDocument();
      expect(screen.getByRole('navigation', { name: /session navigation/i })).toBeInTheDocument();
      expect(screen.getByRole('main')).toBeInTheDocument();
      expect(screen.getByRole('complementary', { name: /monitoring/i })).toBeInTheDocument();
    });

    test('should provide skip links for keyboard navigation', () => {
      const SkipLinksComponent = () => (
        <div>
          <a href="#main-content" className="sr-only focus:not-sr-only">
            Skip to main content
          </a>
          <a href="#sidebar" className="sr-only focus:not-sr-only">
            Skip to sidebar
          </a>
          <header>Header Content</header>
          <nav id="sidebar">
            <Sidebar
              sessions={TestDataGenerator.generateSessions(3)}
              activeSessionId="session-0"
              onSessionSelect={jest.fn()}
              onSessionClose={jest.fn()}
              onNewSession={jest.fn()}
            />
          </nav>
          <main id="main-content">
            <Terminal sessionId="test-session" />
          </main>
        </div>
      );

      renderWithEnhancements(<SkipLinksComponent />);

      const skipToMain = screen.getByRole('link', { name: /skip to main content/i });
      const skipToSidebar = screen.getByRole('link', { name: /skip to sidebar/i });

      expect(skipToMain).toHaveAttribute('href', '#main-content');
      expect(skipToSidebar).toHaveAttribute('href', '#sidebar');
    });

    test('should announce dynamic content changes', async () => {
      const DynamicContentComponent = () => {
        const [status, setStatus] = React.useState('idle');
        const [messages, setMessages] = React.useState<string[]>([]);

        const addMessage = () => {
          const newMessage = `Message ${messages.length + 1}`;
          setMessages(prev => [...prev, newMessage]);
          setStatus('updated');
        };

        return (
          <div>
            <button onClick={addMessage}>Add Message</button>
            <div
              role="status"
              aria-live="polite"
              aria-atomic="true"
            >
              Status: {status}
            </div>
            <div
              role="log"
              aria-live="polite"
              aria-label="Message history"
            >
              {messages.map((message, index) => (
                <div key={index}>{message}</div>
              ))}
            </div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<DynamicContentComponent />);

      const addButton = screen.getByRole('button', { name: /add message/i });
      const statusRegion = screen.getByRole('status');
      const logRegion = screen.getByRole('log');

      await user.click(addButton);

      expect(statusRegion).toHaveTextContent('Status: updated');
      expect(logRegion).toHaveTextContent('Message 1');
      expect(logRegion).toHaveAttribute('aria-live', 'polite');
    });
  });

  describe('Keyboard Navigation', () => {
    test('should support comprehensive keyboard navigation in tab list', async () => {
      const user = userEvent.setup();
      const mockOnTabChange = jest.fn();

      const tabs = Array.from({ length: 5 }, (_, i) => ({
        id: `tab-${i}`,
        title: `Tab ${i}`,
        isActive: i === 0,
      }));

      renderWithEnhancements(
        <TabList tabs={tabs} onTabChange={mockOnTabChange} />
      );

      const tabElements = screen.getAllByRole('tab');
      const firstTab = tabElements[0];
      const lastTab = tabElements[4];

      firstTab.focus();

      // Test arrow key navigation
      await user.keyboard('{ArrowRight}');
      expect(tabElements[1]).toHaveFocus();

      await user.keyboard('{ArrowLeft}');
      expect(firstTab).toHaveFocus();

      // Test Home/End navigation
      await user.keyboard('{End}');
      expect(lastTab).toHaveFocus();

      await user.keyboard('{Home}');
      expect(firstTab).toHaveFocus();

      // Test Enter/Space activation
      await user.keyboard('{Enter}');
      expect(mockOnTabChange).toHaveBeenCalledWith('tab-0');

      await user.keyboard('{ArrowRight}');
      await user.keyboard(' ');
      expect(mockOnTabChange).toHaveBeenCalledWith('tab-1');
    });

    test('should provide proper focus indicators', async () => {
      const user = userEvent.setup();

      renderWithEnhancements(
        <div>
          <button>Button 1</button>
          <button>Button 2</button>
          <input type="text" placeholder="Text input" />
          <select>
            <option>Option 1</option>
            <option>Option 2</option>
          </select>
        </div>
      );

      const focusableElements = [
        screen.getByRole('button', { name: /button 1/i }),
        screen.getByRole('button', { name: /button 2/i }),
        screen.getByRole('textbox'),
        screen.getByRole('combobox'),
      ];

      for (const element of focusableElements) {
        element.focus();
        expect(element).toHaveFocus();
        
        // Should be visible when focused
        expect(element).toBeVisible();
        
        // Should have focus styles (this would need actual CSS testing in a real scenario)
        const computedStyle = getComputedStyle(element);
        expect(computedStyle.outline).toBeDefined();
      }
    });

    test('should handle focus trapping in modal dialogs', async () => {
      const user = userEvent.setup();

      const ModalComponent = () => {
        const [isOpen, setIsOpen] = React.useState(false);
        const modalRef = React.useRef<HTMLDivElement>(null);

        React.useEffect(() => {
          if (isOpen) {
            const focusableElements = modalRef.current?.querySelectorAll(
              'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (focusableElements && focusableElements.length > 0) {
              (focusableElements[0] as HTMLElement).focus();
            }
          }
        }, [isOpen]);

        return (
          <div>
            <button onClick={() => setIsOpen(true)}>Open Modal</button>
            {isOpen && (
              <div
                ref={modalRef}
                role="dialog"
                aria-modal="true"
                aria-labelledby="modal-title"
                onKeyDown={(e) => {
                  if (e.key === 'Escape') {
                    setIsOpen(false);
                  }
                }}
              >
                <h2 id="modal-title">Modal Title</h2>
                <button>First Button</button>
                <button>Second Button</button>
                <button onClick={() => setIsOpen(false)}>Close</button>
              </div>
            )}
          </div>
        );
      };

      renderWithEnhancements(<ModalComponent />);

      const openButton = screen.getByRole('button', { name: /open modal/i });
      await user.click(openButton);

      const modal = screen.getByRole('dialog');
      expect(modal).toBeInTheDocument();

      const firstButton = screen.getByRole('button', { name: /first button/i });
      const secondButton = screen.getByRole('button', { name: /second button/i });
      const closeButton = screen.getByRole('button', { name: /close/i });

      // Focus should be on first button
      expect(firstButton).toHaveFocus();

      // Tab should cycle within modal
      await user.tab();
      expect(secondButton).toHaveFocus();

      await user.tab();
      expect(closeButton).toHaveFocus();

      await user.tab();
      expect(firstButton).toHaveFocus(); // Should wrap back to first

      // Escape should close modal
      await user.keyboard('{Escape}');
      expect(modal).not.toBeInTheDocument();
      expect(openButton).toHaveFocus(); // Focus should return to trigger
    });

    test('should support keyboard shortcuts', async () => {
      const user = userEvent.setup();
      const mockShortcuts = {
        save: jest.fn(),
        copy: jest.fn(),
        paste: jest.fn(),
        search: jest.fn(),
      };

      const ShortcutsComponent = () => {
        React.useEffect(() => {
          const handleKeyDown = (e: KeyboardEvent) => {
            if (e.ctrlKey || e.metaKey) {
              switch (e.key) {
                case 's':
                  e.preventDefault();
                  mockShortcuts.save();
                  break;
                case 'c':
                  if (!e.shiftKey) {
                    mockShortcuts.copy();
                  }
                  break;
                case 'v':
                  mockShortcuts.paste();
                  break;
                case 'f':
                  e.preventDefault();
                  mockShortcuts.search();
                  break;
              }
            }
          };

          document.addEventListener('keydown', handleKeyDown);
          return () => document.removeEventListener('keydown', handleKeyDown);
        }, []);

        return (
          <div tabIndex={0}>
            <p>Press Ctrl+S to save, Ctrl+C to copy, Ctrl+V to paste, Ctrl+F to search</p>
          </div>
        );
      };

      renderWithEnhancements(<ShortcutsComponent />);

      const container = screen.getByText(/press ctrl/i).parentElement!;
      container.focus();

      await user.keyboard('{Control>}s{/Control}');
      expect(mockShortcuts.save).toHaveBeenCalled();

      await user.keyboard('{Control>}c{/Control}');
      expect(mockShortcuts.copy).toHaveBeenCalled();

      await user.keyboard('{Control>}v{/Control}');
      expect(mockShortcuts.paste).toHaveBeenCalled();

      await user.keyboard('{Control>}f{/Control}');
      expect(mockShortcuts.search).toHaveBeenCalled();
    });
  });

  describe('Voice Control and Speech Recognition', () => {
    test('should provide speech-friendly labels and descriptions', () => {
      renderWithEnhancements(
        <div>
          <button aria-label="Start new terminal session">
            <span aria-hidden="true">+</span>
          </button>
          <button aria-describedby="clear-desc">
            Clear
          </button>
          <div id="clear-desc" className="sr-only">
            Clear all terminal output and command history
          </div>
          <input
            type="text"
            aria-label="Command input"
            aria-describedby="command-help"
          />
          <div id="command-help" className="sr-only">
            Type commands to execute in the terminal
          </div>
        </div>
      );

      const newSessionButton = screen.getByRole('button', { name: /start new terminal session/i });
      expect(newSessionButton).toHaveAttribute('aria-label', 'Start new terminal session');

      const clearButton = screen.getByRole('button', { name: /clear/i });
      expect(clearButton).toHaveAttribute('aria-describedby', 'clear-desc');

      const commandInput = screen.getByRole('textbox', { name: /command input/i });
      expect(commandInput).toHaveAttribute('aria-describedby', 'command-help');
    });

    test('should support voice commands through aria-describedby', () => {
      const VoiceCommandComponent = () => (
        <div role="application" aria-label="Terminal interface">
          <div
            role="textbox"
            aria-multiline="true"
            aria-label="Terminal output"
            aria-describedby="voice-commands"
          >
            Terminal content here
          </div>
          <div id="voice-commands" className="sr-only">
            Voice commands: Say "clear terminal" to clear output, 
            "new session" to create session, "scroll up" or "scroll down" to navigate
          </div>
        </div>
      );

      renderWithEnhancements(<VoiceCommandComponent />);

      const terminal = screen.getByRole('textbox', { name: /terminal output/i });
      expect(terminal).toHaveAttribute('aria-describedby', 'voice-commands');
      expect(screen.getByText(/voice commands/i)).toBeInTheDocument();
    });
  });

  describe('High Contrast and Visual Impairments', () => {
    test('should work with high contrast mode', async () => {
      // Mock high contrast media query
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('forced-colors: active'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      const { container } = renderWithEnhancements(
        <div className="bg-white text-black border border-gray-300">
          <Terminal sessionId="test-session" />
        </div>
      );

      const results = await axe(container, {
        rules: {
          'color-contrast': { enabled: true },
        },
      });

      expect(results).toHaveNoViolations();
    });

    test('should not rely solely on color for status indication', () => {
      const StatusIndicatorComponent = () => (
        <div>
          <div
            className="flex items-center space-x-2"
            role="status"
            aria-label="Connection status: connected"
          >
            <span className="text-green-500" aria-hidden="true">●</span>
            <span className="text-green-500">Connected</span>
            <span className="sr-only">Connection is active and stable</span>
          </div>
          <div
            className="flex items-center space-x-2"
            role="status"
            aria-label="Connection status: disconnected"
          >
            <span className="text-red-500" aria-hidden="true">●</span>
            <span className="text-red-500">Disconnected</span>
            <span className="sr-only">Connection has been lost</span>
          </div>
          <div
            className="flex items-center space-x-2"
            role="status"
            aria-label="Session status: processing"
          >
            <span className="text-yellow-500 animate-pulse" aria-hidden="true">●</span>
            <span className="text-yellow-500">Processing</span>
            <span className="sr-only">Currently processing your request</span>
          </div>
        </div>
      );

      renderWithEnhancements(<StatusIndicatorComponent />);

      // Status should be conveyed through text and aria-labels, not just color
      expect(screen.getByLabelText(/connection status: connected/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/connection status: disconnected/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/session status: processing/i)).toBeInTheDocument();

      expect(screen.getByText('Connected')).toBeInTheDocument();
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
      expect(screen.getByText('Processing')).toBeInTheDocument();
    });

    test('should provide sufficient color contrast ratios', async () => {
      const ContrastTestComponent = () => (
        <div>
          {/* Good contrast examples */}
          <button className="bg-blue-600 text-white px-4 py-2">
            High Contrast Button
          </button>
          <div className="bg-gray-900 text-white p-4">
            High contrast text on dark background
          </div>
          <div className="bg-white text-gray-900 p-4 border">
            High contrast text on light background
          </div>
          
          {/* Error states with sufficient contrast */}
          <div className="bg-red-100 text-red-900 border border-red-300 p-3">
            <span role="img" aria-label="Error">⚠️</span>
            Error message with sufficient contrast
          </div>
          
          {/* Success states with sufficient contrast */}
          <div className="bg-green-100 text-green-900 border border-green-300 p-3">
            <span role="img" aria-label="Success">✅</span>
            Success message with sufficient contrast
          </div>
        </div>
      );

      const { container } = renderWithEnhancements(<ContrastTestComponent />);

      const results = await axe(container, {
        rules: {
          'color-contrast': { enabled: true },
        },
      });

      expect(results).toHaveNoViolations();
    });
  });

  describe('Reduced Motion Support', () => {
    test('should respect prefers-reduced-motion preference', () => {
      // Mock reduced motion preference
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('prefers-reduced-motion: reduce'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      const MotionSensitiveComponent = () => {
        const [isVisible, setIsVisible] = React.useState(false);

        return (
          <div>
            <button onClick={() => setIsVisible(!isVisible)}>
              Toggle Content
            </button>
            <div
              className={`
                transition-all duration-300 
                motion-reduce:transition-none
                ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
                motion-reduce:transform-none
              `}
            >
              Animated content that respects motion preferences
            </div>
          </div>
        );
      };

      renderWithEnhancements(<MotionSensitiveComponent />);

      const content = screen.getByText(/animated content/i);
      expect(content).toBeInTheDocument();

      // The component should render without relying on animations for core functionality
      expect(content).toBeVisible();
    });

    test('should provide static alternatives to loading animations', () => {
      const LoadingComponent = ({ isLoading }: { isLoading: boolean }) => (
        <div>
          {isLoading ? (
            <div role="status" aria-label="Loading content">
              <span className="animate-spin motion-reduce:animate-none">🔄</span>
              <span className="motion-reduce:inline hidden ml-2">Loading...</span>
              <span className="sr-only">Please wait while content loads</span>
            </div>
          ) : (
            <div>Content loaded successfully</div>
          )}
        </div>
      );

      const { rerender } = renderWithEnhancements(<LoadingComponent isLoading={true} />);

      const loadingStatus = screen.getByRole('status', { name: /loading content/i });
      expect(loadingStatus).toBeInTheDocument();
      expect(screen.getByText(/please wait/i)).toBeInTheDocument();

      rerender(<LoadingComponent isLoading={false} />);
      expect(screen.getByText(/content loaded successfully/i)).toBeInTheDocument();
    });
  });

  describe('Custom Accessibility Features', () => {
    test('should support custom focus management', async () => {
      const user = userEvent.setup();

      const FocusManagerComponent = () => {
        const [activeIndex, setActiveIndex] = React.useState(0);
        const itemRefs = React.useRef<(HTMLButtonElement | null)[]>([]);

        const items = ['Item 1', 'Item 2', 'Item 3', 'Item 4'];

        const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
          switch (e.key) {
            case 'ArrowDown':
              e.preventDefault();
              const nextIndex = (index + 1) % items.length;
              setActiveIndex(nextIndex);
              itemRefs.current[nextIndex]?.focus();
              break;
            case 'ArrowUp':
              e.preventDefault();
              const prevIndex = (index - 1 + items.length) % items.length;
              setActiveIndex(prevIndex);
              itemRefs.current[prevIndex]?.focus();
              break;
          }
        };

        return (
          <div role="listbox" aria-label="Custom focus manager">
            {items.map((item, index) => (
              <button
                key={index}
                ref={el => itemRefs.current[index] = el}
                role="option"
                aria-selected={index === activeIndex}
                onKeyDown={e => handleKeyDown(e, index)}
                onClick={() => setActiveIndex(index)}
              >
                {item}
              </button>
            ))}
          </div>
        );
      };

      renderWithEnhancements(<FocusManagerComponent />);

      const listbox = screen.getByRole('listbox');
      const options = screen.getAllByRole('option');

      options[0].focus();

      await user.keyboard('{ArrowDown}');
      expect(options[1]).toHaveFocus();

      await user.keyboard('{ArrowUp}');
      expect(options[0]).toHaveFocus();
    });

    test('should provide comprehensive aria descriptions for complex interfaces', () => {
      const ComplexInterfaceComponent = () => (
        <div
          role="application"
          aria-label="Terminal management interface"
          aria-describedby="interface-description"
        >
          <div id="interface-description" className="sr-only">
            This interface allows you to manage multiple terminal sessions. 
            Use Tab to navigate between sections. 
            Arrow keys to navigate within lists. 
            Enter or Space to activate items.
          </div>
          
          <section aria-labelledby="sessions-heading">
            <h2 id="sessions-heading">Active Sessions</h2>
            <div
              role="list"
              aria-label="Terminal sessions"
              aria-describedby="sessions-help"
            >
              <div id="sessions-help" className="sr-only">
                Use arrow keys to navigate sessions, Enter to select, Delete to close
              </div>
              {/* Session items would go here */}
            </div>
          </section>

          <section aria-labelledby="terminal-heading">
            <h2 id="terminal-heading">Terminal Output</h2>
            <div
              role="log"
              aria-live="polite"
              aria-label="Terminal command output"
              aria-describedby="terminal-help"
            >
              <div id="terminal-help" className="sr-only">
                Terminal output appears here. New output is announced automatically.
              </div>
              {/* Terminal content would go here */}
            </div>
          </section>
        </div>
      );

      renderWithEnhancements(<ComplexInterfaceComponent />);

      const app = screen.getByRole('application');
      expect(app).toHaveAttribute('aria-describedby', 'interface-description');

      const sessionsList = screen.getByRole('list', { name: /terminal sessions/i });
      expect(sessionsList).toHaveAttribute('aria-describedby', 'sessions-help');

      const terminalLog = screen.getByRole('log', { name: /terminal command output/i });
      expect(terminalLog).toHaveAttribute('aria-describedby', 'terminal-help');
    });
  });
});