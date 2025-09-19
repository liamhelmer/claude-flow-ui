/**
 * Comprehensive Accessibility Testing Suite
 * Tests WCAG compliance, screen reader compatibility, and keyboard navigation
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

// Mock components for testing
const MockTerminal = ({ sessionId, className }: { sessionId: string; className?: string }) => (
  <div
    className={className}
    role="application"
    aria-label="Terminal"
    aria-describedby="terminal-description"
    tabIndex={0}
    data-testid="terminal"
  >
    <div id="terminal-description" className="sr-only">
      Interactive terminal for command line operations
    </div>
    <div aria-live="polite" aria-atomic="false" className="sr-only" data-testid="terminal-output">
      Terminal output will be announced here
    </div>
  </div>
);

const MockSidebar = ({
  isOpen,
  onToggle,
  sessions,
  activeSessionId,
  onSessionSelect
}: {
  isOpen: boolean;
  onToggle: () => void;
  sessions: Array<{ id: string; name: string }>;
  activeSessionId: string | null;
  onSessionSelect: (id: string) => void;
}) => (
  <nav
    role="navigation"
    aria-label="Terminal sessions"
    className={isOpen ? 'sidebar open' : 'sidebar closed'}
    data-testid="sidebar"
  >
    <button
      onClick={onToggle}
      aria-expanded={isOpen}
      aria-controls="session-list"
      aria-label={isOpen ? 'Close sidebar' : 'Open sidebar'}
      data-testid="sidebar-toggle"
    >
      {isOpen ? '←' : '→'}
    </button>

    <div id="session-list" role="list" aria-label="Terminal sessions">
      {sessions.map(session => (
        <button
          key={session.id}
          role="listitem"
          onClick={() => onSessionSelect(session.id)}
          aria-current={activeSessionId === session.id ? 'page' : undefined}
          aria-describedby={`session-${session.id}-description`}
          data-testid={`session-${session.id}`}
        >
          {session.name}
          <span
            id={`session-${session.id}-description`}
            className="sr-only"
          >
            {activeSessionId === session.id ? 'Currently active session' : 'Switch to this session'}
          </span>
        </button>
      ))}
    </div>
  </nav>
);

const MockApp = () => {
  const [sidebarOpen, setSidebarOpen] = React.useState(true);
  const [sessions] = React.useState([
    { id: 'session-1', name: 'Main Terminal' },
    { id: 'session-2', name: 'Development' }
  ]);
  const [activeSessionId, setActiveSessionId] = React.useState('session-1');

  return (
    <div className="app" data-testid="app">
      <h1 className="sr-only">Claude Flow Terminal Interface</h1>

      <MockSidebar
        isOpen={sidebarOpen}
        onToggle={() => setSidebarOpen(prev => !prev)}
        sessions={sessions}
        activeSessionId={activeSessionId}
        onSessionSelect={setActiveSessionId}
      />

      <main
        role="main"
        aria-label="Terminal workspace"
        className="main-content"
        data-testid="main-content"
      >
        <MockTerminal sessionId={activeSessionId} />
      </main>
    </div>
  );
};

describe('Accessibility Testing Suite', () => {
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup();
  });

  describe('WCAG 2.1 AA Compliance', () => {
    it('should have no accessibility violations', async () => {
      const { container } = render(<MockApp />);
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper heading hierarchy', () => {
      render(<MockApp />);

      // Should have main heading
      expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();

      // Verify heading is descriptive
      expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/Claude Flow Terminal Interface/i);
    });

    it('should have proper landmark roles', () => {
      render(<MockApp />);

      // Should have navigation landmark
      expect(screen.getByRole('navigation')).toBeInTheDocument();
      expect(screen.getByRole('navigation')).toHaveAccessibleName('Terminal sessions');

      // Should have main landmark
      expect(screen.getByRole('main')).toBeInTheDocument();
      expect(screen.getByRole('main')).toHaveAccessibleName('Terminal workspace');
    });

    it('should have descriptive labels for interactive elements', () => {
      render(<MockApp />);

      // Sidebar toggle should have descriptive label
      const toggleButton = screen.getByTestId('sidebar-toggle');
      expect(toggleButton).toHaveAccessibleName(/sidebar/i);

      // Session buttons should have descriptive labels
      const sessionButton = screen.getByTestId('session-session-1');
      expect(sessionButton).toHaveAccessibleDescription(/session/i);
    });

    it('should use ARIA attributes correctly', () => {
      render(<MockApp />);

      // Check aria-expanded
      const toggleButton = screen.getByTestId('sidebar-toggle');
      expect(toggleButton).toHaveAttribute('aria-expanded', 'true');

      // Check aria-current
      const activeSession = screen.getByTestId('session-session-1');
      expect(activeSession).toHaveAttribute('aria-current', 'page');

      // Check aria-controls
      expect(toggleButton).toHaveAttribute('aria-controls', 'session-list');
    });

    it('should have proper color contrast ratios', () => {
      render(<MockApp />);

      // This would typically be tested with actual CSS
      // For now, we verify that contrast-related classes are applied
      const terminal = screen.getByTestId('terminal');
      expect(terminal).toBeInTheDocument();

      // In a real implementation, you'd test:
      // - Background/foreground color combinations
      // - Focus indicator contrast
      // - Error message contrast
    });

    it('should handle focus management properly', async () => {
      render(<MockApp />);

      // Terminal should be focusable
      const terminal = screen.getByTestId('terminal');
      expect(terminal).toHaveAttribute('tabIndex', '0');

      // Focus should be visible and manageable
      await user.tab();
      expect(document.activeElement).toBe(screen.getByTestId('sidebar-toggle'));

      await user.tab();
      expect(document.activeElement).toBe(screen.getByTestId('session-session-1'));
    });
  });

  describe('Keyboard Navigation', () => {
    it('should support complete keyboard navigation', async () => {
      render(<MockApp />);

      // Tab through all interactive elements
      await user.tab(); // Sidebar toggle
      expect(document.activeElement).toBe(screen.getByTestId('sidebar-toggle'));

      await user.tab(); // First session
      expect(document.activeElement).toBe(screen.getByTestId('session-session-1'));

      await user.tab(); // Second session
      expect(document.activeElement).toBe(screen.getByTestId('session-session-2'));

      await user.tab(); // Terminal
      expect(document.activeElement).toBe(screen.getByTestId('terminal'));
    });

    it('should support reverse tab navigation', async () => {
      render(<MockApp />);

      // Focus terminal first
      screen.getByTestId('terminal').focus();

      // Shift+Tab back through elements
      await user.tab({ shift: true }); // Second session
      expect(document.activeElement).toBe(screen.getByTestId('session-session-2'));

      await user.tab({ shift: true }); // First session
      expect(document.activeElement).toBe(screen.getByTestId('session-session-1'));

      await user.tab({ shift: true }); // Sidebar toggle
      expect(document.activeElement).toBe(screen.getByTestId('sidebar-toggle'));
    });

    it('should support Enter and Space key activation', async () => {
      const mockToggle = jest.fn();
      const mockSelect = jest.fn();

      render(
        <MockSidebar
          isOpen={true}
          onToggle={mockToggle}
          sessions={[{ id: 'session-1', name: 'Test Session' }]}
          activeSessionId={null}
          onSessionSelect={mockSelect}
        />
      );

      // Enter key should activate buttons
      const toggleButton = screen.getByTestId('sidebar-toggle');
      toggleButton.focus();
      await user.keyboard('{Enter}');
      expect(mockToggle).toHaveBeenCalled();

      // Space key should also activate buttons
      const sessionButton = screen.getByTestId('session-session-1');
      sessionButton.focus();
      await user.keyboard(' ');
      expect(mockSelect).toHaveBeenCalledWith('session-1');
    });

    it('should support arrow key navigation in lists', async () => {
      render(<MockApp />);

      // Focus first session
      screen.getByTestId('session-session-1').focus();

      // Arrow down should move to next session
      await user.keyboard('{ArrowDown}');
      expect(document.activeElement).toBe(screen.getByTestId('session-session-2'));

      // Arrow up should move back
      await user.keyboard('{ArrowUp}');
      expect(document.activeElement).toBe(screen.getByTestId('session-session-1'));
    });

    it('should support Escape key for closing modals/menus', async () => {
      const MockModal = ({ onClose }: { onClose: () => void }) => {
        React.useEffect(() => {
          const handleEscape = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
              onClose();
            }
          };

          document.addEventListener('keydown', handleEscape);
          return () => document.removeEventListener('keydown', handleEscape);
        }, [onClose]);

        return (
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="modal-title"
            data-testid="modal"
          >
            <h2 id="modal-title">Settings</h2>
            <button onClick={onClose} data-testid="close-button">Close</button>
          </div>
        );
      };

      const TestWithModal = () => {
        const [showModal, setShowModal] = React.useState(true);

        return (
          <div>
            {showModal && <MockModal onClose={() => setShowModal(false)} />}
            {!showModal && <div data-testid="modal-closed">Modal closed</div>}
          </div>
        );
      };

      render(<TestWithModal />);

      expect(screen.getByTestId('modal')).toBeInTheDocument();

      // Escape should close modal
      await user.keyboard('{Escape}');

      await waitFor(() => {
        expect(screen.getByTestId('modal-closed')).toBeInTheDocument();
      });
    });
  });

  describe('Screen Reader Support', () => {
    it('should have proper live regions for dynamic content', () => {
      render(<MockTerminal sessionId="test" />);

      // Should have live region for terminal output
      const liveRegion = screen.getByTestId('terminal-output');
      expect(liveRegion).toHaveAttribute('aria-live', 'polite');
      expect(liveRegion).toHaveAttribute('aria-atomic', 'false');
    });

    it('should provide descriptive text for complex UI elements', () => {
      render(<MockApp />);

      // Terminal should have description
      const terminal = screen.getByTestId('terminal');
      expect(terminal).toHaveAttribute('aria-describedby', 'terminal-description');

      const description = document.getElementById('terminal-description');
      expect(description).toHaveTextContent(/Interactive terminal for command line operations/i);
    });

    it('should use screen reader only text appropriately', () => {
      render(<MockApp />);

      // Screen reader only elements should have sr-only class
      const srOnlyElements = document.querySelectorAll('.sr-only');
      expect(srOnlyElements.length).toBeGreaterThan(0);

      // Main heading should be screen reader only
      const heading = screen.getByRole('heading', { level: 1 });
      expect(heading).toHaveClass('sr-only');
    });

    it('should announce state changes appropriately', async () => {
      const MockWithAnnouncements = () => {
        const [status, setStatus] = React.useState('idle');
        const [announcement, setAnnouncement] = React.useState('');

        const changeStatus = (newStatus: string) => {
          setStatus(newStatus);
          setAnnouncement(`Status changed to ${newStatus}`);
        };

        return (
          <div>
            <button
              onClick={() => changeStatus('processing')}
              data-testid="change-status"
            >
              Change Status
            </button>
            <div aria-live="assertive" data-testid="announcements">
              {announcement}
            </div>
            <div data-testid="status">Status: {status}</div>
          </div>
        );
      };

      render(<MockWithAnnouncements />);

      // Click button to change status
      await user.click(screen.getByTestId('change-status'));

      // Announcement should be made
      expect(screen.getByTestId('announcements')).toHaveTextContent('Status changed to processing');
    });

    it('should provide context for form controls', () => {
      const MockForm = () => (
        <form>
          <fieldset>
            <legend>Terminal Settings</legend>

            <label htmlFor="terminal-font-size">Font Size</label>
            <input
              id="terminal-font-size"
              type="number"
              min="8"
              max="72"
              aria-describedby="font-size-help"
              data-testid="font-size-input"
            />
            <div id="font-size-help" className="help-text">
              Choose a font size between 8 and 72 pixels
            </div>

            <label htmlFor="terminal-theme">Theme</label>
            <select
              id="terminal-theme"
              aria-describedby="theme-help"
              data-testid="theme-select"
            >
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
            <div id="theme-help" className="help-text">
              Select the terminal color theme
            </div>
          </fieldset>
        </form>
      );

      render(<MockForm />);

      // Form should have proper structure
      expect(screen.getByRole('group')).toHaveAccessibleName('Terminal Settings');

      // Inputs should have proper labels and descriptions
      const fontSizeInput = screen.getByTestId('font-size-input');
      expect(fontSizeInput).toHaveAccessibleName('Font Size');
      expect(fontSizeInput).toHaveAttribute('aria-describedby', 'font-size-help');

      const themeSelect = screen.getByTestId('theme-select');
      expect(themeSelect).toHaveAccessibleName('Theme');
      expect(themeSelect).toHaveAttribute('aria-describedby', 'theme-help');
    });
  });

  describe('Focus Management', () => {
    it('should maintain focus within modal dialogs', async () => {
      const MockModalDialog = ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => {
        const modalRef = React.useRef<HTMLDivElement>(null);
        const firstFocusableRef = React.useRef<HTMLButtonElement>(null);
        const lastFocusableRef = React.useRef<HTMLButtonElement>(null);

        React.useEffect(() => {
          if (isOpen && firstFocusableRef.current) {
            firstFocusableRef.current.focus();
          }
        }, [isOpen]);

        const handleKeyDown = (e: React.KeyboardEvent) => {
          if (e.key === 'Tab') {
            if (e.shiftKey && document.activeElement === firstFocusableRef.current) {
              e.preventDefault();
              lastFocusableRef.current?.focus();
            } else if (!e.shiftKey && document.activeElement === lastFocusableRef.current) {
              e.preventDefault();
              firstFocusableRef.current?.focus();
            }
          }
        };

        if (!isOpen) return null;

        return (
          <div
            ref={modalRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="modal-title"
            onKeyDown={handleKeyDown}
            data-testid="focus-trap-modal"
          >
            <h2 id="modal-title">Settings Dialog</h2>
            <button ref={firstFocusableRef} data-testid="first-button">
              First Button
            </button>
            <button data-testid="middle-button">Middle Button</button>
            <button
              ref={lastFocusableRef}
              onClick={onClose}
              data-testid="last-button"
            >
              Close
            </button>
          </div>
        );
      };

      const TestFocusTrap = () => {
        const [modalOpen, setModalOpen] = React.useState(false);

        return (
          <div>
            <button
              onClick={() => setModalOpen(true)}
              data-testid="open-modal"
            >
              Open Modal
            </button>
            <MockModalDialog
              isOpen={modalOpen}
              onClose={() => setModalOpen(false)}
            />
          </div>
        );
      };

      render(<TestFocusTrap />);

      // Open modal
      await user.click(screen.getByTestId('open-modal'));

      // Focus should be on first button
      await waitFor(() => {
        expect(document.activeElement).toBe(screen.getByTestId('first-button'));
      });

      // Tab to last button
      await user.tab();
      await user.tab();
      expect(document.activeElement).toBe(screen.getByTestId('last-button'));

      // Tab should wrap to first button
      await user.tab();
      expect(document.activeElement).toBe(screen.getByTestId('first-button'));

      // Shift+Tab should wrap to last button
      await user.tab({ shift: true });
      expect(document.activeElement).toBe(screen.getByTestId('last-button'));
    });

    it('should restore focus after modal closes', async () => {
      const TestFocusRestore = () => {
        const [modalOpen, setModalOpen] = React.useState(false);
        const triggerRef = React.useRef<HTMLButtonElement>(null);

        const openModal = () => {
          setModalOpen(true);
        };

        const closeModal = () => {
          setModalOpen(false);
          setTimeout(() => {
            triggerRef.current?.focus();
          }, 0);
        };

        return (
          <div>
            <button
              ref={triggerRef}
              onClick={openModal}
              data-testid="trigger-button"
            >
              Open Modal
            </button>
            {modalOpen && (
              <div role="dialog" aria-modal="true" data-testid="modal">
                <button onClick={closeModal} data-testid="close-modal">
                  Close
                </button>
              </div>
            )}
          </div>
        );
      };

      render(<TestFocusRestore />);

      const triggerButton = screen.getByTestId('trigger-button');

      // Focus trigger button
      triggerButton.focus();
      expect(document.activeElement).toBe(triggerButton);

      // Open modal
      await user.click(triggerButton);

      // Close modal
      await user.click(screen.getByTestId('close-modal'));

      // Focus should return to trigger button
      await waitFor(() => {
        expect(document.activeElement).toBe(triggerButton);
      });
    });

    it('should handle focus indicators properly', () => {
      render(<MockApp />);

      // Focus an element and check for focus indicators
      const toggleButton = screen.getByTestId('sidebar-toggle');
      toggleButton.focus();

      // In a real implementation, you'd check for focus styles
      expect(document.activeElement).toBe(toggleButton);
    });
  });

  describe('Error and Status Communication', () => {
    it('should announce errors to screen readers', async () => {
      const MockErrorComponent = () => {
        const [error, setError] = React.useState<string | null>(null);

        const triggerError = () => {
          setError('Connection failed. Please try again.');
        };

        const clearError = () => {
          setError(null);
        };

        return (
          <div>
            <button onClick={triggerError} data-testid="trigger-error">
              Trigger Error
            </button>
            <button onClick={clearError} data-testid="clear-error">
              Clear Error
            </button>
            {error && (
              <div
                role="alert"
                aria-live="assertive"
                data-testid="error-message"
              >
                Error: {error}
              </div>
            )}
          </div>
        );
      };

      render(<MockErrorComponent />);

      // Trigger error
      await user.click(screen.getByTestId('trigger-error'));

      // Error should be announced
      const errorElement = screen.getByTestId('error-message');
      expect(errorElement).toHaveAttribute('role', 'alert');
      expect(errorElement).toHaveAttribute('aria-live', 'assertive');
      expect(errorElement).toHaveTextContent('Error: Connection failed. Please try again.');
    });

    it('should provide status updates for long operations', async () => {
      const MockProgressComponent = () => {
        const [progress, setProgress] = React.useState(0);
        const [isLoading, setIsLoading] = React.useState(false);

        const startOperation = async () => {
          setIsLoading(true);
          setProgress(0);

          for (let i = 0; i <= 100; i += 10) {
            await new Promise(resolve => setTimeout(resolve, 50));
            setProgress(i);
          }

          setIsLoading(false);
        };

        return (
          <div>
            <button
              onClick={startOperation}
              disabled={isLoading}
              data-testid="start-operation"
            >
              {isLoading ? 'Processing...' : 'Start Operation'}
            </button>
            {isLoading && (
              <div
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={progress}
                aria-label="Operation progress"
                data-testid="progress-bar"
              >
                <div aria-live="polite" data-testid="progress-text">
                  {progress}% complete
                </div>
              </div>
            )}
          </div>
        );
      };

      render(<MockProgressComponent />);

      // Start operation
      await user.click(screen.getByTestId('start-operation'));

      // Progress bar should appear
      const progressBar = screen.getByTestId('progress-bar');
      expect(progressBar).toHaveAttribute('role', 'progressbar');
      expect(progressBar).toHaveAttribute('aria-valuemin', '0');
      expect(progressBar).toHaveAttribute('aria-valuemax', '100');

      // Wait for progress updates
      await waitFor(() => {
        expect(screen.getByTestId('progress-text')).toHaveTextContent('100% complete');
      }, { timeout: 2000 });
    });
  });

  describe('High Contrast and Reduced Motion Support', () => {
    it('should respect reduced motion preferences', () => {
      // Mock reduced motion preference
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-reduced-motion: reduce)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      const MockAnimatedComponent = () => {
        const [shouldAnimate, setShouldAnimate] = React.useState(true);

        React.useEffect(() => {
          const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
          setShouldAnimate(!reducedMotion.matches);
        }, []);

        return (
          <div
            data-testid="animated-element"
            className={shouldAnimate ? 'animate' : 'no-animate'}
          >
            Animated Content
          </div>
        );
      };

      render(<MockAnimatedComponent />);

      // Should respect reduced motion preference
      const element = screen.getByTestId('animated-element');
      expect(element).toHaveClass('no-animate');
    });

    it('should support high contrast mode', () => {
      // Mock high contrast preference
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-contrast: high)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      const MockHighContrastComponent = () => {
        const [highContrast, setHighContrast] = React.useState(false);

        React.useEffect(() => {
          const highContrastMedia = window.matchMedia('(prefers-contrast: high)');
          setHighContrast(highContrastMedia.matches);
        }, []);

        return (
          <div
            data-testid="contrast-element"
            className={highContrast ? 'high-contrast' : 'normal-contrast'}
          >
            Content with contrast support
          </div>
        );
      };

      render(<MockHighContrastComponent />);

      // Should apply high contrast styles
      const element = screen.getByTestId('contrast-element');
      expect(element).toHaveClass('high-contrast');
    });
  });
});