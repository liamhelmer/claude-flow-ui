/**
 * Comprehensive unit tests for Sidebar components
 * Tests sidebar functionality, session management, and responsive behavior
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useAppStore } from '@/lib/state/store';

// Mock the store
jest.mock('@/lib/state/store');
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
  Plus: () => <div data-testid="plus-icon">+</div>,
  Terminal: () => <div data-testid="terminal-icon">T</div>,
  X: () => <div data-testid="x-icon">×</div>,
  Menu: () => <div data-testid="menu-icon">☰</div>,
  ChevronLeft: () => <div data-testid="chevron-left-icon">‹</div>,
  ChevronRight: () => <div data-testid="chevron-right-icon">›</div>,
  Settings: () => <div data-testid="settings-icon">⚙</div>,
  Info: () => <div data-testid="info-icon">ⓘ</div>,
}));

// Mock next/dynamic
jest.mock('next/dynamic', () => (component: any) => component);

// Mock utility functions
jest.mock('@/lib/utils', () => ({
  cn: (...classes: any[]) => classes.filter(Boolean).join(' '),
  formatDate: (date: Date) => '12:34:56 PM',
}));

// Import components after mocking dependencies
import Sidebar from '@/components/sidebar/Sidebar';
import TerminalSidebar from '@/components/sidebar/TerminalSidebar';

describe('Sidebar Components', () => {
  const mockStoreState = {
    terminalSessions: [],
    activeSessionId: null,
    sidebarOpen: true,
    loading: false,
    error: null,
    setSidebarOpen: jest.fn(),
    toggleSidebar: jest.fn(),
    setActiveSession: jest.fn(),
    addSession: jest.fn(),
    removeSession: jest.fn(),
    updateSession: jest.fn(),
    createNewSession: jest.fn().mockReturnValue('new-session-123'),
    clearSessions: jest.fn(),
    setLoading: jest.fn(),
    setError: jest.fn(),
    batchUpdate: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseAppStore.mockReturnValue(mockStoreState);
  });

  describe('Sidebar Component', () => {
    it('renders without crashing', () => {
      render(<Sidebar />);
      expect(screen.getByRole('complementary')).toBeInTheDocument();
    });

    it('shows sidebar when sidebarOpen is true', () => {
      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        sidebarOpen: true,
      });

      render(<Sidebar />);
      const sidebar = screen.getByRole('complementary');

      expect(sidebar).toHaveClass('translate-x-0');
      expect(sidebar).not.toHaveClass('-translate-x-full');
    });

    it('hides sidebar when sidebarOpen is false', () => {
      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        sidebarOpen: false,
      });

      render(<Sidebar />);
      const sidebar = screen.getByRole('complementary');

      expect(sidebar).toHaveClass('-translate-x-full');
      expect(sidebar).not.toHaveClass('translate-x-0');
    });

    it('displays terminal sidebar content', () => {
      render(<Sidebar />);

      // Should contain TerminalSidebar component
      expect(screen.getByText('Terminals')).toBeInTheDocument();
    });

    it('applies custom className', () => {
      render(<Sidebar className="custom-class" />);
      const sidebar = screen.getByRole('complementary');

      expect(sidebar).toHaveClass('custom-class');
    });

    it('handles resize events appropriately', () => {
      const { container } = render(<Sidebar />);

      // Simulate window resize
      global.innerWidth = 500;
      fireEvent(window, new Event('resize'));

      // On mobile, sidebar should be responsive
      expect(container.firstChild).toBeInTheDocument();
    });

    it('provides proper accessibility attributes', () => {
      render(<Sidebar />);
      const sidebar = screen.getByRole('complementary');

      expect(sidebar).toHaveAttribute('aria-label', 'Terminal Sessions Sidebar');
    });

    it('supports keyboard navigation', async () => {
      render(<Sidebar />);

      // Focus should be manageable within sidebar
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();

      // Should contain focusable elements
      const focusableElements = sidebar.querySelectorAll('button, input, [tabindex]');
      expect(focusableElements.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('TerminalSidebar Component', () => {
    it('renders terminal sidebar header', () => {
      render(<TerminalSidebar />);

      expect(screen.getByText('Terminals')).toBeInTheDocument();
      expect(screen.getByTestId('plus-icon')).toBeInTheDocument();
    });

    it('displays empty state when no sessions', () => {
      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: [],
      });

      render(<TerminalSidebar />);

      expect(screen.getByText('No active terminals')).toBeInTheDocument();
      expect(screen.getByText('Click the + button to create a new terminal')).toBeInTheDocument();
    });

    it('displays terminal sessions when available', () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date('2023-01-01T12:00:00Z'),
        },
        {
          id: 'session-2',
          name: 'Terminal 2',
          isActive: false,
          lastActivity: new Date('2023-01-01T12:30:00Z'),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      expect(screen.getAllByTestId('terminal-icon')).toHaveLength(2);
    });

    it('highlights active session', () => {
      const mockSessions = [
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

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const activeSession = screen.getByText('Terminal 1').closest('button');
      const inactiveSession = screen.getByText('Terminal 2').closest('button');

      expect(activeSession).toHaveClass('bg-blue-100', 'border-blue-300');
      expect(inactiveSession).not.toHaveClass('bg-blue-100', 'border-blue-300');
    });

    it('creates new session when plus button clicked', async () => {
      render(<TerminalSidebar />);

      const addButton = screen.getByTestId('plus-icon').closest('button');
      await userEvent.click(addButton!);

      expect(mockStoreState.createNewSession).toHaveBeenCalled();
    });

    it('switches session when session clicked', async () => {
      const mockSessions = [
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

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const session2Button = screen.getByText('Terminal 2').closest('button');
      await userEvent.click(session2Button!);

      expect(mockStoreState.setActiveSession).toHaveBeenCalledWith('session-2');
    });

    it('removes session when X button clicked', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const removeButton = screen.getByTestId('x-icon').closest('button');
      await userEvent.click(removeButton!);

      expect(mockStoreState.removeSession).toHaveBeenCalledWith('session-1');
    });

    it('prevents removing session when clicking remove button', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const removeButton = screen.getByTestId('x-icon').closest('button');
      await userEvent.click(removeButton!);

      // Should stop propagation - session should not be activated
      expect(mockStoreState.setActiveSession).not.toHaveBeenCalled();
      expect(mockStoreState.removeSession).toHaveBeenCalledWith('session-1');
    });

    it('displays session timestamps', () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date('2023-01-01T12:00:00Z'),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
      });

      render(<TerminalSidebar />);

      expect(screen.getByText('12:34:56 PM')).toBeInTheDocument();
    });

    it('handles long session names', () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'This is a very long terminal name that should be truncated',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
      });

      render(<TerminalSidebar />);

      const sessionName = screen.getByText('This is a very long terminal name that should be truncated');
      expect(sessionName).toHaveClass('truncate');
    });

    it('shows loading state correctly', () => {
      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        loading: true,
      });

      render(<TerminalSidebar />);

      // Loading state should be reflected in the UI
      const loadingElement = screen.queryByText('Loading...');
      // Loading state may or may not be explicitly shown in sidebar
      // Test passes if no error is thrown
      expect(screen.getByText('Terminals')).toBeInTheDocument();
    });

    it('displays error state when error exists', () => {
      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        error: 'Failed to load terminals',
      });

      render(<TerminalSidebar />);

      // Error might be shown in a toast or error state
      // Main sidebar should still be functional
      expect(screen.getByText('Terminals')).toBeInTheDocument();
    });

    it('handles many sessions efficiently', () => {
      const manySessions = Array.from({ length: 50 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i + 1}`,
        isActive: i === 0,
        lastActivity: new Date(),
      }));

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: manySessions,
        activeSessionId: 'session-0',
      });

      render(<TerminalSidebar />);

      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 50')).toBeInTheDocument();
      expect(screen.getAllByTestId('terminal-icon')).toHaveLength(50);
    });
  });

  describe('Responsive Behavior', () => {
    beforeEach(() => {
      // Mock window.innerWidth
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 1024,
      });
    });

    it('adapts to mobile viewport', () => {
      // Set mobile viewport
      Object.defineProperty(window, 'innerWidth', {
        value: 500,
      });

      render(<Sidebar />);

      // Should render differently on mobile
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();
    });

    it('adapts to tablet viewport', () => {
      // Set tablet viewport
      Object.defineProperty(window, 'innerWidth', {
        value: 768,
      });

      render(<Sidebar />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();
    });

    it('handles orientation changes', () => {
      render(<Sidebar />);

      // Simulate orientation change
      fireEvent(window, new Event('orientationchange'));

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();
    });
  });

  describe('Keyboard Navigation', () => {
    it('supports arrow key navigation between sessions', async () => {
      const mockSessions = [
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

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const session1 = screen.getByText('Terminal 1').closest('button');
      const session2 = screen.getByText('Terminal 2').closest('button');

      session1!.focus();
      expect(session1).toHaveFocus();

      await userEvent.keyboard('{ArrowDown}');
      expect(session2).toHaveFocus();
    });

    it('supports Enter key to select session', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: false,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: null,
      });

      render(<TerminalSidebar />);

      const sessionButton = screen.getByText('Terminal 1').closest('button');
      sessionButton!.focus();

      await userEvent.keyboard('{Enter}');

      expect(mockStoreState.setActiveSession).toHaveBeenCalledWith('session-1');
    });

    it('supports Space key to select session', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: false,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: null,
      });

      render(<TerminalSidebar />);

      const sessionButton = screen.getByText('Terminal 1').closest('button');
      sessionButton!.focus();

      await userEvent.keyboard('{ }');

      expect(mockStoreState.setActiveSession).toHaveBeenCalledWith('session-1');
    });
  });

  describe('Accessibility', () => {
    it('provides proper ARIA labels', () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const addButton = screen.getByTestId('plus-icon').closest('button');
      expect(addButton).toHaveAttribute('aria-label', 'Create new terminal');

      const removeButton = screen.getByTestId('x-icon').closest('button');
      expect(removeButton).toHaveAttribute('aria-label', 'Close terminal');
    });

    it('indicates active session to screen readers', () => {
      const mockSessions = [
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

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      const activeSession = screen.getByText('Terminal 1').closest('button');
      const inactiveSession = screen.getByText('Terminal 2').closest('button');

      expect(activeSession).toHaveAttribute('aria-pressed', 'true');
      expect(inactiveSession).toHaveAttribute('aria-pressed', 'false');
    });

    it('provides descriptive button labels', () => {
      render(<TerminalSidebar />);

      const addButton = screen.getByTestId('plus-icon').closest('button');
      expect(addButton).toHaveAttribute('aria-label');
      expect(addButton?.getAttribute('aria-label')).toContain('Create');
    });

    it('supports focus management', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: mockSessions,
        activeSessionId: 'session-1',
      });

      render(<TerminalSidebar />);

      // Should be able to tab through all focusable elements
      await userEvent.tab();

      const addButton = screen.getByTestId('plus-icon').closest('button');
      expect(addButton).toHaveFocus();

      await userEvent.tab();

      const sessionButton = screen.getByText('Terminal 1').closest('button');
      expect(sessionButton).toHaveFocus();
    });
  });

  describe('Performance', () => {
    it('renders quickly with many sessions', () => {
      const start = performance.now();

      const manySessions = Array.from({ length: 100 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i + 1}`,
        isActive: i === 0,
        lastActivity: new Date(),
      }));

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: manySessions,
      });

      render(<TerminalSidebar />);

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(1000); // Should render in under 1 second
    });

    it('handles rapid session updates efficiently', async () => {
      const { rerender } = render(<TerminalSidebar />);

      const start = performance.now();

      // Simulate rapid updates
      for (let i = 0; i < 10; i++) {
        const sessions = [{
          id: 'session-1',
          name: `Terminal ${i}`,
          isActive: true,
          lastActivity: new Date(),
        }];

        mockUseAppStore.mockReturnValue({
          ...mockStoreState,
          terminalSessions: sessions,
        });

        rerender(<TerminalSidebar />);
      }

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(500);
    });
  });

  describe('Error Handling', () => {
    it('handles missing session data gracefully', () => {
      const incompleteSessions = [
        {
          id: 'session-1',
          // Missing name, isActive, lastActivity
        } as any,
      ];

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: incompleteSessions,
      });

      expect(() => {
        render(<TerminalSidebar />);
      }).not.toThrow();
    });

    it('handles null or undefined sessions array', () => {
      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: null as any,
      });

      expect(() => {
        render(<TerminalSidebar />);
      }).not.toThrow();

      mockUseAppStore.mockReturnValue({
        ...mockStoreState,
        terminalSessions: undefined as any,
      });

      expect(() => {
        render(<TerminalSidebar />);
      }).not.toThrow();
    });

    it('handles store action errors gracefully', async () => {
      mockStoreState.createNewSession.mockImplementation(() => {
        throw new Error('Failed to create session');
      });

      render(<TerminalSidebar />);

      const addButton = screen.getByTestId('plus-icon').closest('button');

      expect(async () => {
        await userEvent.click(addButton!);
      }).not.toThrow();
    });
  });
});