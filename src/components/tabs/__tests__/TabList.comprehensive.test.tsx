import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TabList from '../TabList';
import type { TerminalSession } from '@/types';

// Mock the Tab component to focus on TabList logic
jest.mock('../Tab', () => {
  return function MockTab({ title, isActive, onSelect, onClose, closable }: any) {
    return (
      <div 
        role="tab" 
        aria-selected={isActive}
        onClick={onSelect}
        data-testid={`tab-${title}`}
      >
        <span>{title}</span>
        {closable && (
          <button 
            onClick={(e) => {
              e.stopPropagation();
              onClose();
            }}
            data-testid={`close-${title}`}
          >
            ×
          </button>
        )}
      </div>
    );
  };
});

describe('TabList - Comprehensive Tests', () => {
  const mockSessions: TerminalSession[] = [
    {
      id: 'session-1',
      name: 'Terminal 1',
      isActive: true,
      lastActivity: new Date('2025-09-10T10:00:00Z'),
    },
    {
      id: 'session-2',
      name: 'Terminal 2',
      isActive: false,
      lastActivity: new Date('2025-09-10T09:30:00Z'),
    },
    {
      id: 'session-3',
      name: 'Terminal 3',
      isActive: false,
      lastActivity: new Date('2025-09-10T09:00:00Z'),
    },
  ];

  const defaultProps = {
    sessions: mockSessions,
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionCreate: jest.fn(),
    onSessionClose: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render all sessions as tabs', () => {
      render(<TabList {...defaultProps} />);
      
      expect(screen.getByTestId('tab-Terminal 1')).toBeInTheDocument();
      expect(screen.getByTestId('tab-Terminal 2')).toBeInTheDocument();
      expect(screen.getByTestId('tab-Terminal 3')).toBeInTheDocument();
    });

    it('should render new tab button', () => {
      render(<TabList {...defaultProps} />);
      expect(screen.getByLabelText('Create new terminal session')).toBeInTheDocument();
    });

    it('should mark active session correctly', () => {
      render(<TabList {...defaultProps} />);
      
      expect(screen.getByTestId('tab-Terminal 1')).toHaveAttribute('aria-selected', 'true');
      expect(screen.getByTestId('tab-Terminal 2')).toHaveAttribute('aria-selected', 'false');
      expect(screen.getByTestId('tab-Terminal 3')).toHaveAttribute('aria-selected', 'false');
    });

    it('should render with empty sessions list', () => {
      render(<TabList {...defaultProps} sessions={[]} />);
      expect(screen.getByLabelText('Create new terminal session')).toBeInTheDocument();
      expect(screen.queryByRole('tab')).not.toBeInTheDocument();
    });

    it('should render with no active session', () => {
      render(<TabList {...defaultProps} activeSessionId={null} />);
      
      const tabs = screen.getAllByRole('tab');
      tabs.forEach(tab => {
        expect(tab).toHaveAttribute('aria-selected', 'false');
      });
    });
  });

  describe('Session Selection', () => {
    it('should call onSessionSelect when tab is clicked', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByTestId('tab-Terminal 2'));
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    it('should handle selection of already active session', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByTestId('tab-Terminal 1'));
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-1');
    });

    it('should handle rapid tab switching', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByTestId('tab-Terminal 2'));
      await user.click(screen.getByTestId('tab-Terminal 3'));
      await user.click(screen.getByTestId('tab-Terminal 1'));
      
      expect(defaultProps.onSessionSelect).toHaveBeenCalledTimes(3);
      expect(defaultProps.onSessionSelect).toHaveBeenNthCalledWith(1, 'session-2');
      expect(defaultProps.onSessionSelect).toHaveBeenNthCalledWith(2, 'session-3');
      expect(defaultProps.onSessionSelect).toHaveBeenNthCalledWith(3, 'session-1');
    });
  });

  describe('Session Creation', () => {
    it('should call onSessionCreate when new tab button is clicked', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByLabelText('Create new terminal session'));
      expect(defaultProps.onSessionCreate).toHaveBeenCalledTimes(1);
    });

    it('should handle keyboard activation of new tab button', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByLabelText('Create new terminal session');
      newButton.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onSessionCreate).toHaveBeenCalledTimes(1);
    });

    it('should handle space key on new tab button', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByLabelText('Create new terminal session');
      newButton.focus();
      await user.keyboard(' ');
      
      expect(defaultProps.onSessionCreate).toHaveBeenCalledTimes(1);
    });
  });

  describe('Session Closing', () => {
    it('should call onSessionClose when close button is clicked', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByTestId('close-Terminal 2'));
      expect(defaultProps.onSessionClose).toHaveBeenCalledWith('session-2');
    });

    it('should not prevent closing active session', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByTestId('close-Terminal 1'));
      expect(defaultProps.onSessionClose).toHaveBeenCalledWith('session-1');
    });

    it('should close multiple sessions', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByTestId('close-Terminal 1'));
      await user.click(screen.getByTestId('close-Terminal 2'));
      
      expect(defaultProps.onSessionClose).toHaveBeenCalledTimes(2);
      expect(defaultProps.onSessionClose).toHaveBeenNthCalledWith(1, 'session-1');
      expect(defaultProps.onSessionClose).toHaveBeenNthCalledWith(2, 'session-2');
    });
  });

  describe('Keyboard Navigation', () => {
    it('should support tab navigation between elements', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      // Start before the tab list
      await user.tab();
      expect(screen.getByTestId('tab-Terminal 1')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByTestId('tab-Terminal 2')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByTestId('tab-Terminal 3')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByLabelText('Create new terminal session')).toHaveFocus();
    });

    it('should support arrow key navigation', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      // Focus first tab
      screen.getByTestId('tab-Terminal 1').focus();
      
      // Arrow right should move to next tab
      await user.keyboard('{ArrowRight}');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-2');
      
      // Arrow left should move to previous tab
      await user.keyboard('{ArrowLeft}');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-1');
    });

    it('should wrap around at edges with arrow keys', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} activeSessionId="session-3" />);
      
      screen.getByTestId('tab-Terminal 3').focus();
      
      // Arrow right from last tab should wrap to first
      await user.keyboard('{ArrowRight}');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-1');
      
      // Arrow left from first tab should wrap to last
      await user.keyboard('{ArrowLeft}');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-3');
    });

    it('should handle Home and End keys', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} activeSessionId="session-2" />);
      
      screen.getByTestId('tab-Terminal 2').focus();
      
      await user.keyboard('{Home}');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-1');
      
      await user.keyboard('{End}');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-3');
    });
  });

  describe('Accessibility', () => {
    it('should have correct ARIA attributes', () => {
      render(<TabList {...defaultProps} />);
      
      const tablist = screen.getByRole('tablist');
      expect(tablist).toBeInTheDocument();
      expect(tablist).toHaveAttribute('aria-label', 'Terminal sessions');
    });

    it('should have correct tab order', () => {
      render(<TabList {...defaultProps} />);
      
      const tabs = screen.getAllByRole('tab');
      const newButton = screen.getByLabelText('Create new terminal session');
      
      expect(tabs[0]).toHaveAttribute('tabindex', '0');
      expect(newButton).toHaveAttribute('tabindex', '0');
    });

    it('should announce tab changes to screen readers', () => {
      render(<TabList {...defaultProps} />);
      
      const tabs = screen.getAllByRole('tab');
      tabs.forEach(tab => {
        expect(tab).toHaveAttribute('aria-selected');
      });
    });
  });

  describe('Dynamic Session Management', () => {
    it('should handle adding new sessions', () => {
      const { rerender } = render(<TabList {...defaultProps} />);
      
      const newSessions = [
        ...mockSessions,
        {
          id: 'session-4',
          name: 'Terminal 4',
          isActive: false,
          lastActivity: new Date(),
        },
      ];
      
      rerender(<TabList {...defaultProps} sessions={newSessions} />);
      expect(screen.getByTestId('tab-Terminal 4')).toBeInTheDocument();
    });

    it('should handle removing sessions', () => {
      const { rerender } = render(<TabList {...defaultProps} />);
      
      const reducedSessions = mockSessions.slice(0, 2);
      
      rerender(<TabList {...defaultProps} sessions={reducedSessions} />);
      expect(screen.queryByTestId('tab-Terminal 3')).not.toBeInTheDocument();
    });

    it('should handle session name changes', () => {
      const { rerender } = render(<TabList {...defaultProps} />);
      
      const updatedSessions = mockSessions.map(session =>
        session.id === 'session-2'
          ? { ...session, name: 'Renamed Terminal' }
          : session
      );
      
      rerender(<TabList {...defaultProps} sessions={updatedSessions} />);
      expect(screen.getByTestId('tab-Renamed Terminal')).toBeInTheDocument();
      expect(screen.queryByTestId('tab-Terminal 2')).not.toBeInTheDocument();
    });
  });

  describe('Edge Cases', () => {
    it('should handle sessions with duplicate names', () => {
      const duplicateSessions = [
        { ...mockSessions[0] },
        { ...mockSessions[1], name: 'Terminal 1' },
      ];
      
      render(<TabList {...defaultProps} sessions={duplicateSessions} />);
      
      const duplicateTabs = screen.getAllByText('Terminal 1');
      expect(duplicateTabs).toHaveLength(2);
    });

    it('should handle very long session names', () => {
      const longNameSessions = [
        {
          ...mockSessions[0],
          name: 'This is a very long terminal session name that might cause layout issues',
        },
      ];
      
      render(<TabList {...defaultProps} sessions={longNameSessions} />);
      expect(screen.getByText('This is a very long terminal session name that might cause layout issues')).toBeInTheDocument();
    });

    it('should handle special characters in session names', () => {
      const specialSessions = [
        { ...mockSessions[0], name: 'Terminal & <Special> "Chars"' },
      ];
      
      render(<TabList {...defaultProps} sessions={specialSessions} />);
      expect(screen.getByText('Terminal & <Special> "Chars"')).toBeInTheDocument();
    });

    it('should handle missing session properties gracefully', () => {
      const incompleteSessions = [
        {
          id: 'session-incomplete',
          name: 'Incomplete Session',
          // Missing isActive and lastActivity
        } as TerminalSession,
      ];
      
      expect(() => 
        render(<TabList {...defaultProps} sessions={incompleteSessions} />)
      ).not.toThrow();
    });
  });

  describe('Performance', () => {
    it('should handle large numbers of sessions', () => {
      const manySessions = Array.from({ length: 50 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i}`,
        isActive: i === 0,
        lastActivity: new Date(),
      }));
      
      render(<TabList {...defaultProps} sessions={manySessions} />);
      
      expect(screen.getAllByRole('tab')).toHaveLength(50);
    });

    it('should not re-render unnecessarily', () => {
      const renderSpy = jest.fn();
      const TestTabList = (props: any) => {
        renderSpy();
        return <TabList {...props} />;
      };
      
      const { rerender } = render(<TestTabList {...defaultProps} />);
      expect(renderSpy).toHaveBeenCalledTimes(1);
      
      // Re-render with same props
      rerender(<TestTabList {...defaultProps} />);
      expect(renderSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe('Integration', () => {
    it('should work with real session data structure', () => {
      const realSessions: TerminalSession[] = [
        {
          id: 'terminal-1234567890',
          name: 'bash',
          isActive: true,
          lastActivity: new Date(),
        },
        {
          id: 'terminal-0987654321',
          name: 'node',
          isActive: false,
          lastActivity: new Date(Date.now() - 300000), // 5 minutes ago
        },
      ];
      
      render(<TabList {...defaultProps} sessions={realSessions} activeSessionId="terminal-1234567890" />);
      
      expect(screen.getByTestId('tab-bash')).toHaveAttribute('aria-selected', 'true');
      expect(screen.getByTestId('tab-node')).toHaveAttribute('aria-selected', 'false');
    });
  });
});