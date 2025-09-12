import React from 'react';
import { render, screen, fireEvent, waitFor } from '@/tests/test-utils';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import TabList from '../TabList';
import type { TerminalSession } from '@/types';

expect.extend(toHaveNoViolations);

describe('TabList Enhanced Tests', () => {
  const mockSessions: TerminalSession[] = [
    {
      id: 'session-1',
      name: 'Terminal 1',
      status: 'connected',
      createdAt: '2023-01-01T00:00:00Z',
      lastActivity: '2023-01-01T01:00:00Z'
    },
    {
      id: 'session-2', 
      name: 'Terminal 2',
      status: 'connected',
      createdAt: '2023-01-01T00:30:00Z',
      lastActivity: '2023-01-01T01:15:00Z'
    },
    {
      id: 'session-3',
      name: 'Very Long Terminal Session Name That Should Be Truncated Properly',
      status: 'connecting',
      createdAt: '2023-01-01T01:00:00Z',
      lastActivity: '2023-01-01T01:30:00Z'
    }
  ];

  const defaultProps = {
    sessions: mockSessions,
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionClose: jest.fn(),
    onSessionCreate: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering and Layout', () => {
    it('renders all sessions as tabs', () => {
      render(<TabList {...defaultProps} />);
      
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      expect(screen.getByText(/Very Long Terminal Session Name/)).toBeInTheDocument();
    });

    it('applies correct container classes', () => {
      render(<TabList {...defaultProps} />);
      
      const container = document.querySelector('.flex.items-center.bg-gray-800');
      expect(container).toBeInTheDocument();
      expect(container).toHaveClass('border-b', 'border-gray-700');
    });

    it('renders scrollable tabs container', () => {
      render(<TabList {...defaultProps} />);
      
      const tabsContainer = document.querySelector('.flex.flex-1.overflow-x-auto');
      expect(tabsContainer).toBeInTheDocument();
      expect(tabsContainer).toHaveClass('scrollbar-thin', 'scrollbar-thumb-gray-600');
    });

    it('applies custom className when provided', () => {
      render(<TabList {...defaultProps} className="custom-class" />);
      
      const container = document.querySelector('.custom-class');
      expect(container).toBeInTheDocument();
    });
  });

  describe('Active Session Behavior', () => {
    it('marks correct session as active', () => {
      render(<TabList {...defaultProps} activeSessionId="session-2" />);
      
      const activeTab = screen.getByText('Terminal 2').closest('.tab-button');
      expect(activeTab).toHaveClass('tab-button-active', 'border-blue-500');
    });

    it('handles null active session ID gracefully', () => {
      render(<TabList {...defaultProps} activeSessionId={null} />);
      
      mockSessions.forEach(session => {
        const tab = screen.getByText(session.name).closest('.tab-button');
        expect(tab).toHaveClass('tab-button-inactive');
      });
    });

    it('handles invalid active session ID', () => {
      render(<TabList {...defaultProps} activeSessionId="non-existent" />);
      
      // All tabs should be inactive
      mockSessions.forEach(session => {
        const tab = screen.getByText(session.name).closest('.tab-button');
        expect(tab).toHaveClass('tab-button-inactive');
      });
    });
  });

  describe('Session Interactions', () => {
    it('calls onSessionSelect when tab is clicked', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.click(screen.getByText('Terminal 2'));
      
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-2');
      expect(defaultProps.onSessionSelect).toHaveBeenCalledTimes(1);
    });

    it('calls onSessionClose when close button is clicked', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Terminal 2' });
      await user.click(closeButton);
      
      expect(defaultProps.onSessionClose).toHaveBeenCalledWith('session-2');
      expect(defaultProps.onSessionClose).toHaveBeenCalledTimes(1);
    });

    it('prevents close button click from triggering tab selection', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Terminal 2' });
      await user.click(closeButton);
      
      expect(defaultProps.onSessionClose).toHaveBeenCalledWith('session-2');
      expect(defaultProps.onSessionSelect).not.toHaveBeenCalled();
    });
  });

  describe('Close Button Behavior', () => {
    it('shows close buttons when multiple sessions exist', () => {
      render(<TabList {...defaultProps} />);
      
      const closeButtons = screen.getAllByText('×');
      expect(closeButtons).toHaveLength(mockSessions.length);
    });

    it('hides close buttons when only one session exists', () => {
      const singleSession = [mockSessions[0]];
      render(<TabList {...defaultProps} sessions={singleSession} />);
      
      expect(screen.queryByText('×')).not.toBeInTheDocument();
    });

    it('handles rapid multiple close button clicks', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Terminal 2' });
      
      // Rapid clicks
      await user.click(closeButton);
      await user.click(closeButton);
      await user.click(closeButton);
      
      expect(defaultProps.onSessionClose).toHaveBeenCalledTimes(3);
    });
  });

  describe('New Session Button', () => {
    it('renders new session button with correct aria-label', () => {
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      expect(newButton).toBeInTheDocument();
      expect(newButton).toHaveTextContent('+');
    });

    it('calls onSessionCreate when new button is clicked', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      await user.click(newButton);
      
      expect(defaultProps.onSessionCreate).toHaveBeenCalledTimes(1);
    });

    it('supports legacy onNewSession callback', async () => {
      const onNewSession = jest.fn();
      const user = userEvent.setup();
      
      render(
        <TabList 
          {...defaultProps} 
          onSessionCreate={undefined} 
          onNewSession={onNewSession}
        />
      );
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      await user.click(newButton);
      
      expect(onNewSession).toHaveBeenCalledTimes(1);
    });

    it('prefers onSessionCreate over onNewSession', async () => {
      const onNewSession = jest.fn();
      const user = userEvent.setup();
      
      render(
        <TabList 
          {...defaultProps} 
          onNewSession={onNewSession}
        />
      );
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      await user.click(newButton);
      
      expect(defaultProps.onSessionCreate).toHaveBeenCalledTimes(1);
      expect(onNewSession).not.toHaveBeenCalled();
    });
  });

  describe('Edge Cases and Error States', () => {
    it('handles empty sessions array', () => {
      render(<TabList {...defaultProps} sessions={[]} />);
      
      // Should still render container and new button
      expect(screen.getByRole('button', { name: 'Create new terminal session' })).toBeInTheDocument();
      expect(screen.queryByText('×')).not.toBeInTheDocument();
    });

    it('handles undefined session names gracefully', () => {
      const sessionsWithUndefined = [
        { ...mockSessions[0], name: undefined as any },
        { ...mockSessions[1], name: '' }
      ];
      
      expect(() => render(
        <TabList {...defaultProps} sessions={sessionsWithUndefined} />
      )).not.toThrow();
    });

    it('handles sessions with special characters in names', () => {
      const specialSessions = [{
        id: 'special',
        name: 'Terminal & <Script> "Test" \'Name\'',
        status: 'connected' as const,
        createdAt: '2023-01-01T00:00:00Z',
        lastActivity: '2023-01-01T01:00:00Z'
      }];
      
      render(<TabList {...defaultProps} sessions={specialSessions} />);
      
      expect(screen.getByText(/Terminal & <Script> "Test" 'Name'/)).toBeInTheDocument();
    });

    it('handles very long session names with truncation', () => {
      render(<TabList {...defaultProps} />);
      
      const longNameTab = screen.getByText(/Very Long Terminal Session Name/).closest('.tab-button');
      expect(longNameTab?.querySelector('.truncate')).toBeInTheDocument();
    });
  });

  describe('Keyboard Navigation', () => {
    it('supports keyboard navigation on tabs', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const firstTab = screen.getByText('Terminal 1').closest('.tab-button') as HTMLElement;
      
      // Focus and press Enter
      firstTab.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-1');
    });

    it('supports keyboard navigation on new session button', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      await user.keyboard('{Tab}');
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onSessionCreate).toHaveBeenCalledTimes(1);
    });

    it('supports tab navigation between elements', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      await user.keyboard('{Tab}');
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: 'Close Terminal 1' })
      );
    });
  });

  describe('Accessibility', () => {
    it('has no accessibility violations', async () => {
      const { container } = render(<TabList {...defaultProps} />);
      const results = await axe(container);
      
      expect(results).toHaveNoViolations();
    });

    it('provides proper ARIA labels for all interactive elements', () => {
      render(<TabList {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: 'Close Terminal 1' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Close Terminal 2' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Create new terminal session' })).toBeInTheDocument();
    });

    it('maintains proper focus management', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      newButton.focus();
      
      expect(document.activeElement).toBe(newButton);
      
      // Tab should move focus to close buttons
      await user.keyboard('{Shift>}{Tab}{/Shift}');
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: /Close Very Long Terminal Session Name/ })
      );
    });
  });

  describe('Visual States and Styling', () => {
    it('applies hover states correctly', () => {
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      expect(newButton).toHaveClass('hover:text-gray-200', 'hover:bg-gray-700');
    });

    it('shows proper border and layout classes', () => {
      render(<TabList {...defaultProps} />);
      
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      expect(newButton).toHaveClass(
        'border-l', 
        'border-gray-700', 
        'flex-shrink-0',
        'transition-colors'
      );
    });

    it('applies correct active tab styling through Tab component', () => {
      render(<TabList {...defaultProps} activeSessionId="session-2" />);
      
      const activeTab = screen.getByText('Terminal 2').closest('.tab-button');
      expect(activeTab).toHaveClass('tab-button-active');
    });
  });

  describe('Performance and Optimization', () => {
    it('handles large number of sessions efficiently', () => {
      const manySessions = Array.from({ length: 50 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i}`,
        status: 'connected' as const,
        createdAt: '2023-01-01T00:00:00Z',
        lastActivity: '2023-01-01T01:00:00Z'
      }));
      
      const startTime = performance.now();
      render(<TabList {...defaultProps} sessions={manySessions} />);
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100);
      expect(screen.getAllByText(/Terminal \d+/)).toHaveLength(50);
    });

    it('renders efficiently with rapid prop changes', async () => {
      const { rerender } = render(<TabList {...defaultProps} />);
      
      const startTime = performance.now();
      
      for (let i = 0; i < 10; i++) {
        rerender(<TabList {...defaultProps} activeSessionId={`session-${i % 3 + 1}`} />);
      }
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(50);
    });
  });

  describe('Integration with Tab Component', () => {
    it('passes correct props to Tab components', () => {
      render(<TabList {...defaultProps} />);
      
      // Verify that close buttons are shown for multiple sessions
      const closeButtons = screen.getAllByText('×');
      expect(closeButtons).toHaveLength(3);
      
      // Verify active state is passed correctly
      const activeTab = screen.getByText('Terminal 1').closest('.tab-button');
      expect(activeTab).toHaveClass('tab-button-active');
    });

    it('handles Tab component interactions correctly', async () => {
      const user = userEvent.setup();
      render(<TabList {...defaultProps} />);
      
      // Click on tab itself (not close button)
      const tabElement = screen.getByText('Terminal 2').closest('.tab-button') as HTMLElement;
      await user.click(tabElement);
      
      expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-2');
    });
  });

  describe('Responsive Behavior', () => {
    it('handles horizontal scrolling with many tabs', () => {
      const manySessions = Array.from({ length: 20 }, (_, i) => ({
        id: `session-${i}`,
        name: `Very Long Terminal Session Name ${i}`,
        status: 'connected' as const,
        createdAt: '2023-01-01T00:00:00Z',
        lastActivity: '2023-01-01T01:00:00Z'
      }));
      
      render(<TabList {...defaultProps} sessions={manySessions} />);
      
      const tabsContainer = document.querySelector('.overflow-x-auto');
      expect(tabsContainer).toBeInTheDocument();
      expect(tabsContainer).toHaveClass('scrollbar-thin');
    });

    it('maintains layout integrity with flex properties', () => {
      render(<TabList {...defaultProps} />);
      
      const container = document.querySelector('.flex.items-center');
      const tabsContainer = document.querySelector('.flex.flex-1');
      const newButton = screen.getByRole('button', { name: 'Create new terminal session' });
      
      expect(container).toHaveClass('flex', 'items-center');
      expect(tabsContainer).toHaveClass('flex', 'flex-1');
      expect(newButton).toHaveClass('flex-shrink-0');
    });
  });
});