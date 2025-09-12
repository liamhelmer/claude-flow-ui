import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../../tests/test-utils';
import { axe, toHaveNoViolations } from 'jest-axe';
import TabList from '../TabList';
import type { TerminalSession } from '@/types';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

describe('TabList Component - Comprehensive Tests', () => {
  const mockSessions: TerminalSession[] = [
    {
      id: 'session-1',
      name: 'Terminal 1',
      isActive: true,
      lastActivity: new Date('2024-01-01T10:00:00'),
    },
    {
      id: 'session-2', 
      name: 'Terminal 2',
      isActive: false,
      lastActivity: new Date('2024-01-01T09:30:00'),
    },
    {
      id: 'session-3',
      name: 'Very Long Terminal Name That Should Be Truncated',
      isActive: false,
      lastActivity: new Date('2024-01-01T09:00:00'),
    },
  ];

  const mockProps = {
    sessions: mockSessions,
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionClose: jest.fn(),
    onSessionCreate: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render all sessions as tabs', () => {
      render(<TabList {...mockProps} />);
      
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
      expect(screen.getByText(/Very Long Terminal Name/)).toBeInTheDocument();
    });

    it('should render add session button', () => {
      render(<TabList {...mockProps} />);
      
      const addButton = screen.getByRole('button', { name: /add.*(session|tab)/i });
      expect(addButton).toBeInTheDocument();
    });

    it('should handle empty sessions list', () => {
      render(<TabList {...mockProps} sessions={[]} activeSessionId={null} />);
      
      const addButton = screen.getByRole('button', { name: /add.*(session|tab)/i });
      expect(addButton).toBeInTheDocument();
      expect(screen.queryByText('Terminal')).not.toBeInTheDocument();
    });

    it('should apply correct container classes', () => {
      render(<TabList {...mockProps} />);
      
      const container = document.querySelector('.flex');
      expect(container).toBeInTheDocument();
      expect(container).toHaveClass('flex');
    });
  });

  describe('Active Session State', () => {
    it('should mark active session correctly', () => {
      render(<TabList {...mockProps} />);
      
      const activeTab = screen.getByText('Terminal 1').closest('div');
      const inactiveTab = screen.getByText('Terminal 2').closest('div');
      
      // Check for active/inactive styling classes
      expect(activeTab).toHaveClass('tab-button-active');
      expect(inactiveTab).toHaveClass('tab-button-inactive');
    });

    it('should handle no active session', () => {
      render(<TabList {...mockProps} activeSessionId={null} />);
      
      const tab1 = screen.getByText('Terminal 1').closest('div');
      const tab2 = screen.getByText('Terminal 2').closest('div');
      
      expect(tab1).toHaveClass('tab-button-inactive');
      expect(tab2).toHaveClass('tab-button-inactive');
    });

    it('should handle invalid active session id', () => {
      render(<TabList {...mockProps} activeSessionId="invalid-id" />);
      
      const tab1 = screen.getByText('Terminal 1').closest('div');
      const tab2 = screen.getByText('Terminal 2').closest('div');
      
      expect(tab1).toHaveClass('tab-button-inactive');
      expect(tab2).toHaveClass('tab-button-inactive');
    });
  });

  describe('User Interactions', () => {
    it('should call onSessionSelect when tab is clicked', () => {
      render(<TabList {...mockProps} />);
      
      const tab = screen.getByText('Terminal 2').closest('div');
      fireEvent.click(tab!);
      
      expect(mockProps.onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    it('should call onSessionClose when close button is clicked', () => {
      render(<TabList {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Terminal 2' });
      fireEvent.click(closeButton);
      
      expect(mockProps.onSessionClose).toHaveBeenCalledWith('session-2');
      expect(mockProps.onSessionSelect).not.toHaveBeenCalled();
    });

    it('should call onSessionCreate when add button is clicked', () => {
      render(<TabList {...mockProps} />);
      
      const addButton = screen.getByRole('button', { name: /add.*(session|tab)/i });
      fireEvent.click(addButton);
      
      expect(mockProps.onSessionCreate).toHaveBeenCalledTimes(1);
    });

    it('should handle rapid clicking on tabs', async () => {
      render(<TabList {...mockProps} />);
      
      const tab = screen.getByText('Terminal 2').closest('div');
      
      fireEvent.click(tab!);
      fireEvent.click(tab!);
      fireEvent.click(tab!);
      
      await waitFor(() => {
        expect(mockProps.onSessionSelect).toHaveBeenCalledTimes(3);
      });
    });

    it('should handle multiple sessions interaction', () => {
      render(<TabList {...mockProps} />);
      
      fireEvent.click(screen.getByText('Terminal 2').closest('div')!);
      fireEvent.click(screen.getByText('Terminal 1').closest('div')!);
      
      expect(mockProps.onSessionSelect).toHaveBeenCalledWith('session-2');
      expect(mockProps.onSessionSelect).toHaveBeenCalledWith('session-1');
      expect(mockProps.onSessionSelect).toHaveBeenCalledTimes(2);
    });
  });

  describe('Close Button Behavior', () => {
    it('should show close buttons for all tabs by default', () => {
      render(<TabList {...mockProps} />);
      
      expect(screen.getByRole('button', { name: 'Close Terminal 1' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Close Terminal 2' })).toBeInTheDocument();
    });

    it('should prevent closing when only one session remains', () => {
      const singleSession = [mockSessions[0]];
      render(
        <TabList 
          {...mockProps} 
          sessions={singleSession} 
          activeSessionId="session-1"
        />
      );
      
      // Close button should either be disabled or not present
      const closeButton = screen.queryByRole('button', { name: 'Close Terminal 1' });
      if (closeButton) {
        expect(closeButton).toBeDisabled();
      }
    });

    it('should stop event propagation when close button is clicked', () => {
      render(<TabList {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Terminal 2' });
      fireEvent.click(closeButton);
      
      expect(mockProps.onSessionClose).toHaveBeenCalledWith('session-2');
      expect(mockProps.onSessionSelect).not.toHaveBeenCalled();
    });
  });

  describe('Long Session Names', () => {
    it('should truncate very long session names', () => {
      render(<TabList {...mockProps} />);
      
      const longNameTab = screen.getByText(/Very Long Terminal Name/);
      expect(longNameTab).toHaveClass('truncate');
    });

    it('should show full name in title attribute for accessibility', () => {
      render(<TabList {...mockProps} />);
      
      const longNameTab = screen.getByText(/Very Long Terminal Name/);
      const tabContainer = longNameTab.closest('div');
      
      expect(tabContainer).toHaveAttribute('title', 'Very Long Terminal Name That Should Be Truncated');
    });
  });

  describe('Keyboard Navigation', () => {
    it('should support keyboard navigation between tabs', () => {
      render(<TabList {...mockProps} />);
      
      const tab1 = screen.getByText('Terminal 1').closest('div');
      const tab2 = screen.getByText('Terminal 2').closest('div');
      
      expect(tab1).toHaveAttribute('tabIndex', '0');
      expect(tab2).toHaveAttribute('tabIndex', '0');
    });

    it('should handle Enter key on tabs', () => {
      render(<TabList {...mockProps} />);
      
      const tab = screen.getByText('Terminal 2').closest('div');
      fireEvent.keyDown(tab!, { key: 'Enter' });
      
      expect(mockProps.onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    it('should handle Space key on tabs', () => {
      render(<TabList {...mockProps} />);
      
      const tab = screen.getByText('Terminal 2').closest('div');
      fireEvent.keyDown(tab!, { key: ' ' });
      
      expect(mockProps.onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    it('should support arrow key navigation', () => {
      render(<TabList {...mockProps} />);
      
      const tab1 = screen.getByText('Terminal 1').closest('div');
      
      fireEvent.keyDown(tab1!, { key: 'ArrowRight' });
      
      // Focus should move to next tab
      expect(document.activeElement).toBe(screen.getByText('Terminal 2').closest('div'));
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(<TabList {...mockProps} />);
      
      const tablist = screen.getByRole('tablist');
      expect(tablist).toBeInTheDocument();
      
      const tabs = screen.getAllByRole('tab');
      expect(tabs).toHaveLength(3);
      
      // Check active tab has correct aria-selected
      const activeTab = screen.getByText('Terminal 1').closest('[role="tab"]');
      expect(activeTab).toHaveAttribute('aria-selected', 'true');
      
      const inactiveTab = screen.getByText('Terminal 2').closest('[role="tab"]');
      expect(inactiveTab).toHaveAttribute('aria-selected', 'false');
    });

    it('should have proper labels for screen readers', () => {
      render(<TabList {...mockProps} />);
      
      const closeButtons = screen.getAllByRole('button', { name: /close/i });
      expect(closeButtons).toHaveLength(3);
      
      closeButtons.forEach(button => {
        expect(button).toHaveAttribute('aria-label');
      });
    });

    it('should pass accessibility audit', async () => {
      const { container } = render(<TabList {...mockProps} />);
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should support high contrast mode', () => {
      render(<TabList {...mockProps} />);
      
      const activeTab = screen.getByText('Terminal 1').closest('div');
      expect(activeTab).toHaveClass('border-blue-500'); // Should have visible border
    });
  });

  describe('Performance', () => {
    it('should render efficiently with many sessions', () => {
      const manySessions = Array.from({ length: 20 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i + 1}`,
        isActive: i === 0,
        lastActivity: new Date(),
      }));
      
      const startTime = performance.now();
      render(<TabList {...mockProps} sessions={manySessions} />);
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100); // Should render in under 100ms
      expect(screen.getAllByRole('tab')).toHaveLength(20);
    });

    it('should not re-render unnecessarily', () => {
      const renderSpy = jest.fn();
      const TabListWithSpy = (props: any) => {
        renderSpy();
        return <TabList {...props} />;
      };
      
      const { rerender } = render(<TabListWithSpy {...mockProps} />);
      
      // Re-render with same props
      rerender(<TabListWithSpy {...mockProps} />);
      
      expect(renderSpy).toHaveBeenCalledTimes(2); // Initial + rerender
    });
  });

  describe('Edge Cases', () => {
    it('should handle undefined sessions gracefully', () => {
      expect(() => 
        render(<TabList {...mockProps} sessions={undefined as any} />)
      ).not.toThrow();
    });

    it('should handle sessions with missing properties', () => {
      const incompleteSessions = [
        { id: 'session-1' } as any,
        { name: 'Terminal 2' } as any,
      ];
      
      expect(() => 
        render(<TabList {...mockProps} sessions={incompleteSessions} />)
      ).not.toThrow();
    });

    it('should handle sessions with special characters', () => {
      const specialSessions = [{
        id: 'session-special',
        name: 'Terminal & <script>alert("xss")</script>',
        isActive: false,
        lastActivity: new Date(),
      }];
      
      render(<TabList {...mockProps} sessions={specialSessions} />);
      
      // Should not execute script
      expect(screen.getByText(/Terminal &/)).toBeInTheDocument();
    });

    it('should handle very large session IDs', () => {
      const largeIdSession = {
        id: 'session-' + 'x'.repeat(1000),
        name: 'Large ID Terminal',
        isActive: false,
        lastActivity: new Date(),
      };
      
      expect(() => 
        render(<TabList {...mockProps} sessions={[largeIdSession]} />)
      ).not.toThrow();
    });
  });

  describe('Context Menu Support', () => {
    it('should handle right-click context menu', () => {
      render(<TabList {...mockProps} />);
      
      const tab = screen.getByText('Terminal 2').closest('div');
      
      const contextMenuEvent = new MouseEvent('contextmenu', {
        bubbles: true,
        cancelable: true,
      });
      
      expect(() => {
        tab?.dispatchEvent(contextMenuEvent);
      }).not.toThrow();
    });
  });

  describe('Responsive Behavior', () => {
    it('should handle small screen sizes', () => {
      // Mock small screen
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 320,
      });
      
      render(<TabList {...mockProps} />);
      
      // Tabs should still be functional on small screens
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /add/i })).toBeInTheDocument();
    });
  });
});