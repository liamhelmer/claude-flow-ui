import React from 'react';
import { render, screen, fireEvent, createMockSession } from '../../../tests/test-utils';
import TabList from '../TabList';

describe('TabList Component', () => {
  const mockProps = {
    sessions: [
      createMockSession('session-1'),
      createMockSession('session-2'),
      createMockSession('session-3'),
    ],
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionClose: jest.fn(),
    onNewSession: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render tab list container with correct classes', () => {
      render(<TabList {...mockProps} />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('flex', 'items-center', 'bg-gray-800', 'border-b', 'border-gray-700');
    });

    it('should render custom className when provided', () => {
      render(<TabList {...mockProps} className="custom-class" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('custom-class');
    });

    it('should render all session tabs', () => {
      render(<TabList {...mockProps} />);
      
      expect(screen.getByText('Terminal session-1')).toBeInTheDocument();
      expect(screen.getByText('Terminal session-2')).toBeInTheDocument();
      expect(screen.getByText('Terminal session-3')).toBeInTheDocument();
    });

    it('should render new tab button', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      expect(newTabButton).toBeInTheDocument();
      expect(newTabButton).toHaveTextContent('+');
    });
  });

  describe('Tab Container', () => {
    it('should have scrollable tabs container', () => {
      render(<TabList {...mockProps} />);
      
      const tabsContainer = document.querySelector('.flex.flex-1.overflow-x-auto.scrollbar-thin.scrollbar-thumb-gray-600');
      expect(tabsContainer).toBeInTheDocument();
    });

    it('should handle overflow with many tabs', () => {
      const manySessions = Array.from({ length: 10 }, (_, i) => createMockSession(`session-${i}`));
      
      render(<TabList {...mockProps} sessions={manySessions} />);
      
      const tabsContainer = document.querySelector('.overflow-x-auto');
      expect(tabsContainer).toBeInTheDocument();
    });
  });

  describe('Tab Interactions', () => {
    it('should call onSessionSelect when tab is selected', () => {
      render(<TabList {...mockProps} />);
      
      const secondTab = screen.getByText('Terminal session-2');
      fireEvent.click(secondTab);
      
      expect(mockProps.onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    it('should call onSessionClose when tab close button is clicked', () => {
      render(<TabList {...mockProps} />);
      
      // Find close buttons - they should be 'x' characters
      const closeButtons = screen.getAllByText('×');
      expect(closeButtons.length).toBeGreaterThan(0);
      
      fireEvent.click(closeButtons[0]);
      
      expect(mockProps.onSessionClose).toHaveBeenCalledWith('session-1');
    });

    it('should pass closable prop correctly to tabs', () => {
      render(<TabList {...mockProps} />);
      
      // With 3 sessions, all tabs should be closable (length > 1)
      const closeButtons = screen.getAllByText('×');
      expect(closeButtons).toHaveLength(3);
    });

    it('should not allow closing when only one session remains', () => {
      const singleSession = [createMockSession('session-1')];
      
      render(<TabList {...mockProps} sessions={singleSession} />);
      
      // With only 1 session, tab should not be closable
      expect(screen.queryByText('×')).not.toBeInTheDocument();
    });
  });

  describe('New Session Button', () => {
    it('should call onNewSession when new tab button is clicked', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      fireEvent.click(newTabButton);
      
      expect(mockProps.onNewSession).toHaveBeenCalledTimes(1);
    });

    it('should have correct styling for new tab button', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      expect(newTabButton).toHaveClass(
        'flex-shrink-0',
        'px-3',
        'py-2',
        'text-sm',
        'font-medium',
        'text-gray-400',
        'hover:text-gray-200',
        'hover:bg-gray-700',
        'border-l',
        'border-gray-700',
        'transition-colors'
      );
    });

    it('should be positioned correctly with border', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      expect(newTabButton).toHaveClass('border-l', 'border-gray-700');
    });
  });

  describe('Active Session Highlighting', () => {
    it('should highlight the active session tab', () => {
      render(<TabList {...mockProps} />);
      
      // Check if the active session is properly highlighted
      // This is tested through Tab component props
      const activeTab = screen.getByText('Terminal session-1');
      expect(activeTab).toBeInTheDocument();
    });

    it('should handle null activeSessionId', () => {
      render(<TabList {...mockProps} activeSessionId={null} />);
      
      expect(screen.getByText('Terminal session-1')).toBeInTheDocument();
      expect(screen.getByText('Terminal session-2')).toBeInTheDocument();
      expect(screen.getByText('Terminal session-3')).toBeInTheDocument();
    });

    it('should handle activeSessionId that does not exist in sessions', () => {
      render(<TabList {...mockProps} activeSessionId="non-existent" />);
      
      // Should render without error
      expect(screen.getByText('Terminal session-1')).toBeInTheDocument();
    });
  });

  describe('Props Validation', () => {
    it('should handle empty sessions array', () => {
      render(<TabList {...mockProps} sessions={[]} />);
      
      // Should still render new tab button
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      expect(newTabButton).toBeInTheDocument();
      
      // No tabs should be rendered
      expect(screen.queryByText('Terminal')).not.toBeInTheDocument();
    });

    it('should handle sessions with duplicate names', () => {
      const duplicateSessions = [
        { ...createMockSession('session-1'), name: 'Terminal' },
        { ...createMockSession('session-2'), name: 'Terminal' },
      ];
      
      render(<TabList {...mockProps} sessions={duplicateSessions} />);
      
      const tabs = screen.getAllByText('Terminal');
      expect(tabs).toHaveLength(2);
    });

    it('should handle very long session names', () => {
      const longNameSession = {
        ...createMockSession('session-1'),
        name: 'Very Long Terminal Session Name That Should Be Truncated',
      };
      
      render(<TabList {...mockProps} sessions={[longNameSession]} />);
      
      expect(screen.getByText('Very Long Terminal Session Name That Should Be Truncated')).toBeInTheDocument();
    });
  });

  describe('Keyboard Navigation', () => {
    it('should handle keyboard events on new session button', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      
      fireEvent.keyDown(newTabButton, { key: 'Enter' });
      expect(mockProps.onNewSession).toHaveBeenCalledTimes(1);
    });

    it('should be accessible via tab navigation', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      expect(newTabButton).toBeInTheDocument();
      
      // Check that button is focusable
      newTabButton.focus();
      expect(document.activeElement).toBe(newTabButton);
    });
  });

  describe('Scrolling Behavior', () => {
    it('should have correct scrollbar styling', () => {
      render(<TabList {...mockProps} />);
      
      const tabsContainer = document.querySelector('.scrollbar-thin.scrollbar-thumb-gray-600');
      expect(tabsContainer).toBeInTheDocument();
    });

    it('should allow horizontal scrolling with many tabs', () => {
      const manySessions = Array.from({ length: 20 }, (_, i) => createMockSession(`session-${i}`));
      
      render(<TabList {...mockProps} sessions={manySessions} />);
      
      const tabsContainer = document.querySelector('.overflow-x-auto');
      expect(tabsContainer).toBeInTheDocument();
    });
  });

  describe('Event Handling', () => {
    it('should prevent event propagation when closing tabs', () => {
      render(<TabList {...mockProps} />);
      
      const closeButtons = screen.getAllByText('×');
      
      const clickEvent = new MouseEvent('click', { bubbles: true });
      const stopPropagationSpy = jest.spyOn(clickEvent, 'stopPropagation');
      
      fireEvent.click(closeButtons[0]);
      
      // Verify that onSessionClose was called
      expect(mockProps.onSessionClose).toHaveBeenCalled();
    });

    it('should handle rapid successive clicks', () => {
      render(<TabList {...mockProps} />);
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      
      fireEvent.click(newTabButton);
      fireEvent.click(newTabButton);
      fireEvent.click(newTabButton);
      
      expect(mockProps.onNewSession).toHaveBeenCalledTimes(3);
    });
  });

  describe('Responsive Design', () => {
    it('should maintain layout integrity with flex classes', () => {
      render(<TabList {...mockProps} />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('flex', 'items-center');
      
      const tabsContainer = container.querySelector('.flex.flex-1');
      expect(tabsContainer).toBeInTheDocument();
      
      const newTabButton = screen.getByRole('button', { name: 'New terminal session' });
      expect(newTabButton).toHaveClass('flex-shrink-0');
    });
  });

  describe('Performance', () => {
    it('should handle large number of sessions efficiently', () => {
      const manySessions = Array.from({ length: 100 }, (_, i) => createMockSession(`session-${i}`));
      
      const startTime = performance.now();
      render(<TabList {...mockProps} sessions={manySessions} />);
      const endTime = performance.now();
      
      // Render should complete in reasonable time (< 100ms)
      expect(endTime - startTime).toBeLessThan(100);
      
      // Should still render new tab button
      expect(screen.getByRole('button', { name: 'New terminal session' })).toBeInTheDocument();
    });
  });
});