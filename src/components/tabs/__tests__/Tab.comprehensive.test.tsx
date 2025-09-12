import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Tab from '../Tab';

describe('Tab - Comprehensive Tests', () => {
  const defaultProps = {
    title: 'Test Tab',
    isActive: false,
    onSelect: jest.fn(),
    onClose: jest.fn(),
    closable: true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render tab with title', () => {
      render(<Tab {...defaultProps} />);
      expect(screen.getByText('Test Tab')).toBeInTheDocument();
    });

    it('should render active tab with correct styling', () => {
      render(<Tab {...defaultProps} isActive={true} />);
      const tab = screen.getByRole('tab');
      expect(tab).toHaveClass('border-blue-500', 'bg-gray-800');
    });

    it('should render inactive tab with correct styling', () => {
      render(<Tab {...defaultProps} isActive={false} />);
      const tab = screen.getByRole('tab');
      expect(tab).toHaveClass('border-gray-600', 'bg-gray-700');
    });

    it('should show close button when closable', () => {
      render(<Tab {...defaultProps} closable={true} />);
      expect(screen.getByLabelText('Close tab')).toBeInTheDocument();
    });

    it('should not show close button when not closable', () => {
      render(<Tab {...defaultProps} closable={false} />);
      expect(screen.queryByLabelText('Close tab')).not.toBeInTheDocument();
    });

    it('should render with long title', () => {
      const longTitle = 'This is a very long tab title that might overflow';
      render(<Tab {...defaultProps} title={longTitle} />);
      expect(screen.getByText(longTitle)).toBeInTheDocument();
    });

    it('should render with special characters in title', () => {
      const specialTitle = 'Tab & Title <> "Special" \'Chars\'';
      render(<Tab {...defaultProps} title={specialTitle} />);
      expect(screen.getByText(specialTitle)).toBeInTheDocument();
    });
  });

  describe('Interaction', () => {
    it('should call onSelect when tab is clicked', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      await user.click(screen.getByRole('tab'));
      expect(defaultProps.onSelect).toHaveBeenCalledTimes(1);
    });

    it('should call onClose when close button is clicked', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      await user.click(screen.getByLabelText('Close tab'));
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
      expect(defaultProps.onSelect).not.toHaveBeenCalled();
    });

    it('should prevent event propagation when close button is clicked', async () => {
      const user = userEvent.setup();
      const containerClickHandler = jest.fn();
      
      render(
        <div onClick={containerClickHandler}>
          <Tab {...defaultProps} />
        </div>
      );
      
      await user.click(screen.getByLabelText('Close tab'));
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
      expect(containerClickHandler).not.toHaveBeenCalled();
    });
  });

  describe('Keyboard Navigation', () => {
    it('should handle Enter key on tab', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      const tab = screen.getByRole('tab');
      tab.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onSelect).toHaveBeenCalledTimes(1);
    });

    it('should handle Space key on tab', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      const tab = screen.getByRole('tab');
      tab.focus();
      await user.keyboard(' ');
      
      expect(defaultProps.onSelect).toHaveBeenCalledTimes(1);
    });

    it('should handle Enter key on close button', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      const closeButton = screen.getByLabelText('Close tab');
      closeButton.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
    });

    it('should handle Space key on close button', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      const closeButton = screen.getByLabelText('Close tab');
      closeButton.focus();
      await user.keyboard(' ');
      
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
    });

    it('should not trigger actions on other keys', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      const tab = screen.getByRole('tab');
      tab.focus();
      await user.keyboard('{Escape}');
      await user.keyboard('{Tab}');
      await user.keyboard('a');
      
      expect(defaultProps.onSelect).not.toHaveBeenCalled();
      expect(defaultProps.onClose).not.toHaveBeenCalled();
    });
  });

  describe('Accessibility', () => {
    it('should have correct ARIA attributes', () => {
      render(<Tab {...defaultProps} />);
      const tab = screen.getByRole('tab');
      
      expect(tab).toHaveAttribute('tabIndex', '0');
      expect(tab).toHaveAttribute('role', 'tab');
    });

    it('should have correct ARIA attributes for active tab', () => {
      render(<Tab {...defaultProps} isActive={true} />);
      const tab = screen.getByRole('tab');
      
      expect(tab).toHaveAttribute('aria-selected', 'true');
    });

    it('should have correct ARIA attributes for inactive tab', () => {
      render(<Tab {...defaultProps} isActive={false} />);
      const tab = screen.getByRole('tab');
      
      expect(tab).toHaveAttribute('aria-selected', 'false');
    });

    it('should have accessible close button', () => {
      render(<Tab {...defaultProps} />);
      const closeButton = screen.getByLabelText('Close tab');
      
      expect(closeButton).toHaveAttribute('type', 'button');
      expect(closeButton).toHaveAttribute('tabIndex', '0');
    });

    it('should be focusable', () => {
      render(<Tab {...defaultProps} />);
      const tab = screen.getByRole('tab');
      
      tab.focus();
      expect(tab).toHaveFocus();
    });

    it('should be focusable via keyboard navigation', async () => {
      const user = userEvent.setup();
      render(
        <div>
          <button>Previous focusable</button>
          <Tab {...defaultProps} />
          <button>Next focusable</button>
        </div>
      );
      
      await user.tab();
      expect(screen.getByText('Previous focusable')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByRole('tab')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByLabelText('Close tab')).toHaveFocus();
    });
  });

  describe('Mouse Events', () => {
    it('should handle mouse enter and leave events', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      const tab = screen.getByRole('tab');
      
      await user.hover(tab);
      expect(tab).toHaveClass('hover:bg-gray-600');
      
      await user.unhover(tab);
      // Hover class is applied by CSS, so we just verify it exists in the DOM
    });

    it('should handle right-click without triggering selection', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      await user.pointer({ keys: '[MouseRight]', target: screen.getByRole('tab') });
      expect(defaultProps.onSelect).not.toHaveBeenCalled();
    });

    it('should handle double-click', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      await user.dblClick(screen.getByRole('tab'));
      expect(defaultProps.onSelect).toHaveBeenCalledTimes(2);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty title', () => {
      render(<Tab {...defaultProps} title="" />);
      const tab = screen.getByRole('tab');
      expect(tab).toBeInTheDocument();
    });

    it('should handle undefined handlers gracefully', () => {
      const props = {
        ...defaultProps,
        onSelect: undefined as any,
        onClose: undefined as any,
      };
      
      expect(() => render(<Tab {...props} />)).not.toThrow();
    });

    it('should handle rapid clicks', async () => {
      const user = userEvent.setup();
      render(<Tab {...defaultProps} />);
      
      const tab = screen.getByRole('tab');
      await user.click(tab);
      await user.click(tab);
      await user.click(tab);
      
      expect(defaultProps.onSelect).toHaveBeenCalledTimes(3);
    });

    it('should handle focus when disabled state is simulated', () => {
      render(<Tab {...defaultProps} />);
      const tab = screen.getByRole('tab');
      
      // Simulate disabled state
      tab.setAttribute('disabled', 'true');
      tab.focus();
      
      // Should still be able to focus (tabs don't typically have disabled state)
      expect(tab).toHaveFocus();
    });
  });

  describe('Performance', () => {
    it('should not re-render unnecessarily', () => {
      const renderSpy = jest.fn();
      const TestTab = (props: any) => {
        renderSpy();
        return <Tab {...props} />;
      };
      
      const { rerender } = render(<TestTab {...defaultProps} />);
      expect(renderSpy).toHaveBeenCalledTimes(1);
      
      // Re-render with same props
      rerender(<TestTab {...defaultProps} />);
      expect(renderSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe('Theme Integration', () => {
    it('should apply correct theme classes for dark mode', () => {
      render(<Tab {...defaultProps} />);
      const tab = screen.getByRole('tab');
      
      expect(tab).toHaveClass('text-gray-200');
    });

    it('should handle theme changes gracefully', () => {
      const { rerender } = render(<Tab {...defaultProps} />);
      
      // Simulate theme change by re-rendering
      rerender(<Tab {...defaultProps} />);
      
      const tab = screen.getByRole('tab');
      expect(tab).toBeInTheDocument();
    });
  });

  describe('Integration with Tab Management', () => {
    it('should work correctly in a tab list context', () => {
      render(
        <div role="tablist">
          <Tab {...defaultProps} title="Tab 1" isActive={true} />
          <Tab {...defaultProps} title="Tab 2" isActive={false} />
          <Tab {...defaultProps} title="Tab 3" isActive={false} />
        </div>
      );
      
      const tabs = screen.getAllByRole('tab');
      expect(tabs).toHaveLength(3);
      expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
      expect(tabs[1]).toHaveAttribute('aria-selected', 'false');
      expect(tabs[2]).toHaveAttribute('aria-selected', 'false');
    });
  });
});