import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MonitoringSidebar from '../MonitoringSidebar';

// Mock child components
jest.mock('../AgentsPanel', () => {
  return function MockAgentsPanel() {
    return <div data-testid="agents-panel">Agents Panel</div>;
  };
});

jest.mock('../MemoryPanel', () => {
  return function MockMemoryPanel() {
    return <div data-testid="memory-panel">Memory Panel</div>;
  };
});

jest.mock('../CommandsPanel', () => {
  return function MockCommandsPanel() {
    return <div data-testid="commands-panel">Commands Panel</div>;
  };
});

jest.mock('../PromptPanel', () => {
  return function MockPromptPanel() {
    return <div data-testid="prompt-panel">Prompt Panel</div>;
  };
});

describe('MonitoringSidebar - Comprehensive Tests', () => {
  const defaultProps = {
    isOpen: true,
    onToggle: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render all monitoring panels when open', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();
      expect(screen.getByTestId('memory-panel')).toBeInTheDocument();
      expect(screen.getByTestId('commands-panel')).toBeInTheDocument();
      expect(screen.getByTestId('prompt-panel')).toBeInTheDocument();
    });

    it('should render toggle button', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      expect(screen.getByLabelText('Toggle monitoring sidebar')).toBeInTheDocument();
    });

    it('should render title when open', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      expect(screen.getByText('System Monitor')).toBeInTheDocument();
    });

    it('should not render title when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      expect(screen.queryByText('System Monitor')).not.toBeInTheDocument();
    });

    it('should render with correct width when open', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('w-80');
    });

    it('should render with collapsed width when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('w-12');
    });
  });

  describe('Panel Visibility', () => {
    it('should show all panels when sidebar is open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      expect(screen.getByTestId('agents-panel')).toBeVisible();
      expect(screen.getByTestId('memory-panel')).toBeVisible();
      expect(screen.getByTestId('commands-panel')).toBeVisible();
      expect(screen.getByTestId('prompt-panel')).toBeVisible();
    });

    it('should hide panels when sidebar is closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      expect(screen.queryByTestId('agents-panel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('memory-panel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('commands-panel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('prompt-panel')).not.toBeInTheDocument();
    });
  });

  describe('Toggle Functionality', () => {
    it('should call onToggle when toggle button is clicked', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} />);
      
      await user.click(screen.getByLabelText('Toggle monitoring sidebar'));
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should call onToggle when toggle button is activated via keyboard', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      toggleButton.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should call onToggle when toggle button is activated via space', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      toggleButton.focus();
      await user.keyboard(' ');
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });
  });

  describe('Toggle Button Icon', () => {
    it('should show expand icon when sidebar is closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      const icon = toggleButton.querySelector('svg');
      expect(icon).toBeInTheDocument();
    });

    it('should show collapse icon when sidebar is open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      const icon = toggleButton.querySelector('svg');
      expect(icon).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have correct ARIA attributes', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveAttribute('aria-label', 'System monitoring sidebar');
    });

    it('should have accessible toggle button', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      expect(toggleButton).toHaveAttribute('type', 'button');
      expect(toggleButton).toHaveAttribute('tabIndex', '0');
    });

    it('should be keyboard navigable', async () => {
      const user = userEvent.setup();
      render(
        <div>
          <button>Previous focusable</button>
          <MonitoringSidebar {...defaultProps} />
          <button>Next focusable</button>
        </div>
      );
      
      await user.tab();
      expect(screen.getByText('Previous focusable')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByLabelText('Toggle monitoring sidebar')).toHaveFocus();
    });

    it('should announce state changes to screen readers', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveAttribute('aria-expanded', 'false');
      
      rerender(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      expect(sidebar).toHaveAttribute('aria-expanded', 'true');
    });
  });

  describe('Layout and Styling', () => {
    it('should apply correct CSS classes for open state', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass(
        'fixed',
        'right-0',
        'top-0',
        'h-full',
        'bg-gray-900',
        'border-l',
        'border-gray-700',
        'transition-all',
        'duration-300',
        'z-40',
        'w-80'
      );
    });

    it('should apply correct CSS classes for closed state', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass(
        'fixed',
        'right-0',
        'top-0',
        'h-full',
        'bg-gray-900',
        'border-l',
        'border-gray-700',
        'transition-all',
        'duration-300',
        'z-40',
        'w-12'
      );
    });

    it('should position toggle button correctly when open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      expect(toggleButton).toHaveClass(
        'absolute',
        'left-4',
        'top-4',
        'p-2',
        'text-gray-400',
        'hover:text-gray-200',
        'transition-colors'
      );
    });

    it('should position toggle button correctly when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      expect(toggleButton).toHaveClass(
        'absolute',
        'left-2',
        'top-4',
        'p-1',
        'text-gray-400',
        'hover:text-gray-200',
        'transition-colors'
      );
    });

    it('should apply correct styles to content area when open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const contentArea = screen.getByTestId('agents-panel').closest('.overflow-y-auto');
      expect(contentArea).toHaveClass(
        'flex-1',
        'overflow-y-auto',
        'p-4',
        'pt-16'
      );
    });
  });

  describe('Responsive Behavior', () => {
    it('should handle window resize gracefully', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      // Simulate window resize
      fireEvent(window, new Event('resize'));
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();
    });

    it('should maintain position on scroll', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      // Simulate scroll
      fireEvent.scroll(window, { target: { scrollY: 100 } });
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('fixed');
    });
  });

  describe('Animation and Transitions', () => {
    it('should have transition classes', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('transition-all', 'duration-300');
    });

    it('should animate width changes', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('w-12');
      
      rerender(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      expect(sidebar).toHaveClass('w-80');
    });
  });

  describe('Edge Cases', () => {
    it('should handle undefined onToggle gracefully', () => {
      const props = {
        ...defaultProps,
        onToggle: undefined as any,
      };
      
      expect(() => {
        render(<MonitoringSidebar {...props} />);
      }).not.toThrow();
    });

    it('should handle rapid toggle clicks', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      
      await user.click(toggleButton);
      await user.click(toggleButton);
      await user.click(toggleButton);
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(3);
    });

    it('should handle focus events properly', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} />);
      
      const toggleButton = screen.getByLabelText('Toggle monitoring sidebar');
      
      await user.click(toggleButton);
      expect(toggleButton).toHaveFocus();
    });
  });

  describe('Performance', () => {
    it('should not re-render unnecessarily', () => {
      const renderSpy = jest.fn();
      const TestMonitoringSidebar = (props: any) => {
        renderSpy();
        return <MonitoringSidebar {...props} />;
      };
      
      const { rerender } = render(<TestMonitoringSidebar {...defaultProps} />);
      expect(renderSpy).toHaveBeenCalledTimes(1);
      
      // Re-render with same props
      rerender(<TestMonitoringSidebar {...defaultProps} />);
      expect(renderSpy).toHaveBeenCalledTimes(2);
    });

    it('should handle frequent state changes efficiently', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      for (let i = 0; i < 10; i++) {
        rerender(<MonitoringSidebar {...defaultProps} isOpen={i % 2 === 0} />);
      }
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();
    });
  });

  describe('Z-Index and Layering', () => {
    it('should have appropriate z-index for overlay', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('z-40');
    });

    it('should position above main content', () => {
      render(
        <div>
          <div className="z-10">Main content</div>
          <MonitoringSidebar {...defaultProps} />
        </div>
      );
      
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('z-40');
    });
  });

  describe('Content Overflow', () => {
    it('should handle overflow correctly when open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const scrollContainer = screen.getByTestId('agents-panel').closest('.overflow-y-auto');
      expect(scrollContainer).toHaveClass('overflow-y-auto');
    });

    it('should hide overflow when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      // Content should not be rendered when closed
      expect(screen.queryByTestId('agents-panel')).not.toBeInTheDocument();
    });
  });

  describe('Integration with Child Components', () => {
    it('should render all expected child components', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const expectedPanels = [
        'agents-panel',
        'memory-panel', 
        'commands-panel',
        'prompt-panel'
      ];
      
      expectedPanels.forEach(panelId => {
        expect(screen.getByTestId(panelId)).toBeInTheDocument();
      });
    });

    it('should maintain component order', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      
      const panels = screen.getAllByTestId(/-panel$/);
      expect(panels[0]).toHaveTextContent('Agents Panel');
      expect(panels[1]).toHaveTextContent('Memory Panel');
      expect(panels[2]).toHaveTextContent('Commands Panel');
      expect(panels[3]).toHaveTextContent('Prompt Panel');
    });
  });
});