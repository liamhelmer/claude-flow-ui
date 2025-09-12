import React from 'react';
import { render, screen, fireEvent, waitFor } from '@/tests/test-utils';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import TerminalControls from '../TerminalControls';

expect.extend(toHaveNoViolations);

describe('TerminalControls Enhanced Tests', () => {
  const defaultProps = {
    isAtBottom: false,
    hasNewOutput: false,
    onScrollToTop: jest.fn(),
    onScrollToBottom: jest.fn(),
    terminalConfig: { cols: 80, rows: 24 }
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('renders all control buttons', () => {
      render(<TerminalControls {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: 'Scroll to top' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Scroll to bottom' })).toBeInTheDocument();
    });

    it('displays terminal size when config is provided', () => {
      render(<TerminalControls {...defaultProps} />);
      
      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('80×24')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
    });

    it('shows waiting message when terminal config is null', () => {
      render(<TerminalControls {...defaultProps} terminalConfig={null} />);
      
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    it('shows waiting message when terminal config is undefined', () => {
      render(<TerminalControls {...defaultProps} terminalConfig={undefined} />);
      
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    it('applies custom className when provided', () => {
      const { container } = render(<TerminalControls {...defaultProps} className="custom-class" />);
      
      expect(container.firstChild).toHaveClass('custom-class');
    });
  });

  describe('Scroll Position Indicator', () => {
    it('shows green full indicator when at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);
      
      const indicator = document.querySelector('.bg-green-500.w-full');
      expect(indicator).toBeInTheDocument();
    });

    it('shows gray partial indicator when not at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);
      
      const indicator = document.querySelector('.bg-gray-600.w-1\\/2');
      expect(indicator).toBeInTheDocument();
    });

    it('applies transition classes to indicator', () => {
      render(<TerminalControls {...defaultProps} />);
      
      const indicator = document.querySelector('.transition-all.duration-300');
      expect(indicator).toBeInTheDocument();
    });
  });

  describe('See Latest Button Behavior', () => {
    it('shows see latest button when there is new output and not at bottom', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      expect(screen.getByRole('button', { name: 'Jump to latest output' })).toBeInTheDocument();
      expect(screen.getByText('See latest')).toBeInTheDocument();
    });

    it('hides see latest button when at bottom', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={true} />);
      
      expect(screen.queryByRole('button', { name: 'Jump to latest output' })).not.toBeInTheDocument();
    });

    it('hides see latest button when no new output', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={false} isAtBottom={false} />);
      
      expect(screen.queryByRole('button', { name: 'Jump to latest output' })).not.toBeInTheDocument();
    });

    it('applies animation to see latest button', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Jump to latest output' });
      expect(button).toHaveClass('animate-pulse');
    });

    it('calls onScrollToBottom when see latest button is clicked', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Jump to latest output' });
      await user.click(button);
      
      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });
  });

  describe('Scroll Button States', () => {
    it('disables scroll to bottom button when at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to bottom' });
      expect(button).toBeDisabled();
      expect(button).toHaveClass('opacity-50', 'cursor-default');
    });

    it('enables scroll to bottom button when not at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to bottom' });
      expect(button).not.toBeDisabled();
      expect(button).not.toHaveClass('opacity-50', 'cursor-default');
    });

    it('scroll to top button is always enabled', () => {
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to top' });
      expect(button).not.toBeDisabled();
    });
  });

  describe('Button Click Handlers', () => {
    it('calls onScrollToTop when scroll to top button is clicked', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to top' });
      await user.click(button);
      
      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(1);
    });

    it('calls onScrollToBottom when scroll to bottom button is clicked', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to bottom' });
      await user.click(button);
      
      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('does not call handler when disabled scroll to bottom button is clicked', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to bottom' });
      await user.click(button);
      
      // Should not be called because button is disabled
      expect(defaultProps.onScrollToBottom).not.toHaveBeenCalled();
    });
  });

  describe('Keyboard Navigation', () => {
    it('supports keyboard navigation on scroll to top button', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to top' });
      button.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(1);
    });

    it('supports keyboard navigation on scroll to bottom button', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to bottom' });
      button.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('supports keyboard navigation on see latest button', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Jump to latest output' });
      button.focus();
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('handles tab navigation between buttons', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const topButton = screen.getByRole('button', { name: 'Scroll to top' });
      topButton.focus();
      
      await user.keyboard('{Tab}');
      expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Jump to latest output' }));
      
      await user.keyboard('{Tab}');
      expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Scroll to bottom' }));
    });
  });

  describe('Icon Rendering', () => {
    it('renders ChevronUp icon in scroll to top button', () => {
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to top' });
      const icon = button.querySelector('svg');
      expect(icon).toBeInTheDocument();
      expect(icon).toHaveClass('w-5', 'h-5');
    });

    it('renders ChevronDown icon in scroll to bottom button', () => {
      render(<TerminalControls {...defaultProps} />);
      
      const button = screen.getByRole('button', { name: 'Scroll to bottom' });
      const icon = button.querySelector('svg');
      expect(icon).toBeInTheDocument();
      expect(icon).toHaveClass('w-5', 'h-5');
    });

    it('renders AlertCircle icon in see latest button', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Jump to latest output' });
      const icon = button.querySelector('svg');
      expect(icon).toBeInTheDocument();
      expect(icon).toHaveClass('w-4', 'h-4');
    });
  });

  describe('Terminal Config Display', () => {
    it('handles various terminal config values', () => {
      const configs = [
        { cols: 120, rows: 30 },
        { cols: 40, rows: 10 },
        { cols: 1, rows: 1 },
        { cols: 999, rows: 999 }
      ];
      
      configs.forEach(config => {
        const { rerender } = render(<TerminalControls {...defaultProps} terminalConfig={config} />);
        
        expect(screen.getByText(`${config.cols}×${config.rows}`)).toBeInTheDocument();
        
        rerender(<div />); // Clear for next iteration
      });
    });

    it('applies correct styling to terminal size display', () => {
      render(<TerminalControls {...defaultProps} />);
      
      const sizeDisplay = screen.getByText('80×24');
      expect(sizeDisplay).toHaveClass('text-gray-400', 'font-semibold');
      
      const backendLabel = screen.getByText('Backend');
      expect(backendLabel).toHaveClass('text-gray-600');
    });
  });

  describe('Styling and Layout', () => {
    it('applies correct container classes', () => {
      const { container } = render(<TerminalControls {...defaultProps} />);
      
      expect(container.firstChild).toHaveClass('flex', 'flex-col', 'gap-2', 'p-2');
    });

    it('applies correct button styling', () => {
      render(<TerminalControls {...defaultProps} />);
      
      const topButton = screen.getByRole('button', { name: 'Scroll to top' });
      expect(topButton).toHaveClass(
        'flex', 'items-center', 'justify-center', 'p-2', 'rounded-lg',
        'bg-gray-800', 'hover:bg-gray-700', 'transition-colors',
        'text-gray-400', 'hover:text-white',
        'border', 'border-gray-700', 'group'
      );
    });

    it('applies special styling to see latest button', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Jump to latest output' });
      expect(button).toHaveClass(
        'bg-blue-600', 'hover:bg-blue-700',
        'text-white', 'font-medium', 'text-sm',
        'border-blue-500', 'animate-pulse'
      );
    });
  });

  describe('Accessibility', () => {
    it('has no accessibility violations', async () => {
      const { container } = render(<TerminalControls {...defaultProps} />);
      const results = await axe(container);
      
      expect(results).toHaveNoViolations();
    });

    it('provides proper button titles and labels', () => {
      render(<TerminalControls {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: 'Scroll to top' })).toHaveAttribute('title', 'Scroll to top');
      expect(screen.getByRole('button', { name: 'Scroll to bottom' })).toHaveAttribute('title', 'Scroll to bottom');
    });

    it('provides proper label for see latest button', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const button = screen.getByRole('button', { name: 'Jump to latest output' });
      expect(button).toHaveAttribute('title', 'Jump to latest output');
    });

    it('maintains focus management correctly', async () => {
      const user = userEvent.setup();
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      const buttons = screen.getAllByRole('button');
      
      buttons[0].focus();
      expect(document.activeElement).toBe(buttons[0]);
      
      await user.keyboard('{Tab}');
      expect(document.activeElement).toBe(buttons[1]);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('handles missing callback props gracefully', () => {
      const propsWithoutCallbacks = {
        ...defaultProps,
        onScrollToTop: undefined as any,
        onScrollToBottom: undefined as any
      };
      
      expect(() => render(<TerminalControls {...propsWithoutCallbacks} />)).not.toThrow();
    });

    it('handles rapid prop changes', () => {
      const { rerender } = render(<TerminalControls {...defaultProps} />);
      
      for (let i = 0; i < 10; i++) {
        rerender(
          <TerminalControls 
            {...defaultProps} 
            isAtBottom={i % 2 === 0}
            hasNewOutput={i % 3 === 0}
          />
        );
      }
      
      // Should not throw and should render correctly
      expect(screen.getByRole('button', { name: 'Scroll to top' })).toBeInTheDocument();
    });

    it('handles extreme terminal config values', () => {
      const extremeConfig = { cols: 0, rows: 0 };
      
      expect(() => render(<TerminalControls {...defaultProps} terminalConfig={extremeConfig} />)).not.toThrow();
      expect(screen.getByText('0×0')).toBeInTheDocument();
    });

    it('handles negative terminal config values', () => {
      const negativeConfig = { cols: -10, rows: -5 };
      
      expect(() => render(<TerminalControls {...defaultProps} terminalConfig={negativeConfig} />)).not.toThrow();
      expect(screen.getByText('-10×-5')).toBeInTheDocument();
    });
  });

  describe('Performance', () => {
    it('renders efficiently with frequent updates', () => {
      const { rerender } = render(<TerminalControls {...defaultProps} />);
      
      const startTime = performance.now();
      
      for (let i = 0; i < 50; i++) {
        rerender(
          <TerminalControls
            {...defaultProps}
            isAtBottom={i % 2 === 0}
            hasNewOutput={i % 3 === 0}
            terminalConfig={{ cols: 80 + i, rows: 24 + i }}
          />
        );
      }
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(100);
    });
  });

  describe('Dynamic State Changes', () => {
    it('updates button states correctly when isAtBottom changes', () => {
      const { rerender } = render(<TerminalControls {...defaultProps} isAtBottom={false} />);
      
      let button = screen.getByRole('button', { name: 'Scroll to bottom' });
      expect(button).not.toBeDisabled();
      
      rerender(<TerminalControls {...defaultProps} isAtBottom={true} />);
      
      button = screen.getByRole('button', { name: 'Scroll to bottom' });
      expect(button).toBeDisabled();
    });

    it('shows/hides see latest button based on state changes', () => {
      const { rerender } = render(
        <TerminalControls {...defaultProps} hasNewOutput={false} isAtBottom={false} />
      );
      
      expect(screen.queryByRole('button', { name: 'Jump to latest output' })).not.toBeInTheDocument();
      
      rerender(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);
      
      expect(screen.getByRole('button', { name: 'Jump to latest output' })).toBeInTheDocument();
      
      rerender(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={true} />);
      
      expect(screen.queryByRole('button', { name: 'Jump to latest output' })).not.toBeInTheDocument();
    });

    it('updates scroll position indicator correctly', () => {
      const { rerender } = render(<TerminalControls {...defaultProps} isAtBottom={false} />);
      
      let indicator = document.querySelector('.bg-gray-600');
      expect(indicator).toBeInTheDocument();
      
      rerender(<TerminalControls {...defaultProps} isAtBottom={true} />);
      
      indicator = document.querySelector('.bg-green-500');
      expect(indicator).toBeInTheDocument();
    });
  });
});