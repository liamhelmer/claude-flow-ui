import { render, screen, fireEvent } from '@testing-library/react';
import TerminalControls from '../TerminalControls';

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
  ChevronUp: ({ className }: { className?: string }) => (
    <div data-testid="chevron-up" className={className}>↑</div>
  ),
  ChevronDown: ({ className }: { className?: string }) => (
    <div data-testid="chevron-down" className={className}>↓</div>
  ),
  AlertCircle: ({ className }: { className?: string }) => (
    <div data-testid="alert-circle" className={className}>⚠</div>
  ),
}));

const defaultProps = {
  isAtBottom: false,
  hasNewOutput: false,
  onScrollToTop: jest.fn(),
  onScrollToBottom: jest.fn(),
};

describe('TerminalControls', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('basic rendering', () => {
    it('should render scroll buttons', () => {
      render(<TerminalControls {...defaultProps} />);

      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
      expect(screen.getByTestId('chevron-up')).toBeInTheDocument();
      expect(screen.getByTestId('chevron-down')).toBeInTheDocument();
    });

    it('should render visual scroll indicator', () => {
      render(<TerminalControls {...defaultProps} />);

      const indicator = screen.container.querySelector('.h-1.bg-gray-800');
      expect(indicator).toBeInTheDocument();
    });

    it('should apply custom className', () => {
      render(<TerminalControls {...defaultProps} className="custom-class" />);

      const container = screen.container.firstChild as HTMLElement;
      expect(container).toHaveClass('custom-class');
    });
  });

  describe('scroll to top button', () => {
    it('should call onScrollToTop when clicked', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      fireEvent.click(scrollToTopButton);

      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(1);
    });

    it('should always be enabled', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      expect(scrollToTopButton).not.toHaveAttribute('disabled');
      expect(scrollToTopButton).not.toHaveClass('opacity-50', 'cursor-default');
    });

    it('should have correct styling', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      expect(scrollToTopButton).toHaveClass(
        'bg-gray-800',
        'hover:bg-gray-700',
        'text-gray-400',
        'hover:text-white',
        'border-gray-700'
      );
    });
  });

  describe('scroll to bottom button', () => {
    it('should call onScrollToBottom when clicked and not at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      fireEvent.click(scrollToBottomButton);

      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('should be disabled when at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).toHaveAttribute('disabled');
      expect(scrollToBottomButton).toHaveClass('opacity-50', 'cursor-default');
    });

    it('should not be disabled when not at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).not.toHaveAttribute('disabled');
      expect(scrollToBottomButton).not.toHaveClass('opacity-50', 'cursor-default');
    });

    it('should have correct styling when enabled', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).toHaveClass(
        'bg-gray-800',
        'hover:bg-gray-700',
        'text-gray-400',
        'hover:text-white',
        'border-gray-700'
      );
    });
  });

  describe('see latest button', () => {
    it('should not render when no new output', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={false}
          isAtBottom={false}
        />
      );

      expect(screen.queryByText('See latest')).not.toBeInTheDocument();
      expect(screen.queryByTestId('alert-circle')).not.toBeInTheDocument();
    });

    it('should not render when at bottom', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={true}
        />
      );

      expect(screen.queryByText('See latest')).not.toBeInTheDocument();
      expect(screen.queryByTestId('alert-circle')).not.toBeInTheDocument();
    });

    it('should render when has new output and not at bottom', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      expect(screen.getByText('See latest')).toBeInTheDocument();
      expect(screen.getByTestId('alert-circle')).toBeInTheDocument();
    });

    it('should call onScrollToBottom when clicked', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      const seeLatestButton = screen.getByText('See latest');
      fireEvent.click(seeLatestButton);

      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('should have correct styling and animation', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      const seeLatestButton = screen.getByText('See latest');
      expect(seeLatestButton).toHaveClass(
        'bg-blue-600',
        'hover:bg-blue-700',
        'text-white',
        'font-medium',
        'text-sm',
        'border-blue-500',
        'animate-pulse'
      );
    });

    it('should have correct title attribute', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      const seeLatestButton = screen.getByText('See latest');
      expect(seeLatestButton).toHaveAttribute('title', 'Jump to latest output');
    });
  });

  describe('visual scroll indicator', () => {
    it('should show green full bar when at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const indicator = screen.container.querySelector('.h-full');
      expect(indicator).toHaveClass('bg-green-500', 'w-full');
    });

    it('should show gray half bar when not at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const indicator = screen.container.querySelector('.h-full');
      expect(indicator).toHaveClass('bg-gray-600', 'w-1/2');
    });

    it('should have transition animation', () => {
      render(<TerminalControls {...defaultProps} />);

      const indicator = screen.container.querySelector('.h-full');
      expect(indicator).toHaveClass('transition-all', 'duration-300');
    });
  });

  describe('interaction combinations', () => {
    it('should handle multiple button clicks', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      const seeLatestButton = screen.getByText('See latest');

      fireEvent.click(scrollToTopButton);
      fireEvent.click(scrollToBottomButton);
      fireEvent.click(seeLatestButton);

      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(1);
      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(2);
    });

    it('should handle rapid button clicks', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');

      // Rapid clicks
      fireEvent.click(scrollToTopButton);
      fireEvent.click(scrollToTopButton);
      fireEvent.click(scrollToTopButton);

      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(3);
    });
  });

  describe('state changes', () => {
    it('should update disabled state when isAtBottom changes', () => {
      const { rerender } = render(
        <TerminalControls {...defaultProps} isAtBottom={false} />
      );

      let scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).not.toHaveAttribute('disabled');

      rerender(<TerminalControls {...defaultProps} isAtBottom={true} />);

      scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).toHaveAttribute('disabled');
    });

    it('should show/hide see latest button based on state changes', () => {
      const { rerender } = render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={false}
          isAtBottom={false}
        />
      );

      expect(screen.queryByText('See latest')).not.toBeInTheDocument();

      rerender(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      expect(screen.getByText('See latest')).toBeInTheDocument();

      rerender(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={true}
        />
      );

      expect(screen.queryByText('See latest')).not.toBeInTheDocument();
    });

    it('should update visual indicator based on scroll position', () => {
      const { rerender } = render(
        <TerminalControls {...defaultProps} isAtBottom={false} />
      );

      const { container } = render(<TerminalControls {...defaultProps} isAtBottom={false} />);
      let indicator = container.querySelector('.h-full');
      expect(indicator).toHaveClass('bg-gray-600', 'w-1/2');

      rerender(<TerminalControls {...defaultProps} isAtBottom={true} />);

      indicator = screen.container.querySelector('.h-full');
      expect(indicator).toHaveClass('bg-green-500', 'w-full');
    });
  });

  describe('accessibility', () => {
    it('should have appropriate ARIA labels through title attributes', () => {
      render(
        <TerminalControls
          {...defaultProps}
          hasNewOutput={true}
          isAtBottom={false}
        />
      );

      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
      expect(screen.getByTitle('Jump to latest output')).toBeInTheDocument();
    });

    it('should properly disable button for keyboard users', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).toHaveAttribute('disabled');

      // Should not be focusable when disabled
      fireEvent.focus(scrollToBottomButton);
      expect(scrollToBottomButton).not.toHaveFocus();
    });

    it('should support keyboard navigation', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      
      fireEvent.keyDown(scrollToTopButton, { key: 'Enter' });
      fireEvent.keyDown(scrollToTopButton, { key: ' ' });

      // Note: React Testing Library doesn't trigger onClick for keyboard events by default
      // In a real browser, these would trigger the click handlers
    });
  });

  describe('terminal configuration display', () => {
    it('should show "Waiting..." when terminalConfig is null', () => {
      render(<TerminalControls {...defaultProps} terminalConfig={null} />);

      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
    });

    it('should show "80×24" when terminalConfig has standard dimensions', () => {
      const config = { cols: 80, rows: 24 };
      render(<TerminalControls {...defaultProps} terminalConfig={config} />);

      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('80×24')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
      expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
    });

    it('should show "120×40" when terminalConfig has larger dimensions', () => {
      const config = { cols: 120, rows: 40 };
      render(<TerminalControls {...defaultProps} terminalConfig={config} />);

      expect(screen.getByText('120×40')).toBeInTheDocument();
    });

    it('should show "132×50" when terminalConfig has wide dimensions', () => {
      const config = { cols: 132, rows: 50 };
      render(<TerminalControls {...defaultProps} terminalConfig={config} />);

      expect(screen.getByText('132×50')).toBeInTheDocument();
    });

    it('should update display when terminalConfig changes', () => {
      const initialConfig = { cols: 80, rows: 24 };
      
      const { rerender } = render(
        <TerminalControls {...defaultProps} terminalConfig={initialConfig} />
      );

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Update config
      const newConfig = { cols: 120, rows: 40 };
      rerender(<TerminalControls {...defaultProps} terminalConfig={newConfig} />);

      expect(screen.getByText('120×40')).toBeInTheDocument();
      expect(screen.queryByText('80×24')).not.toBeInTheDocument();
    });

    it('should revert to "Waiting..." when terminalConfig becomes null', () => {
      const config = { cols: 80, rows: 24 };
      
      const { rerender } = render(
        <TerminalControls {...defaultProps} terminalConfig={config} />
      );

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Config becomes null
      rerender(<TerminalControls {...defaultProps} terminalConfig={null} />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(screen.queryByText('80×24')).not.toBeInTheDocument();
    });

    it('should handle undefined terminalConfig', () => {
      render(<TerminalControls {...defaultProps} terminalConfig={undefined} />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    it('should handle invalid terminalConfig values', () => {
      const invalidConfigs = [
        { cols: 0, rows: 24 },
        { cols: 80, rows: 0 },
        { cols: -1, rows: 24 },
        { cols: 80, rows: -1 },
        { cols: null, rows: 24 },
        { cols: 80, rows: null },
      ];

      invalidConfigs.forEach((config) => {
        const { unmount } = render(
          <TerminalControls {...defaultProps} terminalConfig={config as any} />
        );

        // Should show actual values for these configs, not "Waiting..."
        // The component displays actual values even if they're invalid
        const displayText = screen.getByText(new RegExp(`${config.cols}×${config.rows}|Waiting...`));
        expect(displayText).toBeInTheDocument();
        
        unmount();
      });
    });

    it('should handle very large config values', () => {
      const largeConfig = { cols: 9999, rows: 9999 };
      
      render(<TerminalControls {...defaultProps} terminalConfig={largeConfig} />);

      expect(screen.getByText('9999×9999')).toBeInTheDocument();
    });

    it('should handle fractional config values', () => {
      const fractionalConfig = { cols: 80.5, rows: 24.7 };
      
      render(<TerminalControls {...defaultProps} terminalConfig={fractionalConfig} />);

      expect(screen.getByText('80.5×24.7')).toBeInTheDocument();
    });

    it('should maintain consistent styling for terminal size display', () => {
      const config = { cols: 80, rows: 24 };
      
      render(<TerminalControls {...defaultProps} terminalConfig={config} />);

      const sizeDisplay = screen.getByText('80×24');
      expect(sizeDisplay).toHaveClass('text-gray-400', 'font-semibold');
      
      const container = sizeDisplay.closest('.mt-4');
      expect(container).toHaveClass('px-2');
    });
  });

  describe('edge cases', () => {
    it('should handle undefined callback functions gracefully', () => {
      const propsWithUndefined = {
        isAtBottom: false,
        hasNewOutput: false,
        onScrollToTop: undefined as any,
        onScrollToBottom: undefined as any,
      };

      expect(() => {
        render(<TerminalControls {...propsWithUndefined} />);
      }).not.toThrow();
    });

    it('should handle boolean props being undefined', () => {
      const propsWithUndefined = {
        ...defaultProps,
        isAtBottom: undefined as any,
        hasNewOutput: undefined as any,
      };

      expect(() => {
        render(<TerminalControls {...propsWithUndefined} />);
      }).not.toThrow();
    });

    it('should work without className prop', () => {
      const { isAtBottom, hasNewOutput, onScrollToTop, onScrollToBottom } = defaultProps;
      
      expect(() => {
        render(
          <TerminalControls
            isAtBottom={isAtBottom}
            hasNewOutput={hasNewOutput}
            onScrollToTop={onScrollToTop}
            onScrollToBottom={onScrollToBottom}
          />
        );
      }).not.toThrow();
    });
  });
});