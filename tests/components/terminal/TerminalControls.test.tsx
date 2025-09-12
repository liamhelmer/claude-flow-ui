import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import TerminalControls from '@/components/terminal/TerminalControls';

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
  ChevronUp: () => <div data-testid="chevron-up-icon" />,
  ChevronDown: () => <div data-testid="chevron-down-icon" />,
  AlertCircle: () => <div data-testid="alert-circle-icon" />,
}));

describe('TerminalControls', () => {
  const defaultProps = {
    isAtBottom: false,
    hasNewOutput: false,
    onScrollToTop: jest.fn(),
    onScrollToBottom: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('rendering', () => {
    it('should render all basic controls', () => {
      render(<TerminalControls {...defaultProps} />);

      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
      expect(screen.getByTestId('chevron-up-icon')).toBeInTheDocument();
      expect(screen.getByTestId('chevron-down-icon')).toBeInTheDocument();
    });

    it('should render with custom className', () => {
      const { container } = render(
        <TerminalControls {...defaultProps} className="custom-class" />
      );

      expect(container.firstChild).toHaveClass('custom-class');
    });

    it('should apply correct base styling', () => {
      const { container } = render(<TerminalControls {...defaultProps} />);

      expect(container.firstChild).toHaveClass('flex', 'flex-col', 'gap-2', 'p-2');
    });
  });

  describe('scroll to top button', () => {
    it('should call onScrollToTop when clicked', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      fireEvent.click(scrollToTopButton);

      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(1);
    });

    it('should have correct styling', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      
      expect(scrollToTopButton).toHaveClass(
        'flex',
        'items-center',
        'justify-center',
        'p-2',
        'rounded-lg',
        'bg-gray-800',
        'hover:bg-gray-700',
        'transition-colors',
        'text-gray-400',
        'hover:text-white',
        'border',
        'border-gray-700',
        'group'
      );
    });

    it('should be clickable multiple times', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      
      fireEvent.click(scrollToTopButton);
      fireEvent.click(scrollToTopButton);
      fireEvent.click(scrollToTopButton);

      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(3);
    });
  });

  describe('scroll to bottom button', () => {
    it('should call onScrollToBottom when clicked and not disabled', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      fireEvent.click(scrollToBottomButton);

      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('should be disabled when isAtBottom is true', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      
      expect(scrollToBottomButton).toBeDisabled();
      expect(scrollToBottomButton).toHaveClass('opacity-50', 'cursor-default');
    });

    it('should not call onScrollToBottom when disabled', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      fireEvent.click(scrollToBottomButton);

      expect(defaultProps.onScrollToBottom).not.toHaveBeenCalled();
    });

    it('should have correct styling when enabled', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      
      expect(scrollToBottomButton).toHaveClass(
        'flex',
        'items-center',
        'justify-center',
        'p-2',
        'rounded-lg',
        'bg-gray-800',
        'hover:bg-gray-700',
        'transition-colors',
        'text-gray-400',
        'hover:text-white',
        'border',
        'border-gray-700',
        'group'
      );
      expect(scrollToBottomButton).not.toHaveClass('opacity-50', 'cursor-default');
    });
  });

  describe('see latest button', () => {
    it('should show when hasNewOutput is true and not at bottom', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);

      const seeLatestButton = screen.getByTitle('Jump to latest output');
      expect(seeLatestButton).toBeInTheDocument();
      expect(seeLatestButton).toHaveTextContent('See latest');
      expect(screen.getByTestId('alert-circle-icon')).toBeInTheDocument();
    });

    it('should not show when hasNewOutput is false', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={false} isAtBottom={false} />);

      expect(screen.queryByTitle('Jump to latest output')).not.toBeInTheDocument();
      expect(screen.queryByText('See latest')).not.toBeInTheDocument();
    });

    it('should not show when at bottom even if hasNewOutput is true', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={true} />);

      expect(screen.queryByTitle('Jump to latest output')).not.toBeInTheDocument();
      expect(screen.queryByText('See latest')).not.toBeInTheDocument();
    });

    it('should call onScrollToBottom when clicked', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);

      const seeLatestButton = screen.getByTitle('Jump to latest output');
      fireEvent.click(seeLatestButton);

      expect(defaultProps.onScrollToBottom).toHaveBeenCalledTimes(1);
    });

    it('should have correct styling with animation', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);

      const seeLatestButton = screen.getByTitle('Jump to latest output');
      
      expect(seeLatestButton).toHaveClass(
        'flex',
        'items-center',
        'justify-center',
        'gap-2',
        'px-3',
        'py-2',
        'rounded-lg',
        'bg-blue-600',
        'hover:bg-blue-700',
        'transition-all',
        'text-white',
        'font-medium',
        'text-sm',
        'border',
        'border-blue-500',
        'animate-pulse'
      );
    });
  });

  describe('scroll position indicator', () => {
    it('should show green indicator when at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={true} />);

      const indicator = screen.getByRole('generic', { hidden: true });
      const progressBar = indicator.querySelector('div');
      
      expect(progressBar).toHaveClass('bg-green-500', 'w-full');
    });

    it('should show gray indicator when not at bottom', () => {
      render(<TerminalControls {...defaultProps} isAtBottom={false} />);

      const indicator = screen.getByRole('generic', { hidden: true });
      const progressBar = indicator.querySelector('div');
      
      expect(progressBar).toHaveClass('bg-gray-600', 'w-1/2');
    });

    it('should have correct container styling', () => {
      const { container } = render(<TerminalControls {...defaultProps} />);

      const indicatorContainer = container.querySelector('.mt-2.px-2');
      expect(indicatorContainer).toBeInTheDocument();
      
      const progressContainer = indicatorContainer?.querySelector('.h-1.bg-gray-800.rounded-full.overflow-hidden');
      expect(progressContainer).toBeInTheDocument();
    });

    it('should apply transition classes', () => {
      render(<TerminalControls {...defaultProps} />);

      const indicator = screen.getByRole('generic', { hidden: true });
      const progressBar = indicator.querySelector('div');
      
      expect(progressBar).toHaveClass('h-full', 'transition-all', 'duration-300');
    });
  });

  describe('state combinations', () => {
    it('should handle all combinations of isAtBottom and hasNewOutput', () => {
      const combinations = [
        { isAtBottom: true, hasNewOutput: true },
        { isAtBottom: true, hasNewOutput: false },
        { isAtBottom: false, hasNewOutput: true },
        { isAtBottom: false, hasNewOutput: false },
      ];

      combinations.forEach(({ isAtBottom, hasNewOutput }) => {
        const { unmount } = render(
          <TerminalControls
            {...defaultProps}
            isAtBottom={isAtBottom}
            hasNewOutput={hasNewOutput}
          />
        );

        // See latest button should only show when hasNewOutput && !isAtBottom
        const shouldShowSeeLatest = hasNewOutput && !isAtBottom;
        if (shouldShowSeeLatest) {
          expect(screen.getByTitle('Jump to latest output')).toBeInTheDocument();
        } else {
          expect(screen.queryByTitle('Jump to latest output')).not.toBeInTheDocument();
        }

        // Scroll to bottom should be disabled when at bottom
        const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
        if (isAtBottom) {
          expect(scrollToBottomButton).toBeDisabled();
        } else {
          expect(scrollToBottomButton).not.toBeDisabled();
        }

        unmount();
      });
    });
  });

  describe('accessibility', () => {
    it('should have proper button titles', () => {
      render(<TerminalControls {...defaultProps} />);

      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
    });

    it('should have proper title for see latest button', () => {
      render(<TerminalControls {...defaultProps} hasNewOutput={true} isAtBottom={false} />);

      expect(screen.getByTitle('Jump to latest output')).toBeInTheDocument();
    });

    it('should be keyboard accessible', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');

      // These should be focusable
      scrollToTopButton.focus();
      expect(document.activeElement).toBe(scrollToTopButton);

      scrollToBottomButton.focus();
      expect(document.activeElement).toBe(scrollToBottomButton);
    });

    it('should handle keyboard events', () => {
      render(<TerminalControls {...defaultProps} />);

      const scrollToTopButton = screen.getByTitle('Scroll to top');
      
      fireEvent.keyDown(scrollToTopButton, { key: 'Enter' });
      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(1);

      fireEvent.keyDown(scrollToTopButton, { key: ' ' });
      expect(defaultProps.onScrollToTop).toHaveBeenCalledTimes(2);
    });
  });

  describe('edge cases', () => {
    it('should handle rapid state changes', () => {
      const { rerender } = render(<TerminalControls {...defaultProps} />);

      // Rapidly change states
      rerender(<TerminalControls {...defaultProps} isAtBottom={true} hasNewOutput={true} />);
      rerender(<TerminalControls {...defaultProps} isAtBottom={false} hasNewOutput={false} />);
      rerender(<TerminalControls {...defaultProps} isAtBottom={true} hasNewOutput={false} />);

      // Should not crash and render correctly
      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
    });

    it('should handle undefined callbacks gracefully', () => {
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={undefined as any}
          onScrollToBottom={undefined as any}
        />
      );

      // Should render without crashing
      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
    });

    it('should handle boolean props correctly', () => {
      render(
        <TerminalControls
          {...defaultProps}
          isAtBottom={false}
          hasNewOutput={true}
        />
      );

      const scrollToBottomButton = screen.getByTitle('Scroll to bottom');
      expect(scrollToBottomButton).not.toBeDisabled();
      expect(screen.getByTitle('Jump to latest output')).toBeInTheDocument();
    });
  });
});