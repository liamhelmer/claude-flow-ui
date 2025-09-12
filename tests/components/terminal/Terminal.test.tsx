import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import Terminal from '@/components/terminal/Terminal';
import type { TerminalProps } from '@/types';

// Mock the useTerminal hook
const mockUseTerminal = {
  terminalRef: { current: document.createElement('div') },
  focusTerminal: jest.fn(),
  fitTerminal: jest.fn(),
  scrollToTop: jest.fn(),
  scrollToBottom: jest.fn(),
  isAtBottom: true,
  hasNewOutput: false,
};

jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => mockUseTerminal,
}));

// Mock TerminalControls component
jest.mock('@/components/terminal/TerminalControls', () => {
  return function MockTerminalControls({ 
    isAtBottom, 
    hasNewOutput, 
    onScrollToTop, 
    onScrollToBottom,
    className 
  }: any) {
    return (
      <div data-testid="terminal-controls" className={className}>
        <button onClick={onScrollToTop} data-testid="scroll-to-top">
          Scroll to Top
        </button>
        <button onClick={onScrollToBottom} data-testid="scroll-to-bottom">
          Scroll to Bottom
        </button>
        <div data-testid="at-bottom">{isAtBottom ? 'true' : 'false'}</div>
        <div data-testid="has-new-output">{hasNewOutput ? 'true' : 'false'}</div>
      </div>
    );
  };
});

// Mock the cn utility
jest.mock('@/lib/utils', () => ({
  cn: (...classes: any[]) => classes.filter(Boolean).join(' '),
}));

describe('Terminal', () => {
  const defaultProps: TerminalProps = {
    sessionId: 'test-session-1',
    className: 'custom-terminal',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('renders terminal container with correct structure', () => {
    render(<Terminal {...defaultProps} />);

    const container = screen.getByTestId('terminal-controls').closest('.terminal-container');
    expect(container).toBeInTheDocument();
    expect(container).toHaveClass('flex');
    expect(container).toHaveClass('h-full');
    expect(container).toHaveClass('relative');
    expect(container).toHaveClass('bg-[#1e1e1e]');
    expect(container).toHaveClass('custom-terminal');
  });

  it('renders TerminalControls with correct props', () => {
    render(<Terminal {...defaultProps} />);

    const controls = screen.getByTestId('terminal-controls');
    expect(controls).toBeInTheDocument();
    expect(controls).toHaveClass('sticky');
    expect(controls).toHaveClass('top-0');

    // Check props passed to TerminalControls
    expect(screen.getByTestId('at-bottom')).toHaveTextContent('true');
    expect(screen.getByTestId('has-new-output')).toHaveTextContent('false');
  });

  it('renders terminal content area', () => {
    render(<Terminal {...defaultProps} />);

    const terminalContent = screen.getByTestId('terminal-controls').nextElementSibling;
    expect(terminalContent).toHaveClass('flex-1');
    expect(terminalContent).toHaveClass('cursor-text');
    expect(terminalContent).toHaveClass('select-text');
  });

  it('renders xterm wrapper with correct styles', () => {
    render(<Terminal {...defaultProps} />);

    const xtermWrapper = document.querySelector('.xterm-wrapper');
    expect(xtermWrapper).toBeInTheDocument();
    expect(xtermWrapper).toHaveClass('h-full');
    expect(xtermWrapper).toHaveClass('w-full');
    
    // Check inline styles
    const element = xtermWrapper as HTMLElement;
    expect(element.style.height).toBe('100%');
    expect(element.style.width).toBe('100%');
    expect(element.style.position).toBe('relative');
  });

  it('initializes terminal with correct sessionId', () => {
    render(<Terminal {...defaultProps} />);

    expect(require('@/hooks/useTerminal').useTerminal).toHaveBeenCalledWith({
      sessionId: 'test-session-1',
    });
  });

  it('focuses and fits terminal on mount', () => {
    render(<Terminal {...defaultProps} />);

    // Fast-forward initial timer
    jest.advanceTimersByTime(100);

    expect(mockUseTerminal.focusTerminal).toHaveBeenCalledTimes(1);

    // Fast-forward the fitTerminal delay
    jest.advanceTimersByTime(200);

    expect(mockUseTerminal.fitTerminal).toHaveBeenCalledTimes(1);
  });

  it('refocuses and refits when sessionId changes', () => {
    const { rerender } = render(<Terminal {...defaultProps} />);

    jest.advanceTimersByTime(300);
    jest.clearAllMocks();

    // Change sessionId
    rerender(<Terminal {...defaultProps} sessionId="test-session-2" />);

    jest.advanceTimersByTime(100);
    expect(mockUseTerminal.focusTerminal).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(200);
    expect(mockUseTerminal.fitTerminal).toHaveBeenCalledTimes(1);
  });

  it('focuses terminal when clicked', () => {
    render(<Terminal {...defaultProps} />);

    const terminalContent = screen.getByTestId('terminal-controls').nextElementSibling;
    fireEvent.click(terminalContent!);

    expect(mockUseTerminal.focusTerminal).toHaveBeenCalledTimes(2); // Once on mount, once on click
  });

  it('passes scroll functions to TerminalControls', () => {
    render(<Terminal {...defaultProps} />);

    const scrollToTopButton = screen.getByTestId('scroll-to-top');
    const scrollToBottomButton = screen.getByTestId('scroll-to-bottom');

    fireEvent.click(scrollToTopButton);
    expect(mockUseTerminal.scrollToTop).toHaveBeenCalledTimes(1);

    fireEvent.click(scrollToBottomButton);
    expect(mockUseTerminal.scrollToBottom).toHaveBeenCalledTimes(1);
  });

  it('updates TerminalControls when terminal state changes', () => {
    const mockUseTerminalWithNewOutput = {
      ...mockUseTerminal,
      isAtBottom: false,
      hasNewOutput: true,
    };

    jest.mocked(require('@/hooks/useTerminal').useTerminal).mockReturnValue(mockUseTerminalWithNewOutput);

    render(<Terminal {...defaultProps} />);

    expect(screen.getByTestId('at-bottom')).toHaveTextContent('false');
    expect(screen.getByTestId('has-new-output')).toHaveTextContent('true');
  });

  it('handles missing sessionId gracefully', () => {
    const propsWithoutSession = {
      sessionId: undefined as any,
    };

    expect(() => render(<Terminal {...propsWithoutSession} />)).not.toThrow();
  });

  it('applies default className when none provided', () => {
    const propsWithoutClassName = {
      sessionId: 'test-session',
    };

    render(<Terminal {...propsWithoutClassName} />);

    const container = screen.getByTestId('terminal-controls').closest('.terminal-container');
    expect(container).toHaveClass('terminal-container');
    expect(container).toHaveClass('flex');
    expect(container).toHaveClass('h-full');
    expect(container).toHaveClass('relative');
    expect(container).toHaveClass('bg-[#1e1e1e]');
  });

  it('cleans up timers on unmount', () => {
    const { unmount } = render(<Terminal {...defaultProps} />);

    const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
    unmount();

    expect(clearTimeoutSpy).toHaveBeenCalled();
  });

  describe('layout and styling', () => {
    it('applies correct flex layout', () => {
      render(<Terminal {...defaultProps} />);

      const container = screen.getByTestId('terminal-controls').closest('.terminal-container');
      expect(container).toHaveClass('flex');

      const controlsArea = screen.getByTestId('terminal-controls').parentElement;
      expect(controlsArea).toHaveClass('flex-shrink-0');
      expect(controlsArea).toHaveClass('bg-gray-900');
      expect(controlsArea).toHaveClass('border-r');
      expect(controlsArea).toHaveClass('border-gray-800');

      const contentArea = screen.getByTestId('terminal-controls').nextElementSibling;
      expect(contentArea).toHaveClass('flex-1');
    });

    it('maintains proper terminal wrapper dimensions', () => {
      render(<Terminal {...defaultProps} />);

      const wrapper = document.querySelector('.xterm-wrapper') as HTMLElement;
      expect(wrapper.style.height).toBe('100%');
      expect(wrapper.style.width).toBe('100%');
      expect(wrapper.style.position).toBe('relative');
    });
  });

  describe('interaction handling', () => {
    it('handles multiple clicks without issues', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = screen.getByTestId('terminal-controls').nextElementSibling;
      
      fireEvent.click(terminalContent!);
      fireEvent.click(terminalContent!);
      fireEvent.click(terminalContent!);

      expect(mockUseTerminal.focusTerminal).toHaveBeenCalledTimes(4); // 1 on mount + 3 clicks
    });

    it('handles rapid session changes', async () => {
      const { rerender } = render(<Terminal {...defaultProps} />);

      // Rapid session changes
      rerender(<Terminal {...defaultProps} sessionId="session-2" />);
      rerender(<Terminal {...defaultProps} sessionId="session-3" />);
      rerender(<Terminal {...defaultProps} sessionId="session-4" />);

      jest.advanceTimersByTime(300);

      // Should handle all changes without crashing
      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
      expect(mockUseTerminal.fitTerminal).toHaveBeenCalled();
    });
  });

  describe('terminal ref handling', () => {
    it('passes terminal ref to xterm wrapper', () => {
      render(<Terminal {...defaultProps} />);

      const wrapper = document.querySelector('.xterm-wrapper');
      expect(wrapper).toBeInTheDocument();
      
      // The ref should be set by the useTerminal hook
      expect(mockUseTerminal.terminalRef.current).toBeDefined();
    });
  });

  describe('accessibility', () => {
    it('maintains text cursor and selection', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = screen.getByTestId('terminal-controls').nextElementSibling;
      expect(terminalContent).toHaveClass('cursor-text');
      expect(terminalContent).toHaveClass('select-text');
    });

    it('provides proper interaction area', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = screen.getByTestId('terminal-controls').nextElementSibling;
      expect(terminalContent).toBeInTheDocument();
      
      // Should be clickable
      fireEvent.click(terminalContent!);
      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
    });
  });
});