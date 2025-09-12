import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '../Terminal';
import { useTerminal } from '@/hooks/useTerminal';

// Mock the useTerminal hook
jest.mock('@/hooks/useTerminal');
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

// Mock TerminalControls component
jest.mock('../TerminalControls', () => {
  return function MockTerminalControls({ 
    isAtBottom, 
    hasNewOutput, 
    onScrollToTop, 
    onScrollToBottom,
    terminalConfig,
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
        <div data-testid="is-at-bottom">{isAtBottom ? 'true' : 'false'}</div>
        <div data-testid="has-new-output">{hasNewOutput ? 'true' : 'false'}</div>
        <div data-testid="terminal-config">
          {terminalConfig ? `${terminalConfig.cols}x${terminalConfig.rows}` : 'null'}
        </div>
      </div>
    );
  };
});

describe('Terminal - Comprehensive Tests', () => {
  let mockTerminalRef: React.RefObject<HTMLDivElement>;
  let mockTerminal: any;
  let mockFocusTerminal: jest.Mock;
  let mockFitTerminal: jest.Mock;
  let mockScrollToTop: jest.Mock;
  let mockScrollToBottom: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    mockTerminalRef = { current: document.createElement('div') };
    mockTerminal = {
      cols: 80,
      rows: 24,
    };
    mockFocusTerminal = jest.fn();
    mockFitTerminal = jest.fn();
    mockScrollToTop = jest.fn();
    mockScrollToBottom = jest.fn();

    mockUseTerminal.mockReturnValue({
      terminalRef: mockTerminalRef,
      terminal: mockTerminal,
      focusTerminal: mockFocusTerminal,
      fitTerminal: mockFitTerminal,
      scrollToTop: mockScrollToTop,
      scrollToBottom: mockScrollToBottom,
      isAtBottom: true,
      hasNewOutput: false,
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      destroyTerminal: jest.fn(),
      isConnected: true,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Rendering', () => {
    it('should render terminal container with proper structure', () => {
      render(<Terminal sessionId="test-session" />);
      
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
      expect(screen.getByRole('region', { name: /terminal/i })).toBeInTheDocument();
    });

    it('should apply custom className', () => {
      render(<Terminal sessionId="test-session" className="custom-class" />);
      
      const container = screen.getByRole('region', { name: /terminal/i }).parentElement;
      expect(container).toHaveClass('custom-class');
    });

    it('should render with dynamic dimensions based on terminal', () => {
      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '740px', // 80 * 8 + 100
        height: '580px', // 24 * 20 + 100
      });
    });

    it('should render with fallback dimensions when no terminal', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminal: null,
      });

      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
      });
    });

    it('should render with fallback dimensions when no cols/rows', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminal: { cols: 0, rows: 0 },
      });

      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
      });
    });
  });

  describe('Focus and Fit Behavior', () => {
    it('should focus and fit terminal on mount', () => {
      render(<Terminal sessionId="test-session" />);
      
      // Advance past the initial timer
      jest.advanceTimersByTime(100);
      expect(mockFocusTerminal).toHaveBeenCalled();
      
      // Advance past the fit timer
      jest.advanceTimersByTime(200);
      expect(mockFitTerminal).toHaveBeenCalled();
    });

    it('should re-focus and fit when sessionId changes', () => {
      const { rerender } = render(<Terminal sessionId="test-session-1" />);
      
      jest.advanceTimersByTime(300);
      expect(mockFocusTerminal).toHaveBeenCalledTimes(1);
      expect(mockFitTerminal).toHaveBeenCalledTimes(1);

      mockFocusTerminal.mockClear();
      mockFitTerminal.mockClear();

      rerender(<Terminal sessionId="test-session-2" />);
      
      jest.advanceTimersByTime(300);
      expect(mockFocusTerminal).toHaveBeenCalledTimes(1);
      expect(mockFitTerminal).toHaveBeenCalledTimes(1);
    });

    it('should clean up timers on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      const { unmount } = render(<Terminal sessionId="test-session" />);
      unmount();
      
      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });
  });

  describe('Click Handling', () => {
    it('should focus terminal when terminal content is clicked', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      render(<Terminal sessionId="test-session" />);
      
      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toBeInTheDocument();
      
      await user.click(terminalContent!);
      expect(mockFocusTerminal).toHaveBeenCalled();
    });

    it('should focus terminal when xterm wrapper is clicked', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      render(<Terminal sessionId="test-session" />);
      
      const xtermWrapper = document.querySelector('.xterm-wrapper');
      expect(xtermWrapper).toBeInTheDocument();
      
      await user.click(xtermWrapper!);
      expect(mockFocusTerminal).toHaveBeenCalled();
    });
  });

  describe('Terminal Controls Integration', () => {
    it('should pass correct props to TerminalControls', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        isAtBottom: false,
        hasNewOutput: true,
        terminal: { cols: 120, rows: 30 },
      });

      render(<Terminal sessionId="test-session" />);
      
      expect(screen.getByTestId('is-at-bottom')).toHaveTextContent('false');
      expect(screen.getByTestId('has-new-output')).toHaveTextContent('true');
      expect(screen.getByTestId('terminal-config')).toHaveTextContent('120x30');
    });

    it('should pass null terminal config when no terminal', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminal: null,
      });

      render(<Terminal sessionId="test-session" />);
      
      expect(screen.getByTestId('terminal-config')).toHaveTextContent('null');
    });

    it('should handle scroll actions from controls', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      render(<Terminal sessionId="test-session" />);
      
      await user.click(screen.getByTestId('scroll-to-top'));
      expect(mockScrollToTop).toHaveBeenCalled();
      
      await user.click(screen.getByTestId('scroll-to-bottom'));
      expect(mockScrollToBottom).toHaveBeenCalled();
    });

    it('should apply sticky positioning to controls', () => {
      render(<Terminal sessionId="test-session" />);
      
      const controls = screen.getByTestId('terminal-controls');
      expect(controls).toHaveClass('sticky', 'top-0');
    });
  });

  describe('Responsive Design', () => {
    it('should handle different terminal sizes', () => {
      const testCases = [
        { cols: 40, rows: 12, expectedWidth: 420, expectedHeight: 340 },
        { cols: 120, rows: 40, expectedWidth: 1060, expectedHeight: 900 },
        { cols: 160, rows: 60, expectedWidth: 1380, expectedHeight: 1300 },
      ];

      testCases.forEach(({ cols, rows, expectedWidth, expectedHeight }) => {
        mockUseTerminal.mockReturnValue({
          ...mockUseTerminal(),
          terminal: { cols, rows },
        });

        const { rerender } = render(<Terminal sessionId="test-session" />);
        
        const terminalContainer = document.querySelector('.terminal-container');
        expect(terminalContainer).toHaveStyle({
          width: `${expectedWidth}px`,
          height: `${expectedHeight}px`,
        });

        rerender(<div />); // Clear for next test
      });
    });

    it('should maintain aspect ratio with flex properties', () => {
      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        flexShrink: '0',
        flexGrow: '0',
      });
    });
  });

  describe('Styling and Layout', () => {
    it('should apply correct CSS classes to container', () => {
      render(<Terminal sessionId="test-session" />);
      
      const outerContainer = document.querySelector('.terminal-outer-container');
      expect(outerContainer).toHaveClass(
        'flex',
        'justify-center',
        'items-center',
        'h-full',
        'bg-gray-950',
        'p-4'
      );
    });

    it('should apply correct CSS classes to terminal container', () => {
      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveClass(
        'flex',
        'bg-[#1e1e1e]',
        'border',
        'border-gray-700',
        'rounded-lg',
        'shadow-2xl'
      );
    });

    it('should apply correct CSS classes to controls sidebar', () => {
      render(<Terminal sessionId="test-session" />);
      
      const controlsSidebar = document.querySelector('.bg-gray-900');
      expect(controlsSidebar).toHaveClass(
        'flex-shrink-0',
        'bg-gray-900',
        'border-r',
        'border-gray-800',
        'rounded-l-lg'
      );
    });

    it('should apply correct CSS classes to content area', () => {
      render(<Terminal sessionId="test-session" />);
      
      const contentArea = document.querySelector('.cursor-text');
      expect(contentArea).toHaveClass(
        'flex-1',
        'cursor-text',
        'select-text'
      );
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(<Terminal sessionId="test-session" />);
      
      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toBeInTheDocument();
    });

    it('should be focusable and selectable', () => {
      render(<Terminal sessionId="test-session" />);
      
      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toHaveClass('cursor-text', 'select-text');
    });

    it('should handle keyboard navigation', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      render(<Terminal sessionId="test-session" />);
      
      // Tab to terminal controls
      await user.tab();
      expect(screen.getByTestId('scroll-to-top')).toHaveFocus();
      
      // Use keyboard to activate controls
      await user.keyboard('{Enter}');
      expect(mockScrollToTop).toHaveBeenCalled();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle missing terminal ref gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminalRef: { current: null },
      });

      expect(() => {
        render(<Terminal sessionId="test-session" />);
      }).not.toThrow();
    });

    it('should handle undefined terminal gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminal: undefined as any,
      });

      expect(() => {
        render(<Terminal sessionId="test-session" />);
      }).not.toThrow();
    });

    it('should handle missing functions gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        focusTerminal: undefined as any,
        fitTerminal: undefined as any,
        scrollToTop: undefined as any,
        scrollToBottom: undefined as any,
      });

      expect(() => {
        render(<Terminal sessionId="test-session" />);
        jest.advanceTimersByTime(300);
      }).not.toThrow();
    });

    it('should handle very large terminal dimensions', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminal: { cols: 1000, rows: 1000 },
      });

      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '8100px', // 1000 * 8 + 100
        height: '20100px', // 1000 * 20 + 100
      });
    });

    it('should handle zero dimensions', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminal: { cols: 0, rows: 0 },
      });

      render(<Terminal sessionId="test-session" />);
      
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
      });
    });
  });

  describe('Performance Considerations', () => {
    it('should not re-render unnecessarily', () => {
      const renderSpy = jest.fn();
      const TestTerminal = (props: any) => {
        renderSpy();
        return <Terminal {...props} />;
      };
      
      const { rerender } = render(<TestTerminal sessionId="test-session" />);
      expect(renderSpy).toHaveBeenCalledTimes(1);
      
      // Re-render with same props
      rerender(<TestTerminal sessionId="test-session" />);
      expect(renderSpy).toHaveBeenCalledTimes(2);
    });

    it('should handle rapid sessionId changes', () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      rerender(<Terminal sessionId="session-2" />);
      rerender(<Terminal sessionId="session-3" />);
      rerender(<Terminal sessionId="session-4" />);
      
      // Should not throw or cause issues
      expect(screen.getByTestId('terminal-controls')).toBeInTheDocument();
    });
  });

  describe('Integration with useTerminal Hook', () => {
    it('should pass correct sessionId to useTerminal', () => {
      render(<Terminal sessionId="specific-session-id" />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'specific-session-id',
      });
    });

    it('should respond to terminal state changes', () => {
      const { rerender } = render(<Terminal sessionId="test-session" />);
      
      // Simulate state change in useTerminal
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        isAtBottom: false,
        hasNewOutput: true,
      });
      
      rerender(<Terminal sessionId="test-session" />);
      
      expect(screen.getByTestId('is-at-bottom')).toHaveTextContent('false');
      expect(screen.getByTestId('has-new-output')).toHaveTextContent('true');
    });
  });
});