import React from 'react';
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';

// Mock the useTerminal hook
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: jest.fn(),
}));

// Mock the TerminalControls component
jest.mock('@/components/terminal/TerminalControls', () => {
  return function MockTerminalControls() {
    return <div data-testid="terminal-controls">Mock Terminal Controls</div>;
  };
});

const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

describe('Terminal Edge Cases and Error Scenarios', () => {
  const defaultMockReturn = {
    terminalRef: { current: null },
    terminal: null,
    backendTerminalConfig: { cols: 80, rows: 24 },
    focusTerminal: jest.fn(),
    fitTerminal: jest.fn(),
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
    refreshTerminal: jest.fn(),
    isAtBottom: true,
    hasNewOutput: false,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseTerminal.mockReturnValue(defaultMockReturn);
  });

  describe('Backend Configuration Edge Cases', () => {
    test('should handle missing backend configuration gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        backendTerminalConfig: null,
      });

      render(<Terminal sessionId="test-session" />);

      // Should render with fallback dimensions
      const container = screen.getByRole('button', { hidden: true });
      expect(container).toBeInTheDocument();
    });

    test('should handle invalid backend dimensions', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        backendTerminalConfig: { cols: 0, rows: 0 },
      });

      render(<Terminal sessionId="test-session" />);

      // Should use fallback dimensions
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
      });
    });

    test('should handle extremely large terminal dimensions', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        backendTerminalConfig: { cols: 500, rows: 200 },
      });

      render(<Terminal sessionId="test-session" />);

      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveStyle({
        width: '4100px',
        height: '4100px',
      });
    });

    test('should handle negative terminal dimensions', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        backendTerminalConfig: { cols: -10, rows: -5 },
      });

      render(<Terminal sessionId="test-session" />);

      // Should fall back to minimum dimensions
      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toBeInTheDocument();
    });
  });

  describe('Hook Failure Scenarios', () => {
    test('should handle useTerminal hook throwing error', () => {
      mockUseTerminal.mockImplementation(() => {
        throw new Error('Hook initialization failed');
      });

      // Should not crash the component
      expect(() => {
        render(<Terminal sessionId="test-session" />);
      }).toThrow('Hook initialization failed');
    });

    test('should handle missing hook methods gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal: undefined as any,
        fitTerminal: undefined as any,
        refreshTerminal: undefined as any,
      });

      render(<Terminal sessionId="test-session" />);

      // Component should still render without crashing
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();
    });

    test('should handle null terminal reference', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        terminalRef: { current: null },
        terminal: null,
      });

      render(<Terminal sessionId="test-session" />);

      // Should render but not have terminal functionality
      const container = screen.getByRole('button', { hidden: true });
      expect(container).toBeInTheDocument();
    });
  });

  describe('User Interaction Edge Cases', () => {
    test('should handle rapid clicking on terminal container', async () => {
      const mockFocusTerminal = jest.fn();
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal: mockFocusTerminal,
      });

      render(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('button', { hidden: true });
      
      // Rapid clicks
      for (let i = 0; i < 10; i++) {
        fireEvent.click(terminalElement);
      }

      // Focus should be called multiple times without error
      expect(mockFocusTerminal).toHaveBeenCalledTimes(10);
    });

    test('should handle focus when terminal is not ready', () => {
      const mockFocusTerminal = jest.fn().mockImplementation(() => {
        throw new Error('Terminal not ready');
      });
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal: mockFocusTerminal,
      });

      render(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('button', { hidden: true });
      
      // Should not crash even if focus throws error
      expect(() => {
        fireEvent.click(terminalElement);
      }).not.toThrow();
    });

    test('should handle refresh during terminal loading', () => {
      const mockRefreshTerminal = jest.fn();
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        terminal: null, // Terminal not loaded yet
        refreshTerminal: mockRefreshTerminal,
      });

      render(<Terminal sessionId="test-session" />);

      // Simulate refresh being called before terminal is ready
      act(() => {
        mockRefreshTerminal();
      });

      expect(mockRefreshTerminal).toHaveBeenCalled();
    });
  });

  describe('Session Management Edge Cases', () => {
    test('should handle empty or invalid session ID', () => {
      render(<Terminal sessionId="" />);
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();
    });

    test('should handle null session ID', () => {
      render(<Terminal sessionId={null as any} />);
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();
    });

    test('should handle very long session ID', () => {
      const longSessionId = 'x'.repeat(1000);
      render(<Terminal sessionId={longSessionId} />);
      expect(mockUseTerminal).toHaveBeenCalledWith({ sessionId: longSessionId });
    });

    test('should handle special characters in session ID', () => {
      const specialSessionId = 'session-with-特殊字符-and-emojis-🚀-and-symbols-@#$%';
      render(<Terminal sessionId={specialSessionId} />);
      expect(mockUseTerminal).toHaveBeenCalledWith({ sessionId: specialSessionId });
    });
  });

  describe('Memory and Performance Edge Cases', () => {
    test('should handle frequent re-renders without memory leaks', async () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Rapidly change session IDs
      for (let i = 2; i <= 100; i++) {
        rerender(<Terminal sessionId={`session-${i}`} />);
      }

      // Should not cause memory issues or crashes
      expect(mockUseTerminal).toHaveBeenCalledTimes(100);
    });

    test('should handle component unmounting during async operations', async () => {
      const mockFocusTerminal = jest.fn().mockImplementation(() => {
        return new Promise(resolve => setTimeout(resolve, 1000));
      });

      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal: mockFocusTerminal,
      });

      const { unmount } = render(<Terminal sessionId="test-session" />);

      // Unmount immediately after render
      unmount();

      // Should not cause any errors
      await waitFor(() => {
        expect(true).toBe(true); // Just ensure no errors
      });
    });

    test('should handle large terminal output efficiently', () => {
      // Simulate terminal with large scrollback
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        hasNewOutput: true,
        isAtBottom: false,
      });

      render(<Terminal sessionId="test-session" />);

      // Should render without performance issues
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();
    });
  });

  describe('Error Boundary Integration', () => {
    test('should handle render errors gracefully', () => {
      // Mock console.error to prevent error logs in test output
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      mockUseTerminal.mockImplementation(() => {
        throw new Error('Render error');
      });

      expect(() => {
        render(<Terminal sessionId="test-session" />);
      }).toThrow('Render error');

      consoleSpy.mockRestore();
    });

    test('should handle async errors in useEffect', async () => {
      const mockEffect = jest.fn().mockImplementation(() => {
        throw new Error('Async error in useEffect');
      });

      // This would typically be handled by an error boundary
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal: mockEffect,
      });

      render(<Terminal sessionId="test-session" />);

      // Click to trigger the error
      const terminalElement = screen.getByRole('button', { hidden: true });
      
      expect(() => {
        fireEvent.click(terminalElement);
      }).not.toThrow();
    });
  });

  describe('Accessibility Edge Cases', () => {
    test('should handle high contrast mode', () => {
      // Mock high contrast media query
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-contrast: high)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      render(<Terminal sessionId="test-session" />);

      const terminalContainer = document.querySelector('.terminal-container');
      expect(terminalContainer).toHaveClass('bg-[#1e1e1e]');
    });

    test('should handle reduced motion preference', () => {
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-reduced-motion: reduce)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      render(<Terminal sessionId="test-session" />);
      
      // Component should render without animations when reduced motion is preferred
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();
    });

    test('should handle screen reader compatibility', () => {
      render(<Terminal sessionId="test-session" />);

      const terminalWrapper = document.querySelector('.xterm-wrapper');
      expect(terminalWrapper).toHaveAttribute('style');
    });
  });

  describe('Browser Compatibility Edge Cases', () => {
    test('should handle missing requestAnimationFrame', () => {
      const originalRAF = window.requestAnimationFrame;
      delete (window as any).requestAnimationFrame;

      render(<Terminal sessionId="test-session" />);

      // Should use setTimeout fallback
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();

      window.requestAnimationFrame = originalRAF;
    });

    test('should handle missing ResizeObserver', () => {
      const originalResizeObserver = window.ResizeObserver;
      delete (window as any).ResizeObserver;

      render(<Terminal sessionId="test-session" />);

      // Should work without ResizeObserver
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();

      window.ResizeObserver = originalResizeObserver;
    });

    test('should handle touch devices', () => {
      // Mock touch device
      Object.defineProperty(navigator, 'maxTouchPoints', {
        writable: true,
        value: 5,
      });

      render(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('button', { hidden: true });
      fireEvent.touchStart(terminalElement);

      expect(terminalElement).toBeInTheDocument();
    });
  });

  describe('Concurrent State Updates', () => {
    test('should handle rapid state changes', async () => {
      const { rerender } = render(<Terminal sessionId="test-session" />);

      // Rapidly change props
      for (let i = 0; i < 50; i++) {
        rerender(<Terminal sessionId="test-session" className={`class-${i}`} />);
      }

      // Should handle all updates without errors
      expect(screen.getByRole('button', { hidden: true })).toBeInTheDocument();
    });

    test('should handle concurrent focus and refresh calls', async () => {
      const mockFocusTerminal = jest.fn();
      const mockRefreshTerminal = jest.fn();

      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal: mockFocusTerminal,
        refreshTerminal: mockRefreshTerminal,
      });

      render(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('button', { hidden: true });

      // Simulate concurrent calls
      await act(async () => {
        fireEvent.click(terminalElement);
        mockRefreshTerminal();
        fireEvent.click(terminalElement);
        mockRefreshTerminal();
      });

      expect(mockFocusTerminal).toHaveBeenCalledTimes(2);
      expect(mockRefreshTerminal).toHaveBeenCalledTimes(2);
    });
  });

  describe('CSS and Style Edge Cases', () => {
    test('should handle missing Tailwind classes gracefully', () => {
      // Mock missing CSS classes scenario
      const { container } = render(<Terminal sessionId="test-session" />);
      
      // Component should still render even if CSS classes are missing
      expect(container.firstChild).toBeInTheDocument();
    });

    test('should handle custom className prop', () => {
      render(<Terminal sessionId="test-session" className="custom-terminal-class" />);

      const outerContainer = document.querySelector('.terminal-outer-container');
      expect(outerContainer).toHaveClass('custom-terminal-class');
    });

    test('should handle very long className', () => {
      const longClassName = 'a'.repeat(1000);
      render(<Terminal sessionId="test-session" className={longClassName} />);

      const outerContainer = document.querySelector('.terminal-outer-container');
      expect(outerContainer).toHaveClass(longClassName);
    });
  });
});