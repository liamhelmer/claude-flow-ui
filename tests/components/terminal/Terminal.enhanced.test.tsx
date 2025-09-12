import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import Terminal from '@/components/terminal/Terminal';
import type { TerminalProps } from '@/types';

// Mock the useTerminal hook with enhanced functionality
const mockUseTerminal = {
  terminalRef: { current: document.createElement('div') },
  terminal: null,
  backendTerminalConfig: null,
  focusTerminal: jest.fn(),
  fitTerminal: jest.fn(),
  writeToTerminal: jest.fn(),
  clearTerminal: jest.fn(),
  destroyTerminal: jest.fn(),
  scrollToBottom: jest.fn(),
  scrollToTop: jest.fn(),
  isAtBottom: true,
  hasNewOutput: false,
  isConnected: true,
  echoEnabled: true,
  lastCursorPosition: { row: 1, col: 1 },
};

jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: jest.fn(() => mockUseTerminal),
}));

// Mock the cn utility
jest.mock('@/lib/utils', () => ({
  cn: (...classes: any[]) => classes.filter(Boolean).join(' '),
}));

describe('Terminal - Enhanced Tests', () => {
  const defaultProps: TerminalProps = {
    sessionId: 'test-session-1',
    className: 'custom-terminal',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    // Reset mock to default state
    Object.assign(mockUseTerminal, {
      backendTerminalConfig: { cols: 80, rows: 24 },
      isAtBottom: true,
      hasNewOutput: false,
      isConnected: true,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Dynamic Terminal Sizing', () => {
    it('calculates terminal dimensions based on backend config', () => {
      const mockConfig = { cols: 100, rows: 30 };
      Object.assign(mockUseTerminal, { backendTerminalConfig: mockConfig });

      render(<Terminal {...defaultProps} />);

      const container = document.querySelector('.terminal-container') as HTMLElement;
      expect(container).toBeInTheDocument();
      
      // Expected width: (100 * 8) + 100 = 900px
      // Expected height: (30 * 20) + 100 = 700px
      expect(container.style.width).toBe('900px');
      expect(container.style.height).toBe('700px');
    });

    it('uses minimal fallback when no backend config available', () => {
      Object.assign(mockUseTerminal, { backendTerminalConfig: null });

      render(<Terminal {...defaultProps} />);

      const container = document.querySelector('.terminal-container') as HTMLElement;
      expect(container.style.width).toBe('400px');
      expect(container.style.height).toBe('300px');
    });

    it('handles partial backend config gracefully', () => {
      Object.assign(mockUseTerminal, { backendTerminalConfig: { cols: 0, rows: 0 } });

      render(<Terminal {...defaultProps} />);

      const container = document.querySelector('.terminal-container') as HTMLElement;
      expect(container.style.width).toBe('400px');
      expect(container.style.height).toBe('300px');
    });

    it('applies consistent min/max dimensions', () => {
      const mockConfig = { cols: 120, rows: 40 };
      Object.assign(mockUseTerminal, { backendTerminalConfig: mockConfig });

      render(<Terminal {...defaultProps} />);

      const container = document.querySelector('.terminal-container') as HTMLElement;
      const expectedWidth = '1060px'; // (120 * 8) + 100
      const expectedHeight = '900px'; // (40 * 20) + 100
      
      expect(container.style.width).toBe(expectedWidth);
      expect(container.style.height).toBe(expectedHeight);
      expect(container.style.minWidth).toBe(expectedWidth);
      expect(container.style.minHeight).toBe(expectedHeight);
      expect(container.style.maxWidth).toBe(expectedWidth);
      expect(container.style.maxHeight).toBe(expectedHeight);
    });
  });

  describe('Backend Config Integration', () => {
    it('initializes terminal with sessionId from props', () => {
      render(<Terminal {...defaultProps} />);

      expect(require('@/hooks/useTerminal').useTerminal).toHaveBeenCalledWith({
        sessionId: 'test-session-1',
      });
    });

    it('handles config changes dynamically', () => {
      const { rerender } = render(<Terminal {...defaultProps} />);

      // Change to new session
      rerender(<Terminal {...defaultProps} sessionId="new-session" />);

      expect(require('@/hooks/useTerminal').useTerminal).toHaveBeenLastCalledWith({
        sessionId: 'new-session',
      });
    });

    it('maintains terminal state during config updates', () => {
      const initialConfig = { cols: 80, rows: 24 };
      Object.assign(mockUseTerminal, { backendTerminalConfig: initialConfig });

      const { rerender } = render(<Terminal {...defaultProps} />);

      // Update config
      const newConfig = { cols: 100, rows: 30 };
      Object.assign(mockUseTerminal, { backendTerminalConfig: newConfig });
      rerender(<Terminal {...defaultProps} />);

      // Should maintain ref
      expect(mockUseTerminal.terminalRef.current).toBeDefined();
    });
  });

  describe('Focus and Fit Timing', () => {
    it('focuses terminal after initial delay', () => {
      render(<Terminal {...defaultProps} />);

      expect(mockUseTerminal.focusTerminal).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockUseTerminal.focusTerminal).toHaveBeenCalledTimes(1);
    });

    it('fits terminal after additional delay', () => {
      render(<Terminal {...defaultProps} />);

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockUseTerminal.fitTerminal).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(200);
      });

      expect(mockUseTerminal.fitTerminal).toHaveBeenCalledTimes(1);
    });

    it('handles rapid session changes without timer conflicts', () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Quick session changes
      rerender(<Terminal sessionId="session-2" />);
      rerender(<Terminal sessionId="session-3" />);
      rerender(<Terminal sessionId="session-4" />);

      act(() => {
        jest.advanceTimersByTime(300);
      });

      // Should focus and fit for the final session
      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
      expect(mockUseTerminal.fitTerminal).toHaveBeenCalled();
    });
  });

  describe('Click Interaction', () => {
    it('focuses terminal when content area is clicked', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toBeInTheDocument();

      fireEvent.click(terminalContent!);
      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
    });

    it('maintains focus on multiple clicks', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = document.querySelector('.cursor-text');
      
      fireEvent.click(terminalContent!);
      fireEvent.click(terminalContent!);
      fireEvent.click(terminalContent!);

      expect(mockUseTerminal.focusTerminal).toHaveBeenCalledTimes(3);
    });

    it('handles clicks during initialization gracefully', () => {
      Object.assign(mockUseTerminal, { backendTerminalConfig: null });
      render(<Terminal {...defaultProps} />);

      const terminalContent = document.querySelector('.cursor-text');
      
      // Should not throw even without backend config
      expect(() => fireEvent.click(terminalContent!)).not.toThrow();
      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
    });
  });

  describe('Layout and Styling', () => {
    it('applies correct container classes', () => {
      render(<Terminal {...defaultProps} />);

      const outerContainer = document.querySelector('.terminal-outer-container');
      expect(outerContainer).toHaveClass(
        'flex',
        'justify-center',
        'items-center',
        'h-full',
        'bg-gray-950',
        'p-4',
        'custom-terminal'
      );
    });

    it('applies terminal container styling', () => {
      render(<Terminal {...defaultProps} />);

      const container = document.querySelector('.terminal-container');
      expect(container).toHaveClass(
        'flex',
        'bg-[#1e1e1e]',
        'border',
        'border-gray-700',
        'rounded-lg',
        'shadow-2xl'
      );
    });

    it('sets flex properties correctly', () => {
      render(<Terminal {...defaultProps} />);

      const container = document.querySelector('.terminal-container') as HTMLElement;
      expect(container.style.flexShrink).toBe('0');
      expect(container.style.flexGrow).toBe('0');
    });

    it('maintains xterm wrapper positioning', () => {
      render(<Terminal {...defaultProps} />);

      const wrapper = document.querySelector('.xterm-wrapper') as HTMLElement;
      expect(wrapper.style.position).toBe('relative');
    });
  });

  describe('Props Handling', () => {
    it('handles undefined sessionId gracefully', () => {
      const propsWithUndefinedSession = {
        sessionId: undefined as any,
      };

      expect(() => render(<Terminal {...propsWithUndefinedSession} />)).not.toThrow();
    });

    it('applies default className when none provided', () => {
      const propsWithoutClassName = {
        sessionId: 'test-session',
      };

      render(<Terminal {...propsWithoutClassName} />);

      const outerContainer = document.querySelector('.terminal-outer-container');
      expect(outerContainer).toHaveClass(
        'terminal-outer-container',
        'flex',
        'justify-center',
        'items-center'
      );
    });

    it('merges custom className with default classes', () => {
      const customProps = {
        sessionId: 'test-session',
        className: 'my-custom-class another-class',
      };

      render(<Terminal {...customProps} />);

      const outerContainer = document.querySelector('.terminal-outer-container');
      expect(outerContainer).toHaveClass('my-custom-class', 'another-class');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('handles useTerminal hook returning null values', () => {
      Object.assign(mockUseTerminal, {
        terminalRef: { current: null },
        terminal: null,
        backendTerminalConfig: null,
      });

      expect(() => render(<Terminal {...defaultProps} />)).not.toThrow();
    });

    it('continues to work after backend config errors', () => {
      // Start with error state
      Object.assign(mockUseTerminal, { backendTerminalConfig: null });
      const { rerender } = render(<Terminal {...defaultProps} />);

      // Recover with valid config
      Object.assign(mockUseTerminal, { backendTerminalConfig: { cols: 80, rows: 24 } });
      rerender(<Terminal {...defaultProps} />);

      expect(document.querySelector('.terminal-container')).toBeInTheDocument();
    });

    it('handles extreme backend configurations', () => {
      const extremeConfig = { cols: 200, rows: 60 };
      Object.assign(mockUseTerminal, { backendTerminalConfig: extremeConfig });

      expect(() => render(<Terminal {...defaultProps} />)).not.toThrow();

      const container = document.querySelector('.terminal-container') as HTMLElement;
      expect(container.style.width).toBe('1700px'); // (200 * 8) + 100
      expect(container.style.height).toBe('1300px'); // (60 * 20) + 100
    });
  });

  describe('Cleanup and Memory Management', () => {
    it('cleans up timers on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      const { unmount } = render(<Terminal {...defaultProps} />);
      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it('cleans up timers on session change', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      const { rerender } = render(<Terminal sessionId="session-1" />);
      rerender(<Terminal sessionId="session-2" />);

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it('does not accumulate timers on rapid re-renders', () => {
      const setTimeoutSpy = jest.spyOn(global, 'setTimeout');
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      const { rerender } = render(<Terminal sessionId="session-1" />);
      const initialTimeoutCount = setTimeoutSpy.mock.calls.length;
      
      // Rapid re-renders
      for (let i = 0; i < 5; i++) {
        rerender(<Terminal sessionId={`session-${i}`} />);
      }
      
      // Should clean up previous timers
      expect(clearTimeoutSpy.mock.calls.length).toBeGreaterThan(0);
      
      setTimeoutSpy.mockRestore();
      clearTimeoutSpy.mockRestore();
    });
  });

  describe('Accessibility and Interaction', () => {
    it('maintains proper cursor and selection styles', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toHaveClass('cursor-text', 'select-text');
    });

    it('provides clickable interaction area', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toBeInTheDocument();
      
      // Should handle click events
      fireEvent.click(terminalContent!);
      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
    });

    it('maintains flex-1 layout for content area', () => {
      render(<Terminal {...defaultProps} />);

      const terminalContent = document.querySelector('.cursor-text');
      expect(terminalContent).toHaveClass('flex-1');
    });
  });
});
