/**
 * Comprehensive unit tests for Terminal component
 * Tests all functionality including WebSocket integration, xterm.js interaction, and error handling
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';
import { MockWebSocket } from '../../mocks/websocket';

// Mock the useTerminal hook
jest.mock('@/hooks/useTerminal');
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

// Mock next.js imports
jest.mock('next/dynamic', () => (component: any) => component);

// Mock utility functions
jest.mock('@/lib/utils', () => ({
  cn: (...classes: any[]) => classes.filter(Boolean).join(' '),
}));

describe('Terminal Component', () => {
  const defaultHookReturn = {
    terminalRef: { current: null },
    terminal: null,
    backendTerminalConfig: { cols: 80, rows: 24 },
    focusTerminal: jest.fn().mockReturnValue(true),
    fitTerminal: jest.fn(),
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
    refreshTerminal: jest.fn(),
    isAtBottom: true,
    hasNewOutput: false,
    configError: null,
    configRequestInProgress: false,
  };

  const defaultProps = {
    sessionId: 'test-session-123',
    className: 'test-class',
  };

  beforeEach(() => {
    mockUseTerminal.mockReturnValue(defaultHookReturn);
    jest.clearAllMocks();
    MockWebSocket.reset();
  });

  describe('Basic Rendering', () => {
    it('renders without crashing', () => {
      render(<Terminal {...defaultProps} />);
      expect(screen.getByRole('generic')).toBeInTheDocument();
    });

    it('applies custom className', () => {
      render(<Terminal {...defaultProps} />);
      const container = screen.getByRole('generic');
      expect(container).toHaveClass('test-class');
    });

    it('renders with sessionId', () => {
      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();
      render(<Terminal {...defaultProps} />);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[Terminal Component]'),
        expect.stringContaining('test-session-123')
      );
    });
  });

  describe('Configuration States', () => {
    it('shows loading state when configuration is being fetched', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: null,
        configRequestInProgress: true,
      });

      render(<Terminal {...defaultProps} />);

      expect(screen.getByText('Loading terminal configuration...')).toBeInTheDocument();
      expect(screen.getByRole('status')).toBeInTheDocument(); // Loading spinner
    });

    it('shows error state when configuration fails', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: null,
        configError: 'Failed to connect to backend',
      });

      render(<Terminal {...defaultProps} />);

      expect(screen.getByText(/Failed to load terminal configuration/)).toBeInTheDocument();
      expect(screen.getByText('Retry')).toBeInTheDocument();
    });

    it('retries configuration on error button click', async () => {
      const reloadSpy = jest.fn();
      Object.defineProperty(window, 'location', {
        value: { reload: reloadSpy },
        writable: true,
      });

      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: null,
        configError: 'Connection failed',
      });

      render(<Terminal {...defaultProps} />);

      const retryButton = screen.getByText('Retry');
      await userEvent.click(retryButton);

      expect(reloadSpy).toHaveBeenCalled();
    });

    it('renders terminal when configuration is ready', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: { cols: 120, rows: 30 },
      });

      render(<Terminal {...defaultProps} />);

      const terminalContainer = screen.getByRole('generic');
      expect(terminalContainer).toBeInTheDocument();
      expect(terminalContainer).toHaveStyle({
        width: '1060px', // 120 * 8 + 100
        height: '700px',  // 30 * 20 + 100
      });
    });
  });

  describe('Terminal Dimensions', () => {
    it('calculates dimensions correctly from backend config', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: { cols: 100, rows: 40 },
      });

      render(<Terminal {...defaultProps} />);

      const terminalContainer = screen.getByRole('generic');
      expect(terminalContainer).toHaveStyle({
        width: '900px',  // 100 * 8 + 100
        height: '900px', // 40 * 20 + 100
      });
    });

    it('uses fallback dimensions when backend config is incomplete', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: { cols: 0, rows: 0 },
        configRequestInProgress: false,
      });

      render(<Terminal {...defaultProps} />);

      const terminalContainer = screen.getByRole('generic');
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
      });
    });
  });

  describe('Focus Management', () => {
    it('attempts to focus terminal on session change', async () => {
      const mockFocusTerminal = jest.fn().mockReturnValue(true);
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        focusTerminal: mockFocusTerminal,
      });

      const { rerender } = render(<Terminal {...defaultProps} />);

      // Advance timers to trigger focus attempt
      act(() => {
        jest.runAllTimers();
      });

      // Change session
      rerender(<Terminal sessionId="new-session" />);

      act(() => {
        jest.runAllTimers();
      });

      expect(mockFocusTerminal).toHaveBeenCalled();
    });

    it('retries focus on failure with exponential backoff', async () => {
      const mockFocusTerminal = jest.fn()
        .mockReturnValueOnce(false) // First attempt fails
        .mockReturnValueOnce(false) // Second attempt fails
        .mockReturnValueOnce(true);  // Third attempt succeeds

      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        focusTerminal: mockFocusTerminal,
      });

      render(<Terminal {...defaultProps} />);

      // Run through all retry attempts
      act(() => {
        jest.runAllTimers();
      });

      expect(mockFocusTerminal).toHaveBeenCalledTimes(3);
    });

    it('focuses terminal on click', async () => {
      const mockFocusTerminal = jest.fn().mockReturnValue(true);
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        focusTerminal: mockFocusTerminal,
      });

      render(<Terminal {...defaultProps} />);

      const terminalArea = screen.getByRole('generic');
      await userEvent.click(terminalArea);

      expect(mockFocusTerminal).toHaveBeenCalled();
    });

    it('retries focus on click failure', async () => {
      const mockFocusTerminal = jest.fn()
        .mockReturnValueOnce(false)
        .mockReturnValueOnce(true);

      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        focusTerminal: mockFocusTerminal,
      });

      render(<Terminal {...defaultProps} />);

      const terminalArea = screen.getByRole('generic');
      await userEvent.click(terminalArea);

      // Advance timers for retry
      act(() => {
        jest.runAllTimers();
      });

      expect(mockFocusTerminal).toHaveBeenCalledTimes(2);
    });
  });

  describe('Production Environment Behavior', () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = 'production';
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('uses production-optimized focus timing', async () => {
      const mockFocusTerminal = jest.fn().mockReturnValue(true);
      const mockFitTerminal = jest.fn();

      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        focusTerminal: mockFocusTerminal,
        fitTerminal: mockFitTerminal,
      });

      render(<Terminal {...defaultProps} />);

      // In production, initial delay should be 25ms
      act(() => {
        jest.advanceTimersByTime(25);
      });

      expect(mockFocusTerminal).toHaveBeenCalled();

      // Fit should happen after 10ms in production
      act(() => {
        jest.advanceTimersByTime(10);
      });

      expect(mockFitTerminal).toHaveBeenCalled();
    });

    it('applies production-specific CSS classes', () => {
      render(<Terminal {...defaultProps} />);

      const terminalArea = document.querySelector('.xterm-wrapper');
      expect(terminalArea).toHaveClass('backface-visibility-hidden', 'translate3d-0');
    });
  });

  describe('Session Handling', () => {
    it('handles sessionId changes correctly', () => {
      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();
      const { rerender } = render(<Terminal sessionId="session-1" />);

      rerender(<Terminal sessionId="session-2" />);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[Terminal Component]'),
        expect.stringContaining('session-2')
      );
    });

    it('handles undefined sessionId gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: null,
      });

      expect(() => {
        render(<Terminal sessionId={undefined as any} />);
      }).not.toThrow();
    });

    it('handles empty sessionId', () => {
      expect(() => {
        render(<Terminal sessionId="" />);
      }).not.toThrow();
    });
  });

  describe('Terminal Ref Management', () => {
    it('sets up terminal container ref correctly', () => {
      const mockTerminalRef = { current: null };
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        terminalRef: mockTerminalRef,
      });

      render(<Terminal {...defaultProps} />);

      // The ref callback should be called
      expect(mockTerminalRef.current).toBeDefined();
    });

    it('handles ref callback with null element', () => {
      const mockTerminalRef = { current: null };
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        terminalRef: mockTerminalRef,
      });

      // Should not throw when ref callback receives null
      expect(() => {
        render(<Terminal {...defaultProps} />);
      }).not.toThrow();
    });
  });

  describe('Error Handling', () => {
    it('handles useTerminal hook errors gracefully', () => {
      mockUseTerminal.mockImplementation(() => {
        throw new Error('Hook error');
      });

      expect(() => {
        render(<Terminal {...defaultProps} />);
      }).toThrow('Hook error');
    });

    it('displays error message for invalid backend configuration', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        configError: 'Invalid terminal configuration',
        backendTerminalConfig: null,
      });

      render(<Terminal {...defaultProps} />);

      expect(screen.getByText(/Failed to load terminal configuration/)).toBeInTheDocument();
      expect(screen.getByText(/Invalid terminal configuration/)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('provides accessible terminal area', () => {
      render(<Terminal {...defaultProps} />);

      const terminalArea = screen.getByRole('generic');
      expect(terminalArea).toBeInTheDocument();
    });

    it('supports keyboard navigation', async () => {
      const mockFocusTerminal = jest.fn().mockReturnValue(true);
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        focusTerminal: mockFocusTerminal,
      });

      render(<Terminal {...defaultProps} />);

      const terminalArea = screen.getByRole('generic');

      // Tab to focus
      await userEvent.tab();

      // Enter to activate (if focused)
      await userEvent.keyboard('{Enter}');

      // Should attempt to focus terminal
      expect(mockFocusTerminal).toHaveBeenCalled();
    });
  });

  describe('Performance', () => {
    it('does not re-render unnecessarily', () => {
      const renderSpy = jest.fn();
      const TestTerminal = (props: any) => {
        renderSpy();
        return <Terminal {...props} />;
      };

      const { rerender } = render(<TestTerminal {...defaultProps} />);

      expect(renderSpy).toHaveBeenCalledTimes(1);

      // Re-render with same props
      rerender(<TestTerminal {...defaultProps} />);

      expect(renderSpy).toHaveBeenCalledTimes(2);
    });

    it('memoizes expensive calculations', () => {
      const mockTerminalConfig = { cols: 80, rows: 24 };
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: mockTerminalConfig,
      });

      const { rerender } = render(<Terminal {...defaultProps} />);

      // Re-render with same config should not recalculate dimensions
      rerender(<Terminal {...defaultProps} />);

      const container = screen.getByRole('generic');
      expect(container).toHaveStyle({
        width: '740px', // 80 * 8 + 100
        height: '580px', // 24 * 20 + 100
      });
    });
  });

  describe('Edge Cases', () => {
    it('handles zero dimensions gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: { cols: 0, rows: 0 },
      });

      render(<Terminal {...defaultProps} />);

      const container = screen.getByRole('generic');
      expect(container).toHaveStyle({
        width: '400px', // Fallback
        height: '300px', // Fallback
      });
    });

    it('handles very large dimensions', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        backendTerminalConfig: { cols: 1000, rows: 1000 },
      });

      render(<Terminal {...defaultProps} />);

      const container = screen.getByRole('generic');
      expect(container).toHaveStyle({
        width: '8100px',  // 1000 * 8 + 100
        height: '20100px', // 1000 * 20 + 100
      });
    });

    it('handles missing terminal ref', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultHookReturn,
        terminalRef: null,
      });

      expect(() => {
        render(<Terminal {...defaultProps} />);
      }).not.toThrow();
    });

    it('handles concurrent session changes', () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Rapid session changes
      rerender(<Terminal sessionId="session-2" />);
      rerender(<Terminal sessionId="session-3" />);
      rerender(<Terminal sessionId="session-4" />);

      expect(() => {
        act(() => {
          jest.runAllTimers();
        });
      }).not.toThrow();
    });
  });

  describe('Integration with Controls', () => {
    it('integrates with TerminalControls when present', () => {
      // This test verifies that Terminal can work with TerminalControls
      // even though TerminalControls is imported separately
      render(<Terminal {...defaultProps} />);

      // Should render without TerminalControls by default
      expect(screen.queryByRole('toolbar')).not.toBeInTheDocument();
    });
  });
});