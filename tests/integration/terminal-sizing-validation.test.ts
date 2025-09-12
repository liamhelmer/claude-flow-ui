/**
 * Terminal Sizing Validation Tests
 * 
 * Tests to verify that terminal window sizing matches displayed dimensions
 * and that the getTerminalDimensions function works correctly.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { testUtils, createIntegrationTest } from '../utils/testHelpers';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';

// Mock the hooks
jest.mock('@/hooks/useTerminal');

createIntegrationTest('Terminal Sizing Validation', () => {
  let mockUseTerminal: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock useTerminal hook
    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      isAtBottom: false,
      hasNewOutput: false,
      terminal: null,
    };
    (useTerminal as jest.Mock).mockReturnValue(mockUseTerminal);
  });

  describe('Terminal Dimensions Calculation', () => {
    test('should use minimal fallback dimensions when no terminal', () => {
      mockUseTerminal.terminal = null;

      const { container } = render(<Terminal sessionId="test-session" />);

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      
      // Should use minimal fallback: 400x300 + padding
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
        maxWidth: '400px',
        maxHeight: '300px',
        minWidth: '400px',
        minHeight: '300px',
      });
    });

    test('should use minimal fallback when terminal has no cols/rows', () => {
      mockUseTerminal.terminal = {
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
        // cols and rows are undefined
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      
      expect(terminalContainer).toHaveStyle({
        width: '400px',
        height: '300px',
      });
    });

    test('should calculate dimensions for 80x24 terminal', () => {
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      
      // Expected: 80 * 8 + 100 = 740, 24 * 20 + 100 = 580
      expect(terminalContainer).toHaveStyle({
        width: '740px',
        height: '580px',
        maxWidth: '740px',
        maxHeight: '580px',
        minWidth: '740px',
        minHeight: '580px',
      });
    });

    test('should calculate dimensions for 120x40 terminal', () => {
      mockUseTerminal.terminal = {
        cols: 120,
        rows: 40,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      
      // Expected: 120 * 8 + 100 = 1060, 40 * 20 + 100 = 900
      expect(terminalContainer).toHaveStyle({
        width: '1060px',
        height: '900px',
      });
    });

    test('should calculate dimensions for 132x50 wide terminal', () => {
      mockUseTerminal.terminal = {
        cols: 132,
        rows: 50,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      
      // Expected: 132 * 8 + 100 = 1156, 50 * 20 + 100 = 1100
      expect(terminalContainer).toHaveStyle({
        width: '1156px',
        height: '1100px',
      });
    });

    test('should update dimensions when terminal config changes', () => {
      // Start with 80x24
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container, rerender } = render(<Terminal sessionId="test-session" />);

      let terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '740px', height: '580px' });

      // Change to 120x40
      mockUseTerminal.terminal = {
        cols: 120,
        rows: 40,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };
      (useTerminal as jest.Mock).mockReturnValue({
        ...mockUseTerminal,
        terminal: mockUseTerminal.terminal,
      });

      rerender(<Terminal sessionId="test-session" />);

      terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '1060px', height: '900px' });
    });
  });

  describe('Dimension Display Consistency', () => {
    test('should show same dimensions in controls as used for sizing (80x24)', () => {
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed dimensions
      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Check actual container dimensions
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '740px', height: '580px' });
    });

    test('should show same dimensions in controls as used for sizing (120x40)', () => {
      mockUseTerminal.terminal = {
        cols: 120,
        rows: 40,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed dimensions
      expect(screen.getByText('120×40')).toBeInTheDocument();

      // Check actual container dimensions
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '1060px', height: '900px' });
    });

    test('should show same dimensions in controls as used for sizing (132x50)', () => {
      mockUseTerminal.terminal = {
        cols: 132,
        rows: 50,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed dimensions
      expect(screen.getByText('132×50')).toBeInTheDocument();

      // Check actual container dimensions
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '1156px', height: '1100px' });
    });

    test('should show "Waiting..." when using fallback dimensions', () => {
      mockUseTerminal.terminal = null;

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed text
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Check fallback dimensions are used
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '400px', height: '300px' });
    });
  });

  describe('Edge Cases for Sizing', () => {
    test('should handle very small terminal dimensions', () => {
      mockUseTerminal.terminal = {
        cols: 1,
        rows: 1,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed dimensions
      expect(screen.getByText('1×1')).toBeInTheDocument();

      // Check calculated dimensions: 1 * 8 + 100 = 108, 1 * 20 + 100 = 120
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '108px', height: '120px' });
    });

    test('should handle very large terminal dimensions', () => {
      mockUseTerminal.terminal = {
        cols: 300,
        rows: 100,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed dimensions
      expect(screen.getByText('300×100')).toBeInTheDocument();

      // Check calculated dimensions: 300 * 8 + 100 = 2500, 100 * 20 + 100 = 2100
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '2500px', height: '2100px' });
    });

    test('should handle zero dimensions gracefully', () => {
      mockUseTerminal.terminal = {
        cols: 0,
        rows: 0,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Should fall back to minimal dimensions
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '400px', height: '300px' });
    });

    test('should handle negative dimensions gracefully', () => {
      mockUseTerminal.terminal = {
        cols: -10,
        rows: -5,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Should fall back to minimal dimensions
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '400px', height: '300px' });
    });

    test('should handle fractional dimensions', () => {
      mockUseTerminal.terminal = {
        cols: 80.5,
        rows: 24.7,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      // Check displayed dimensions
      expect(screen.getByText('80.5×24.7')).toBeInTheDocument();

      // Check calculated dimensions: 80.5 * 8 + 100 = 744, 24.7 * 20 + 100 = 594
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '744px', height: '594px' });
    });
  });

  describe('Container Styling Consistency', () => {
    test('should maintain consistent container classes', () => {
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      const outerContainer = container.querySelector('.terminal-outer-container') as HTMLElement;
      expect(outerContainer).toHaveClass(
        'terminal-outer-container',
        'flex',
        'justify-center',
        'items-center',
        'h-full',
        'bg-gray-950',
        'p-4'
      );

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveClass(
        'terminal-container',
        'flex',
        'bg-[#1e1e1e]',
        'border',
        'border-gray-700',
        'rounded-lg',
        'shadow-2xl'
      );
    });

    test('should maintain flex properties for sizing', () => {
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" />);

      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      
      // Should have explicit sizing properties
      expect(terminalContainer).toHaveStyle({
        flexShrink: '0',
        flexGrow: '0',
      });
    });

    test('should apply custom className while maintaining dimensions', () => {
      mockUseTerminal.terminal = {
        cols: 80,
        rows: 24,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      const { container } = render(<Terminal sessionId="test-session" className="custom-terminal" />);

      const outerContainer = container.querySelector('.terminal-outer-container') as HTMLElement;
      expect(outerContainer).toHaveClass('custom-terminal');

      // Dimensions should still be applied
      const terminalContainer = container.querySelector('.terminal-container') as HTMLElement;
      expect(terminalContainer).toHaveStyle({ width: '740px', height: '580px' });
    });
  });

  describe('Performance and Memory', () => {
    test('should not cause memory leaks with dimension calculations', () => {
      const { rerender, unmount } = render(<Terminal sessionId="test-session" />);

      // Multiple re-renders with different dimensions
      const configs = [
        { cols: 80, rows: 24 },
        { cols: 120, rows: 40 },
        { cols: 132, rows: 50 },
        null,
        { cols: 100, rows: 30 },
      ];

      configs.forEach((config) => {
        mockUseTerminal.terminal = config ? {
          cols: config.cols,
          rows: config.rows,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        } : null;

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        rerender(<Terminal sessionId="test-session" />);
      });

      // Should cleanup without issues
      expect(() => unmount()).not.toThrow();
    });

    test('should handle rapid dimension changes efficiently', () => {
      const { rerender } = render(<Terminal sessionId="test-session" />);

      const startTime = performance.now();

      // Rapid dimension changes
      for (let i = 0; i < 100; i++) {
        mockUseTerminal.terminal = {
          cols: 80 + i,
          rows: 24 + i,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          terminal: mockUseTerminal.terminal,
        });

        rerender(<Terminal sessionId="test-session" />);
      }

      const endTime = performance.now();
      
      // Should complete within reasonable time (1 second)
      expect(endTime - startTime).toBeLessThan(1000);
    });
  });
});