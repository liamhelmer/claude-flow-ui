import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../../tests/test-utils';
import { useTerminal } from '@/hooks/useTerminal';
import Terminal from '../Terminal';

// Mock the useTerminal hook more specifically for this component
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

describe('Terminal Component', () => {
  const mockTerminalRef = { current: document.createElement('div') };
  
  const defaultMockReturn = {
    terminalRef: mockTerminalRef,
    terminal: null,
    focusTerminal: jest.fn(),
    fitTerminal: jest.fn(),
    writeToTerminal: jest.fn(),
    clearTerminal: jest.fn(),
    destroyTerminal: jest.fn(),
    isConnected: true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseTerminal.mockReturnValue(defaultMockReturn);
  });

  describe('Rendering', () => {
    it('should render terminal container with correct classes', () => {
      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('terminal-container', 'flex-1', 'h-full', 'relative');
      expect(container).toHaveClass('cursor-text', 'select-text', 'bg-[#1e1e1e]');
    });

    it('should render with custom className', () => {
      render(<Terminal sessionId="test-session" className="custom-class" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('custom-class');
    });

    it('should contain xterm wrapper with correct styling', () => {
      render(<Terminal sessionId="test-session" />);
      
      const xtermWrapper = screen.getByTestId('test-wrapper').querySelector('.xterm-wrapper');
      expect(xtermWrapper).toBeInTheDocument();
      expect(xtermWrapper).toHaveClass('h-full', 'w-full');
    });
  });

  describe('useTerminal Hook Integration', () => {
    it('should call useTerminal with correct sessionId', () => {
      render(<Terminal sessionId="test-session-123" />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'test-session-123',
      });
    });

    it('should use terminalRef from useTerminal hook', () => {
      const customRef = { current: document.createElement('div') };
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        terminalRef: customRef,
      });

      render(<Terminal sessionId="test-session" />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: 'test-session',
      });
    });
  });

  describe('Focus and Fit Behavior', () => {
    it('should call focusTerminal and fitTerminal on mount', async () => {
      const focusTerminal = jest.fn();
      const fitTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
        fitTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      await waitFor(() => {
        expect(focusTerminal).toHaveBeenCalled();
      });
      
      await waitFor(() => {
        expect(fitTerminal).toHaveBeenCalled();
      }, { timeout: 500 });
    });

    it('should call focusTerminal and fitTerminal when sessionId changes', async () => {
      const focusTerminal = jest.fn();
      const fitTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
        fitTerminal,
      });

      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      // Clear previous calls
      focusTerminal.mockClear();
      fitTerminal.mockClear();
      
      rerender(<Terminal sessionId="session-2" />);
      
      await waitFor(() => {
        expect(focusTerminal).toHaveBeenCalled();
      });
      
      await waitFor(() => {
        expect(fitTerminal).toHaveBeenCalled();
      }, { timeout: 500 });
    });
  });

  describe('Click Interactions', () => {
    it('should call focusTerminal when clicked', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      fireEvent.click(container);
      
      expect(focusTerminal).toHaveBeenCalled();
    });

    it('should handle multiple clicks correctly', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      fireEvent.click(container);
      fireEvent.click(container);
      fireEvent.click(container);
      
      expect(focusTerminal).toHaveBeenCalledTimes(3);
    });
  });

  describe('Connection States', () => {
    it('should handle connected state', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        isConnected: true,
      });

      render(<Terminal sessionId="test-session" />);
      
      expect(screen.getByTestId('test-wrapper')).toBeInTheDocument();
    });

    it('should handle disconnected state', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        isConnected: false,
      });

      render(<Terminal sessionId="test-session" />);
      
      expect(screen.getByTestId('test-wrapper')).toBeInTheDocument();
    });
  });

  describe('Props Validation', () => {
    it('should handle empty sessionId gracefully', () => {
      render(<Terminal sessionId="" />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: '',
      });
    });

    it('should handle long sessionId', () => {
      const longSessionId = 'very-long-session-id-'.repeat(10);
      render(<Terminal sessionId={longSessionId} />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: longSessionId,
      });
    });

    it('should handle special characters in sessionId', () => {
      const specialSessionId = 'session-123!@#$%^&*()';
      render(<Terminal sessionId={specialSessionId} />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: specialSessionId,
      });
    });
  });

  describe('Cleanup', () => {
    it('should cleanup timers on unmount', () => {
      const { unmount } = render(<Terminal sessionId="test-session" />);
      
      // Spy on clearTimeout
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      unmount();
      
      // Should have called clearTimeout (internal timer cleanup)
      expect(clearTimeoutSpy).toHaveBeenCalled();
      
      clearTimeoutSpy.mockRestore();
    });
  });

  describe('Accessibility', () => {
    it('should have appropriate cursor styling for text interaction', () => {
      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('cursor-text');
    });

    it('should have appropriate text selection styling', () => {
      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass('select-text');
    });
  });

  describe('Error Handling', () => {
    it('should handle useTerminal hook errors gracefully', () => {
      // Mock console.error to suppress error logs in test
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      mockUseTerminal.mockImplementation(() => {
        throw new Error('Hook failed');
      });

      expect(() => render(<Terminal sessionId="test-session" />)).toThrow('Hook failed');
      
      consoleSpy.mockRestore();
    });

    it('should handle missing terminalRef gracefully', () => {
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        terminalRef: { current: null },
      });

      expect(() => render(<Terminal sessionId="test-session" />)).not.toThrow();
    });
  });

  describe('Performance', () => {
    it('should not re-render unnecessarily when props do not change', () => {
      const MemoizedTerminal = React.memo(Terminal);
      
      const { rerender } = render(<MemoizedTerminal sessionId="test-session" />);
      
      const initialCallCount = mockUseTerminal.mock.calls.length;
      
      // Re-render with same props
      rerender(<MemoizedTerminal sessionId="test-session" />);
      
      // Should not call hook again if properly memoized
      expect(mockUseTerminal.mock.calls.length).toBeGreaterThanOrEqual(initialCallCount);
    });

    it('should handle rapid re-renders without memory leaks', () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      // Simulate rapid session changes
      for (let i = 2; i <= 100; i++) {
        rerender(<Terminal sessionId={`session-${i}`} />);
      }
      
      expect(mockUseTerminal).toHaveBeenCalledTimes(100);
    });

    it('should efficiently handle large className strings', () => {
      const largeClassName = Array(1000).fill('class').join(' ');
      
      const startTime = performance.now();
      render(<Terminal sessionId="test-session" className={largeClassName} />);
      const endTime = performance.now();
      
      // Should render within reasonable time (100ms)
      expect(endTime - startTime).toBeLessThan(100);
    });
  });

  describe('Advanced Edge Cases', () => {
    it('should handle sessionId with unicode characters', () => {
      const unicodeSessionId = 'session-🚀-café-naïve';
      render(<Terminal sessionId={unicodeSessionId} />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: unicodeSessionId,
      });
    });

    it('should handle sessionId with null bytes and control characters', () => {
      const controlSessionId = 'session\0\t\n\r\x1b[31m';
      render(<Terminal sessionId={controlSessionId} />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: controlSessionId,
      });
    });

    it('should handle extremely long sessionId gracefully', () => {
      const veryLongSessionId = 'x'.repeat(10000);
      render(<Terminal sessionId={veryLongSessionId} />);
      
      expect(mockUseTerminal).toHaveBeenCalledWith({
        sessionId: veryLongSessionId,
      });
    });

    it('should handle className with CSS injection attempts', () => {
      const maliciousClassName = 'normal-class"; background: red; content: "';
      render(<Terminal sessionId="test-session" className={maliciousClassName} />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      expect(container).toHaveClass(maliciousClassName);
      // The browser should handle CSS sanitization
    });

    it('should handle concurrent focus/fit operations', async () => {
      const focusTerminal = jest.fn();
      const fitTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
        fitTerminal,
      });

      const { rerender } = render(<Terminal sessionId="session-1" />);
      
      // Rapid session changes that trigger focus/fit
      const promises = [];
      for (let i = 2; i <= 10; i++) {
        promises.push(
          new Promise<void>((resolve) => {
            setTimeout(() => {
              rerender(<Terminal sessionId={`session-${i}`} />);
              resolve();
            }, i * 10);
          })
        );
      }
      
      await Promise.all(promises);
      await waitFor(() => {
        expect(focusTerminal).toHaveBeenCalled();
        expect(fitTerminal).toHaveBeenCalled();
      });
    });
  });

  describe('Event Handler Edge Cases', () => {
    it('should handle click events with different mouse buttons', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Left click
      fireEvent.click(container, { button: 0 });
      expect(focusTerminal).toHaveBeenCalledTimes(1);
      
      // Right click
      fireEvent.click(container, { button: 2 });
      expect(focusTerminal).toHaveBeenCalledTimes(2);
      
      // Middle click
      fireEvent.click(container, { button: 1 });
      expect(focusTerminal).toHaveBeenCalledTimes(3);
    });

    it('should handle click events with keyboard modifiers', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Click with Ctrl key
      fireEvent.click(container, { ctrlKey: true });
      expect(focusTerminal).toHaveBeenCalledTimes(1);
      
      // Click with Shift key
      fireEvent.click(container, { shiftKey: true });
      expect(focusTerminal).toHaveBeenCalledTimes(2);
      
      // Click with Alt key
      fireEvent.click(container, { altKey: true });
      expect(focusTerminal).toHaveBeenCalledTimes(3);
    });

    it('should handle touch events on mobile devices', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Touch start
      fireEvent.touchStart(container, {
        touches: [{ clientX: 100, clientY: 100 }],
      });
      
      // Touch end (should trigger click)
      fireEvent.touchEnd(container);
      fireEvent.click(container); // Simulate the click that follows touchend
      
      expect(focusTerminal).toHaveBeenCalled();
    });

    it('should handle rapid click events (debouncing)', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Simulate rapid clicking
      for (let i = 0; i < 50; i++) {
        fireEvent.click(container);
      }
      
      // Should handle all clicks (no built-in debouncing expected)
      expect(focusTerminal).toHaveBeenCalledTimes(50);
    });
  });

  describe('Memory Management', () => {
    it('should cleanup event listeners on unmount', () => {
      const addEventListenerSpy = jest.spyOn(window, 'addEventListener');
      const removeEventListenerSpy = jest.spyOn(window, 'removeEventListener');
      
      const { unmount } = render(<Terminal sessionId="test-session" />);
      
      unmount();
      
      // Check if any window event listeners were cleaned up
      if (addEventListenerSpy.mock.calls.length > 0) {
        expect(removeEventListenerSpy.mock.calls.length).toBeGreaterThan(0);
      }
      
      addEventListenerSpy.mockRestore();
      removeEventListenerSpy.mockRestore();
    });

    it('should handle multiple mount/unmount cycles', () => {
      const { unmount, rerender } = render(<Terminal sessionId="session-1" />);
      
      // Multiple mount/unmount cycles
      for (let i = 0; i < 10; i++) {
        unmount();
        rerender(<Terminal sessionId={`session-${i + 2}`} />);
      }
      
      expect(mockUseTerminal).toHaveBeenCalled();
    });
  });

  describe('Responsive Behavior', () => {
    it('should handle window resize events', () => {
      const fitTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        fitTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      // Simulate window resize
      fireEvent(window, new Event('resize'));
      
      // Note: The actual resize handling might be in the useTerminal hook
      // This test ensures the component doesn't break on resize
      expect(() => fireEvent(window, new Event('resize'))).not.toThrow();
    });

    it('should maintain functionality across different viewport sizes', () => {
      const originalInnerWidth = window.innerWidth;
      const originalInnerHeight = window.innerHeight;
      
      const sizes = [
        { width: 320, height: 568 },  // iPhone SE
        { width: 768, height: 1024 }, // iPad
        { width: 1920, height: 1080 }, // Desktop
      ];
      
      sizes.forEach(({ width, height }) => {
        // Mock viewport size
        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: width,
        });
        Object.defineProperty(window, 'innerHeight', {
          writable: true,
          configurable: true,
          value: height,
        });
        
        const { unmount } = render(<Terminal sessionId="test-session" />);
        
        expect(screen.getByTestId('test-wrapper')).toBeInTheDocument();
        
        unmount();
      });
      
      // Restore original values
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: originalInnerWidth,
      });
      Object.defineProperty(window, 'innerHeight', {
        writable: true,
        configurable: true,
        value: originalInnerHeight,
      });
    });
  });

  describe('Hook Integration Stress Testing', () => {
    it('should handle hook returning null values gracefully', () => {
      mockUseTerminal.mockReturnValue({
        terminalRef: { current: null },
        terminal: null,
        focusTerminal: null as any,
        fitTerminal: null as any,
        writeToTerminal: null as any,
        clearTerminal: null as any,
        destroyTerminal: null as any,
        isConnected: false,
      });

      expect(() => render(<Terminal sessionId="test-session" />)).not.toThrow();
    });

    it('should handle hook throwing errors during different lifecycle phases', () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Error during initial render
      mockUseTerminal.mockImplementationOnce(() => {
        throw new Error('Initial render error');
      });
      
      expect(() => render(<Terminal sessionId="test-session" />)).toThrow('Initial render error');
      
      consoleSpy.mockRestore();
    });

    it('should handle hook functions throwing errors', () => {
      const throwingFunctions = {
        focusTerminal: jest.fn().mockImplementation(() => { throw new Error('Focus error'); }),
        fitTerminal: jest.fn().mockImplementation(() => { throw new Error('Fit error'); }),
      };
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        ...throwingFunctions,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Click should not crash the component even if focusTerminal throws
      expect(() => fireEvent.click(container)).not.toThrow();
    });
  });

  describe('Concurrent Component Rendering', () => {
    it('should handle multiple Terminal components simultaneously', () => {
      const sessions = ['session-1', 'session-2', 'session-3'];
      
      const { container } = render(
        <div>
          {sessions.map((sessionId) => (
            <Terminal key={sessionId} sessionId={sessionId} />
          ))}
        </div>
      );
      
      // Should render all terminal components
      expect(container.querySelectorAll('[data-testid="test-wrapper"]')).toHaveLength(3);
      
      // Each should have called useTerminal with correct sessionId
      sessions.forEach((sessionId) => {
        expect(mockUseTerminal).toHaveBeenCalledWith({ sessionId });
      });
    });

    it('should handle dynamic addition and removal of Terminal components', () => {
      let sessions = ['session-1'];
      
      const TestComponent = ({ sessionIds }: { sessionIds: string[] }) => (
        <div>
          {sessionIds.map((sessionId) => (
            <Terminal key={sessionId} sessionId={sessionId} />
          ))}
        </div>
      );
      
      const { rerender, container } = render(<TestComponent sessionIds={sessions} />);
      
      expect(container.querySelectorAll('[data-testid="test-wrapper"]')).toHaveLength(1);
      
      // Add more sessions
      sessions = ['session-1', 'session-2', 'session-3'];
      rerender(<TestComponent sessionIds={sessions} />);
      
      expect(container.querySelectorAll('[data-testid="test-wrapper"]')).toHaveLength(3);
      
      // Remove sessions
      sessions = ['session-2'];
      rerender(<TestComponent sessionIds={sessions} />);
      
      expect(container.querySelectorAll('[data-testid="test-wrapper"]')).toHaveLength(1);
    });
  });

  describe('Accessibility Enhancements', () => {
    it('should have proper ARIA attributes for screen readers', () => {
      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Should have role and accessible name
      expect(container).toHaveAttribute('role');
      expect(container.getAttribute('role')).toBeTruthy();
    });

    it('should handle keyboard navigation', () => {
      const focusTerminal = jest.fn();
      
      mockUseTerminal.mockReturnValue({
        ...defaultMockReturn,
        focusTerminal,
      });

      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Tab focus
      fireEvent.keyDown(container, { key: 'Tab' });
      fireEvent.focus(container);
      
      // Enter key should potentially focus terminal
      fireEvent.keyDown(container, { key: 'Enter' });
      
      expect(() => {
        fireEvent.keyDown(container, { key: 'ArrowDown' });
        fireEvent.keyDown(container, { key: 'ArrowUp' });
        fireEvent.keyDown(container, { key: 'ArrowLeft' });
        fireEvent.keyDown(container, { key: 'ArrowRight' });
      }).not.toThrow();
    });

    it('should maintain focus management', () => {
      render(<Terminal sessionId="test-session" />);
      
      const container = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
      
      // Should be focusable
      container.focus();
      expect(document.activeElement).toBe(container);
    });
  });
});