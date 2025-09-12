/**
 * Comprehensive Error Handling Test Suite
 * 
 * Tests error boundaries, WebSocket failures, and edge case error scenarios.
 * Focuses on application resilience and graceful failure modes.
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';
import '@testing-library/jest-dom';

import { createTestWrapper, mockWebSocket, createMockTerminal } from '../utils/test-helpers';
import ErrorBoundary from '../../src/components/ErrorBoundary';

// Mock dependencies
const mockSocket = mockWebSocket();
jest.mock('socket.io-client', () => ({
  io: jest.fn(() => mockSocket),
}));

jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => createMockTerminal()),
}));

// Console error suppression for error boundary tests
const originalError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalError;
});

describe('Comprehensive Error Handling Tests', () => {
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup();
    jest.clearAllMocks();
    mockSocket.resetMocks();
    (console.error as jest.Mock).mockClear();
  });

  describe('Error Boundary Tests', () => {
    const ThrowError = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
      if (shouldThrow) {
        throw new Error('Test component error');
      }
      return <div data-testid="working-component">Working</div>;
    };

    it('should catch and display component errors', () => {
      const { rerender } = render(
        <ErrorBoundary fallback={<div>Something went wrong</div>}>
          <ThrowError />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('working-component')).toBeInTheDocument();

      // Trigger error
      rerender(
        <ErrorBoundary fallback={<div>Something went wrong</div>}>
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );

      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(console.error).toHaveBeenCalled();
    });

    it('should allow error recovery with reset', () => {
      const TestComponent = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
        if (shouldThrow) {
          throw new Error('Recoverable error');
        }
        return <div data-testid="recovered-component">Recovered</div>;
      };

      const { rerender } = render(
        <ErrorBoundary 
          fallback={
            <div>
              <p>Error occurred</p>
              <button onClick={() => window.location.reload()}>Retry</button>
            </div>
          }
        >
          <TestComponent shouldThrow />
        </ErrorBoundary>
      );

      expect(screen.getByText('Error occurred')).toBeInTheDocument();

      // Simulate recovery
      rerender(
        <ErrorBoundary 
          fallback={
            <div>
              <p>Error occurred</p>
              <button onClick={() => window.location.reload()}>Retry</button>
            </div>
          }
        >
          <TestComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('recovered-component')).toBeInTheDocument();
    });

    it('should handle async component errors', async () => {
      const AsyncThrowError = () => {
        const [shouldError, setShouldError] = React.useState(false);

        React.useEffect(() => {
          if (shouldError) {
            throw new Error('Async error');
          }
        }, [shouldError]);

        return (
          <div>
            <button onClick={() => setShouldError(true)}>Trigger Error</button>
            <div data-testid="async-component">Async Component</div>
          </div>
        );
      };

      render(
        <ErrorBoundary fallback={<div>Async error caught</div>}>
          <AsyncThrowError />
        </ErrorBoundary>
      );

      const triggerButton = screen.getByText('Trigger Error');
      
      await act(async () => {
        fireEvent.click(triggerButton);
      });

      await waitFor(() => {
        expect(screen.getByText('Async error caught')).toBeInTheDocument();
      });
    });
  });

  describe('WebSocket Error Handling', () => {
    it('should handle connection timeout gracefully', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Simulate connection timeout
      mockSocket.triggerEvent('connect_timeout');

      await waitFor(() => {
        expect(screen.getByText(/connection timeout/i)).toBeInTheDocument();
      });

      // Should attempt reconnection
      expect(mockSocket.connect).toHaveBeenCalledTimes(2); // Initial + retry
    });

    it('should handle server errors with proper feedback', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Simulate server error
      mockSocket.triggerEvent('connect_error', new Error('Server unavailable'));

      await waitFor(() => {
        expect(screen.getByText(/server unavailable/i)).toBeInTheDocument();
      });

      // Should show retry option
      const retryButton = screen.getByRole('button', { name: /retry/i });
      expect(retryButton).toBeInTheDocument();

      await user.click(retryButton);
      expect(mockSocket.connect).toHaveBeenCalled();
    });

    it('should handle malformed WebSocket data', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Send malformed data
      mockSocket.triggerEvent('data', 'invalid-json');
      mockSocket.triggerEvent('data', null);
      mockSocket.triggerEvent('data', undefined);

      // Application should remain stable
      await waitFor(() => {
        expect(screen.getByRole('main')).toBeInTheDocument();
      });

      // Error should be logged but not crash app
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle rapid connection state changes', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Rapid connect/disconnect cycles
      for (let i = 0; i < 5; i++) {
        mockSocket.triggerEvent('disconnect', 'transport close');
        mockSocket.triggerEvent('connect');
        mockSocket.triggerEvent('disconnect', 'client disconnect');
        mockSocket.triggerEvent('reconnect');
      }

      // Should stabilize eventually
      await waitFor(() => {
        expect(mockSocket.connected).toBe(true);
      });

      expect(screen.getByRole('main')).toBeInTheDocument();
    });
  });

  describe('Terminal Error Scenarios', () => {
    it('should handle terminal initialization failures', async () => {
      // Mock terminal creation failure
      const mockTerminalConstructor = jest.fn(() => {
        throw new Error('Terminal initialization failed');
      });
      
      jest.doMock('@xterm/xterm', () => ({
        Terminal: mockTerminalConstructor,
      }));

      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);

      await waitFor(() => {
        expect(screen.getByText(/terminal error/i)).toBeInTheDocument();
      });
    });

    it('should handle terminal process crashes', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Create terminal
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);

      mockSocket.triggerEvent('session-created', { sessionId: 'test-session' });

      // Simulate process crash
      mockSocket.triggerEvent('session-error', {
        sessionId: 'test-session',
        error: 'Process terminated unexpectedly',
        code: 1
      });

      await waitFor(() => {
        expect(screen.getByText(/process terminated/i)).toBeInTheDocument();
      });

      // Should offer restart option
      const restartButton = screen.getByRole('button', { name: /restart/i });
      expect(restartButton).toBeInTheDocument();
    });

    it('should handle memory exhaustion gracefully', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Simulate memory pressure
      const memoryPressureEvent = new Event('memoryPressure');
      Object.defineProperty(memoryPressureEvent, 'detail', {
        value: { level: 'critical' },
        writable: false
      });

      act(() => {
        window.dispatchEvent(memoryPressureEvent);
      });

      await waitFor(() => {
        expect(screen.getByText(/memory/i)).toBeInTheDocument();
      });
    });
  });

  describe('Input Validation and Sanitization', () => {
    it('should sanitize potentially dangerous input', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Dangerous inputs that should be sanitized
      const dangerousInputs = [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '"><script>alert("xss")</script>',
        '\x00\x01\x02', // null bytes and control characters
      ];

      for (const input of dangerousInputs) {
        mockSocket.triggerEvent('data', { data: input });
      }

      // Check that dangerous content is not rendered unsafely
      const scriptTags = document.querySelectorAll('script');
      const dangerousContent = Array.from(scriptTags).some(script => 
        script.textContent?.includes('alert("xss")')
      );

      expect(dangerousContent).toBe(false);
    });

    it('should handle extremely large data payloads', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Create very large payload (10MB string)
      const largePayload = 'A'.repeat(10 * 1024 * 1024);

      // Monitor memory usage
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;

      mockSocket.triggerEvent('data', { data: largePayload });

      await waitFor(() => {
        // Application should remain responsive
        expect(screen.getByRole('main')).toBeInTheDocument();
      });

      // Memory should not explode (within reasonable bounds)
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Should not use more than 50MB additional memory
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe('Network Error Recovery', () => {
    it('should handle network unavailability', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Simulate network offline
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: false,
      });

      const offlineEvent = new Event('offline');
      act(() => {
        window.dispatchEvent(offlineEvent);
      });

      await waitFor(() => {
        expect(screen.getByText(/offline/i)).toBeInTheDocument();
      });

      // Simulate network back online
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: true,
      });

      const onlineEvent = new Event('online');
      act(() => {
        window.dispatchEvent(onlineEvent);
      });

      await waitFor(() => {
        expect(screen.queryByText(/offline/i)).not.toBeInTheDocument();
      });
    });

    it('should handle intermittent connectivity', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Simulate intermittent connectivity
      for (let i = 0; i < 3; i++) {
        mockSocket.triggerEvent('disconnect', 'ping timeout');
        
        await new Promise(resolve => setTimeout(resolve, 100));
        
        mockSocket.triggerEvent('reconnect', i + 1);
      }

      // Should eventually stabilize
      await waitFor(() => {
        expect(mockSocket.connected).toBe(true);
      });

      expect(screen.getByRole('main')).toBeInTheDocument();
    });
  });

  describe('State Corruption Recovery', () => {
    it('should recover from corrupted application state', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Simulate state corruption by dispatching invalid actions
      const corruptAction = {
        type: 'CORRUPT_STATE',
        payload: { invalid: 'data' }
      };

      // This should be handled gracefully by the store
      act(() => {
        window.dispatchEvent(new CustomEvent('stateUpdate', { detail: corruptAction }));
      });

      // Application should remain functional
      await waitFor(() => {
        expect(screen.getByRole('main')).toBeInTheDocument();
      });
    });

    it('should handle localStorage corruption', async () => {
      // Corrupt localStorage data
      localStorage.setItem('app-state', 'invalid-json{');
      localStorage.setItem('user-preferences', null as any);

      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });

      // Should load with default state instead of crashing
      await waitFor(() => {
        expect(screen.getByRole('main')).toBeInTheDocument();
      });

      // Should have cleared corrupted data
      expect(localStorage.getItem('app-state')).toBeNull();
    });
  });
});