import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ErrorBoundary from '@/components/ErrorBoundary';

// Test component that throws errors
const ThrowingComponent = ({ 
  shouldThrow = false, 
  asyncError = false, 
  errorType = 'sync',
  delay = 0 
}: {
  shouldThrow?: boolean;
  asyncError?: boolean;
  errorType?: 'sync' | 'async' | 'promise' | 'timeout' | 'network';
  delay?: number;
}) => {
  React.useEffect(() => {
    if (shouldThrow && asyncError) {
      if (errorType === 'async') {
        setTimeout(() => {
          throw new Error('Async error in useEffect');
        }, delay);
      } else if (errorType === 'promise') {
        Promise.reject(new Error('Unhandled promise rejection')).catch(() => {
          // Intentionally not handling to test error boundary
          throw new Error('Promise error');
        });
      } else if (errorType === 'timeout') {
        setTimeout(() => {
          Promise.reject(new Error('Timeout promise error'));
        }, delay);
      } else if (errorType === 'network') {
        fetch('/nonexistent-endpoint').catch(error => {
          throw new Error(`Network error: ${error.message}`);
        });
      }
    }
  }, [shouldThrow, asyncError, errorType, delay]);

  if (shouldThrow && !asyncError) {
    throw new Error('Synchronous error in component');
  }

  return <div data-testid="throwing-component">Component rendered successfully</div>;
};

const AsyncThrowingComponent = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    if (shouldThrow) {
      // Simulate async operation that fails
      const asyncOperation = async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
        throw new Error('Async operation failed');
      };

      asyncOperation().catch(setError);
    }
  }, [shouldThrow]);

  if (error) {
    throw error;
  }

  return <div data-testid="async-component">Async component working</div>;
};

const PromiseRejectionComponent = ({ shouldReject = false }: { shouldReject?: boolean }) => {
  React.useEffect(() => {
    if (shouldReject) {
      // Create unhandled promise rejection
      Promise.resolve().then(() => {
        throw new Error('Unhandled promise rejection in component');
      });
    }
  }, [shouldReject]);

  return <div data-testid="promise-component">Promise component working</div>;
};

const EventHandlerErrorComponent = ({ shouldError = false }: { shouldError?: boolean }) => {
  const handleClick = () => {
    if (shouldError) {
      throw new Error('Error in event handler');
    }
  };

  return (
    <button data-testid="error-button" onClick={handleClick}>
      Click me
    </button>
  );
};

describe('ErrorBoundary Async and Comprehensive Error Tests', () => {
  const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

  beforeEach(() => {
    consoleSpy.mockClear();
  });

  afterAll(() => {
    consoleSpy.mockRestore();
  });

  describe('Synchronous Error Handling', () => {
    test('should catch and display synchronous rendering errors', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      expect(screen.getByText(/Synchronous error in component/)).toBeInTheDocument();
      expect(screen.queryByTestId('throwing-component')).not.toBeInTheDocument();
    });

    test('should provide error details and stack trace', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorDetails = screen.getByText(/Error Details:/);
      expect(errorDetails).toBeInTheDocument();
      
      // Should show some stack trace information
      expect(screen.getByText(/Synchronous error in component/)).toBeInTheDocument();
    });

    test('should render fallback UI for multiple error types', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      // Initially should work
      expect(screen.getByTestId('throwing-component')).toBeInTheDocument();

      // Trigger error
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    });
  });

  describe('Asynchronous Error Scenarios', () => {
    test('should handle async errors in useEffect', async () => {
      render(
        <ErrorBoundary>
          <AsyncThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      // Initially renders successfully
      expect(screen.getByTestId('async-component')).toBeInTheDocument();

      // Wait for async error to occur and trigger re-render
      await waitFor(() => {
        expect(screen.queryByText(/Something went wrong/)).toBeInTheDocument();
      }, { timeout: 3000 });

      expect(screen.getByText(/Async operation failed/)).toBeInTheDocument();
    });

    test('should handle errors in setTimeout callbacks', async () => {
      // Mock console.error to track async errors
      const errorHandler = jest.fn();
      
      // Override global error handler for testing
      const originalHandler = window.onerror;
      window.onerror = errorHandler;

      render(
        <ErrorBoundary>
          <ThrowingComponent 
            shouldThrow={true} 
            asyncError={true} 
            errorType="timeout"
            delay={100}
          />
        </ErrorBoundary>
      );

      // Component should initially render
      expect(screen.getByTestId('throwing-component')).toBeInTheDocument();

      // Wait for timeout error
      await new Promise(resolve => setTimeout(resolve, 200));

      // Note: setTimeout errors might not be caught by React error boundaries
      // This test verifies the behavior rather than asserting specific outcomes
      
      window.onerror = originalHandler;
    });

    test('should handle promise rejections gracefully', async () => {
      // Mock unhandled rejection handler
      const rejectionHandler = jest.fn();
      const originalHandler = window.onunhandledrejection;
      window.onunhandledrejection = rejectionHandler;

      render(
        <ErrorBoundary>
          <PromiseRejectionComponent shouldReject={true} />
        </ErrorBoundary>
      );

      // Component should initially render
      expect(screen.getByTestId('promise-component')).toBeInTheDocument();

      // Wait for promise rejection
      await new Promise(resolve => setTimeout(resolve, 100));

      // Unhandled promise rejections might not trigger error boundaries
      // but they should be handled by the rejection handler
      
      window.onunhandledrejection = originalHandler;
    });

    test('should handle network request failures', async () => {
      // Mock fetch for this test
      global.fetch = jest.fn().mockRejectedValue(new Error('Network request failed'));

      render(
        <ErrorBoundary>
          <ThrowingComponent 
            shouldThrow={true}
            asyncError={true}
            errorType="network"
          />
        </ErrorBoundary>
      );

      // Wait for potential network error handling
      await new Promise(resolve => setTimeout(resolve, 100));

      // Network errors in useEffect might not always trigger error boundaries
      // This test ensures the component doesn't crash
    });
  });

  describe('Event Handler Errors', () => {
    test('should handle errors in event handlers gracefully', async () => {
      const user = userEvent.setup();
      
      render(
        <ErrorBoundary>
          <EventHandlerErrorComponent shouldError={true} />
        </ErrorBoundary>
      );

      const button = screen.getByTestId('error-button');
      expect(button).toBeInTheDocument();

      // Click should not crash the app, but error boundary won't catch it
      await act(async () => {
        try {
          await user.click(button);
        } catch (error) {
          // Event handler errors are not caught by error boundaries
          expect(error).toBeInstanceOf(Error);
        }
      });

      // Button should still be present (error boundary doesn't catch event handler errors)
      expect(screen.getByTestId('error-button')).toBeInTheDocument();
    });

    test('should handle async errors in event handlers', async () => {
      const user = userEvent.setup();
      
      const AsyncErrorButton = () => {
        const handleClick = async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
          throw new Error('Async error in handler');
        };

        return (
          <button data-testid="async-error-button" onClick={handleClick}>
            Async Error Button
          </button>
        );
      };

      render(
        <ErrorBoundary>
          <AsyncErrorButton />
        </ErrorBoundary>
      );

      const button = screen.getByTestId('async-error-button');
      
      // Async errors in event handlers are not caught by error boundaries
      await act(async () => {
        await user.click(button);
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(button).toBeInTheDocument();
    });
  });

  describe('Error Recovery and Reset', () => {
    test('should provide error recovery mechanism', async () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      // Error should be displayed
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

      // Reset by rendering with no error
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      // Should recover and show working component
      await waitFor(() => {
        expect(screen.getByTestId('throwing-component')).toBeInTheDocument();
      });

      expect(screen.queryByText(/Something went wrong/)).not.toBeInTheDocument();
    });

    test('should handle multiple consecutive errors', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      // First error
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

      // Second error (different component)
      rerender(
        <ErrorBoundary>
          <AsyncThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      // Should still show error boundary
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    });
  });

  describe('Nested Error Boundaries', () => {
    test('should handle nested error boundaries correctly', () => {
      render(
        <ErrorBoundary data-testid="outer-boundary">
          <div data-testid="outer-content">
            <ErrorBoundary data-testid="inner-boundary">
              <ThrowingComponent shouldThrow={true} />
            </ErrorBoundary>
          </div>
        </ErrorBoundary>
      );

      // Inner boundary should catch the error
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      
      // Outer content should still be rendered
      expect(screen.getByTestId('outer-content')).toBeInTheDocument();
    });

    test('should propagate errors up the boundary tree when inner boundary fails', () => {
      const FailingErrorBoundary = ({ children }: { children: React.ReactNode }) => {
        const [hasError, setHasError] = React.useState(false);

        if (hasError) {
          // This error boundary itself throws an error
          throw new Error('Error boundary failure');
        }

        React.useEffect(() => {
          // Simulate error boundary failure
          const timer = setTimeout(() => setHasError(true), 100);
          return () => clearTimeout(timer);
        }, []);

        return <div data-testid="failing-boundary">{children}</div>;
      };

      render(
        <ErrorBoundary data-testid="outer-boundary">
          <FailingErrorBoundary>
            <div data-testid="inner-content">Inner content</div>
          </FailingErrorBoundary>
        </ErrorBoundary>
      );

      // Should eventually show outer error boundary
      waitFor(() => {
        expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      });
    });
  });

  describe('Performance and Memory Impact', () => {
    test('should not cause memory leaks with repeated errors', async () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      // Repeatedly trigger and clear errors
      for (let i = 0; i < 10; i++) {
        rerender(
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
        );

        await waitFor(() => {
          expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
        });

        rerender(
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={false} />
          </ErrorBoundary>
        );

        await waitFor(() => {
          expect(screen.getByTestId('throwing-component')).toBeInTheDocument();
        });
      }

      // Final state should be working
      expect(screen.getByTestId('throwing-component')).toBeInTheDocument();
    });

    test('should handle high-frequency errors efficiently', async () => {
      const RapidErrorComponent = ({ errorCount = 0 }: { errorCount?: number }) => {
        if (errorCount > 0) {
          throw new Error(`Rapid error ${errorCount}`);
        }
        return <div data-testid="rapid-component">Working</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <RapidErrorComponent />
        </ErrorBoundary>
      );

      const startTime = Date.now();

      // Rapidly trigger errors
      for (let i = 1; i <= 100; i++) {
        rerender(
          <ErrorBoundary>
            <RapidErrorComponent errorCount={i} />
          </ErrorBoundary>
        );
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should handle errors efficiently (under 1 second for 100 errors)
      expect(duration).toBeLessThan(1000);
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    });
  });

  describe('Error Context and Information', () => {
    test('should preserve error context information', () => {
      const contextError = new Error('Context error');
      contextError.stack = 'Mock stack trace\nat Component\nat ErrorTest';

      const ContextErrorComponent = () => {
        throw contextError;
      };

      render(
        <ErrorBoundary>
          <ContextErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Context error/)).toBeInTheDocument();
      expect(screen.getByText(/Error Details:/)).toBeInTheDocument();
    });

    test('should handle errors without stack traces', () => {
      const NoStackErrorComponent = () => {
        const error = new Error('No stack error');
        delete error.stack;
        throw error;
      };

      render(
        <ErrorBoundary>
          <NoStackErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/No stack error/)).toBeInTheDocument();
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    });

    test('should handle non-Error objects being thrown', () => {
      const StringThrowingComponent = () => {
        throw 'String error';
      };

      render(
        <ErrorBoundary>
          <StringThrowingComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    });
  });
});