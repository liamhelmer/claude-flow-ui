/**
 * @jest-environment jsdom
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Mock console methods to capture error logs
const mockConsoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
const mockConsoleWarn = jest.spyOn(console, 'warn').mockImplementation(() => {});

// Enhanced Error Boundary with comprehensive error handling
interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
  errorId: string;
  retryCount: number;
}

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ComponentType<{ 
    error: Error | null; 
    retry: () => void; 
    errorId: string;
    retryCount: number;
  }>;
  onError?: (error: Error, errorInfo: React.ErrorInfo, errorId: string) => void;
  maxRetries?: number;
  resetKeys?: string[];
  resetOnPropsChange?: boolean;
}

class ComprehensiveErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private retryTimeoutId: NodeJS.Timeout | null = null;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: '',
      retryCount: 0,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    const errorId = `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    return {
      hasError: true,
      error,
      errorId,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({
      errorInfo,
    });

    // Call custom error handler
    this.props.onError?.(error, errorInfo, this.state.errorId);

    // Log error details
    console.error('Error Boundary caught an error:', {
      error: error.toString(),
      errorId: this.state.errorId,
      componentStack: errorInfo.componentStack,
      retryCount: this.state.retryCount,
    });
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    const { resetKeys, resetOnPropsChange } = this.props;
    const { hasError } = this.state;

    // Reset on props change if enabled
    if (hasError && resetOnPropsChange && prevProps.children !== this.props.children) {
      this.resetErrorBoundary();
      return;
    }

    // Reset on key changes
    if (hasError && resetKeys && prevProps.resetKeys) {
      const hasResetKeyChanged = resetKeys.some((key, index) => 
        prevProps.resetKeys![index] !== key
      );
      
      if (hasResetKeyChanged) {
        this.resetErrorBoundary();
      }
    }
  }

  resetErrorBoundary = () => {
    if (this.retryTimeoutId) {
      clearTimeout(this.retryTimeoutId);
    }

    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: '',
      retryCount: 0,
    });
  };

  handleRetry = () => {
    const { maxRetries = 3 } = this.props;
    const { retryCount } = this.state;

    if (retryCount >= maxRetries) {
      return;
    }

    // Add exponential backoff
    const delay = Math.min(1000 * Math.pow(2, retryCount), 10000);

    this.retryTimeoutId = setTimeout(() => {
      this.setState(prevState => ({
        hasError: false,
        error: null,
        errorInfo: null,
        retryCount: prevState.retryCount + 1,
      }));
    }, delay);
  };

  render() {
    const { hasError, error, retryCount } = this.state;
    const { children, fallback: Fallback, maxRetries = 3 } = this.props;

    if (hasError) {
      if (Fallback) {
        return (
          <Fallback
            error={error}
            retry={this.handleRetry}
            errorId={this.state.errorId}
            retryCount={retryCount}
          />
        );
      }

      return (
        <div
          role="alert"
          className="error-boundary"
          aria-live="assertive"
          data-testid="error-boundary"
        >
          <div className="error-content">
            <h2>Something went wrong</h2>
            <p>An unexpected error has occurred.</p>
            
            {process.env.NODE_ENV === 'development' && error && (
              <details className="error-details">
                <summary>Error Details (Development Only)</summary>
                <pre>{error.toString()}</pre>
                {this.state.errorInfo && (
                  <pre>{this.state.errorInfo.componentStack}</pre>
                )}
              </details>
            )}

            <div className="error-actions">
              {retryCount < maxRetries ? (
                <button
                  onClick={this.handleRetry}
                  aria-label={`Retry (${retryCount}/${maxRetries})`}
                  disabled={this.retryTimeoutId !== null}
                >
                  Retry ({retryCount}/{maxRetries})
                </button>
              ) : (
                <p>Maximum retry attempts reached. Please refresh the page.</p>
              )}
              
              <button
                onClick={this.resetErrorBoundary}
                aria-label="Reset application"
              >
                Reset
              </button>
            </div>

            <div className="error-id" aria-label={`Error ID: ${this.state.errorId}`}>
              Error ID: {this.state.errorId}
            </div>
          </div>
        </div>
      );
    }

    return children;
  }
}

// Custom Error Fallback Components
const MinimalErrorFallback = ({ error, retry, errorId }: any) => (
  <div role="alert" data-testid="minimal-error-fallback">
    <h3>Error occurred</h3>
    <button onClick={retry}>Try again</button>
    <small>Error ID: {errorId}</small>
  </div>
);

const DetailedErrorFallback = ({ error, retry, errorId, retryCount }: any) => (
  <div role="alert" data-testid="detailed-error-fallback">
    <h3>Detailed Error Information</h3>
    <p><strong>Error:</strong> {error?.message}</p>
    <p><strong>Error ID:</strong> {errorId}</p>
    <p><strong>Retry Count:</strong> {retryCount}</p>
    <button onClick={retry} disabled={retryCount >= 3}>
      {retryCount >= 3 ? 'Max retries reached' : 'Retry'}
    </button>
  </div>
);

// Test Components
const ThrowingComponent = ({ shouldThrow = false, errorMessage = 'Test error' }) => {
  if (shouldThrow) {
    throw new Error(errorMessage);
  }
  return <div>Component working normally</div>;
};

const AsyncThrowingComponent = ({ shouldThrow = false, delay = 100 }) => {
  const [hasThrown, setHasThrown] = React.useState(false);

  React.useEffect(() => {
    if (shouldThrow && !hasThrown) {
      setTimeout(() => {
        setHasThrown(true);
      }, delay);
    }
  }, [shouldThrow, delay, hasThrown]);

  if (hasThrown) {
    throw new Error('Async error');
  }

  return <div>Async component working</div>;
};

const RenderErrorComponent = () => {
  const [shouldError, setShouldError] = React.useState(false);

  return (
    <div>
      <button onClick={() => setShouldError(true)}>
        Trigger Error
      </button>
      {shouldError && <ThrowingComponent shouldThrow />}
    </div>
  );
};

describe('Comprehensive Error Boundary Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  describe('Basic Error Catching', () => {
    test('should catch and display error with default fallback', () => {
      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Basic test error" />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText(/Error ID:/)).toBeInTheDocument();
      expect(mockConsoleError).toHaveBeenCalled();
    });

    test('should not catch error when component is working normally', () => {
      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByText('Component working normally')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('should use custom fallback component', () => {
      render(
        <ComprehensiveErrorBoundary fallback={MinimalErrorFallback}>
          <ThrowingComponent shouldThrow errorMessage="Custom fallback test" />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByTestId('minimal-error-fallback')).toBeInTheDocument();
      expect(screen.getByText('Error occurred')).toBeInTheDocument();
      expect(screen.getByText('Try again')).toBeInTheDocument();
    });
  });

  describe('Error Information and Logging', () => {
    test('should call custom error handler', () => {
      const mockOnError = jest.fn();
      
      render(
        <ComprehensiveErrorBoundary onError={mockOnError}>
          <ThrowingComponent shouldThrow errorMessage="Handler test error" />
        </ComprehensiveErrorBoundary>
      );

      expect(mockOnError).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({
          componentStack: expect.any(String)
        }),
        expect.any(String)
      );
    });

    test('should generate unique error IDs', () => {
      const { rerender } = render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ComprehensiveErrorBoundary>
      );

      // Trigger first error
      rerender(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="First error" />
        </ComprehensiveErrorBoundary>
      );

      const firstErrorId = screen.getByText(/Error ID:/).textContent;

      // Reset and trigger second error
      fireEvent.click(screen.getByText('Reset'));
      
      rerender(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Second error" />
        </ComprehensiveErrorBoundary>
      );

      const secondErrorId = screen.getByText(/Error ID:/).textContent;
      expect(firstErrorId).not.toBe(secondErrorId);
    });

    test('should show development-only error details in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Dev error details" />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByText('Error Details (Development Only)')).toBeInTheDocument();
      expect(screen.getByText('Dev error details')).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });

    test('should hide error details in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Prod error" />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.queryByText('Error Details (Development Only)')).not.toBeInTheDocument();
      expect(screen.queryByText('Prod error')).not.toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Retry Functionality', () => {
    test('should retry and recover from error', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      let shouldThrow = true;

      const { rerender } = render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow={shouldThrow} />
        </ComprehensiveErrorBoundary>
      );

      // Error should be displayed
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Retry (0/3)')).toBeInTheDocument();

      // Fix the error condition
      shouldThrow = false;

      // Click retry
      await user.click(screen.getByText('Retry (0/3)'));

      // Fast-forward timer for retry delay
      jest.advanceTimersByTime(1000);

      // Rerender with fixed component
      rerender(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow={shouldThrow} />
        </ComprehensiveErrorBoundary>
      );

      // Should recover
      await waitFor(() => {
        expect(screen.getByText('Component working normally')).toBeInTheDocument();
      });

      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('should implement exponential backoff for retries', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Backoff test" />
        </ComprehensiveErrorBoundary>
      );

      // First retry - should have 1 second delay
      await user.click(screen.getByText('Retry (0/3)'));
      expect(screen.getByText('Retry (0/3)')).toBeDisabled();

      // Advance by 500ms - should still be disabled
      jest.advanceTimersByTime(500);
      expect(screen.getByText('Retry (0/3)')).toBeDisabled();

      // Advance by another 500ms - should be enabled
      jest.advanceTimersByTime(500);
      
      // Error will trigger again, now with retry count 1
      await waitFor(() => {
        expect(screen.getByText('Retry (1/3)')).toBeInTheDocument();
      });
    });

    test('should disable retry after max attempts', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

      render(
        <ComprehensiveErrorBoundary maxRetries={2}>
          <ThrowingComponent shouldThrow errorMessage="Max retry test" />
        </ComprehensiveErrorBoundary>
      );

      // Exhaust all retry attempts
      for (let i = 0; i < 2; i++) {
        await user.click(screen.getByText(`Retry (${i}/2)`));
        jest.advanceTimersByTime(5000); // Advance enough for any delay
        
        await waitFor(() => {
          expect(screen.getByText(`Retry (${i + 1}/2)`)).toBeInTheDocument();
        });
      }

      // Should show max retries message
      expect(screen.getByText('Maximum retry attempts reached. Please refresh the page.')).toBeInTheDocument();
      expect(screen.queryByText('Retry')).not.toBeInTheDocument();
    });
  });

  describe('Reset Functionality', () => {
    test('should reset error boundary manually', async () => {
      const user = userEvent.setup();

      const { rerender } = render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Reset test" />
        </ComprehensiveErrorBoundary>
      );

      // Error should be displayed
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Click reset
      await user.click(screen.getByText('Reset'));

      // Rerender with working component
      rerender(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ComprehensiveErrorBoundary>
      );

      // Should recover
      expect(screen.getByText('Component working normally')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('should reset on props change when enabled', () => {
      const { rerender } = render(
        <ComprehensiveErrorBoundary resetOnPropsChange>
          <ThrowingComponent shouldThrow errorMessage="Props reset test" />
        </ComprehensiveErrorBoundary>
      );

      // Error should be displayed
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Change props
      rerender(
        <ComprehensiveErrorBoundary resetOnPropsChange>
          <ThrowingComponent shouldThrow={false} />
        </ComprehensiveErrorBoundary>
      );

      // Should automatically reset
      expect(screen.getByText('Component working normally')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('should reset on key changes', () => {
      const { rerender } = render(
        <ComprehensiveErrorBoundary resetKeys={['key1']}>
          <ThrowingComponent shouldThrow errorMessage="Key reset test" />
        </ComprehensiveErrorBoundary>
      );

      // Error should be displayed
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Change reset key
      rerender(
        <ComprehensiveErrorBoundary resetKeys={['key2']}>
          <ThrowingComponent shouldThrow={false} />
        </ComprehensiveErrorBoundary>
      );

      // Should automatically reset
      expect(screen.getByText('Component working normally')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });

  describe('Accessibility Features', () => {
    test('should have proper ARIA attributes', () => {
      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Accessibility test" />
        </ComprehensiveErrorBoundary>
      );

      const alert = screen.getByRole('alert');
      expect(alert).toHaveAttribute('aria-live', 'assertive');
      expect(alert).toHaveAttribute('data-testid', 'error-boundary');

      const retryButton = screen.getByRole('button', { name: /retry/i });
      expect(retryButton).toHaveAttribute('aria-label', 'Retry (0/3)');

      const resetButton = screen.getByRole('button', { name: /reset/i });
      expect(resetButton).toHaveAttribute('aria-label', 'Reset application');
    });

    test('should announce error to screen readers', () => {
      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Screen reader test" />
        </ComprehensiveErrorBoundary>
      );

      const alert = screen.getByRole('alert');
      expect(alert).toBeInTheDocument();
      expect(alert).toHaveAttribute('aria-live', 'assertive');
    });
  });

  describe('Complex Error Scenarios', () => {
    test('should handle errors in event handlers', async () => {
      const user = userEvent.setup();

      const ErrorInEventHandler = () => {
        const handleClick = () => {
          throw new Error('Event handler error');
        };

        return <button onClick={handleClick}>Click to error</button>;
      };

      render(
        <ComprehensiveErrorBoundary>
          <ErrorInEventHandler />
        </ComprehensiveErrorBoundary>
      );

      const button = screen.getByText('Click to error');
      
      // Event handler errors are not caught by error boundaries
      // This tests that the error boundary doesn't interfere
      expect(() => {
        fireEvent.click(button);
      }).toThrow('Event handler error');

      // Component should still be mounted normally
      expect(screen.getByText('Click to error')).toBeInTheDocument();
    });

    test('should handle render-time errors after interaction', async () => {
      const user = userEvent.setup();

      render(
        <ComprehensiveErrorBoundary>
          <RenderErrorComponent />
        </ComprehensiveErrorBoundary>
      );

      // Initially working
      expect(screen.getByText('Trigger Error')).toBeInTheDocument();

      // Trigger error
      await user.click(screen.getByText('Trigger Error'));

      // Should catch render error
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    test('should handle nested error boundaries', () => {
      const NestedErrorComponent = () => {
        throw new Error('Nested error');
      };

      render(
        <ComprehensiveErrorBoundary fallback={DetailedErrorFallback}>
          <div>
            <h1>Outer Component</h1>
            <ComprehensiveErrorBoundary fallback={MinimalErrorFallback}>
              <NestedErrorComponent />
            </ComprehensiveErrorBoundary>
          </div>
        </ComprehensiveErrorBoundary>
      );

      // Inner boundary should catch the error
      expect(screen.getByTestId('minimal-error-fallback')).toBeInTheDocument();
      expect(screen.getByText('Outer Component')).toBeInTheDocument();
      expect(screen.queryByTestId('detailed-error-fallback')).not.toBeInTheDocument();
    });
  });

  describe('Performance and Memory', () => {
    test('should not cause memory leaks during multiple errors', () => {
      const { rerender } = render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ComprehensiveErrorBoundary>
      );

      // Trigger multiple errors
      for (let i = 0; i < 10; i++) {
        rerender(
          <ComprehensiveErrorBoundary>
            <ThrowingComponent shouldThrow errorMessage={`Error ${i}`} />
          </ComprehensiveErrorBoundary>
        );

        fireEvent.click(screen.getByText('Reset'));

        rerender(
          <ComprehensiveErrorBoundary>
            <ThrowingComponent shouldThrow={false} />
          </ComprehensiveErrorBoundary>
        );
      }

      // Should still work normally
      expect(screen.getByText('Component working normally')).toBeInTheDocument();
    });

    test('should cleanup timers on unmount', () => {
      const { unmount } = render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage="Cleanup test" />
        </ComprehensiveErrorBoundary>
      );

      // Start a retry (which sets a timeout)
      fireEvent.click(screen.getByText('Retry (0/3)'));

      // Unmount component
      unmount();

      // Advance timers - should not cause any issues
      jest.advanceTimersByTime(5000);

      // No errors should occur
      expect(mockConsoleError).toHaveBeenCalledTimes(1); // Only the initial error
    });
  });

  describe('Edge Cases', () => {
    test('should handle components that throw non-Error objects', () => {
      const StringThrowingComponent = () => {
        throw 'String error';  // eslint-disable-line no-throw-literal
      };

      render(
        <ComprehensiveErrorBoundary>
          <StringThrowingComponent />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    test('should handle undefined/null errors gracefully', () => {
      const NullThrowingComponent = () => {
        throw null;  // eslint-disable-line no-throw-literal
      };

      render(
        <ComprehensiveErrorBoundary>
          <NullThrowingComponent />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    test('should handle very long error messages', () => {
      const longMessage = 'A'.repeat(1000);
      
      render(
        <ComprehensiveErrorBoundary>
          <ThrowingComponent shouldThrow errorMessage={longMessage} />
        </ComprehensiveErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });
  });
});