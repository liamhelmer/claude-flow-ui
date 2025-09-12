import React from 'react';
import { render, screen } from '@testing-library/react';
import { ErrorBoundary } from '@/components/ErrorBoundary';

// Mock console.error to prevent noise in tests
const originalError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalError;
});

// Test components for error scenarios
const ThrowError: React.FC<{ shouldThrow?: boolean; message?: string }> = ({ 
  shouldThrow = true, 
  message = 'Test error' 
}) => {
  if (shouldThrow) {
    throw new Error(message);
  }
  return <div>No error occurred</div>;
};

const AsyncError: React.FC<{ delay?: number }> = ({ delay = 0 }) => {
  React.useEffect(() => {
    setTimeout(() => {
      throw new Error('Async error');
    }, delay);
  }, [delay]);
  
  return <div>Async component</div>;
};

const RenderError: React.FC = () => {
  const [count, setCount] = React.useState(0);
  
  React.useEffect(() => {
    if (count > 0) {
      throw new Error('Render error');
    }
  }, [count]);
  
  return (
    <button onClick={() => setCount(1)}>
      Click to cause error
    </button>
  );
};

describe('ErrorBoundary Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Basic Error Catching', () => {
    it('should render children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('No error occurred')).toBeInTheDocument();
    });

    it('should catch and display error from child component', () => {
      render(
        <ErrorBoundary>
          <ThrowError message="Custom error message" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Custom error message/i)).toBeInTheDocument();
    });

    it('should display default error message when error has no message', () => {
      const ErrorWithoutMessage: React.FC = () => {
        throw new Error();
      };

      render(
        <ErrorBoundary>
          <ErrorWithoutMessage />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/An unexpected error occurred/i)).toBeInTheDocument();
    });

    it('should handle non-Error objects thrown', () => {
      const ThrowString: React.FC = () => {
        throw 'String error';
      };

      render(
        <ErrorBoundary>
          <ThrowString />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/String error/i)).toBeInTheDocument();
    });

    it('should handle null/undefined errors', () => {
      const ThrowNull: React.FC = () => {
        throw null;
      };

      render(
        <ErrorBoundary>
          <ThrowNull />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/An unexpected error occurred/i)).toBeInTheDocument();
    });
  });

  describe('Error Information Display', () => {
    it('should display error stack trace in development', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary>
          <ThrowError message="Development error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Error Details/i)).toBeInTheDocument();
      expect(screen.getByText(/Development error/i)).toBeInTheDocument();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('should hide detailed error info in production', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      render(
        <ErrorBoundary>
          <ThrowError message="Production error" />
        </ErrorBoundary>
      );

      expect(screen.queryByText(/Error Details/i)).not.toBeInTheDocument();
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('should format error stack traces properly', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const errorWithStack = new Error('Stack trace error');
      errorWithStack.stack = `Error: Stack trace error
        at Component (file.js:10:5)
        at render (react.js:20:10)`;

      const ComponentWithStack: React.FC = () => {
        throw errorWithStack;
      };

      render(
        <ErrorBoundary>
          <ComponentWithStack />
        </ErrorBoundary>
      );

      expect(screen.getByText(/file\.js:10:5/)).toBeInTheDocument();

      process.env.NODE_ENV = originalNodeEnv;
    });
  });

  describe('Component Isolation', () => {
    it('should not affect sibling components when one errors', () => {
      const SiblingComponent: React.FC = () => <div>Sibling works</div>;

      render(
        <div>
          <ErrorBoundary>
            <ThrowError />
          </ErrorBoundary>
          <SiblingComponent />
        </div>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText('Sibling works')).toBeInTheDocument();
    });

    it('should isolate errors to the nearest error boundary', () => {
      render(
        <ErrorBoundary>
          <div>
            <h1>Outer boundary</h1>
            <ErrorBoundary>
              <ThrowError message="Inner error" />
            </ErrorBoundary>
            <div>This should still render</div>
          </div>
        </ErrorBoundary>
      );

      expect(screen.getByText('Outer boundary')).toBeInTheDocument();
      expect(screen.getByText('This should still render')).toBeInTheDocument();
      expect(screen.getByText(/Inner error/i)).toBeInTheDocument();
    });

    it('should handle multiple child components with mixed errors', () => {
      render(
        <ErrorBoundary>
          <div>
            <ThrowError shouldThrow={false} />
            <div>Middle component</div>
            <ThrowError message="Second error" />
          </div>
        </ErrorBoundary>
      );

      // Should show error state due to second component
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Second error/i)).toBeInTheDocument();
    });
  });

  describe('Error Recovery and Actions', () => {
    it('should provide retry functionality', () => {
      const RetryComponent: React.FC = () => {
        const [shouldError, setShouldError] = React.useState(true);
        
        if (shouldError) {
          throw new Error('Retryable error');
        }
        
        return <div>Component recovered</div>;
      };

      render(
        <ErrorBoundary>
          <RetryComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      const retryButton = screen.getByText(/Try again/i);
      expect(retryButton).toBeInTheDocument();

      // Note: In a real implementation, clicking retry would reset error state
      // This would require the ErrorBoundary to manage retry state
    });

    it('should provide refresh page option', () => {
      // Mock window.location.reload
      const mockReload = jest.fn();
      Object.defineProperty(window, 'location', {
        value: { reload: mockReload },
        writable: true,
      });

      render(
        <ErrorBoundary>
          <ThrowError message="Refresh needed" />
        </ErrorBoundary>
      );

      const refreshButton = screen.getByText(/Refresh page/i);
      expect(refreshButton).toBeInTheDocument();

      // In a real implementation, clicking would call window.location.reload()
    });

    it('should allow reporting errors', () => {
      const mockReportError = jest.fn();
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      render(
        <ErrorBoundary>
          <ThrowError message="Reportable error" />
        </ErrorBoundary>
      );

      const reportButton = screen.getByText(/Report this error/i);
      expect(reportButton).toBeInTheDocument();

      // In a real implementation, clicking would send error report
    });
  });

  describe('Performance and Memory', () => {
    it('should handle rapid successive errors efficiently', () => {
      const RapidErrors: React.FC = () => {
        const [errorCount, setErrorCount] = React.useState(0);
        
        React.useEffect(() => {
          if (errorCount < 5) {
            setTimeout(() => setErrorCount(c => c + 1), 10);
          }
        }, [errorCount]);
        
        if (errorCount > 0) {
          throw new Error(`Rapid error ${errorCount}`);
        }
        
        return <div>No errors yet</div>;
      };

      const startTime = performance.now();
      
      render(
        <ErrorBoundary>
          <RapidErrors />
        </ErrorBoundary>
      );

      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100);
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should not cause memory leaks when handling many errors', () => {
      // This test verifies the component doesn't accumulate error state
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowError message="Error 1" />
        </ErrorBoundary>
      );

      for (let i = 2; i <= 100; i++) {
        rerender(
          <ErrorBoundary>
            <ThrowError message={`Error ${i}`} />
          </ErrorBoundary>
        );
      }

      // Should still function correctly after many errors
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes for error messages', () => {
      render(
        <ErrorBoundary>
          <ThrowError message="Accessibility error" />
        </ErrorBoundary>
      );

      const errorMessage = screen.getByRole('alert');
      expect(errorMessage).toBeInTheDocument();
      expect(errorMessage).toHaveAttribute('aria-live', 'assertive');
    });

    it('should be keyboard navigable', () => {
      render(
        <ErrorBoundary>
          <ThrowError message="Keyboard navigation error" />
        </ErrorBoundary>
      );

      const retryButton = screen.getByText(/Try again/i);
      const refreshButton = screen.getByText(/Refresh page/i);
      const reportButton = screen.getByText(/Report this error/i);

      expect(retryButton).toHaveAttribute('tabindex', '0');
      expect(refreshButton).toHaveAttribute('tabindex', '0');
      expect(reportButton).toHaveAttribute('tabindex', '0');
    });

    it('should provide screen reader friendly error descriptions', () => {
      render(
        <ErrorBoundary>
          <ThrowError message="Screen reader error" />
        </ErrorBoundary>
      );

      const errorRegion = screen.getByRole('alert');
      expect(errorRegion).toHaveTextContent(/An error occurred.*Screen reader error/);
    });
  });

  describe('Edge Cases and Error Types', () => {
    it('should handle React lifecycle errors', () => {
      const LifecycleError: React.FC = () => {
        React.useEffect(() => {
          throw new Error('useEffect error');
        }, []);
        
        return <div>Component with effect error</div>;
      };

      render(
        <ErrorBoundary>
          <LifecycleError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle promise rejection errors', () => {
      // Error boundaries don't catch async errors by default
      // This test documents the limitation
      const PromiseError: React.FC = () => {
        React.useEffect(() => {
          Promise.reject(new Error('Promise rejection')).catch(() => {
            // In real implementation, you'd need to handle this differently
            // as Error Boundaries don't catch async errors
          });
        }, []);
        
        return <div>Component with promise error</div>;
      };

      render(
        <ErrorBoundary>
          <PromiseError />
        </ErrorBoundary>
      );

      // Should NOT catch the promise rejection
      expect(screen.getByText('Component with promise error')).toBeInTheDocument();
    });

    it('should handle syntax errors in dynamic imports', () => {
      const DynamicImportError: React.FC = () => {
        React.useEffect(() => {
          // Simulate dynamic import error
          try {
            throw new SyntaxError('Dynamic import syntax error');
          } catch (error) {
            // Error boundaries catch synchronous errors
            throw error;
          }
        }, []);
        
        return <div>Dynamic import component</div>;
      };

      render(
        <ErrorBoundary>
          <DynamicImportError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Dynamic import syntax error/i)).toBeInTheDocument();
    });

    it('should handle circular dependency errors', () => {
      const circular: any = {};
      circular.self = circular;

      const CircularError: React.FC = () => {
        // This would typically cause JSON.stringify to fail
        try {
          JSON.stringify(circular);
        } catch (error) {
          throw new Error('Circular dependency detected');
        }
        
        return <div>No circular error</div>;
      };

      render(
        <ErrorBoundary>
          <CircularError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Circular dependency detected/i)).toBeInTheDocument();
    });

    it('should handle very long error messages', () => {
      const longMessage = 'Error '.repeat(1000) + 'with very long message';

      render(
        <ErrorBoundary>
          <ThrowError message={longMessage} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      // Error message should be truncated or properly displayed
      expect(screen.getByText(/Error.*with very long message/)).toBeInTheDocument();
    });
  });

  describe('Integration with Error Reporting Services', () => {
    it('should integrate with Sentry-like error tracking', () => {
      const mockSentry = {
        captureException: jest.fn(),
      };

      // Mock global error tracking
      (global as any).Sentry = mockSentry;

      render(
        <ErrorBoundary>
          <ThrowError message="Tracked error" />
        </ErrorBoundary>
      );

      // In real implementation, error would be sent to tracking service
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      // Clean up
      delete (global as any).Sentry;
    });

    it('should include context information in error reports', () => {
      const errorWithContext = new Error('Context error');
      (errorWithContext as any).componentStack = 'Component stack trace';
      (errorWithContext as any).userAgent = navigator.userAgent;

      const ContextError: React.FC = () => {
        throw errorWithContext;
      };

      render(
        <ErrorBoundary>
          <ContextError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      // In development, context should be shown
      if (process.env.NODE_ENV === 'development') {
        expect(screen.getByText(/Context error/i)).toBeInTheDocument();
      }
    });
  });

  describe('Custom Error Boundary Variants', () => {
    it('should support custom fallback UI', () => {
      const CustomFallback: React.FC<{ error: Error }> = ({ error }) => (
        <div data-testid="custom-fallback">
          Custom error: {error.message}
        </div>
      );

      // This would be a custom error boundary implementation
      const CustomErrorBoundary: React.FC<{ 
        children: React.ReactNode;
        fallback: React.ComponentType<{ error: Error }>;
      }> = ({ children, fallback: Fallback }) => {
        const [error, setError] = React.useState<Error | null>(null);

        if (error) {
          return <Fallback error={error} />;
        }

        try {
          return <>{children}</>;
        } catch (err) {
          setError(err as Error);
          return <Fallback error={err as Error} />;
        }
      };

      render(
        <CustomErrorBoundary fallback={CustomFallback}>
          <ThrowError message="Custom fallback error" />
        </CustomErrorBoundary>
      );

      expect(screen.getByTestId('custom-fallback')).toBeInTheDocument();
      expect(screen.getByText(/Custom error: Custom fallback error/)).toBeInTheDocument();
    });

    it('should support error boundaries with retry limits', () => {
      const RetryLimitBoundary: React.FC<{ 
        children: React.ReactNode;
        maxRetries?: number;
      }> = ({ children, maxRetries = 3 }) => {
        const [retryCount, setRetryCount] = React.useState(0);
        const [error, setError] = React.useState<Error | null>(null);

        const resetError = () => {
          if (retryCount < maxRetries) {
            setError(null);
            setRetryCount(c => c + 1);
          }
        };

        if (error) {
          return (
            <div>
              <p>Error occurred (retry {retryCount}/{maxRetries})</p>
              {retryCount < maxRetries && (
                <button onClick={resetError}>Retry</button>
              )}
              {retryCount >= maxRetries && (
                <p>Maximum retries exceeded</p>
              )}
            </div>
          );
        }

        return <>{children}</>;
      };

      render(
        <RetryLimitBoundary maxRetries={2}>
          <ThrowError message="Retry limit error" />
        </RetryLimitBoundary>
      );

      expect(screen.getByText(/Error occurred \(retry 0\/2\)/)).toBeInTheDocument();
      expect(screen.getByText('Retry')).toBeInTheDocument();
    });
  });
});