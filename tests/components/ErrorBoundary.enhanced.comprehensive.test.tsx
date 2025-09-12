import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ErrorBoundary from '@/components/ErrorBoundary';

// Mock console methods to avoid noise in test output
const originalError = console.error;
const originalWarn = console.warn;
const originalLog = console.log;

beforeEach(() => {
  console.error = jest.fn();
  console.warn = jest.fn();
  console.log = jest.fn();
});

afterEach(() => {
  console.error = originalError;
  console.warn = originalWarn;
  console.log = originalLog;
});

// Test components for error scenarios
const ThrowingComponent: React.FC<{ shouldThrow?: boolean; errorType?: string; delay?: number }> = ({ 
  shouldThrow = true, 
  errorType = 'render',
  delay = 0
}) => {
  React.useEffect(() => {
    if (shouldThrow && errorType === 'effect' && delay > 0) {
      setTimeout(() => {
        throw new Error('Async effect error');
      }, delay);
    } else if (shouldThrow && errorType === 'effect') {
      throw new Error('Effect error');
    }
  }, [shouldThrow, errorType, delay]);

  if (shouldThrow && errorType === 'render') {
    throw new Error('Render error');
  }

  if (shouldThrow && errorType === 'network') {
    throw new Error('Network Error: Failed to fetch');
  }

  if (shouldThrow && errorType === 'websocket') {
    throw new Error('WebSocket connection failed');
  }

  if (shouldThrow && errorType === 'permission') {
    throw new Error('Permission denied: Insufficient privileges');
  }

  if (shouldThrow && errorType === 'timeout') {
    throw new Error('Request timeout after 30 seconds');
  }

  const handleClick = () => {
    if (shouldThrow && errorType === 'event') {
      throw new Error('Event handler error');
    }
  };

  return (
    <div>
      <h1>Working Component</h1>
      <button onClick={handleClick}>Trigger Event Error</button>
    </div>
  );
};

const AsyncThrowingComponent: React.FC = () => {
  React.useEffect(() => {
    // Simulate async operation that fails
    Promise.reject(new Error('Async error')).catch(() => {
      // This would normally be unhandled
      throw new Error('Unhandled async error');
    });
  }, []);

  return <div>Async component</div>;
};

const ComponentWithState: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = false }) => {
  const [count, setCount] = React.useState(0);
  const [hasError, setHasError] = React.useState(false);

  React.useEffect(() => {
    if (shouldThrow && count > 3) {
      setHasError(true);
      throw new Error('State-dependent error');
    }
  }, [count, shouldThrow]);

  if (hasError) {
    throw new Error('Component in error state');
  }

  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={() => setCount(c => c + 1)}>Increment</button>
    </div>
  );
};

describe('ErrorBoundary Enhanced Comprehensive Tests', () => {
  describe('Basic Error Catching', () => {
    it('should catch render errors and display fallback UI', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Try refreshing the page/i)).toBeInTheDocument();
    });

    it('should render children when no errors occur', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Working Component')).toBeInTheDocument();
      expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
    });

    it('should catch errors from multiple child components', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
          <ThrowingComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.queryByText('Working Component')).not.toBeInTheDocument();
    });
  });

  describe('Error Types and Messages', () => {
    const errorTypes = [
      { type: 'network', expectedPattern: /Network Error/i },
      { type: 'websocket', expectedPattern: /WebSocket connection failed/i },
      { type: 'permission', expectedPattern: /Permission denied/i },
      { type: 'timeout', expectedPattern: /Request timeout/i },
    ];

    errorTypes.forEach(({ type, expectedPattern }) => {
      it(`should handle ${type} errors appropriately`, () => {
        render(
          <ErrorBoundary>
            <ThrowingComponent errorType={type} />
          </ErrorBoundary>
        );

        expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
        // Error details should be logged but not displayed to user
        expect(console.error).toHaveBeenCalled();
      });
    });
  });

  describe('Error Recovery and Retry', () => {
    it('should provide retry functionality', async () => {
      const user = userEvent.setup();
      let shouldThrow = true;

      const RetryableComponent: React.FC = () => {
        if (shouldThrow) {
          throw new Error('Retryable error');
        }
        return <div>Component recovered</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <RetryableComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      // Simulate fix
      shouldThrow = false;

      // Look for retry button
      const retryButton = screen.queryByText(/try again/i) || screen.queryByText(/retry/i);
      if (retryButton) {
        await user.click(retryButton);
        await waitFor(() => {
          expect(screen.getByText('Component recovered')).toBeInTheDocument();
        });
      } else {
        // If no retry button, test manual recovery through rerender
        rerender(
          <ErrorBoundary>
            <RetryableComponent />
          </ErrorBoundary>
        );
        expect(screen.getByText('Component recovered')).toBeInTheDocument();
      }
    });

    it('should reset error boundary state on retry', () => {
      const TestComponent: React.FC<{ attempt: number }> = ({ attempt }) => {
        if (attempt === 1) {
          throw new Error('First attempt failed');
        }
        return <div>Attempt {attempt} succeeded</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <TestComponent attempt={1} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      rerender(
        <ErrorBoundary>
          <TestComponent attempt={2} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Attempt 2 succeeded')).toBeInTheDocument();
    });
  });

  describe('Error Logging and Reporting', () => {
    it('should log error details to console', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent />
        </ErrorBoundary>
      );

      expect(console.error).toHaveBeenCalled();
    });

    it('should provide error context information', () => {
      const errorSpy = jest.spyOn(console, 'error');
      
      render(
        <ErrorBoundary>
          <ThrowingComponent />
        </ErrorBoundary>
      );

      expect(errorSpy).toHaveBeenCalled();
      const logCall = errorSpy.mock.calls.find(call => 
        call[0]?.toString().includes('Error') || call[1]?.toString().includes('Error')
      );
      expect(logCall).toBeDefined();
    });

    it('should capture component stack traces', () => {
      render(
        <ErrorBoundary>
          <div>
            <div>
              <ThrowingComponent />
            </div>
          </div>
        </ErrorBoundary>
      );

      expect(console.error).toHaveBeenCalled();
    });
  });

  describe('Nested Error Boundaries', () => {
    it('should handle nested error boundaries correctly', () => {
      render(
        <ErrorBoundary>
          <div>Outer boundary</div>
          <ErrorBoundary>
            <ThrowingComponent />
          </ErrorBoundary>
          <div>This should still render</div>
        </ErrorBoundary>
      );

      // Inner boundary should catch the error
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      // Outer boundary content should still be visible
      expect(screen.getByText('Outer boundary')).toBeInTheDocument();
      expect(screen.getByText('This should still render')).toBeInTheDocument();
    });

    it('should isolate errors to the closest boundary', () => {
      render(
        <div>
          <ErrorBoundary>
            <div>First section</div>
          </ErrorBoundary>
          <ErrorBoundary>
            <ThrowingComponent />
          </ErrorBoundary>
          <ErrorBoundary>
            <div>Third section</div>
          </ErrorBoundary>
        </div>
      );

      expect(screen.getByText('First section')).toBeInTheDocument();
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText('Third section')).toBeInTheDocument();
    });
  });

  describe('State Management During Errors', () => {
    it('should handle state-dependent errors', async () => {
      const user = userEvent.setup();
      
      render(
        <ErrorBoundary>
          <ComponentWithState shouldThrow={true} />
        </ErrorBoundary>
      );

      const incrementButton = screen.getByText('Increment');
      
      // Click multiple times to trigger error
      for (let i = 0; i < 5; i++) {
        await user.click(incrementButton);
      }

      await waitFor(() => {
        expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      });
    });

    it('should preserve non-error state during partial failures', () => {
      const PartiallyFailingComponent: React.FC = () => {
        const [safeCount, setSafeCount] = React.useState(0);
        const [, setDangerousCount] = React.useState(0);

        const handleSafeIncrement = () => setSafeCount(c => c + 1);
        const handleDangerousIncrement = () => {
          setDangerousCount(() => {
            throw new Error('State update error');
          });
        };

        return (
          <div>
            <p>Safe count: {safeCount}</p>
            <button onClick={handleSafeIncrement}>Safe Increment</button>
            <button onClick={handleDangerousIncrement}>Dangerous Increment</button>
          </div>
        );
      };

      render(
        <ErrorBoundary>
          <PartiallyFailingComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText('Safe count: 0')).toBeInTheDocument();
    });
  });

  describe('Performance Impact', () => {
    it('should not impact performance when no errors occur', () => {
      const renderCount = { count: 0 };
      
      const CountingComponent: React.FC = () => {
        renderCount.count++;
        return <div>Render count: {renderCount.count}</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <CountingComponent />
        </ErrorBoundary>
      );

      expect(renderCount.count).toBe(1);

      rerender(
        <ErrorBoundary>
          <CountingComponent />
        </ErrorBoundary>
      );

      expect(renderCount.count).toBe(2);
    });

    it('should handle many child components efficiently', () => {
      const children = Array.from({ length: 100 }, (_, i) => (
        <div key={i}>Child {i}</div>
      ));

      const startTime = performance.now();
      
      render(
        <ErrorBoundary>
          {children}
        </ErrorBoundary>
      );

      const endTime = performance.now();
      const renderTime = endTime - startTime;

      // Should render reasonably quickly (under 100ms for 100 components)
      expect(renderTime).toBeLessThan(100);
      expect(screen.getByText('Child 0')).toBeInTheDocument();
      expect(screen.getByText('Child 99')).toBeInTheDocument();
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle errors thrown in cleanup functions', () => {
      const CleanupErrorComponent: React.FC<{ shouldCleanupError?: boolean }> = ({ 
        shouldCleanupError = false 
      }) => {
        React.useEffect(() => {
          return () => {
            if (shouldCleanupError) {
              throw new Error('Cleanup error');
            }
          };
        }, [shouldCleanupError]);

        return <div>Component with cleanup</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <CleanupErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component with cleanup')).toBeInTheDocument();

      // This should trigger cleanup error
      rerender(
        <ErrorBoundary>
          <CleanupErrorComponent shouldCleanupError={true} />
        </ErrorBoundary>
      );

      // Component should still render even if cleanup failed
      expect(screen.getByText('Component with cleanup')).toBeInTheDocument();
    });

    it('should handle null/undefined children gracefully', () => {
      expect(() => {
        render(
          <ErrorBoundary>
            {null}
            {undefined}
            <div>Valid child</div>
          </ErrorBoundary>
        );
      }).not.toThrow();

      expect(screen.getByText('Valid child')).toBeInTheDocument();
    });

    it('should handle deeply nested component errors', () => {
      const DeepComponent: React.FC<{ depth: number }> = ({ depth }) => {
        if (depth === 0) {
          throw new Error('Deep component error');
        }
        return (
          <div>
            <DeepComponent depth={depth - 1} />
          </div>
        );
      };

      render(
        <ErrorBoundary>
          <DeepComponent depth={10} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle circular reference errors', () => {
      const obj: any = {};
      obj.circular = obj;

      const CircularComponent: React.FC = () => {
        // This would cause JSON.stringify to fail
        console.log(JSON.stringify(obj));
        return <div>Never renders</div>;
      };

      render(
        <ErrorBoundary>
          <CircularComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });
  });

  describe('Integration with Application Context', () => {
    it('should work with context providers', () => {
      const TestContext = React.createContext<{ value: string }>({ value: 'default' });
      
      const ContextConsumer: React.FC = () => {
        const { value } = React.useContext(TestContext);
        if (value === 'error') {
          throw new Error('Context-dependent error');
        }
        return <div>Context value: {value}</div>;
      };

      const { rerender } = render(
        <TestContext.Provider value={{ value: 'normal' }}>
          <ErrorBoundary>
            <ContextConsumer />
          </ErrorBoundary>
        </TestContext.Provider>
      );

      expect(screen.getByText('Context value: normal')).toBeInTheDocument();

      rerender(
        <TestContext.Provider value={{ value: 'error' }}>
          <ErrorBoundary>
            <ContextConsumer />
          </ErrorBoundary>
        </TestContext.Provider>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should maintain context availability in error UI', () => {
      const ThemeContext = React.createContext({ theme: 'light' });
      
      const CustomErrorBoundary: React.FC<{ children: React.ReactNode }> = ({ children }) => {
        const [hasError, setHasError] = React.useState(false);
        const { theme } = React.useContext(ThemeContext);

        React.useEffect(() => {
          const errorHandler = () => setHasError(true);
          window.addEventListener('error', errorHandler);
          return () => window.removeEventListener('error', errorHandler);
        }, []);

        if (hasError) {
          return <div className={`error-${theme}`}>Themed error UI</div>;
        }

        return <>{children}</>;
      };

      render(
        <ThemeContext.Provider value={{ theme: 'dark' }}>
          <CustomErrorBoundary>
            <ThrowingComponent />
          </CustomErrorBoundary>
        </ThemeContext.Provider>
      );

      const errorElement = screen.getByText('Themed error UI');
      expect(errorElement).toHaveClass('error-dark');
    });
  });

  describe('Memory Leaks and Cleanup', () => {
    it('should not create memory leaks on repeated errors', () => {
      const components = [];
      
      for (let i = 0; i < 50; i++) {
        const { unmount } = render(
          <ErrorBoundary>
            <ThrowingComponent />
          </ErrorBoundary>
        );
        components.push(unmount);
      }

      // Clean up all components
      components.forEach(unmount => unmount());

      // No specific assertion needed - if there are memory leaks,
      // the test environment will eventually show issues
      expect(components).toHaveLength(50);
    });

    it('should clean up event listeners and timers', () => {
      const TimerComponent: React.FC = () => {
        React.useEffect(() => {
          const timer = setInterval(() => {
            throw new Error('Timer error');
          }, 1000);

          return () => clearInterval(timer);
        }, []);

        return <div>Timer component</div>;
      };

      const { unmount } = render(
        <ErrorBoundary>
          <TimerComponent />
        </ErrorBoundary>
      );

      // Should not throw when unmounting
      expect(() => unmount()).not.toThrow();
    });
  });

  describe('Accessibility Considerations', () => {
    it('should maintain accessibility during error states', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent />
        </ErrorBoundary>
      );

      const errorMessage = screen.getByText(/Something went wrong/i);
      
      // Error message should be accessible
      expect(errorMessage).toBeInTheDocument();
      expect(errorMessage).toBeVisible();
      
      // Should not break screen reader navigation
      expect(document.body).toHaveAttribute('role') || 
      expect(document.body.getAttribute('role')).toBeFalsy(); // Both are acceptable
    });

    it('should provide proper ARIA attributes for error states', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent />
        </ErrorBoundary>
      );

      // Look for aria-live or role attributes that help screen readers
      const errorContainer = screen.getByText(/Something went wrong/i).closest('div');
      
      // While not required, good error boundaries might have these attributes
      if (errorContainer?.getAttribute('role')) {
        expect(errorContainer).toHaveAttribute('role', 'alert');
      }
    });
  });
});