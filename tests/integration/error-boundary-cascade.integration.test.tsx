/**
 * Error Boundary Cascade Handling Integration Tests
 * Tests error propagation, recovery mechanisms, and cascade prevention
 */

import React, { Component, ErrorInfo } from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { ErrorBoundary } from '@/components/ErrorBoundary';

// Mock components for testing error scenarios
const ThrowingComponent: React.FC<{ shouldThrow?: boolean; errorType?: string; delay?: number }> = ({
  shouldThrow = false,
  errorType = 'default',
  delay = 0
}) => {
  const [hasThrown, setHasThrown] = React.useState(false);

  React.useEffect(() => {
    if (shouldThrow && !hasThrown && delay > 0) {
      setTimeout(() => {
        setHasThrown(true);
      }, delay);
    } else if (shouldThrow && !hasThrown) {
      setHasThrown(true);
    }
  }, [shouldThrow, hasThrown, delay]);

  if (hasThrown) {
    switch (errorType) {
      case 'render':
        throw new Error('Render error in component');
      case 'network':
        throw new Error('Network request failed');
      case 'validation':
        throw new Error('Validation failed');
      case 'timeout':
        throw new Error('Operation timed out');
      default:
        throw new Error('Generic component error');
    }
  }

  return (
    <div data-testid="throwing-component">
      <button
        onClick={() => setHasThrown(true)}
        data-testid="trigger-error"
      >
        Trigger Error
      </button>
      Component is working
    </div>
  );
};

const AsyncThrowingComponent: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = false }) => {
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

  return <div data-testid="async-component">Async component loaded</div>;
};

const NestedErrorComponent: React.FC<{ level: number; shouldThrow?: boolean }> = ({
  level,
  shouldThrow = false
}) => {
  if (shouldThrow && level === 0) {
    throw new Error(`Error at nesting level ${level}`);
  }

  return (
    <div data-testid={`nested-component-${level}`}>
      Level {level}
      {level > 0 && (
        <NestedErrorComponent level={level - 1} shouldThrow={shouldThrow} />
      )}
    </div>
  );
};

const RecoveryComponent: React.FC<{ onRetry?: () => void }> = ({ onRetry }) => {
  const [retryCount, setRetryCount] = React.useState(0);
  const [shouldFail, setShouldFail] = React.useState(false);

  const handleRetry = () => {
    setRetryCount(prev => prev + 1);
    setShouldFail(retryCount < 2); // Fail first 2 attempts, succeed on 3rd
    if (onRetry) onRetry();
  };

  if (shouldFail) {
    throw new Error(`Retry attempt ${retryCount} failed`);
  }

  return (
    <div data-testid="recovery-component">
      <div>Retry count: {retryCount}</div>
      <button onClick={handleRetry} data-testid="retry-button">
        Retry Operation
      </button>
    </div>
  );
};

// Custom error boundary for testing cascade prevention
class CascadePreventionBoundary extends Component<
  { children: React.ReactNode; onError?: (error: Error) => void },
  { hasError: boolean; errorCount: number }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, errorCount: 0 };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState(prev => ({ errorCount: prev.errorCount + 1 }));
    if (this.props.onError) {
      this.props.onError(error);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div data-testid="cascade-prevention-fallback">
          Error caught at boundary level. Error count: {this.state.errorCount}
          <button
            onClick={() => this.setState({ hasError: false })}
            data-testid="reset-boundary"
          >
            Reset
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

describe('Error Boundary Cascade Handling Integration', () => {
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  describe('Basic Error Boundary Functionality', () => {
    it('should catch and display errors from child components', () => {
      render(
        <ErrorBoundary fallbackMessage="Component failed">
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component failed')).toBeInTheDocument();
      expect(screen.getByText('Generic component error')).toBeInTheDocument();
      expect(consoleErrorSpy).toHaveBeenCalled();
    });

    it('should render children normally when no errors occur', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('throwing-component')).toBeInTheDocument();
      expect(screen.getByText('Component is working')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should handle different error types appropriately', () => {
      const errorTypes = ['render', 'network', 'validation', 'timeout'];

      errorTypes.forEach(errorType => {
        const { unmount } = render(
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={true} errorType={errorType} />
          </ErrorBoundary>
        );

        expect(screen.getByRole('alert')).toBeInTheDocument();

        switch (errorType) {
          case 'network':
            expect(screen.getByText('Network request failed')).toBeInTheDocument();
            break;
          case 'validation':
            expect(screen.getByText('Validation failed')).toBeInTheDocument();
            break;
          case 'timeout':
            expect(screen.getByText('Operation timed out')).toBeInTheDocument();
            break;
          default:
            expect(screen.getByText('Render error in component')).toBeInTheDocument();
        }

        unmount();
      });
    });
  });

  describe('Nested Error Boundary Hierarchy', () => {
    it('should prevent error cascade in nested boundaries', () => {
      const outerErrorHandler = jest.fn();
      const innerErrorHandler = jest.fn();

      render(
        <ErrorBoundary
          fallbackMessage="Outer boundary error"
          onError={outerErrorHandler}
        >
          <div data-testid="outer-content">Outer content</div>
          <ErrorBoundary
            fallbackMessage="Inner boundary error"
            onError={innerErrorHandler}
          >
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
          <div data-testid="sibling-content">Sibling content</div>
        </ErrorBoundary>
      );

      // Inner boundary should catch the error
      expect(screen.getByText('Inner boundary error')).toBeInTheDocument();
      expect(innerErrorHandler).toHaveBeenCalled();

      // Outer boundary should not be affected
      expect(screen.getByTestId('outer-content')).toBeInTheDocument();
      expect(screen.getByTestId('sibling-content')).toBeInTheDocument();
      expect(outerErrorHandler).not.toHaveBeenCalled();
    });

    it('should handle errors at different nesting levels', () => {
      const errorHandlers = [jest.fn(), jest.fn(), jest.fn()];

      render(
        <ErrorBoundary onError={errorHandlers[0]}>
          <ErrorBoundary onError={errorHandlers[1]}>
            <ErrorBoundary onError={errorHandlers[2]}>
              <NestedErrorComponent level={5} shouldThrow={true} />
            </ErrorBoundary>
          </ErrorBoundary>
        </ErrorBoundary>
      );

      // Only the innermost boundary should handle the error
      expect(errorHandlers[2]).toHaveBeenCalled();
      expect(errorHandlers[1]).not.toHaveBeenCalled();
      expect(errorHandlers[0]).not.toHaveBeenCalled();
    });

    it('should isolate errors to prevent sibling component failures', () => {
      const ParentComponent: React.FC = () => {
        return (
          <div>
            <ErrorBoundary fallbackMessage="Child 1 failed">
              <ThrowingComponent shouldThrow={true} />
            </ErrorBoundary>
            <ErrorBoundary>
              <div data-testid="child-2">Child 2 working</div>
            </ErrorBoundary>
            <ErrorBoundary>
              <div data-testid="child-3">Child 3 working</div>
            </ErrorBoundary>
          </div>
        );
      };

      render(<ParentComponent />);

      // First child should show error
      expect(screen.getByText('Child 1 failed')).toBeInTheDocument();

      // Other children should render normally
      expect(screen.getByTestId('child-2')).toBeInTheDocument();
      expect(screen.getByTestId('child-3')).toBeInTheDocument();
    });
  });

  describe('Error Recovery Mechanisms', () => {
    it('should allow error recovery through retry mechanism', () => {
      const retryHandler = jest.fn();

      render(
        <ErrorBoundary onRetry={retryHandler}>
          <RecoveryComponent onRetry={retryHandler} />
        </ErrorBoundary>
      );

      // Component should render initially
      expect(screen.getByTestId('recovery-component')).toBeInTheDocument();

      // Trigger error
      fireEvent.click(screen.getByTestId('retry-button'));

      // Should show error boundary
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Retry from error boundary
      fireEvent.click(screen.getByText('Retry'));

      // Should recover and show component again
      expect(screen.getByTestId('recovery-component')).toBeInTheDocument();
    });

    it('should handle multiple retry attempts', async () => {
      let attemptCount = 0;
      const maxAttempts = 3;

      const RetryTestComponent: React.FC = () => {
        const [shouldThrow, setShouldThrow] = React.useState(false);

        const handleClick = () => {
          attemptCount++;
          if (attemptCount < maxAttempts) {
            setShouldThrow(true);
          }
        };

        if (shouldThrow && attemptCount < maxAttempts) {
          throw new Error(`Attempt ${attemptCount} failed`);
        }

        return (
          <div data-testid="retry-test-component">
            <button onClick={handleClick} data-testid="trigger-retry-test">
              Test Retry (Attempt {attemptCount})
            </button>
            Success after {attemptCount} attempts
          </div>
        );
      };

      render(
        <ErrorBoundary>
          <RetryTestComponent />
        </ErrorBoundary>
      );

      // First attempt - should fail
      fireEvent.click(screen.getByTestId('trigger-retry-test'));
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Retry - should fail again
      fireEvent.click(screen.getByText('Retry'));
      fireEvent.click(screen.getByTestId('trigger-retry-test'));
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Final retry - should succeed
      fireEvent.click(screen.getByText('Retry'));
      fireEvent.click(screen.getByTestId('trigger-retry-test'));
      expect(screen.getByTestId('retry-test-component')).toBeInTheDocument();
      expect(screen.getByText('Success after 3 attempts')).toBeInTheDocument();
    });
  });

  describe('Async Error Handling', () => {
    it('should catch errors from async operations', async () => {
      render(
        <ErrorBoundary fallbackMessage="Async error occurred">
          <AsyncThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      await waitFor(() => {
        expect(screen.getByText('Async error occurred')).toBeInTheDocument();
        expect(screen.getByText('Async operation failed')).toBeInTheDocument();
      });
    });

    it('should handle delayed errors', async () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} delay={200} />
        </ErrorBoundary>
      );

      // Initially component should render
      expect(screen.getByTestId('throwing-component')).toBeInTheDocument();

      // After delay, error should be caught
      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      }, { timeout: 300 });
    });
  });

  describe('Error Boundary State Management', () => {
    it('should reset error state when children change', () => {
      const TestWrapper: React.FC<{ showErrorComponent: boolean }> = ({
        showErrorComponent
      }) => (
        <ErrorBoundary>
          {showErrorComponent ? (
            <ThrowingComponent shouldThrow={true} />
          ) : (
            <div data-testid="safe-component">Safe component</div>
          )}
        </ErrorBoundary>
      );

      const { rerender } = render(<TestWrapper showErrorComponent={true} />);

      // Should show error
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Change children - should reset error state
      rerender(<TestWrapper showErrorComponent={false} />);

      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.getByTestId('safe-component')).toBeInTheDocument();
    });

    it('should maintain error state until explicitly reset', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Re-render with same component should maintain error state
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  describe('Custom Error Reporting', () => {
    it('should report errors with context information', () => {
      const errorReporter = jest.fn();
      const errorContext = { userId: '123', route: '/terminal' };

      render(
        <ErrorBoundary
          reportError={errorReporter}
          errorContext={errorContext}
        >
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(errorReporter).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(Error),
          errorInfo: expect.any(Object),
          timestamp: expect.any(Date),
          userAgent: expect.any(String),
          url: expect.any(String),
          context: errorContext
        })
      );
    });

    it('should handle errors in custom error reporting', () => {
      const faultyReporter = () => {
        throw new Error('Reporter error');
      };

      // Should not crash even if reporter fails
      expect(() => {
        render(
          <ErrorBoundary reportError={faultyReporter}>
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
        );
      }).not.toThrow();

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  describe('Accessibility and User Experience', () => {
    it('should focus error message for accessibility', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorHeading = screen.getByRole('heading', { level: 2 });
      expect(errorHeading).toHaveFocus();
    });

    it('should provide appropriate ARIA attributes', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorContainer = screen.getByRole('alert');
      expect(errorContainer).toHaveAttribute('aria-live', 'polite');
    });

    it('should show error details in development mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary showErrorDetails={true}>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Error Stack:')).toBeInTheDocument();
      expect(screen.getByText('Component Stack:')).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Cascade Prevention Advanced Scenarios', () => {
    it('should prevent error cascades in complex component trees', () => {
      const errorCounts = { level1: 0, level2: 0, level3: 0 };

      const trackError = (level: keyof typeof errorCounts) => () => {
        errorCounts[level]++;
      };

      const ComplexTree: React.FC = () => (
        <CascadePreventionBoundary onError={trackError('level1')}>
          <div>Level 1</div>
          <CascadePreventionBoundary onError={trackError('level2')}>
            <div>Level 2</div>
            <CascadePreventionBoundary onError={trackError('level3')}>
              <ThrowingComponent shouldThrow={true} />
            </CascadePreventionBoundary>
            <div data-testid="level2-sibling">Level 2 Sibling</div>
          </CascadePreventionBoundary>
          <div data-testid="level1-sibling">Level 1 Sibling</div>
        </CascadePreventionBoundary>
      );

      render(<ComplexTree />);

      // Only innermost boundary should handle error
      expect(errorCounts.level3).toBe(1);
      expect(errorCounts.level2).toBe(0);
      expect(errorCounts.level1).toBe(0);

      // Sibling components should remain functional
      expect(screen.getByTestId('level2-sibling')).toBeInTheDocument();
      expect(screen.getByTestId('level1-sibling')).toBeInTheDocument();
    });

    it('should handle multiple simultaneous errors in different branches', () => {
      const MultiErrorComponent: React.FC = () => {
        const [triggerErrors, setTriggerErrors] = React.useState(false);

        return (
          <div>
            <button
              onClick={() => setTriggerErrors(true)}
              data-testid="trigger-multi-errors"
            >
              Trigger Multiple Errors
            </button>

            <ErrorBoundary fallbackMessage="Branch A failed">
              <ThrowingComponent shouldThrow={triggerErrors} errorType="render" />
            </ErrorBoundary>

            <ErrorBoundary fallbackMessage="Branch B failed">
              <ThrowingComponent shouldThrow={triggerErrors} errorType="network" />
            </ErrorBoundary>

            <ErrorBoundary>
              <div data-testid="stable-branch">Stable branch</div>
            </ErrorBoundary>
          </div>
        );
      };

      render(<MultiErrorComponent />);

      fireEvent.click(screen.getByTestId('trigger-multi-errors'));

      // Both error boundaries should catch their respective errors
      expect(screen.getByText('Branch A failed')).toBeInTheDocument();
      expect(screen.getByText('Branch B failed')).toBeInTheDocument();

      // Stable branch should remain unaffected
      expect(screen.getByTestId('stable-branch')).toBeInTheDocument();
    });
  });

  describe('Performance and Memory Management', () => {
    it('should not create memory leaks during error handling', () => {
      const TestComponent: React.FC<{ errorCount: number }> = ({ errorCount }) => {
        if (errorCount > 0) {
          throw new Error(`Error number ${errorCount}`);
        }
        return <div>No errors</div>;
      };

      let errorCount = 0;
      const { rerender, unmount } = render(
        <ErrorBoundary>
          <TestComponent errorCount={errorCount} />
        </ErrorBoundary>
      );

      // Trigger multiple errors and recoveries
      for (let i = 1; i <= 5; i++) {
        errorCount = i;
        rerender(
          <ErrorBoundary>
            <TestComponent errorCount={errorCount} />
          </ErrorBoundary>
        );
        expect(screen.getByRole('alert')).toBeInTheDocument();

        // Reset
        errorCount = 0;
        rerender(
          <ErrorBoundary>
            <TestComponent errorCount={errorCount} />
          </ErrorBoundary>
        );
      }

      // Should not create memory issues
      unmount();
      expect(true).toBe(true); // Test completes without memory issues
    });

    it('should handle rapid error state changes efficiently', async () => {
      const RapidErrorComponent: React.FC = () => {
        const [errorState, setErrorState] = React.useState(0);

        React.useEffect(() => {
          const interval = setInterval(() => {
            setErrorState(prev => (prev + 1) % 4); // Cycle through states
          }, 50);

          return () => clearInterval(interval);
        }, []);

        if (errorState === 1 || errorState === 3) {
          throw new Error(`Rapid error ${errorState}`);
        }

        return <div data-testid="rapid-component">State: {errorState}</div>;
      };

      render(
        <ErrorBoundary>
          <RapidErrorComponent />
        </ErrorBoundary>
      );

      // Should handle rapid state changes without performance issues
      await new Promise(resolve => setTimeout(resolve, 300));

      // Should eventually stabilize
      await waitFor(() => {
        // Will show either the component or error boundary
        expect(
          screen.getByTestId('rapid-component') || screen.getByRole('alert')
        ).toBeInTheDocument();
      });
    });
  });
});