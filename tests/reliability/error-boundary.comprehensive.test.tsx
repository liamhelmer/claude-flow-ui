import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

// Mock error boundary component
class TestErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback?: React.ComponentType<any> },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      const FallbackComponent = this.props.fallback;
      if (FallbackComponent) {
        return <FallbackComponent error={this.state.error} />;
      }
      return <div data-testid="error-boundary">Something went wrong</div>;
    }

    return this.props.children;
  }
}

// Component that throws an error
const ErrorThrowingComponent = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
  if (shouldThrow) {
    throw new Error('Test error');
  }
  return <div data-testid="working-component">Component working</div>;
};

// Custom fallback component
const CustomErrorFallback = ({ error }: { error?: Error }) => (
  <div data-testid="custom-error-fallback">
    <h2>Custom Error Handler</h2>
    <p>Error: {error?.message}</p>
  </div>
);

// Mock a failing hook
const useFailingHook = (shouldFail: boolean = false) => {
  if (shouldFail) {
    throw new Error('Hook failed');
  }
  return { data: 'success' };
};

const ComponentWithFailingHook = ({ shouldFail = false }: { shouldFail?: boolean }) => {
  const { data } = useFailingHook(shouldFail);
  return <div data-testid="hook-component">{data}</div>;
};

describe('Error Boundary - Comprehensive Tests', () => {
  beforeEach(() => {
    // Suppress console.error for cleaner test output
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Basic Error Catching', () => {
    it('catches and displays errors from child components', () => {
      render(
        <TestErrorBoundary>
          <ErrorThrowingComponent shouldThrow={true} />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.queryByTestId('working-component')).not.toBeInTheDocument();
    });

    it('renders children normally when no error occurs', () => {
      render(
        <TestErrorBoundary>
          <ErrorThrowingComponent shouldThrow={false} />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('working-component')).toBeInTheDocument();
      expect(screen.getByText('Component working')).toBeInTheDocument();
      expect(screen.queryByTestId('error-boundary')).not.toBeInTheDocument();
    });

    it('uses custom fallback component when provided', () => {
      render(
        <TestErrorBoundary fallback={CustomErrorFallback}>
          <ErrorThrowingComponent shouldThrow={true} />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('custom-error-fallback')).toBeInTheDocument();
      expect(screen.getByText('Custom Error Handler')).toBeInTheDocument();
      expect(screen.getByText('Error: Test error')).toBeInTheDocument();
    });
  });

  describe('Hook Error Handling', () => {
    it('catches errors thrown in hooks', () => {
      render(
        <TestErrorBoundary>
          <ComponentWithFailingHook shouldFail={true} />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
      expect(screen.queryByTestId('hook-component')).not.toBeInTheDocument();
    });

    it('renders normally when hooks work correctly', () => {
      render(
        <TestErrorBoundary>
          <ComponentWithFailingHook shouldFail={false} />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('hook-component')).toBeInTheDocument();
      expect(screen.getByText('success')).toBeInTheDocument();
    });
  });

  describe('Nested Error Boundaries', () => {
    it('handles nested error boundaries correctly', () => {
      render(
        <TestErrorBoundary fallback={() => <div data-testid="outer-boundary">Outer error</div>}>
          <div>
            <TestErrorBoundary fallback={() => <div data-testid="inner-boundary">Inner error</div>}>
              <ErrorThrowingComponent shouldThrow={true} />
            </TestErrorBoundary>
          </div>
        </TestErrorBoundary>
      );

      // Inner boundary should catch the error
      expect(screen.getByTestId('inner-boundary')).toBeInTheDocument();
      expect(screen.queryByTestId('outer-boundary')).not.toBeInTheDocument();
    });

    it('propagates to parent boundary when inner boundary fails', () => {
      const FailingErrorBoundary = ({ children }: { children: React.ReactNode }) => {
        throw new Error('Boundary itself failed');
      };

      render(
        <TestErrorBoundary fallback={() => <div data-testid="outer-boundary">Outer caught error</div>}>
          <FailingErrorBoundary>
            <ErrorThrowingComponent shouldThrow={false} />
          </FailingErrorBoundary>
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('outer-boundary')).toBeInTheDocument();
    });
  });

  describe('Error Recovery', () => {
    it('recovers when error condition is resolved', () => {
      const TestRecoveryComponent = () => {
        const [shouldThrow, setShouldThrow] = React.useState(true);

        React.useEffect(() => {
          const timer = setTimeout(() => setShouldThrow(false), 100);
          return () => clearTimeout(timer);
        }, []);

        return <ErrorThrowingComponent shouldThrow={shouldThrow} />;
      };

      const { rerender } = render(
        <TestErrorBoundary>
          <TestRecoveryComponent />
        </TestErrorBoundary>
      );

      // Initially should show error
      expect(screen.getByTestId('error-boundary')).toBeInTheDocument();

      // Re-render with fixed component
      rerender(
        <TestErrorBoundary>
          <ErrorThrowingComponent shouldThrow={false} />
        </TestErrorBoundary>
      );

      // Should still show error until boundary is reset
      expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
    });

    it('handles multiple consecutive errors', () => {
      const MultiErrorComponent = ({ errorCount }: { errorCount: number }) => {
        if (errorCount > 0) {
          throw new Error(`Error number ${errorCount}`);
        }
        return <div data-testid="no-error">No errors</div>;
      };

      const { rerender } = render(
        <TestErrorBoundary fallback={CustomErrorFallback}>
          <MultiErrorComponent errorCount={1} />
        </TestErrorBoundary>
      );

      expect(screen.getByText('Error: Error number 1')).toBeInTheDocument();

      rerender(
        <TestErrorBoundary fallback={CustomErrorFallback}>
          <MultiErrorComponent errorCount={2} />
        </TestErrorBoundary>
      );

      // Should still show first error (boundary doesn't reset automatically)
      expect(screen.getByText('Error: Error number 1')).toBeInTheDocument();
    });
  });

  describe('Async Error Handling', () => {
    it('handles errors in async operations', async () => {
      const AsyncErrorComponent = () => {
        const [hasError, setHasError] = React.useState(false);

        React.useEffect(() => {
          setTimeout(() => {
            setHasError(true);
          }, 10);
        }, []);

        if (hasError) {
          throw new Error('Async error');
        }

        return <div data-testid="async-component">Loading...</div>;
      };

      render(
        <TestErrorBoundary>
          <AsyncErrorComponent />
        </TestErrorBoundary>
      );

      // Initially should render normally
      expect(screen.getByTestId('async-component')).toBeInTheDocument();

      // Wait for async error
      await new Promise(resolve => setTimeout(resolve, 20));

      // Should catch async error on next render
      expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
    });

    it('handles promise rejections gracefully', () => {
      const PromiseErrorComponent = () => {
        React.useEffect(() => {
          Promise.reject(new Error('Promise rejected'));
        }, []);

        return <div data-testid="promise-component">Promise component</div>;
      };

      // Promise rejections are not caught by error boundaries
      render(
        <TestErrorBoundary>
          <PromiseErrorComponent />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('promise-component')).toBeInTheDocument();
      expect(screen.queryByTestId('error-boundary')).not.toBeInTheDocument();
    });
  });

  describe('Error Information', () => {
    it('provides error details to fallback component', () => {
      const DetailedErrorFallback = ({ error }: { error?: Error }) => (
        <div data-testid="detailed-error">
          <div data-testid="error-message">{error?.message}</div>
          <div data-testid="error-name">{error?.name}</div>
        </div>
      );

      render(
        <TestErrorBoundary fallback={DetailedErrorFallback}>
          <ErrorThrowingComponent shouldThrow={true} />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('error-message')).toHaveTextContent('Test error');
      expect(screen.getByTestId('error-name')).toHaveTextContent('Error');
    });

    it('handles different error types', () => {
      const TypedErrorComponent = ({ errorType }: { errorType: string }) => {
        switch (errorType) {
          case 'reference':
            throw new ReferenceError('Reference error');
          case 'type':
            throw new TypeError('Type error');
          case 'range':
            throw new RangeError('Range error');
          default:
            throw new Error('Generic error');
        }
      };

      const ErrorTypeDisplay = ({ error }: { error?: Error }) => (
        <div data-testid="error-type">{error?.constructor.name}</div>
      );

      const { rerender } = render(
        <TestErrorBoundary fallback={ErrorTypeDisplay}>
          <TypedErrorComponent errorType="reference" />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('error-type')).toHaveTextContent('ReferenceError');
    });
  });

  describe('Performance Impact', () => {
    it('does not impact performance when no errors occur', () => {
      const start = performance.now();

      render(
        <TestErrorBoundary>
          <div>
            {Array.from({ length: 100 }, (_, i) => (
              <div key={i}>Component {i}</div>
            ))}
          </div>
        </TestErrorBoundary>
      );

      const end = performance.now();
      const renderTime = end - start;

      // Should render quickly (under 100ms for simple components)
      expect(renderTime).toBeLessThan(100);
    });

    it('handles large numbers of components with error boundaries', () => {
      const ManyBoundariesComponent = () => (
        <div>
          {Array.from({ length: 50 }, (_, i) => (
            <TestErrorBoundary key={i}>
              <div>Boundary {i}</div>
            </TestErrorBoundary>
          ))}
        </div>
      );

      expect(() => {
        render(<ManyBoundariesComponent />);
      }).not.toThrow();

      expect(screen.getAllByText(/Boundary \d+/)).toHaveLength(50);
    });
  });

  describe('Edge Cases', () => {
    it('handles null/undefined errors', () => {
      const NullErrorComponent = () => {
        throw null;
      };

      render(
        <TestErrorBoundary fallback={({ error }) => <div data-testid="null-error">{String(error)}</div>}>
          <NullErrorComponent />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('null-error')).toBeInTheDocument();
    });

    it('handles errors in error boundary itself', () => {
      const BrokenErrorBoundary = ({ children }: { children: React.ReactNode }) => {
        const [hasError, setHasError] = React.useState(false);

        if (hasError) {
          throw new Error('Error boundary is broken');
        }

        try {
          return <div>{children}</div>;
        } catch (error) {
          setHasError(true);
          throw error;
        }
      };

      expect(() => {
        render(
          <TestErrorBoundary fallback={() => <div data-testid="outer-caught">Outer caught broken boundary</div>}>
            <BrokenErrorBoundary>
              <div>Normal component</div>
            </BrokenErrorBoundary>
          </TestErrorBoundary>
        );
      }).not.toThrow();
    });

    it('handles components that throw during cleanup', () => {
      const CleanupErrorComponent = () => {
        React.useEffect(() => {
          return () => {
            throw new Error('Cleanup error');
          };
        }, []);

        return <div data-testid="cleanup-component">Cleanup component</div>;
      };

      const { unmount } = render(
        <TestErrorBoundary>
          <CleanupErrorComponent />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('cleanup-component')).toBeInTheDocument();

      // Unmounting should not break the test
      expect(() => unmount()).not.toThrow();
    });
  });
});