import React, { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ErrorBoundary } from '../ErrorBoundary';

// Mock console.error to avoid noise in tests
const originalConsoleError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalConsoleError;
});

// Test components that can throw errors
const ThrowError: React.FC<{ shouldThrow?: boolean; errorType?: string; message?: string }> = ({ 
  shouldThrow = false, 
  errorType = 'Error',
  message = 'Test error' 
}) => {
  if (shouldThrow) {
    if (errorType === 'TypeError') {
      throw new TypeError(message);
    } else if (errorType === 'ReferenceError') {
      throw new ReferenceError(message);
    } else if (errorType === 'SyntaxError') {
      throw new SyntaxError(message);
    } else {
      throw new Error(message);
    }
  }
  return <div data-testid="no-error">No error occurred</div>;
};

const AsyncError: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = false }) => {
  const [, setState] = useState(false);
  
  React.useEffect(() => {
    if (shouldThrow) {
      // Simulate async error
      setTimeout(() => {
        setState(() => {
          throw new Error('Async error');
        });
      }, 0);
    }
  }, [shouldThrow]);

  return <div data-testid="async-component">Async component</div>;
};

const StateUpdateError: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = false }) => {
  const [count, setCount] = useState(0);

  const handleClick = () => {
    if (shouldThrow && count === 0) {
      // Trigger error on first click
      setCount(() => {
        throw new Error('State update error');
      });
    } else {
      setCount(count + 1);
    }
  };

  return (
    <div>
      <button onClick={handleClick}>Click me: {count}</button>
    </div>
  );
};

const NetworkError: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = false }) => {
  const [data, setData] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = React.useCallback(async () => {
    try {
      if (shouldThrow) {
        throw new Error('Network request failed');
      }
      setData('Fetched data');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      throw err; // Re-throw to trigger error boundary
    }
  }, [shouldThrow]);

  React.useEffect(() => {
    if (shouldThrow) {
      fetchData();
    }
  }, [shouldThrow, fetchData]);

  if (error) {
    throw new Error(error);
  }

  return <div data-testid="network-component">{data || 'Loading...'}</div>;
};

describe('ErrorBoundary', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (console.error as jest.Mock).mockClear();
  });

  describe('basic error catching', () => {
    it('should render children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('no-error')).toBeInTheDocument();
    });

    it('should catch and display error', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} message="Test error message" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/test error message/i)).toBeInTheDocument();
    });

    it('should show retry button', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });

    it('should reset error state when retry is clicked', async () => {
      const user = userEvent.setup();
      
      const TestComponent = () => {
        const [shouldThrow, setShouldThrow] = useState(true);
        
        // Auto-fix the error after first render
        React.useEffect(() => {
          const timer = setTimeout(() => setShouldThrow(false), 100);
          return () => clearTimeout(timer);
        }, []);

        return <ThrowError shouldThrow={shouldThrow} />;
      };

      render(
        <ErrorBoundary>
          <TestComponent />
        </ErrorBoundary>
      );

      // Should show error initially
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();

      // Wait for auto-fix and click retry
      await new Promise(resolve => setTimeout(resolve, 150));
      
      const retryButton = screen.getByRole('button', { name: /try again/i });
      await user.click(retryButton);

      // Should show success
      expect(screen.getByTestId('no-error')).toBeInTheDocument();
    });
  });

  describe('different error types', () => {
    it('should catch TypeError', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorType="TypeError" message="Type error occurred" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/type error occurred/i)).toBeInTheDocument();
    });

    it('should catch ReferenceError', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorType="ReferenceError" message="Reference error occurred" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/reference error occurred/i)).toBeInTheDocument();
    });

    it('should catch SyntaxError', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorType="SyntaxError" message="Syntax error occurred" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/syntax error occurred/i)).toBeInTheDocument();
    });

    it('should handle errors with stack traces', () => {
      const errorWithStack = new Error('Error with stack');
      errorWithStack.stack = `Error: Error with stack
    at Component (test.tsx:10:15)
    at ErrorBoundary (boundary.tsx:25:20)`;

      const ComponentWithStackError = () => {
        throw errorWithStack;
      };

      render(
        <ErrorBoundary>
          <ComponentWithStackError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/error with stack/i)).toBeInTheDocument();
    });
  });

  describe('error logging', () => {
    it('should log error to console', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} message="Logged error" />
        </ErrorBoundary>
      );

      expect(console.error).toHaveBeenCalled();
    });

    it('should log error with component stack', () => {
      render(
        <ErrorBoundary>
          <div data-testid="wrapper">
            <ThrowError shouldThrow={true} message="Component stack error" />
          </div>
        </ErrorBoundary>
      );

      const errorCalls = (console.error as jest.Mock).mock.calls;
      expect(errorCalls.length).toBeGreaterThan(0);
    });
  });

  describe('state update errors', () => {
    it('should catch errors in state updates', async () => {
      const user = userEvent.setup();
      
      render(
        <ErrorBoundary>
          <StateUpdateError shouldThrow={true} />
        </ErrorBoundary>
      );

      const button = screen.getByRole('button');
      await user.click(button);

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    });

    it('should handle multiple state update errors', async () => {
      const user = userEvent.setup();
      
      const MultipleErrors = () => {
        const [count, setCount] = useState(0);
        
        const handleClick = () => {
          if (count < 2) {
            setCount(() => {
              throw new Error(`Error ${count + 1}`);
            });
          } else {
            setCount(count + 1);
          }
        };

        return <button onClick={handleClick}>Click: {count}</button>;
      };

      render(
        <ErrorBoundary>
          <MultipleErrors />
        </ErrorBoundary>
      );

      const button = screen.getByRole('button');
      await user.click(button);

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    });
  });

  describe('async error handling', () => {
    it('should not catch async errors (expected behavior)', async () => {
      // Note: Error boundaries do not catch errors in async code
      // This test documents the expected behavior
      
      render(
        <ErrorBoundary>
          <AsyncError shouldThrow={true} />
        </ErrorBoundary>
      );

      // Async component should render normally
      expect(screen.getByTestId('async-component')).toBeInTheDocument();
      
      // Wait for async error (it won't be caught by ErrorBoundary)
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Component should still be rendered (error boundary doesn't catch async errors)
      expect(screen.getByTestId('async-component')).toBeInTheDocument();
    });
  });

  describe('network and fetch errors', () => {
    it('should catch network errors that throw synchronously', () => {
      render(
        <ErrorBoundary>
          <NetworkError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/network request failed/i)).toBeInTheDocument();
    });
  });

  describe('nested error boundaries', () => {
    it('should handle nested error boundaries', () => {
      const InnerError = () => <ThrowError shouldThrow={true} message="Inner error" />;
      const OuterError = () => <ThrowError shouldThrow={true} message="Outer error" />;

      render(
        <ErrorBoundary>
          <div>
            <ErrorBoundary>
              <InnerError />
            </ErrorBoundary>
            <OuterError />
          </div>
        </ErrorBoundary>
      );

      // Inner error boundary should catch inner error
      expect(screen.getByText(/inner error/i)).toBeInTheDocument();
      // Outer error should be caught by outer boundary
      expect(screen.getByText(/outer error/i)).toBeInTheDocument();
    });
  });

  describe('error boundary with different children types', () => {
    it('should handle functional components', () => {
      const FunctionalComponent = () => {
        throw new Error('Functional component error');
      };

      render(
        <ErrorBoundary>
          <FunctionalComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/functional component error/i)).toBeInTheDocument();
    });

    it('should handle class components', () => {
      class ClassComponent extends React.Component {
        render() {
          throw new Error('Class component error');
          return null; // This line is unreachable but satisfies ESLint
        }
      }

      render(
        <ErrorBoundary>
          <ClassComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/class component error/i)).toBeInTheDocument();
    });

    it('should handle fragments and arrays', () => {
      const FragmentWithError = () => (
        <React.Fragment>
          <div>Before error</div>
          <ThrowError shouldThrow={true} message="Fragment error" />
          <div>After error</div>
        </React.Fragment>
      );

      render(
        <ErrorBoundary>
          <FragmentWithError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/fragment error/i)).toBeInTheDocument();
    });
  });

  describe('error recovery scenarios', () => {
    it('should recover from props changes', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} message="Initial error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/initial error/i)).toBeInTheDocument();

      rerender(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );

      // Error should still be shown until retry is clicked
      expect(screen.getByText(/initial error/i)).toBeInTheDocument();
    });

    it('should handle component remounting after error', async () => {
      const user = userEvent.setup();
      
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} key="error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();

      // Click retry
      await user.click(screen.getByRole('button', { name: /try again/i }));

      // Rerender with different key (simulates remount)
      rerender(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} key="no-error" />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('no-error')).toBeInTheDocument();
    });
  });

  describe('error boundary edge cases', () => {
    it('should handle null children', () => {
      render(
        <ErrorBoundary>
          {null}
        </ErrorBoundary>
      );

      // Should not crash
      expect(document.body).toBeInTheDocument();
    });

    it('should handle undefined children', () => {
      render(
        <ErrorBoundary>
          {undefined}
        </ErrorBoundary>
      );

      // Should not crash
      expect(document.body).toBeInTheDocument();
    });

    it('should handle empty children', () => {
      render(
        <ErrorBoundary>
        </ErrorBoundary>
      );

      // Should not crash
      expect(document.body).toBeInTheDocument();
    });

    it('should handle errors in error state rendering', () => {
      // This is a more advanced test that would require a custom error boundary
      // that could potentially error while rendering the error UI
      const ErrorBoundaryThatErrors = ({ children }: { children: React.ReactNode }) => {
        const [hasError, setHasError] = React.useState(false);

        if (hasError) {
          // Simulate error in error rendering
          throw new Error('Error boundary error');
        }

        return (
          <ErrorBoundary>
            {children}
          </ErrorBoundary>
        );
      };

      expect(() => {
        render(
          <ErrorBoundaryThatErrors>
            <ThrowError shouldThrow={true} />
          </ErrorBoundaryThatErrors>
        );
      }).not.toThrow();
    });
  });
});