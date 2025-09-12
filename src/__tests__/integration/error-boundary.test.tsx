import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ErrorBoundary from '../../components/ErrorBoundary';

// Create a component that throws an error for testing
const ThrowError = ({ shouldThrow = false, errorMessage = 'Test error' }) => {
  if (shouldThrow) {
    throw new Error(errorMessage);
  }
  return <div data-testid="success-component">No error occurred</div>;
};

// Mock console.error to avoid noise in test output
const mockConsoleError = () => {
  const originalError = console.error;
  beforeAll(() => {
    console.error = jest.fn();
  });
  afterAll(() => {
    console.error = originalError;
  });
};

describe('Error Boundary Integration Tests', () => {
  mockConsoleError();

  describe('Error Catching', () => {
    it('should catch and display error when child component throws', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Component crashed!" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/component crashed!/i)).toBeInTheDocument();
    });

    it('should render children normally when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('success-component')).toBeInTheDocument();
      expect(screen.getByText('No error occurred')).toBeInTheDocument();
    });

    it('should catch errors in nested components', () => {
      const NestedComponent = () => (
        <div>
          <div>
            <ThrowError shouldThrow={true} errorMessage="Nested error!" />
          </div>
        </div>
      );

      render(
        <ErrorBoundary>
          <NestedComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/nested error!/i)).toBeInTheDocument();
    });
  });

  describe('Multiple Error Boundaries', () => {
    it('should isolate errors to the nearest error boundary', () => {
      render(
        <div>
          <ErrorBoundary>
            <div data-testid="boundary-1">
              <ThrowError shouldThrow={true} errorMessage="Error in boundary 1" />
            </div>
          </ErrorBoundary>
          
          <ErrorBoundary>
            <div data-testid="boundary-2">
              <ThrowError shouldThrow={false} />
            </div>
          </ErrorBoundary>
        </div>
      );

      // First boundary should show error
      expect(screen.getByText(/error in boundary 1/i)).toBeInTheDocument();
      
      // Second boundary should work normally
      expect(screen.getByTestId('success-component')).toBeInTheDocument();
    });

    it('should handle nested error boundaries correctly', () => {
      const InnerError = () => <ThrowError shouldThrow={true} errorMessage="Inner error" />;
      const OuterError = () => <ThrowError shouldThrow={true} errorMessage="Outer error" />;

      render(
        <ErrorBoundary>
          <div>
            <h1>Outer Component</h1>
            <ErrorBoundary>
              <div>
                <h2>Inner Component</h2>
                <InnerError />
              </div>
            </ErrorBoundary>
            <OuterError />
          </div>
        </ErrorBoundary>
      );

      // Inner error boundary should catch its error, but outer error will cause outer boundary to catch
      expect(screen.getByText(/outer error/i)).toBeInTheDocument();
    });
  });

  describe('Error Boundary with Different Error Types', () => {
    it('should handle JavaScript errors', () => {
      const JSError = () => {
        throw new Error('JavaScript error');
      };

      render(
        <ErrorBoundary>
          <JSError />
        </ErrorBoundary>
      );

      expect(screen.getByText(/javascript error/i)).toBeInTheDocument();
    });

    it('should handle TypeError', () => {
      const TypeErrorComponent = () => {
        throw new TypeError('Type error occurred');
      };

      render(
        <ErrorBoundary>
          <TypeErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/type error occurred/i)).toBeInTheDocument();
    });

    it('should handle ReferenceError', () => {
      const ReferenceErrorComponent = () => {
        throw new ReferenceError('Reference error occurred');
      };

      render(
        <ErrorBoundary>
          <ReferenceErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/reference error occurred/i)).toBeInTheDocument();
    });

    it('should handle custom error types', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }

      const CustomErrorComponent = () => {
        throw new CustomError('Custom error occurred');
      };

      render(
        <ErrorBoundary>
          <CustomErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/custom error occurred/i)).toBeInTheDocument();
    });
  });

  describe('Error Boundary Lifecycle', () => {
    it('should handle errors during component mounting', () => {
      const MountError = () => {
        React.useEffect(() => {
          throw new Error('Mount error');
        }, []);
        return <div>Component mounted</div>;
      };

      // Note: useEffect errors aren't caught by error boundaries in React
      // This test demonstrates the limitation
      render(
        <ErrorBoundary>
          <MountError />
        </ErrorBoundary>
      );

      // Component should render but error boundary won't catch useEffect errors
      expect(screen.getByText('Component mounted')).toBeInTheDocument();
    });

    it('should handle errors in render method', () => {
      const RenderError = ({ shouldError }: { shouldError: boolean }) => {
        if (shouldError) {
          throw new Error('Render error');
        }
        return <div>Rendered successfully</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <RenderError shouldError={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Rendered successfully')).toBeInTheDocument();

      // Trigger error on re-render
      rerender(
        <ErrorBoundary>
          <RenderError shouldError={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/render error/i)).toBeInTheDocument();
    });
  });

  describe('Error Boundary Recovery', () => {
    it('should recover when error is fixed and component re-renders', () => {
      const ConditionalError = ({ hasError }: { hasError: boolean }) => {
        if (hasError) {
          throw new Error('Conditional error');
        }
        return <div data-testid="recovered-component">Component recovered</div>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <ConditionalError hasError={true} />
        </ErrorBoundary>
      );

      // Should show error initially
      expect(screen.getByText(/conditional error/i)).toBeInTheDocument();

      // Fix the error
      rerender(
        <ErrorBoundary>
          <ConditionalError hasError={false} />
        </ErrorBoundary>
      );

      // Should still show error (error boundaries don't automatically recover)
      expect(screen.getByText(/conditional error/i)).toBeInTheDocument();
      expect(screen.queryByTestId('recovered-component')).not.toBeInTheDocument();
    });

    it('should maintain error state across re-renders with same props', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Persistent error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/persistent error/i)).toBeInTheDocument();

      // Re-render should maintain error state
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Persistent error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/persistent error/i)).toBeInTheDocument();
    });
  });

  describe('Error Boundary with Complex Components', () => {
    it('should handle errors in components with hooks', () => {
      const ComponentWithHooks = ({ shouldThrow }: { shouldThrow: boolean }) => {
        const [count, setCount] = React.useState(0);
        const [error, setError] = React.useState(false);

        React.useEffect(() => {
          if (shouldThrow) {
            setError(true);
          }
        }, [shouldThrow]);

        if (error && shouldThrow) {
          throw new Error('Hook component error');
        }

        return (
          <div>
            <span>Count: {count}</span>
            <button onClick={() => setCount(c => c + 1)}>Increment</button>
          </div>
        );
      };

      const { rerender } = render(
        <ErrorBoundary>
          <ComponentWithHooks shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Count: 0')).toBeInTheDocument();

      // Trigger error
      rerender(
        <ErrorBoundary>
          <ComponentWithHooks shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/hook component error/i)).toBeInTheDocument();
    });

    it('should handle errors in components with context', () => {
      const TestContext = React.createContext<{ value: string }>({ value: 'default' });

      const ContextConsumer = ({ shouldThrow }: { shouldThrow: boolean }) => {
        const context = React.useContext(TestContext);
        
        if (shouldThrow) {
          throw new Error(`Context error: ${context.value}`);
        }
        
        return <div>Context value: {context.value}</div>;
      };

      render(
        <TestContext.Provider value={{ value: 'test-value' }}>
          <ErrorBoundary>
            <ContextConsumer shouldThrow={true} />
          </ErrorBoundary>
        </TestContext.Provider>
      );

      expect(screen.getByText(/context error: test-value/i)).toBeInTheDocument();
    });
  });

  describe('Error Boundary Accessibility', () => {
    it('should provide accessible error information', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Accessibility test error" />
        </ErrorBoundary>
      );

      // The error message should be accessible to screen readers
      expect(screen.getByText(/accessibility test error/i)).toBeInTheDocument();
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    });

    it('should maintain focus management when error occurs', () => {
      const FocusableError = ({ shouldThrow }: { shouldThrow: boolean }) => {
        if (shouldThrow) {
          throw new Error('Focus test error');
        }
        return <button>Focusable element</button>;
      };

      const { rerender } = render(
        <ErrorBoundary>
          <FocusableError shouldThrow={false} />
        </ErrorBoundary>
      );

      const button = screen.getByRole('button', { name: 'Focusable element' });
      button.focus();
      expect(document.activeElement).toBe(button);

      // Trigger error
      rerender(
        <ErrorBoundary>
          <FocusableError shouldThrow={true} />
        </ErrorBoundary>
      );

      // Error boundary should be displayed
      expect(screen.getByText(/focus test error/i)).toBeInTheDocument();
    });
  });

  describe('Error Boundary Performance', () => {
    it('should not impact performance when no errors occur', () => {
      const PerformanceComponent = () => {
        const [count, setCount] = React.useState(0);
        
        return (
          <div>
            <span data-testid="performance-counter">Count: {count}</span>
            <button onClick={() => setCount(c => c + 1)}>Increment</button>
          </div>
        );
      };

      const startTime = performance.now();

      render(
        <ErrorBoundary>
          <PerformanceComponent />
        </ErrorBoundary>
      );

      const endTime = performance.now();
      const renderTime = endTime - startTime;

      expect(renderTime).toBeLessThan(50); // Should be very fast
      expect(screen.getByTestId('performance-counter')).toBeInTheDocument();
    });

    it('should handle multiple error boundaries efficiently', () => {
      const MultipleErrorBoundaries = () => (
        <div>
          {Array.from({ length: 10 }, (_, i) => (
            <ErrorBoundary key={i}>
              <div data-testid={`boundary-${i}`}>Boundary {i}</div>
            </ErrorBoundary>
          ))}
        </div>
      );

      const startTime = performance.now();

      render(<MultipleErrorBoundaries />);

      const endTime = performance.now();
      const renderTime = endTime - startTime;

      expect(renderTime).toBeLessThan(100);
      
      // All boundaries should render
      for (let i = 0; i < 10; i++) {
        expect(screen.getByTestId(`boundary-${i}`)).toBeInTheDocument();
      }
    });
  });
});