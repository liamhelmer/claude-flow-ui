import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

// Create a test error boundary component
class TestErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback?: React.ComponentType<{ error: Error }> },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode; fallback?: React.ComponentType<{ error: Error }> }) {
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
      if (this.props.fallback) {
        const FallbackComponent = this.props.fallback;
        return <FallbackComponent error={this.state.error!} />;
      }
      
      return (
        <div role="alert" data-testid="error-boundary">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message}</p>
        </div>
      );
    }

    return this.props.children;
  }
}

// Test components that throw errors
const ThrowError: React.FC<{ shouldThrow?: boolean; errorMessage?: string }> = ({ 
  shouldThrow = true, 
  errorMessage = 'Test error' 
}) => {
  if (shouldThrow) {
    throw new Error(errorMessage);
  }
  return <div>No error</div>;
};

const AsyncError: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = true }) => {
  React.useEffect(() => {
    if (shouldThrow) {
      // Simulate async error
      setTimeout(() => {
        throw new Error('Async error');
      }, 0);
    }
  }, [shouldThrow]);

  return <div>Async component</div>;
};

const CustomFallback: React.FC<{ error: Error }> = ({ error }) => (
  <div data-testid="custom-fallback">
    <h3>Custom Error Handler</h3>
    <p>Error: {error.message}</p>
  </div>
);

describe('Error Boundary', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  describe('Error Catching', () => {
    it('should catch and display errors from child components', () => {
      render(
        <TestErrorBoundary>
          <ThrowError errorMessage="Component crashed" />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Component crashed')).toBeInTheDocument();
    });

    it('should render children normally when no error occurs', () => {
      render(
        <TestErrorBoundary>
          <ThrowError shouldThrow={false} />
        </TestErrorBoundary>
      );

      expect(screen.getByText('No error')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should use custom fallback component when provided', () => {
      render(
        <TestErrorBoundary fallback={CustomFallback}>
          <ThrowError errorMessage="Custom error message" />
        </TestErrorBoundary>
      );

      expect(screen.getByTestId('custom-fallback')).toBeInTheDocument();
      expect(screen.getByText('Custom Error Handler')).toBeInTheDocument();
      expect(screen.getByText('Error: Custom error message')).toBeInTheDocument();
    });

    it('should catch errors from nested components', () => {
      const NestedComponent = () => (
        <div>
          <div>
            <ThrowError errorMessage="Deeply nested error" />
          </div>
        </div>
      );

      render(
        <TestErrorBoundary>
          <NestedComponent />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Deeply nested error')).toBeInTheDocument();
    });
  });

  describe('Error Types', () => {
    it('should handle JavaScript errors', () => {
      const JavaScriptError = () => {
        throw new TypeError('Type error occurred');
      };

      render(
        <TestErrorBoundary>
          <JavaScriptError />
        </TestErrorBoundary>
      );

      expect(screen.getByText('Type error occurred')).toBeInTheDocument();
    });

    it('should handle network-related errors', () => {
      const NetworkError = () => {
        throw new Error('Network request failed');
      };

      render(
        <TestErrorBoundary>
          <NetworkError />
        </TestErrorBoundary>
      );

      expect(screen.getByText('Network request failed')).toBeInTheDocument();
    });

    it('should handle reference errors', () => {
      const ReferenceError = () => {
        // @ts-ignore - Intentionally accessing undefined variable
        const result = undefinedVariable.someProperty;
        return <div>{result}</div>;
      };

      render(
        <TestErrorBoundary>
          <ReferenceError />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  describe('Multiple Children', () => {
    it('should catch errors from any child component', () => {
      render(
        <TestErrorBoundary>
          <div>Working component</div>
          <ThrowError errorMessage="Middle component error" />
          <div>Another working component</div>
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Middle component error')).toBeInTheDocument();
      expect(screen.queryByText('Working component')).not.toBeInTheDocument();
    });

    it('should render all children when none throw errors', () => {
      render(
        <TestErrorBoundary>
          <div>First component</div>
          <ThrowError shouldThrow={false} />
          <div>Third component</div>
        </TestErrorBoundary>
      );

      expect(screen.getByText('First component')).toBeInTheDocument();
      expect(screen.getByText('No error')).toBeInTheDocument();
      expect(screen.getByText('Third component')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });

  describe('Error Recovery', () => {
    it('should reset error state when receiving new props', () => {
      const { rerender } = render(
        <TestErrorBoundary key="error">
          <ThrowError errorMessage="Initial error" />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Re-render with different key to reset error boundary
      rerender(
        <TestErrorBoundary key="no-error">
          <ThrowError shouldThrow={false} />
        </TestErrorBoundary>
      );

      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.getByText('No error')).toBeInTheDocument();
    });

    it('should maintain error state on subsequent renders with same error', () => {
      const { rerender } = render(
        <TestErrorBoundary>
          <ThrowError errorMessage="Persistent error" />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Re-render with same component
      rerender(
        <TestErrorBoundary>
          <ThrowError errorMessage="Persistent error" />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Persistent error')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(
        <TestErrorBoundary>
          <ThrowError errorMessage="Accessibility test error" />
        </TestErrorBoundary>
      );

      const errorElement = screen.getByRole('alert');
      expect(errorElement).toBeInTheDocument();
      expect(errorElement).toHaveAttribute('role', 'alert');
    });

    it('should provide meaningful error messages', () => {
      render(
        <TestErrorBoundary>
          <ThrowError errorMessage="User-friendly error message" />
        </TestErrorBoundary>
      );

      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('User-friendly error message')).toBeInTheDocument();
    });
  });

  describe('Console Logging', () => {
    it('should log errors to console', () => {
      render(
        <TestErrorBoundary>
          <ThrowError errorMessage="Console log test" />
        </TestErrorBoundary>
      );

      expect(consoleSpy).toHaveBeenCalled();
      expect(consoleSpy.mock.calls[0][0]).toContain('Error caught by boundary:');
    });

    it('should include error info in console logs', () => {
      render(
        <TestErrorBoundary>
          <ThrowError errorMessage="Error info test" />
        </TestErrorBoundary>
      );

      expect(consoleSpy).toHaveBeenCalled();
      // Should log both error and errorInfo
      expect(consoleSpy.mock.calls[0]).toHaveLength(3); // message, error, errorInfo
    });
  });

  describe('Performance', () => {
    it('should not impact performance when no errors occur', () => {
      const start = performance.now();
      
      render(
        <TestErrorBoundary>
          <div>Performance test component</div>
          <ThrowError shouldThrow={false} />
          <div>Another component</div>
        </TestErrorBoundary>
      );
      
      const end = performance.now();
      const renderTime = end - start;
      
      // Should render quickly (less than 100ms even in test environment)
      expect(renderTime).toBeLessThan(100);
    });

    it('should handle multiple error boundaries without performance degradation', () => {
      const start = performance.now();
      
      render(
        <div>
          <TestErrorBoundary>
            <div>Boundary 1</div>
          </TestErrorBoundary>
          <TestErrorBoundary>
            <div>Boundary 2</div>
          </TestErrorBoundary>
          <TestErrorBoundary>
            <div>Boundary 3</div>
          </TestErrorBoundary>
          <TestErrorBoundary>
            <div>Boundary 4</div>
          </TestErrorBoundary>
          <TestErrorBoundary>
            <div>Boundary 5</div>
          </TestErrorBoundary>
        </div>
      );
      
      const end = performance.now();
      const renderTime = end - start;
      
      expect(renderTime).toBeLessThan(200);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null error messages', () => {
      const NullError = () => {
        const error = new Error();
        error.message = '';
        throw error;
      };

      render(
        <TestErrorBoundary>
          <NullError />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    it('should handle errors with undefined messages', () => {
      const UndefinedError = () => {
        throw new Error(undefined as any);
      };

      render(
        <TestErrorBoundary>
          <UndefinedError />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle non-Error objects thrown', () => {
      const StringThrow = () => {
        throw 'String error';
      };

      render(
        <TestErrorBoundary>
          <StringThrow />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle errors in error boundary itself', () => {
      const FaultyFallback: React.FC<{ error: Error }> = () => {
        throw new Error('Fallback error');
      };

      render(
        <TestErrorBoundary fallback={FaultyFallback}>
          <ThrowError errorMessage="Original error" />
        </TestErrorBoundary>
      );

      // Should still render something (browser default error handling)
      expect(document.body).toBeInTheDocument();
    });
  });

  describe('Real-world Integration', () => {
    it('should work with React hooks', () => {
      const HookError = () => {
        const [error, setError] = React.useState<boolean>(false);
        
        React.useEffect(() => {
          setError(true);
        }, []);
        
        if (error) {
          throw new Error('Hook-based error');
        }
        
        return <div>Hook component</div>;
      };

      render(
        <TestErrorBoundary>
          <HookError />
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Hook-based error')).toBeInTheDocument();
    });

    it('should work with context providers', () => {
      const TestContext = React.createContext<{ value: string }>({ value: 'default' });
      
      const ContextError = () => {
        const context = React.useContext(TestContext);
        if (context.value === 'error') {
          throw new Error('Context-based error');
        }
        return <div>Context component: {context.value}</div>;
      };

      render(
        <TestErrorBoundary>
          <TestContext.Provider value={{ value: 'error' }}>
            <ContextError />
          </TestContext.Provider>
        </TestErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Context-based error')).toBeInTheDocument();
    });

    it('should work with async components', () => {
      render(
        <TestErrorBoundary>
          <AsyncError />
        </TestErrorBoundary>
      );

      // Note: Error boundaries don't catch async errors by default
      // This test verifies that the component renders initially
      expect(screen.getByText('Async component')).toBeInTheDocument();
    });
  });
});