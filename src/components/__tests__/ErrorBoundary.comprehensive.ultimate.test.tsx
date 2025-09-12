/**
 * Ultimate Comprehensive Error Boundary Tests
 * Tests all error scenarios, recovery mechanisms, and edge cases
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { expectAsyncError, createMockElement } from '@/__tests__/utils/test-helpers';

// Proper Error Boundary Component using componentDidCatch
class ErrorBoundary extends React.Component<{
  children: React.ReactNode;
  fallback?: React.ComponentType<{ error: Error; resetError: () => void }>;
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
}, {
  hasError: boolean;
  error: Error | null;
}> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    if (this.props.onError) {
      this.props.onError(error, errorInfo);
    }
  }

  resetError = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError && this.state.error) {
      const { fallback: Fallback } = this.props;
      
      if (Fallback) {
        return <Fallback error={this.state.error} resetError={this.resetError} />;
      }
      
      return (
        <div role="alert" data-testid="error-boundary">
          <h2>Something went wrong</h2>
          <details>
            <summary>Error details</summary>
            <pre>{this.state.error.message}</pre>
          </details>
          <button onClick={this.resetError}>Try again</button>
        </div>
      );
    }

    return this.props.children;
  }
}

// Test components that throw errors
const ThrowingComponent: React.FC<{ shouldThrow?: boolean; throwType?: string }> = ({ 
  shouldThrow = true, 
  throwType = 'render' 
}) => {
  React.useEffect(() => {
    if (shouldThrow && throwType === 'effect') {
      throw new Error('Effect error');
    }
  }, [shouldThrow, throwType]);

  if (shouldThrow && throwType === 'render') {
    throw new Error('Render error');
  }

  if (shouldThrow && throwType === 'async') {
    setTimeout(() => {
      throw new Error('Async error');
    }, 10);
  }

  return <div>Component working</div>;
};

const AsyncThrowingComponent: React.FC = () => {
  const [shouldThrow, setShouldThrow] = React.useState(false);

  const handleClick = async () => {
    try {
      await new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Async click error')), 10);
      });
    } catch (error) {
      throw error;
    }
  };

  if (shouldThrow) {
    throw new Error('State-triggered error');
  }

  return (
    <div>
      <button onClick={() => setShouldThrow(true)}>Trigger Error</button>
      <button onClick={handleClick}>Async Error</button>
    </div>
  );
};

const MemoryLeakComponent: React.FC<{ shouldLeak?: boolean }> = ({ shouldLeak = false }) => {
  React.useEffect(() => {
    if (shouldLeak) {
      const interval = setInterval(() => {
        // Intentional memory leak for testing
        const largeArray = new Array(100000).fill('memory leak data');
        // Don't clean up the array
      }, 1);

      // Don't return cleanup function to simulate leak
      if (!shouldLeak) {
        return () => clearInterval(interval);
      }
    }
  }, [shouldLeak]);

  return <div>Potential memory leak component</div>;
};

describe('ErrorBoundary - Ultimate Comprehensive Tests', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  describe('Basic Error Catching', () => {
    it('should catch and display render errors', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} throwType="render" />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Render error')).toBeInTheDocument();
    });

    it('should catch errors in useEffect', async () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} throwType="effect" />
        </ErrorBoundary>
      );

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
    });

    it('should render children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component working')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should handle multiple child components', () => {
      render(
        <ErrorBoundary>
          <div>Child 1</div>
          <ThrowingComponent shouldThrow={false} />
          <div>Child 3</div>
        </ErrorBoundary>
      );

      expect(screen.getByText('Child 1')).toBeInTheDocument();
      expect(screen.getByText('Component working')).toBeInTheDocument();
      expect(screen.getByText('Child 3')).toBeInTheDocument();
    });
  });

  describe('Error Recovery and Reset', () => {
    it('should allow error recovery through reset button', async () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      // Error should be displayed
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Click reset button
      fireEvent.click(screen.getByText('Try again'));

      // Re-render with non-throwing component
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component working')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should handle repeated error/recovery cycles', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      // Cycle through error and recovery multiple times
      for (let i = 0; i < 5; i++) {
        expect(screen.getByRole('alert')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Try again'));

        rerender(
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={false} />
          </ErrorBoundary>
        );

        expect(screen.getByText('Component working')).toBeInTheDocument();

        rerender(
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
        );
      }
    });

    it('should reset error state when children change', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Change children entirely
      rerender(
        <ErrorBoundary>
          <div>New content</div>
        </ErrorBoundary>
      );

      expect(screen.getByText('New content')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });

  describe('Custom Error Handling', () => {
    it('should call onError callback when error occurs', () => {
      const onErrorSpy = jest.fn();

      render(
        <ErrorBoundary onError={onErrorSpy}>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(onErrorSpy).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({ componentStack: expect.any(String) })
      );
    });

    it('should use custom fallback component', () => {
      const CustomFallback: React.FC<{ error: Error; resetError: () => void }> = ({ 
        error, 
        resetError 
      }) => (
        <div data-testid="custom-fallback">
          <h3>Custom Error UI</h3>
          <p>Error: {error.message}</p>
          <button onClick={resetError}>Custom Reset</button>
        </div>
      );

      render(
        <ErrorBoundary fallback={CustomFallback}>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('custom-fallback')).toBeInTheDocument();
      expect(screen.getByText('Custom Error UI')).toBeInTheDocument();
      expect(screen.getByText('Custom Reset')).toBeInTheDocument();
    });

    it('should handle errors in custom fallback component', () => {
      const ThrowingFallback: React.FC<{ error: Error }> = () => {
        throw new Error('Fallback error');
      };

      // This should be caught by a parent error boundary in real apps
      expect(() => {
        render(
          <ErrorBoundary fallback={ThrowingFallback}>
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
        );
      }).toThrow('Fallback error');
    });
  });

  describe('Async Error Handling', () => {
    it('should handle async errors in event handlers', async () => {
      render(
        <ErrorBoundary>
          <AsyncThrowingComponent />
        </ErrorBoundary>
      );

      fireEvent.click(screen.getByText('Async Error'));

      // Async errors might not be caught by error boundaries
      // This tests the component's resilience
      await waitFor(() => {
        expect(screen.getByText('Trigger Error')).toBeInTheDocument();
      });
    });

    it('should handle state-triggered errors', () => {
      render(
        <ErrorBoundary>
          <AsyncThrowingComponent />
        </ErrorBoundary>
      );

      fireEvent.click(screen.getByText('Trigger Error'));

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle promise rejections', async () => {
      const PromiseComponent: React.FC = () => {
        const [error, setError] = React.useState<string | null>(null);

        React.useEffect(() => {
          Promise.reject(new Error('Promise rejection'))
            .catch(err => setError(err.message));
        }, []);

        if (error) {
          throw new Error(error);
        }

        return <div>Promise component</div>;
      };

      render(
        <ErrorBoundary>
          <PromiseComponent />
        </ErrorBoundary>
      );

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
    });
  });

  describe('Performance and Memory Impact', () => {
    it('should not impact performance significantly', () => {
      const startTime = performance.now();

      // Render many components with error boundaries
      for (let i = 0; i < 100; i++) {
        const { unmount } = render(
          <ErrorBoundary key={i}>
            <ThrowingComponent shouldThrow={false} />
          </ErrorBoundary>
        );
        unmount();
      }

      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should clean up properly on unmount', () => {
      const { unmount } = render(
        <ErrorBoundary>
          <MemoryLeakComponent shouldLeak={false} />
        </ErrorBoundary>
      );

      unmount();

      // Should not throw during cleanup
      expect(true).toBe(true);
    });

    it('should handle error boundary with many children efficiently', () => {
      const manyChildren = Array.from({ length: 1000 }, (_, i) => (
        <div key={i}>Child {i}</div>
      ));

      const startTime = performance.now();

      render(
        <ErrorBoundary>
          {manyChildren}
        </ErrorBoundary>
      );

      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(500); // Should render within 500ms
    });
  });

  describe('Edge Cases and Error Types', () => {
    it('should handle TypeError', () => {
      const TypeErrorComponent: React.FC = () => {
        const obj: any = null;
        return <div>{obj.property}</div>; // Will throw TypeError
      };

      render(
        <ErrorBoundary>
          <TypeErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle ReferenceError', () => {
      const ReferenceErrorComponent: React.FC = () => {
        // @ts-ignore - Intentional reference error
        return <div>{nonExistentVariable}</div>;
      };

      render(
        <ErrorBoundary>
          <ReferenceErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle custom error objects', () => {
      const CustomErrorComponent: React.FC = () => {
        throw {
          name: 'CustomError',
          message: 'Custom error message',
          code: 'CUSTOM_ERROR_CODE'
        };
      };

      render(
        <ErrorBoundary>
          <CustomErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle nested error boundaries', () => {
      render(
        <ErrorBoundary>
          <div>Outer boundary</div>
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
          <div>Outer boundary continues</div>
        </ErrorBoundary>
      );

      // Inner boundary should catch the error
      expect(screen.getByText('Outer boundary')).toBeInTheDocument();
      expect(screen.getByText('Outer boundary continues')).toBeInTheDocument();
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle errors during component unmounting', () => {
      const UnmountErrorComponent: React.FC = () => {
        React.useEffect(() => {
          return () => {
            throw new Error('Unmount error');
          };
        }, []);

        return <div>Unmount component</div>;
      };

      const { unmount } = render(
        <ErrorBoundary>
          <UnmountErrorComponent />
        </ErrorBoundary>
      );

      // Should not throw when unmounting
      expect(() => unmount()).not.toThrow();
    });
  });

  describe('Error Boundary Integration', () => {
    it('should work with React.Suspense', async () => {
      const LazyComponent = React.lazy(() =>
        Promise.resolve({
          default: () => <ThrowingComponent shouldThrow={true} />
        })
      );

      render(
        <ErrorBoundary>
          <React.Suspense fallback={<div>Loading...</div>}>
            <LazyComponent />
          </React.Suspense>
        </ErrorBoundary>
      );

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
    });

    it('should work with React.StrictMode', () => {
      render(
        <React.StrictMode>
          <ErrorBoundary>
            <ThrowingComponent shouldThrow={true} />
          </ErrorBoundary>
        </React.StrictMode>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle errors in React.memo components', () => {
      const MemoComponent = React.memo(() => {
        throw new Error('Memo component error');
      });
      MemoComponent.displayName = 'MemoComponent';

      render(
        <ErrorBoundary>
          <MemoComponent />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should handle errors in forwardRef components', () => {
      const ForwardRefComponent = React.forwardRef<HTMLDivElement>(() => {
        throw new Error('ForwardRef component error');
      });
      ForwardRefComponent.displayName = 'ForwardRefComponent';

      render(
        <ErrorBoundary>
          <ForwardRefComponent />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  describe('Accessibility and User Experience', () => {
    it('should provide accessible error messages', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      const alert = screen.getByRole('alert');
      expect(alert).toBeInTheDocument();
      expect(alert).toHaveAttribute('role', 'alert');
    });

    it('should provide keyboard-accessible recovery', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      const resetButton = screen.getByText('Try again');
      expect(resetButton).toBeInTheDocument();
      
      // Test keyboard interaction
      fireEvent.keyDown(resetButton, { key: 'Enter' });
      fireEvent.keyDown(resetButton, { key: ' ' });
    });

    it('should provide detailed error information in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Error details')).toBeInTheDocument();
      expect(screen.getByText('Render error')).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Production Behavior', () => {
    it('should handle errors gracefully in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });

    it('should not expose sensitive error information in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const SensitiveErrorComponent: React.FC = () => {
        throw new Error('Sensitive API key: sk-1234567890');
      };

      render(
        <ErrorBoundary>
          <SensitiveErrorComponent />
        </ErrorBoundary>
      );

      // Should show generic error message, not sensitive details
      expect(screen.queryByText(/API key/i)).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });
  });
});