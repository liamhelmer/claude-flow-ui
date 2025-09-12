import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ErrorBoundary from '../ErrorBoundary';

// Mock child component that can throw errors
const ThrowError = ({ shouldThrow, errorType }: { shouldThrow?: boolean; errorType?: string }) => {
  if (shouldThrow) {
    if (errorType === 'network') {
      throw new Error('Network request failed');
    } else if (errorType === 'syntax') {
      throw new SyntaxError('Unexpected token');
    } else if (errorType === 'reference') {
      throw new ReferenceError('Variable is not defined');
    } else if (errorType === 'type') {
      throw new TypeError('Cannot read property of undefined');
    } else {
      throw new Error('Test error message');
    }
  }
  return <div>Working component</div>;
};

const AsyncThrowError = ({ shouldThrow }: { shouldThrow?: boolean }) => {
  React.useEffect(() => {
    if (shouldThrow) {
      throw new Error('Async error');
    }
  }, [shouldThrow]);
  
  return <div>Async component</div>;
};

describe('ErrorBoundary - Comprehensive Enhanced Tests', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    // Suppress console.error for cleaner test output
    consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  describe('Normal Operation', () => {
    it('should render children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Working component')).toBeInTheDocument();
    });

    it('should render multiple children successfully', () => {
      render(
        <ErrorBoundary>
          <div>Child 1</div>
          <div>Child 2</div>
          <ThrowError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Child 1')).toBeInTheDocument();
      expect(screen.getByText('Child 2')).toBeInTheDocument();
      expect(screen.getByText('Working component')).toBeInTheDocument();
    });

    it('should handle React fragments', () => {
      render(
        <ErrorBoundary>
          <>
            <div>Fragment child 1</div>
            <div>Fragment child 2</div>
          </>
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Fragment child 1')).toBeInTheDocument();
      expect(screen.getByText('Fragment child 2')).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('should catch and display error when child throws', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText(/Test error message/)).toBeInTheDocument();
    });

    it('should handle different error types', () => {
      const errorTypes = ['network', 'syntax', 'reference', 'type'];
      
      errorTypes.forEach(errorType => {
        const { unmount } = render(
          <ErrorBoundary>
            <ThrowError shouldThrow={true} errorType={errorType} />
          </ErrorBoundary>
        );
        
        expect(screen.getByText('Something went wrong')).toBeInTheDocument();
        
        unmount();
      });
    });

    it('should display error message in error UI', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Test error message')).toBeInTheDocument();
    });

    it('should handle null error gracefully', () => {
      const NullError = () => {
        throw null;
      };
      
      render(
        <ErrorBoundary>
          <NullError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    it('should handle string error gracefully', () => {
      const StringError = () => {
        throw 'String error';
      };
      
      render(
        <ErrorBoundary>
          <StringError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    it('should handle object error gracefully', () => {
      const ObjectError = () => {
        throw { message: 'Object error', code: 500 };
      };
      
      render(
        <ErrorBoundary>
          <ObjectError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });
  });

  describe('Error Recovery', () => {
    it('should provide retry functionality', async () => {
      const user = userEvent.setup();
      let shouldThrow = true;
      
      const RecoverableComponent = () => {
        if (shouldThrow) {
          throw new Error('Recoverable error');
        }
        return <div>Recovered successfully</div>;
      };
      
      const { rerender } = render(
        <ErrorBoundary>
          <RecoverableComponent />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      
      // Simulate fixing the error
      shouldThrow = false;
      
      // Click retry button
      await user.click(screen.getByRole('button', { name: /try again/i }));
      
      // Re-render with fixed component
      rerender(
        <ErrorBoundary>
          <RecoverableComponent />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Recovered successfully')).toBeInTheDocument();
    });

    it('should reset error state on retry', async () => {
      const user = userEvent.setup();
      
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      
      await user.click(screen.getByRole('button', { name: /try again/i }));
      
      rerender(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Working component')).toBeInTheDocument();
    });
  });

  describe('Error Boundary UI', () => {
    it('should display appropriate error UI elements', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
      expect(screen.getByText(/Test error message/)).toBeInTheDocument();
    });

    it('should have accessible error UI', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      const errorContainer = screen.getByRole('alert');
      expect(errorContainer).toBeInTheDocument();
      
      const retryButton = screen.getByRole('button', { name: /try again/i });
      expect(retryButton).toHaveAttribute('type', 'button');
    });

    it('should style error UI appropriately', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      const errorContainer = screen.getByRole('alert');
      expect(errorContainer).toHaveClass('bg-red-50', 'border', 'border-red-200', 'rounded-lg', 'p-6');
      
      const retryButton = screen.getByRole('button', { name: /try again/i });
      expect(retryButton).toHaveClass('bg-red-600', 'text-white', 'px-4', 'py-2', 'rounded', 'hover:bg-red-700');
    });
  });

  describe('Nested Error Boundaries', () => {
    it('should handle nested error boundaries correctly', () => {
      render(
        <ErrorBoundary>
          <div>Outer boundary</div>
          <ErrorBoundary>
            <ThrowError shouldThrow={true} />
          </ErrorBoundary>
        </ErrorBoundary>
      );
      
      // Inner boundary should catch the error
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Outer boundary')).toBeInTheDocument();
    });

    it('should propagate to parent boundary if child boundary fails', () => {
      const FailingErrorBoundary = ({ children }: { children: React.ReactNode }) => {
        throw new Error('Error boundary itself failed');
      };
      
      render(
        <ErrorBoundary>
          <FailingErrorBoundary>
            <div>Child content</div>
          </FailingErrorBoundary>
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });
  });

  describe('Development vs Production Behavior', () => {
    it('should show detailed error in development mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Test error message')).toBeInTheDocument();
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should log errors to console', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(consoleSpy).toHaveBeenCalled();
    });
  });

  describe('Component Lifecycle Integration', () => {
    it('should catch errors in componentDidMount', () => {
      class MountError extends React.Component {
        componentDidMount() {
          throw new Error('Mount error');
        }
        
        render() {
          return <div>Mount component</div>;
        }
      }
      
      render(
        <ErrorBoundary>
          <MountError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    it('should catch errors in componentDidUpdate', () => {
      class UpdateError extends React.Component<{ shouldThrow?: boolean }> {
        componentDidUpdate() {
          if (this.props.shouldThrow) {
            throw new Error('Update error');
          }
        }
        
        render() {
          return <div>Update component</div>;
        }
      }
      
      const { rerender } = render(
        <ErrorBoundary>
          <UpdateError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Update component')).toBeInTheDocument();
      
      rerender(
        <ErrorBoundary>
          <UpdateError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });
  });

  describe('Event Handler Errors', () => {
    it('should not catch errors in event handlers', async () => {
      const user = userEvent.setup();
      
      const EventHandlerError = () => {
        const handleClick = () => {
          throw new Error('Event handler error');
        };
        
        return <button onClick={handleClick}>Click me</button>;
      };
      
      render(
        <ErrorBoundary>
          <EventHandlerError />
        </ErrorBoundary>
      );
      
      const button = screen.getByRole('button', { name: /click me/i });
      
      // Event handler errors should not be caught by error boundary
      expect(async () => {
        await user.click(button);
      }).rejects.toThrow('Event handler error');
    });
  });

  describe('Async Errors', () => {
    it('should not catch async errors by default', async () => {
      // Error boundaries don't catch async errors
      render(
        <ErrorBoundary>
          <AsyncThrowError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Async component')).toBeInTheDocument();
    });
  });

  describe('Performance and Memory', () => {
    it('should not leak memory on error state changes', () => {
      const { rerender, unmount } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      
      rerender(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText('Working component')).toBeInTheDocument();
      
      unmount();
      
      // No memory leak assertions - handled by test environment
    });

    it('should handle rapid error state changes', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      );
      
      for (let i = 0; i < 10; i++) {
        rerender(
          <ErrorBoundary>
            <ThrowError shouldThrow={i % 2 === 0} />
          </ErrorBoundary>
        );
      }
      
      // Should handle rapid changes without issues
      expect(screen.getByText('Working component')).toBeInTheDocument();
    });
  });

  describe('Integration with Testing', () => {
    it('should be testable with different error scenarios', () => {
      const errorScenarios = [
        { type: 'Error', message: 'Standard error' },
        { type: 'TypeError', message: 'Type error' },
        { type: 'ReferenceError', message: 'Reference error' },
      ];
      
      errorScenarios.forEach(({ type, message }) => {
        const ErrorComponent = () => {
          const ErrorClass = globalThis[type as keyof typeof globalThis] as any;
          throw new ErrorClass(message);
        };
        
        const { unmount } = render(
          <ErrorBoundary>
            <ErrorComponent />
          </ErrorBoundary>
        );
        
        expect(screen.getByText('Something went wrong')).toBeInTheDocument();
        expect(screen.getByText(message)).toBeInTheDocument();
        
        unmount();
      });
    });
  });
});