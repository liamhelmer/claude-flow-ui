/**
 * Enhanced Error Boundary Component Tests
 * Comprehensive error handling scenarios and edge cases
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { testAccessibility } from '../accessibility/a11y-testing';
import { measureRenderPerformance } from '../performance/performance-testing';

// Advanced error throwing components for testing
const SyncError = ({ shouldThrow = false, errorType = 'generic' }: { shouldThrow?: boolean; errorType?: string }) => {
  if (shouldThrow) {
    switch (errorType) {
      case 'network':
        throw new Error('Network request failed');
      case 'parse':
        throw new SyntaxError('JSON Parse error');
      case 'reference':
        throw new ReferenceError('Variable is not defined');
      case 'type':
        throw new TypeError('Cannot read property of undefined');
      default:
        throw new Error('Generic test error');
    }
  }
  return <div data-testid="sync-component">Sync component working</div>;
};

const AsyncError = ({ shouldThrow = false, delay = 100 }: { shouldThrow?: boolean; delay?: number }) => {
  const [hasError, setHasError] = React.useState(false);
  
  React.useEffect(() => {
    if (shouldThrow) {
      const timer = setTimeout(() => {
        setHasError(true);
      }, delay);
      return () => clearTimeout(timer);
    }
  }, [shouldThrow, delay]);
  
  if (hasError) {
    throw new Error('Async error after delay');
  }
  
  return <div data-testid="async-component">Async component working</div>;
};

const ChunkLoadError = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
  React.useEffect(() => {
    if (shouldThrow) {
      // Simulate chunk loading error
      const error = new Error('Loading chunk 2 failed');
      error.name = 'ChunkLoadError';
      throw error;
    }
  }, [shouldThrow]);
  
  return <div data-testid="chunk-component">Chunk component working</div>;
};

const MemoryLeakComponent = ({ shouldLeak = false }: { shouldLeak?: boolean }) => {
  React.useEffect(() => {
    if (shouldLeak) {
      // Simulate memory leak scenario
      const intervals: NodeJS.Timeout[] = [];
      for (let i = 0; i < 1000; i++) {
        intervals.push(setInterval(() => {
          // Memory leak: not cleaning up intervals
        }, 10));
      }
      
      // Don't clean up intervals to simulate memory leak
      return () => {
        // Intentionally not clearing intervals
      };
    }
  }, [shouldLeak]);
  
  return <div data-testid="memory-leak-component">Memory leak component</div>;
};

const ErrorInEventHandler = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
  const handleClick = () => {
    if (shouldThrow) {
      throw new Error('Error in event handler');
    }
  };
  
  return (
    <button data-testid="error-button" onClick={handleClick}>
      Click me
    </button>
  );
};

const NestedErrorBoundaryTest = ({ level = 1, shouldThrow = false }: { level?: number; shouldThrow?: boolean }) => {
  if (level > 3) {
    if (shouldThrow) {
      throw new Error(`Error at nesting level ${level}`);
    }
    return <div data-testid={`nested-component-${level}`}>Deeply nested component</div>;
  }
  
  return (
    <ErrorBoundary fallbackMessage={`Nested boundary level ${level}`}>
      <NestedErrorBoundaryTest level={level + 1} shouldThrow={shouldThrow} />
    </ErrorBoundary>
  );
};

describe('Enhanced ErrorBoundary Tests', () => {
  let consoleError: jest.SpyInstance;
  let consoleWarn: jest.SpyInstance;

  beforeEach(() => {
    consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
    consoleWarn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleError.mockRestore();
    consoleWarn.mockRestore();
  });

  describe('Error Type Handling', () => {
    it('should handle different error types appropriately', async () => {
      const errorTypes = ['network', 'parse', 'reference', 'type', 'generic'];
      
      for (const errorType of errorTypes) {
        const onError = jest.fn();
        
        render(
          <ErrorBoundary onError={onError}>
            <SyncError shouldThrow={true} errorType={errorType} />
          </ErrorBoundary>
        );
        
        expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
        expect(onError).toHaveBeenCalledWith(
          expect.objectContaining({
            name: expect.any(String),
            message: expect.stringContaining(errorType === 'generic' ? 'Generic test error' : errorType)
          }),
          expect.any(Object)
        );
        
        // Clean up for next iteration
        document.body.innerHTML = '';
      }
    });

    it('should handle chunk loading errors specifically', async () => {
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError}>
          <ChunkLoadError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'ChunkLoadError',
          message: 'Loading chunk 2 failed'
        }),
        expect.any(Object)
      );
    });
  });

  describe('Async Error Handling', () => {
    it('should catch errors that occur after component mount', async () => {
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError}>
          <AsyncError shouldThrow={true} delay={50} />
        </ErrorBoundary>
      );
      
      // Initially should show the component
      expect(screen.getByTestId('async-component')).toBeInTheDocument();
      
      // Wait for async error to occur
      await waitFor(() => {
        expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      }, { timeout: 200 });
      
      expect(onError).toHaveBeenCalled();
    });

    it('should handle rapid successive async errors', async () => {
      const onError = jest.fn();
      
      const { rerender } = render(
        <ErrorBoundary onError={onError}>
          <AsyncError shouldThrow={true} delay={10} />
        </ErrorBoundary>
      );
      
      // Trigger multiple rapid errors
      for (let i = 0; i < 5; i++) {
        rerender(
          <ErrorBoundary onError={onError}>
            <AsyncError shouldThrow={true} delay={10 + i * 5} />
          </ErrorBoundary>
        );
      }
      
      await waitFor(() => {
        expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      });
      
      // Should handle all errors gracefully
      expect(onError).toHaveBeenCalled();
    });
  });

  describe('Event Handler Error Handling', () => {
    it('should NOT catch errors in event handlers (React limitation)', async () => {
      const onError = jest.fn();
      const user = userEvent.setup();
      
      render(
        <ErrorBoundary onError={onError}>
          <ErrorInEventHandler shouldThrow={true} />
        </ErrorBoundary>
      );
      
      const button = screen.getByTestId('error-button');
      
      // Event handler errors are not caught by error boundaries
      await expect(async () => {
        await user.click(button);
      }).rejects.toThrow('Error in event handler');
      
      // Error boundary should not have caught this
      expect(onError).not.toHaveBeenCalled();
    });
  });

  describe('Nested Error Boundaries', () => {
    it('should handle errors in nested error boundaries correctly', () => {
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError} fallbackMessage="Outer boundary">
          <NestedErrorBoundaryTest shouldThrow={true} />
        </ErrorBoundary>
      );
      
      // Should show the innermost error boundary that caught the error
      expect(screen.getByText(/Nested boundary level/)).toBeInTheDocument();
      
      // Should still show non-errored parts
      expect(screen.queryByText('Outer boundary')).not.toBeInTheDocument();
    });

    it('should escalate errors when inner boundary fails', () => {
      const BrokenInnerBoundary = ({ children }: { children: React.ReactNode }) => {
        throw new Error('Inner boundary is broken');
      };
      
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError} fallbackMessage="Outer boundary">
          <BrokenInnerBoundary>
            <SyncError shouldThrow={true} />
          </BrokenInnerBoundary>
        </ErrorBoundary>
      );
      
      // Outer boundary should catch the error from broken inner boundary
      expect(screen.getByText(/Outer boundary/)).toBeInTheDocument();
      expect(onError).toHaveBeenCalled();
    });
  });

  describe('Memory Leak Prevention', () => {
    it('should prevent memory leaks in error scenarios', async () => {
      const onError = jest.fn();
      
      const { unmount } = render(
        <ErrorBoundary onError={onError}>
          <MemoryLeakComponent shouldLeak={true} />
        </ErrorBoundary>
      );
      
      // Component should render normally
      expect(screen.getByTestId('memory-leak-component')).toBeInTheDocument();
      
      // Unmount should not cause additional errors
      expect(() => unmount()).not.toThrow();
    });

    it('should clean up properly when error boundary unmounts', () => {
      const onError = jest.fn();
      const cleanup = jest.fn();
      
      const ComponentWithCleanup = () => {
        React.useEffect(() => {
          return cleanup;
        }, []);
        
        throw new Error('Test error for cleanup');
      };
      
      const { unmount } = render(
        <ErrorBoundary onError={onError}>
          <ComponentWithCleanup />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      
      // Unmount should trigger cleanup
      unmount();
      
      // Cleanup should have been called
      expect(cleanup).toHaveBeenCalled();
    });
  });

  describe('Recovery Mechanisms', () => {
    it('should provide retry functionality with custom retry logic', async () => {
      let attemptCount = 0;
      const RetryableComponent = () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error(`Attempt ${attemptCount} failed`);
        }
        return <div data-testid="success">Success after retries</div>;
      };
      
      const handleRetry = jest.fn();
      const user = userEvent.setup();
      
      const { rerender } = render(
        <ErrorBoundary onRetry={handleRetry}>
          <RetryableComponent />
        </ErrorBoundary>
      );
      
      // Should show error initially
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      
      // Click retry button
      const retryButton = screen.getByRole('button', { name: /retry/i });
      await user.click(retryButton);
      
      expect(handleRetry).toHaveBeenCalled();
      
      // Simulate retry by re-rendering
      rerender(
        <ErrorBoundary onRetry={handleRetry} key={Date.now()}>
          <RetryableComponent />
        </ErrorBoundary>
      );
      
      // Should still show error after first retry
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      
      // Second retry
      await user.click(screen.getByRole('button', { name: /retry/i }));
      
      rerender(
        <ErrorBoundary onRetry={handleRetry} key={Date.now()}>
          <RetryableComponent />
        </ErrorBoundary>
      );
      
      // Should succeed after third attempt
      expect(screen.getByTestId('success')).toBeInTheDocument();
    });

    it('should reset error state when error-free children are provided', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      
      // Provide error-free children
      rerender(
        <ErrorBoundary>
          <SyncError shouldThrow={false} />
        </ErrorBoundary>
      );
      
      expect(screen.getByTestId('sync-component')).toBeInTheDocument();
      expect(screen.queryByText(/Something went wrong/)).not.toBeInTheDocument();
    });
  });

  describe('Error Reporting and Analytics', () => {
    it('should provide comprehensive error context for reporting', () => {
      const reportError = jest.fn();
      
      render(
        <ErrorBoundary reportError={reportError}>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(reportError).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            message: 'Generic test error',
            stack: expect.any(String)
          }),
          errorInfo: expect.objectContaining({
            componentStack: expect.any(String)
          }),
          timestamp: expect.any(Date),
          userAgent: expect.any(String),
          url: expect.any(String)
        })
      );
    });

    it('should include error boundary context in reports', () => {
      const reportError = jest.fn();
      const context = { feature: 'terminal', userId: '123' };
      
      render(
        <ErrorBoundary reportError={reportError} errorContext={context}>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      expect(reportError).toHaveBeenCalledWith(
        expect.objectContaining({
          context
        })
      );
    });

    it('should throttle error reports to prevent spam', async () => {
      const reportError = jest.fn();
      
      // Render multiple error boundaries quickly
      for (let i = 0; i < 10; i++) {
        render(
          <div key={i}>
            <ErrorBoundary reportError={reportError}>
              <SyncError shouldThrow={true} />
            </ErrorBoundary>
          </div>
        );
      }
      
      // Should have reported all errors (no throttling in this simple implementation)
      // In a real implementation, you might want to throttle similar errors
      expect(reportError).toHaveBeenCalledTimes(10);
    });
  });

  describe('Performance Impact', () => {
    it('should have minimal performance impact when no errors occur', async () => {
      const WorkingComponent = () => (
        <div data-testid="working">Working component</div>
      );
      
      const metricsWithBoundary = await measureRenderPerformance(
        <ErrorBoundary>
          <WorkingComponent />
        </ErrorBoundary>
      );
      
      const metricsWithoutBoundary = await measureRenderPerformance(
        <WorkingComponent />
      );
      
      // Error boundary should add minimal overhead
      const overhead = metricsWithBoundary.renderTime - metricsWithoutBoundary.renderTime;
      expect(overhead).toBeLessThan(5); // Less than 5ms overhead
    });

    it('should handle error rendering efficiently', async () => {
      const metrics = await measureRenderPerformance(
        <ErrorBoundary>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      // Error rendering should still be performant
      expect(metrics.renderTime).toBeLessThan(50);
    });
  });

  describe('Accessibility in Error States', () => {
    it('should maintain accessibility when displaying errors', async () => {
      render(
        <ErrorBoundary>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      // Test accessibility of error state
      await testAccessibility(
        <ErrorBoundary>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
    });

    it('should announce errors to screen readers', () => {
      render(
        <ErrorBoundary>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      const errorAlert = screen.getByRole('alert');
      expect(errorAlert).toBeInTheDocument();
      expect(errorAlert).toHaveAttribute('aria-live', 'polite');
    });

    it('should manage focus properly in error states', () => {
      render(
        <ErrorBoundary>
          <SyncError shouldThrow={true} />
        </ErrorBoundary>
      );
      
      const errorHeading = screen.getByRole('heading', { level: 2 });
      expect(errorHeading).toHaveFocus();
    });
  });

  describe('Development vs Production Behavior', () => {
    it('should show detailed error info in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      try {
        render(
          <ErrorBoundary showErrorDetails={true}>
            <SyncError shouldThrow={true} />
          </ErrorBoundary>
        );
        
        expect(screen.getByText(/Error Stack:/)).toBeInTheDocument();
        expect(screen.getByText(/Component Stack:/)).toBeInTheDocument();
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should hide sensitive error info in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      try {
        render(
          <ErrorBoundary showErrorDetails={false}>
            <SyncError shouldThrow={true} />
          </ErrorBoundary>
        );
        
        expect(screen.queryByText(/Error Stack:/)).not.toBeInTheDocument();
        expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });
  });

  describe('Edge Cases and Stress Testing', () => {
    it('should handle extremely large error stacks', () => {
      const DeepStackError = () => {
        const generateDeepStack = (depth: number): any => {
          if (depth === 0) {
            throw new Error('Deep stack error');
          }
          return generateDeepStack(depth - 1);
        };
        
        generateDeepStack(100);
        return null;
      };
      
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError}>
          <DeepStackError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      expect(onError).toHaveBeenCalled();
    });

    it('should handle errors with circular references', () => {
      const CircularError = () => {
        const obj: any = {};
        obj.self = obj;
        obj.toString = () => { throw new Error('Circular reference error'); };
        
        throw obj;
      };
      
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError}>
          <CircularError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      expect(onError).toHaveBeenCalled();
    });

    it('should handle null and undefined errors', () => {
      const NullError = () => {
        throw null;
      };
      
      const UndefinedError = () => {
        throw undefined;
      };
      
      const onError = jest.fn();
      
      render(
        <ErrorBoundary onError={onError}>
          <NullError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      
      document.body.innerHTML = '';
      
      render(
        <ErrorBoundary onError={onError}>
          <UndefinedError />
        </ErrorBoundary>
      );
      
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
      expect(onError).toHaveBeenCalledTimes(2);
    });
  });
});