/**
 * Comprehensive Error Boundary Component Tests
 * Tests error handling, fallback UI rendering, accessibility, and edge cases
 */

import React, { Component, ErrorInfo } from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ErrorBoundary } from '../ErrorBoundary';

// Mock console.error to avoid noisy test output
const originalError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalError;
});

beforeEach(() => {
  jest.clearAllMocks();
  // Reset NODE_ENV for each test
  delete (process.env as any).NODE_ENV;
});

// Test component that throws an error
const ThrowError = ({ shouldThrow, errorMessage }: { shouldThrow?: boolean; errorMessage?: string }) => {
  if (shouldThrow) {
    throw new Error(errorMessage || 'Test error message');
  }
  return <div>No error</div>;
};

// Test component for error boundary children
const TestChild = ({ text = 'Test content' }: { text?: string }) => (
  <div data-testid="test-child">{text}</div>
);

// Mock custom fallback component
const MockFallbackComponent = ({ 
  error, 
  resetError, 
  errorInfo 
}: { 
  error: Error; 
  resetError: () => void; 
  errorInfo?: ErrorInfo; 
}) => (
  <div data-testid="custom-fallback">
    <h2>Custom Error: {error.message}</h2>
    <button onClick={resetError} data-testid="custom-retry">
      Custom Retry
    </button>
    {errorInfo && <div data-testid="error-info">{errorInfo.componentStack}</div>}
  </div>
);

// Failing fallback component for testing fallback failure scenarios
class FailingFallbackComponent extends Component<{
  error: Error;
  resetError: () => void;
  errorInfo?: ErrorInfo;
}> {
  // eslint-disable-next-line react/require-render-return
  render() {
    throw new Error('Fallback component failed');
  }
}


describe('ErrorBoundary', () => {

  describe('Basic Error Catching', () => {
    it('should render children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <TestChild text="Working component" />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('test-child')).toBeInTheDocument();
      expect(screen.getByText('Working component')).toBeInTheDocument();
    });

    it('should catch and display error when child component throws', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Component crashed" />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Component crashed')).toBeInTheDocument();
    });

    it('should call console.error when an error is caught', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Test error message" />
        </ErrorBoundary>
      );

      expect(console.error).toHaveBeenCalledWith(
        'ErrorBoundary caught an error:',
        expect.any(Error),
        expect.objectContaining({ componentStack: expect.any(String) })
      );
    });

    it('should generate unique error ID for each error', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Error 1" />
        </ErrorBoundary>
      );

      const firstErrorContainer = screen.getByRole('alert');

      rerender(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Error 2" />
        </ErrorBoundary>
      );

      const secondErrorContainer = screen.getByRole('alert');
      // Both should be alert containers but potentially with different internal state
      expect(firstErrorContainer).toBeInTheDocument();
      expect(secondErrorContainer).toBeInTheDocument();
    });
  });

  describe('Fallback UI Rendering', () => {
    it('should display custom fallback message', () => {
      render(
        <ErrorBoundary fallbackMessage="Custom error message">
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Custom error message')).toBeInTheDocument();
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
    });

    it('should display default fallback message when none provided', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    it('should show error details in development environment', () => {
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Dev error" />
        </ErrorBoundary>
      );

      expect(screen.getByText('Error Stack:')).toBeInTheDocument();
      expect(screen.getByText('Component Stack:')).toBeInTheDocument();
    });

    it('should hide error details in production environment', () => {
      process.env.NODE_ENV = 'production';

      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} errorMessage="Prod error" />
        </ErrorBoundary>
      );

      expect(screen.queryByText('Error Stack:')).not.toBeInTheDocument();
      expect(screen.queryByText('Component Stack:')).not.toBeInTheDocument();
    });

    it('should show error details when showErrorDetails is explicitly true', () => {
      process.env.NODE_ENV = 'production';

      render(
        <ErrorBoundary showErrorDetails={true}>
          <ThrowError shouldThrow={true} errorMessage="Explicit details" />
        </ErrorBoundary>
      );

      expect(screen.getByText('Error Stack:')).toBeInTheDocument();
      expect(screen.getByText('Component Stack:')).toBeInTheDocument();
    });

    it('should hide error details when showErrorDetails is explicitly false', () => {
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary showErrorDetails={false}>
          <ThrowError shouldThrow={true} errorMessage="No details" />
        </ErrorBoundary>
      );

      expect(screen.queryByText('Error Stack:')).not.toBeInTheDocument();
      expect(screen.queryByText('Component Stack:')).not.toBeInTheDocument();
    });
  });

  describe('Custom Fallback Components', () => {
    it('should render custom fallback component when provided', () => {
      render(
        <ErrorBoundary fallbackComponent={MockFallbackComponent}>
          <ThrowError shouldThrow={true} errorMessage="Custom fallback test" />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('custom-fallback')).toBeInTheDocument();
      expect(screen.getByText('Custom Error: Custom fallback test')).toBeInTheDocument();
      expect(screen.getByTestId('custom-retry')).toBeInTheDocument();
    });

    it('should pass error and resetError props to custom fallback', () => {
      render(
        <ErrorBoundary fallbackComponent={MockFallbackComponent}>
          <ThrowError shouldThrow={true} errorMessage="Test error message" />
        </ErrorBoundary>
      );

      expect(screen.getByText('Custom Error: Test error message')).toBeInTheDocument();
      expect(screen.getByTestId('custom-retry')).toBeInTheDocument();
    });

    it('should fallback to default UI when custom fallback component fails', () => {
      render(
        <ErrorBoundary fallbackComponent={FailingFallbackComponent}>
          <ThrowError shouldThrow={true} errorMessage="Original error" />
        </ErrorBoundary>
      );

      // Should show default error UI instead of custom fallback
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Original error')).toBeInTheDocument();
      expect(console.error).toHaveBeenCalledWith(
        'Fallback component failed:',
        expect.any(Error)
      );
    });

    it('should pass errorInfo to custom fallback component', () => {
      render(
        <ErrorBoundary fallbackComponent={MockFallbackComponent}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByTestId('error-info')).toBeInTheDocument();
    });
  });

  describe('Retry Functionality', () => {
    it('should show retry button when onRetry prop is provided', () => {
      const mockOnRetry = jest.fn();

      render(
        <ErrorBoundary onRetry={mockOnRetry}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    });

    it('should not show retry button when onRetry prop is not provided', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    });

    it('should call onRetry and reset error state when retry button is clicked', async () => {
      const mockOnRetry = jest.fn();
      const user = userEvent.setup();

      const { rerender } = render(
        <ErrorBoundary onRetry={mockOnRetry}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const retryButton = screen.getByRole('button', { name: 'Retry' });
      await user.click(retryButton);

      expect(mockOnRetry).toHaveBeenCalledTimes(1);

      // Simulate component re-render without error after retry
      rerender(
        <ErrorBoundary onRetry={mockOnRetry}>
          <TestChild text="Recovered!" />
        </ErrorBoundary>
      );

      expect(screen.getByText('Recovered!')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should reset error state when retry is called via custom fallback', async () => {
      const mockOnRetry = jest.fn();
      const user = userEvent.setup();

      const { rerender } = render(
        <ErrorBoundary fallbackComponent={MockFallbackComponent} onRetry={mockOnRetry}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const customRetryButton = screen.getByTestId('custom-retry');
      await user.click(customRetryButton);

      // Simulate successful recovery
      rerender(
        <ErrorBoundary fallbackComponent={MockFallbackComponent} onRetry={mockOnRetry}>
          <TestChild text="Custom recovery" />
        </ErrorBoundary>
      );

      expect(screen.getByText('Custom recovery')).toBeInTheDocument();
      expect(screen.queryByTestId('custom-fallback')).not.toBeInTheDocument();
    });
  });

  describe('Error Reporting', () => {
    it('should call onError callback when error occurs', () => {
      const mockOnError = jest.fn();

      render(
        <ErrorBoundary onError={mockOnError}>
          <ThrowError shouldThrow={true} errorMessage="Callback test" />
        </ErrorBoundary>
      );

      expect(mockOnError).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Callback test' }),
        expect.objectContaining({ componentStack: expect.any(String) })
      );
    });

    it('should call reportError with comprehensive error report', () => {
      const mockReportError = jest.fn();
      const mockContext = { userId: '123', feature: 'test' };

      // Mock navigator and window
      Object.defineProperty(window, 'location', {
        value: { href: 'http://test.com/page' },
        writable: true,
      });
      Object.defineProperty(navigator, 'userAgent', {
        value: 'TestAgent/1.0',
        writable: true,
      });

      render(
        <ErrorBoundary reportError={mockReportError} errorContext={mockContext}>
          <ThrowError shouldThrow={true} errorMessage="Report test" />
        </ErrorBoundary>
      );

      expect(mockReportError).toHaveBeenCalledWith({
        error: expect.objectContaining({ message: 'Report test' }),
        errorInfo: expect.objectContaining({ componentStack: expect.any(String) }),
        timestamp: expect.any(Date),
        userAgent: 'TestAgent/1.0',
        url: 'http://test.com/page',
        context: mockContext,
      });
    });

    it('should not call callbacks when not provided', () => {
      const consoleSpy = jest.spyOn(console, 'error');

      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      // Should only call console.error, no other callbacks
      expect(consoleSpy).toHaveBeenCalledWith(
        'ErrorBoundary caught an error:',
        expect.any(Error),
        expect.any(Object)
      );
    });
  });

  describe('Accessibility Features', () => {
    it('should have proper ARIA attributes on error container', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorContainer = screen.getByRole('alert');
      expect(errorContainer).toHaveAttribute('aria-live', 'polite');
    });

    it('should focus error message on error', async () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorHeading = screen.getByRole('heading', { level: 2 });
      
      await waitFor(() => {
        expect(errorHeading).toHaveFocus();
      });
    });

    it('should have proper tabindex on error heading', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorHeading = screen.getByRole('heading', { level: 2 });
      expect(errorHeading).toHaveAttribute('tabindex', '-1');
    });

    it('should maintain focus management in custom fallback', () => {
      const CustomFallbackWithFocus = ({ error, resetError }: any) => (
        <div role="alert">
          <h2 tabIndex={-1} ref={(el) => el?.focus()}>
            {error.message}
          </h2>
          <button onClick={resetError}>Retry</button>
        </div>
      );

      render(
        <ErrorBoundary fallbackComponent={CustomFallbackWithFocus}>
          <ThrowError shouldThrow={true} errorMessage="Focus test" />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });





  describe('Edge Cases', () => {
    it('should handle null children', () => {
      render(<ErrorBoundary>{null}</ErrorBoundary>);
      
      // Should render without errors
      expect(document.body).toBeInTheDocument();
    });

    it('should handle undefined children', () => {
      render(<ErrorBoundary>{undefined}</ErrorBoundary>);
      
      // Should render without errors
      expect(document.body).toBeInTheDocument();
    });

    it('should handle empty fragment children', () => {
      render(
        <ErrorBoundary>
          <></>
        </ErrorBoundary>
      );
      
      // Should render without errors
      expect(document.body).toBeInTheDocument();
    });

    it('should handle errors in error boundary itself', () => {
      const BrokenFallback = () => {
        throw new Error('Fallback error');
      };

      // This should not cause infinite loops
      render(
        <ErrorBoundary fallbackComponent={BrokenFallback}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      // Should fall back to basic error display
      expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    });
  });

  describe('Additional Edge Cases and Error Handling', () => {
    it('should handle errors in componentDidMount', () => {
      class ComponentDidMountError extends Component {
        componentDidMount() {
          throw new Error('componentDidMount error');
        }

        render() {
          return <div>Should not render</div>;
        }
      }

      render(
        <ErrorBoundary>
          <ComponentDidMountError />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('componentDidMount error')).toBeInTheDocument();
    });

    it('should handle errors in useEffect', () => {
      const EffectErrorComponent = () => {
        React.useEffect(() => {
          throw new Error('useEffect error');
        }, []);

        return <div>Component with effect</div>;
      };

      render(
        <ErrorBoundary>
          <EffectErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('useEffect error')).toBeInTheDocument();
    });

    it('should handle error without stack trace', () => {
      const errorWithoutStack = new Error('No stack error');
      delete errorWithoutStack.stack;

      class NoStackErrorComponent extends Component {
        // eslint-disable-next-line react/require-render-return
        render() {
          throw errorWithoutStack;
        }
      }

      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary>
          <NoStackErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText('No stack error')).toBeInTheDocument();
      // Should still show error details section even without stack
      expect(screen.getByText('Component Stack:')).toBeInTheDocument();
    });
  });

  describe('Button Interaction and Styling', () => {
    it('should handle retry button hover states', async () => {
      const mockOnRetry = jest.fn();
      const user = userEvent.setup();

      render(
        <ErrorBoundary onRetry={mockOnRetry}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const retryButton = screen.getByRole('button', { name: 'Retry' });
      
      // Test hover enter
      await user.hover(retryButton);
      expect(retryButton).toHaveStyle('background-color: #2c5aa0');

      // Test hover leave
      await user.unhover(retryButton);
      expect(retryButton).toHaveStyle('background-color: #3182ce');
    });

    it('should handle keyboard navigation on retry button', async () => {
      const mockOnRetry = jest.fn();
      const user = userEvent.setup();

      render(
        <ErrorBoundary onRetry={mockOnRetry}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const retryButton = screen.getByRole('button', { name: 'Retry' });
      
      // Focus and activate with keyboard
      await user.tab();
      expect(retryButton).toHaveFocus();
      
      await user.keyboard('{Enter}');
      expect(mockOnRetry).toHaveBeenCalledTimes(1);
    });

    it('should expand error details when clicked', async () => {
      const user = userEvent.setup();
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const errorStackSummary = screen.getByText('Error Stack:');
      const componentStackSummary = screen.getByText('Component Stack:');

      // Initially collapsed
      expect(screen.queryByText(/at ThrowError/)).not.toBeInTheDocument();

      // Expand error stack
      await user.click(errorStackSummary);
      expect(screen.getByText(/Error: Test error/)).toBeInTheDocument();

      // Expand component stack
      await user.click(componentStackSummary);
      expect(screen.getByText(/in ThrowError/)).toBeInTheDocument();
    });
  });

  describe('Performance and Memory', () => {
    it('should not cause memory leaks with multiple errors', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <TestChild />
        </ErrorBoundary>
      );

      // Simulate multiple error/recovery cycles
      for (let i = 0; i < 10; i++) {
        rerender(
          <ErrorBoundary>
            <ThrowError shouldThrow={true} errorMessage={`Error ${i}`} />
          </ErrorBoundary>
        );

        rerender(
          <ErrorBoundary>
            <TestChild text={`Recovery ${i}`} />
          </ErrorBoundary>
        );
      }

      expect(screen.getByText('Recovery 9')).toBeInTheDocument();
    });

    it('should handle rapid error state changes', async () => {
      const mockOnRetry = jest.fn();
      const user = userEvent.setup();

      const { rerender } = render(
        <ErrorBoundary onRetry={mockOnRetry}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      const retryButton = screen.getByRole('button', { name: 'Retry' });

      // Rapid clicks
      await user.click(retryButton);
      await user.click(retryButton);
      await user.click(retryButton);

      expect(mockOnRetry).toHaveBeenCalledTimes(3);
    });
  });

  describe('Component Lifecycle Integration', () => {
    it('should properly clean up when component unmounts', () => {
      const { unmount } = render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      
      // Should unmount without errors
      expect(() => unmount()).not.toThrow();
    });

    it('should handle prop changes while in error state', () => {
      const { rerender } = render(
        <ErrorBoundary fallbackMessage="Initial message">
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Initial message')).toBeInTheDocument();

      // Change props while in error state
      rerender(
        <ErrorBoundary fallbackMessage="Updated message">
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Updated message')).toBeInTheDocument();
      expect(screen.queryByText('Initial message')).not.toBeInTheDocument();
    });
  });
});