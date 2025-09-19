'use client';

import { Component, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: any) => void;
  level?: 'page' | 'component';
  name?: string;
}

interface State {
  hasError: boolean;
  error?: Error;
  errorInfo?: any;
  errorId?: string;
}

export class EnhancedErrorBoundary extends Component<Props, State> {
  private retryCount = 0;
  private maxRetries = 2;

  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorId: `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error(`ErrorBoundary (${this.props.name || 'Unknown'}) caught an error:`, {
      error,
      errorInfo,
      props: this.props,
      level: this.props.level || 'component'
    });

    // Store error info in state for display
    this.setState({ errorInfo });

    // Call error handler if provided
    this.props.onError?.(error, errorInfo);

    // Report to monitoring service in production
    if (process.env.NODE_ENV === 'production') {
      this.reportError(error, errorInfo);
    }
  }

  private reportError = (error: Error, errorInfo: any) => {
    // In a real app, you'd send this to a monitoring service like Sentry
    const errorReport = {
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
      },
      errorInfo,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      component: this.props.name || 'Unknown',
      level: this.props.level || 'component',
    };

    console.error('Error report:', errorReport);
    // TODO: Send to monitoring service
  };

  private handleRetry = () => {
    if (this.retryCount < this.maxRetries) {
      this.retryCount++;
      console.log(`Retrying component (${this.retryCount}/${this.maxRetries})...`);
      this.setState({ hasError: false, error: undefined, errorInfo: undefined });
    } else {
      console.error('Max retry attempts reached');
    }
  };

  private handleReset = () => {
    this.retryCount = 0;
    this.setState({ hasError: false, error: undefined, errorInfo: undefined });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const isPageLevel = this.props.level === 'page';
      const componentName = this.props.name || 'Component';

      return (
        <div className={isPageLevel ? "min-h-screen flex items-center justify-center bg-gray-900 text-white p-4" : "flex items-center justify-center bg-gray-800 text-white p-4 rounded-lg border border-gray-700 m-2"}>
          <div className="text-center max-w-md">
            <div className="mb-4">
              <svg
                className={`${isPageLevel ? 'w-16 h-16' : 'w-8 h-8'} mx-auto text-red-500`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.464 0L4.35 16.5c-.77.833.192 2.5 1.732 2.5z"
                />
              </svg>
            </div>
            <h1 className={`${isPageLevel ? 'text-2xl' : 'text-lg'} font-bold mb-2`}>
              {isPageLevel ? 'Something went wrong' : `${componentName} Error`}
            </h1>
            <p className="text-gray-400 mb-4 text-sm">
              {isPageLevel
                ? 'We encountered an unexpected error. Please try refreshing the page.'
                : `The ${componentName.toLowerCase()} component encountered an error.`
              }
            </p>

            {/* Error ID for support */}
            {this.state.errorId && (
              <p className="text-xs text-gray-500 mb-4 font-mono">
                Error ID: {this.state.errorId}
              </p>
            )}

            {/* Development error details */}
            {process.env.NODE_ENV === 'development' && this.state.error && (
              <details className="text-left text-sm text-gray-500 bg-gray-800 p-3 rounded mb-4 border border-gray-600">
                <summary className="cursor-pointer font-semibold mb-2">Error Details</summary>
                <div className="space-y-2">
                  <div>
                    <strong>Message:</strong> {this.state.error.message}
                  </div>
                  <div>
                    <strong>Component:</strong> {componentName}
                  </div>
                  {this.state.errorInfo?.componentStack && (
                    <div>
                      <strong>Component Stack:</strong>
                      <pre className="mt-1 text-xs whitespace-pre-wrap bg-gray-900 p-2 rounded overflow-x-auto">
                        {this.state.errorInfo.componentStack}
                      </pre>
                    </div>
                  )}
                  {this.state.error.stack && (
                    <div>
                      <strong>Stack Trace:</strong>
                      <pre className="mt-1 text-xs whitespace-pre-wrap bg-gray-900 p-2 rounded overflow-x-auto">
                        {this.state.error.stack}
                      </pre>
                    </div>
                  )}
                </div>
              </details>
            )}

            {/* Action buttons */}
            <div className="flex gap-2 justify-center">
              {this.retryCount < this.maxRetries && (
                <button
                  onClick={this.handleRetry}
                  className="px-3 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors text-sm"
                >
                  Try Again ({this.maxRetries - this.retryCount} left)
                </button>
              )}
              <button
                onClick={this.handleReset}
                className="px-3 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors text-sm"
              >
                Reset
              </button>
              {isPageLevel && (
                <button
                  onClick={() => window.location.reload()}
                  className="px-3 py-2 bg-gray-600 text-white rounded hover:bg-gray-700 transition-colors text-sm"
                >
                  Refresh Page
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Utility hook for functional components to catch errors
export const useErrorHandler = () => {
  const handleError = (error: Error, errorInfo?: any) => {
    console.error('Caught error:', error, errorInfo);

    if (process.env.NODE_ENV === 'production') {
      // Report to monitoring service
      const errorReport = {
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
        errorInfo,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href,
      };
      console.error('Error report:', errorReport);
      // TODO: Send to monitoring service
    }
  };

  return { handleError };
};

export default EnhancedErrorBoundary;