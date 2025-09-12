import React, { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorId: string;
}

interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackMessage?: string;
  fallbackComponent?: React.ComponentType<{
    error: Error;
    resetError: () => void;
    errorInfo?: ErrorInfo;
  }>;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  onRetry?: () => void;
  reportError?: (report: {
    error: Error;
    errorInfo: ErrorInfo;
    timestamp: Date;
    userAgent: string;
    url: string;
    context?: Record<string, any>;
  }) => void;
  errorContext?: Record<string, any>;
  showErrorDetails?: boolean;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private errorMessageRef = React.createRef<HTMLHeadingElement>();

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: ''
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
      errorId: `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });

    // Call onError callback
    if (this.props.onError) {
      this.props.onError(error, errorInfo);
    }

    // Report error if reportError function is provided
    if (this.props.reportError) {
      this.props.reportError({
        error,
        errorInfo,
        timestamp: new Date(),
        userAgent: navigator.userAgent,
        url: window.location.href,
        context: this.props.errorContext
      });
    }

    // Log error to console
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  componentDidUpdate(_: ErrorBoundaryProps, prevState: ErrorBoundaryState) {
    // Focus error message for accessibility
    if (this.state.hasError && !prevState.hasError && this.errorMessageRef.current) {
      this.errorMessageRef.current.focus();
    }
  }

  componentDidMount() {
    // Reset error state when children change
    if (this.state.hasError && this.errorMessageRef.current) {
      this.errorMessageRef.current.focus();
    }
  }

  static getDerivedStateFromProps(props: ErrorBoundaryProps, state: ErrorBoundaryState) {
    // Reset error state when children change (key-based reset)
    // Only reset if we have an error and children are provided
    if (state.hasError && state.errorId && props.children) {
      const childrenChanged = React.Children.count(props.children) > 0;
      if (childrenChanged) {
        return {
          hasError: false,
          error: null,
          errorInfo: null,
          errorId: ''
        };
      }
    }
    return null;
  }

  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: ''
    });

    if (this.props.onRetry) {
      this.props.onRetry();
    }
  };

  render() {
    // Handle null/undefined children gracefully
    if (!this.props.children && !this.state.hasError) {
      return null;
    }
    
    if (this.state.hasError && this.state.error) {
      const { fallbackComponent: FallbackComponent, fallbackMessage, showErrorDetails, onRetry } = this.props;

      // Use custom fallback component if provided
      if (FallbackComponent) {
        try {
          return (
            <FallbackComponent
              error={this.state.error}
              resetError={this.handleRetry}
              errorInfo={this.state.errorInfo || undefined}
            />
          );
        } catch (fallbackError) {
          // If custom fallback component fails, fall back to basic error display
          console.error('Fallback component failed:', fallbackError);
        }
      }

      const isDevelopment = process.env.NODE_ENV === 'development';
      const shouldShowDetails = showErrorDetails ?? isDevelopment;

      return (
        <div
          role="alert"
          aria-live="polite"
          style={{
            padding: '20px',
            border: '1px solid #e53e3e',
            borderRadius: '4px',
            backgroundColor: '#fed7d7',
            color: '#742a2a',
            fontFamily: 'system-ui, sans-serif'
          }}
        >
          <h2
            ref={this.errorMessageRef}
            tabIndex={-1}
            style={{
              margin: '0 0 16px 0',
              fontSize: '20px',
              fontWeight: 600,
              color: '#742a2a'
            }}
          >
            {fallbackMessage || 'Something went wrong'}
          </h2>

          <p style={{ margin: '0 0 16px 0', fontSize: '16px' }}>
            {this.state.error.message}
          </p>

          {shouldShowDetails && (
            <div style={{ marginBottom: '16px' }}>
              {this.state.error.stack && (
                <details style={{ marginBottom: '12px' }}>
                  <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                    Error Stack:
                  </summary>
                  <pre
                    style={{
                      margin: '8px 0 0 0',
                      padding: '12px',
                      backgroundColor: '#f7fafc',
                      border: '1px solid #e2e8f0',
                      borderRadius: '4px',
                      fontSize: '12px',
                      overflow: 'auto',
                      color: '#2d3748'
                    }}
                  >
                    {this.state.error.stack}
                  </pre>
                </details>
              )}

              {this.state.errorInfo?.componentStack && (
                <details>
                  <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                    Component Stack:
                  </summary>
                  <pre
                    style={{
                      margin: '8px 0 0 0',
                      padding: '12px',
                      backgroundColor: '#f7fafc',
                      border: '1px solid #e2e8f0',
                      borderRadius: '4px',
                      fontSize: '12px',
                      overflow: 'auto',
                      color: '#2d3748'
                    }}
                  >
                    {this.state.errorInfo.componentStack}
                  </pre>
                </details>
              )}
            </div>
          )}

          {onRetry && (
            <button
              onClick={this.handleRetry}
              style={{
                padding: '8px 16px',
                backgroundColor: '#3182ce',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'background-color 0.2s'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = '#2c5aa0';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = '#3182ce';
              }}
            >
              Retry
            </button>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}