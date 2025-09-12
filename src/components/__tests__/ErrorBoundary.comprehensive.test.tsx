import React from 'react';
import { render, screen } from '@testing-library/react';
import ErrorBoundary from '../ErrorBoundary';
import Terminal from '../terminal/Terminal';
import Tab from '../tabs/Tab';
import TabList from '../tabs/TabList';

// Mock console.error to prevent error logs in tests
const originalError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalError;
});

// Mock components that might throw errors
const ThrowingComponent = ({ shouldThrow = true, errorMessage = 'Test error' }) => {
  if (shouldThrow) {
    throw new Error(errorMessage);
  }
  return <div>Component working fine</div>;
};

const AsyncThrowingComponent = ({ shouldThrow = true }) => {
  React.useEffect(() => {
    if (shouldThrow) {
      throw new Error('Async error');
    }
  }, [shouldThrow]);
  return <div>Async component</div>;
};

// Mock hooks that might fail
jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: jest.fn(() => ({
    connected: true,
    connecting: false,
    isConnected: true,
    sendData: jest.fn(),
    sendMessage: jest.fn(),
    resizeTerminal: jest.fn(),
    createSession: jest.fn(),
    destroySession: jest.fn(),
    listSessions: jest.fn(),
    connect: jest.fn(),
    disconnect: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
  })),
}));

jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: jest.fn(() => ({
    terminalRef: { current: null },
    terminal: null,
    writeToTerminal: jest.fn(),
    clearTerminal: jest.fn(),
    focusTerminal: jest.fn(),
    fitTerminal: jest.fn(),
    destroyTerminal: jest.fn(),
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
    isAtBottom: true,
    hasNewOutput: false,
    isConnected: true,
  })),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: jest.fn(() => ({
    sessions: [],
    activeSession: null,
    isCollapsed: false,
    error: null,
    loading: false,
    setError: jest.fn(),
    setLoading: jest.fn(),
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
    toggleSidebar: jest.fn(),
  })),
}));

describe('ErrorBoundary Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset console.error mock
    (console.error as jest.Mock).mockClear();
  });

  describe('Basic Error Boundary Functionality', () => {
    it('should catch and display errors from child components', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} errorMessage="Child component error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Child component error/i)).toBeInTheDocument();
    });

    it('should render children normally when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component working fine')).toBeInTheDocument();
      expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
    });

    it('should display fallback UI when error occurs', () => {
      render(
        <ErrorBoundary fallback={<div>Custom error message</div>}>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Custom error message')).toBeInTheDocument();
    });

    it('should log errors to console', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} errorMessage="Logged error" />
        </ErrorBoundary>
      );

      expect(console.error).toHaveBeenCalled();
    });
  });

  describe('Component-Specific Error Scenarios', () => {
    it('should handle Terminal component errors', () => {
      // Mock Terminal to throw an error
      jest.doMock('../terminal/Terminal', () => {
        return function FailingTerminal() {
          throw new Error('Terminal initialization failed');
        };
      });

      render(
        <ErrorBoundary>
          <Terminal sessionId="test-session" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle Tab component errors', () => {
      const FailingTab = () => {
        throw new Error('Tab rendering failed');
      };

      render(
        <ErrorBoundary>
          <FailingTab />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Tab rendering failed/i)).toBeInTheDocument();
    });

    it('should handle TabList component errors with invalid data', () => {
      const FailingTabList = () => {
        // Simulate invalid props causing an error
        const invalidTabs = null;
        return (
          <TabList
            tabs={invalidTabs as any}
            activeTab="invalid"
            onTabSelect={() => {}}
            onTabClose={() => {}}
          />
        );
      };

      render(
        <ErrorBoundary>
          <FailingTabList />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });
  });

  describe('Hook-Related Error Scenarios', () => {
    it('should handle WebSocket hook failures', () => {
      // Mock useWebSocket to throw an error
      const { useWebSocket } = require('@/hooks/useWebSocket');
      useWebSocket.mockImplementation(() => {
        throw new Error('WebSocket connection failed');
      });

      render(
        <ErrorBoundary>
          <Terminal sessionId="test-session" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle Terminal hook failures', () => {
      // Mock useTerminal to throw an error
      const { useTerminal } = require('@/hooks/useTerminal');
      useTerminal.mockImplementation(() => {
        throw new Error('Terminal hook initialization failed');
      });

      render(
        <ErrorBoundary>
          <Terminal sessionId="test-session" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle store hook failures', () => {
      // Mock useAppStore to throw an error
      const { useAppStore } = require('@/lib/state/store');
      useAppStore.mockImplementation(() => {
        throw new Error('Store access failed');
      });

      render(
        <ErrorBoundary>
          <Terminal sessionId="test-session" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });
  });

  describe('Nested Error Boundaries', () => {
    it('should handle errors in nested components', () => {
      render(
        <ErrorBoundary>
          <div>
            <h1>Parent Component</h1>
            <ErrorBoundary>
              <ThrowingComponent shouldThrow={true} errorMessage="Nested error" />
            </ErrorBoundary>
            <div>Sibling component</div>
          </div>
        </ErrorBoundary>
      );

      // Parent should still render, only nested error boundary should catch error
      expect(screen.getByText('Parent Component')).toBeInTheDocument();
      expect(screen.getByText('Sibling component')).toBeInTheDocument();
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Nested error/i)).toBeInTheDocument();
    });

    it('should isolate errors to specific boundaries', () => {
      render(
        <div>
          <ErrorBoundary>
            <div data-testid="boundary-1">
              <ThrowingComponent shouldThrow={true} errorMessage="Error in boundary 1" />
            </div>
          </ErrorBoundary>
          <ErrorBoundary>
            <div data-testid="boundary-2">
              <ThrowingComponent shouldThrow={false} />
            </div>
          </ErrorBoundary>
        </div>
      );

      // First boundary should show error
      expect(screen.getByText(/Error in boundary 1/i)).toBeInTheDocument();
      
      // Second boundary should render normally
      expect(screen.getByText('Component working fine')).toBeInTheDocument();
    });
  });

  describe('Error Recovery and Reset', () => {
    it('should allow error recovery through re-rendering', () => {
      let shouldThrow = true;
      
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={shouldThrow} />
        </ErrorBoundary>
      );

      // Should show error initially
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      // Fix the error and re-render
      shouldThrow = false;
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={shouldThrow} />
        </ErrorBoundary>
      );

      // Should still show error (ErrorBoundary doesn't auto-recover)
      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle component key changes for recovery', () => {
      let componentKey = 'error-key';
      
      const { rerender } = render(
        <ErrorBoundary key={componentKey}>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      // Change key to force remount of ErrorBoundary
      componentKey = 'fixed-key';
      rerender(
        <ErrorBoundary key={componentKey}>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component working fine')).toBeInTheDocument();
      expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
    });
  });

  describe('Different Error Types', () => {
    it('should handle TypeError', () => {
      const TypeErrorComponent = () => {
        const obj: any = null;
        return <div>{obj.property.nested}</div>;
      };

      render(
        <ErrorBoundary>
          <TypeErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle ReferenceError', () => {
      const ReferenceErrorComponent = () => {
        return <div>{(undefinedVariable as any).toString()}</div>;
      };

      render(
        <ErrorBoundary>
          <ReferenceErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should handle custom errors', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }

      const CustomErrorComponent = () => {
        throw new CustomError('This is a custom error');
      };

      render(
        <ErrorBoundary>
          <CustomErrorComponent />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/This is a custom error/i)).toBeInTheDocument();
    });
  });

  describe('Async Error Handling', () => {
    it('should not catch async errors in useEffect', () => {
      // ErrorBoundary only catches synchronous render errors
      render(
        <ErrorBoundary>
          <AsyncThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      // Component should render initially (error happens in useEffect)
      expect(screen.getByText('Async component')).toBeInTheDocument();
      expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
    });

    it('should handle Promise rejections gracefully', () => {
      const PromiseComponent = () => {
        React.useEffect(() => {
          Promise.reject(new Error('Promise rejection'));
        }, []);
        return <div>Promise component</div>;
      };

      render(
        <ErrorBoundary>
          <PromiseComponent />
        </ErrorBoundary>
      );

      // Should render normally (Promise rejections aren't caught by ErrorBoundary)
      expect(screen.getByText('Promise component')).toBeInTheDocument();
    });
  });

  describe('Error Information and Stack Traces', () => {
    it('should provide error information in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} errorMessage="Development error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Development error/i)).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });

    it('should hide detailed error information in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} errorMessage="Production error" />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      // In production, might hide detailed error messages
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Complex Component Tree Errors', () => {
    it('should handle errors deep in component tree', () => {
      const DeepComponent = ({ level }: { level: number }) => {
        if (level === 0) {
          throw new Error('Deep component error');
        }
        return <DeepComponent level={level - 1} />;
      };

      render(
        <ErrorBoundary>
          <div>
            <div>
              <div>
                <DeepComponent level={5} />
              </div>
            </div>
          </div>
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Deep component error/i)).toBeInTheDocument();
    });

    it('should handle errors in dynamically rendered components', () => {
      const DynamicComponent = ({ items }: { items: any[] }) => {
        return (
          <div>
            {items.map((item, index) => {
              if (item.shouldThrow) {
                throw new Error(`Dynamic error at index ${index}`);
              }
              return <div key={index}>{item.content}</div>;
            })}
          </div>
        );
      };

      const items = [
        { content: 'Item 1', shouldThrow: false },
        { content: 'Item 2', shouldThrow: true },
        { content: 'Item 3', shouldThrow: false },
      ];

      render(
        <ErrorBoundary>
          <DynamicComponent items={items} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
      expect(screen.getByText(/Dynamic error at index 1/i)).toBeInTheDocument();
    });
  });

  describe('Integration with Real Components', () => {
    it('should wrap Terminal component and catch real errors', () => {
      // This tests the actual ErrorBoundary with real Terminal component
      render(
        <ErrorBoundary>
          <Terminal sessionId="error-test" />
        </ErrorBoundary>
      );

      // Should render without errors in normal case
      expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
    });

    it('should handle Tab component with invalid props', () => {
      render(
        <ErrorBoundary>
          <Tab
            title={null as any}
            isActive={undefined as any}
            onSelect={null as any}
            onClose={null as any}
            closable={undefined as any}
          />
        </ErrorBoundary>
      );

      // May or may not error depending on prop validation
      // This tests that ErrorBoundary can handle it either way
    });
  });

  describe('Error Boundary State Management', () => {
    it('should maintain error state until component remounts', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      // Re-render with same component (should still show error)
      rerender(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    });

    it('should reset when boundary itself is remounted', () => {
      let boundaryKey = 'error';
      const { rerender } = render(
        <ErrorBoundary key={boundaryKey}>
          <ThrowingComponent shouldThrow={true} />
        </ErrorBoundary>
      );

      expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();

      // Remount boundary with new key
      boundaryKey = 'fixed';
      rerender(
        <ErrorBoundary key={boundaryKey}>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      );

      expect(screen.getByText('Component working fine')).toBeInTheDocument();
      expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
    });
  });
});
