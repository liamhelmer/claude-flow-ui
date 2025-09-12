/**
 * Error Boundary and Edge Case Testing Patterns
 * Comprehensive testing for error handling, edge cases, and resilience
 */

import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders, TestErrorBoundary } from '../utils/test-utils';

// Import components for error testing
import TabList from '@/components/tabs/TabList';
import Terminal from '@/components/terminal/Terminal';
import Sidebar from '@/components/sidebar/Sidebar';

// Error simulation utilities
const createErrorComponent = (errorType: 'render' | 'effect' | 'event' | 'async') => {
  return React.memo(({ shouldError = false }: { shouldError?: boolean }) => {
    const [hasError, setHasError] = React.useState(false);

    React.useEffect(() => {
      if (shouldError && errorType === 'effect') {
        throw new Error('Effect error');
      }
    }, [shouldError]);

    const handleClick = () => {
      if (shouldError && errorType === 'event') {
        throw new Error('Event handler error');
      }
    };

    const handleAsync = async () => {
      if (shouldError && errorType === 'async') {
        return Promise.reject(new Error('Async operation error'));
      }
    };

    React.useEffect(() => {
      if (shouldError && errorType === 'async') {
        handleAsync().catch(() => setHasError(true));
      }
    }, [shouldError]);

    if (shouldError && errorType === 'render') {
      throw new Error('Render error');
    }

    if (hasError) {
      return <div>Async error occurred</div>;
    }

    return (
      <div>
        <span>Error Test Component</span>
        <button onClick={handleClick}>Trigger Event Error</button>
      </div>
    );
  });
};

describe('Error Boundary and Edge Case Testing', () => {
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.useFakeTimers();
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  describe('Component Error Boundaries', () => {
    describe('Render Error Handling', () => {
      it('should catch render errors in TabList component', () => {
        const ErrorTabList = () => {
          throw new Error('TabList render error');
        };

        const onError = jest.fn();

        render(
          <TestErrorBoundary onError={onError}>
            <ErrorTabList />
          </TestErrorBoundary>
        );

        expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
        expect(onError).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should catch render errors in Terminal component', () => {
        const ErrorTerminal = () => {
          throw new Error('Terminal render error');
        };

        const onError = jest.fn();

        render(
          <TestErrorBoundary onError={onError}>
            <ErrorTerminal />
          </TestErrorBoundary>
        );

        expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
        expect(onError).toHaveBeenCalledWith(
          expect.objectContaining({ message: 'Terminal render error' })
        );
      });

      it('should isolate errors to specific components', () => {
        const StableComponent = () => <div>I should still render</div>;
        const ErrorComponent = createErrorComponent('render');

        render(
          <div>
            <StableComponent />
            <TestErrorBoundary>
              <ErrorComponent shouldError={true} />
            </TestErrorBoundary>
          </div>
        );

        expect(screen.getByText('I should still render')).toBeInTheDocument();
        expect(screen.getByTestId('error-boundary')).toBeInTheDocument();
      });
    });

    describe('Effect Error Handling', () => {
      it('should handle useEffect errors gracefully', async () => {
        const ErrorComponent = createErrorComponent('effect');
        const onError = jest.fn();

        render(
          <TestErrorBoundary onError={onError}>
            <ErrorComponent shouldError={true} />
          </TestErrorBoundary>
        );

        // Effect errors are caught by error boundaries in React 18+
        await waitFor(() => {
          expect(onError).toHaveBeenCalled();
        });
      });

      it('should handle cleanup function errors', () => {
        const CleanupErrorComponent = () => {
          React.useEffect(() => {
            return () => {
              throw new Error('Cleanup error');
            };
          }, []);

          return <div>Component with cleanup error</div>;
        };

        const { unmount } = render(
          <TestErrorBoundary>
            <CleanupErrorComponent />
          </TestErrorBoundary>
        );

        // Should not crash when unmounting
        expect(() => unmount()).not.toThrow();
      });
    });

    describe('Event Handler Error Handling', () => {
      it('should handle click event errors', async () => {
        const user = userEvent.setup();
        const ErrorComponent = createErrorComponent('event');

        render(
          <TestErrorBoundary>
            <ErrorComponent shouldError={true} />
          </TestErrorBoundary>
        );

        const button = screen.getByText('Trigger Event Error');
        
        // Event handler errors don't trigger error boundaries by default
        // They should be caught and handled locally
        await expect(user.click(button)).resolves.not.toThrow();
      });

      it('should handle form submission errors', async () => {
        const user = userEvent.setup();
        
        const FormWithError = () => {
          const handleSubmit = (e: React.FormEvent) => {
            e.preventDefault();
            throw new Error('Form submission error');
          };

          return (
            <form onSubmit={handleSubmit}>
              <button type="submit">Submit</button>
            </form>
          );
        };

        render(
          <TestErrorBoundary>
            <FormWithError />
          </TestErrorBoundary>
        );

        const submitButton = screen.getByText('Submit');
        
        // Form submission errors should be handled gracefully
        await expect(user.click(submitButton)).resolves.not.toThrow();
      });
    });

    describe('Async Error Handling', () => {
      it('should handle Promise rejection errors', async () => {
        const AsyncErrorComponent = () => {
          const [error, setError] = React.useState<string | null>(null);

          const handleAsyncOperation = async () => {
            try {
              await Promise.reject(new Error('Async operation failed'));
            } catch (err) {
              setError((err as Error).message);
            }
          };

          React.useEffect(() => {
            handleAsyncOperation();
          }, []);

          if (error) {
            return <div>Error: {error}</div>;
          }

          return <div>Loading...</div>;
        };

        render(<AsyncErrorComponent />);

        await waitFor(() => {
          expect(screen.getByText('Error: Async operation failed')).toBeInTheDocument();
        });
      });

      it('should handle fetch errors', async () => {
        const fetchSpy = jest.spyOn(global, 'fetch').mockRejectedValue(
          new Error('Network error')
        );

        const FetchComponent = () => {
          const [data, setData] = React.useState<string | null>(null);
          const [error, setError] = React.useState<string | null>(null);

          React.useEffect(() => {
            fetch('/api/data')
              .then(response => response.json())
              .then(setData)
              .catch(err => setError(err.message));
          }, []);

          if (error) return <div>Fetch error: {error}</div>;
          if (!data) return <div>Loading...</div>;
          return <div>Data: {data}</div>;
        };

        render(<FetchComponent />);

        await waitFor(() => {
          expect(screen.getByText('Fetch error: Network error')).toBeInTheDocument();
        });

        fetchSpy.mockRestore();
      });
    });
  });

  describe('Edge Case Data Handling', () => {
    describe('Null and Undefined Props', () => {
      it('should handle null tab data gracefully', () => {
        expect(() => {
          render(
            <TabList
              tabs={null as any}
              activeTab=""
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
          );
        }).not.toThrow();
      });

      it('should handle undefined session ID', () => {
        expect(() => {
          render(<Terminal sessionId={undefined as any} />);
        }).not.toThrow();
      });

      it('should handle null callback functions', () => {
        const tabs = [{ id: 'tab-1', title: 'Test Tab', content: 'Test' }];

        expect(() => {
          render(
            <TabList
              tabs={tabs}
              activeTab="tab-1"
              onTabSelect={null as any}
              onTabClose={null as any}
            />
          );
        }).not.toThrow();
      });
    });

    describe('Empty and Invalid Data', () => {
      it('should handle empty arrays gracefully', () => {
        render(
          <TabList
            tabs={[]}
            activeTab=""
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        // Should render without errors
        expect(screen.getByRole('tablist')).toBeInTheDocument();
      });

      it('should handle malformed tab data', () => {
        const malformedTabs = [
          { id: '', title: '', content: '' }, // Empty strings
          { id: 'tab-2' }, // Missing properties
          { id: 'tab-3', title: 'Tab 3', content: null }, // Null content
          null, // Null item
          undefined, // Undefined item
        ];

        expect(() => {
          render(
            <TabList
              tabs={malformedTabs as any}
              activeTab="tab-2"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
          );
        }).not.toThrow();
      });

      it('should handle extremely long strings', () => {
        const veryLongTitle = 'x'.repeat(10000);
        const tabs = [{ id: 'tab-1', title: veryLongTitle, content: 'Test' }];

        expect(() => {
          render(
            <TabList
              tabs={tabs}
              activeTab="tab-1"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
          );
        }).not.toThrow();
      });

      it('should handle special characters and unicode', () => {
        const specialChars = '💻🚀🔥 Special "quotes" & <tags> 中文 العربية 🎉';
        const tabs = [{ id: 'tab-1', title: specialChars, content: specialChars }];

        render(
          <TabList
            tabs={tabs}
            activeTab="tab-1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        expect(screen.getByText(specialChars)).toBeInTheDocument();
      });
    });

    describe('Extreme Values and Boundaries', () => {
      it('should handle very large numbers of tabs', () => {
        const hugeTabs = Array.from({ length: 10000 }, (_, i) => ({
          id: `tab-${i}`,
          title: `Tab ${i}`,
          content: `Content ${i}`,
        }));

        const renderTime = performance.now();
        
        render(
          <TabList
            tabs={hugeTabs}
            activeTab="tab-0"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        const endTime = performance.now();
        
        // Should render within reasonable time (5 seconds max)
        expect(endTime - renderTime).toBeLessThan(5000);
      });

      it('should handle rapid state changes', () => {
        const { mockStore } = renderWithProviders(<Sidebar />);

        // Perform many rapid state changes
        for (let i = 0; i < 1000; i++) {
          mockStore.addAgent({ id: `agent-${i}`, name: `Agent ${i}` });
          mockStore.setLoading(i % 2 === 0);
          mockStore.setError(i % 3 === 0 ? 'Error' : null);
        }

        // Should handle rapid changes without crashing
        expect(mockStore.getState().agents).toHaveLength(1000);
      });

      it('should handle negative array indices gracefully', () => {
        const tabs = [
          { id: 'tab-1', title: 'Tab 1', content: 'Content 1' },
          { id: 'tab-2', title: 'Tab 2', content: 'Content 2' },
        ];

        // Try to access tab with negative index
        expect(() => {
          render(
            <TabList
              tabs={tabs}
              activeTab="tab--1" // Negative-like ID
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
          );
        }).not.toThrow();
      });
    });
  });

  describe('Memory and Resource Edge Cases', () => {
    describe('Memory Pressure Scenarios', () => {
      it('should handle memory pressure gracefully', () => {
        // Simulate memory pressure by creating many large objects
        const largeObjects = Array.from({ length: 1000 }, () => ({
          data: new Array(10000).fill('x').join(''),
          timestamp: Date.now(),
        }));

        expect(() => {
          render(
            <div>
              {largeObjects.slice(0, 10).map((obj, i) => (
                <div key={i}>{obj.data.slice(0, 100)}</div>
              ))}
            </div>
          );
        }).not.toThrow();
      });

      it('should cleanup resources on unmount', () => {
        const cleanupSpies: jest.SpyInstance[] = [];

        const ResourceComponent = () => {
          React.useEffect(() => {
            const interval = setInterval(() => {}, 1000);
            const timeout = setTimeout(() => {}, 5000);

            const cleanupInterval = jest.fn(() => clearInterval(interval));
            const cleanupTimeout = jest.fn(() => clearTimeout(timeout));

            cleanupSpies.push(cleanupInterval, cleanupTimeout);

            return () => {
              cleanupInterval();
              cleanupTimeout();
            };
          }, []);

          return <div>Resource Component</div>;
        };

        const { unmount } = render(<ResourceComponent />);
        unmount();

        // All cleanup functions should have been called
        cleanupSpies.forEach(spy => {
          expect(spy).toHaveBeenCalled();
        });
      });
    });

    describe('Race Condition Handling', () => {
      it('should handle concurrent state updates', async () => {
        const RaceConditionComponent = () => {
          const [count, setCount] = React.useState(0);

          const incrementAsync = async (delay: number) => {
            await new Promise(resolve => setTimeout(resolve, delay));
            setCount(prev => prev + 1);
          };

          React.useEffect(() => {
            // Trigger multiple concurrent updates
            incrementAsync(10);
            incrementAsync(20);
            incrementAsync(30);
          }, []);

          return <div>Count: {count}</div>;
        };

        render(<RaceConditionComponent />);

        act(() => {
          jest.advanceTimersByTime(50);
        });

        await waitFor(() => {
          expect(screen.getByText('Count: 3')).toBeInTheDocument();
        });
      });

      it('should handle rapid component remounting', () => {
        const RemountComponent = ({ key }: { key: string }) => {
          React.useEffect(() => {
            // Simulate some initialization
            return () => {
              // Cleanup
            };
          }, []);

          return <div>Component {key}</div>;
        };

        const { rerender } = render(<RemountComponent key="1" />);

        // Rapidly remount component
        for (let i = 2; i <= 100; i++) {
          rerender(<RemountComponent key={i.toString()} />);
        }

        expect(screen.getByText('Component 100')).toBeInTheDocument();
      });
    });
  });

  describe('Network and Connectivity Edge Cases', () => {
    describe('WebSocket Connection Issues', () => {
      it('should handle WebSocket connection timeouts', async () => {
        const { mockWs } = renderWithProviders(
          <Terminal sessionId="test-session" />,
          {
            wsConfig: {
              autoConnect: false,
              simulateLatency: 10000, // Very long delay
            },
          }
        );

        // Connection should timeout gracefully
        jest.advanceTimersByTime(5000);

        await waitFor(() => {
          expect(mockWs.readyState).toBe(mockWs.constructor.CONNECTING);
        });

        // Should not crash the component
        expect(screen.getByTestId('test-wrapper')).toBeInTheDocument();
      });

      it('should handle malformed WebSocket messages', () => {
        const { mockWs } = renderWithProviders(
          <Terminal sessionId="test-session" />
        );

        expect(() => {
          mockWs.simulateMessage('invalid json string');
          mockWs.simulateMessage({ invalidProperty: true });
          mockWs.simulateMessage(null);
          mockWs.simulateMessage(undefined);
        }).not.toThrow();
      });

      it('should handle WebSocket message flooding', () => {
        const { mockWs } = renderWithProviders(
          <Terminal sessionId="test-session" />
        );

        // Send many messages rapidly
        for (let i = 0; i < 10000; i++) {
          mockWs.simulateMessage({
            type: 'flood-test',
            data: `Message ${i}`,
          });
        }

        // Should handle flood without crashing
        expect(mockWs.getMessageQueue()).toHaveLength(10000);
      });
    });
  });

  describe('Browser Environment Edge Cases', () => {
    describe('Missing APIs', () => {
      it('should handle missing WebSocket API', () => {
        const originalWebSocket = global.WebSocket;
        delete (global as any).WebSocket;

        expect(() => {
          renderWithProviders(<Terminal sessionId="test-session" />);
        }).not.toThrow();

        global.WebSocket = originalWebSocket;
      });

      it('should handle missing ResizeObserver', () => {
        const originalResizeObserver = global.ResizeObserver;
        delete (global as any).ResizeObserver;

        expect(() => {
          render(<Terminal sessionId="test-session" />);
        }).not.toThrow();

        global.ResizeObserver = originalResizeObserver;
      });

      it('should handle missing performance API', () => {
        const originalPerformance = global.performance;
        delete (global as any).performance;

        expect(() => {
          render(<Terminal sessionId="test-session" />);
        }).not.toThrow();

        global.performance = originalPerformance;
      });
    });

    describe('Viewport and Accessibility Edge Cases', () => {
      it('should handle very small viewport sizes', () => {
        // Mock very small viewport
        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: 100,
        });
        Object.defineProperty(window, 'innerHeight', {
          writable: true,
          configurable: true,
          value: 100,
        });

        expect(() => {
          render(<Terminal sessionId="test-session" />);
        }).not.toThrow();
      });

      it('should handle accessibility tools', () => {
        // Mock screen reader detection
        Object.defineProperty(navigator, 'userAgent', {
          writable: true,
          value: 'NVDA screen reader',
        });

        render(<Terminal sessionId="test-session" />);

        // Component should render with accessibility considerations
        expect(screen.getByTestId('test-wrapper')).toBeInTheDocument();
      });
    });
  });
});