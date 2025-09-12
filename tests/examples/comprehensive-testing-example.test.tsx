/**
 * Comprehensive Testing Example
 * Demonstrates usage of all testing frameworks and utilities
 */
import React from 'react';
import { renderWithProviders } from '../test-utils-enhanced';
import { testAccessibility, createA11yTestSuite } from '../accessibility/a11y-testing';
import { createPerformanceTestSuite, benchmarkComponent } from '../performance/performance-testing';
import { createVisualTestSuite, captureSnapshot } from '../visual/visual-regression';
import { createE2ETestSuite, TerminalE2EWorkflows } from '../e2e/e2e-workflows';
import { testComponentInteraction, TerminalIntegrationPatterns } from '../integration/integration-testing';

// Example component for demonstration
const ExampleTerminalComponent: React.FC<{
  sessionId?: string;
  isActive?: boolean;
  hasError?: boolean;
  theme?: 'light' | 'dark';
}> = ({ 
  sessionId = 'example-session', 
  isActive = true, 
  hasError = false,
  theme = 'light'
}) => {
  const [output, setOutput] = React.useState<string[]>([]);
  const [connectionState, setConnectionState] = React.useState<'connected' | 'disconnected' | 'error'>('connected');

  React.useEffect(() => {
    if (hasError) {
      setConnectionState('error');
    }
  }, [hasError]);

  const handleCommand = (command: string) => {
    setOutput(prev => [...prev, `$ ${command}`, `Output for: ${command}`]);
  };

  if (hasError) {
    throw new Error('Example terminal error');
  }

  return (
    <div 
      data-testid="example-terminal"
      data-session-id={sessionId}
      data-connection-state={connectionState}
      className={`terminal-container theme-${theme} ${isActive ? 'active' : 'inactive'}`}
      role="application"
      aria-label={`Terminal session ${sessionId}`}
    >
      <div className="terminal-header">
        <h2>Terminal - {sessionId}</h2>
        <div className="connection-status" aria-live="polite">
          Status: {connectionState}
        </div>
        <button 
          aria-label={`Close terminal ${sessionId}`}
          onClick={() => {/* close logic */}}
        >
          ×
        </button>
      </div>
      
      <div 
        className="terminal-output" 
        data-testid="terminal-output"
        role="log"
        aria-live="polite"
      >
        {output.map((line, index) => (
          <div key={index} className="output-line">
            {line}
          </div>
        ))}
      </div>
      
      <div className="terminal-input">
        <input
          type="text"
          placeholder="Enter command..."
          aria-label="Terminal command input"
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleCommand(e.currentTarget.value);
              e.currentTarget.value = '';
            }
          }}
        />
      </div>
    </div>
  );
};

// Example Error Boundary for testing
const ExampleErrorBoundary: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [hasError, setHasError] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    const handleError = (error: Error) => {
      setHasError(true);
      setError(error);
    };

    const errorHandler = (event: ErrorEvent) => {
      handleError(new Error(event.message));
    };

    window.addEventListener('error', errorHandler);
    return () => window.removeEventListener('error', errorHandler);
  }, []);

  if (hasError) {
    return (
      <div role="alert" aria-live="polite" data-testid="error-boundary">
        <h2>Something went wrong</h2>
        <p>{error?.message}</p>
        <button onClick={() => { setHasError(false); setError(null); }}>
          Retry
        </button>
      </div>
    );
  }

  return <>{children}</>;
};

describe('Comprehensive Testing Example', () => {
  // Basic rendering and functionality tests
  describe('Basic Component Tests', () => {
    it('should render terminal component correctly', async () => {
      const { container, user, a11yResults } = await renderWithProviders(
        <ExampleTerminalComponent sessionId="test-123" />
      );

      // Basic assertions
      expect(container.querySelector('[data-testid="example-terminal"]')).toBeInTheDocument();
      expect(container.querySelector('[data-session-id="test-123"]')).toBeInTheDocument();
      
      // Accessibility check
      if (a11yResults) {
        expect(a11yResults).toHaveNoViolations();
      }
    });

    it('should handle user interactions correctly', async () => {
      const { container, user } = await renderWithProviders(
        <ExampleTerminalComponent />
      );

      const input = container.querySelector('input') as HTMLInputElement;
      const output = container.querySelector('[data-testid="terminal-output"]');

      // Type command and press Enter
      await user.type(input, 'echo hello');
      await user.keyboard('{Enter}');

      // Verify output
      expect(output).toHaveTextContent('$ echo hello');
      expect(output).toHaveTextContent('Output for: echo hello');
    });

    it('should handle different states correctly', async () => {
      const states = [
        { name: 'active', props: { isActive: true } },
        { name: 'inactive', props: { isActive: false } },
        { name: 'light-theme', props: { theme: 'light' } },
        { name: 'dark-theme', props: { theme: 'dark' } }
      ];

      for (const state of states) {
        const { container } = await renderWithProviders(
          <ExampleTerminalComponent {...state.props} />
        );

        expect(container.querySelector('[data-testid="example-terminal"]')).toBeInTheDocument();
        
        if (state.props.isActive !== undefined) {
          const expectedClass = state.props.isActive ? 'active' : 'inactive';
          expect(container.querySelector(`.${expectedClass}`)).toBeInTheDocument();
        }

        if (state.props.theme) {
          expect(container.querySelector(`.theme-${state.props.theme}`)).toBeInTheDocument();
        }
      }
    });
  });

  // Accessibility testing suite
  createA11yTestSuite(
    'ExampleTerminalComponent',
    <ExampleTerminalComponent />,
    {
      customTests: [
        async () => {
          const { container } = await renderWithProviders(
            <ExampleTerminalComponent />
          );
          
          // Custom accessibility test: Check for proper ARIA roles
          const terminal = container.querySelector('[role="application"]');
          expect(terminal).toBeInTheDocument();
          
          const output = container.querySelector('[role="log"]');
          expect(output).toBeInTheDocument();
          
          const status = container.querySelector('[aria-live="polite"]');
          expect(status).toBeInTheDocument();
        }
      ]
    }
  );

  // Performance testing suite
  createPerformanceTestSuite(
    'ExampleTerminalComponent',
    <ExampleTerminalComponent />,
    {
      thresholds: {
        maxRenderTime: 50, // 50ms
        maxMemoryUsage: 512 * 1024, // 512KB
        maxReRenderTime: 25 // 25ms
      },
      loadTestFactory: (size) => (
        <ExampleTerminalComponent sessionId={`session-${size}`} />
      )
    }
  );

  // Visual regression testing suite
  createVisualTestSuite(
    'ExampleTerminalComponent',
    <ExampleTerminalComponent />,
    {
      states: [
        { name: 'default', props: {} },
        { name: 'active', props: { isActive: true } },
        { name: 'inactive', props: { isActive: false } }
      ],
      themes: ['light', 'dark'],
      breakpoints: [
        { name: 'mobile', width: 375, height: 667 },
        { name: 'desktop', width: 1440, height: 900 }
      ],
      interactions: [
        {
          name: 'focus-input',
          action: async (container) => {
            const input = container.querySelector('input') as HTMLElement;
            input.focus();
          }
        },
        {
          name: 'hover-close-button',
          action: async (container) => {
            const closeBtn = container.querySelector('button') as HTMLElement;
            closeBtn.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
          }
        }
      ]
    }
  );

  // Integration testing
  describe('Integration Tests', () => {
    it('should handle terminal and error boundary integration', async () => {
      await testComponentInteraction({
        name: 'Terminal with Error Boundary',
        components: [
          <ExampleErrorBoundary>
            <ExampleTerminalComponent hasError={false} />
          </ExampleErrorBoundary>
        ],
        workflow: [
          {
            name: 'Initial render without error',
            action: async (ctx) => {
              // Component should render normally
            },
            validation: async (ctx) => {
              expect(ctx.container.querySelector('[data-testid="example-terminal"]')).toBeInTheDocument();
              expect(ctx.container.querySelector('[data-testid="error-boundary"]')).not.toBeInTheDocument();
            }
          },
          {
            name: 'Trigger error in component',
            action: async (ctx) => {
              // This would typically involve triggering an error
              // For this example, we'll simulate it by throwing an error
              const errorEvent = new ErrorEvent('error', {
                message: 'Simulated terminal error',
                error: new Error('Simulated terminal error')
              });
              window.dispatchEvent(errorEvent);
            },
            validation: async (ctx) => {
              await ctx.waitFor(() => {
                expect(ctx.container.querySelector('[data-testid="error-boundary"]')).toBeInTheDocument();
              });
            }
          },
          {
            name: 'Retry after error',
            action: async (ctx) => {
              const retryButton = ctx.container.querySelector('button') as HTMLElement;
              await ctx.user.click(retryButton);
            },
            validation: async (ctx) => {
              expect(ctx.container.querySelector('[data-testid="error-boundary"]')).not.toBeInTheDocument();
            }
          }
        ]
      });
    });

    it('should handle multiple terminal sessions', async () => {
      const multiTerminalApp = (
        <div data-testid="multi-terminal-app">
          <ExampleTerminalComponent sessionId="session-1" />
          <ExampleTerminalComponent sessionId="session-2" />
        </div>
      );

      await testComponentInteraction({
        name: 'Multi-Terminal Session Management',
        components: [multiTerminalApp],
        workflow: [
          {
            name: 'Both terminals render',
            action: async () => {},
            validation: async (ctx) => {
              const terminals = ctx.container.querySelectorAll('[data-testid="example-terminal"]');
              expect(terminals).toHaveLength(2);
            }
          },
          {
            name: 'Interact with first terminal',
            action: async (ctx) => {
              const firstTerminal = ctx.container.querySelector('[data-session-id="session-1"]');
              const input = firstTerminal?.querySelector('input') as HTMLInputElement;
              await ctx.user.type(input, 'command for session 1');
              await ctx.user.keyboard('{Enter}');
            },
            validation: async (ctx) => {
              const firstTerminal = ctx.container.querySelector('[data-session-id="session-1"]');
              expect(firstTerminal).toHaveTextContent('command for session 1');
            }
          },
          {
            name: 'Interact with second terminal',
            action: async (ctx) => {
              const secondTerminal = ctx.container.querySelector('[data-session-id="session-2"]');
              const input = secondTerminal?.querySelector('input') as HTMLInputElement;
              await ctx.user.type(input, 'command for session 2');
              await ctx.user.keyboard('{Enter}');
            },
            validation: async (ctx) => {
              const secondTerminal = ctx.container.querySelector('[data-session-id="session-2"]');
              expect(secondTerminal).toHaveTextContent('command for session 2');
            }
          }
        ]
      });
    });
  });

  // End-to-end testing suite
  createE2ETestSuite('Example Terminal E2E', [
    {
      name: 'Complete Terminal Workflow',
      description: 'Test the entire terminal user workflow',
      component: (
        <div data-testid="terminal-app">
          <ExampleTerminalComponent />
        </div>
      ),
      steps: [
        {
          name: 'Application loads',
          action: async () => {},
          validation: async (ctx) => {
            expect(ctx.container.querySelector('[data-testid="terminal-app"]')).toBeInTheDocument();
          }
        },
        {
          name: 'Execute terminal command',
          action: async (ctx) => {
            const input = ctx.container.querySelector('input') as HTMLInputElement;
            await ctx.user.type(input, 'ls -la');
            await ctx.user.keyboard('{Enter}');
          },
          validation: async (ctx) => {
            await ctx.waitFor(() => {
              expect(ctx.container).toHaveTextContent('$ ls -la');
            });
          }
        },
        {
          name: 'Verify output appears',
          action: async () => {},
          validation: async (ctx) => {
            expect(ctx.container).toHaveTextContent('Output for: ls -la');
          }
        }
      ]
    }
  ]);

  // Advanced testing scenarios
  describe('Advanced Testing Scenarios', () => {
    it('should handle stress testing with rapid interactions', async () => {
      const { container, user } = await renderWithProviders(
        <ExampleTerminalComponent />
      );

      const input = container.querySelector('input') as HTMLInputElement;
      
      // Rapid fire commands
      for (let i = 0; i < 10; i++) {
        await user.type(input, `command-${i}`);
        await user.keyboard('{Enter}');
      }

      // Verify all commands were processed
      const output = container.querySelector('[data-testid="terminal-output"]');
      for (let i = 0; i < 10; i++) {
        expect(output).toHaveTextContent(`command-${i}`);
      }
    });

    it('should maintain performance under load', async () => {
      const result = await benchmarkComponent(
        <ExampleTerminalComponent />,
        {
          maxRenderTime: 100,
          maxMemoryUsage: 1024 * 1024 // 1MB
        }
      );

      expect(result.passed).toBe(true);
      
      if (!result.passed) {
        console.error('Performance benchmark failed:', result.failures);
      }
    });

    it('should capture visual snapshots for comparison', async () => {
      const snapshot = await captureSnapshot(
        <ExampleTerminalComponent theme="dark" isActive={true} />,
        {
          name: 'terminal-dark-active',
          viewport: { width: 1024, height: 768 }
        }
      );

      expect(snapshot.name).toBe('terminal-dark-active');
      expect(snapshot.html).toBeTruthy();
      expect(snapshot.styles).toBeTruthy();
      expect(snapshot.viewport).toEqual({ width: 1024, height: 768 });
    });

    it('should test accessibility across different themes', async () => {
      const themes = ['light', 'dark'];
      
      for (const theme of themes) {
        await testAccessibility(
          <ExampleTerminalComponent theme={theme as 'light' | 'dark'} />
        );
      }
    });

    it('should handle edge cases gracefully', async () => {
      // Test with unusual props
      const edgeCases = [
        { sessionId: '', isActive: true },
        { sessionId: 'very-long-session-id-that-might-cause-issues-with-rendering', isActive: false },
        { sessionId: 'session with spaces and special chars !@#$%', isActive: true }
      ];

      for (const props of edgeCases) {
        const { container } = await renderWithProviders(
          <ExampleTerminalComponent {...props} />
        );

        expect(container.querySelector('[data-testid="example-terminal"]')).toBeInTheDocument();
      }
    });
  });

  // Cross-browser compatibility testing (mock)
  describe('Cross-Browser Compatibility', () => {
    const browsers = [
      { name: 'Chrome', userAgent: 'Chrome/91.0.4472.124' },
      { name: 'Firefox', userAgent: 'Firefox/89.0' },
      { name: 'Safari', userAgent: 'Safari/14.1.1' }
    ];

    browsers.forEach(browser => {
      it(`should work correctly in ${browser.name}`, async () => {
        // Mock user agent
        Object.defineProperty(navigator, 'userAgent', {
          writable: true,
          value: browser.userAgent
        });

        const { container } = await renderWithProviders(
          <ExampleTerminalComponent />
        );

        expect(container.querySelector('[data-testid="example-terminal"]')).toBeInTheDocument();
      });
    });
  });
});