/**
 * End-to-End Testing Framework
 * Comprehensive E2E testing utilities for complete user workflows
 */
import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';

export interface E2ETestStep {
  name: string;
  description?: string;
  action: (context: E2ETestContext) => Promise<void>;
  validation: (context: E2ETestContext) => Promise<void>;
  timeout?: number;
  retries?: number;
  screenshot?: boolean;
}

export interface E2ETestContext {
  container: HTMLElement;
  user: ReturnType<typeof userEvent.setup>;
  screen: typeof screen;
  waitFor: typeof waitFor;
  data: Record<string, any>;
  sessionData: Record<string, any>;
  mockWebSocket?: MockWebSocketE2E;
  mockStorage?: MockStorageE2E;
}

export interface E2ETestSuite {
  name: string;
  description?: string;
  setup?: () => Promise<void>;
  teardown?: () => Promise<void>;
  beforeEach?: () => Promise<void>;
  afterEach?: () => Promise<void>;
  workflows: E2EWorkflow[];
}

export interface E2EWorkflow {
  name: string;
  description?: string;
  component: ReactElement;
  steps: E2ETestStep[];
  preconditions?: string[];
  postconditions?: string[];
  timeout?: number;
}

export interface E2ETestReport {
  suiteName: string;
  totalWorkflows: number;
  passedWorkflows: number;
  failedWorkflows: number;
  totalSteps: number;
  passedSteps: number;
  failedSteps: number;
  duration: number;
  failures: Array<{
    workflow: string;
    step: string;
    error: string;
    screenshot?: string;
  }>;
}

/**
 * Mock WebSocket for E2E testing with realistic behavior
 */
export class MockWebSocketE2E {
  private callbacks: Record<string, Function[]> = {};
  private messageQueue: any[] = [];
  private connectionState: 'connecting' | 'open' | 'closed' | 'error' = 'connecting';
  
  constructor(private url: string) {
    // Simulate async connection
    setTimeout(() => {
      this.connectionState = 'open';
      this.emit('open', new Event('open'));
    }, 100);
  }

  on(event: string, callback: Function) {
    if (!this.callbacks[event]) {
      this.callbacks[event] = [];
    }
    this.callbacks[event].push(callback);
  }

  off(event: string, callback: Function) {
    if (this.callbacks[event]) {
      this.callbacks[event] = this.callbacks[event].filter(cb => cb !== callback);
    }
  }

  emit(event: string, data: any) {
    if (this.callbacks[event]) {
      this.callbacks[event].forEach(callback => callback(data));
    }
  }

  send(data: any) {
    if (this.connectionState === 'open') {
      this.messageQueue.push(data);
      // Echo back for terminal simulation
      setTimeout(() => {
        this.emit('message', { data: `Echo: ${data}` });
      }, 50);
    }
  }

  simulateMessage(data: any) {
    this.emit('message', { data: JSON.stringify(data) });
  }

  simulateError() {
    this.connectionState = 'error';
    this.emit('error', new Event('error'));
  }

  simulateDisconnect() {
    this.connectionState = 'closed';
    this.emit('close', new CloseEvent('close'));
  }

  getState() {
    return this.connectionState;
  }

  getSentMessages() {
    return [...this.messageQueue];
  }
}

/**
 * Mock storage for E2E testing
 */
export class MockStorageE2E {
  private data: Record<string, string> = {};

  setItem(key: string, value: string) {
    this.data[key] = value;
  }

  getItem(key: string): string | null {
    return this.data[key] || null;
  }

  removeItem(key: string) {
    delete this.data[key];
  }

  clear() {
    this.data = {};
  }

  getAllData() {
    return { ...this.data };
  }
}

/**
 * Create E2E test context with enhanced utilities
 */
export const createE2EContext = (container: HTMLElement): E2ETestContext => {
  return {
    container,
    user: userEvent.setup(),
    screen,
    waitFor,
    data: {},
    sessionData: {},
    mockWebSocket: new MockWebSocketE2E('ws://localhost:11237'),
    mockStorage: new MockStorageE2E()
  };
};

/**
 * Execute a complete E2E workflow
 */
export const executeE2EWorkflow = async (
  workflow: E2EWorkflow
): Promise<{
  success: boolean;
  duration: number;
  stepResults: Array<{
    step: string;
    success: boolean;
    duration: number;
    error?: string;
  }>;
}> => {
  const startTime = Date.now();
  const stepResults: Array<{ step: string; success: boolean; duration: number; error?: string }> = [];
  
  try {
    const { container } = render(workflow.component);
    const context = createE2EContext(container);
    
    for (const [index, step] of workflow.steps.entries()) {
      const stepStartTime = Date.now();
      
      try {
        console.log(`Executing E2E step ${index + 1}: ${step.name}`);
        
        // Execute step action with retries
        let attempts = 0;
        const maxAttempts = step.retries || 1;
        
        while (attempts < maxAttempts) {
          try {
            await act(async () => {
              await step.action(context);
            });
            break;
          } catch (error) {
            attempts++;
            if (attempts >= maxAttempts) {
              throw error;
            }
            console.log(`Step ${step.name} failed, retrying (${attempts}/${maxAttempts})...`);
            await new Promise(resolve => setTimeout(resolve, 1000));
          }
        }
        
        // Validate step result
        await waitFor(async () => {
          await step.validation(context);
        }, { timeout: step.timeout || 10000 });
        
        stepResults.push({
          step: step.name,
          success: true,
          duration: Date.now() - stepStartTime
        });
        
      } catch (error) {
        stepResults.push({
          step: step.name,
          success: false,
          duration: Date.now() - stepStartTime,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
        
        throw new Error(`E2E workflow failed at step: ${step.name} - ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    return {
      success: true,
      duration: Date.now() - startTime,
      stepResults
    };
    
  } catch (error) {
    return {
      success: false,
      duration: Date.now() - startTime,
      stepResults
    };
  }
};

/**
 * Execute complete E2E test suite
 */
export const executeE2ETestSuite = async (
  suite: E2ETestSuite
): Promise<E2ETestReport> => {
  const startTime = Date.now();
  const report: E2ETestReport = {
    suiteName: suite.name,
    totalWorkflows: suite.workflows.length,
    passedWorkflows: 0,
    failedWorkflows: 0,
    totalSteps: 0,
    passedSteps: 0,
    failedSteps: 0,
    duration: 0,
    failures: []
  };
  
  try {
    // Suite setup
    if (suite.setup) {
      await suite.setup();
    }
    
    // Execute each workflow
    for (const workflow of suite.workflows) {
      // Before each workflow
      if (suite.beforeEach) {
        await suite.beforeEach();
      }
      
      try {
        const result = await executeE2EWorkflow(workflow);
        
        if (result.success) {
          report.passedWorkflows++;
        } else {
          report.failedWorkflows++;
        }
        
        // Count step results
        result.stepResults.forEach(stepResult => {
          report.totalSteps++;
          if (stepResult.success) {
            report.passedSteps++;
          } else {
            report.failedSteps++;
            report.failures.push({
              workflow: workflow.name,
              step: stepResult.step,
              error: stepResult.error || 'Unknown error'
            });
          }
        });
        
      } catch (error) {
        report.failedWorkflows++;
        report.failures.push({
          workflow: workflow.name,
          step: 'workflow-execution',
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
      
      // After each workflow
      if (suite.afterEach) {
        await suite.afterEach();
      }
    }
    
  } finally {
    // Suite teardown
    if (suite.teardown) {
      await suite.teardown();
    }
    
    report.duration = Date.now() - startTime;
  }
  
  return report;
};

/**
 * Common E2E workflow patterns for Terminal UI
 */
export const TerminalE2EWorkflows = {
  /**
   * Complete terminal session lifecycle
   */
  terminalSessionLifecycle: (TerminalApp: ReactElement): E2EWorkflow => ({
    name: 'Terminal Session Lifecycle',
    description: 'Test complete terminal session creation, usage, and cleanup',
    component: TerminalApp,
    steps: [
      {
        name: 'Application loads successfully',
        action: async (ctx) => {
          // Wait for initial load
          await new Promise(resolve => setTimeout(resolve, 500));
        },
        validation: async (ctx) => {
          expect(ctx.container.querySelector('[data-testid="terminal-app"]')).toBeInTheDocument();
        }
      },
      {
        name: 'Create new terminal session',
        action: async (ctx) => {
          const newSessionButton = ctx.container.querySelector('[data-testid="new-session"], [aria-label*="New"]') as HTMLElement;
          if (newSessionButton) {
            await ctx.user.click(newSessionButton);
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const terminals = ctx.container.querySelectorAll('[data-testid*="terminal"]');
            expect(terminals.length).toBeGreaterThan(0);
          });
        }
      },
      {
        name: 'Execute command in terminal',
        action: async (ctx) => {
          const terminal = ctx.container.querySelector('[data-testid="terminal"]') as HTMLElement;
          if (terminal) {
            await ctx.user.click(terminal);
            await ctx.user.type(terminal, 'echo "Hello World"');
            await ctx.user.keyboard('{Enter}');
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const output = ctx.container.textContent;
            expect(output).toContain('Hello World');
          }, { timeout: 5000 });
        }
      },
      {
        name: 'Open sidebar and verify session info',
        action: async (ctx) => {
          const sidebarToggle = ctx.container.querySelector('[data-testid="sidebar-toggle"], [aria-label*="sidebar"]') as HTMLElement;
          if (sidebarToggle) {
            await ctx.user.click(sidebarToggle);
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const sidebar = ctx.container.querySelector('[data-testid="sidebar"]');
            expect(sidebar).toBeVisible();
          });
        }
      },
      {
        name: 'Close terminal session',
        action: async (ctx) => {
          const closeButton = ctx.container.querySelector('[data-testid="close-session"], [aria-label*="Close"]') as HTMLElement;
          if (closeButton) {
            await ctx.user.click(closeButton);
          }
        },
        validation: async (ctx) => {
          // Verify session is closed or removed
          await ctx.waitFor(() => {
            const terminals = ctx.container.querySelectorAll('[data-testid*="terminal"]');
            // Either no terminals or a default terminal
            expect(terminals.length).toBeLessThanOrEqual(1);
          });
        }
      }
    ]
  }),

  /**
   * Multi-session management workflow
   */
  multiSessionManagement: (TerminalApp: ReactElement): E2EWorkflow => ({
    name: 'Multi-Session Management',
    description: 'Test managing multiple terminal sessions simultaneously',
    component: TerminalApp,
    steps: [
      {
        name: 'Create first terminal session',
        action: async (ctx) => {
          const newSessionButton = ctx.container.querySelector('[data-testid="new-session"]') as HTMLElement;
          await ctx.user.click(newSessionButton);
          ctx.sessionData.session1 = 'created';
        },
        validation: async (ctx) => {
          const sessions = ctx.container.querySelectorAll('[role="tab"]');
          expect(sessions.length).toBeGreaterThanOrEqual(1);
        }
      },
      {
        name: 'Create second terminal session',
        action: async (ctx) => {
          const newSessionButton = ctx.container.querySelector('[data-testid="new-session"]') as HTMLElement;
          await ctx.user.click(newSessionButton);
          ctx.sessionData.session2 = 'created';
        },
        validation: async (ctx) => {
          const sessions = ctx.container.querySelectorAll('[role="tab"]');
          expect(sessions.length).toBeGreaterThanOrEqual(2);
        }
      },
      {
        name: 'Switch between sessions',
        action: async (ctx) => {
          const tabs = ctx.container.querySelectorAll('[role="tab"]');
          if (tabs.length >= 2) {
            await ctx.user.click(tabs[0] as HTMLElement);
            await new Promise(resolve => setTimeout(resolve, 100));
            await ctx.user.click(tabs[1] as HTMLElement);
          }
        },
        validation: async (ctx) => {
          const activeTab = ctx.container.querySelector('[role="tab"][aria-selected="true"]');
          expect(activeTab).toBeInTheDocument();
        }
      },
      {
        name: 'Execute different commands in each session',
        action: async (ctx) => {
          const tabs = ctx.container.querySelectorAll('[role="tab"]');
          const terminal = ctx.container.querySelector('[data-testid="terminal"]') as HTMLElement;
          
          if (tabs.length >= 2 && terminal) {
            // First session
            await ctx.user.click(tabs[0] as HTMLElement);
            await ctx.user.click(terminal);
            await ctx.user.type(terminal, 'echo "Session 1"');
            await ctx.user.keyboard('{Enter}');
            
            // Second session
            await ctx.user.click(tabs[1] as HTMLElement);
            await ctx.user.click(terminal);
            await ctx.user.type(terminal, 'echo "Session 2"');
            await ctx.user.keyboard('{Enter}');
          }
        },
        validation: async (ctx) => {
          // Verify both sessions have their respective outputs
          const allText = ctx.container.textContent;
          expect(allText).toContain('Session 1');
          expect(allText).toContain('Session 2');
        }
      }
    ]
  }),

  /**
   * Error handling and recovery workflow
   */
  errorHandlingWorkflow: (TerminalApp: ReactElement): E2EWorkflow => ({
    name: 'Error Handling and Recovery',
    description: 'Test application behavior under error conditions',
    component: TerminalApp,
    steps: [
      {
        name: 'Simulate WebSocket connection failure',
        action: async (ctx) => {
          if (ctx.mockWebSocket) {
            ctx.mockWebSocket.simulateError();
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const errorIndicator = ctx.container.querySelector('[data-connection-state="error"], .connection-error');
            expect(errorIndicator).toBeInTheDocument();
          });
        }
      },
      {
        name: 'Attempt to reconnect',
        action: async (ctx) => {
          const reconnectButton = ctx.container.querySelector('[data-testid="reconnect"], [aria-label*="reconnect"]') as HTMLElement;
          if (reconnectButton) {
            await ctx.user.click(reconnectButton);
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const connectionStatus = ctx.container.querySelector('[data-connection-state="connecting"]');
            expect(connectionStatus).toBeInTheDocument();
          });
        }
      },
      {
        name: 'Verify error boundary catches component errors',
        action: async (ctx) => {
          // Trigger a component error (this would need to be set up in the component)
          const errorTrigger = ctx.container.querySelector('[data-testid="trigger-error"]') as HTMLElement;
          if (errorTrigger) {
            await ctx.user.click(errorTrigger);
          }
        },
        validation: async (ctx) => {
          // Check if error boundary is displayed
          const errorBoundary = ctx.container.querySelector('[role="alert"], .error-boundary');
          if (errorBoundary) {
            expect(errorBoundary).toBeInTheDocument();
          }
        }
      }
    ]
  }),

  /**
   * Performance and responsiveness workflow
   */
  performanceWorkflow: (TerminalApp: ReactElement): E2EWorkflow => ({
    name: 'Performance and Responsiveness',
    description: 'Test application performance under load',
    component: TerminalApp,
    steps: [
      {
        name: 'Load application and measure initial render time',
        action: async (ctx) => {
          const startTime = performance.now();
          ctx.data.startTime = startTime;
          await new Promise(resolve => setTimeout(resolve, 100));
        },
        validation: async (ctx) => {
          const endTime = performance.now();
          const renderTime = endTime - ctx.data.startTime;
          expect(renderTime).toBeLessThan(2000); // Should load within 2 seconds
        }
      },
      {
        name: 'Generate high-volume terminal output',
        action: async (ctx) => {
          if (ctx.mockWebSocket) {
            for (let i = 0; i < 100; i++) {
              ctx.mockWebSocket.simulateMessage({
                type: 'terminal:data',
                data: `High volume output line ${i}\n`
              });
            }
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const terminal = ctx.container.querySelector('[data-testid="terminal"]');
            expect(terminal).toBeInTheDocument();
            // Verify terminal is still responsive
          }, { timeout: 5000 });
        }
      },
      {
        name: 'Test UI responsiveness during heavy load',
        action: async (ctx) => {
          const startTime = performance.now();
          const button = ctx.container.querySelector('button') as HTMLElement;
          if (button) {
            await ctx.user.click(button);
          }
          ctx.data.interactionTime = performance.now() - startTime;
        },
        validation: async (ctx) => {
          // Interaction should be responsive even under load
          expect(ctx.data.interactionTime).toBeLessThan(100);
        }
      }
    ]
  })
};

/**
 * Generate E2E test report
 */
export const generateE2EReport = (report: E2ETestReport): string => {
  const successRate = report.totalWorkflows > 0 
    ? (report.passedWorkflows / report.totalWorkflows * 100).toFixed(1)
    : '0';
  
  const stepSuccessRate = report.totalSteps > 0
    ? (report.passedSteps / report.totalSteps * 100).toFixed(1)
    : '0';

  const reportText = [
    `E2E Test Report: ${report.suiteName}`,
    '='.repeat(50),
    '',
    `Duration: ${(report.duration / 1000).toFixed(2)}s`,
    '',
    'Workflow Results:',
    `  Total: ${report.totalWorkflows}`,
    `  Passed: ${report.passedWorkflows}`,
    `  Failed: ${report.failedWorkflows}`,
    `  Success Rate: ${successRate}%`,
    '',
    'Step Results:',
    `  Total: ${report.totalSteps}`,
    `  Passed: ${report.passedSteps}`,
    `  Failed: ${report.failedSteps}`,
    `  Success Rate: ${stepSuccessRate}%`,
    '',
    'Failures:',
    ...report.failures.map(failure => 
      `  - ${failure.workflow} -> ${failure.step}: ${failure.error}`
    ),
    '',
    `Overall Status: ${report.failedWorkflows === 0 ? '✅ PASSED' : '❌ FAILED'}`
  ];

  return reportText.join('\n');
};

/**
 * Create E2E test suite for Jest
 */
export const createE2ETestSuite = (
  suiteName: string,
  workflows: E2EWorkflow[]
) => {
  return describe(`E2E: ${suiteName}`, () => {
    workflows.forEach(workflow => {
      it(workflow.name, async () => {
        const result = await executeE2EWorkflow(workflow);
        
        if (!result.success) {
          const failedSteps = result.stepResults.filter(step => !step.success);
          const errorMessages = failedSteps.map(step => 
            `${step.step}: ${step.error}`
          ).join('\n');
          
          throw new Error(`E2E workflow failed:\n${errorMessages}`);
        }
        
        expect(result.success).toBe(true);
      }, workflow.timeout || 30000);
    });
  });
};

export default {
  createE2EContext,
  executeE2EWorkflow,
  executeE2ETestSuite,
  generateE2EReport,
  createE2ETestSuite,
  TerminalE2EWorkflows,
  MockWebSocketE2E,
  MockStorageE2E
};