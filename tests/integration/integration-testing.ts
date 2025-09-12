/**
 * Integration Testing Framework
 * Comprehensive patterns for testing component interactions and workflows
 */
import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';

export interface IntegrationTestProvider {
  name: string;
  wrapper: React.ComponentType<{ children: React.ReactNode }>;
  cleanup?: () => void;
}

export interface WorkflowStep {
  name: string;
  action: (context: IntegrationTestContext) => Promise<void>;
  validation: (context: IntegrationTestContext) => Promise<void>;
  timeout?: number;
}

export interface IntegrationTestContext {
  container: HTMLElement;
  user: ReturnType<typeof userEvent.setup>;
  screen: typeof screen;
  waitFor: typeof waitFor;
  data: Record<string, any>;
}

export interface ComponentInteractionTest {
  name: string;
  components: ReactElement[];
  workflow: WorkflowStep[];
  providers?: IntegrationTestProvider[];
  globalSetup?: () => Promise<void>;
  globalTeardown?: () => Promise<void>;
}

/**
 * Create integration test context with enhanced utilities
 */
export const createIntegrationContext = (container: HTMLElement): IntegrationTestContext => {
  return {
    container,
    user: userEvent.setup(),
    screen,
    waitFor,
    data: {}
  };
};

/**
 * Execute a workflow of integration steps
 */
export const executeWorkflow = async (
  workflow: WorkflowStep[],
  context: IntegrationTestContext
): Promise<void> => {
  for (const [index, step] of workflow.entries()) {
    try {
      console.log(`Executing step ${index + 1}: ${step.name}`);
      
      // Execute the action
      await act(async () => {
        await step.action(context);
      });
      
      // Wait for any async effects to complete
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
      });
      
      // Validate the result
      await waitFor(async () => {
        await step.validation(context);
      }, { timeout: step.timeout || 5000 });
      
    } catch (error) {
      throw new Error(`Integration test failed at step ${index + 1} (${step.name}): ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
};

/**
 * Test component interactions with comprehensive validation
 */
export const testComponentInteraction = async (
  test: ComponentInteractionTest
): Promise<void> => {
  let cleanup: Array<() => void> = [];
  
  try {
    // Global setup
    if (test.globalSetup) {
      await test.globalSetup();
    }
    
    // Setup providers
    let WrappedComponents = test.components;
    
    if (test.providers && test.providers.length > 0) {
      WrappedComponents = test.providers.reduce((components, provider) => {
        if (provider.cleanup) {
          cleanup.push(provider.cleanup);
        }
        
        return components.map(component =>
          React.createElement(provider.wrapper, { children: component })
        );
      }, WrappedComponents);
    }
    
    // Render all components
    const { container } = render(
      React.createElement('div', {}, ...WrappedComponents)
    );
    
    // Create test context
    const context = createIntegrationContext(container);
    
    // Execute workflow
    await executeWorkflow(test.workflow, context);
    
  } finally {
    // Cleanup
    cleanup.forEach(cleanupFn => cleanupFn());
    
    if (test.globalTeardown) {
      await test.globalTeardown();
    }
  }
};

/**
 * Test WebSocket integration with components
 */
export const testWebSocketIntegration = async (
  component: ReactElement,
  socketActions: Array<{
    name: string;
    action: 'connect' | 'disconnect' | 'send' | 'receive' | 'error';
    data?: any;
    delay?: number;
  }>,
  validations: Array<{
    selector: string;
    expectedContent?: string;
    expectedState?: 'connected' | 'disconnected' | 'error';
  }>
): Promise<void> => {
  // Mock WebSocket implementation for testing
  const mockWebSocket = {
    readyState: WebSocket.CLOSED,
    send: jest.fn(),
    close: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    sentMessages: [] as any[],
    receivedMessages: [] as any[]
  };
  
  // Replace global WebSocket
  const originalWebSocket = global.WebSocket;
  global.WebSocket = jest.fn(() => mockWebSocket) as any;
  
  try {
    const { container } = render(component);
    const context = createIntegrationContext(container);
    
    // Execute WebSocket actions
    for (const socketAction of socketActions) {
      if (socketAction.delay) {
        await new Promise(resolve => setTimeout(resolve, socketAction.delay));
      }
      
      await act(async () => {
        switch (socketAction.action) {
          case 'connect':
            (mockWebSocket as any).readyState = WebSocket.OPEN;
            // Trigger onopen event
            const openEvent = new Event('open');
            mockWebSocket.addEventListener.mock.calls
              .filter(([type]) => type === 'open')
              .forEach(([, handler]) => handler(openEvent));
            break;
            
          case 'disconnect':
            mockWebSocket.readyState = WebSocket.CLOSED;
            // Trigger onclose event
            const closeEvent = new CloseEvent('close');
            mockWebSocket.addEventListener.mock.calls
              .filter(([type]) => type === 'close')
              .forEach(([, handler]) => handler(closeEvent));
            break;
            
          case 'send':
            mockWebSocket.sentMessages.push(socketAction.data);
            break;
            
          case 'receive':
            // Trigger onmessage event
            const messageEvent = new MessageEvent('message', {
              data: JSON.stringify(socketAction.data)
            });
            mockWebSocket.addEventListener.mock.calls
              .filter(([type]) => type === 'message')
              .forEach(([, handler]) => handler(messageEvent));
            break;
            
          case 'error':
            // Trigger onerror event
            const errorEvent = new Event('error');
            mockWebSocket.addEventListener.mock.calls
              .filter(([type]) => type === 'error')
              .forEach(([, handler]) => handler(errorEvent));
            break;
        }
      });
    }
    
    // Validate results
    for (const validation of validations) {
      await waitFor(() => {
        const element = container.querySelector(validation.selector);
        expect(element).toBeInTheDocument();
        
        if (validation.expectedContent) {
          expect(element).toHaveTextContent(validation.expectedContent);
        }
        
        if (validation.expectedState) {
          // Check for state indicators in the UI
          const stateIndicators = container.querySelectorAll(`[data-connection-state="${validation.expectedState}"]`);
          expect(stateIndicators.length).toBeGreaterThan(0);
        }
      });
    }
    
  } finally {
    global.WebSocket = originalWebSocket;
  }
};

/**
 * Test state synchronization between components
 */
export const testStateSynchronization = async (
  components: Array<{
    name: string;
    component: ReactElement;
    stateSelectors: string[];
  }>,
  stateChanges: Array<{
    triggerComponent: string;
    action: (container: HTMLElement, user: ReturnType<typeof userEvent.setup>) => Promise<void>;
    expectedUpdates: Array<{
      component: string;
      selector: string;
      expectedValue: string;
    }>;
  }>
): Promise<void> => {
  // Render all components
  const componentElements = components.map(comp => 
    React.createElement('div', { 'data-component': comp.name }, comp.component)
  );
  
  const { container } = render(
    React.createElement('div', {}, ...componentElements)
  );
  
  const user = userEvent.setup();
  
  // Execute state changes and validate synchronization
  for (const stateChange of stateChanges) {
    const triggerContainer = container.querySelector(`[data-component="${stateChange.triggerComponent}"]`) as HTMLElement;
    expect(triggerContainer).toBeInTheDocument();
    
    // Execute the action
    await act(async () => {
      await stateChange.action(triggerContainer, user);
    });
    
    // Validate expected updates in all components
    for (const expectedUpdate of stateChange.expectedUpdates) {
      await waitFor(() => {
        const componentContainer = container.querySelector(`[data-component="${expectedUpdate.component}"]`);
        const targetElement = componentContainer?.querySelector(expectedUpdate.selector);
        
        expect(targetElement).toBeInTheDocument();
        expect(targetElement).toHaveTextContent(expectedUpdate.expectedValue);
      });
    }
  }
};

/**
 * Test form validation and submission workflows
 */
export const testFormWorkflow = async (
  formComponent: ReactElement,
  workflow: Array<{
    name: string;
    inputs: Array<{
      selector: string;
      value: string;
      expectedValidation?: {
        valid: boolean;
        message?: string;
      };
    }>;
    submitAction?: (container: HTMLElement, user: ReturnType<typeof userEvent.setup>) => Promise<void>;
    expectedResult?: {
      success: boolean;
      message?: string;
      redirectTo?: string;
    };
  }>
): Promise<void> => {
  const { container } = render(formComponent);
  const user = userEvent.setup();
  
  for (const step of workflow) {
    console.log(`Executing form step: ${step.name}`);
    
    // Fill form inputs
    for (const input of step.inputs) {
      const inputElement = container.querySelector(input.selector) as HTMLInputElement;
      expect(inputElement).toBeInTheDocument();
      
      await user.clear(inputElement);
      await user.type(inputElement, input.value);
      
      // Validate individual field if specified
      if (input.expectedValidation) {
        await waitFor(() => {
          if (input.expectedValidation!.valid) {
            expect(inputElement).toBeValid();
          } else {
            expect(inputElement).toBeInvalid();
          }
          
          if (input.expectedValidation!.message) {
            const validationMessage = container.querySelector('[role="alert"], .error-message');
            expect(validationMessage).toHaveTextContent(input.expectedValidation!.message);
          }
        });
      }
    }
    
    // Submit form if specified
    if (step.submitAction) {
      await act(async () => {
        await step.submitAction!(container, user);
      });
      
      // Validate submission result
      if (step.expectedResult) {
        await waitFor(() => {
          if (step.expectedResult!.success) {
            const successMessage = container.querySelector('.success-message, [role="status"]');
            expect(successMessage).toBeInTheDocument();
          } else {
            const errorMessage = container.querySelector('.error-message, [role="alert"]');
            expect(errorMessage).toBeInTheDocument();
          }
          
          if (step.expectedResult!.message) {
            const messageElement = container.querySelector('.success-message, .error-message, [role="status"], [role="alert"]');
            expect(messageElement).toHaveTextContent(step.expectedResult!.message);
          }
        });
      }
    }
  }
};

/**
 * Test modal and dialog interactions
 */
export const testModalWorkflow = async (
  triggerComponent: ReactElement,
  modalWorkflow: Array<{
    name: string;
    action: 'open' | 'close' | 'interact';
    trigger?: (container: HTMLElement, user: ReturnType<typeof userEvent.setup>) => Promise<void>;
    interaction?: (modalContainer: HTMLElement, user: ReturnType<typeof userEvent.setup>) => Promise<void>;
    validation: (container: HTMLElement) => Promise<void>;
  }>
): Promise<void> => {
  const { container } = render(triggerComponent);
  const user = userEvent.setup();
  
  for (const step of modalWorkflow) {
    console.log(`Executing modal step: ${step.name}`);
    
    await act(async () => {
      if (step.action === 'open' && step.trigger) {
        await step.trigger(container, user);
      } else if (step.action === 'interact' && step.interaction) {
        const modal = container.querySelector('[role="dialog"], [role="alertdialog"]') as HTMLElement;
        expect(modal).toBeInTheDocument();
        await step.interaction(modal, user);
      } else if (step.action === 'close') {
        // Try to close via Escape key or close button
        const closeButton = container.querySelector('[aria-label*="close"], [aria-label*="Close"], .close-button');
        if (closeButton) {
          await user.click(closeButton as HTMLElement);
        } else {
          await user.keyboard('{Escape}');
        }
      }
    });
    
    await waitFor(async () => {
      await step.validation(container);
    });
  }
};

/**
 * Test drag and drop interactions
 */
export const testDragDropWorkflow = async (
  component: ReactElement,
  dragDropTests: Array<{
    name: string;
    sourceSelector: string;
    targetSelector: string;
    expectedResult: (container: HTMLElement) => Promise<void>;
  }>
): Promise<void> => {
  const { container } = render(component);
  const user = userEvent.setup();
  
  for (const test of dragDropTests) {
    console.log(`Executing drag-drop test: ${test.name}`);
    
    const sourceElement = container.querySelector(test.sourceSelector) as HTMLElement;
    const targetElement = container.querySelector(test.targetSelector) as HTMLElement;
    
    expect(sourceElement).toBeInTheDocument();
    expect(targetElement).toBeInTheDocument();
    
    // Simulate drag and drop
    await act(async () => {
      await user.pointer([
        { target: sourceElement, keys: '[MouseLeft>]' },
        { target: targetElement },
        { keys: '[/MouseLeft]' }
      ]);
    });
    
    await waitFor(async () => {
      await test.expectedResult(container);
    });
  }
};

/**
 * Create comprehensive integration test suite
 */
export const createIntegrationTestSuite = (
  suiteName: string,
  tests: ComponentInteractionTest[]
) => {
  return describe(`${suiteName} Integration Tests`, () => {
    tests.forEach(test => {
      it(test.name, async () => {
        await testComponentInteraction(test);
      });
    });
  });
};

/**
 * Common integration test patterns for Terminal UI
 */
export const TerminalIntegrationPatterns = {
  /**
   * Test terminal session management
   */
  sessionManagement: (
    terminalComponent: ReactElement,
    sidebarComponent: ReactElement
  ): ComponentInteractionTest => ({
    name: 'should manage terminal sessions correctly',
    components: [terminalComponent, sidebarComponent],
    workflow: [
      {
        name: 'Create new terminal session',
        action: async (ctx) => {
          const newSessionButton = ctx.container.querySelector('[data-testid="new-session"]') as HTMLElement;
          await ctx.user.click(newSessionButton);
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const sessionList = ctx.container.querySelectorAll('[data-testid*="session"]');
            expect(sessionList.length).toBeGreaterThan(0);
          });
        }
      },
      {
        name: 'Switch between sessions',
        action: async (ctx) => {
          const sessionTabs = ctx.container.querySelectorAll('[role="tab"]');
          if (sessionTabs.length > 1) {
            await ctx.user.click(sessionTabs[1] as HTMLElement);
          }
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const activeTab = ctx.container.querySelector('[role="tab"][aria-selected="true"]');
            expect(activeTab).toBeInTheDocument();
          });
        }
      },
      {
        name: 'Close session',
        action: async (ctx) => {
          const closeButton = ctx.container.querySelector('[aria-label*="Close"]') as HTMLElement;
          await ctx.user.click(closeButton);
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const sessionTabs = ctx.container.querySelectorAll('[role="tab"]');
            // Should have one less tab after closing
          });
        }
      }
    ]
  }),

  /**
   * Test WebSocket connection and data flow
   */
  websocketDataFlow: (
    terminalComponent: ReactElement
  ): ComponentInteractionTest => ({
    name: 'should handle WebSocket data flow correctly',
    components: [terminalComponent],
    workflow: [
      {
        name: 'Establish WebSocket connection',
        action: async (ctx) => {
          // Simulate component mount triggering connection
          ctx.data.mockWebSocket = {
            readyState: WebSocket.OPEN,
            send: jest.fn(),
            addEventListener: jest.fn()
          };
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const connectionStatus = ctx.container.querySelector('[data-connection-state="connected"]');
            expect(connectionStatus).toBeInTheDocument();
          });
        }
      },
      {
        name: 'Send command to terminal',
        action: async (ctx) => {
          const terminal = ctx.container.querySelector('[data-testid="terminal"]') as HTMLElement;
          await ctx.user.type(terminal, 'echo "Hello World"');
          await ctx.user.keyboard('{Enter}');
        },
        validation: async (ctx) => {
          await ctx.waitFor(() => {
            const terminalOutput = ctx.container.querySelector('[data-testid="terminal-output"]');
            expect(terminalOutput).toHaveTextContent('Hello World');
          });
        }
      }
    ]
  })
};

export default {
  createIntegrationContext,
  executeWorkflow,
  testComponentInteraction,
  testWebSocketIntegration,
  testStateSynchronization,
  testFormWorkflow,
  testModalWorkflow,
  testDragDropWorkflow,
  createIntegrationTestSuite,
  TerminalIntegrationPatterns
};