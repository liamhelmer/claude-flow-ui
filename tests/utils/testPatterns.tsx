/**
 * Standardized Test Patterns for Claude Flow UI
 * Provides consistent testing utilities and patterns across the codebase
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';

// === COMPONENT TESTING PATTERNS ===

/**
 * Standard component test wrapper with common providers
 */
export const renderWithProviders = (
  ui: ReactElement,
  options?: {
    initialState?: any;
    providers?: React.ComponentType<{ children: React.ReactNode }>[];
  }
) => {
  const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
    return (
      <div data-testid="test-wrapper">
        {options?.providers ? (
          options.providers.reduce(
            (acc, Provider) => <Provider>{acc}</Provider>,
            children as ReactElement
          )
        ) : (
          children
        )}
      </div>
    );
  };

  return render(ui, {
    wrapper: AllTheProviders,
    ...options,
  });
};

/**
 * Standard accessibility test patterns
 */
export const testAccessibility = {
  hasRole: (element: HTMLElement, role: string) => {
    expect(element).toHaveAttribute('role', role);
  },
  
  hasAriaLabel: (element: HTMLElement, label: string) => {
    expect(element).toHaveAttribute('aria-label', label);
  },
  
  isKeyboardAccessible: async (element: HTMLElement) => {
    element.focus();
    expect(element).toHaveFocus();
    
    // Test Enter key
    fireEvent.keyDown(element, { key: 'Enter', code: 'Enter' });
    
    // Test Space key for buttons
    if (element.tagName === 'BUTTON') {
      fireEvent.keyDown(element, { key: ' ', code: 'Space' });
    }
  },
};

/**
 * Performance testing utilities
 */
export const testPerformance = {
  measureRenderTime: async (renderFn: () => void) => {
    const start = performance.now();
    renderFn();
    await waitFor(() => {
      // Wait for render to complete
    });
    const end = performance.now();
    return end - start;
  },
  
  expectRenderTimeUnder: async (renderFn: () => void, maxTime: number) => {
    const renderTime = await testPerformance.measureRenderTime(renderFn);
    expect(renderTime).toBeLessThan(maxTime);
  },
};

// === HOOK TESTING PATTERNS ===

/**
 * Custom hook testing utilities
 */
export const hookTestUtils = {
  createHookWrapper: (initialProps?: any) => {
    const results: any[] = [];
    
    const TestComponent = (props: any) => {
      const result = props.hook(props.hookProps);
      results.push(result);
      return null;
    };
    
    const rerender = (newProps?: any) => {
      render(<TestComponent hook={newProps?.hook} hookProps={newProps?.hookProps} />);
    };
    
    return { results, rerender };
  },
};

// === WEBSOCKET TESTING PATTERNS ===

/**
 * WebSocket testing utilities
 */
export const websocketTestUtils = {
  createMockWebSocket: () => {
    const mockWs = {
      send: jest.fn(),
      close: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      readyState: WebSocket.OPEN,
      onopen: null as any,
      onclose: null as any,
      onmessage: null as any,
      onerror: null as any,
    };
    
    return mockWs;
  },
  
  simulateMessage: (mockWs: any, data: any) => {
    if (mockWs.onmessage) {
      mockWs.onmessage({ data: JSON.stringify(data) });
    }
  },
  
  simulateConnection: (mockWs: any) => {
    mockWs.readyState = WebSocket.OPEN;
    if (mockWs.onopen) {
      mockWs.onopen({});
    }
  },
  
  simulateDisconnection: (mockWs: any) => {
    mockWs.readyState = WebSocket.CLOSED;
    if (mockWs.onclose) {
      mockWs.onclose({});
    }
  },
};

// === TERMINAL TESTING PATTERNS ===

/**
 * Terminal component testing utilities
 */
export const terminalTestUtils = {
  createMockTerminal: () => ({
    write: jest.fn(),
    writeln: jest.fn(),
    clear: jest.fn(),
    focus: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
    cols: 80,
    rows: 24,
    element: document.createElement('div'),
  }),
  
  simulateTerminalInput: async (input: string) => {
    const user = userEvent.setup();
    const terminal = screen.getByTestId(/terminal/i);
    await user.type(terminal, input);
  },
  
  expectTerminalOutput: (mockTerminal: any, expectedOutput: string) => {
    expect(mockTerminal.write).toHaveBeenCalledWith(expectedOutput);
  },
};

// === STATE MANAGEMENT TESTING ===

/**
 * Zustand store testing utilities
 */
export const storeTestUtils = {
  createTestStore: <T = any>(initialState: Partial<T>, storeFn: any) => {
    // Reset store state before each test
    const store = storeFn();
    store.setState(initialState);
    return store;
  },
  
  expectStateChange: <T = any>(
    store: any, 
    action: () => void, 
    expectedState: Partial<T>
  ) => {
    const initialState = store.getState();
    action();
    const newState = store.getState();
    
    Object.keys(expectedState).forEach(key => {
      expect((newState as any)[key]).toEqual((expectedState as any)[key]);
    });
  },
};

// === ASYNC TESTING PATTERNS ===

/**
 * Async operation testing utilities
 */
export const asyncTestUtils = {
  waitForCondition: async (
    condition: () => boolean,
    timeout: number = 5000,
    interval: number = 100
  ) => {
    const startTime = Date.now();
    
    while (!condition()) {
      if (Date.now() - startTime > timeout) {
        throw new Error('Condition not met within timeout');
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }
  },
  
  expectEventually: async (
    assertion: () => void,
    timeout: number = 5000
  ) => {
    await waitFor(assertion, { timeout });
  },
};

// === ERROR BOUNDARY TESTING ===

/**
 * Error boundary testing utilities
 */
export const errorBoundaryTestUtils = {
  createThrowError: (shouldThrow: boolean = true) => {
    const ThrowError = ({ children }: { children?: React.ReactNode }) => {
      if (shouldThrow) {
        throw new Error('Test error');
      }
      return <>{children}</>;
    };
    return ThrowError;
  },
  
  expectErrorBoundary: (
    ErrorBoundaryComponent: React.ComponentType<any>,
    fallback?: React.ReactElement
  ) => {
    const ThrowError = errorBoundaryTestUtils.createThrowError();
    
    render(
      <ErrorBoundaryComponent>
        <ThrowError />
      </ErrorBoundaryComponent>
    );
    
    if (fallback) {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    }
  },
};

// === INTEGRATION TESTING PATTERNS ===

/**
 * Integration test utilities
 */
export const integrationTestUtils = {
  simulateUserWorkflow: async (steps: Array<() => Promise<void> | void>) => {
    for (const step of steps) {
      await step();
      // Allow time for state updates
      await waitFor(() => {});
    }
  },
  
  expectWorkflowCompleted: async (
    verification: () => void,
    timeout: number = 10000
  ) => {
    await waitFor(verification, { timeout });
  },
};

// === MOCK FACTORIES ===

/**
 * Common mock data factories
 */
export const mockFactories = {
  terminalSession: (overrides: any = {}) => ({
    id: 'session-1',
    name: 'Terminal 1',
    isActive: true,
    lastActivity: new Date().toISOString(),
    ...overrides,
  }),
  
  websocketMessage: (overrides: any = {}) => ({
    type: 'data',
    sessionId: 'session-1',
    data: 'test output',
    timestamp: Date.now(),
    ...overrides,
  }),
  
  systemMetrics: (overrides: any = {}) => ({
    memoryTotal: 16 * 1024 * 1024 * 1024, // 16GB
    memoryUsed: 8 * 1024 * 1024 * 1024,   // 8GB
    memoryFree: 8 * 1024 * 1024 * 1024,   // 8GB
    cpuLoad: [1.2, 1.1, 1.0],
    timestamp: Date.now(),
    ...overrides,
  }),
  
  agentStatus: (overrides: any = {}) => ({
    id: 'agent-1',
    type: 'coder',
    state: 'idle',
    currentTask: null,
    lastActivity: Date.now(),
    ...overrides,
  }),
};

// === COMMON TEST SCENARIOS ===

/**
 * Reusable test scenarios
 */
export const testScenarios = {
  componentRender: (Component: React.ComponentType, props: any = {}) => {
    it('renders without crashing', () => {
      expect(() => {
        render(<Component {...props} />);
      }).not.toThrow();
    });
  },
  
  componentAccessibility: (
    Component: React.ComponentType,
    props: any = {}
  ) => {
    it('meets accessibility requirements', async () => {
      render(<Component {...props} />);
      
      // Check for basic accessibility
      const component = screen.getByRole(props.role || 'generic');
      expect(component).toBeInTheDocument();
      
      if (props.ariaLabel) {
        expect(component).toHaveAttribute('aria-label', props.ariaLabel);
      }
    });
  },
  
  hookReturnValue: (hook: () => any, expectedShape: any) => {
    it('returns expected value shape', () => {
      const { results } = hookTestUtils.createHookWrapper();
      expect(results[0]).toMatchObject(expectedShape);
    });
  },
};

// Export all utilities as default
export default {
  renderWithProviders,
  testAccessibility,
  testPerformance,
  hookTestUtils,
  websocketTestUtils,
  terminalTestUtils,
  storeTestUtils,
  asyncTestUtils,
  errorBoundaryTestUtils,
  integrationTestUtils,
  mockFactories,
  testScenarios,
};