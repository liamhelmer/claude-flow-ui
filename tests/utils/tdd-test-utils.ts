/**
 * TDD Test Utilities
 * Comprehensive utility functions for Test-Driven Development
 */

import { render, RenderResult, RenderOptions } from '@testing-library/react';
import { ReactElement, ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';
import { act } from 'react-dom/test-utils';

// Enhanced render function with common providers
interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialState?: any;
  user?: ReturnType<typeof userEvent.setup>;
}

// Wrapper component for providers
const AllTheProviders = ({ children }: { children: ReactNode }) => {
  return (
    <div data-testid="test-wrapper">
      {children}
    </div>
  );
};

/**
 * Enhanced render function with user event setup
 */
export function renderWithProviders(
  ui: ReactElement,
  options: CustomRenderOptions = {}
): RenderResult & { user: ReturnType<typeof userEvent.setup> } {
  const { user = userEvent.setup(), ...renderOptions } = options;

  const result = render(ui, {
    wrapper: AllTheProviders,
    ...renderOptions,
  });

  return {
    user,
    ...result,
  };
}

/**
 * Wait for element with enhanced error messaging
 */
export async function waitForElement(
  callback: () => HTMLElement | null,
  options: { timeout?: number; interval?: number } = {}
): Promise<HTMLElement> {
  const { timeout = 5000, interval = 50 } = options;
  const startTime = Date.now();

  return new Promise((resolve, reject) => {
    const check = () => {
      const element = callback();

      if (element) {
        resolve(element);
        return;
      }

      if (Date.now() - startTime >= timeout) {
        reject(new Error(`Element not found within ${timeout}ms`));
        return;
      }

      setTimeout(check, interval);
    };

    check();
  });
}

/**
 * Mock timer utilities for TDD
 */
export const mockTimers = {
  setup: () => {
    jest.useFakeTimers();
    return {
      advance: (ms: number) => jest.advanceTimersByTime(ms),
      advanceToNext: () => jest.advanceTimersToNextTimer(),
      runAll: () => jest.runAllTimers(),
      runPending: () => jest.runOnlyPendingTimers(),
      cleanup: () => {
        jest.runOnlyPendingTimers();
        jest.useRealTimers();
      },
    };
  },

  cleanup: () => {
    jest.useRealTimers();
  },
};

/**
 * Performance testing utilities
 */
export const performance = {
  measure: async (name: string, fn: () => Promise<void> | void): Promise<number> => {
    const start = Date.now();
    await fn();
    const duration = Date.now() - start;

    if (process.env.DEBUG_PERFORMANCE) {
      console.log(`[Performance] ${name}: ${duration}ms`);
    }

    return duration;
  },

  expectFast: (duration: number, threshold: number = 100) => {
    expect(duration).toBeLessThan(threshold);
  },

  profile: async (fn: () => Promise<void> | void) => {
    const startMemory = process.memoryUsage().heapUsed;
    const start = Date.now();

    await fn();

    const duration = Date.now() - start;
    const endMemory = process.memoryUsage().heapUsed;
    const memoryDiff = endMemory - startMemory;

    return {
      duration,
      memoryUsed: memoryDiff,
      startMemory,
      endMemory,
    };
  },
};

/**
 * Accessibility testing utilities
 */
export const accessibility = {
  checkFocus: (element: HTMLElement) => {
    expect(element).toHaveFocus();
  },

  checkAriaLabel: (element: HTMLElement, expectedLabel?: string) => {
    const ariaLabel = element.getAttribute('aria-label') ||
                     element.getAttribute('aria-labelledby');

    expect(ariaLabel).toBeTruthy();

    if (expectedLabel) {
      expect(ariaLabel).toBe(expectedLabel);
    }
  },

  checkKeyboardNavigation: async (
    container: HTMLElement,
    user: ReturnType<typeof userEvent.setup>
  ) => {
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    expect(focusableElements.length).toBeGreaterThan(0);

    // Test Tab navigation
    for (let i = 0; i < focusableElements.length; i++) {
      await user.tab();
      expect(focusableElements[i]).toHaveFocus();
    }
  },

  checkRole: (element: HTMLElement, expectedRole: string) => {
    expect(element).toHaveAttribute('role', expectedRole);
  },
};

/**
 * Form testing utilities
 */
export const forms = {
  fillForm: async (
    form: HTMLElement,
    data: Record<string, string>,
    user: ReturnType<typeof userEvent.setup>
  ) => {
    for (const [name, value] of Object.entries(data)) {
      const field = form.querySelector(`[name="${name}"]`) as HTMLElement;
      if (field) {
        await user.clear(field);
        await user.type(field, value);
      }
    }
  },

  submitForm: async (
    form: HTMLElement,
    user: ReturnType<typeof userEvent.setup>
  ) => {
    const submitButton = form.querySelector('[type="submit"]') as HTMLElement;
    if (submitButton) {
      await user.click(submitButton);
    } else {
      // Fallback: find any button in the form
      const button = form.querySelector('button') as HTMLElement;
      if (button) {
        await user.click(button);
      }
    }
  },

  expectValidationError: (form: HTMLElement, fieldName: string) => {
    const field = form.querySelector(`[name="${fieldName}"]`);
    expect(field).toHaveAttribute('aria-invalid', 'true');
  },
};

/**
 * API testing utilities
 */
export const api = {
  mockResponse: (data: any, status: number = 200) => ({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  }),

  mockError: (message: string, status: number = 500) => ({
    ok: false,
    status,
    statusText: 'Error',
    json: () => Promise.reject(new Error(message)),
    text: () => Promise.reject(new Error(message)),
  }),

  expectApiCall: (mockFetch: jest.MockedFunction<any>, url: string, options?: any) => {
    expect(mockFetch).toHaveBeenCalledWith(url, options);
  },
};

/**
 * Component testing utilities
 */
export const component = {
  expectToRender: (element: HTMLElement) => {
    expect(element).toBeInTheDocument();
  },

  expectNotToRender: (element: HTMLElement | null) => {
    expect(element).not.toBeInTheDocument();
  },

  expectText: (element: HTMLElement, text: string) => {
    expect(element).toHaveTextContent(text);
  },

  expectClass: (element: HTMLElement, className: string) => {
    expect(element).toHaveClass(className);
  },

  expectAttribute: (element: HTMLElement, attr: string, value?: string) => {
    if (value !== undefined) {
      expect(element).toHaveAttribute(attr, value);
    } else {
      expect(element).toHaveAttribute(attr);
    }
  },

  expectVisible: (element: HTMLElement) => {
    expect(element).toBeVisible();
  },

  expectHidden: (element: HTMLElement) => {
    expect(element).not.toBeVisible();
  },
};

/**
 * Async testing utilities
 */
export const async = {
  waitForCondition: async (
    condition: () => boolean,
    timeout: number = 5000,
    interval: number = 100
  ): Promise<void> => {
    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const check = () => {
        if (condition()) {
          resolve();
          return;
        }

        if (Date.now() - startTime >= timeout) {
          reject(new Error(`Condition not met within ${timeout}ms`));
          return;
        }

        setTimeout(check, interval);
      };

      check();
    });
  },

  waitForStateChange: async <T>(
    getCurrentState: () => T,
    expectedState: T,
    timeout: number = 5000
  ): Promise<void> => {
    await async.waitForCondition(
      () => getCurrentState() === expectedState,
      timeout
    );
  },

  flushPromises: () => act(async () => {
    await new Promise(resolve => setTimeout(resolve, 0));
  }),
};

/**
 * Error boundary testing utilities
 */
export const errorBoundary = {
  expectToRender: (element: HTMLElement) => {
    expect(element).toBeInTheDocument();
  },

  expectErrorMessage: (container: HTMLElement, message: string) => {
    expect(container).toHaveTextContent(message);
  },

  expectFallbackUI: (container: HTMLElement, testId: string) => {
    expect(container.querySelector(`[data-testid="${testId}"]`)).toBeInTheDocument();
  },
};

/**
 * WebSocket testing utilities
 */
export const websocket = {
  mockWebSocket: () => {
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

    (global as any).WebSocket = jest.fn(() => mockWs);

    return mockWs;
  },

  simulateMessage: (mockWs: any, data: any) => {
    if (mockWs.onmessage) {
      mockWs.onmessage({ data: JSON.stringify(data) });
    }
  },

  simulateClose: (mockWs: any, code: number = 1000, reason: string = '') => {
    mockWs.readyState = WebSocket.CLOSED;
    if (mockWs.onclose) {
      mockWs.onclose({ code, reason });
    }
  },

  simulateError: (mockWs: any, error: any) => {
    if (mockWs.onerror) {
      mockWs.onerror(error);
    }
  },
};

/**
 * Snapshot testing utilities
 */
export const snapshot = {
  toMatchSnapshot: (component: any, name?: string) => {
    expect(component).toMatchSnapshot(name);
  },

  toMatchInlineSnapshot: (component: any, snapshot?: string) => {
    expect(component).toMatchInlineSnapshot(snapshot);
  },

  updateSnapshots: () => {
    // This would be controlled by --updateSnapshot flag
    console.log('Snapshots can be updated with --updateSnapshot flag');
  },
};

// Export all utilities
export default {
  renderWithProviders,
  waitForElement,
  mockTimers,
  performance,
  accessibility,
  forms,
  api,
  component,
  async,
  errorBoundary,
  websocket,
  snapshot,
};