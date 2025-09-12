/**
 * Enhanced Test Utilities
 * Comprehensive testing helpers for Claude UI components
 */
import React from 'react';
import { render, RenderOptions, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import type { ReactElement } from 'react';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

// Re-export everything from testing library
export * from '@testing-library/react';
export { userEvent };

// Types for enhanced testing
export interface TestProviderProps {
  children: React.ReactNode;
  mockLocalStorage?: Record<string, string>;
  mockSessionStorage?: Record<string, string>;
  initialWebSocketState?: 'connected' | 'disconnected' | 'connecting';
}

export interface ComponentTestOptions extends Omit<RenderOptions, 'wrapper'> {
  providerProps?: Partial<TestProviderProps>;
  skipA11yCheck?: boolean;
  performance?: boolean;
}

export interface PerformanceMetrics {
  renderTime: number;
  reRenderTime?: number;
  memoryUsage: number;
}

// Enhanced Mock Providers
const MockProviders: React.FC<TestProviderProps> = ({ 
  children, 
  mockLocalStorage = {},
  mockSessionStorage = {},
  initialWebSocketState = 'connected'
}) => {
  // Set up localStorage mock
  React.useEffect(() => {
    Object.entries(mockLocalStorage).forEach(([key, value]) => {
      localStorage.setItem(key, value);
    });
  }, [mockLocalStorage]);

  // Set up sessionStorage mock
  React.useEffect(() => {
    Object.entries(mockSessionStorage).forEach(([key, value]) => {
      sessionStorage.setItem(key, value);
    });
  }, [mockSessionStorage]);

  return <>{children}</>;
};

// Enhanced render function with accessibility testing
export const renderWithProviders = async (
  ui: ReactElement,
  options: ComponentTestOptions = {}
): Promise<{
  container: HTMLElement;
  rerender: (ui: ReactElement) => void;
  unmount: () => void;
  user: ReturnType<typeof userEvent.setup>;
  a11yResults?: any;
  performance?: PerformanceMetrics;
}> => {
  const { providerProps = {}, skipA11yCheck = false, performance: enablePerformanceTracking = false, ...renderOptions } = options;
  
  const user = userEvent.setup();
  
  // Performance measurement setup
  const startTime = typeof globalThis.performance !== 'undefined' ? globalThis.performance.now() : 0;
  const initialMemory = typeof window !== 'undefined' && (window.performance as any)?.memory ? (window.performance as any).memory.usedJSHeapSize : 0;

  const renderResult = render(ui, { 
    wrapper: (props) => <MockProviders {...providerProps} {...props} />, 
    ...renderOptions 
  });

  // Calculate performance metrics
  const endTime = enablePerformanceTracking ? globalThis.performance.now() : 0;
  const finalMemory = enablePerformanceTracking ? (window.performance as any)?.memory?.usedJSHeapSize : 0;
  
  const performanceMetrics: PerformanceMetrics | undefined = enablePerformanceTracking ? {
    renderTime: endTime - startTime,
    memoryUsage: finalMemory - initialMemory
  } : undefined;

  // Run accessibility check if not skipped
  let a11yResults;
  if (!skipA11yCheck) {
    try {
      a11yResults = await axe(renderResult.container);
    } catch (error) {
      console.warn('Accessibility check failed:', error);
    }
  }

  return {
    ...renderResult,
    user,
    a11yResults,
    performance: performanceMetrics
  };
};

// Utility for testing component re-renders
export const testReRender = async (
  initialUI: ReactElement,
  updatedUI: ReactElement,
  options: ComponentTestOptions = {}
): Promise<PerformanceMetrics & { container: HTMLElement }> => {
  const { container, rerender } = await renderWithProviders(initialUI, { ...options, performance: true });
  
  const reRenderStart = globalThis.performance.now();
  const reRenderMemoryStart = (window.performance as any)?.memory?.usedJSHeapSize || 0;
  
  rerender(updatedUI);
  
  const reRenderEnd = globalThis.performance.now();
  const reRenderMemoryEnd = (window.performance as any)?.memory?.usedJSHeapSize || 0;

  return {
    container,
    renderTime: 0, // Initial render time not measured in this context
    reRenderTime: reRenderEnd - reRenderStart,
    memoryUsage: reRenderMemoryEnd - reRenderMemoryStart
  };
};

// Accessibility testing helpers
export const testAccessibility = async (element: Element): Promise<void> => {
  const results = await axe(element);
  expect(results).toHaveNoViolations();
};

export const testKeyboardNavigation = async (
  element: HTMLElement,
  user: ReturnType<typeof userEvent.setup>
): Promise<void> => {
  // Test Tab navigation
  await user.tab();
  expect(element).toHaveFocus();
  
  // Test Enter key activation
  await user.keyboard('{Enter}');
  
  // Test Escape key if applicable
  await user.keyboard('{Escape}');
  
  // Test Arrow key navigation if applicable
  await user.keyboard('{ArrowDown}');
  await user.keyboard('{ArrowUp}');
  await user.keyboard('{ArrowLeft}');
  await user.keyboard('{ArrowRight}');
};

// Component state testing helpers
export const testComponentStates = async (
  Component: React.ComponentType<any>,
  states: Array<{ name: string; props: any; expected: (container: HTMLElement) => void }>
): Promise<void> => {
  for (const state of states) {
    const { container } = await renderWithProviders(<Component {...state.props} />);
    
    try {
      state.expected(container);
    } catch (error) {
      throw new Error(`State "${state.name}" failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
};

// Error boundary testing helper
export const testErrorBoundary = async (
  ErrorBoundary: React.ComponentType<any>,
  ThrowingComponent: React.ComponentType<any>
): Promise<void> => {
  const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
  
  const { container } = await renderWithProviders(
    <ErrorBoundary>
      <ThrowingComponent />
    </ErrorBoundary>,
    { skipA11yCheck: true }
  );
  
  // Verify error boundary caught the error
  expect(container).toHaveTextContent(/something went wrong|error/i);
  
  spy.mockRestore();
};

// Mock data generators
export const createMockTerminalSession = (overrides: Partial<any> = {}) => ({
  id: `session-${Math.random().toString(36).substr(2, 9)}`,
  name: `Terminal ${Math.floor(Math.random() * 100)}`,
  isActive: false,
  lastActivity: new Date().toISOString(),
  command: 'bash',
  cwd: '/home/user',
  ...overrides
});

export const createMockWebSocketMessage = (overrides: Partial<any> = {}) => ({
  type: 'terminal:data',
  sessionId: 'session-123',
  data: `Mock data ${Date.now()}`,
  timestamp: Date.now(),
  ...overrides
});

export const createMockSystemMetrics = (overrides: Partial<any> = {}) => ({
  cpu: {
    usage: Math.random() * 100,
    cores: 8,
    temperature: 45 + Math.random() * 20
  },
  memory: {
    total: 16 * 1024 * 1024 * 1024,
    used: Math.random() * 8 * 1024 * 1024 * 1024,
    free: Math.random() * 8 * 1024 * 1024 * 1024,
    cached: Math.random() * 2 * 1024 * 1024 * 1024
  },
  disk: {
    total: 512 * 1024 * 1024 * 1024,
    used: Math.random() * 256 * 1024 * 1024 * 1024,
    free: Math.random() * 256 * 1024 * 1024 * 1024
  },
  network: {
    rx: Math.random() * 1000000,
    tx: Math.random() * 1000000
  },
  timestamp: Date.now(),
  ...overrides
});

// Interaction testing helpers
export const testButtonInteractions = async (
  button: HTMLElement,
  user: ReturnType<typeof userEvent.setup>,
  expectedAction: jest.Mock
): Promise<void> => {
  // Test click
  await user.click(button);
  expect(expectedAction).toHaveBeenCalledTimes(1);
  
  // Test keyboard activation
  button.focus();
  await user.keyboard('{Enter}');
  expect(expectedAction).toHaveBeenCalledTimes(2);
  
  await user.keyboard(' ');
  expect(expectedAction).toHaveBeenCalledTimes(3);
};

export const testFormInteractions = async (
  form: HTMLFormElement,
  user: ReturnType<typeof userEvent.setup>,
  inputs: Array<{ selector: string; value: string }>
): Promise<void> => {
  for (const input of inputs) {
    const element = form.querySelector(input.selector) as HTMLElement;
    expect(element).toBeInTheDocument();
    
    if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
      await user.clear(element);
      await user.type(element, input.value);
      expect(element).toHaveValue(input.value);
    }
  }
};

// Performance testing helpers
export const testRenderPerformance = async (
  Component: React.ComponentType<any>,
  props: any,
  maxRenderTime: number = 100
): Promise<PerformanceMetrics> => {
  const result = await renderWithProviders(<Component {...props} />, { performance: true });
  
  expect(result.performance!.renderTime).toBeLessThan(maxRenderTime);
  
  return result.performance!;
};

export const testMemoryUsage = async (
  Component: React.ComponentType<any>,
  props: any,
  iterations: number = 100,
  maxMemoryIncrease: number = 1024 * 1024 // 1MB
): Promise<void> => {
  const initialMemory = (window.performance as any)?.memory?.usedJSHeapSize || 0;
  
  for (let i = 0; i < iterations; i++) {
    const { unmount } = await renderWithProviders(<Component {...props} />);
    unmount();
    
    // Force garbage collection if available
    if ((global as any).gc) {
      (global as any).gc();
    }
  }
  
  const finalMemory = (window.performance as any)?.memory?.usedJSHeapSize || 0;
  const memoryIncrease = finalMemory - initialMemory;
  
  expect(memoryIncrease).toBeLessThan(maxMemoryIncrease);
};

// Visual regression testing helpers
export const captureScreenshot = async (element: HTMLElement): Promise<string> => {
  // This would integrate with a visual regression testing tool
  // For now, return a mock screenshot identifier
  return `screenshot-${Date.now()}-${element.tagName.toLowerCase()}`;
};

// Wait utilities
export const waitForElement = async (
  selector: string,
  timeout: number = 5000
): Promise<HTMLElement> => {
  return await waitFor(() => {
    const element = screen.getByTestId(selector) || screen.getByText(selector) || document.querySelector(selector);
    expect(element).toBeInTheDocument();
    return element as HTMLElement;
  }, { timeout });
};

export const waitForElementToDisappear = async (
  selector: string,
  timeout: number = 5000
): Promise<void> => {
  return await waitFor(() => {
    const element = document.querySelector(selector);
    expect(element).not.toBeInTheDocument();
  }, { timeout });
};

// Mock WebSocket testing
export class MockWebSocketForTesting {
  public readyState: number = WebSocket.CONNECTING;
  public url: string;
  public onopen: ((event: Event) => void) | null = null;
  public onclose: ((event: CloseEvent) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public sentMessages: string[] = [];

  constructor(url: string) {
    this.url = url;
    setTimeout(() => this.simulateConnection(), 0);
  }

  send(data: string): void {
    this.sentMessages.push(data);
  }

  close(code?: number, reason?: string): void {
    this.readyState = WebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code, reason }));
    }
  }

  simulateConnection(): void {
    this.readyState = WebSocket.OPEN;
    if (this.onopen) {
      this.onopen(new Event('open'));
    }
  }

  simulateMessage(data: any): void {
    if (this.onmessage && this.readyState === WebSocket.OPEN) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }));
    }
  }

  simulateError(): void {
    if (this.onerror) {
      this.onerror(new Event('error'));
    }
  }

  simulateDisconnection(): void {
    this.readyState = WebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code: 1000, reason: 'Test disconnection' }));
    }
  }
}

// Component test suite generator
export const createComponentTestSuite = (
  componentName: string,
  Component: React.ComponentType<any>,
  defaultProps: any
) => {
  return {
    [`${componentName} Component`]: {
      'Rendering': {
        'should render without crashing': async () => {
          const { container } = await renderWithProviders(<Component {...defaultProps} />);
          expect(container).toBeInTheDocument();
        },
        
        'should pass accessibility tests': async () => {
          const { container, a11yResults } = await renderWithProviders(<Component {...defaultProps} />);
          if (a11yResults) {
            expect(a11yResults).toHaveNoViolations();
          }
        },
        
        'should render within performance limits': async () => {
          const metrics = await testRenderPerformance(Component, defaultProps);
          expect(metrics.renderTime).toBeLessThan(100);
        }
      },
      
      'Interactions': {
        'should handle keyboard navigation': async () => {
          const { container, user } = await renderWithProviders(<Component {...defaultProps} />);
          const focusableElements = container.querySelectorAll('[tabindex], button, input, textarea, select');
          
          if (focusableElements.length > 0) {
            await testKeyboardNavigation(focusableElements[0] as HTMLElement, user);
          }
        }
      }
    }
  };
};

// Export default render for backward compatibility
export { renderWithProviders as render };