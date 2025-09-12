# Test Utility Specifications

## Overview
This document specifies the comprehensive set of testing utilities for the Claude UI project, providing reusable components that enhance test readability, maintainability, and consistency.

## Core Test Utilities

### 1. Render Utilities

#### Custom Render with Providers
```typescript
// tests/utils/renderWithProviders.tsx
import React from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { WebSocketProvider } from '@/contexts/WebSocketContext';
import { StoreProvider } from '@/contexts/StoreContext';

interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  webSocketClient?: MockWebSocketClient;
  initialStore?: Partial<StoreState>;
  theme?: 'light' | 'dark';
}

export const renderWithProviders = (
  ui: React.ReactElement,
  options: CustomRenderOptions = {}
) => {
  const {
    webSocketClient = createMockWebSocketClient(),
    initialStore = {},
    theme = 'light',
    ...renderOptions
  } = options;

  const mockStore = createMockStore(initialStore);

  const AllTheProviders: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    return (
      <WebSocketProvider client={webSocketClient}>
        <StoreProvider store={mockStore}>
          <ThemeProvider theme={theme}>
            {children}
          </ThemeProvider>
        </StoreProvider>
      </WebSocketProvider>
    );
  };

  return {
    ...render(ui, { wrapper: AllTheProviders, ...renderOptions }),
    mockStore,
    webSocketClient,
  };
};

// Enhanced render for terminal components
export const renderTerminalComponent = (
  ui: React.ReactElement,
  options: CustomRenderOptions & {
    sessionId?: string;
    connected?: boolean;
    terminalConfig?: Partial<TerminalConfig>;
  } = {}
) => {
  const {
    sessionId = 'test-session',
    connected = true,
    terminalConfig = {},
    ...rest
  } = options;

  const defaultStore = {
    sessions: [createSessionFactory().withId(sessionId).active().build()],
    activeSessionId: sessionId,
    connected,
  };

  return renderWithProviders(ui, {
    initialStore: { ...defaultStore, ...rest.initialStore },
    ...rest,
  });
};
```

#### Responsive Render Utility
```typescript
// tests/utils/renderResponsive.ts
interface ResponsiveRenderOptions {
  viewport: 'mobile' | 'tablet' | 'desktop' | { width: number; height: number };
  orientation?: 'portrait' | 'landscape';
}

export const renderResponsive = (
  ui: React.ReactElement,
  options: ResponsiveRenderOptions
) => {
  const viewports = {
    mobile: { width: 375, height: 667 },
    tablet: { width: 768, height: 1024 },
    desktop: { width: 1920, height: 1080 },
  };

  const viewport = typeof options.viewport === 'string' 
    ? viewports[options.viewport] 
    : options.viewport;

  // Adjust for orientation
  let { width, height } = viewport;
  if (options.orientation === 'landscape' && height > width) {
    [width, height] = [height, width];
  }

  // Mock window dimensions
  Object.defineProperty(window, 'innerWidth', {
    writable: true,
    configurable: true,
    value: width,
  });
  Object.defineProperty(window, 'innerHeight', {
    writable: true,
    configurable: true,
    value: height,
  });

  // Mock matchMedia for responsive queries
  const mockMatchMedia = (query: string) => {
    const isMobile = width < 768;
    const isTablet = width >= 768 && width < 1024;
    const isDesktop = width >= 1024;

    let matches = false;
    if (query.includes('max-width: 767px')) matches = isMobile;
    if (query.includes('min-width: 768px') && query.includes('max-width: 1023px')) matches = isTablet;
    if (query.includes('min-width: 1024px')) matches = isDesktop;

    return {
      matches,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    };
  };

  window.matchMedia = mockMatchMedia as any;

  return renderWithProviders(ui);
};
```

### 2. Interaction Utilities

#### Advanced User Event Utilities
```typescript
// tests/utils/userInteractions.ts
import userEvent from '@testing-library/user-event';

export const createUserInteractions = () => {
  const user = userEvent.setup();

  return {
    ...user,

    // Terminal-specific interactions
    async typeCommand(element: Element, command: string) {
      await user.clear(element);
      await user.type(element, command);
      await user.keyboard('{Enter}');
    },

    async sendKeyboardShortcut(combination: string) {
      await user.keyboard(combination);
    },

    async rightClick(element: Element) {
      await user.pointer({ target: element, keys: '[MouseRight]' });
    },

    async doubleClick(element: Element) {
      await user.dblClick(element);
    },

    async dragAndDrop(source: Element, target: Element) {
      await user.pointer([
        { target: source },
        { down: 'MouseLeft' },
        { target: target },
        { up: 'MouseLeft' },
      ]);
    },

    // Accessibility interactions
    async navigateWithTab(steps: number = 1) {
      for (let i = 0; i < steps; i++) {
        await user.tab();
      }
    },

    async navigateWithArrows(direction: 'up' | 'down' | 'left' | 'right', steps: number = 1) {
      const keyMap = {
        up: '{ArrowUp}',
        down: '{ArrowDown}',
        left: '{ArrowLeft}',
        right: '{ArrowRight}',
      };

      for (let i = 0; i < steps; i++) {
        await user.keyboard(keyMap[direction]);
      }
    },

    // Form interactions
    async fillForm(fields: Record<string, string>) {
      for (const [fieldName, value] of Object.entries(fields)) {
        const field = screen.getByLabelText(new RegExp(fieldName, 'i'));
        await user.clear(field);
        await user.type(field, value);
      }
    },

    // File upload
    async uploadFile(input: Element, file: File) {
      await user.upload(input, file);
    },

    // Hover interactions
    async hoverSequence(elements: Element[]) {
      for (const element of elements) {
        await user.hover(element);
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    },
  };
};
```

#### Terminal Interaction Utilities
```typescript
// tests/utils/terminalInteractions.ts
export const createTerminalInteractions = (mockWebSocket: MockWebSocketClient) => {
  return {
    async executeCommand(command: string, sessionId: string = 'test-session') {
      const terminalInput = screen.getByRole('textbox');
      const user = createUserInteractions();
      
      await user.typeCommand(terminalInput, command);
      
      // Simulate server response
      mockWebSocket.simulateMessage('terminal-data', {
        sessionId,
        data: `${command}\r\n`,
      });
    },

    async sendOutput(output: string, sessionId: string = 'test-session') {
      mockWebSocket.simulateMessage('terminal-data', {
        sessionId,
        data: output,
      });
    },

    async simulateCommandSequence(commands: Array<{ command: string; output: string }>, sessionId: string = 'test-session') {
      for (const { command, output } of commands) {
        await this.executeCommand(command, sessionId);
        await waitFor(() => {
          expect(screen.getByText(command)).toBeInTheDocument();
        });
        
        await this.sendOutput(output, sessionId);
        await waitFor(() => {
          expect(screen.getByText(output)).toBeInTheDocument();
        });
      }
    },

    async resizeTerminal(cols: number, rows: number, sessionId: string = 'test-session') {
      // Simulate window resize
      window.dispatchEvent(new Event('resize'));
      
      // Simulate terminal resize message
      mockWebSocket.simulateMessage('terminal-resize', {
        sessionId,
        cols,
        rows,
      });
    },

    async clearTerminal(sessionId: string = 'test-session') {
      const user = createUserInteractions();
      await user.sendKeyboardShortcut('{Control>}l{/Control}');
      
      // Simulate clear command
      mockWebSocket.simulateMessage('terminal-data', {
        sessionId,
        data: '\x1b[2J\x1b[H',
      });
    },
  };
};
```

### 3. Assertion Utilities

#### Custom Jest Matchers
```typescript
// tests/utils/customMatchers.ts
import { expect } from '@jest/globals';

expect.extend({
  toBeConnectedToWebSocket(mockClient: MockWebSocketClient) {
    const pass = mockClient.connected === true;
    
    return {
      pass,
      message: () => pass
        ? `Expected WebSocket to not be connected`
        : `Expected WebSocket to be connected, but it was ${mockClient.connected ? 'connected' : 'disconnected'}`,
    };
  },

  toHaveTerminalOutput(container: HTMLElement, expectedOutput: string | RegExp) {
    const terminalElement = container.querySelector('[data-testid="terminal-output"]');
    
    if (!terminalElement) {
      return {
        pass: false,
        message: () => 'Terminal output element not found',
      };
    }

    const content = terminalElement.textContent || '';
    const pass = typeof expectedOutput === 'string'
      ? content.includes(expectedOutput)
      : expectedOutput.test(content);

    return {
      pass,
      message: () => pass
        ? `Expected terminal to not contain "${expectedOutput}"`
        : `Expected terminal to contain "${expectedOutput}", but got: "${content}"`,
    };
  },

  toHaveSessionCount(store: any, expectedCount: number) {
    const actualCount = store.getState().sessions.length;
    const pass = actualCount === expectedCount;

    return {
      pass,
      message: () => pass
        ? `Expected store to not have ${expectedCount} sessions`
        : `Expected store to have ${expectedCount} sessions, but got ${actualCount}`,
    };
  },

  toHaveMemoryUsageBelow(metrics: SystemMetrics, threshold: number) {
    const pass = metrics.memoryUsagePercent < threshold;

    return {
      pass,
      message: () => pass
        ? `Expected memory usage to be at or above ${threshold}%`
        : `Expected memory usage to be below ${threshold}%, but got ${metrics.memoryUsagePercent}%`,
    };
  },

  toBeAccessible(element: HTMLElement) {
    // Basic accessibility checks
    const hasAriaLabel = element.hasAttribute('aria-label') || element.hasAttribute('aria-labelledby');
    const hasRole = element.hasAttribute('role');
    const isInteractive = ['button', 'input', 'select', 'textarea', 'a'].includes(element.tagName.toLowerCase());
    
    const pass = !isInteractive || (hasAriaLabel && hasRole);

    return {
      pass,
      message: () => pass
        ? `Expected element to not be accessible`
        : `Expected element to be accessible (have aria-label/aria-labelledby and role)`,
    };
  },
});

// Type declarations for TypeScript
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeConnectedToWebSocket(): R;
      toHaveTerminalOutput(expectedOutput: string | RegExp): R;
      toHaveSessionCount(expectedCount: number): R;
      toHaveMemoryUsageBelow(threshold: number): R;
      toBeAccessible(): R;
    }
  }
}
```

#### Assertion Helpers
```typescript
// tests/utils/assertionHelpers.ts
export const assertTerminalState = {
  isConnected: (mockClient: MockWebSocketClient) => {
    expect(mockClient).toBeConnectedToWebSocket();
  },

  hasOutput: (container: HTMLElement, output: string | RegExp) => {
    expect(container).toHaveTerminalOutput(output);
  },

  hasPrompt: (container: HTMLElement, prompt: string = '$ ') => {
    expect(container).toHaveTerminalOutput(new RegExp(prompt + '$'));
  },

  isExecutingCommand: (container: HTMLElement) => {
    expect(container.querySelector('[data-testid="command-executing"]')).toBeInTheDocument();
  },

  hasError: (container: HTMLElement, errorMessage?: string) => {
    const errorElement = container.querySelector('[data-testid="terminal-error"]');
    expect(errorElement).toBeInTheDocument();
    
    if (errorMessage) {
      expect(errorElement).toHaveTextContent(errorMessage);
    }
  },
};

export const assertStoreState = {
  hasSessionCount: (store: any, count: number) => {
    expect(store).toHaveSessionCount(count);
  },

  hasActiveSession: (store: any, sessionId: string) => {
    const state = store.getState();
    expect(state.activeSessionId).toBe(sessionId);
  },

  sessionExists: (store: any, sessionId: string) => {
    const state = store.getState();
    const session = state.sessions.find((s: any) => s.id === sessionId);
    expect(session).toBeDefined();
  },

  sessionIsActive: (store: any, sessionId: string) => {
    const state = store.getState();
    const session = state.sessions.find((s: any) => s.id === sessionId);
    expect(session?.isActive).toBe(true);
  },
};

export const assertSystemMetrics = {
  isWithinNormalRange: (metrics: SystemMetrics) => {
    expect(metrics).toHaveMemoryUsageBelow(90);
    expect(metrics.cpuLoad.every(load => load < 2)).toBe(true);
  },

  isUnderLoad: (metrics: SystemMetrics) => {
    expect(metrics.memoryUsagePercent).toBeGreaterThan(80);
    expect(metrics.cpuLoad.some(load => load > 1.5)).toBe(true);
  },

  isIdle: (metrics: SystemMetrics) => {
    expect(metrics).toHaveMemoryUsageBelow(50);
    expect(metrics.cpuLoad.every(load => load < 0.5)).toBe(true);
  },
};

export const assertAccessibility = {
  hasProperLabels: (element: HTMLElement) => {
    expect(element).toBeAccessible();
  },

  supportsFocusManagement: async (element: HTMLElement) => {
    const user = createUserInteractions();
    await user.tab();
    expect(element).toHaveFocus();
  },

  supportsKeyboardNavigation: async (element: HTMLElement, expectedKeys: string[]) => {
    const user = createUserInteractions();
    element.focus();
    
    for (const key of expectedKeys) {
      await user.keyboard(key);
      // Add specific assertions based on expected behavior
    }
  },

  hasCorrectAriaAttributes: (element: HTMLElement, expectedAttributes: Record<string, string>) => {
    Object.entries(expectedAttributes).forEach(([attr, value]) => {
      expect(element).toHaveAttribute(attr, value);
    });
  },
};
```

### 4. Wait Utilities

#### Advanced Wait Helpers
```typescript
// tests/utils/waitHelpers.ts
export const waitForCondition = async (
  condition: () => boolean | Promise<boolean>,
  options: {
    timeout?: number;
    interval?: number;
    timeoutMessage?: string;
  } = {}
) => {
  const {
    timeout = 5000,
    interval = 100,
    timeoutMessage = 'Condition was not met within timeout',
  } = options;

  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }

  throw new Error(timeoutMessage);
};

export const waitForWebSocketConnection = async (
  mockClient: MockWebSocketClient,
  timeout: number = 5000
) => {
  await waitForCondition(
    () => mockClient.connected,
    {
      timeout,
      timeoutMessage: 'WebSocket did not connect within timeout',
    }
  );
};

export const waitForTerminalOutput = async (
  container: HTMLElement,
  expectedOutput: string | RegExp,
  timeout: number = 5000
) => {
  await waitFor(() => {
    expect(container).toHaveTerminalOutput(expectedOutput);
  }, { timeout });
};

export const waitForStoreUpdate = async (
  store: any,
  predicate: (state: any) => boolean,
  timeout: number = 5000
) => {
  await waitForCondition(
    () => predicate(store.getState()),
    {
      timeout,
      timeoutMessage: 'Store state did not update as expected',
    }
  );
};

export const waitForMetricsUpdate = async (
  store: any,
  expectedMetrics: Partial<SystemMetrics>,
  timeout: number = 5000
) => {
  await waitForStoreUpdate(
    store,
    (state) => {
      const metrics = state.metrics;
      return Object.entries(expectedMetrics).every(
        ([key, value]) => metrics[key] === value
      );
    },
    timeout
  );
};

export const waitForAnimation = async (duration: number = 300) => {
  await new Promise(resolve => setTimeout(resolve, duration));
};

export const waitForNextTick = async () => {
  await new Promise(resolve => setTimeout(resolve, 0));
};
```

### 5. Snapshot Utilities

#### Enhanced Snapshot Testing
```typescript
// tests/utils/snapshotHelpers.ts
export const createSnapshotTest = (
  componentName: string,
  Component: React.ComponentType<any>,
  props: any[] = [{}]
) => {
  describe(`${componentName} Snapshots`, () => {
    props.forEach((propSet, index) => {
      it(`should render correctly with props set ${index + 1}`, () => {
        const { container } = renderWithProviders(<Component {...propSet} />);
        expect(container.firstChild).toMatchSnapshot();
      });
    });
  });
};

export const snapshotWithProps = (
  Component: React.ComponentType<any>,
  propVariations: any[]
) => {
  return propVariations.map((props, index) => {
    const { container } = renderWithProviders(<Component {...props} />);
    return {
      name: `variation-${index + 1}`,
      snapshot: container.firstChild,
    };
  });
};

export const createResponsiveSnapshots = (
  Component: React.ComponentType<any>,
  props: any = {}
) => {
  const viewports = ['mobile', 'tablet', 'desktop'] as const;
  
  return viewports.map(viewport => {
    const { container } = renderResponsive(<Component {...props} />, { viewport });
    return {
      name: viewport,
      snapshot: container.firstChild,
    };
  });
};
```

### 6. Performance Utilities

#### Performance Testing Helpers
```typescript
// tests/utils/performanceHelpers.ts
export const measureRenderTime = (
  Component: React.ComponentType<any>,
  props: any = {}
): number => {
  const startTime = performance.now();
  renderWithProviders(<Component {...props} />);
  const endTime = performance.now();
  
  return endTime - startTime;
};

export const measureAverageRenderTime = (
  Component: React.ComponentType<any>,
  props: any = {},
  iterations: number = 10
): number => {
  const times = Array.from({ length: iterations }, () => 
    measureRenderTime(Component, props)
  );
  
  return times.reduce((sum, time) => sum + time, 0) / times.length;
};

export const expectRenderTimeBelow = (
  Component: React.ComponentType<any>,
  props: any = {},
  threshold: number = 100
) => {
  const renderTime = measureRenderTime(Component, props);
  expect(renderTime).toBeLessThan(threshold);
};

export const createPerformanceBenchmark = (
  name: string,
  testFn: () => void | Promise<void>
) => {
  return async () => {
    const startTime = performance.now();
    const startMemory = performance.memory?.usedJSHeapSize || 0;
    
    await testFn();
    
    const endTime = performance.now();
    const endMemory = performance.memory?.usedJSHeapSize || 0;
    
    const duration = endTime - startTime;
    const memoryDelta = endMemory - startMemory;
    
    console.log(`Performance Benchmark: ${name}`);
    console.log(`Duration: ${duration.toFixed(2)}ms`);
    console.log(`Memory Delta: ${memoryDelta} bytes`);
    
    return { duration, memoryDelta };
  };
};
```

### 7. Mock Management Utilities

#### Mock State Management
```typescript
// tests/utils/mockStateManager.ts
export class MockStateManager {
  private mocks: Map<string, any> = new Map();
  private cleanupFunctions: Array<() => void> = [];

  register<T>(name: string, mock: T): T {
    this.mocks.set(name, mock);
    return mock;
  }

  get<T>(name: string): T {
    return this.mocks.get(name);
  }

  addCleanup(cleanupFn: () => void) {
    this.cleanupFunctions.push(cleanupFn);
  }

  reset() {
    this.mocks.clear();
    this.cleanupFunctions.forEach(fn => fn());
    this.cleanupFunctions = [];
  }

  createWebSocketMock(name: string = 'default') {
    const mock = createMockWebSocketClient();
    this.register(`websocket-${name}`, mock);
    
    this.addCleanup(() => {
      mock.disconnect();
    });
    
    return mock;
  }

  createStoreMock(name: string = 'default', initialState: any = {}) {
    const mock = createMockStore(initialState);
    this.register(`store-${name}`, mock);
    
    this.addCleanup(() => {
      mock.reset();
    });
    
    return mock;
  }

  createTerminalMock(name: string = 'default') {
    const mock = {
      write: jest.fn(),
      onData: jest.fn(),
      onResize: jest.fn(),
      focus: jest.fn(),
      clear: jest.fn(),
      dispose: jest.fn(),
    };
    
    this.register(`terminal-${name}`, mock);
    
    this.addCleanup(() => {
      jest.clearAllMocks();
    });
    
    return mock;
  }
}

export const createMockStateManager = () => new MockStateManager();
```

### 8. Test Suite Utilities

#### Integration Test Helper
```typescript
// tests/utils/integrationTestHelper.ts
export const createIntegrationTest = (
  suiteName: string,
  testDefinition: () => void
) => {
  describe(`Integration: ${suiteName}`, () => {
    let mockStateManager: MockStateManager;

    beforeEach(() => {
      mockStateManager = createMockStateManager();
    });

    afterEach(() => {
      mockStateManager.reset();
    });

    testDefinition();
  });
};

export const createE2ETest = (
  suiteName: string,
  testDefinition: () => void
) => {
  describe(`E2E: ${suiteName}`, () => {
    let mockStateManager: MockStateManager;

    beforeAll(async () => {
      // Setup E2E environment
      mockStateManager = createMockStateManager();
    });

    afterAll(async () => {
      // Cleanup E2E environment
      mockStateManager.reset();
    });

    beforeEach(() => {
      // Reset state for each test
      mockStateManager.reset();
    });

    testDefinition();
  });
};
```

### 9. Accessibility Testing Utilities

#### A11y Testing Helpers
```typescript
// tests/utils/accessibilityHelpers.ts
import { axe, toHaveNoViolations } from 'jest-axe';

expect.extend(toHaveNoViolations);

export const runAxeTest = async (container: HTMLElement) => {
  const results = await axe(container);
  expect(results).toHaveNoViolations();
};

export const testKeyboardNavigation = async (
  container: HTMLElement,
  expectedFocusSequence: string[]
) => {
  const user = createUserInteractions();
  
  for (const selector of expectedFocusSequence) {
    await user.tab();
    const focusedElement = container.querySelector(selector);
    expect(focusedElement).toHaveFocus();
  }
};

export const testScreenReader = (
  container: HTMLElement,
  expectedAnnouncements: string[]
) => {
  const liveRegions = container.querySelectorAll('[aria-live]');
  
  expectedAnnouncements.forEach((announcement, index) => {
    expect(liveRegions[index]).toHaveTextContent(announcement);
  });
};

export const createAccessibilityTestSuite = (
  Component: React.ComponentType<any>,
  props: any = {}
) => {
  describe('Accessibility', () => {
    it('should have no accessibility violations', async () => {
      const { container } = renderWithProviders(<Component {...props} />);
      await runAxeTest(container);
    });

    it('should support keyboard navigation', async () => {
      const { container } = renderWithProviders(<Component {...props} />);
      await testKeyboardNavigation(container, [
        '[role="button"]',
        '[role="textbox"]',
        '[role="menuitem"]',
      ]);
    });

    it('should have proper ARIA attributes', () => {
      const { container } = renderWithProviders(<Component {...props} />);
      
      const interactiveElements = container.querySelectorAll(
        'button, input, select, textarea, a, [role]'
      );
      
      interactiveElements.forEach(element => {
        expect(element).toBeAccessible();
      });
    });
  });
};
```

## Usage Examples

### Basic Component Testing
```typescript
// Example: Testing a component with utilities
import { renderWithProviders, createUserInteractions } from '@tests/utils';

describe('TerminalComponent', () => {
  it('should handle user input correctly', async () => {
    const { container, webSocketClient } = renderTerminalComponent(
      <TerminalComponent sessionId="test" />
    );
    
    const user = createUserInteractions();
    const terminalInteractions = createTerminalInteractions(webSocketClient);
    
    await terminalInteractions.executeCommand('ls -la');
    
    expect(container).toHaveTerminalOutput('ls -la');
    expect(webSocketClient).toBeConnectedToWebSocket();
  });
});
```

### Integration Testing
```typescript
// Example: Integration test with utilities
createIntegrationTest('Terminal and Sidebar Integration', () => {
  it('should synchronize session state', async () => {
    const mockStateManager = createMockStateManager();
    const webSocket = mockStateManager.createWebSocketMock();
    const store = mockStateManager.createStoreMock();
    
    const { container } = renderWithProviders(
      <App />,
      { webSocketClient: webSocket, initialStore: store.getState() }
    );
    
    const user = createUserInteractions();
    await user.click(screen.getByRole('button', { name: /new session/i }));
    
    expect(store).toHaveSessionCount(1);
    assertStoreState.hasActiveSession(store, expect.any(String));
  });
});
```

## Best Practices

1. **Reusability**: Create utilities that can be used across multiple tests
2. **Consistency**: Use consistent naming and patterns across utilities
3. **Documentation**: Document complex utilities with examples
4. **Performance**: Keep utilities lightweight and efficient
5. **Maintenance**: Regularly review and update utilities as the codebase evolves

## Conclusion

These test utilities provide a comprehensive foundation for creating maintainable, readable, and consistent tests across the Claude UI project. They encapsulate common testing patterns and provide specialized helpers for domain-specific testing scenarios.