/**
 * Component Testing Framework for TDD
 * Comprehensive framework for testing React components with TDD methodology
 */

import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ReactElement, ReactNode } from 'react';
import { jest } from '@jest/globals';
import { act } from 'react-dom/test-utils';

/**
 * Component Test Builder
 * Fluent interface for building component tests
 */
export class ComponentTestBuilder {
  private component: ReactElement;
  private props: Record<string, any> = {};
  private context: Record<string, any> = {};
  private mocks: Record<string, jest.MockedFunction<any>> = {};

  constructor(component: ReactElement) {
    this.component = component;
  }

  /**
   * Set component props
   */
  withProps(props: Record<string, any>): ComponentTestBuilder {
    this.props = { ...this.props, ...props };
    return this;
  }

  /**
   * Set component context
   */
  withContext(context: Record<string, any>): ComponentTestBuilder {
    this.context = { ...this.context, ...context };
    return this;
  }

  /**
   * Add mocked function
   */
  withMock(name: string, mock: jest.MockedFunction<any>): ComponentTestBuilder {
    this.mocks[name] = mock;
    return this;
  }

  /**
   * Build and render component with test assertions
   */
  build(): ComponentTestSuite {
    const user = userEvent.setup();
    const renderResult = render(this.component, {
      wrapper: ({ children }: { children: ReactNode }) => (
        <div data-testid="component-wrapper">{children}</div>
      ),
    });

    return new ComponentTestSuite(renderResult, user, this.mocks);
  }
}

/**
 * Component Test Suite
 * Collection of test methods for component testing
 */
export class ComponentTestSuite {
  constructor(
    private renderResult: ReturnType<typeof render>,
    private user: ReturnType<typeof userEvent.setup>,
    private mocks: Record<string, jest.MockedFunction<any>>
  ) {}

  /**
   * Test component rendering
   */
  shouldRender(): ComponentTestSuite {
    expect(this.renderResult.container.firstChild).toBeInTheDocument();
    return this;
  }

  /**
   * Test component not rendering
   */
  shouldNotRender(): ComponentTestSuite {
    expect(this.renderResult.container.firstChild).not.toBeInTheDocument();
    return this;
  }

  /**
   * Test element presence by test ID
   */
  shouldHaveElement(testId: string): ComponentTestSuite {
    expect(screen.getByTestId(testId)).toBeInTheDocument();
    return this;
  }

  /**
   * Test element absence by test ID
   */
  shouldNotHaveElement(testId: string): ComponentTestSuite {
    expect(screen.queryByTestId(testId)).not.toBeInTheDocument();
    return this;
  }

  /**
   * Test text content
   */
  shouldHaveText(text: string): ComponentTestSuite {
    expect(screen.getByText(text)).toBeInTheDocument();
    return this;
  }

  /**
   * Test element attributes
   */
  shouldHaveAttribute(testId: string, attribute: string, value?: string): ComponentTestSuite {
    const element = screen.getByTestId(testId);
    if (value !== undefined) {
      expect(element).toHaveAttribute(attribute, value);
    } else {
      expect(element).toHaveAttribute(attribute);
    }
    return this;
  }

  /**
   * Test CSS classes
   */
  shouldHaveClass(testId: string, className: string): ComponentTestSuite {
    expect(screen.getByTestId(testId)).toHaveClass(className);
    return this;
  }

  /**
   * Test element visibility
   */
  shouldBeVisible(testId: string): ComponentTestSuite {
    expect(screen.getByTestId(testId)).toBeVisible();
    return this;
  }

  /**
   * Test element invisibility
   */
  shouldBeHidden(testId: string): ComponentTestSuite {
    expect(screen.getByTestId(testId)).not.toBeVisible();
    return this;
  }

  /**
   * Test element focus
   */
  shouldHaveFocus(testId: string): ComponentTestSuite {
    expect(screen.getByTestId(testId)).toHaveFocus();
    return this;
  }

  /**
   * Test click interaction
   */
  async whenClicked(testId: string): Promise<ComponentTestSuite> {
    await this.user.click(screen.getByTestId(testId));
    return this;
  }

  /**
   * Test hover interaction
   */
  async whenHovered(testId: string): Promise<ComponentTestSuite> {
    await this.user.hover(screen.getByTestId(testId));
    return this;
  }

  /**
   * Test keyboard interaction
   */
  async whenKeyPressed(testId: string, key: string): Promise<ComponentTestSuite> {
    const element = screen.getByTestId(testId);
    element.focus();
    await this.user.keyboard(key);
    return this;
  }

  /**
   * Test form input
   */
  async whenTyped(testId: string, text: string): Promise<ComponentTestSuite> {
    await this.user.type(screen.getByTestId(testId), text);
    return this;
  }

  /**
   * Test form submission
   */
  async whenSubmitted(formTestId: string): Promise<ComponentTestSuite> {
    const form = screen.getByTestId(formTestId);
    await this.user.click(form.querySelector('button[type="submit"]') || form.querySelector('button')!);
    return this;
  }

  /**
   * Test async state changes
   */
  async shouldEventuallyHaveText(text: string, timeout: number = 5000): Promise<ComponentTestSuite> {
    await waitFor(
      () => {
        expect(screen.getByText(text)).toBeInTheDocument();
      },
      { timeout }
    );
    return this;
  }

  /**
   * Test async element appearance
   */
  async shouldEventuallyHaveElement(testId: string, timeout: number = 5000): Promise<ComponentTestSuite> {
    await waitFor(
      () => {
        expect(screen.getByTestId(testId)).toBeInTheDocument();
      },
      { timeout }
    );
    return this;
  }

  /**
   * Test mock function calls
   */
  shouldHaveCalledMock(mockName: string, times?: number): ComponentTestSuite {
    const mock = this.mocks[mockName];
    if (times !== undefined) {
      expect(mock).toHaveBeenCalledTimes(times);
    } else {
      expect(mock).toHaveBeenCalled();
    }
    return this;
  }

  /**
   * Test mock function arguments
   */
  shouldHaveCalledMockWith(mockName: string, ...args: any[]): ComponentTestSuite {
    const mock = this.mocks[mockName];
    expect(mock).toHaveBeenCalledWith(...args);
    return this;
  }

  /**
   * Test accessibility
   */
  shouldBeAccessible(): ComponentTestSuite {
    // Check for basic accessibility attributes
    const interactiveElements = this.renderResult.container.querySelectorAll(
      'button, [role="button"], input, select, textarea, [tabindex]'
    );

    interactiveElements.forEach(element => {
      const hasLabel =
        element.hasAttribute('aria-label') ||
        element.hasAttribute('aria-labelledby') ||
        element.hasAttribute('title') ||
        (element as HTMLLabelElement).labels?.length > 0;

      expect(hasLabel).toBeTruthy();
    });

    return this;
  }

  /**
   * Test keyboard navigation
   */
  async shouldSupportKeyboardNavigation(): Promise<ComponentTestSuite> {
    const focusableElements = this.renderResult.container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    if (focusableElements.length > 0) {
      // Test Tab navigation
      for (let i = 0; i < focusableElements.length; i++) {
        await this.user.tab();
        expect(focusableElements[i]).toHaveFocus();
      }
    }

    return this;
  }

  /**
   * Test component cleanup
   */
  shouldCleanupProperly(): ComponentTestSuite {
    // Unmount component
    this.renderResult.unmount();

    // Check for memory leaks (simplified check)
    expect(this.renderResult.container.innerHTML).toBe('');

    return this;
  }

  /**
   * Custom assertion
   */
  should(assertion: (suite: ComponentTestSuite) => void): ComponentTestSuite {
    assertion(this);
    return this;
  }

  /**
   * Wait for condition
   */
  async waitFor(condition: () => void, timeout: number = 5000): Promise<ComponentTestSuite> {
    await waitFor(condition, { timeout });
    return this;
  }
}

/**
 * Test Scenario Builder
 * For building complex test scenarios
 */
export class TestScenarioBuilder {
  private steps: Array<() => Promise<void> | void> = [];

  /**
   * Add a test step
   */
  step(description: string, action: () => Promise<void> | void): TestScenarioBuilder {
    this.steps.push(async () => {
      console.log(`[TDD] Executing step: ${description}`);
      await action();
    });
    return this;
  }

  /**
   * Add async wait step
   */
  wait(ms: number): TestScenarioBuilder {
    this.steps.push(() => new Promise(resolve => setTimeout(resolve, ms)));
    return this;
  }

  /**
   * Execute all steps
   */
  async execute(): Promise<void> {
    for (const step of this.steps) {
      await step();
    }
  }
}

/**
 * Performance Test Builder
 * For testing component performance
 */
export class PerformanceTestBuilder {
  private component: ReactElement;
  private iterations: number = 1;

  constructor(component: ReactElement) {
    this.component = component;
  }

  /**
   * Set number of iterations
   */
  iterations(count: number): PerformanceTestBuilder {
    this.iterations = count;
    return this;
  }

  /**
   * Test render performance
   */
  async testRenderPerformance(maxTime: number = 100): Promise<void> {
    const times: number[] = [];

    for (let i = 0; i < this.iterations; i++) {
      const start = performance.now();
      const { unmount } = render(this.component);
      const end = performance.now();

      times.push(end - start);
      unmount();
    }

    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    const maxTimeRecorded = Math.max(...times);

    expect(avgTime).toBeLessThan(maxTime);
    expect(maxTimeRecorded).toBeLessThan(maxTime * 2);
  }

  /**
   * Test memory usage
   */
  async testMemoryUsage(maxIncrease: number = 10 * 1024 * 1024): Promise<void> {
    const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;

    for (let i = 0; i < this.iterations; i++) {
      const { unmount } = render(this.component);
      unmount();
    }

    // Force garbage collection if available
    if ((global as any).gc) {
      (global as any).gc();
    }

    const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
    const memoryIncrease = finalMemory - initialMemory;

    if (initialMemory > 0) {
      expect(memoryIncrease).toBeLessThan(maxIncrease);
    }
  }
}

/**
 * Factory functions for creating test builders
 */
export const createComponentTest = (component: ReactElement): ComponentTestBuilder =>
  new ComponentTestBuilder(component);

export const createTestScenario = (): TestScenarioBuilder =>
  new TestScenarioBuilder();

export const createPerformanceTest = (component: ReactElement): PerformanceTestBuilder =>
  new PerformanceTestBuilder(component);

/**
 * Utility functions
 */
export const tddHelpers = {
  mockFunction: <T extends (...args: any[]) => any>(): jest.MockedFunction<T> =>
    jest.fn() as jest.MockedFunction<T>,

  mockComponent: (displayName: string) =>
    jest.fn(({ children, ...props }) => (
      <div data-testid={`mock-${displayName.toLowerCase()}`} {...props}>
        {children}
      </div>
    )),

  flushPromises: () => act(async () => {
    await new Promise(resolve => setTimeout(resolve, 0));
  }),

  createMockEvent: (type: string, properties: Record<string, any> = {}) => ({
    type,
    preventDefault: jest.fn(),
    stopPropagation: jest.fn(),
    ...properties,
  }),
};

/**
 * Test decorators for common patterns
 */
export const testDecorators = {
  /**
   * Skip test in CI environment
   */
  skipInCI: (testFn: () => void) => {
    if (process.env.CI) {
      return test.skip;
    }
    return testFn;
  },

  /**
   * Run test only in development
   */
  onlyInDev: (testFn: () => void) => {
    if (process.env.NODE_ENV !== 'development') {
      return test.skip;
    }
    return testFn;
  },

  /**
   * Timeout decorator
   */
  withTimeout: (timeout: number) => (testFn: () => Promise<void>) =>
    async () => {
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Test timeout after ${timeout}ms`)), timeout)
      );

      await Promise.race([testFn(), timeoutPromise]);
    },

  /**
   * Retry decorator
   */
  withRetry: (retries: number) => (testFn: () => Promise<void>) =>
    async () => {
      let lastError: Error;

      for (let i = 0; i <= retries; i++) {
        try {
          await testFn();
          return;
        } catch (error) {
          lastError = error as Error;
          if (i < retries) {
            console.log(`Test failed, retrying... (${i + 1}/${retries})`);
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        }
      }

      throw lastError!;
    },
};

// Export everything
export default {
  createComponentTest,
  createTestScenario,
  createPerformanceTest,
  tddHelpers,
  testDecorators,
  ComponentTestBuilder,
  ComponentTestSuite,
  TestScenarioBuilder,
  PerformanceTestBuilder,
};