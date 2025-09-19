/**
 * Enhanced Test Utilities for Claude UI Testing
 * Comprehensive utilities for edge cases, performance, and advanced testing scenarios
 */

import { render, RenderOptions, RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React, { ReactElement } from 'react';

type UserEvent = ReturnType<typeof userEvent.setup>;

// Types for enhanced testing
export interface TestSession {
  id: string;
  name: string;
  status: 'active' | 'inactive' | 'error' | 'loading';
  createdAt: number;
  lastActivity: number;
  commands: Array<{
    id: string;
    command: string;
    timestamp: number;
    status: 'success' | 'error' | 'running';
    output?: string;
  }>;
}

export interface TestAgent {
  id: string;
  name: string;
  type: 'coder' | 'reviewer' | 'tester' | 'researcher' | 'planner';
  status: 'active' | 'idle' | 'error' | 'disconnected';
  capabilities: string[];
  metrics: {
    tasksCompleted: number;
    errorRate: number;
    averageResponseTime: number;
  };
}

export interface TestMemoryData {
  usage: number;
  limit: number;
  items: Array<{
    key: string;
    size: number;
    type: 'session' | 'cache' | 'agent' | 'temp';
    lastAccessed: number;
  }>;
}

// Performance tracking utilities
export class TestPerformanceTracker {
  private measurements: Map<string, number[]> = new Map();
  private startTimes: Map<string, number> = new Map();

  startMeasurement(name: string): void {
    this.startTimes.set(name, performance.now());
  }

  endMeasurement(name: string): number {
    const startTime = this.startTimes.get(name);
    if (!startTime) {
      throw new Error(`No start time found for measurement: ${name}`);
    }

    const duration = performance.now() - startTime;
    
    if (!this.measurements.has(name)) {
      this.measurements.set(name, []);
    }
    this.measurements.get(name)!.push(duration);
    
    this.startTimes.delete(name);
    return duration;
  }

  getStats(name: string) {
    const durations = this.measurements.get(name) || [];
    if (durations.length === 0) return null;

    const sorted = [...durations].sort((a, b) => a - b);
    return {
      average: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      min: Math.min(...durations),
      max: Math.max(...durations),
      median: sorted[Math.floor(sorted.length / 2)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)],
      count: durations.length,
    };
  }

  reset(): void {
    this.measurements.clear();
    this.startTimes.clear();
  }
}

// Mock data generators
export class TestDataGenerator {
  static generateSessions(count: number): TestSession[] {
    return Array.from({ length: count }, (_, i) => ({
      id: `session-${i}`,
      name: `Test Session ${i}`,
      status: (['active', 'inactive', 'error', 'loading'] as const)[i % 4],
      createdAt: Date.now() - (i * 60000),
      lastActivity: Date.now() - (i * 10000),
      commands: this.generateCommands(Math.floor(Math.random() * 10) + 1),
    }));
  }

  static generateCommands(count: number) {
    const commands = [
      'npm start', 'npm test', 'git status', 'git commit -m "update"',
      'docker build', 'kubectl apply', 'terraform plan', 'python script.py',
      'node server.js', 'curl -X GET api/health'
    ];

    return Array.from({ length: count }, (_, i) => ({
      id: `cmd-${i}`,
      command: commands[Math.floor(Math.random() * commands.length)],
      timestamp: Date.now() - (i * 5000),
      status: (['success', 'error', 'running'] as const)[i % 3],
      output: `Output for command ${i}`,
    }));
  }

  static generateAgents(count: number): TestAgent[] {
    const types = ['coder', 'reviewer', 'tester', 'researcher', 'planner'] as const;
    const statuses = ['active', 'idle', 'error', 'disconnected'] as const;

    return Array.from({ length: count }, (_, i) => ({
      id: `agent-${i}`,
      name: `Agent ${i}`,
      type: types[i % types.length],
      status: statuses[i % statuses.length],
      capabilities: [`skill-${i}`, `capability-${i}`],
      metrics: {
        tasksCompleted: Math.floor(Math.random() * 100),
        errorRate: Math.random() * 0.1,
        averageResponseTime: Math.random() * 1000 + 100,
      },
    }));
  }

  static generateMemoryData(): TestMemoryData {
    const items = Array.from({ length: 20 }, (_, i) => ({
      key: `memory-item-${i}`,
      size: Math.floor(Math.random() * 50) + 10,
      type: (['session', 'cache', 'agent', 'temp'] as const)[i % 4],
      lastAccessed: Date.now() - (i * 60000),
    }));

    const totalUsage = items.reduce((sum, item) => sum + item.size, 0);

    return {
      usage: totalUsage,
      limit: 1000,
      items,
    };
  }

  static generateLargeDataset(size: number) {
    return Array.from({ length: size }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      description: `Description for item ${i}`.repeat(10),
      metadata: {
        tags: [`tag-${i % 5}`, `category-${i % 3}`],
        priority: Math.floor(Math.random() * 5) + 1,
        created: Date.now() - (i * 60000),
        updated: Date.now() - (i * 30000),
      },
      nestedData: Array.from({ length: 10 }, (_, j) => ({
        subId: j,
        value: Math.random() * 1000,
        label: `Sub-item ${j}`,
      })),
    }));
  }
}

// Edge case scenarios
export class EdgeCaseScenarios {
  static async simulateNetworkFlakiness(
    callback: () => Promise<void>,
    failureRate: number = 0.3
  ): Promise<void> {
    if (Math.random() < failureRate) {
      await new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 500));
      throw new Error('Network timeout');
    }
    await callback();
  }

  static async simulateSlowNetwork(
    callback: () => Promise<void>,
    delay: number = 1000
  ): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, delay));
    await callback();
  }

  static generateMaliciousInput() {
    return {
      xssPayloads: [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert("XSS")',
        '<svg onload="alert(1)">',
        '"><script>alert("XSS")</script>',
      ],
      sqlInjection: [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "UNION SELECT * FROM passwords",
        "'; UPDATE users SET admin=1; --",
      ],
      oversizedInput: 'A'.repeat(10000),
      specialCharacters: '©®™€¥£§¶•‰†‡°÷×±∞≈≤≥≠',
      unicode: '🔥💯🚀🎉👍💔😂🤔🙃',
      controlCharacters: '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D',
      binaryData: String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i)),
    };
  }

  static generateBoundaryValues() {
    return {
      integers: {
        zero: 0,
        negative: -1,
        maxSafeInteger: Number.MAX_SAFE_INTEGER,
        minSafeInteger: Number.MIN_SAFE_INTEGER,
        infinity: Infinity,
        negativeInfinity: -Infinity,
        nan: NaN,
      },
      strings: {
        empty: '',
        single: 'a',
        maxLength: 'a'.repeat(1000000),
        nullByte: '\0',
        newlines: '\n\r\n',
        tabs: '\t\t\t',
        spaces: '   ',
      },
      arrays: {
        empty: [],
        single: [1],
        large: Array.from({ length: 100000 }, (_, i) => i),
        nested: Array(100).fill(Array(100).fill(1)),
      },
      objects: {
        empty: {},
        circular: (() => {
          const obj: any = { a: 1 };
          obj.self = obj;
          return obj;
        })(),
        deeplyNested: Array(100).fill(null).reduce((acc) => ({ nested: acc }), {}),
      },
    };
  }
}

// Accessibility testing utilities
export class AccessibilityTestUtils {
  static async checkColorContrast(element: Element): Promise<boolean> {
    const style = getComputedStyle(element);
    const bgColor = style.backgroundColor;
    const textColor = style.color;
    
    // Simplified contrast check (in real scenario, use proper color contrast library)
    return bgColor !== 'transparent' && textColor !== bgColor;
  }

  static checkAriaLabels(container: Element): string[] {
    const issues: string[] = [];
    
    // Check for buttons without accessible names
    const buttons = container.querySelectorAll('button:not([aria-label]):not([aria-labelledby])');
    buttons.forEach((button, index) => {
      if (!button.textContent?.trim()) {
        issues.push(`Button at index ${index} has no accessible name`);
      }
    });

    // Check for images without alt text
    const images = container.querySelectorAll('img:not([alt])');
    if (images.length > 0) {
      issues.push(`${images.length} images without alt text`);
    }

    // Check for form inputs without labels
    const inputs = container.querySelectorAll('input:not([aria-label]):not([aria-labelledby])');
    inputs.forEach((input, index) => {
      const id = input.getAttribute('id');
      if (id) {
        const label = container.querySelector(`label[for="${id}"]`);
        if (!label) {
          issues.push(`Input at index ${index} has no associated label`);
        }
      } else {
        issues.push(`Input at index ${index} has no label or aria-label`);
      }
    });

    return issues;
  }

  static checkFocusManagement(container: Element): string[] {
    const issues: string[] = [];
    
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    focusableElements.forEach((element, index) => {
      const tabindex = element.getAttribute('tabindex');
      if (tabindex && parseInt(tabindex) > 0) {
        issues.push(`Element at index ${index} has positive tabindex (${tabindex})`);
      }
    });

    return issues;
  }
}

// Performance testing utilities
export class PerformanceTestUtils {
  static async measureRenderTime<T>(
    renderFn: () => T,
    iterations: number = 10
  ): Promise<{ average: number; min: number; max: number; results: T }> {
    const times: number[] = [];
    let lastResult: T;

    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      lastResult = renderFn();
      const end = performance.now();
      times.push(end - start);
    }

    return {
      average: times.reduce((sum, time) => sum + time, 0) / times.length,
      min: Math.min(...times),
      max: Math.max(...times),
      results: lastResult!,
    };
  }

  static createMemoryPressure(): void {
    // Create temporary memory pressure for testing
    const largeArrays: number[][] = [];
    for (let i = 0; i < 100; i++) {
      largeArrays.push(new Array(10000).fill(i));
    }
    
    // Clean up after short delay
    setTimeout(() => {
      largeArrays.length = 0;
    }, 100);
  }

  static async simulateHighCPULoad(duration: number = 100): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < duration) {
      // Busy wait to simulate CPU load
      Math.random();
    }
  }
}

// Enhanced render function with additional options
export interface EnhancedRenderOptions extends RenderOptions {
  withPerformanceTracking?: boolean;
  withAccessibilityChecks?: boolean;
  withErrorBoundary?: boolean;
  simulateSlowRender?: number;
}

export function renderWithEnhancements(
  ui: ReactElement,
  options: EnhancedRenderOptions = {}
): RenderResult & {
  user: UserEvent;
  performanceTracker?: TestPerformanceTracker;
  accessibilityIssues?: string[];
} {
  const {
    withPerformanceTracking,
    withAccessibilityChecks,
    withErrorBoundary,
    simulateSlowRender,
    ...renderOptions
  } = options;

  // Create error boundary wrapper if requested
  let wrappedUi = ui;
  if (withErrorBoundary) {
    const ErrorBoundary = ({ children }: { children: React.ReactNode }) => {
      const [hasError, setHasError] = React.useState(false);
      
      React.useEffect(() => {
        const handleError = () => setHasError(true);
        window.addEventListener('error', handleError);
        return () => window.removeEventListener('error', handleError);
      }, []);

      if (hasError) {
        return React.createElement('div', { role: 'alert' }, 'Something went wrong');
      }

      return React.createElement(React.Fragment, null, children);
    };

    wrappedUi = React.createElement(ErrorBoundary, null, ui);
  }

  // Simulate slow render if requested
  if (simulateSlowRender) {
    const start = Date.now();
    while (Date.now() - start < simulateSlowRender) {
      // Busy wait
    }
  }

  // Setup performance tracking
  let performanceTracker: TestPerformanceTracker | undefined;
  if (withPerformanceTracking) {
    performanceTracker = new TestPerformanceTracker();
    performanceTracker.startMeasurement('render');
  }

  // Render component
  const result = render(wrappedUi, renderOptions);

  // Complete performance tracking
  if (performanceTracker) {
    performanceTracker.endMeasurement('render');
  }

  // Check accessibility if requested
  let accessibilityIssues: string[] | undefined;
  if (withAccessibilityChecks) {
    accessibilityIssues = AccessibilityTestUtils.checkAriaLabels(result.container);
    accessibilityIssues.push(...AccessibilityTestUtils.checkFocusManagement(result.container));
  }

  return {
    ...result,
    user: userEvent.setup(),
    performanceTracker,
    accessibilityIssues,
  };
}

// Test scenario builders
export class TestScenarioBuilder {
  static buildTerminalTestScenario() {
    return {
      sessionId: 'test-terminal-session',
      mockCommands: [
        { command: 'npm start', output: 'Server started on port 3000', exitCode: 0 },
        { command: 'npm test', output: 'All tests passed', exitCode: 0 },
        { command: 'invalid-cmd', output: 'Command not found', exitCode: 1 },
      ],
      mockWebSocketEvents: [
        { type: 'connect', data: null },
        { type: 'data', data: 'Terminal output data' },
        { type: 'disconnect', data: null },
        { type: 'error', data: new Error('Connection failed') },
      ],
    };
  }

  static buildAgentTestScenario() {
    return {
      agents: TestDataGenerator.generateAgents(10),
      swarmEvents: [
        { type: 'agent_spawned', agentId: 'agent-1' },
        { type: 'task_assigned', agentId: 'agent-1', taskId: 'task-1' },
        { type: 'task_completed', agentId: 'agent-1', taskId: 'task-1' },
        { type: 'agent_error', agentId: 'agent-2', error: 'Processing failed' },
      ],
    };
  }

  static buildMemoryTestScenario() {
    return {
      memoryData: TestDataGenerator.generateMemoryData(),
      memoryEvents: [
        { type: 'allocation', size: 100, key: 'new-session' },
        { type: 'deallocation', key: 'old-session' },
        { type: 'pressure_warning', usage: 0.9 },
        { type: 'gc_triggered', freed: 200 },
      ],
    };
  }
}

const testUtilities = {
  TestDataGenerator,
  EdgeCaseScenarios,
  AccessibilityTestUtils,
  PerformanceTestUtils,
  TestPerformanceTracker,
  renderWithEnhancements,
  TestScenarioBuilder,
};

export default testUtilities;