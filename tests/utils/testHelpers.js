import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MockWebSocketClient, MockWebSocketServer } from '../mocks/mockWebSocket';

// Mock system metrics for testing
const mockSystemMetrics = {
  timestamp: Date.now(),
  cpuUsagePercent: 45.2,
  memoryUsagePercent: 67.8,
  diskUsagePercent: 34.5,
  networkBytesIn: 1024 * 1024 * 15,
  networkBytesOut: 1024 * 1024 * 8,
  activeConnections: 12,
  uptime: 86400,
};

// Test utilities for integration tests
export class TestUtils {
  constructor() {
    this.mockWsServer = new MockWebSocketServer();
    this.mockClients = new Set();
  }
  
  // Setup and teardown
  async setup() {
    this.mockWsServer.start(11237);
  }
  
  async teardown() {
    this.mockClients.forEach(client => client.disconnect());
    this.mockClients.clear();
    this.mockWsServer.stop();
  }
  
  // WebSocket utilities
  createMockWebSocketClient(url = 'ws://localhost:11237') {
    const client = new MockWebSocketClient(url);
    this.mockClients.add(client);
    this.mockWsServer.addClient(client);
    return client;
  }
  
  // Simulation utilities
  simulateTerminalOutput(sessionId = 'mock-session-1', data = 'Hello, World!\r\n') {
    this.mockWsServer.simulateTerminalData(sessionId, data);
  }
  
  simulateSystemMetrics() {
    this.mockWsServer.simulateSystemMetrics();
  }
  
  simulateAgentActivity() {
    this.mockWsServer.simulateAgentStatus();
  }
  
  simulateCommandExecution() {
    this.mockWsServer.simulateCommand();
  }
  
  // Terminal interaction utilities
  async typeInTerminal(text, terminal) {
    const user = userEvent.setup();
    await user.type(terminal, text);
  }
  
  async sendTerminalInput(client, sessionId, data) {
    client.send('data', { sessionId, data });
  }
  
  // Enhanced wait utilities with better timeout handling
  async waitForTerminalData(client, timeout = 1000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('Timeout waiting for terminal data'));
      }, timeout);
      
      const handler = (data) => {
        clearTimeout(timer);
        client.off('terminal-data', handler);
        resolve(data);
      };
      
      client.on('terminal-data', handler);
    });
  }
  
  // CRITICAL: Add flushPromises utility for test reliability
  async flushPromises() {
    return new Promise(resolve => setImmediate(resolve));
  }
  
  async waitForNextTick() {
    return new Promise(resolve => process.nextTick(resolve));
  }
  
  async waitForSystemMetrics(client, timeout = 1000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('Timeout waiting for system metrics'));
      }, timeout);
      
      const handler = (data) => {
        clearTimeout(timer);
        client.off('system-metrics', handler);
        resolve(data);
      };
      
      client.on('system-metrics', handler);
    });
  }
  
  async waitForConnection(client, timeout = 1000) {
    if (client.connected) return;
    
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('Timeout waiting for connection'));
      }, timeout);
      
      const handler = () => {
        clearTimeout(timer);
        client.off('connect', handler);
        resolve();
      };
      
      client.on('connect', handler);
    });
  }
  
  // Component testing utilities
  renderWithProviders(component, { initialState = {}, ...renderOptions } = {}) {
    // Mock providers for testing
    const Wrapper = ({ children }) => {
      return children; // Simplified for now
    };
    
    return render(component, { wrapper: Wrapper, ...renderOptions });
  }
  
  // Navigation testing utilities
  async clickTab(tabName) {
    const tab = screen.getByRole('tab', { name: tabName });
    await userEvent.click(tab);
    return tab;
  }
  
  async toggleSidebar() {
    const toggleButton = screen.getByRole('button', { name: /toggle|menu|sidebar/i });
    await userEvent.click(toggleButton);
    return toggleButton;
  }
  
  // Assertion utilities
  expectTerminalToBeVisible() {
    expect(screen.getByRole('group', { name: /terminal/i })).toBeInTheDocument();
  }
  
  expectSidebarToBeVisible() {
    expect(screen.getByRole('complementary', { name: /sidebar/i })).toBeInTheDocument();
  }
  
  expectMonitoringPanelToBeVisible() {
    expect(screen.getByRole('region', { name: /monitor/i })).toBeInTheDocument();
  }
  
  // Data flow testing utilities with optimized timeouts
  async testDataFlow(source, target, data, timeout = 1000) {
    const startTime = Date.now();
    
    // Send data from source
    if (typeof source.send === 'function') {
      source.send('test-data', data);
    } else if (typeof source === 'function') {
      source(data);
    }
    
    // Wait for data to arrive at target
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Data flow test timeout after ${timeout}ms`));
      }, timeout);
      
      const checkData = () => {
        if (target.hasReceivedData?.(data) || target.lastData === data) {
          clearTimeout(timer);
          resolve({
            data,
            latency: Date.now() - startTime,
          });
        } else if (Date.now() - startTime < timeout) {
          setTimeout(checkData, 10);
        }
      };
      
      checkData();
    });
  }
  
  // Performance testing utilities
  measureRenderTime(renderFunction) {
    const start = performance.now();
    const result = renderFunction();
    const end = performance.now();
    
    return {
      result,
      renderTime: end - start,
    };
  }
  
  // Memory testing utilities
  getMemoryUsage() {
    if (typeof window !== 'undefined' && window.performance?.memory) {
      return {
        used: window.performance.memory.usedJSHeapSize,
        total: window.performance.memory.totalJSHeapSize,
        limit: window.performance.memory.jsHeapSizeLimit,
      };
    }
    return null;
  }
}

// Singleton instance
export const testUtils = new TestUtils();

// Helper functions for common test patterns
export const createIntegrationTest = (name, testFn) => {
  return describe(`Integration: ${name}`, () => {
    beforeEach(async () => {
      await testUtils.setup();
    });
    
    afterEach(async () => {
      await testUtils.teardown();
    });
    
    testFn();
  });
};

export const createE2ETest = (name, testFn) => {
  return describe(`E2E: ${name}`, () => {
    beforeAll(async () => {
      await testUtils.setup();
    });
    
    afterAll(async () => {
      await testUtils.teardown();
    });
    
    testFn();
  });
};

// Custom matchers
expect.extend({
  toHaveReceivedData(received, expected) {
    const pass = JSON.stringify(received) === JSON.stringify(expected);
    
    if (pass) {
      return {
        message: () => `Expected not to receive data ${JSON.stringify(expected)}`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected to receive data ${JSON.stringify(expected)}, but got ${JSON.stringify(received)}`,
        pass: false,
      };
    }
  },
  
  toBeConnectedToWebSocket(received) {
    const pass = received.connected === true;
    
    if (pass) {
      return {
        message: () => 'Expected not to be connected to WebSocket',
        pass: true,
      };
    } else {
      return {
        message: () => 'Expected to be connected to WebSocket',
        pass: false,
      };
    }
  },
});