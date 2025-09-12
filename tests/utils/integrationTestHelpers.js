/**
 * Enhanced Integration Test Helpers
 * 
 * Specialized utilities for integration testing with better
 * async handling, mock management, and test reliability
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

export class IntegrationTestHelpers {
  constructor() {
    this.cleanupFunctions = new Set();
    this.activeTimeouts = new Set();
    this.activeMocks = new Map();
  }

  /**
   * Enhanced async wait with better error handling
   */
  async waitForCondition(condition, options = {}) {
    const { timeout = 3000, interval = 100, message = 'Condition not met' } = options;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return true;
      }
      await this.sleep(interval);
    }

    throw new Error(`${message} after ${timeout}ms`);
  }

  /**
   * Sleep utility for test timing
   */
  sleep(ms) {
    return new Promise(resolve => {
      const timeoutId = setTimeout(resolve, ms);
      this.activeTimeouts.add(timeoutId);
    });
  }

  /**
   * Enhanced mock function with call tracking
   */
  createTrackedMock(name, implementation) {
    const mock = jest.fn(implementation);
    mock._name = name;
    mock._callHistory = [];
    
    const originalMock = mock;
    const trackedMock = (...args) => {
      mock._callHistory.push({
        args,
        timestamp: Date.now(),
        stack: new Error().stack
      });
      return originalMock(...args);
    };

    // Copy jest mock properties
    Object.setPrototypeOf(trackedMock, originalMock);
    Object.keys(originalMock).forEach(key => {
      trackedMock[key] = originalMock[key];
    });

    this.activeMocks.set(name, trackedMock);
    return trackedMock;
  }

  /**
   * Wait for mock to be called with specific conditions
   */
  async waitForMockCall(mock, options = {}) {
    const { timeout = 2000, times = 1, withArgs } = options;
    
    return await this.waitForCondition(
      () => {
        if (withArgs) {
          return mock.mock.calls.some(call => 
            this.deepEqual(call, withArgs)
          );
        }
        return mock.mock.calls.length >= times;
      },
      { 
        timeout, 
        message: `Mock ${mock._name || 'function'} not called as expected` 
      }
    );
  }

  /**
   * Deep equality check for mock arguments
   */
  deepEqual(a, b) {
    if (a === b) return true;
    if (a == null || b == null) return false;
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      return a.every((item, index) => this.deepEqual(item, b[index]));
    }
    if (typeof a === 'object' && typeof b === 'object') {
      const keysA = Object.keys(a);
      const keysB = Object.keys(b);
      if (keysA.length !== keysB.length) return false;
      return keysA.every(key => this.deepEqual(a[key], b[key]));
    }
    return false;
  }

  /**
   * Enhanced component rendering with cleanup tracking
   */
  renderWithCleanup(component, options = {}) {
    const result = render(component, options);
    
    this.cleanupFunctions.add(() => {
      if (result.unmount) {
        result.unmount();
      }
    });

    return result;
  }

  /**
   * Wait for component to be in specific state
   */
  async waitForComponent(selector, options = {}) {
    const { state = 'visible', timeout = 3000 } = options;
    
    if (state === 'visible') {
      return await waitFor(() => {
        expect(screen.getByTestId(selector) || screen.getByRole(selector)).toBeInTheDocument();
      }, { timeout });
    } else if (state === 'hidden') {
      return await waitFor(() => {
        expect(screen.queryByTestId(selector) || screen.queryByRole(selector)).not.toBeInTheDocument();
      }, { timeout });
    }
  }

  /**
   * Enhanced user interaction with retry logic
   */
  async userInteraction(action, options = {}) {
    const { retries = 3, delay = 100 } = options;
    let lastError;

    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        await action();
        return; // Success
      } catch (error) {
        lastError = error;
        if (attempt < retries - 1) {
          await this.sleep(delay);
        }
      }
    }

    throw new Error(`User interaction failed after ${retries} attempts: ${lastError.message}`);
  }

  /**
   * Simulate terminal data flow with proper timing
   */
  async simulateTerminalFlow(client, sessionId, commands) {
    const results = [];

    for (const command of commands) {
      // Send command
      await act(async () => {
        client.emit('terminal-input', { sessionId, data: command.input });
      });

      await this.sleep(command.delay || 50);

      // Simulate response
      await act(async () => {
        client.emit('terminal-data', { 
          sessionId, 
          data: command.output 
        });
      });

      results.push({ input: command.input, output: command.output });
      await this.sleep(10); // Small delay between commands
    }

    return results;
  }

  /**
   * Enhanced WebSocket mock with state management
   */
  createAdvancedWebSocketMock() {
    const state = {
      connected: false,
      connecting: false,
      sessions: new Map(),
      handlers: new Map()
    };

    const mock = {
      // Connection methods
      connect: this.createTrackedMock('connect', async () => {
        state.connecting = true;
        await this.sleep(10);
        state.connected = true;
        state.connecting = false;
        this.emit('connect');
        return true;
      }),

      disconnect: this.createTrackedMock('disconnect', async () => {
        state.connected = false;
        this.emit('disconnect');
        return true;
      }),

      // Session methods
      createSession: this.createTrackedMock('createSession', async (sessionData) => {
        const sessionId = sessionData?.id || `session-${Date.now()}`;
        state.sessions.set(sessionId, {
          id: sessionId,
          name: sessionData?.name || `Terminal ${state.sessions.size + 1}`,
          created: Date.now()
        });
        
        await this.sleep(5);
        this.emit('session-created', { sessionId, ...sessionData });
        return { id: sessionId };
      }),

      destroySession: this.createTrackedMock('destroySession', async (sessionId) => {
        state.sessions.delete(sessionId);
        await this.sleep(5);
        this.emit('session-destroyed', { sessionId });
        return true;
      }),

      // Data methods
      sendData: this.createTrackedMock('sendData', async (sessionId, data) => {
        if (!state.connected) {
          throw new Error('WebSocket not connected');
        }
        await this.sleep(5);
        return true;
      }),

      // Event handling
      on: (event, handler) => {
        if (!state.handlers.has(event)) {
          state.handlers.set(event, new Set());
        }
        state.handlers.get(event).add(handler);
      },

      off: (event, handler) => {
        const handlers = state.handlers.get(event);
        if (handlers) {
          handlers.delete(handler);
        }
      },

      emit: (event, data) => {
        const handlers = state.handlers.get(event);
        if (handlers) {
          handlers.forEach(handler => {
            try {
              handler(data);
            } catch (error) {
              console.error(`Error in ${event} handler:`, error);
            }
          });
        }
      },

      // State accessors
      get connected() { return state.connected; },
      get connecting() { return state.connecting; },
      get isConnected() { return state.connected; },
      getSessionCount: () => state.sessions.size,
      getSession: (id) => state.sessions.get(id)
    };

    return mock;
  }

  /**
   * Create enhanced terminal mock with better data handling
   */
  createAdvancedTerminalMock() {
    const terminalElement = document.createElement('div');
    terminalElement.setAttribute('role', 'group');
    terminalElement.setAttribute('aria-label', 'Terminal');

    let dataCallback = null;
    const writeHistory = [];

    const mock = {
      terminalRef: { current: terminalElement },
      
      terminal: {
        write: this.createTrackedMock('terminal.write', (data) => {
          writeHistory.push({ data, timestamp: Date.now() });
          return Promise.resolve();
        }),
        
        onData: this.createTrackedMock('terminal.onData', (callback) => {
          dataCallback = callback;
        }),
        
        focus: this.createTrackedMock('terminal.focus', () => {}),
        resize: this.createTrackedMock('terminal.resize', (cols, rows) => {}),
        clear: this.createTrackedMock('terminal.clear', () => {}),
        dispose: this.createTrackedMock('terminal.dispose', () => {}),
        
        cols: 120,
        rows: 30,
        
        // Internal methods for testing
        _triggerData: (data) => {
          if (dataCallback) {
            dataCallback(data);
          }
        },
        _getWriteHistory: () => writeHistory
      },

      // Terminal utilities
      writeToTerminal: this.createTrackedMock('writeToTerminal', (data) => {}),
      clearTerminal: this.createTrackedMock('clearTerminal', () => {}),
      focusTerminal: this.createTrackedMock('focusTerminal', () => {}),
      destroyTerminal: this.createTrackedMock('destroyTerminal', () => {}),
      
      // State
      isConnected: true,
      isAtBottom: true,
      hasNewOutput: false
    };

    return mock;
  }

  /**
   * Cleanup all test resources
   */
  async cleanup() {
    // Clear timeouts
    this.activeTimeouts.forEach(timeoutId => clearTimeout(timeoutId));
    this.activeTimeouts.clear();

    // Run cleanup functions
    for (const cleanup of this.cleanupFunctions) {
      try {
        await cleanup();
      } catch (error) {
        console.error('Cleanup error:', error);
      }
    }
    this.cleanupFunctions.clear();

    // Clear mocks
    this.activeMocks.clear();
  }

  /**
   * Setup integration test environment
   */
  setupIntegrationTest() {
    const wsClient = this.createAdvancedWebSocketMock();
    const terminal = this.createAdvancedTerminalMock();
    
    return {
      websocketClient: wsClient,
      terminalMock: terminal,
      cleanup: () => this.cleanup()
    };
  }
}

// Create singleton instance
export const integrationHelpers = new IntegrationTestHelpers();

// Helper functions
export const createE2ETestSuite = (name, testFn) => {
  return describe(`E2E: ${name}`, () => {
    let testHelpers;

    beforeEach(async () => {
      testHelpers = new IntegrationTestHelpers();
    });

    afterEach(async () => {
      if (testHelpers) {
        await testHelpers.cleanup();
      }
    });

    testFn(testHelpers);
  });
};

export const expectEventuallyToBeTrue = async (condition, timeout = 3000) => {
  return integrationHelpers.waitForCondition(condition, { timeout });
};