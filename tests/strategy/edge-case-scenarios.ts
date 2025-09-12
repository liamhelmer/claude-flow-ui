/**
 * Edge Case Testing Scenarios for Claude UI Terminal Application
 * 
 * Comprehensive edge case testing strategies covering boundary conditions,
 * error states, and resilience testing
 */

import { MockWebSocket, MockTerminal, ErrorSimulator } from './mock-factories';

// ============================================================================
// WebSocket Edge Cases
// ============================================================================

export class WebSocketEdgeCases {
  
  /**
   * Test WebSocket connection under extreme network conditions
   */
  static async testNetworkResilience() {
    const scenarios = [
      {
        name: 'High latency connection (5s)',
        setup: () => new MockWebSocket('ws://localhost:8080', { simulateLatency: 5000 })
      },
      {
        name: 'Intermittent connection drops',
        setup: () => {
          const ws = new MockWebSocket('ws://localhost:8080');
          // Simulate random disconnections
          const interval = setInterval(() => {
            if (Math.random() < 0.3) {
              ws.simulateNetworkInterruption(1000);
            }
          }, 2000);
          return { ws, cleanup: () => clearInterval(interval) };
        }
      },
      {
        name: 'Server becomes unresponsive',
        setup: () => {
          const ws = new MockWebSocket('ws://localhost:8080');
          // Stop responding to messages after 3 seconds
          setTimeout(() => {
            ws.simulateConnectionError();
          }, 3000);
          return ws;
        }
      }
    ];

    return scenarios;
  }

  /**
   * Test WebSocket message handling edge cases
   */
  static getMessageEdgeCases() {
    return [
      {
        name: 'Empty message',
        message: ''
      },
      {
        name: 'Malformed JSON',
        message: '{"invalid": json}'
      },
      {
        name: 'Very large message (1MB)',
        message: JSON.stringify({ data: 'x'.repeat(1024 * 1024) })
      },
      {
        name: 'Binary data',
        message: new ArrayBuffer(1024)
      },
      {
        name: 'Unicode characters',
        message: JSON.stringify({ text: '🚀 Terminal 测试 العربية' })
      },
      {
        name: 'Null values',
        message: JSON.stringify({ sessionId: null, data: undefined })
      },
      {
        name: 'Circular reference (should fail gracefully)',
        message: (() => {
          const obj: any = { data: 'test' };
          obj.circular = obj;
          return obj;
        })()
      }
    ];
  }

  /**
   * Test concurrent WebSocket operations
   */
  static async testConcurrentOperations() {
    const ws = new MockWebSocket('ws://localhost:8080');
    
    const operations = [
      // Rapid message sending
      async () => {
        for (let i = 0; i < 100; i++) {
          ws.send(JSON.stringify({ type: 'data', index: i }));
        }
      },
      // Connection state changes
      async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
        ws.close();
        await new Promise(resolve => setTimeout(resolve, 100));
        ws.simulateConnection();
      },
      // Event listener management
      async () => {
        for (let i = 0; i < 50; i++) {
          const handler = () => {};
          ws.addEventListener('message', handler);
          ws.removeEventListener('message', handler);
        }
      }
    ];

    return Promise.all(operations);
  }
}

// ============================================================================
// Terminal Edge Cases
// ============================================================================

export class TerminalEdgeCases {
  
  /**
   * Test terminal with extreme dimensions
   */
  static getTerminalDimensionEdgeCases() {
    return [
      {
        name: 'Minimum dimensions',
        cols: 1,
        rows: 1
      },
      {
        name: 'Maximum practical dimensions',
        cols: 500,
        rows: 200
      },
      {
        name: 'Zero dimensions (should handle gracefully)',
        cols: 0,
        rows: 0
      },
      {
        name: 'Negative dimensions (should handle gracefully)',
        cols: -10,
        rows: -5
      },
      {
        name: 'Very large dimensions',
        cols: 10000,
        rows: 10000
      }
    ];
  }

  /**
   * Test terminal input edge cases
   */
  static getTerminalInputEdgeCases() {
    return [
      {
        name: 'Empty input',
        input: ''
      },
      {
        name: 'Very long single line (10KB)',
        input: 'x'.repeat(10 * 1024)
      },
      {
        name: 'Control characters',
        input: '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
      },
      {
        name: 'ANSI escape sequences',
        input: '\x1b[31mRed text\x1b[0m\x1b[1mBold\x1b[0m'
      },
      {
        name: 'Unicode characters',
        input: '🎯 Testing unicode: 测试 العربية ñáéíóú'
      },
      {
        name: 'Null bytes',
        input: 'Before\x00After'
      },
      {
        name: 'Rapid input sequence',
        input: Array.from({ length: 1000 }, (_, i) => `line${i}\n`).join('')
      },
      {
        name: 'Binary data as string',
        input: String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i))
      }
    ];
  }

  /**
   * Test terminal output edge cases
   */
  static getTerminalOutputEdgeCases() {
    return [
      {
        name: 'Scrollback buffer overflow',
        output: Array.from({ length: 10000 }, (_, i) => `Line ${i + 1}\n`).join('')
      },
      {
        name: 'Mixed content types',
        output: 'Text\x1b[31mColor\x1b[0m🎯Unicode\x00Binary\n'
      },
      {
        name: 'Malformed ANSI sequences',
        output: '\x1b[999mInvalid\x1b[incomplete'
      },
      {
        name: 'Cursor positioning edge cases',
        output: '\x1b[999;999HMove to impossible position\x1b[0;0H'
      },
      {
        name: 'Screen clearing operations',
        output: '\x1b[2J\x1b[H\x1b[3J'
      }
    ];
  }

  /**
   * Test terminal performance under stress
   */
  static async testTerminalPerformance() {
    const terminal = new MockTerminal();
    const startTime = performance.now();
    
    // Test scenarios
    const scenarios = [
      {
        name: 'High-frequency writes',
        test: () => {
          for (let i = 0; i < 10000; i++) {
            terminal.write(`Message ${i}\n`);
          }
        }
      },
      {
        name: 'Large single write',
        test: () => {
          terminal.write('x'.repeat(1024 * 1024)); // 1MB
        }
      },
      {
        name: 'Rapid resize operations',
        test: () => {
          for (let i = 0; i < 100; i++) {
            terminal.simulateResize(80 + i, 24 + i);
          }
        }
      }
    ];

    const results = [];
    for (const scenario of scenarios) {
      const scenarioStart = performance.now();
      scenario.test();
      const scenarioEnd = performance.now();
      
      results.push({
        name: scenario.name,
        duration: scenarioEnd - scenarioStart
      });
    }

    return {
      totalDuration: performance.now() - startTime,
      scenarios: results
    };
  }
}

// ============================================================================
// State Management Edge Cases
// ============================================================================

export class StateManagementEdgeCases {
  
  /**
   * Test store operations under extreme conditions
   */
  static getStoreEdgeCases() {
    return [
      {
        name: 'Maximum session count',
        operation: (store: any) => {
          // Add 1000 sessions
          for (let i = 0; i < 1000; i++) {
            store.addSession({
              id: `session-${i}`,
              name: `Terminal ${i}`,
              isActive: i === 0,
              lastActivity: new Date()
            });
          }
        }
      },
      {
        name: 'Rapid state updates',
        operation: async (store: any) => {
          // Perform 1000 rapid updates
          for (let i = 0; i < 1000; i++) {
            store.setActiveSession(`session-${i % 10}`);
            store.toggleSidebar();
            await new Promise(resolve => setTimeout(resolve, 1));
          }
        }
      },
      {
        name: 'Concurrent modifications',
        operation: async (store: any) => {
          const operations = [
            () => store.addSession({ id: 'concurrent-1', name: 'Test 1', isActive: true, lastActivity: new Date() }),
            () => store.addSession({ id: 'concurrent-2', name: 'Test 2', isActive: true, lastActivity: new Date() }),
            () => store.removeSession('concurrent-1'),
            () => store.updateSession('concurrent-2', { name: 'Updated' })
          ];
          
          await Promise.all(operations.map(op => op()));
        }
      },
      {
        name: 'Invalid data handling',
        operation: (store: any) => {
          // Try to add sessions with invalid data
          store.addSession(null);
          store.addSession({ id: null, name: undefined });
          store.setActiveSession('nonexistent-session');
          store.updateSession('invalid-id', { name: 'test' });
        }
      }
    ];
  }

  /**
   * Test memory usage patterns
   */
  static async testMemoryUsage() {
    const measurements = [];
    
    // Measure baseline
    const baseline = (performance as any).memory ? (performance as any).memory.usedJSHeapSize : 0;
    measurements.push({ phase: 'baseline', memory: baseline });

    // Create large state
    const sessions = Array.from({ length: 10000 }, (_, i) => ({
      id: `session-${i}`,
      name: `Terminal ${i}`,
      isActive: i === 0,
      lastActivity: new Date(),
      history: Array.from({ length: 1000 }, (_, j) => `Command ${j}`)
    }));

    const afterCreation = (performance as any).memory ? (performance as any).memory.usedJSHeapSize : 0;
    measurements.push({ phase: 'after_creation', memory: afterCreation });

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    const afterGC = (performance as any).memory ? (performance as any).memory.usedJSHeapSize : 0;
    measurements.push({ phase: 'after_gc', memory: afterGC });

    return measurements;
  }
}

// ============================================================================
// Error Handling Edge Cases
// ============================================================================

export class ErrorHandlingEdgeCases {
  
  /**
   * Test error boundary with various error types
   */
  static getErrorBoundaryEdgeCases() {
    return [
      {
        name: 'Synchronous error in render',
        trigger: () => {
          throw new Error('Render error');
        }
      },
      {
        name: 'Asynchronous error in effect',
        trigger: async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          throw new Error('Async effect error');
        }
      },
      {
        name: 'Network error',
        trigger: () => {
          throw ErrorSimulator.createNetworkError();
        }
      },
      {
        name: 'WebSocket error',
        trigger: () => {
          throw ErrorSimulator.createWebSocketError(1006);
        }
      },
      {
        name: 'Parser error',
        trigger: () => {
          throw ErrorSimulator.createParsingError();
        }
      },
      {
        name: 'Timeout error',
        trigger: () => {
          throw ErrorSimulator.createTimeoutError();
        }
      },
      {
        name: 'Null reference error',
        trigger: () => {
          const obj: any = null;
          return obj.property;
        }
      },
      {
        name: 'Type error',
        trigger: () => {
          const num: any = 'not a number';
          return num.toFixed(2);
        }
      }
    ];
  }

  /**
   * Test error recovery scenarios
   */
  static getErrorRecoveryScenarios() {
    return [
      {
        name: 'Recover from WebSocket disconnection',
        scenario: async (mockWs: MockWebSocket) => {
          mockWs.simulateConnectionError();
          await new Promise(resolve => setTimeout(resolve, 1000));
          mockWs.simulateConnection();
        }
      },
      {
        name: 'Recover from terminal crash',
        scenario: async (mockTerminal: MockTerminal) => {
          mockTerminal.dispose();
          await new Promise(resolve => setTimeout(resolve, 500));
          // Simulate recreation
          const newTerminal = new MockTerminal();
          return newTerminal;
        }
      },
      {
        name: 'Recover from state corruption',
        scenario: async (store: any) => {
          // Corrupt state
          store.setState({ terminalSessions: null, activeSessionId: 'invalid' });
          await new Promise(resolve => setTimeout(resolve, 100));
          // Reset to valid state
          store.clearSessions();
        }
      }
    ];
  }
}

// ============================================================================
// Performance Edge Cases
// ============================================================================

export class PerformanceEdgeCases {
  
  /**
   * Test application performance under extreme load
   */
  static async testExtremeLload() {
    const scenarios = [
      {
        name: 'High message frequency',
        test: async () => {
          const mockWs = new MockWebSocket('ws://localhost:8080');
          const startTime = performance.now();
          
          // Send 10,000 messages rapidly
          for (let i = 0; i < 10000; i++) {
            mockWs.simulateServerMessage({ type: 'output', data: `Message ${i}` });
          }
          
          return {
            duration: performance.now() - startTime,
            messagesPerSecond: 10000 / ((performance.now() - startTime) / 1000)
          };
        }
      },
      {
        name: 'Large terminal buffer',
        test: async () => {
          const mockTerminal = new MockTerminal();
          const startTime = performance.now();
          
          // Write 1MB of data
          const largeData = 'x'.repeat(1024 * 1024);
          mockTerminal.write(largeData);
          
          return {
            duration: performance.now() - startTime,
            dataSize: largeData.length
          };
        }
      },
      {
        name: 'Massive session count',
        test: async () => {
          const startTime = performance.now();
          
          // Create 10,000 sessions
          const sessions = Array.from({ length: 10000 }, (_, i) => ({
            id: `session-${i}`,
            name: `Terminal ${i}`,
            isActive: i === 0,
            lastActivity: new Date()
          }));
          
          return {
            duration: performance.now() - startTime,
            sessionCount: sessions.length
          };
        }
      }
    ];

    const results = [];
    for (const scenario of scenarios) {
      try {
        const result = await scenario.test();
        results.push({ name: scenario.name, ...result, success: true });
      } catch (error) {
        results.push({ 
          name: scenario.name, 
          error: error instanceof Error ? error.message : String(error), 
          success: false 
        });
      }
    }

    return results;
  }
}

// ============================================================================
// Security Edge Cases
// ============================================================================

export class SecurityEdgeCases {
  
  /**
   * Test input sanitization edge cases
   */
  static getInputSanitizationTests() {
    return [
      {
        name: 'XSS attempt in terminal output',
        input: '<script>alert("XSS")</script>',
        expected: '&lt;script&gt;alert("XSS")&lt;/script&gt;'
      },
      {
        name: 'SQL injection attempt',
        input: "'; DROP TABLE users; --",
        expected: "''; DROP TABLE users; --" // Should be escaped
      },
      {
        name: 'Command injection attempt',
        input: 'ls; rm -rf /',
        expected: 'ls; rm -rf /' // Should be treated as literal text
      },
      {
        name: 'Path traversal attempt',
        input: '../../../etc/passwd',
        expected: '../../../etc/passwd' // Should be treated as literal text
      },
      {
        name: 'Malicious ANSI sequences',
        input: '\x1b]0;evil\x07\x1b[2J\x1b[H',
        expected: null // Should be sanitized or escaped
      },
      {
        name: 'Unicode normalization attack',
        input: '\u0041\u0301', // A with combining acute accent
        expected: 'Á' // Should be normalized
      }
    ];
  }

  /**
   * Test authorization edge cases
   */
  static getAuthorizationTests() {
    return [
      {
        name: 'Access without valid session',
        scenario: async () => {
          // Attempt to access terminal without authentication
          const mockWs = new MockWebSocket('ws://localhost:8080');
          mockWs.send(JSON.stringify({ type: 'create', sessionId: 'invalid' }));
        }
      },
      {
        name: 'Session hijacking attempt',
        scenario: async () => {
          // Attempt to access someone else's session
          const mockWs = new MockWebSocket('ws://localhost:8080');
          mockWs.send(JSON.stringify({ 
            type: 'data', 
            sessionId: 'another-users-session-id',
            data: 'malicious command'
          }));
        }
      },
      {
        name: 'Rate limiting bypass attempt',
        scenario: async () => {
          const mockWs = new MockWebSocket('ws://localhost:8080');
          // Send 10,000 rapid requests
          for (let i = 0; i < 10000; i++) {
            mockWs.send(JSON.stringify({ type: 'create' }));
          }
        }
      }
    ];
  }
}

// ============================================================================
// Browser Compatibility Edge Cases
// ============================================================================

export class BrowserCompatibilityEdgeCases {
  
  /**
   * Test WebSocket API differences across browsers
   */
  static getBrowserSpecificTests() {
    return [
      {
        name: 'Safari WebSocket quirks',
        test: () => {
          // Safari has specific behaviors with WebSocket readyState
          const ws = new MockWebSocket('ws://localhost:8080');
          return ws.readyState;
        }
      },
      {
        name: 'Firefox memory management',
        test: () => {
          // Firefox handles large WebSocket messages differently
          const largeMessage = 'x'.repeat(64 * 1024 * 1024); // 64MB
          return largeMessage.length;
        }
      },
      {
        name: 'Chrome DevTools integration',
        test: () => {
          // Chrome has specific DevTools behaviors
          const ws = new MockWebSocket('ws://localhost:8080');
          return ws.url;
        }
      },
      {
        name: 'Edge legacy compatibility',
        test: () => {
          // Edge legacy has specific WebSocket limitations
          const ws = new MockWebSocket('ws://localhost:8080');
          return typeof ws.addEventListener === 'function';
        }
      }
    ];
  }
}

// ============================================================================
// Accessibility Edge Cases
// ============================================================================

export class AccessibilityEdgeCases {
  
  /**
   * Test screen reader compatibility edge cases
   */
  static getScreenReaderTests() {
    return [
      {
        name: 'Rapid terminal output announcement',
        scenario: 'High-frequency terminal output should be debounced for screen readers'
      },
      {
        name: 'Color-only information',
        scenario: 'Error states indicated only by color should have text alternatives'
      },
      {
        name: 'Dynamic content updates',
        scenario: 'Live region updates should be properly announced'
      },
      {
        name: 'Keyboard trap in terminal',
        scenario: 'Terminal should not create keyboard traps that prevent navigation'
      },
      {
        name: 'Focus management during errors',
        scenario: 'Error states should move focus to error messages appropriately'
      }
    ];
  }

  /**
   * Test keyboard navigation edge cases
   */
  static getKeyboardNavigationTests() {
    return [
      {
        name: 'Tab order with dynamic content',
        scenario: 'Tab order should remain logical when terminals are added/removed'
      },
      {
        name: 'Terminal focus during modal dialogs',
        scenario: 'Modal dialogs should not break terminal focus management'
      },
      {
        name: 'Multiple terminal focus management',
        scenario: 'Only one terminal should be focused at a time'
      }
    ];
  }
}

