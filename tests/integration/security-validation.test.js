/**
 * Security Validation Integration Tests
 * 
 * These tests validate security aspects of the terminal application,
 * including input sanitization, XSS prevention, and secure data handling.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { testUtils, createIntegrationTest } from '@tests/utils/testHelpers';
import Terminal from '@/components/terminal/Terminal';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import PromptPanel from '@/components/monitoring/PromptPanel';

// Mock hooks
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');

createIntegrationTest('Security Validation', () => {
  let mockClient;
  let mockUseWebSocket;
  let mockUseTerminal;

  beforeEach(() => {
    // Setup WebSocket mock
    mockClient = testUtils.createMockWebSocketClient();
    mockUseWebSocket = {
      connected: true,
      connecting: false,
      isConnected: true,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: mockClient.on.bind(mockClient),
      off: mockClient.off.bind(mockClient),
    };
    require('@/hooks/useWebSocket').useWebSocket.mockReturnValue(mockUseWebSocket);

    // Setup terminal mock with security tracking
    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      terminal: {
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
        focus: jest.fn(),
        resize: jest.fn(),
        clear: jest.fn(),
        dispose: jest.fn(),
        cols: 120,
        rows: 30,
        // Track what was written for security validation
        _writtenContent: [],
        write: jest.fn().mockImplementation(function(data) {
          this._writtenContent.push(data);
        }),
      },
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      destroyTerminal: jest.fn(),
      scrollToBottom: jest.fn(),
      scrollToTop: jest.fn(),
      isAtBottom: true,
      hasNewOutput: false,
      isConnected: true,
    };
    require('@/hooks/useTerminal').useTerminal.mockReturnValue(mockUseTerminal);
  });

  describe('Input Sanitization and Validation', () => {
    test('should handle potentially malicious terminal input safely', async () => {
      render(<Terminal sessionId="security-test" />);

      const maliciousInputs = [
        // Control character injection attempts
        '\x1b]0;malicious title\x07',
        '\x1b[2J\x1b[H', // Clear screen
        '\x1b[?1049h', // Switch to alternate buffer
        
        // Command injection attempts (should be passed through as they're just terminal data)
        '; rm -rf /',
        '`whoami`',
        '$(cat /etc/passwd)',
        
        // Long strings that could cause buffer overflow
        'A'.repeat(100000),
        
        // Special characters and encoding
        'test\x00null',
        'test\r\ninjection',
        '\\u0000\\u001b',
        
        // Binary data simulation
        Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]).toString(),
      ];

      const onDataCallback = mockUseTerminal.terminal.onData.mock.calls[0]?.[0];

      maliciousInputs.forEach((input, index) => {
        if (onDataCallback) {
          act(() => {
            onDataCallback(input);
          });
        }
      });

      // Verify all inputs were sent (terminal should pass through raw data)
      await waitFor(() => {
        expect(mockUseWebSocket.sendData).toHaveBeenCalledTimes(maliciousInputs.length);
      });

      // Verify no crashes occurred
      expect(mockUseTerminal.terminalRef.current).toBeTruthy();
      
      // The application should handle these gracefully without breaking
      maliciousInputs.forEach((input) => {
        expect(mockUseWebSocket.sendData).toHaveBeenCalledWith('security-test', input);
      });
    });

    test('should validate WebSocket message structure', async () => {
      render(<Terminal sessionId="validation-test" />);

      const malformedMessages = [
        // Missing required fields
        null,
        undefined,
        {},
        { sessionId: 'validation-test' }, // missing data
        { data: 'test' }, // missing sessionId
        
        // Wrong data types
        { sessionId: 123, data: 'test' },
        { sessionId: 'validation-test', data: 123 },
        { sessionId: 'validation-test', data: null },
        { sessionId: 'validation-test', data: undefined },
        
        // Potentially malicious payloads
        { sessionId: 'validation-test', data: '<script>alert("xss")</script>' },
        { sessionId: 'validation-test', data: 'javascript:alert("xss")' },
        { sessionId: 'validation-test', data: 'data:text/html,<script>alert("xss")</script>' },
        
        // Oversized data
        { sessionId: 'validation-test', data: 'A'.repeat(1024 * 1024) }, // 1MB
        
        // Invalid session IDs
        { sessionId: '../../../etc/passwd', data: 'test' },
        { sessionId: '<script>alert(1)</script>', data: 'test' },
        { sessionId: 'validation-test\n\rinjection', data: 'test' },
      ];

      let validMessagesProcessed = 0;
      let crashesOccurred = 0;

      malformedMessages.forEach((message, index) => {
        try {
          act(() => {
            mockClient.emit('terminal-data', message);
          });
          
          // Check if the message was processed (only valid ones should be)
          if (message && message.sessionId === 'validation-test' && typeof message.data === 'string') {
            validMessagesProcessed++;
          }
        } catch (error) {
          crashesOccurred++;
          console.warn(`Message ${index} caused an error:`, error);
        }
      });

      // Should handle malformed messages gracefully without crashing
      expect(crashesOccurred).toBe(0);
      
      // Should only process valid messages
      await waitFor(() => {
        const writeCallCount = mockUseTerminal.terminal.write.mock.calls.length;
        expect(writeCallCount).toBeLessThanOrEqual(validMessagesProcessed + 5); // Allow some margin
      });
    });

    test('should prevent XSS in terminal output', async () => {
      render(<Terminal sessionId="xss-test" />);

      const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<svg onload="alert(1)">',
        '"><script>alert(1)</script>',
        "';alert(1);//",
        '<div onmouseover="alert(1)">hover me</div>',
        '<input onfocus="alert(1)" autofocus>',
        '<details open ontoggle="alert(1)">',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
      ];

      xssPayloads.forEach((payload) => {
        act(() => {
          mockClient.emit('terminal-data', {
            sessionId: 'xss-test',
            data: payload,
          });
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(xssPayloads.length);
      });

      // Verify that XSS payloads are handled safely
      // Terminal should display them as text, not execute them
      xssPayloads.forEach((payload) => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(payload);
      });

      // No JavaScript should have been executed
      // This would need to be verified in a real browser environment
      expect(document.querySelectorAll('script')).toHaveLength(0);
    });
  });

  describe('Data Integrity and Validation', () => {
    test('should maintain data integrity during transmission', async () => {
      render(<Terminal sessionId="integrity-test" />);

      const testData = [
        // Unicode characters
        'Hello 世界 🌍',
        'Emoji test: 👨‍💻 🚀 ⚡',
        
        // Special characters
        'Special chars: !@#$%^&*()_+-=[]{}|;:\'",.<>?',
        
        // Control characters (should be preserved)
        '\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m \x1b[34mBlue\x1b[0m',
        
        // Mixed content
        'Mixed: ASCII + 中文 + العربية + עברית',
        
        // Binary-like content
        Buffer.from('Binary test', 'utf8').toString('base64'),
        
        // Large data chunk
        'Large data: ' + 'X'.repeat(8192),
      ];

      const onDataCallback = mockUseTerminal.terminal.onData.mock.calls[0]?.[0];
      
      // Send data through input
      if (onDataCallback) {
        testData.forEach((data) => {
          act(() => {
            onDataCallback(data);
          });
        });
      }

      // Verify data integrity
      await waitFor(() => {
        expect(mockUseWebSocket.sendData).toHaveBeenCalledTimes(testData.length);
      });

      testData.forEach((data) => {
        expect(mockUseWebSocket.sendData).toHaveBeenCalledWith('integrity-test', data);
      });

      // Test receiving the same data back
      testData.forEach((data) => {
        act(() => {
          mockClient.emit('terminal-data', {
            sessionId: 'integrity-test',
            data: data,
          });
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(testData.length);
      });

      // Verify received data matches sent data
      testData.forEach((data) => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(data);
      });
    });

    test('should handle concurrent access safely', async () => {
      // Create multiple terminal instances
      const sessionIds = ['concurrent-1', 'concurrent-2', 'concurrent-3'];
      const terminals = sessionIds.map(sessionId => ({
        sessionId,
        component: render(<Terminal sessionId={sessionId} />)
      }));

      // Send data to all terminals simultaneously
      const concurrentData = sessionIds.map((sessionId, index) => ({
        sessionId,
        data: `Concurrent data for session ${index}: ${Date.now()}\r\n`,
      }));

      // Simulate race conditions
      concurrentData.forEach(({ sessionId, data }, index) => {
        setTimeout(() => {
          act(() => {
            mockClient.emit('terminal-data', { sessionId, data });
          });
        }, Math.random() * 10); // Random delay up to 10ms
      });

      // Verify each session received its own data
      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(sessionIds.length);
      });

      // Should not have cross-contamination between sessions
      concurrentData.forEach(({ data }) => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(data);
      });
    });
  });

  describe('Resource Protection', () => {
    test('should limit resource consumption', async () => {
      render(<Terminal sessionId="resource-test" />);

      // Test memory consumption limits
      const largeDataArray = Array.from({ length: 1000 }, (_, i) => 
        `Large data chunk ${i}: ${'X'.repeat(1024)}\r\n`
      );

      const startMemory = process.memoryUsage ? process.memoryUsage().heapUsed : 0;

      largeDataArray.forEach((data, index) => {
        setTimeout(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'resource-test',
              data,
            });
          });
        }, index); // 1ms intervals
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(largeDataArray.length);
      }, { timeout: 5000 });

      const endMemory = process.memoryUsage ? process.memoryUsage().heapUsed : 0;
      const memoryGrowth = endMemory - startMemory;

      console.log(`Memory growth: ${memoryGrowth} bytes`);

      // Should not consume excessive memory
      expect(memoryGrowth).toBeLessThan(100 * 1024 * 1024); // Less than 100MB
    });

    test('should handle DoS-like message flooding', async () => {
      render(<Terminal sessionId="dos-test" />);

      const floodCount = 10000;
      const messageSize = 100;
      const startTime = Date.now();

      // Simulate message flooding
      for (let i = 0; i < floodCount; i++) {
        const message = `Flood message ${i}: ${'A'.repeat(messageSize)}\r\n`;
        
        // Don't use setTimeout to simulate true flooding
        act(() => {
          mockClient.emit('terminal-data', {
            sessionId: 'dos-test',
            data: message,
          });
        });
        
        // Yield occasionally to prevent blocking
        if (i % 100 === 0) {
          await new Promise(resolve => setImmediate(resolve));
        }
      }

      const floodTime = Date.now() - startTime;
      console.log(`Processed ${floodCount} messages in ${floodTime}ms`);

      // Should handle flooding without crashing
      expect(mockUseTerminal.terminalRef.current).toBeTruthy();
      
      // Should process messages (may be rate-limited or dropped under extreme load)
      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalled();
      });

      // Performance should remain reasonable
      expect(floodTime).toBeLessThan(30000); // Should complete within 30 seconds
    });
  });

  describe('Session Security', () => {
    test('should isolate sessions properly', async () => {
      const TestIsolation = () => (
        <div>
          <Terminal sessionId="session-a" />
          <Terminal sessionId="session-b" />
        </div>
      );

      render(<TestIsolation />);

      // Send data to session-a
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'session-a',
          data: 'Secret data for session A\r\n',
        });
      });

      // Send data to session-b
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'session-b',
          data: 'Private data for session B\r\n',
        });
      });

      // Try to send data with malicious session ID
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'session-a\r\nsession-b', // Attempted injection
          data: 'This should not appear anywhere\r\n',
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith('Secret data for session A\r\n');
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith('Private data for session B\r\n');
      });

      // Malicious session data should not be processed
      expect(mockUseTerminal.terminal.write).not.toHaveBeenCalledWith('This should not appear anywhere\r\n');
    });

    test('should validate session permissions', async () => {
      render(<Terminal sessionId="auth-test" />);

      // Simulate various session access attempts
      const unauthorizedAttempts = [
        { sessionId: '../session-1', data: 'unauthorized' },
        { sessionId: '/etc/passwd', data: 'unauthorized' },
        { sessionId: 'auth-test\n\rother-session', data: 'unauthorized' },
        { sessionId: '', data: 'unauthorized' },
        { sessionId: null, data: 'unauthorized' },
      ];

      unauthorizedAttempts.forEach((attempt) => {
        act(() => {
          mockClient.emit('terminal-data', attempt);
        });
      });

      // Only valid session should receive legitimate data
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'auth-test',
          data: 'legitimate data\r\n',
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith('legitimate data\r\n');
      });

      // Should not have processed unauthorized attempts
      expect(mockUseTerminal.terminal.write).not.toHaveBeenCalledWith('unauthorized');
    });
  });

  describe('Monitoring Panel Security', () => {
    test('should sanitize monitoring data display', async () => {
      render(<MonitoringSidebar isOpen={true} onToggle={() => {}} />);

      // Simulate potentially malicious monitoring data
      const maliciousMetrics = {
        memoryUsagePercent: '<script>alert("xss")</script>',
        memoryUsed: '"><img src=x onerror=alert(1)>',
        cpuLoad: 'javascript:alert(1)',
        timestamp: Date.now(),
      };

      act(() => {
        mockClient.emit('system-metrics', maliciousMetrics);
      });

      // Should display the data safely without executing scripts
      await waitFor(() => {
        const memoryPanel = screen.getByText(/Memory/);
        expect(memoryPanel).toBeInTheDocument();
      });

      // No script elements should be created
      expect(document.querySelectorAll('script')).toHaveLength(0);
      expect(document.querySelectorAll('img[src="x"]')).toHaveLength(0);
    });

    test('should validate agent status data', async () => {
      render(<MonitoringSidebar isOpen={true} onToggle={() => {}} />);

      const maliciousAgentData = [
        {
          agentId: '<script>alert("xss")</script>',
          state: 'busy',
          currentTask: 'normal task',
        },
        {
          agentId: 'agent-1',
          state: '"><script>alert(1)</script>',
          currentTask: 'normal task',
        },
        {
          agentId: 'agent-2',
          state: 'busy',
          currentTask: '<iframe src="javascript:alert(1)"></iframe>',
        },
        {
          agentId: 'agent-3\n\r<script>',
          state: 'idle',
          currentTask: undefined,
        },
      ];

      maliciousAgentData.forEach((data) => {
        act(() => {
          mockClient.emit('agent-status', data);
        });
      });

      // Should handle the data without executing malicious content
      await waitFor(() => {
        // Component should still be functional
        expect(screen.getByText(/Agents/)).toBeInTheDocument();
      });

      // No malicious scripts should be executed
      expect(document.querySelectorAll('script')).toHaveLength(0);
      expect(document.querySelectorAll('iframe')).toHaveLength(0);
    });
  });
});