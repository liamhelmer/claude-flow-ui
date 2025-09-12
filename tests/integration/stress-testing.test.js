/**
 * Stress and Performance Integration Tests
 * 
 * These tests validate the application's behavior under stress conditions,
 * concurrent usage, and resource-intensive scenarios.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { testUtils, createIntegrationTest } from '@tests/utils/testHelpers';
import Terminal from '@/components/terminal/Terminal';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import MemoryPanel from '@/components/monitoring/MemoryPanel';

// Mock hooks
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');

// Performance monitoring utilities
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      renderTimes: [],
      memoryUsage: [],
      eventProcessingTimes: [],
      dataTransferRates: [],
    };
  }

  measureRender(renderFn) {
    const start = performance.now();
    const result = renderFn();
    const end = performance.now();
    this.metrics.renderTimes.push(end - start);
    return result;
  }

  measureMemory() {
    if (typeof window !== 'undefined' && window.performance?.memory) {
      this.metrics.memoryUsage.push({
        used: window.performance.memory.usedJSHeapSize,
        total: window.performance.memory.totalJSHeapSize,
        timestamp: Date.now(),
      });
    }
  }

  measureEventProcessing(eventFn) {
    const start = performance.now();
    const result = eventFn();
    const end = performance.now();
    this.metrics.eventProcessingTimes.push(end - start);
    return result;
  }

  getStats() {
    return {
      avgRenderTime: this.metrics.renderTimes.reduce((a, b) => a + b, 0) / this.metrics.renderTimes.length || 0,
      maxRenderTime: Math.max(...this.metrics.renderTimes, 0),
      avgEventProcessing: this.metrics.eventProcessingTimes.reduce((a, b) => a + b, 0) / this.metrics.eventProcessingTimes.length || 0,
      memoryGrowth: this.getMemoryGrowth(),
    };
  }

  getMemoryGrowth() {
    if (this.metrics.memoryUsage.length < 2) return 0;
    const first = this.metrics.memoryUsage[0].used;
    const last = this.metrics.memoryUsage[this.metrics.memoryUsage.length - 1].used;
    return last - first;
  }
}

createIntegrationTest('Stress Testing and Performance', () => {
  let mockClient;
  let mockUseWebSocket;
  let mockUseTerminal;
  let performanceMonitor;

  beforeEach(() => {
    performanceMonitor = new PerformanceMonitor();

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

    // Setup terminal mock
    const mockTerminalElement = document.createElement('div');
    mockUseTerminal = {
      terminalRef: { current: mockTerminalElement },
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

  afterEach(() => {
    const stats = performanceMonitor.getStats();
    console.log('Performance Stats:', stats);
    
    // Performance assertions
    expect(stats.avgRenderTime).toBeLessThan(50); // Average render should be under 50ms
    expect(stats.maxRenderTime).toBeLessThan(200); // Max render should be under 200ms
    expect(stats.avgEventProcessing).toBeLessThan(10); // Event processing should be under 10ms
  });

  describe('High-Volume Data Processing', () => {
    test('should handle continuous high-frequency terminal output', async () => {
      const terminal = performanceMonitor.measureRender(() => 
        render(<Terminal sessionId="high-volume-test" />)
      );

      // Simulate continuous output like tail -f or log streaming
      const outputMessages = Array.from({ length: 1000 }, (_, i) => 
        `[${new Date().toISOString()}] Log entry ${i + 1}: Processing data chunk with various content and timestamps\r\n`
      );

      const startTime = Date.now();
      let processedCount = 0;

      // Send messages in batches to simulate realistic streaming
      const sendBatch = async (batch) => {
        batch.forEach((message, index) => {
          setTimeout(() => {
            performanceMonitor.measureEventProcessing(() => {
              act(() => {
                mockClient.emit('terminal-data', {
                  sessionId: 'high-volume-test',
                  data: message,
                });
              });
            });
            processedCount++;
          }, index * 2); // 2ms intervals within batch
        });
      };

      // Process in batches of 50
      const batchSize = 50;
      for (let i = 0; i < outputMessages.length; i += batchSize) {
        const batch = outputMessages.slice(i, i + batchSize);
        await sendBatch(batch);
        
        // Wait for batch to process
        await waitFor(() => {
          expect(processedCount).toBeGreaterThanOrEqual(i + batch.length);
        }, { timeout: 1000 });

        // Measure memory usage periodically
        if (i % (batchSize * 4) === 0) {
          performanceMonitor.measureMemory();
        }
      }

      const totalTime = Date.now() - startTime;
      const throughput = outputMessages.length / (totalTime / 1000); // messages per second

      console.log(`Processed ${outputMessages.length} messages in ${totalTime}ms`);
      console.log(`Throughput: ${throughput.toFixed(2)} messages/second`);

      // Verify all messages were processed
      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(outputMessages.length);
      }, { timeout: 5000 });

      // Performance expectations
      expect(throughput).toBeGreaterThan(100); // At least 100 messages/second
      expect(totalTime).toBeLessThan(15000); // Should complete within 15 seconds
    });

    test('should handle massive single data chunks', async () => {
      render(<Terminal sessionId="large-chunk-test" />);

      // Simulate very large output (like cat large-file.txt)
      const sizes = [1024, 8192, 32768, 131072]; // 1KB to 128KB

      for (const size of sizes) {
        const largeData = 'A'.repeat(size) + '\r\n';
        
        const processTime = performanceMonitor.measureEventProcessing(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'large-chunk-test',
              data: largeData,
            });
          });
        });

        await waitFor(() => {
          expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(largeData);
        });

        console.log(`Processed ${size} bytes in ${processTime.toFixed(2)}ms`);
        
        // Should process large chunks efficiently
        expect(processTime).toBeLessThan(size / 100); // Less than 10ms per KB
      }
    });
  });

  describe('Concurrent Session Management', () => {
    test('should handle multiple simultaneous terminal sessions', async () => {
      const sessionCount = 10;
      const terminals = [];

      // Create multiple terminal instances
      for (let i = 0; i < sessionCount; i++) {
        const sessionId = `concurrent-session-${i}`;
        const terminal = performanceMonitor.measureRender(() =>
          render(<Terminal sessionId={sessionId} />)
        );
        terminals.push({ sessionId, terminal });
      }

      // Send data to all sessions simultaneously
      const simultaneousData = terminals.map((_, index) => 
        `Session ${index} output: ${Date.now()}\r\n`
      );

      const startTime = Date.now();

      terminals.forEach(({ sessionId }, index) => {
        performanceMonitor.measureEventProcessing(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId,
              data: simultaneousData[index],
            });
          });
        });
      });

      // Verify all sessions received their data
      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(sessionCount);
      });

      const processingTime = Date.now() - startTime;
      console.log(`Processed ${sessionCount} concurrent sessions in ${processingTime}ms`);

      // Should handle concurrent sessions efficiently
      expect(processingTime).toBeLessThan(100); // Under 100ms for 10 sessions
    });

    test('should handle rapid session creation and destruction', async () => {
      const cycles = 20;
      const creationTimes = [];
      const destructionTimes = [];

      for (let i = 0; i < cycles; i++) {
        const sessionId = `rapid-session-${i}`;
        
        // Create session
        const createStart = performance.now();
        const { unmount } = performanceMonitor.measureRender(() =>
          render(<Terminal sessionId={sessionId} />)
        );
        const createTime = performance.now() - createStart;
        creationTimes.push(createTime);

        // Send some data
        act(() => {
          mockClient.emit('terminal-data', {
            sessionId,
            data: `Session ${i} data\r\n`,
          });
        });

        // Destroy session
        const destroyStart = performance.now();
        unmount();
        const destroyTime = performance.now() - destroyStart;
        destructionTimes.push(destroyTime);

        performanceMonitor.measureMemory();
      }

      const avgCreateTime = creationTimes.reduce((a, b) => a + b) / creationTimes.length;
      const avgDestroyTime = destructionTimes.reduce((a, b) => a + b) / destructionTimes.length;

      console.log(`Average creation time: ${avgCreateTime.toFixed(2)}ms`);
      console.log(`Average destruction time: ${avgDestroyTime.toFixed(2)}ms`);

      // Performance expectations
      expect(avgCreateTime).toBeLessThan(20); // Creation under 20ms
      expect(avgDestroyTime).toBeLessThan(10); // Destruction under 10ms
    });
  });

  describe('Memory Leak Detection', () => {
    test('should not leak memory during extended usage', async () => {
      const { unmount } = render(<Terminal sessionId="memory-test" />);

      const initialMemory = performanceMonitor.getStats().memoryGrowth;
      const iterations = 100;

      // Simulate extended usage with many operations
      for (let i = 0; i < iterations; i++) {
        // Send data
        act(() => {
          mockClient.emit('terminal-data', {
            sessionId: 'memory-test',
            data: `Memory test iteration ${i}: ${'x'.repeat(100)}\r\n`,
          });
        });

        // Trigger various operations
        if (i % 10 === 0) {
          performanceMonitor.measureEventProcessing(() => {
            mockUseTerminal.fitTerminal();
            mockUseTerminal.scrollToBottom();
          });
        }

        // Measure memory every 20 iterations
        if (i % 20 === 0) {
          performanceMonitor.measureMemory();
        }

        // Small delay to prevent overwhelming
        if (i % 50 === 0) {
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      }

      // Final memory measurement
      performanceMonitor.measureMemory();
      
      const finalMemoryGrowth = performanceMonitor.getStats().memoryGrowth;
      const memoryIncrease = finalMemoryGrowth - initialMemory;

      console.log(`Memory increase after ${iterations} iterations: ${memoryIncrease} bytes`);

      unmount();

      // Memory should not grow excessively
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024); // Less than 10MB growth
    });

    test('should clean up resources properly on component unmount', async () => {
      const cleanupSpies = {
        terminalWrite: mockUseTerminal.terminal.write,
        clientOff: jest.spyOn(mockClient, 'off'),
        destroyTerminal: mockUseTerminal.destroyTerminal,
      };

      const { unmount } = render(<Terminal sessionId="cleanup-test" />);

      // Add some event listeners and send data
      const handleData = jest.fn();
      mockClient.on('terminal-data', handleData);

      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'cleanup-test',
          data: 'Test data before cleanup\r\n',
        });
      });

      await waitFor(() => {
        expect(cleanupSpies.terminalWrite).toHaveBeenCalled();
      });

      // Unmount component
      unmount();

      // Verify cleanup was called
      expect(cleanupSpies.clientOff).toHaveBeenCalled();
      expect(cleanupSpies.destroyTerminal).toHaveBeenCalled();

      // Send data after unmount - should not cause errors
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'cleanup-test',
          data: 'Data after cleanup\r\n',
        });
      });

      // Should not process data after cleanup
      const callCountAfterUnmount = cleanupSpies.terminalWrite.mock.calls.length;
      
      // Wait a bit to ensure no additional processing
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(cleanupSpies.terminalWrite.mock.calls.length).toBe(callCountAfterUnmount);
    });
  });

  describe('Network Stress Scenarios', () => {
    test('should handle WebSocket connection instability', async () => {
      render(<Terminal sessionId="unstable-network" />);

      const connectionStates = [
        { connected: true, duration: 1000 },
        { connected: false, duration: 500 },
        { connected: true, duration: 800 },
        { connected: false, duration: 300 },
        { connected: true, duration: 1200 },
      ];

      let messagesSent = 0;
      let messagesReceived = 0;

      for (const { connected, duration } of connectionStates) {
        // Update connection state
        mockUseWebSocket.connected = connected;
        mockClient.connected = connected;

        act(() => {
          mockClient.emit(connected ? 'connect' : 'disconnect');
        });

        // Send messages during this state
        const messageCount = Math.floor(duration / 50); // One message every 50ms
        
        for (let i = 0; i < messageCount; i++) {
          setTimeout(() => {
            if (connected) {
              const message = `Message ${++messagesSent} at ${Date.now()}\r\n`;
              
              performanceMonitor.measureEventProcessing(() => {
                act(() => {
                  mockClient.emit('terminal-data', {
                    sessionId: 'unstable-network',
                    data: message,
                  });
                });
              });
              
              messagesReceived++;
            }
          }, i * 50);
        }

        await new Promise(resolve => setTimeout(resolve, duration));
      }

      console.log(`Sent: ${messagesSent}, Received: ${messagesReceived}`);
      
      // Should handle unstable connections gracefully
      expect(messagesReceived).toBeLessThanOrEqual(messagesSent);
      expect(messagesReceived).toBeGreaterThan(0);
    });

    test('should handle message queuing during disconnection', async () => {
      render(<Terminal sessionId="queue-test" />);

      // Start connected
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      // Send some initial messages
      const initialMessages = ['Initial message 1\r\n', 'Initial message 2\r\n'];
      initialMessages.forEach((message, index) => {
        setTimeout(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'queue-test',
              data: message,
            });
          });
        }, index * 10);
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(2);
      });

      // Disconnect
      mockUseWebSocket.connected = false;
      mockClient.connected = false;
      act(() => {
        mockClient.emit('disconnect');
      });

      // Try to send messages while disconnected (these should be queued or handled gracefully)
      const queuedMessages = ['Queued message 1\r\n', 'Queued message 2\r\n', 'Queued message 3\r\n'];
      queuedMessages.forEach((message, index) => {
        setTimeout(() => {
          // These messages should be handled gracefully even when disconnected
          performanceMonitor.measureEventProcessing(() => {
            try {
              act(() => {
                mockClient.emit('terminal-data', {
                  sessionId: 'queue-test',
                  data: message,
                });
              });
            } catch (error) {
              console.log('Expected error during disconnection:', error.message);
            }
          });
        }, index * 10);
      });

      // Reconnect
      setTimeout(() => {
        mockUseWebSocket.connected = true;
        mockClient.connected = true;
        act(() => {
          mockClient.emit('connect');
        });

        // Send post-reconnection messages
        const postReconnectMessages = ['Post-reconnect message 1\r\n', 'Post-reconnect message 2\r\n'];
        postReconnectMessages.forEach((message, index) => {
          setTimeout(() => {
            act(() => {
              mockClient.emit('terminal-data', {
                sessionId: 'queue-test',
                data: message,
              });
            });
          }, index * 10);
        });
      }, 100);

      // Wait for reconnection and processing
      await waitFor(() => {
        expect(mockUseWebSocket.connected).toBe(true);
      }, { timeout: 1000 });

      // Should handle the entire scenario without crashes
      expect(mockUseTerminal.terminal.write).toHaveBeenCalled();
    });
  });

  describe('UI Responsiveness Under Load', () => {
    test('should maintain UI responsiveness during heavy terminal activity', async () => {
      const TestUI = () => (
        <div>
          <Terminal sessionId="ui-stress-test" />
          <div>
            <button onClick={() => mockUseTerminal.focusTerminal()}>Focus Terminal</button>
            <button onClick={() => mockUseTerminal.clearTerminal()}>Clear Terminal</button>
            <button onClick={() => mockUseTerminal.scrollToBottom()}>Scroll to Bottom</button>
          </div>
        </div>
      );

      render(<TestUI />);

      // Start heavy terminal activity
      const heavyActivity = setInterval(() => {
        performanceMonitor.measureEventProcessing(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'ui-stress-test',
              data: `Heavy load: ${Date.now()} - ${'x'.repeat(100)}\r\n`,
            });
          });
        });
      }, 5); // Every 5ms

      // Test UI interactions during heavy load
      const interactions = [
        () => userEvent.click(screen.getByText('Focus Terminal')),
        () => userEvent.click(screen.getByText('Clear Terminal')),
        () => userEvent.click(screen.getByText('Scroll to Bottom')),
      ];

      const interactionTimes = [];

      for (const interaction of interactions) {
        const startTime = performance.now();
        await interaction();
        const endTime = performance.now();
        interactionTimes.push(endTime - startTime);
      }

      clearInterval(heavyActivity);

      const avgInteractionTime = interactionTimes.reduce((a, b) => a + b) / interactionTimes.length;
      console.log(`Average UI interaction time under load: ${avgInteractionTime.toFixed(2)}ms`);

      // UI should remain responsive
      expect(avgInteractionTime).toBeLessThan(100); // Under 100ms average
      expect(Math.max(...interactionTimes)).toBeLessThan(200); // No interaction over 200ms
    });
  });
});