/**
 * WebSocket Performance Tests
 * Tests performance characteristics and memory usage of WebSocket client
 */

import WebSocketClient from '@/lib/websocket/client';
import type { WebSocketMessage } from '@/types';

describe('WebSocket Performance Tests', () => {
  let client: WebSocketClient;
  let performanceObserver: PerformanceObserver;
  const performanceEntries: PerformanceEntry[] = [];

  beforeAll(() => {
    // Mock performance observer for testing
    performanceObserver = new PerformanceObserver((list) => {
      performanceEntries.push(...list.getEntries());
    });
    
    // Mock high-resolution timing
    global.performance.mark = jest.fn();
    global.performance.measure = jest.fn();
    global.performance.getEntriesByType = jest.fn(() => performanceEntries);
  });

  beforeEach(() => {
    client = new WebSocketClient();
    performanceEntries.length = 0;
  });

  afterEach(() => {
    if (client && client.disconnect) {
      client.disconnect();
    }
    jest.clearAllTimers();
  });

  describe('Connection Performance', () => {
    it('should connect within acceptable time limit', async () => {
      const startTime = performance.now();
      
      await client.connect();
      
      const endTime = performance.now();
      const connectionTime = endTime - startTime;
      
      // Connection should complete within 100ms in test environment
      expect(connectionTime).toBeLessThan(100);
    });

    it('should handle rapid connection/disconnection cycles', async () => {
      const cycles = 10;
      const timings: number[] = [];

      for (let i = 0; i < cycles; i++) {
        const start = performance.now();
        
        await client.connect();
        client.disconnect();
        
        const end = performance.now();
        timings.push(end - start);
      }

      // Average cycle time should be reasonable
      const averageTime = timings.reduce((sum, time) => sum + time, 0) / cycles;
      expect(averageTime).toBeLessThan(50);
    });

    it('should not leak memory with multiple connections', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Create and destroy multiple clients
      for (let i = 0; i < 50; i++) {
        const testClient = new WebSocketClient();
        await testClient.connect();
        testClient.disconnect();
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be minimal (<10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });

  describe('Message Throughput', () => {
    beforeEach(async () => {
      await client.connect();
    });

    it('should handle high-frequency message sending', () => {
      const messageCount = 1000;
      const messages: WebSocketMessage[] = [];
      
      const startTime = performance.now();
      
      for (let i = 0; i < messageCount; i++) {
        const message: WebSocketMessage = {
          type: 'data',
          sessionId: 'test-session',
          data: `Message ${i}`,
          timestamp: Date.now()
        };
        
        client.sendMessage(message);
        messages.push(message);
      }
      
      const endTime = performance.now();
      const throughputTime = endTime - startTime;
      const messagesPerMs = messageCount / throughputTime;
      
      // Should handle at least 10 messages per millisecond
      expect(messagesPerMs).toBeGreaterThan(10);
    });

    it('should maintain performance with large payloads', () => {
      const largeData = 'x'.repeat(1024 * 100); // 100KB payload
      const iterations = 10;
      
      const startTime = performance.now();
      
      for (let i = 0; i < iterations; i++) {
        client.sendMessage({
          type: 'data',
          sessionId: 'test-session',
          data: largeData,
          timestamp: Date.now()
        });
      }
      
      const endTime = performance.now();
      const totalTime = endTime - startTime;
      
      // Should handle large payloads within reasonable time
      expect(totalTime).toBeLessThan(100);
    });
  });

  describe('Event Listener Performance', () => {
    beforeEach(async () => {
      await client.connect();
    });

    it('should efficiently manage multiple event listeners', () => {
      const listenerCount = 100;
      const callbacks: Array<() => void> = [];
      
      const startTime = performance.now();
      
      // Add listeners
      for (let i = 0; i < listenerCount; i++) {
        const callback = jest.fn();
        callbacks.push(callback);
        client.on('test-event', callback);
      }
      
      const addTime = performance.now() - startTime;
      
      // Emit event to all listeners
      const emitStart = performance.now();
      (client as any).emit('test-event', { test: 'data' });
      const emitTime = performance.now() - emitStart;
      
      // Remove listeners
      const removeStart = performance.now();
      callbacks.forEach((callback, index) => {
        client.off('test-event', callback);
      });
      const removeTime = performance.now() - removeStart;
      
      // All operations should be fast
      expect(addTime).toBeLessThan(50);
      expect(emitTime).toBeLessThan(10);
      expect(removeTime).toBeLessThan(50);
      
      // All callbacks should have been called
      callbacks.forEach(callback => {
        expect(callback).toHaveBeenCalledTimes(1);
      });
    });

    it('should prevent memory leaks with listener warnings', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Add more than 10 listeners (warning threshold)
      for (let i = 0; i < 12; i++) {
        client.on('test-event', jest.fn());
      }
      
      // Should have issued memory leak warning
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/MaxListenersExceededWarning.*test-event.*12.*listeners/)
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('Stress Testing', () => {
    it('should handle concurrent operations without degradation', async () => {
      const concurrentOperations = 50;
      const operations: Promise<void>[] = [];
      
      const startTime = performance.now();
      
      // Create concurrent connect/send/disconnect operations
      for (let i = 0; i < concurrentOperations; i++) {
        const operation = async () => {
          const testClient = new WebSocketClient();
          await testClient.connect();
          
          testClient.sendMessage({
            type: 'data',
            sessionId: `session-${i}`,
            data: `Data for operation ${i}`,
            timestamp: Date.now()
          });
          
          testClient.disconnect();
        };
        
        operations.push(operation());
      }
      
      await Promise.all(operations);
      
      const totalTime = performance.now() - startTime;
      
      // All concurrent operations should complete within reasonable time
      expect(totalTime).toBeLessThan(500);
    });

    it('should maintain stable performance under load', async () => {
      await client.connect();
      
      const iterations = 5;
      const messagesPerIteration = 100;
      const timings: number[] = [];
      
      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        
        // Send batch of messages
        for (let j = 0; j < messagesPerIteration; j++) {
          client.sendMessage({
            type: 'data',
            sessionId: 'load-test',
            data: `Batch ${i}, Message ${j}`,
            timestamp: Date.now()
          });
        }
        
        const endTime = performance.now();
        timings.push(endTime - startTime);
        
        // Small delay between batches
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      
      // Performance should be consistent across iterations
      const maxTime = Math.max(...timings);
      const minTime = Math.min(...timings);
      const variance = maxTime - minTime;
      
      // Variance should be less than 50% of minimum time
      expect(variance).toBeLessThan(minTime * 0.5);
    });
  });

  describe('Resource Cleanup', () => {
    it('should properly clean up resources on disconnect', async () => {
      await client.connect();
      
      // Add listeners
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      client.on('test-event-1', callback1);
      client.on('test-event-2', callback2);
      
      // Verify listeners are active
      expect((client as any).listeners.size).toBe(2);
      
      // Disconnect should clean up everything
      client.disconnect();
      
      // All listeners should be cleared
      expect((client as any).listeners.size).toBe(0);
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });

    it('should handle cleanup of partial initialization', () => {
      // Test cleanup when connection fails midway
      const testClient = new WebSocketClient();
      
      // Simulate partial setup
      testClient.on('test-event', jest.fn());
      expect((testClient as any).listeners.size).toBe(1);
      
      // Disconnect should still clean up properly
      testClient.disconnect();
      expect((testClient as any).listeners.size).toBe(0);
    });
  });
});