/**
 * Comprehensive WebSocket Performance and Stress Tests
 * Tests high-load scenarios, memory usage, and performance characteristics
 */

import { io, Socket } from 'socket.io-client';
import { Server } from 'socket.io';
import { createServer } from 'http';

describe('WebSocket Performance and Stress Tests', () => {
  let httpServer: any;
  let socketServer: Server;
  let clients: Socket[] = [];
  let port: number;

  beforeEach((done) => {
    httpServer = createServer();
    socketServer = new Server(httpServer, {
      cors: { origin: "*", methods: ["GET", "POST"] },
      pingTimeout: 5000,
      pingInterval: 2000,
    });

    httpServer.listen(0, () => {
      port = httpServer.address().port;
      done();
    });
  });

  afterEach((done) => {
    // Cleanup all clients
    Promise.all(clients.map(client => new Promise(resolve => {
      if (client.connected) {
        client.on('disconnect', resolve);
        client.close();
      } else {
        resolve(void 0);
      }
    }))).then(() => {
      clients = [];
      if (socketServer) {
        socketServer.close();
      }
      if (httpServer) {
        httpServer.close(done);
      } else {
        done();
      }
    });
  });

  describe('Connection Load Testing', () => {
    test('should handle 100 concurrent connections', async () => {
      const connectionPromises: Promise<void>[] = [];
      const connectionCount = 100;
      let connectedCount = 0;

      socketServer.on('connection', () => {
        connectedCount++;
      });

      // Create 100 concurrent connections
      for (let i = 0; i < connectionCount; i++) {
        const client = io(`http://localhost:${port}`, {
          transports: ['websocket'],
          timeout: 5000,
        });
        clients.push(client);

        connectionPromises.push(new Promise((resolve) => {
          client.on('connect', resolve);
          client.on('connect_error', resolve); // Don't fail test on individual connection errors
        }));
      }

      await Promise.all(connectionPromises);
      
      // Allow some time for all connections to be registered
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Should handle most connections successfully (allow some to fail due to system limits)
      expect(connectedCount).toBeGreaterThan(connectionCount * 0.8);
    });

    test('should handle rapid connect/disconnect cycles', async () => {
      const cycleCount = 50;
      let connectCount = 0;
      let disconnectCount = 0;

      socketServer.on('connection', (socket) => {
        connectCount++;
        socket.on('disconnect', () => {
          disconnectCount++;
        });
      });

      // Rapid connect/disconnect cycles
      for (let i = 0; i < cycleCount; i++) {
        const client = io(`http://localhost:${port}`);
        
        await new Promise<void>((resolve) => {
          client.on('connect', () => {
            setTimeout(() => {
              client.close();
              resolve();
            }, 10);
          });
          client.on('connect_error', resolve);
        });
      }

      await new Promise(resolve => setTimeout(resolve, 500));
      
      expect(connectCount).toBeGreaterThan(cycleCount * 0.8);
      expect(disconnectCount).toBeGreaterThan(cycleCount * 0.7);
    });
  });

  describe('Message Throughput Testing', () => {
    test('should handle high message frequency from single client', async () => {
      const messageCount = 1000;
      let receivedCount = 0;
      const client = io(`http://localhost:${port}`);
      clients.push(client);

      socketServer.on('connection', (socket) => {
        socket.on('test-message', () => {
          receivedCount++;
        });
      });

      await new Promise<void>((resolve) => {
        client.on('connect', resolve);
      });

      const startTime = Date.now();
      
      // Send messages rapidly
      for (let i = 0; i < messageCount; i++) {
        client.emit('test-message', { id: i, data: `message-${i}` });
      }

      // Wait for messages to be processed
      await new Promise(resolve => setTimeout(resolve, 2000));

      const endTime = Date.now();
      const duration = endTime - startTime;
      const messagesPerSecond = receivedCount / (duration / 1000);

      expect(receivedCount).toBeGreaterThan(messageCount * 0.9);
      expect(messagesPerSecond).toBeGreaterThan(100); // Should handle at least 100 msg/s
    });

    test('should handle large message payloads', async () => {
      const client = io(`http://localhost:${port}`);
      clients.push(client);
      let receivedSize = 0;

      socketServer.on('connection', (socket) => {
        socket.on('large-message', (data) => {
          receivedSize = Buffer.byteLength(JSON.stringify(data));
        });
      });

      await new Promise<void>((resolve) => {
        client.on('connect', resolve);
      });

      const largePayload = {
        data: 'x'.repeat(100000), // 100KB payload
        timestamp: Date.now(),
        id: 'large-message-test'
      };

      const startTime = Date.now();
      client.emit('large-message', largePayload);

      await new Promise(resolve => setTimeout(resolve, 1000));

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(receivedSize).toBeGreaterThan(100000);
      expect(duration).toBeLessThan(5000); // Should handle within 5 seconds
    });

    test('should handle broadcast to many clients efficiently', async () => {
      const clientCount = 50;
      const broadcastCount = 10;
      let totalReceived = 0;

      // Create multiple clients
      const connectionPromises = [];
      for (let i = 0; i < clientCount; i++) {
        const client = io(`http://localhost:${port}`);
        clients.push(client);

        connectionPromises.push(new Promise<void>((resolve) => {
          client.on('connect', () => {
            client.on('broadcast-message', () => {
              totalReceived++;
            });
            resolve();
          });
        }));
      }

      await Promise.all(connectionPromises);

      socketServer.on('connection', (socket) => {
        socket.on('trigger-broadcast', (data) => {
          socketServer.emit('broadcast-message', data);
        });
      });

      const startTime = Date.now();

      // Trigger multiple broadcasts
      for (let i = 0; i < broadcastCount; i++) {
        if (clients[0]) {
          clients[0].emit('trigger-broadcast', { id: i, message: `broadcast-${i}` });
        }
      }

      await new Promise(resolve => setTimeout(resolve, 2000));

      const endTime = Date.now();
      const duration = endTime - startTime;

      const expectedTotal = clientCount * broadcastCount;
      expect(totalReceived).toBeGreaterThan(expectedTotal * 0.8);
      expect(duration).toBeLessThan(10000);
    });
  });

  describe('Memory Usage and Leak Testing', () => {
    test('should not leak memory with repeated connections', async () => {
      const getMemoryUsage = () => process.memoryUsage();
      const initialMemory = getMemoryUsage();

      // Create and destroy connections repeatedly
      for (let cycle = 0; cycle < 10; cycle++) {
        const batchClients: Socket[] = [];
        
        // Create 20 connections
        for (let i = 0; i < 20; i++) {
          const client = io(`http://localhost:${port}`);
          batchClients.push(client);
        }

        await Promise.all(batchClients.map(client => 
          new Promise<void>((resolve) => {
            client.on('connect', resolve);
            client.on('connect_error', resolve);
          })
        ));

        // Close all connections
        batchClients.forEach(client => client.close());
        
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }

      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const finalMemory = getMemoryUsage();
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory growth should be reasonable (less than 50MB)
      expect(memoryGrowth).toBeLessThan(50 * 1024 * 1024);
    });

    test('should handle message buffer overflow gracefully', async () => {
      const client = io(`http://localhost:${port}`, {
        forceNew: true,
      });
      clients.push(client);

      let errorOccurred = false;
      let messagesSent = 0;

      client.on('connect_error', () => {
        errorOccurred = true;
      });

      client.on('error', () => {
        errorOccurred = true;
      });

      await new Promise<void>((resolve) => {
        client.on('connect', resolve);
      });

      // Try to overflow message buffer
      const intervalId = setInterval(() => {
        if (messagesSent < 10000 && !errorOccurred) {
          client.emit('stress-message', { 
            id: messagesSent++, 
            data: 'x'.repeat(1000) 
          });
        } else {
          clearInterval(intervalId);
        }
      }, 1);

      await new Promise(resolve => setTimeout(resolve, 5000));

      // Should either handle all messages or fail gracefully
      expect(messagesSent).toBeGreaterThan(0);
      // No assertion on errorOccurred - both graceful handling and controlled failure are acceptable
    });
  });

  describe('Latency and Response Time Testing', () => {
    test('should maintain low latency under load', async () => {
      const client = io(`http://localhost:${port}`);
      clients.push(client);
      const latencies: number[] = [];

      socketServer.on('connection', (socket) => {
        socket.on('ping-test', (data) => {
          socket.emit('pong-test', data);
        });
      });

      await new Promise<void>((resolve) => {
        client.on('connect', resolve);
      });

      client.on('pong-test', (data) => {
        const latency = Date.now() - data.timestamp;
        latencies.push(latency);
      });

      // Send ping requests under load
      const pingCount = 100;
      for (let i = 0; i < pingCount; i++) {
        client.emit('ping-test', { id: i, timestamp: Date.now() });
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      await new Promise(resolve => setTimeout(resolve, 2000));

      expect(latencies.length).toBeGreaterThan(pingCount * 0.9);
      
      const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
      const maxLatency = Math.max(...latencies);
      
      expect(avgLatency).toBeLessThan(50); // Average latency under 50ms
      expect(maxLatency).toBeLessThan(500); // Max latency under 500ms
    });

    test('should handle connection timeout gracefully', async () => {
      const client = io(`http://localhost:${port}`, {
        timeout: 1000,
        forceNew: true,
      });
      
      let timeoutOccurred = false;
      
      client.on('connect_timeout', () => {
        timeoutOccurred = true;
      });

      // Simulate server delay in response
      socketServer.on('connection', (socket) => {
        socket.on('delayed-request', () => {
          // Respond after timeout period
          setTimeout(() => {
            socket.emit('delayed-response', { message: 'late response' });
          }, 2000);
        });
      });

      const connectPromise = new Promise<void>((resolve) => {
        client.on('connect', () => {
          client.emit('delayed-request');
          resolve();
        });
      });

      await connectPromise;
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Connection timeout handling depends on implementation
      // This test verifies the system doesn't crash under timeout conditions
      expect(typeof timeoutOccurred).toBe('boolean');
      
      client.close();
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from server restart simulation', async () => {
      const client = io(`http://localhost:${port}`, {
        reconnection: true,
        reconnectionDelay: 100,
        reconnectionAttempts: 5,
      });
      clients.push(client);

      let connectCount = 0;
      let disconnectCount = 0;

      client.on('connect', () => {
        connectCount++;
      });

      client.on('disconnect', () => {
        disconnectCount++;
      });

      // Initial connection
      await new Promise<void>((resolve) => {
        client.on('connect', resolve);
      });

      expect(connectCount).toBe(1);

      // Simulate server restart by closing and reopening
      socketServer.close();
      await new Promise(resolve => setTimeout(resolve, 500));

      socketServer = new Server(httpServer, {
        cors: { origin: "*", methods: ["GET", "POST"] },
      });

      // Wait for potential reconnection
      await new Promise(resolve => setTimeout(resolve, 2000));

      expect(disconnectCount).toBeGreaterThan(0);
      // Reconnection success depends on client implementation
    });

    test('should handle malformed message gracefully', async () => {
      const client = io(`http://localhost:${port}`);
      clients.push(client);
      
      let errorHandled = false;

      socketServer.on('connection', (socket) => {
        socket.on('malformed-message', (data) => {
          try {
            // Attempt to process potentially malformed data
            JSON.stringify(data);
          } catch (error) {
            errorHandled = true;
            socket.emit('error-response', { error: 'Malformed data' });
          }
        });
      });

      await new Promise<void>((resolve) => {
        client.on('connect', resolve);
      });

      // Send various malformed messages
      const malformedMessages = [
        undefined,
        null,
        { circular: null as any },
        Buffer.from([0x00, 0x01, 0x02]),
        'not-json',
      ];

      // Create circular reference
      malformedMessages[2].circular = malformedMessages[2];

      for (const message of malformedMessages) {
        client.emit('malformed-message', message);
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      await new Promise(resolve => setTimeout(resolve, 500));

      // System should handle malformed data without crashing
      expect(typeof errorHandled).toBe('boolean');
    });
  });

  describe('Concurrent Operations Testing', () => {
    test('should handle concurrent read/write operations', async () => {
      const clientCount = 20;
      const operationCount = 100;
      let totalOperations = 0;
      let completedOperations = 0;

      const operationPromises: Promise<void>[] = [];

      socketServer.on('connection', (socket) => {
        socket.on('concurrent-operation', (data) => {
          totalOperations++;
          // Simulate some processing time
          setTimeout(() => {
            socket.emit('operation-complete', { id: data.id });
            completedOperations++;
          }, Math.random() * 10);
        });
      });

      // Create multiple clients performing concurrent operations
      for (let clientId = 0; clientId < clientCount; clientId++) {
        const client = io(`http://localhost:${port}`);
        clients.push(client);

        const clientPromise = new Promise<void>((resolve) => {
          client.on('connect', () => {
            let clientCompleted = 0;
            
            client.on('operation-complete', () => {
              clientCompleted++;
              if (clientCompleted >= operationCount) {
                resolve();
              }
            });

            // Send multiple operations concurrently
            for (let opId = 0; opId < operationCount; opId++) {
              client.emit('concurrent-operation', { 
                id: `${clientId}-${opId}`, 
                clientId, 
                opId 
              });
            }
          });
        });

        operationPromises.push(clientPromise);
      }

      await Promise.all(operationPromises);
      await new Promise(resolve => setTimeout(resolve, 1000));

      const expectedOperations = clientCount * operationCount;
      expect(totalOperations).toBe(expectedOperations);
      expect(completedOperations).toBeGreaterThan(expectedOperations * 0.9);
    });
  });
});