/**
 * Mock WebSocket Client and Server for Testing
 */

export class MockWebSocketClient {
  constructor(url = 'ws://localhost:11237') {
    this.url = url;
    this.connected = false;
    this.connecting = false;
    this.listeners = new Map();
    this.lastData = null;
    this.maxListeners = 10;
    this._destroyed = false;
  }

  connect() {
    return new Promise((resolve) => {
      if (this._destroyed) {
        resolve();
        return;
      }
      this.connecting = true;
      // CRITICAL: Use immediate scheduling for faster, more reliable tests
      setImmediate(() => {
        if (!this._destroyed) {
          this.connected = true;
          this.connecting = false;
          this.emit('connect');
        }
        resolve();
      });
    });
  }

  disconnect() {
    this._destroyed = true;
    this.connected = false;
    this.connecting = false;
    
    // Emit disconnect event before cleanup
    if (!this._destroyed) {
      this.emit('disconnect');
    }
    
    // Clean up all listeners to prevent memory leaks
    this.listeners.clear();
  }

  send(type, data) {
    if (this.connected && !this._destroyed) {
      this.lastData = { type, data };
      // CRITICAL: Use immediate scheduling for faster test execution
      setImmediate(() => {
        if (!this._destroyed) {
          this.emit(type + '-response', { success: true, data });
        }
      });
    } else if (!this.connected && !this._destroyed) {
      // Handle disconnected state gracefully
      console.warn('Attempting to send data while disconnected');
    }
  }

  sendMessage(message) {
    this.send('message', message);
  }

  on(event, handler) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    const eventListeners = this.listeners.get(event);
    
    // Prevent memory leaks by limiting listeners
    if (eventListeners.size >= this.maxListeners) {
      console.warn(`MaxListenersExceededWarning: ${event} has ${eventListeners.size} listeners. Consider using off() to remove listeners.`);
    }
    
    eventListeners.add(handler);
  }

  off(event, handler) {
    if (this.listeners.has(event)) {
      const eventListeners = this.listeners.get(event);
      eventListeners.delete(handler);
      
      // Clean up empty event listeners
      if (eventListeners.size === 0) {
        this.listeners.delete(event);
      }
    }
  }

  emit(event, data) {
    if (this._destroyed) return;
    
    if (this.listeners.has(event)) {
      // Create a copy of listeners to avoid modification during iteration
      const listeners = Array.from(this.listeners.get(event));
      listeners.forEach(handler => {
        try {
          if (!this._destroyed) {
            handler(data);
          }
        } catch (error) {
          console.error('Mock WebSocket event handler error:', error);
        }
      });
    }
  }

  hasReceivedData(expectedData) {
    return JSON.stringify(this.lastData) === JSON.stringify(expectedData);
  }
}

export class MockWebSocketServer {
  constructor() {
    this.clients = new Set();
    this.port = null;
    this.isRunning = false;
  }

  start(port = 11237) {
    this.port = port;
    this.isRunning = true;
    console.log(`Mock WebSocket server started on port ${port}`);
    return Promise.resolve(); // Make it async for consistency
  }

  stop() {
    this.isRunning = false;
    // Properly disconnect all clients before clearing
    this.clients.forEach(client => {
      if (client.disconnect) {
        client.disconnect();
      }
    });
    this.clients.clear();
    console.log('Mock WebSocket server stopped');
    return Promise.resolve(); // Make it async for consistency
  }

  addClient(client) {
    this.clients.add(client);
  }

  removeClient(client) {
    this.clients.delete(client);
  }

  broadcast(event, data) {
    // CRITICAL: Use immediate scheduling to prevent blocking
    setImmediate(() => {
      this.clients.forEach(client => {
        if (client.emit && !client._destroyed) {
          try {
            client.emit(event, data);
          } catch (error) {
            console.warn('Error broadcasting to client:', error);
          }
        }
      });
    });
  }

  simulateTerminalData(sessionId = 'mock-session-1', data = 'Hello, World!\r\n') {
    this.broadcast('terminal-data', { sessionId, data });
  }

  simulateSystemMetrics() {
    const metrics = {
      timestamp: Date.now(),
      cpuUsagePercent: Math.random() * 100,
      memoryUsagePercent: Math.random() * 100,
      diskUsagePercent: Math.random() * 100,
      networkBytesIn: Math.floor(Math.random() * 1024 * 1024),
      networkBytesOut: Math.floor(Math.random() * 1024 * 1024),
      activeConnections: Math.floor(Math.random() * 50),
      uptime: Math.floor(Math.random() * 86400),
    };
    this.broadcast('system-metrics', metrics);
  }

  simulateAgentStatus() {
    const agentData = {
      agents: [
        { id: 'agent-1', status: 'active', cpu: Math.random() * 100 },
        { id: 'agent-2', status: 'idle', cpu: Math.random() * 20 },
      ]
    };
    this.broadcast('agent-status', agentData);
  }

  simulateCommand() {
    const commandData = {
      command: 'test-command',
      status: 'completed',
      output: 'Command executed successfully',
      timestamp: Date.now()
    };
    this.broadcast('command-result', commandData);
  }
}