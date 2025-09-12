/**
 * Enhanced Mock WebSocket implementation for integration tests
 * 
 * Provides better session management, error handling, and async support
 */

// Enhanced Mock WebSocket Server with better session management
class EnhancedMockWebSocketServer {
  constructor() {
    this.clients = new Set();
    this.messageHandlers = new Map();
    this.isRunning = false;
    this.sessions = new Map();
    this.eventHistory = [];
  }
  
  start(port = 11237) {
    this.port = port;
    this.isRunning = true;
    console.log(`Enhanced Mock WebSocket server started on port ${port}`);
  }
  
  stop() {
    this.clients.clear();
    this.messageHandlers.clear();
    this.sessions.clear();
    this.eventHistory = [];
    this.isRunning = false;
  }
  
  addClient(client) {
    this.clients.add(client);
    
    // Simulate connection events with better timing
    setTimeout(() => {
      if (client.connected) {
        const sessionId = 'mock-session-1';
        
        // Create initial session
        this.sessions.set(sessionId, {
          id: sessionId,
          name: 'Terminal 1',
          created: Date.now(),
          active: true
        });

        client.emit('connected', {
          message: 'Connected to Enhanced Mock Terminal',
          sessionId,
          timestamp: Date.now(),
        });
        
        client.emit('session-created', { 
          sessionId,
          name: 'Terminal 1'
        });

        this.eventHistory.push({
          type: 'client-connected',
          clientId: client.id,
          timestamp: Date.now()
        });
      }
    }, 5);
  }
  
  removeClient(client) {
    this.clients.delete(client);
    this.eventHistory.push({
      type: 'client-disconnected',
      clientId: client.id,
      timestamp: Date.now()
    });
  }
  
  broadcast(event, data) {
    this.eventHistory.push({
      type: 'broadcast',
      event,
      data,
      timestamp: Date.now()
    });

    this.clients.forEach(client => {
      if (client.emit) {
        try {
          client.emit(event, data);
        } catch (error) {
          console.error(`Error broadcasting ${event}:`, error);
        }
      }
    });
  }
  
  // Enhanced session management
  createSession(sessionData) {
    const sessionId = sessionData?.id || `session-${Date.now()}`;
    const session = {
      id: sessionId,
      name: sessionData?.name || `Terminal ${this.sessions.size + 1}`,
      created: Date.now(),
      active: true,
      lastActivity: Date.now()
    };
    
    this.sessions.set(sessionId, session);
    
    this.broadcast('session-created', {
      sessionId,
      name: session.name
    });
    
    return session;
  }
  
  destroySession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.sessions.delete(sessionId);
      
      this.broadcast('session-destroyed', {
        sessionId
      });
      
      return true;
    }
    return false;
  }
  
  simulateTerminalData(sessionId, data) {
    if (this.sessions.has(sessionId)) {
      const session = this.sessions.get(sessionId);
      session.lastActivity = Date.now();
      
      this.broadcast('terminal-data', { sessionId, data });
      return true;
    }
    return false;
  }
  
  simulateSystemMetrics() {
    const metrics = {
      memoryTotal: 17179869184,
      memoryUsed: Math.floor(15000000000 + Math.random() * 2000000000),
      memoryFree: Math.floor(2000000000 + Math.random() * 179869184),
      memoryUsagePercent: 85 + Math.random() * 10,
      memoryEfficiency: Math.random() * 20,
      cpuCount: 10,
      cpuLoad: Math.random() * 2,
      platform: 'darwin',
      uptime: Date.now() / 1000,
      timestamp: Date.now(),
    };
    
    this.broadcast('system-metrics', metrics);
  }
  
  simulateAgentStatus() {
    const agentId = `agent-${Math.floor(Math.random() * 3) + 1}`;
    const status = {
      agentId,
      state: ['idle', 'busy', 'initializing'][Math.floor(Math.random() * 3)],
      currentTask: Math.random() > 0.5 ? 'Processing task...' : undefined,
    };
    
    this.broadcast('agent-status', status);
  }
  
  simulateCommand() {
    const command = {
      id: `cmd-${Date.now()}`,
      command: ['ls -la', 'git status', 'npm install'][Math.floor(Math.random() * 3)],
      agentId: `agent-${Math.floor(Math.random() * 3) + 1}`,
    };
    
    this.broadcast('command-created', command);
  }

  // Testing utilities
  getEventHistory() {
    return [...this.eventHistory];
  }
  
  clearEventHistory() {
    this.eventHistory = [];
  }
  
  getSessionCount() {
    return this.sessions.size;
  }
  
  getSession(sessionId) {
    return this.sessions.get(sessionId);
  }
  
  getAllSessions() {
    return Array.from(this.sessions.values());
  }
}

// Enhanced Mock WebSocket Client with better promise support
class EnhancedMockWebSocketClient {
  constructor(url) {
    this.url = url;
    this.connected = false;
    this.connecting = false;
    this.handlers = new Map();
    this.id = `mock-client-${Math.random().toString(36).substr(2, 9)}`;
    this.messageHistory = [];
  }
  
  connect() {
    return new Promise((resolve) => {
      this.connecting = true;
      
      setTimeout(() => {
        this.connected = true;
        this.connecting = false;
        this.emit('connect');
        resolve(true);
      }, 5); // Faster connection for tests
    });
  }
  
  disconnect() {
    this.connected = false;
    this.emit('disconnect', 'client disconnect');
    return Promise.resolve(true);
  }
  
  emit(event, data) {
    this.messageHistory.push({
      type: 'emit',
      event,
      data,
      timestamp: Date.now()
    });

    const handlers = this.handlers.get(event) || [];
    handlers.forEach(handler => {
      try {
        handler(data);
      } catch (error) {
        console.error(`Error in ${event} handler:`, error);
      }
    });
  }
  
  on(event, handler) {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, []);
    }
    this.handlers.get(event).push(handler);
  }
  
  off(event, handler) {
    const handlers = this.handlers.get(event);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }
  
  send(event, data) {
    this.messageHistory.push({
      type: 'send',
      event,
      data,
      timestamp: Date.now()
    });

    // Enhanced response simulation
    if (!this.connected) {
      throw new Error('WebSocket not connected');
    }

    // Simulate different event types
    if (event === 'data' && data?.sessionId) {
      // Echo back terminal data
      setTimeout(() => {
        this.emit('terminal-data', {
          sessionId: data.sessionId,
          data: data.data,
        });
      }, 5);
    } else if (event === 'create-session') {
      // Simulate session creation
      setTimeout(() => {
        const sessionId = data?.id || `session-${Date.now()}`;
        this.emit('session-created', {
          sessionId,
          name: data?.name || 'New Terminal'
        });
      }, 10);
    } else if (event === 'destroy-session') {
      // Simulate session destruction
      setTimeout(() => {
        this.emit('session-destroyed', {
          sessionId: data?.sessionId
        });
      }, 10);
    } else if (event === 'resize-terminal') {
      // Simulate terminal resize
      setTimeout(() => {
        this.emit('terminal-resized', {
          sessionId: data?.sessionId,
          cols: data?.cols || 120,
          rows: data?.rows || 30
        });
      }, 5);
    }
    
    return Promise.resolve(true);
  }

  // Testing utilities
  getMessageHistory() {
    return [...this.messageHistory];
  }
  
  clearMessageHistory() {
    this.messageHistory = [];
  }
  
  getHandlerCount(event) {
    return (this.handlers.get(event) || []).length;
  }
  
  hasHandler(event) {
    return this.handlers.has(event) && this.handlers.get(event).length > 0;
  }
  
  simulateError(error) {
    this.emit('error', error);
  }
  
  simulateDisconnect(reason = 'test disconnect') {
    this.connected = false;
    this.emit('disconnect', reason);
  }
  
  simulateReconnect() {
    return this.connect();
  }
}

module.exports = {
  MockWebSocketServer: EnhancedMockWebSocketServer,
  MockWebSocketClient: EnhancedMockWebSocketClient,
  EnhancedMockWebSocketServer,
  EnhancedMockWebSocketClient,
};