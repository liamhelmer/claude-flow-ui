/**
 * Advanced WebSocket Client Example for Claude Flow UI
 *
 * This example demonstrates how to create a robust WebSocket client
 * that can handle terminal sessions, reconnections, and real-time data.
 */

const WebSocket = require('ws');
const EventEmitter = require('events');

/**
 * Advanced WebSocket client for Claude Flow UI
 */
class ClaudeFlowUIWebSocketClient extends EventEmitter {
  constructor(options = {}) {
    super();

    this.url = options.url || 'ws://localhost:3000/ws';
    this.autoReconnect = options.autoReconnect !== false;
    this.maxReconnectAttempts = options.maxReconnectAttempts || 5;
    this.reconnectDelay = options.reconnectDelay || 1000;
    this.heartbeatInterval = options.heartbeatInterval || 30000;

    this.ws = null;
    this.reconnectAttempts = 0;
    this.heartbeatTimer = null;
    this.messageQueue = [];
    this.isConnected = false;
    this.currentSessionId = null;

    this.connect();
  }

  /**
   * Establish WebSocket connection
   */
  connect() {
    try {
      this.ws = new WebSocket(this.url);
      this.setupEventHandlers();
    } catch (error) {
      this.emit('error', error);
      if (this.autoReconnect) {
        this.scheduleReconnect();
      }
    }
  }

  /**
   * Setup WebSocket event handlers
   */
  setupEventHandlers() {
    this.ws.on('open', () => {
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.startHeartbeat();
      this.flushMessageQueue();
      this.emit('connected');

      // Request initial configuration
      this.requestConfig();
    });

    this.ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        this.handleMessage(message);
      } catch (error) {
        this.emit('error', new Error(`Failed to parse message: ${error.message}`));
      }
    });

    this.ws.on('error', (error) => {
      this.emit('error', error);
    });

    this.ws.on('close', (code, reason) => {
      this.isConnected = false;
      this.stopHeartbeat();
      this.emit('disconnected', { code, reason: reason.toString() });

      if (this.autoReconnect && code !== 1000) { // Don't reconnect on normal closure
        this.scheduleReconnect();
      }
    });

    this.ws.on('pong', () => {
      this.emit('pong');
    });
  }

  /**
   * Handle incoming messages
   */
  handleMessage(message) {
    this.emit('message', message);

    switch (message.type) {
      case 'terminal-data':
        this.handleTerminalData(message);
        break;
      case 'terminal-config':
        this.handleTerminalConfig(message);
        break;
      case 'session-created':
        this.handleSessionCreated(message);
        break;
      case 'session-switched':
        this.handleSessionSwitched(message);
        break;
      case 'terminal-spawned':
        this.handleTerminalSpawned(message);
        break;
      case 'terminal-closed':
        this.handleTerminalClosed(message);
        break;
      case 'error':
        this.handleServerError(message);
        break;
      default:
        this.emit('unknown-message', message);
    }
  }

  /**
   * Handle terminal data output
   */
  handleTerminalData(message) {
    this.emit('terminal-data', {
      sessionId: message.sessionId,
      data: message.data
    });
  }

  /**
   * Handle terminal configuration
   */
  handleTerminalConfig(message) {
    this.emit('terminal-config', {
      sessionId: message.sessionId,
      cols: message.cols,
      rows: message.rows,
      timestamp: message.timestamp
    });
  }

  /**
   * Handle session creation confirmation
   */
  handleSessionCreated(message) {
    this.currentSessionId = message.sessionId;
    this.emit('session-created', message);
  }

  /**
   * Handle session switch confirmation
   */
  handleSessionSwitched(message) {
    if (message.success) {
      this.currentSessionId = message.sessionId;
      this.emit('session-switched', message);
    } else {
      this.emit('session-switch-error', message);
    }
  }

  /**
   * Handle new terminal spawned
   */
  handleTerminalSpawned(message) {
    this.emit('terminal-spawned', message);
  }

  /**
   * Handle terminal closed
   */
  handleTerminalClosed(message) {
    this.emit('terminal-closed', message);
  }

  /**
   * Handle server errors
   */
  handleServerError(message) {
    this.emit('server-error', message);
  }

  /**
   * Send a message to the server
   */
  send(message) {
    if (this.isConnected && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify(message));
        return true;
      } catch (error) {
        this.emit('error', error);
        this.messageQueue.push(message);
        return false;
      }
    } else {
      this.messageQueue.push(message);
      return false;
    }
  }

  /**
   * Send terminal input
   */
  sendInput(data, sessionId = null) {
    return this.send({
      type: 'data',
      sessionId: sessionId || this.currentSessionId,
      data: data
    });
  }

  /**
   * Send command to terminal
   */
  sendCommand(command, sessionId = null) {
    return this.sendInput(command + '\n', sessionId);
  }

  /**
   * Resize terminal
   */
  resize(cols, rows, sessionId = null) {
    return this.send({
      type: 'resize',
      sessionId: sessionId || this.currentSessionId,
      cols: cols,
      rows: rows
    });
  }

  /**
   * Request terminal configuration
   */
  requestConfig(sessionId = null) {
    return this.send({
      type: 'request-config',
      sessionId: sessionId
    });
  }

  /**
   * Switch to a different terminal session
   */
  switchSession(targetSessionId) {
    return this.send({
      type: 'switch-session',
      targetSessionId: targetSessionId
    });
  }

  /**
   * Create a new terminal session
   */
  createSession(name, command = null) {
    return this.send({
      type: 'create-session',
      name: name,
      command: command
    });
  }

  /**
   * Close a terminal session
   */
  closeSession(sessionId = null) {
    return this.send({
      type: 'close-session',
      sessionId: sessionId || this.currentSessionId
    });
  }

  /**
   * List all terminal sessions
   */
  listSessions() {
    return this.send({
      type: 'list-sessions'
    });
  }

  /**
   * Refresh terminal history
   */
  refreshHistory(sessionId = null) {
    return this.send({
      type: 'refresh-history',
      sessionId: sessionId || this.currentSessionId
    });
  }

  /**
   * Start heartbeat to keep connection alive
   */
  startHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.ping();
      }
    }, this.heartbeatInterval);
  }

  /**
   * Stop heartbeat
   */
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Schedule reconnection attempt
   */
  scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.emit('max-reconnect-attempts-reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    this.emit('reconnecting', {
      attempt: this.reconnectAttempts,
      maxAttempts: this.maxReconnectAttempts,
      delay: delay
    });

    setTimeout(() => {
      this.connect();
    }, delay);
  }

  /**
   * Flush queued messages
   */
  flushMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected) {
      const message = this.messageQueue.shift();
      this.send(message);
    }
  }

  /**
   * Get connection status
   */
  getStatus() {
    return {
      connected: this.isConnected,
      currentSessionId: this.currentSessionId,
      reconnectAttempts: this.reconnectAttempts,
      queuedMessages: this.messageQueue.length,
      readyState: this.ws ? this.ws.readyState : -1
    };
  }

  /**
   * Close the connection
   */
  close() {
    this.autoReconnect = false;
    this.stopHeartbeat();

    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
    }
  }

  /**
   * Enable auto-reconnect
   */
  enableAutoReconnect() {
    this.autoReconnect = true;
  }

  /**
   * Disable auto-reconnect
   */
  disableAutoReconnect() {
    this.autoReconnect = false;
  }
}

/**
 * Terminal Session Manager
 * Manages multiple terminal sessions through WebSocket
 */
class TerminalSessionManager {
  constructor(wsClient) {
    this.client = wsClient;
    this.sessions = new Map();
    this.activeSessionId = null;

    this.setupEventHandlers();
  }

  setupEventHandlers() {
    this.client.on('session-created', (message) => {
      this.sessions.set(message.sessionId, {
        id: message.sessionId,
        name: message.name || `Session ${message.sessionId}`,
        active: false,
        created: new Date()
      });
    });

    this.client.on('terminal-spawned', (message) => {
      this.sessions.set(message.id, {
        id: message.id,
        name: message.name,
        command: message.command,
        active: false,
        created: new Date(message.createdAt)
      });
    });

    this.client.on('terminal-closed', (message) => {
      this.sessions.delete(message.id);
    });

    this.client.on('session-switched', (message) => {
      if (message.success) {
        // Update active session
        this.sessions.forEach(session => {
          session.active = session.id === message.sessionId;
        });
        this.activeSessionId = message.sessionId;
      }
    });
  }

  /**
   * Create a new terminal session
   */
  async createSession(name, command) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Session creation timeout'));
      }, 10000);

      const onSessionCreated = (message) => {
        clearTimeout(timeout);
        this.client.off('session-created', onSessionCreated);
        resolve(message);
      };

      this.client.on('session-created', onSessionCreated);
      this.client.createSession(name, command);
    });
  }

  /**
   * Switch to a session
   */
  async switchToSession(sessionId) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Session switch timeout'));
      }, 5000);

      const onSwitched = (message) => {
        clearTimeout(timeout);
        this.client.off('session-switched', onSwitched);
        this.client.off('session-switch-error', onError);
        resolve(message);
      };

      const onError = (message) => {
        clearTimeout(timeout);
        this.client.off('session-switched', onSwitched);
        this.client.off('session-switch-error', onError);
        reject(new Error(message.error));
      };

      this.client.on('session-switched', onSwitched);
      this.client.on('session-switch-error', onError);
      this.client.switchSession(sessionId);
    });
  }

  /**
   * Get all sessions
   */
  getSessions() {
    return Array.from(this.sessions.values());
  }

  /**
   * Get active session
   */
  getActiveSession() {
    return this.sessions.get(this.activeSessionId);
  }

  /**
   * Close a session
   */
  closeSession(sessionId) {
    this.client.closeSession(sessionId);
  }
}

/**
 * Terminal Buffer Manager
 * Manages terminal output buffering and scrollback
 */
class TerminalBufferManager {
  constructor(wsClient, maxBufferSize = 10000) {
    this.client = wsClient;
    this.maxBufferSize = maxBufferSize;
    this.buffers = new Map(); // sessionId -> buffer array

    this.setupEventHandlers();
  }

  setupEventHandlers() {
    this.client.on('terminal-data', (message) => {
      this.appendToBuffer(message.sessionId, message.data);
    });

    this.client.on('session-created', (message) => {
      this.buffers.set(message.sessionId, []);
    });

    this.client.on('terminal-closed', (message) => {
      this.buffers.delete(message.id);
    });
  }

  appendToBuffer(sessionId, data) {
    if (!this.buffers.has(sessionId)) {
      this.buffers.set(sessionId, []);
    }

    const buffer = this.buffers.get(sessionId);
    buffer.push({
      data: data,
      timestamp: new Date()
    });

    // Trim buffer if it exceeds max size
    if (buffer.length > this.maxBufferSize) {
      buffer.shift();
    }
  }

  getBuffer(sessionId) {
    return this.buffers.get(sessionId) || [];
  }

  getBufferAsString(sessionId) {
    const buffer = this.getBuffer(sessionId);
    return buffer.map(item => item.data).join('');
  }

  clearBuffer(sessionId) {
    if (this.buffers.has(sessionId)) {
      this.buffers.set(sessionId, []);
    }
  }

  searchBuffer(sessionId, searchTerm) {
    const buffer = this.getBuffer(sessionId);
    const results = [];

    buffer.forEach((item, index) => {
      if (item.data.includes(searchTerm)) {
        results.push({
          index: index,
          data: item.data,
          timestamp: item.timestamp
        });
      }
    });

    return results;
  }
}

/**
 * Example usage and demonstrations
 */
class ExampleUsage {
  static async basicUsage() {
    console.log('=== Basic WebSocket Usage ===');

    const client = new ClaudeFlowUIWebSocketClient({
      url: 'ws://localhost:3000/ws',
      autoReconnect: true,
      maxReconnectAttempts: 3
    });

    // Handle connection events
    client.on('connected', () => {
      console.log('✅ Connected to Claude Flow UI');
    });

    client.on('disconnected', ({ code, reason }) => {
      console.log(`❌ Disconnected: ${code} ${reason}`);
    });

    client.on('reconnecting', ({ attempt, maxAttempts, delay }) => {
      console.log(`🔄 Reconnecting... (${attempt}/${maxAttempts}) in ${delay}ms`);
    });

    // Handle terminal data
    client.on('terminal-data', ({ sessionId, data }) => {
      process.stdout.write(data);
    });

    // Wait for connection
    await new Promise((resolve) => {
      client.once('connected', resolve);
    });

    // Send some commands
    client.sendCommand('echo "Hello from WebSocket client"');
    client.sendCommand('pwd');
    client.sendCommand('ls -la');

    // Wait a bit and then close
    setTimeout(() => {
      client.close();
    }, 5000);
  }

  static async advancedUsage() {
    console.log('=== Advanced WebSocket Usage ===');

    const client = new ClaudeFlowUIWebSocketClient();
    const sessionManager = new TerminalSessionManager(client);
    const bufferManager = new TerminalBufferManager(client);

    // Wait for connection
    await new Promise((resolve) => {
      client.once('connected', resolve);
    });

    // Create multiple sessions
    console.log('Creating terminal sessions...');

    try {
      const session1 = await sessionManager.createSession('Development', 'bash');
      console.log('✅ Created session 1:', session1);

      const session2 = await sessionManager.createSession('Testing', 'zsh');
      console.log('✅ Created session 2:', session2);

      // Switch between sessions
      console.log('Switching to session 1...');
      await sessionManager.switchToSession(session1.sessionId);

      client.sendCommand('echo "This is session 1"');

      // Wait and switch to session 2
      setTimeout(async () => {
        console.log('Switching to session 2...');
        await sessionManager.switchToSession(session2.sessionId);
        client.sendCommand('echo "This is session 2"');
      }, 2000);

      // Demonstrate buffer management
      setTimeout(() => {
        console.log('\n=== Buffer Contents ===');
        const sessions = sessionManager.getSessions();
        sessions.forEach(session => {
          console.log(`\nBuffer for ${session.name}:`);
          console.log(bufferManager.getBufferAsString(session.id));
        });
      }, 4000);

    } catch (error) {
      console.error('❌ Error:', error.message);
    }

    // Cleanup
    setTimeout(() => {
      client.close();
    }, 6000);
  }

  static async errorHandlingExample() {
    console.log('=== Error Handling Example ===');

    const client = new ClaudeFlowUIWebSocketClient({
      url: 'ws://localhost:9999', // Intentionally wrong port
      autoReconnect: true,
      maxReconnectAttempts: 3,
      reconnectDelay: 1000
    });

    client.on('error', (error) => {
      console.error('❌ WebSocket error:', error.message);
    });

    client.on('reconnecting', ({ attempt, maxAttempts, delay }) => {
      console.log(`🔄 Reconnect attempt ${attempt}/${maxAttempts} in ${delay}ms`);
    });

    client.on('max-reconnect-attempts-reached', () => {
      console.log('❌ Max reconnection attempts reached');
      process.exit(1);
    });

    // This will demonstrate reconnection logic
    setTimeout(() => {
      console.log('Changing to correct URL...');
      client.url = 'ws://localhost:3000/ws';
      client.connect();
    }, 5000);
  }
}

// Export classes and examples
module.exports = {
  ClaudeFlowUIWebSocketClient,
  TerminalSessionManager,
  TerminalBufferManager,
  ExampleUsage
};

// Run examples if this file is executed directly
if (require.main === module) {
  const args = process.argv.slice(2);
  const example = args[0] || 'basic';

  switch (example) {
    case 'basic':
      ExampleUsage.basicUsage().catch(console.error);
      break;
    case 'advanced':
      ExampleUsage.advancedUsage().catch(console.error);
      break;
    case 'error':
      ExampleUsage.errorHandlingExample().catch(console.error);
      break;
    default:
      console.log('Usage: node websocket-client.js [basic|advanced|error]');
      process.exit(1);
  }
}