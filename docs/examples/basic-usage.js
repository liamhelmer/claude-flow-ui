/**
 * Basic Usage Examples for Claude Flow UI
 *
 * This file demonstrates common usage patterns and API interactions
 * with the Claude Flow UI system.
 */

// ============================================================================
// SERVER SETUP AND BASIC USAGE
// ============================================================================

// Example 1: Basic server startup
const claudeFlowUI = require('@liamhelmer/claude-flow-ui');

// Start with default configuration
claudeFlowUI.start();

// Start with custom configuration
claudeFlowUI.start({
  port: 8080,
  terminalSize: '120x40',
  claudeFlowArgs: ['swarm', '--objective', 'development tasks']
});

// ============================================================================
// PROGRAMMATIC API USAGE
// ============================================================================

// Example 2: Using the API programmatically
const express = require('express');
const { ClaudeFlowUIServer } = require('@liamhelmer/claude-flow-ui');

async function setupCustomServer() {
  const server = new ClaudeFlowUIServer({
    port: 3000,
    terminalConfig: {
      cols: 100,
      rows: 30,
      scrollback: 2000,
      theme: 'dark'
    }
  });

  // Add custom middleware
  server.app.use('/api/custom', (req, res) => {
    res.json({ message: 'Custom endpoint' });
  });

  // Start server
  await server.start();
  console.log('Claude Flow UI server started');
}

// ============================================================================
// WEBSOCKET CLIENT EXAMPLES
// ============================================================================

// Example 3: WebSocket client for terminal interaction
const WebSocket = require('ws');

class TerminalClient {
  constructor(url = 'ws://localhost:3000/ws') {
    this.ws = new WebSocket(url);
    this.setupEventHandlers();
  }

  setupEventHandlers() {
    this.ws.on('open', () => {
      console.log('Connected to Claude Flow UI WebSocket');
      this.requestTerminalConfig();
    });

    this.ws.on('message', (data) => {
      const message = JSON.parse(data);
      this.handleMessage(message);
    });

    this.ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    this.ws.on('close', () => {
      console.log('WebSocket connection closed');
    });
  }

  handleMessage(message) {
    switch (message.type) {
      case 'terminal-data':
        console.log(`Terminal output: ${message.data}`);
        break;
      case 'terminal-config':
        console.log('Terminal config:', message);
        break;
      case 'session-created':
        console.log('Session created:', message.sessionId);
        break;
      default:
        console.log('Unknown message:', message);
    }
  }

  requestTerminalConfig() {
    this.ws.send(JSON.stringify({
      type: 'request-config'
    }));
  }

  sendCommand(command) {
    this.ws.send(JSON.stringify({
      type: 'data',
      data: command + '\n'
    }));
  }

  resizeTerminal(cols, rows) {
    this.ws.send(JSON.stringify({
      type: 'resize',
      cols: cols,
      rows: rows
    }));
  }
}

// Usage
const client = new TerminalClient();

// Send commands after connection
setTimeout(() => {
  client.sendCommand('ls -la');
  client.sendCommand('pwd');
}, 1000);

// ============================================================================
// HTTP API EXAMPLES
// ============================================================================

// Example 4: HTTP API interactions
const axios = require('axios');

class ClaudeFlowUIClient {
  constructor(baseURL = 'http://localhost:3000') {
    this.api = axios.create({ baseURL });
  }

  async getHealth() {
    try {
      const response = await this.api.get('/api/health');
      return response.data;
    } catch (error) {
      console.error('Health check failed:', error.message);
      throw error;
    }
  }

  async getTerminalConfig(sessionId = null) {
    const url = sessionId
      ? `/api/terminal-config/${sessionId}`
      : '/api/terminal-config';

    const response = await this.api.get(url);
    return response.data;
  }

  async listTerminals() {
    const response = await this.api.get('/api/terminals');
    return response.data;
  }

  async createTerminal(name, command = '/bin/bash') {
    const response = await this.api.post('/api/terminals/spawn', {
      name,
      command
    });
    return response.data;
  }

  async closeTerminal(terminalId) {
    await this.api.delete(`/api/terminals/${terminalId}`);
  }
}

// Usage examples
async function demonstrateAPI() {
  const client = new ClaudeFlowUIClient();

  try {
    // Check server health
    const health = await client.getHealth();
    console.log('Server health:', health);

    // Get terminal configuration
    const config = await client.getTerminalConfig();
    console.log('Terminal config:', config);

    // List existing terminals
    const terminals = await client.listTerminals();
    console.log('Active terminals:', terminals);

    // Create a new terminal
    const newTerminal = await client.createTerminal('Development Terminal', 'zsh');
    console.log('Created terminal:', newTerminal);

    // Wait a bit, then close it
    setTimeout(async () => {
      await client.closeTerminal(newTerminal.id);
      console.log('Terminal closed');
    }, 5000);

  } catch (error) {
    console.error('API error:', error.message);
  }
}

// ============================================================================
// TRANSFORMATION SYSTEM EXAMPLES
// ============================================================================

// Example 5: Using the transformation system
const { TransformationManager, DataCleanerTransformation } = require('@liamhelmer/claude-flow-ui');

async function demonstrateTransformations() {
  const manager = new TransformationManager();

  // Register built-in transformations
  manager.register(new DataCleanerTransformation());

  // Execute transformation
  const inputData = [
    { name: 'John', age: '30', email: 'john@example.com' },
    { name: 'Jane', age: '25', email: 'jane@example.com' },
    { name: '', age: 'invalid', email: 'not-an-email' }
  ];

  try {
    const transformation = manager.get('data-cleaner');
    transformation.configure({
      batchSize: 100,
      parallel: true
    });

    const context = {
      id: 'demo-transformation',
      startTime: new Date(),
      metadata: {},
      config: transformation.config
    };

    const result = await transformation.transform(inputData, context, (progress) => {
      console.log(`Progress: ${progress.percentage}%`);
    });

    console.log('Transformation result:', result);

    if (result.success) {
      console.log('Processed data:', result.data);
    } else {
      console.log('Errors:', result.errors);
    }

  } catch (error) {
    console.error('Transformation failed:', error);
  }
}

// ============================================================================
// CUSTOM TRANSFORMATION EXAMPLE
// ============================================================================

// Example 6: Creating a custom transformation
const { AbstractTransformation } = require('@liamhelmer/claude-flow-ui');

class EmailValidatorTransformation extends AbstractTransformation {
  constructor() {
    super();
    this.name = 'email-validator';
    this.version = '1.0.0';
    this.description = 'Validates and filters email addresses';
  }

  async transform(data, context, onProgress) {
    const startTime = new Date();
    const validEmails = [];
    const errors = [];

    if (!Array.isArray(data)) {
      return {
        success: false,
        data: null,
        errors: [{
          code: 'INVALID_INPUT',
          message: 'Input must be an array',
          severity: 'error'
        }],
        warnings: [],
        metadata: { processed: 0, skipped: 0, failed: 1, duration: 0 }
      };
    }

    for (let i = 0; i < data.length; i++) {
      const item = data[i];

      if (this.isValidEmail(item.email)) {
        validEmails.push({
          ...item,
          emailValid: true,
          validatedAt: new Date().toISOString()
        });
      } else {
        errors.push({
          code: 'INVALID_EMAIL',
          message: `Invalid email: ${item.email}`,
          severity: 'warning'
        });
      }

      if (onProgress && i % 10 === 0) {
        onProgress({
          taskId: context.id,
          total: data.length,
          processed: i + 1,
          failed: errors.length,
          percentage: Math.round(((i + 1) / data.length) * 100),
          currentOperation: `Validating email ${i + 1}/${data.length}`
        });
      }
    }

    return {
      success: true,
      data: validEmails,
      errors: errors,
      warnings: errors.length > 0 ? [`${errors.length} invalid emails found`] : [],
      metadata: {
        processed: validEmails.length,
        skipped: 0,
        failed: errors.length,
        duration: Date.now() - startTime.getTime()
      }
    };
  }

  async validate(data) {
    const errors = [];

    if (!Array.isArray(data)) {
      errors.push({
        code: 'INVALID_INPUT',
        message: 'Input must be an array',
        severity: 'error'
      });
    } else if (data.length === 0) {
      errors.push({
        code: 'EMPTY_INPUT',
        message: 'Input array is empty',
        severity: 'warning'
      });
    }

    return errors;
  }

  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return typeof email === 'string' && emailRegex.test(email);
  }
}

// Usage
async function useCustomTransformation() {
  const transformation = new EmailValidatorTransformation();
  const testData = [
    { name: 'John', email: 'john@example.com' },
    { name: 'Jane', email: 'jane@example.com' },
    { name: 'Bob', email: 'invalid-email' }
  ];

  const context = {
    id: 'email-validation-test',
    startTime: new Date(),
    metadata: {},
    config: {}
  };

  const result = await transformation.transform(testData, context);
  console.log('Email validation result:', result);
}

// ============================================================================
// CONFIGURATION EXAMPLES
// ============================================================================

// Example 7: Advanced configuration
const config = {
  server: {
    port: 3000,
    host: 'localhost',
    maxSessions: 20
  },

  terminal: {
    size: '120x40',
    scrollbackLines: 5000,
    theme: {
      background: '#1a1b26',
      foreground: '#c0caf5',
      cursor: '#c0caf5',
      black: '#15161e',
      red: '#f7768e',
      green: '#9ece6a',
      yellow: '#e0af68',
      blue: '#7aa2f7',
      magenta: '#bb9af7',
      cyan: '#7dcfff',
      white: '#a9b1d6'
    },
    fontFamily: 'JetBrains Mono, Monaco, Consolas, monospace',
    fontSize: 14,
    cursorBlink: true
  },

  websocket: {
    heartbeatInterval: 30000,
    compression: true,
    maxMessageSize: 1048576
  },

  claudeFlow: {
    apiKey: process.env.CLAUDE_API_KEY,
    initCommand: 'swarm --objective "development tasks"',
    autostart: true
  },

  logging: {
    level: 'info',
    file: './logs/claude-flow-ui.log',
    maxSize: '100MB',
    maxFiles: 5
  }
};

// Start with configuration
// claudeFlowUI.start(config);

// ============================================================================
// ERROR HANDLING EXAMPLES
// ============================================================================

// Example 8: Robust error handling
class RobustTerminalClient {
  constructor(url = 'ws://localhost:3000/ws') {
    this.url = url;
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.messageQueue = [];

    this.connect();
  }

  connect() {
    try {
      this.ws = new WebSocket(this.url);
      this.setupEventHandlers();
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this.scheduleReconnect();
    }
  }

  setupEventHandlers() {
    this.ws.on('open', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
      this.flushMessageQueue();
    });

    this.ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        this.handleMessage(message);
      } catch (error) {
        console.error('Failed to parse message:', error);
      }
    });

    this.ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    this.ws.on('close', (code, reason) => {
      console.log(`WebSocket closed: ${code} ${reason}`);
      this.scheduleReconnect();
    });
  }

  scheduleReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

      console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

      setTimeout(() => {
        this.connect();
      }, delay);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify(message));
      } catch (error) {
        console.error('Failed to send message:', error);
        this.messageQueue.push(message);
      }
    } else {
      // Queue message for when connection is restored
      this.messageQueue.push(message);
    }
  }

  flushMessageQueue() {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      this.send(message);
    }
  }

  handleMessage(message) {
    // Handle different message types with error boundaries
    try {
      switch (message.type) {
        case 'terminal-data':
          this.handleTerminalData(message);
          break;
        case 'terminal-config':
          this.handleTerminalConfig(message);
          break;
        case 'error':
          this.handleError(message);
          break;
        default:
          console.warn('Unknown message type:', message.type);
      }
    } catch (error) {
      console.error('Error handling message:', error);
    }
  }

  handleTerminalData(message) {
    // Process terminal data safely
    if (message.data && typeof message.data === 'string') {
      process.stdout.write(message.data);
    }
  }

  handleTerminalConfig(message) {
    console.log('Terminal configured:', {
      cols: message.cols,
      rows: message.rows,
      sessionId: message.sessionId
    });
  }

  handleError(message) {
    console.error('Server error:', message.error);
  }

  close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// ============================================================================
// INTEGRATION EXAMPLES
// ============================================================================

// Example 9: Integration with Express.js
const express = require('express');

async function createIntegratedServer() {
  const app = express();

  // Create Claude Flow UI instance
  const claudeFlowUI = new ClaudeFlowUIServer({
    port: null, // Don't start HTTP server
    embedMode: true
  });

  // Mount Claude Flow UI routes
  app.use('/terminal', claudeFlowUI.router);

  // Add custom routes
  app.get('/api/status', (req, res) => {
    res.json({
      status: 'running',
      terminals: claudeFlowUI.getActiveTerminals(),
      uptime: process.uptime()
    });
  });

  // Start integrated server
  const server = app.listen(3000, () => {
    console.log('Integrated server running on port 3000');
    console.log('Terminal UI available at: http://localhost:3000/terminal');
  });

  // Attach WebSocket to the same server
  claudeFlowUI.attachWebSocket(server);

  return { app, server, claudeFlowUI };
}

// ============================================================================
// MONITORING AND METRICS
// ============================================================================

// Example 10: Performance monitoring
class PerformanceMonitor {
  constructor(apiClient) {
    this.api = apiClient;
    this.metrics = {
      requestCount: 0,
      errorCount: 0,
      responseTime: []
    };

    this.startMonitoring();
  }

  startMonitoring() {
    setInterval(async () => {
      await this.collectMetrics();
    }, 10000); // Every 10 seconds
  }

  async collectMetrics() {
    try {
      const startTime = Date.now();
      const health = await this.api.getHealth();
      const responseTime = Date.now() - startTime;

      this.metrics.requestCount++;
      this.metrics.responseTime.push(responseTime);

      // Keep only last 100 measurements
      if (this.metrics.responseTime.length > 100) {
        this.metrics.responseTime.shift();
      }

      console.log('Metrics:', {
        status: health.status,
        responseTime: `${responseTime}ms`,
        avgResponseTime: this.getAverageResponseTime(),
        requests: this.metrics.requestCount,
        errors: this.metrics.errorCount
      });

    } catch (error) {
      this.metrics.errorCount++;
      console.error('Health check failed:', error.message);
    }
  }

  getAverageResponseTime() {
    if (this.metrics.responseTime.length === 0) return 0;
    const sum = this.metrics.responseTime.reduce((a, b) => a + b, 0);
    return Math.round(sum / this.metrics.responseTime.length);
  }

  getMetrics() {
    return {
      ...this.metrics,
      averageResponseTime: this.getAverageResponseTime()
    };
  }
}

// Usage
const apiClient = new ClaudeFlowUIClient();
const monitor = new PerformanceMonitor(apiClient);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Helper functions for common operations
const utils = {
  // Wait for server to be ready
  async waitForServer(url = 'http://localhost:3000', timeout = 30000) {
    const start = Date.now();

    while (Date.now() - start < timeout) {
      try {
        const response = await axios.get(`${url}/api/health`);
        if (response.status === 200) {
          return true;
        }
      } catch (error) {
        // Server not ready yet
      }

      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    throw new Error(`Server not ready after ${timeout}ms`);
  },

  // Create test data
  generateTestData(count = 100) {
    const data = [];
    for (let i = 0; i < count; i++) {
      data.push({
        id: i + 1,
        name: `User ${i + 1}`,
        email: `user${i + 1}@example.com`,
        age: Math.floor(Math.random() * 50) + 18,
        createdAt: new Date().toISOString()
      });
    }
    return data;
  },

  // Format file size
  formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  },

  // Validate configuration
  validateConfig(config) {
    const errors = [];

    if (config.port && (config.port < 1 || config.port > 65535)) {
      errors.push('Port must be between 1 and 65535');
    }

    if (config.terminalSize) {
      const sizeRegex = /^\d+x\d+$/;
      if (!sizeRegex.test(config.terminalSize)) {
        errors.push('Terminal size must be in format COLSxROWS (e.g., 80x24)');
      }
    }

    return errors;
  }
};

// Export for use in other modules
module.exports = {
  TerminalClient,
  ClaudeFlowUIClient,
  EmailValidatorTransformation,
  RobustTerminalClient,
  PerformanceMonitor,
  utils,

  // Example functions
  setupCustomServer,
  demonstrateAPI,
  demonstrateTransformations,
  useCustomTransformation,
  createIntegratedServer
};

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

// Uncomment to run examples
// (async () => {
//   try {
//     console.log('Starting Claude Flow UI examples...');
//
//     // Wait for server to be ready
//     await utils.waitForServer();
//     console.log('Server is ready');
//
//     // Run API demonstration
//     await demonstrateAPI();
//
//     // Run transformation demonstration
//     await demonstrateTransformations();
//
//     // Use custom transformation
//     await useCustomTransformation();
//
//   } catch (error) {
//     console.error('Example failed:', error);
//   }
// })();