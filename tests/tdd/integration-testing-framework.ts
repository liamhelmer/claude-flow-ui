/**
 * Integration Testing Framework for TDD
 * Comprehensive framework for integration testing with proper lifecycle management
 */

import { spawn, ChildProcess } from 'child_process';
import { createServer, Server } from 'http';
import { WebSocket, WebSocketServer } from 'ws';
import { jest } from '@jest/globals';
import { EventEmitter } from 'events';

/**
 * Test Server Manager
 * Manages test servers and their lifecycle
 */
export class TestServerManager {
  private servers: Map<string, Server> = new Map();
  private processes: Map<string, ChildProcess> = new Map();
  private websocketServers: Map<string, WebSocketServer> = new Map();

  /**
   * Start HTTP server for testing
   */
  async startHttpServer(name: string, port: number, handler?: any): Promise<Server> {
    const server = createServer(handler);

    return new Promise((resolve, reject) => {
      server.listen(port, (err?: Error) => {
        if (err) {
          reject(err);
          return;
        }

        this.servers.set(name, server);
        resolve(server);
      });

      server.on('error', reject);
    });
  }

  /**
   * Start WebSocket server for testing
   */
  async startWebSocketServer(name: string, port: number): Promise<WebSocketServer> {
    const wss = new WebSocketServer({ port });

    return new Promise((resolve) => {
      wss.on('listening', () => {
        this.websocketServers.set(name, wss);
        resolve(wss);
      });
    });
  }

  /**
   * Start external process for testing
   */
  async startProcess(name: string, command: string, args: string[] = [], options: any = {}): Promise<ChildProcess> {
    const process = spawn(command, args, {
      stdio: 'pipe',
      ...options,
    });

    this.processes.set(name, process);

    // Wait for process to be ready
    return new Promise((resolve, reject) => {
      process.on('spawn', () => resolve(process));
      process.on('error', reject);

      // Auto-cleanup on process exit
      process.on('exit', () => {
        this.processes.delete(name);
      });
    });
  }

  /**
   * Stop server by name
   */
  async stopServer(name: string): Promise<void> {
    const server = this.servers.get(name);
    if (server) {
      return new Promise((resolve) => {
        server.close(() => {
          this.servers.delete(name);
          resolve();
        });
      });
    }
  }

  /**
   * Stop WebSocket server by name
   */
  async stopWebSocketServer(name: string): Promise<void> {
    const wss = this.websocketServers.get(name);
    if (wss) {
      return new Promise((resolve) => {
        wss.close(() => {
          this.websocketServers.delete(name);
          resolve();
        });
      });
    }
  }

  /**
   * Stop process by name
   */
  async stopProcess(name: string): Promise<void> {
    const process = this.processes.get(name);
    if (process) {
      return new Promise((resolve) => {
        process.on('exit', () => {
          this.processes.delete(name);
          resolve();
        });

        process.kill('SIGTERM');

        // Force kill after timeout
        setTimeout(() => {
          if (!process.killed) {
            process.kill('SIGKILL');
          }
        }, 5000);
      });
    }
  }

  /**
   * Get server by name
   */
  getServer(name: string): Server | undefined {
    return this.servers.get(name);
  }

  /**
   * Get WebSocket server by name
   */
  getWebSocketServer(name: string): WebSocketServer | undefined {
    return this.websocketServers.get(name);
  }

  /**
   * Get process by name
   */
  getProcess(name: string): ChildProcess | undefined {
    return this.processes.get(name);
  }

  /**
   * Cleanup all servers and processes
   */
  async cleanup(): Promise<void> {
    const cleanupPromises: Promise<void>[] = [];

    // Stop all servers
    for (const name of this.servers.keys()) {
      cleanupPromises.push(this.stopServer(name));
    }

    // Stop all WebSocket servers
    for (const name of this.websocketServers.keys()) {
      cleanupPromises.push(this.stopWebSocketServer(name));
    }

    // Stop all processes
    for (const name of this.processes.keys()) {
      cleanupPromises.push(this.stopProcess(name));
    }

    await Promise.all(cleanupPromises);
  }
}

/**
 * Integration Test Suite Builder
 */
export class IntegrationTestSuite {
  private serverManager = new TestServerManager();
  private setup: (() => Promise<void>)[] = [];
  private teardown: (() => Promise<void>)[] = [];
  private beforeEachHooks: (() => Promise<void>)[] = [];
  private afterEachHooks: (() => Promise<void>)[] = [];

  /**
   * Add setup hook
   */
  addSetup(hook: () => Promise<void>): IntegrationTestSuite {
    this.setup.push(hook);
    return this;
  }

  /**
   * Add teardown hook
   */
  addTeardown(hook: () => Promise<void>): IntegrationTestSuite {
    this.teardown.push(hook);
    return this;
  }

  /**
   * Add before each hook
   */
  addBeforeEach(hook: () => Promise<void>): IntegrationTestSuite {
    this.beforeEachHooks.push(hook);
    return this;
  }

  /**
   * Add after each hook
   */
  addAfterEach(hook: () => Promise<void>): IntegrationTestSuite {
    this.afterEachHooks.push(hook);
    return this;
  }

  /**
   * Setup test environment
   */
  async runSetup(): Promise<void> {
    for (const hook of this.setup) {
      await hook();
    }
  }

  /**
   * Teardown test environment
   */
  async runTeardown(): Promise<void> {
    for (const hook of this.teardown) {
      await hook();
    }
    await this.serverManager.cleanup();
  }

  /**
   * Run before each hooks
   */
  async runBeforeEach(): Promise<void> {
    for (const hook of this.beforeEachHooks) {
      await hook();
    }
  }

  /**
   * Run after each hooks
   */
  async runAfterEach(): Promise<void> {
    for (const hook of this.afterEachHooks) {
      await hook();
    }
  }

  /**
   * Get server manager
   */
  getServerManager(): TestServerManager {
    return this.serverManager;
  }
}

/**
 * Database Test Helper
 */
export class DatabaseTestHelper {
  private connections: Map<string, any> = new Map();
  private migrations: string[] = [];

  /**
   * Add database connection
   */
  addConnection(name: string, connection: any): void {
    this.connections.set(name, connection);
  }

  /**
   * Get database connection
   */
  getConnection(name: string = 'default'): any {
    return this.connections.get(name);
  }

  /**
   * Run database migrations
   */
  async runMigrations(): Promise<void> {
    // Mock migration runner - implement based on your database
    console.log('Running database migrations...');
    // This would typically run actual migrations
  }

  /**
   * Seed test data
   */
  async seedTestData(data: any): Promise<void> {
    // Mock data seeding - implement based on your database
    console.log('Seeding test data...');
    // This would typically insert test data
  }

  /**
   * Clean database
   */
  async cleanDatabase(): Promise<void> {
    // Mock database cleaning - implement based on your database
    console.log('Cleaning database...');
    // This would typically truncate tables or delete test data
  }

  /**
   * Cleanup all connections
   */
  async cleanup(): Promise<void> {
    for (const [name, connection] of this.connections) {
      if (connection && typeof connection.close === 'function') {
        await connection.close();
      }
    }
    this.connections.clear();
  }
}

/**
 * API Test Client
 */
export class ApiTestClient {
  private baseUrl: string;
  private headers: Record<string, string> = {};

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  /**
   * Set default headers
   */
  setHeaders(headers: Record<string, string>): void {
    this.headers = { ...this.headers, ...headers };
  }

  /**
   * Set authentication token
   */
  setAuthToken(token: string): void {
    this.headers['Authorization'] = `Bearer ${token}`;
  }

  /**
   * Make GET request
   */
  async get(path: string, headers: Record<string, string> = {}): Promise<any> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: { ...this.headers, ...headers },
    });

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: await response.json().catch(() => null),
    };
  }

  /**
   * Make POST request
   */
  async post(path: string, data: any = {}, headers: Record<string, string> = {}): Promise<any> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
        ...headers,
      },
      body: JSON.stringify(data),
    });

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: await response.json().catch(() => null),
    };
  }

  /**
   * Make PUT request
   */
  async put(path: string, data: any = {}, headers: Record<string, string> = {}): Promise<any> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
        ...headers,
      },
      body: JSON.stringify(data),
    });

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: await response.json().catch(() => null),
    };
  }

  /**
   * Make DELETE request
   */
  async delete(path: string, headers: Record<string, string> = {}): Promise<any> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: { ...this.headers, ...headers },
    });

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: await response.json().catch(() => null),
    };
  }
}

/**
 * WebSocket Test Client
 */
export class WebSocketTestClient extends EventEmitter {
  private ws: WebSocket | null = null;
  private url: string;
  private messages: any[] = [];

  constructor(url: string) {
    super();
    this.url = url;
  }

  /**
   * Connect to WebSocket
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        this.emit('open');
        resolve();
      };

      this.ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        this.messages.push(message);
        this.emit('message', message);
      };

      this.ws.onclose = (event) => {
        this.emit('close', event);
      };

      this.ws.onerror = (error) => {
        this.emit('error', error);
        reject(error);
      };
    });
  }

  /**
   * Send message
   */
  send(message: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      throw new Error('WebSocket is not connected');
    }
  }

  /**
   * Wait for specific message
   */
  async waitForMessage(predicate: (message: any) => boolean, timeout: number = 5000): Promise<any> {
    return new Promise((resolve, reject) => {
      // Check existing messages first
      const existingMessage = this.messages.find(predicate);
      if (existingMessage) {
        resolve(existingMessage);
        return;
      }

      const timeoutId = setTimeout(() => {
        reject(new Error(`Timeout waiting for message after ${timeout}ms`));
      }, timeout);

      const onMessage = (message: any) => {
        if (predicate(message)) {
          clearTimeout(timeoutId);
          this.off('message', onMessage);
          resolve(message);
        }
      };

      this.on('message', onMessage);
    });
  }

  /**
   * Get all received messages
   */
  getMessages(): any[] {
    return [...this.messages];
  }

  /**
   * Clear message history
   */
  clearMessages(): void {
    this.messages = [];
  }

  /**
   * Close connection
   */
  async close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.ws) {
        this.ws.onclose = () => resolve();
        this.ws.close();
      } else {
        resolve();
      }
    });
  }
}

/**
 * Integration Test Builder
 */
export class IntegrationTestBuilder {
  private suite = new IntegrationTestSuite();
  private dbHelper = new DatabaseTestHelper();

  /**
   * Setup HTTP server
   */
  withHttpServer(name: string, port: number, handler?: any): IntegrationTestBuilder {
    this.suite.addSetup(async () => {
      await this.suite.getServerManager().startHttpServer(name, port, handler);
    });

    this.suite.addTeardown(async () => {
      await this.suite.getServerManager().stopServer(name);
    });

    return this;
  }

  /**
   * Setup WebSocket server
   */
  withWebSocketServer(name: string, port: number): IntegrationTestBuilder {
    this.suite.addSetup(async () => {
      await this.suite.getServerManager().startWebSocketServer(name, port);
    });

    this.suite.addTeardown(async () => {
      await this.suite.getServerManager().stopWebSocketServer(name);
    });

    return this;
  }

  /**
   * Setup database
   */
  withDatabase(name: string, connection: any): IntegrationTestBuilder {
    this.suite.addSetup(async () => {
      this.dbHelper.addConnection(name, connection);
      await this.dbHelper.runMigrations();
    });

    this.suite.addAfterEach(async () => {
      await this.dbHelper.cleanDatabase();
    });

    this.suite.addTeardown(async () => {
      await this.dbHelper.cleanup();
    });

    return this;
  }

  /**
   * Add custom setup
   */
  withSetup(hook: () => Promise<void>): IntegrationTestBuilder {
    this.suite.addSetup(hook);
    return this;
  }

  /**
   * Add custom teardown
   */
  withTeardown(hook: () => Promise<void>): IntegrationTestBuilder {
    this.suite.addTeardown(hook);
    return this;
  }

  /**
   * Build the integration test suite
   */
  build(): {
    suite: IntegrationTestSuite;
    dbHelper: DatabaseTestHelper;
    createApiClient: (baseUrl: string) => ApiTestClient;
    createWebSocketClient: (url: string) => WebSocketTestClient;
  } {
    return {
      suite: this.suite,
      dbHelper: this.dbHelper,
      createApiClient: (baseUrl: string) => new ApiTestClient(baseUrl),
      createWebSocketClient: (url: string) => new WebSocketTestClient(url),
    };
  }
}

/**
 * Factory function to create integration test builder
 */
export const createIntegrationTest = (): IntegrationTestBuilder => {
  return new IntegrationTestBuilder();
};

/**
 * Utilities for integration testing
 */
export const integrationTestUtils = {
  /**
   * Wait for port to be available
   */
  waitForPort: async (port: number, timeout: number = 10000): Promise<void> => {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      try {
        const response = await fetch(`http://localhost:${port}`);
        return; // Port is available
      } catch (error) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    throw new Error(`Port ${port} not available after ${timeout}ms`);
  },

  /**
   * Wait for process to be ready
   */
  waitForProcess: async (process: ChildProcess, readyPattern: RegExp, timeout: number = 10000): Promise<void> => {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Process not ready after ${timeout}ms`));
      }, timeout);

      const onData = (data: Buffer) => {
        if (readyPattern.test(data.toString())) {
          clearTimeout(timeoutId);
          process.stdout?.off('data', onData);
          resolve();
        }
      };

      process.stdout?.on('data', onData);
    });
  },

  /**
   * Create mock HTTP handler
   */
  createMockHandler: (routes: Record<string, (req: any, res: any) => void>) => {
    return (req: any, res: any) => {
      const key = `${req.method} ${req.url}`;
      const handler = routes[key];

      if (handler) {
        handler(req, res);
      } else {
        res.statusCode = 404;
        res.end('Not Found');
      }
    };
  },
};

// Export everything
export default {
  createIntegrationTest,
  IntegrationTestBuilder,
  IntegrationTestSuite,
  TestServerManager,
  DatabaseTestHelper,
  ApiTestClient,
  WebSocketTestClient,
  integrationTestUtils,
};