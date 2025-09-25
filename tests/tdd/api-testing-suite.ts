/**
 * API Testing Suite for TDD
 * Comprehensive framework for testing REST APIs and WebSocket endpoints
 */

import { jest } from '@jest/globals';
import { EventEmitter } from 'events';

/**
 * API Test Configuration
 */
export interface ApiTestConfig {
  baseUrl: string;
  timeout?: number;
  retries?: number;
  headers?: Record<string, string>;
  auth?: {
    type: 'bearer' | 'basic' | 'custom';
    token?: string;
    username?: string;
    password?: string;
    headerName?: string;
  };
}

/**
 * API Response Interface
 */
export interface ApiTestResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: any;
  duration: number;
}

/**
 * API Test Expectation Builder
 */
export class ApiExpectationBuilder {
  private response: ApiTestResponse;

  constructor(response: ApiTestResponse) {
    this.response = response;
  }

  /**
   * Expect specific status code
   */
  toHaveStatus(status: number): ApiExpectationBuilder {
    expect(this.response.status).toBe(status);
    return this;
  }

  /**
   * Expect successful status (2xx)
   */
  toBeSuccessful(): ApiExpectationBuilder {
    expect(this.response.status).toBeGreaterThanOrEqual(200);
    expect(this.response.status).toBeLessThan(300);
    return this;
  }

  /**
   * Expect error status (4xx or 5xx)
   */
  toBeError(): ApiExpectationBuilder {
    expect(this.response.status).toBeGreaterThanOrEqual(400);
    return this;
  }

  /**
   * Expect client error (4xx)
   */
  toBeClientError(): ApiExpectationBuilder {
    expect(this.response.status).toBeGreaterThanOrEqual(400);
    expect(this.response.status).toBeLessThan(500);
    return this;
  }

  /**
   * Expect server error (5xx)
   */
  toBeServerError(): ApiExpectationBuilder {
    expect(this.response.status).toBeGreaterThanOrEqual(500);
    return this;
  }

  /**
   * Expect specific header
   */
  toHaveHeader(name: string, value?: string): ApiExpectationBuilder {
    expect(this.response.headers).toHaveProperty(name);
    if (value !== undefined) {
      expect(this.response.headers[name]).toBe(value);
    }
    return this;
  }

  /**
   * Expect JSON content type
   */
  toBeJson(): ApiExpectationBuilder {
    expect(this.response.headers['content-type']).toMatch(/application\/json/);
    return this;
  }

  /**
   * Expect specific data structure
   */
  toHaveData(expectedData: any): ApiExpectationBuilder {
    expect(this.response.data).toEqual(expectedData);
    return this;
  }

  /**
   * Expect data to match partial structure
   */
  toMatchData(partialData: any): ApiExpectationBuilder {
    expect(this.response.data).toMatchObject(partialData);
    return this;
  }

  /**
   * Expect data to have property
   */
  toHaveProperty(path: string, value?: any): ApiExpectationBuilder {
    if (value !== undefined) {
      expect(this.response.data).toHaveProperty(path, value);
    } else {
      expect(this.response.data).toHaveProperty(path);
    }
    return this;
  }

  /**
   * Expect array response
   */
  toBeArray(length?: number): ApiExpectationBuilder {
    expect(Array.isArray(this.response.data)).toBe(true);
    if (length !== undefined) {
      expect(this.response.data).toHaveLength(length);
    }
    return this;
  }

  /**
   * Expect response time within limit
   */
  toRespondWithin(milliseconds: number): ApiExpectationBuilder {
    expect(this.response.duration).toBeLessThanOrEqual(milliseconds);
    return this;
  }

  /**
   * Expect pagination structure
   */
  toHavePagination(): ApiExpectationBuilder {
    expect(this.response.data).toHaveProperty('data');
    expect(this.response.data).toHaveProperty('pagination');
    expect(this.response.data.pagination).toHaveProperty('page');
    expect(this.response.data.pagination).toHaveProperty('limit');
    expect(this.response.data.pagination).toHaveProperty('total');
    return this;
  }

  /**
   * Custom assertion
   */
  toSatisfy(predicate: (response: ApiTestResponse) => boolean, message?: string): ApiExpectationBuilder {
    expect(predicate(this.response)).toBe(true);
    if (message) {
      console.log(`Custom assertion: ${message}`);
    }
    return this;
  }

  /**
   * Get the raw response for further testing
   */
  getResponse(): ApiTestResponse {
    return this.response;
  }
}

/**
 * API Test Client
 */
export class ApiTestClient {
  private config: ApiTestConfig;
  private interceptors: {
    request: Array<(options: RequestInit) => RequestInit | Promise<RequestInit>>;
    response: Array<(response: ApiTestResponse) => ApiTestResponse | Promise<ApiTestResponse>>;
  } = { request: [], response: [] };

  constructor(config: ApiTestConfig) {
    this.config = config;
  }

  /**
   * Add request interceptor
   */
  addRequestInterceptor(interceptor: (options: RequestInit) => RequestInit | Promise<RequestInit>): void {
    this.interceptors.request.push(interceptor);
  }

  /**
   * Add response interceptor
   */
  addResponseInterceptor(interceptor: (response: ApiTestResponse) => ApiTestResponse | Promise<ApiTestResponse>): void {
    this.interceptors.response.push(interceptor);
  }

  /**
   * Prepare request options
   */
  private async prepareRequestOptions(options: RequestInit = {}): Promise<RequestInit> {
    let requestOptions: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
        ...options.headers,
      },
      ...options,
    };

    // Apply authentication
    if (this.config.auth) {
      const headers = requestOptions.headers as Record<string, string>;

      switch (this.config.auth.type) {
        case 'bearer':
          if (this.config.auth.token) {
            headers['Authorization'] = `Bearer ${this.config.auth.token}`;
          }
          break;
        case 'basic':
          if (this.config.auth.username && this.config.auth.password) {
            const credentials = btoa(`${this.config.auth.username}:${this.config.auth.password}`);
            headers['Authorization'] = `Basic ${credentials}`;
          }
          break;
        case 'custom':
          if (this.config.auth.headerName && this.config.auth.token) {
            headers[this.config.auth.headerName] = this.config.auth.token;
          }
          break;
      }
    }

    // Apply request interceptors
    for (const interceptor of this.interceptors.request) {
      requestOptions = await interceptor(requestOptions);
    }

    return requestOptions;
  }

  /**
   * Make HTTP request
   */
  private async makeRequest(path: string, options: RequestInit = {}): Promise<ApiTestResponse> {
    const startTime = Date.now();
    const url = `${this.config.baseUrl}${path}`;
    const requestOptions = await this.prepareRequestOptions(options);

    try {
      const response = await fetch(url, requestOptions);
      const duration = Date.now() - startTime;

      let data: any;
      try {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          data = await response.json();
        } else {
          data = await response.text();
        }
      } catch {
        data = null;
      }

      let apiResponse: ApiTestResponse = {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        data,
        duration,
      };

      // Apply response interceptors
      for (const interceptor of this.interceptors.response) {
        apiResponse = await interceptor(apiResponse);
      }

      return apiResponse;
    } catch (error) {
      const duration = Date.now() - startTime;
      throw new Error(`Request failed after ${duration}ms: ${error}`);
    }
  }

  /**
   * GET request
   */
  async get(path: string, options: RequestInit = {}): Promise<ApiExpectationBuilder> {
    const response = await this.makeRequest(path, { ...options, method: 'GET' });
    return new ApiExpectationBuilder(response);
  }

  /**
   * POST request
   */
  async post(path: string, body?: any, options: RequestInit = {}): Promise<ApiExpectationBuilder> {
    const requestOptions: RequestInit = { ...options, method: 'POST' };
    if (body !== undefined) {
      requestOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const response = await this.makeRequest(path, requestOptions);
    return new ApiExpectationBuilder(response);
  }

  /**
   * PUT request
   */
  async put(path: string, body?: any, options: RequestInit = {}): Promise<ApiExpectationBuilder> {
    const requestOptions: RequestInit = { ...options, method: 'PUT' };
    if (body !== undefined) {
      requestOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const response = await this.makeRequest(path, requestOptions);
    return new ApiExpectationBuilder(response);
  }

  /**
   * PATCH request
   */
  async patch(path: string, body?: any, options: RequestInit = {}): Promise<ApiExpectationBuilder> {
    const requestOptions: RequestInit = { ...options, method: 'PATCH' };
    if (body !== undefined) {
      requestOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const response = await this.makeRequest(path, requestOptions);
    return new ApiExpectationBuilder(response);
  }

  /**
   * DELETE request
   */
  async delete(path: string, options: RequestInit = {}): Promise<ApiExpectationBuilder> {
    const response = await this.makeRequest(path, { ...options, method: 'DELETE' });
    return new ApiExpectationBuilder(response);
  }

  /**
   * Upload file
   */
  async upload(path: string, file: Blob | Buffer, filename: string, options: RequestInit = {}): Promise<ApiExpectationBuilder> {
    const formData = new FormData();
    formData.append('file', file as Blob, filename);

    const requestOptions: RequestInit = {
      ...options,
      method: 'POST',
      body: formData,
      headers: {
        // Don't set Content-Type for FormData, let browser set it with boundary
        ...options.headers,
      },
    };

    // Remove Content-Type header to let browser set it
    if (requestOptions.headers) {
      delete (requestOptions.headers as any)['Content-Type'];
    }

    const response = await this.makeRequest(path, requestOptions);
    return new ApiExpectationBuilder(response);
  }

  /**
   * Batch requests (run multiple requests in parallel)
   */
  async batch(requests: Array<{ method: string; path: string; body?: any }>): Promise<ApiExpectationBuilder[]> {
    const promises = requests.map(req => {
      switch (req.method.toLowerCase()) {
        case 'get':
          return this.get(req.path);
        case 'post':
          return this.post(req.path, req.body);
        case 'put':
          return this.put(req.path, req.body);
        case 'patch':
          return this.patch(req.path, req.body);
        case 'delete':
          return this.delete(req.path);
        default:
          throw new Error(`Unsupported method: ${req.method}`);
      }
    });

    return Promise.all(promises);
  }
}

/**
 * WebSocket Test Client
 */
export class WebSocketTestClient extends EventEmitter {
  private ws: WebSocket | null = null;
  private url: string;
  private messages: any[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 3;

  constructor(url: string) {
    super();
    this.url = url;
  }

  /**
   * Connect to WebSocket
   */
  async connect(timeout: number = 5000): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`WebSocket connection timeout after ${timeout}ms`));
      }, timeout);

      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        clearTimeout(timeoutId);
        this.reconnectAttempts = 0;
        this.emit('open');
        resolve();
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.messages.push(message);
          this.emit('message', message);
        } catch {
          // Handle non-JSON messages
          this.messages.push(event.data);
          this.emit('message', event.data);
        }
      };

      this.ws.onclose = (event) => {
        clearTimeout(timeoutId);
        this.emit('close', event);

        // Auto-reconnect logic
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          this.reconnectAttempts++;
          setTimeout(() => this.connect(), 1000);
        }
      };

      this.ws.onerror = (error) => {
        clearTimeout(timeoutId);
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
      const data = typeof message === 'string' ? message : JSON.stringify(message);
      this.ws.send(data);
    } else {
      throw new Error('WebSocket is not connected');
    }
  }

  /**
   * Wait for specific message
   */
  async waitForMessage(
    predicate: (message: any) => boolean,
    timeout: number = 5000
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      // Check existing messages
      const existingMessage = this.messages.find(predicate);
      if (existingMessage) {
        resolve(existingMessage);
        return;
      }

      const timeoutId = setTimeout(() => {
        this.off('message', onMessage);
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
   * Wait for connection to be ready
   */
  async waitForOpen(timeout: number = 5000): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`WebSocket not ready after ${timeout}ms`));
      }, timeout);

      this.once('open', () => {
        clearTimeout(timeoutId);
        resolve();
      });
    });
  }

  /**
   * Get all messages
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

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

/**
 * API Test Suite Builder
 */
export class ApiTestSuiteBuilder {
  private client: ApiTestClient;
  private wsClients: WebSocketTestClient[] = [];
  private beforeHooks: (() => Promise<void>)[] = [];
  private afterHooks: (() => Promise<void>)[] = [];

  constructor(config: ApiTestConfig) {
    this.client = new ApiTestClient(config);
  }

  /**
   * Add before hook
   */
  before(hook: () => Promise<void>): ApiTestSuiteBuilder {
    this.beforeHooks.push(hook);
    return this;
  }

  /**
   * Add after hook
   */
  after(hook: () => Promise<void>): ApiTestSuiteBuilder {
    this.afterHooks.push(hook);
    return this;
  }

  /**
   * Add request interceptor
   */
  interceptRequest(interceptor: (options: RequestInit) => RequestInit | Promise<RequestInit>): ApiTestSuiteBuilder {
    this.client.addRequestInterceptor(interceptor);
    return this;
  }

  /**
   * Add response interceptor
   */
  interceptResponse(interceptor: (response: ApiTestResponse) => ApiTestResponse | Promise<ApiTestResponse>): ApiTestSuiteBuilder {
    this.client.addResponseInterceptor(interceptor);
    return this;
  }

  /**
   * Create WebSocket client
   */
  createWebSocketClient(url: string): WebSocketTestClient {
    const wsClient = new WebSocketTestClient(url);
    this.wsClients.push(wsClient);
    return wsClient;
  }

  /**
   * Build the test suite
   */
  build(): {
    client: ApiTestClient;
    runBefore: () => Promise<void>;
    runAfter: () => Promise<void>;
    createWebSocketClient: (url: string) => WebSocketTestClient;
  } {
    return {
      client: this.client,
      runBefore: async () => {
        for (const hook of this.beforeHooks) {
          await hook();
        }
      },
      runAfter: async () => {
        // Close all WebSocket connections
        await Promise.all(this.wsClients.map(ws => ws.close()));

        for (const hook of this.afterHooks) {
          await hook();
        }
      },
      createWebSocketClient: (url: string) => this.createWebSocketClient(url),
    };
  }
}

/**
 * Factory function to create API test suite
 */
export const createApiTestSuite = (config: ApiTestConfig): ApiTestSuiteBuilder => {
  return new ApiTestSuiteBuilder(config);
};

/**
 * Utility functions for API testing
 */
export const apiTestUtils = {
  /**
   * Create mock API server responses
   */
  mockResponses: {
    success: (data: any) => ({ success: true, data }),
    error: (message: string, code = 400) => ({ success: false, error: { message, code } }),
    paginated: (items: any[], page = 1, limit = 10) => ({
      success: true,
      data: items,
      pagination: { page, limit, total: items.length * 3, totalPages: 3 },
    }),
  },

  /**
   * Generate test data for API endpoints
   */
  generateTestData: {
    user: () => ({
      id: Math.random().toString(36).substr(2, 9),
      name: `Test User ${Date.now()}`,
      email: `test${Date.now()}@example.com`,
    }),
    session: () => ({
      id: Math.random().toString(36).substr(2, 9),
      userId: Math.random().toString(36).substr(2, 9),
      token: Math.random().toString(36).substr(2, 32),
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
    }),
  },

  /**
   * Validate API response schemas
   */
  validateSchema: (data: any, schema: any): boolean => {
    // Basic schema validation - extend with proper JSON schema validator
    for (const [key, type] of Object.entries(schema)) {
      if (!(key in data)) return false;
      if (typeof data[key] !== type) return false;
    }
    return true;
  },
};

// Export everything
export default {
  createApiTestSuite,
  ApiTestClient,
  WebSocketTestClient,
  ApiExpectationBuilder,
  apiTestUtils,
};