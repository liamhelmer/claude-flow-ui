import { describe, expect, it, beforeEach, afterEach, jest } from '@jest/globals';

// Mock API client for testing
class MockApiClient {
  private baseUrl: string;
  private timeout: number;
  private headers: Record<string, string>;

  constructor(baseUrl = 'http://localhost:3000', timeout = 5000) {
    this.baseUrl = baseUrl;
    this.timeout = timeout;
    this.headers = {
      'Content-Type': 'application/json',
    };
  }

  async get<T>(endpoint: string, options?: RequestInit): Promise<T> {
    return this.request<T>('GET', endpoint, undefined, options);
  }

  async post<T>(endpoint: string, data?: any, options?: RequestInit): Promise<T> {
    return this.request<T>('POST', endpoint, data, options);
  }

  async put<T>(endpoint: string, data?: any, options?: RequestInit): Promise<T> {
    return this.request<T>('PUT', endpoint, data, options);
  }

  async delete<T>(endpoint: string, options?: RequestInit): Promise<T> {
    return this.request<T>('DELETE', endpoint, undefined, options);
  }

  async patch<T>(endpoint: string, data?: any, options?: RequestInit): Promise<T> {
    return this.request<T>('PATCH', endpoint, data, options);
  }

  private async request<T>(
    method: string,
    endpoint: string,
    data?: any,
    options?: RequestInit
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const config: RequestInit = {
      method,
      headers: {
        ...this.headers,
        ...options?.headers,
      },
      ...options,
    };

    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      config.body = JSON.stringify(data);
    }

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...config,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }

      return await response.text() as T;
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Request timeout');
      }
      
      throw error;
    }
  }

  setHeader(key: string, value: string): void {
    this.headers[key] = value;
  }

  removeHeader(key: string): void {
    delete this.headers[key];
  }

  setTimeout(timeout: number): void {
    this.timeout = timeout;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }
}

// Mock fetch globally
const mockFetch = jest.fn() as jest.MockedFunction<typeof fetch>;
global.fetch = mockFetch;

describe('ApiClient Enhanced Tests', () => {
  let apiClient: MockApiClient;
  let mockResponse: any;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    apiClient = new MockApiClient('http://localhost:3000', 5000);

    mockResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Map([['content-type', 'application/json']]),
      json: jest.fn().mockResolvedValue({ success: true }),
      text: jest.fn().mockResolvedValue('success'),
    };

    mockFetch.mockResolvedValue(mockResponse as Response);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Constructor and Configuration', () => {
    it('should initialize with default configuration', () => {
      const client = new MockApiClient();
      
      expect(client.getBaseUrl()).toBe('http://localhost:3000');
    });

    it('should initialize with custom base URL and timeout', () => {
      const client = new MockApiClient('https://api.example.com', 10000);
      
      expect(client.getBaseUrl()).toBe('https://api.example.com');
    });

    it('should set default headers', () => {
      expect(apiClient['headers']).toEqual({
        'Content-Type': 'application/json',
      });
    });

    it('should allow header management', () => {
      apiClient.setHeader('Authorization', 'Bearer token123');
      
      expect(apiClient['headers']['Authorization']).toBe('Bearer token123');

      apiClient.removeHeader('Authorization');
      
      expect(apiClient['headers']['Authorization']).toBeUndefined();
    });

    it('should allow timeout configuration', () => {
      apiClient.setTimeout(10000);
      
      expect(apiClient['timeout']).toBe(10000);
    });
  });

  describe('HTTP Methods', () => {
    it('should make GET requests', async () => {
      const result = await apiClient.get('/api/test');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );
      expect(result).toEqual({ success: true });
    });

    it('should make POST requests with data', async () => {
      const testData = { name: 'test', value: 123 };
      
      await apiClient.post('/api/test', testData);

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify(testData),
        })
      );
    });

    it('should make PUT requests with data', async () => {
      const testData = { id: 1, name: 'updated' };
      
      await apiClient.put('/api/test/1', testData);

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test/1',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify(testData),
        })
      );
    });

    it('should make DELETE requests', async () => {
      await apiClient.delete('/api/test/1');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test/1',
        expect.objectContaining({
          method: 'DELETE',
        })
      );
    });

    it('should make PATCH requests with data', async () => {
      const testData = { name: 'patched' };
      
      await apiClient.patch('/api/test/1', testData);

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test/1',
        expect.objectContaining({
          method: 'PATCH',
          body: JSON.stringify(testData),
        })
      );
    });
  });

  describe('Request Options and Headers', () => {
    it('should merge custom headers with default headers', async () => {
      const customHeaders = { 'X-Custom-Header': 'custom-value' };
      
      await apiClient.get('/api/test', { headers: customHeaders });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-Custom-Header': 'custom-value',
          }),
        })
      );
    });

    it('should allow custom headers to override defaults', async () => {
      await apiClient.get('/api/test', {
        headers: { 'Content-Type': 'text/plain' },
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'text/plain',
          }),
        })
      );
    });

    it('should pass through additional request options', async () => {
      await apiClient.get('/api/test', {
        cache: 'no-cache',
        credentials: 'include',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.objectContaining({
          cache: 'no-cache',
          credentials: 'include',
        })
      );
    });
  });

  describe('Response Handling', () => {
    it('should parse JSON responses', async () => {
      const mockData = { id: 1, name: 'test' };
      mockResponse.json.mockResolvedValue(mockData);

      const result = await apiClient.get('/api/test');

      expect(result).toEqual(mockData);
    });

    it('should handle text responses when not JSON', async () => {
      mockResponse.headers = new Map([['content-type', 'text/plain']]);
      mockResponse.text.mockResolvedValue('plain text response');

      const result = await apiClient.get('/api/test');

      expect(result).toBe('plain text response');
    });

    it('should handle responses with no content-type header', async () => {
      mockResponse.headers = new Map();
      mockResponse.text.mockResolvedValue('no content type');

      const result = await apiClient.get('/api/test');

      expect(result).toBe('no content type');
    });

    it('should handle empty responses', async () => {
      mockResponse.text.mockResolvedValue('');

      const result = await apiClient.get('/api/test');

      expect(result).toBe('');
    });
  });

  describe('Error Handling', () => {
    it('should throw error for HTTP error responses', async () => {
      mockResponse.ok = false;
      mockResponse.status = 404;
      mockResponse.statusText = 'Not Found';

      await expect(apiClient.get('/api/test')).rejects.toThrow(
        'HTTP Error: 404 Not Found'
      );
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(apiClient.get('/api/test')).rejects.toThrow('Network error');
    });

    it('should handle request timeout', async () => {
      // Mock a request that never resolves
      mockFetch.mockImplementation(() => new Promise(() => {}));

      const timeoutPromise = apiClient.get('/api/test');

      // Advance timers to trigger timeout
      jest.advanceTimersByTime(5000);

      await expect(timeoutPromise).rejects.toThrow('Request timeout');
    });

    it('should handle abort signal errors', async () => {
      mockFetch.mockRejectedValue(Object.assign(new Error('Aborted'), { name: 'AbortError' }));

      await expect(apiClient.get('/api/test')).rejects.toThrow('Request timeout');
    });

    it('should handle JSON parsing errors', async () => {
      mockResponse.headers = new Map([['content-type', 'application/json']]);
      mockResponse.json.mockRejectedValue(new Error('Invalid JSON'));

      await expect(apiClient.get('/api/test')).rejects.toThrow('Invalid JSON');
    });

    it('should handle different HTTP error codes', async () => {
      const errorCodes = [400, 401, 403, 500, 502, 503];

      for (const code of errorCodes) {
        mockResponse.ok = false;
        mockResponse.status = code;
        mockResponse.statusText = `Error ${code}`;

        await expect(apiClient.get('/api/test')).rejects.toThrow(
          `HTTP Error: ${code} Error ${code}`
        );
      }
    });
  });

  describe('Request Body Handling', () => {
    it('should not include body for GET requests', async () => {
      await apiClient.get('/api/test');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.not.objectContaining({
          body: expect.anything(),
        })
      );
    });

    it('should not include body for DELETE requests', async () => {
      await apiClient.delete('/api/test');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.not.objectContaining({
          body: expect.anything(),
        })
      );
    });

    it('should handle null/undefined data gracefully', async () => {
      await apiClient.post('/api/test', null);
      await apiClient.post('/api/test', undefined);

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle complex data structures', async () => {
      const complexData = {
        user: { id: 1, name: 'John' },
        items: [1, 2, 3],
        metadata: { created: new Date().toISOString() },
      };

      await apiClient.post('/api/test', complexData);

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test',
        expect.objectContaining({
          body: JSON.stringify(complexData),
        })
      );
    });
  });

  describe('Timeout Management', () => {
    it('should use custom timeout for specific requests', async () => {
      apiClient.setTimeout(1000);

      mockFetch.mockImplementation(() => new Promise(() => {}));

      const timeoutPromise = apiClient.get('/api/test');

      jest.advanceTimersByTime(1000);

      await expect(timeoutPromise).rejects.toThrow('Request timeout');
    });

    it('should handle very short timeouts', async () => {
      apiClient.setTimeout(1);

      mockFetch.mockImplementation(() => new Promise(() => {}));

      const timeoutPromise = apiClient.get('/api/test');

      jest.advanceTimersByTime(1);

      await expect(timeoutPromise).rejects.toThrow('Request timeout');
    });

    it('should handle zero timeout', async () => {
      apiClient.setTimeout(0);

      mockFetch.mockImplementation(() => new Promise(() => {}));

      const timeoutPromise = apiClient.get('/api/test');

      jest.advanceTimersByTime(0);

      await expect(timeoutPromise).rejects.toThrow('Request timeout');
    });
  });

  describe('Concurrent Requests', () => {
    it('should handle multiple concurrent requests', async () => {
      const requests = [
        apiClient.get('/api/test1'),
        apiClient.get('/api/test2'),
        apiClient.get('/api/test3'),
      ];

      const results = await Promise.all(requests);

      expect(results).toHaveLength(3);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should handle mixed success and failure responses', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse as Response)
        .mockRejectedValueOnce(new Error('Request failed'))
        .mockResolvedValueOnce(mockResponse as Response);

      const requests = [
        apiClient.get('/api/test1'),
        apiClient.get('/api/test2'),
        apiClient.get('/api/test3'),
      ];

      const results = await Promise.allSettled(requests);

      expect(results[0].status).toBe('fulfilled');
      expect(results[1].status).toBe('rejected');
      expect(results[2].status).toBe('fulfilled');
    });
  });

  describe('Performance and Memory', () => {
    it('should handle high-frequency requests efficiently', async () => {
      const startTime = performance.now();

      const requests = [];
      for (let i = 0; i < 100; i++) {
        requests.push(apiClient.get(`/api/test${i}`));
      }

      await Promise.all(requests);

      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(1000); // Should complete quickly
      expect(mockFetch).toHaveBeenCalledTimes(100);
    });

    it('should properly cleanup timers for cancelled requests', async () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      await apiClient.get('/api/test');

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
    });

    it('should handle large response payloads', async () => {
      const largeData = Array(10000).fill(0).map((_, i) => ({ id: i, data: `item${i}` }));
      mockResponse.json.mockResolvedValue(largeData);

      const result = await apiClient.get('/api/test');

      expect(result).toHaveLength(10000);
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle empty endpoint paths', async () => {
      await apiClient.get('');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000',
        expect.any(Object)
      );
    });

    it('should handle endpoints with query parameters', async () => {
      await apiClient.get('/api/test?param1=value1&param2=value2');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/test?param1=value1&param2=value2',
        expect.any(Object)
      );
    });

    it('should handle base URLs with trailing slashes', async () => {
      const client = new MockApiClient('http://localhost:3000/');
      
      await client.get('/api/test');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000//api/test',
        expect.any(Object)
      );
    });

    it('should handle special characters in endpoints', async () => {
      const endpoint = '/api/test with spaces/äöü/123';
      
      await apiClient.get(endpoint);

      expect(mockFetch).toHaveBeenCalledWith(
        `http://localhost:3000${endpoint}`,
        expect.any(Object)
      );
    });

    it('should handle circular reference in request data', async () => {
      const circularData: any = { name: 'test' };
      circularData.self = circularData;

      await expect(apiClient.post('/api/test', circularData)).rejects.toThrow();
    });

    it('should handle undefined/null endpoints', async () => {
      await expect(apiClient.get(null as any)).rejects.toThrow();
      await expect(apiClient.get(undefined as any)).rejects.toThrow();
    });
  });

  describe('Type Safety and Generics', () => {
    interface TestResponse {
      id: number;
      name: string;
    }

    it('should provide type-safe responses', async () => {
      const mockTypedResponse = { id: 1, name: 'test' };
      mockResponse.json.mockResolvedValue(mockTypedResponse);

      const result = await apiClient.get<TestResponse>('/api/test');

      expect(result.id).toBe(1);
      expect(result.name).toBe('test');
    });

    it('should handle array responses', async () => {
      const mockArrayResponse = [{ id: 1, name: 'test1' }, { id: 2, name: 'test2' }];
      mockResponse.json.mockResolvedValue(mockArrayResponse);

      const result = await apiClient.get<TestResponse[]>('/api/test');

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe(1);
    });
  });
});