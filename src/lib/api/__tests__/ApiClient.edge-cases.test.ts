/**
 * Comprehensive Edge Case Tests for ApiClient
 * 
 * Coverage Focus:
 * - Network error scenarios
 * - Invalid parameter validation
 * - HTTP status code edge cases
 * - Response parsing errors
 * - Timeout handling
 * - URL construction edge cases
 * 
 * Priority: HIGH - Critical for API reliability
 */

import { ApiClient } from '../index';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('ApiClient - Edge Cases & Error Handling', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient('http://test-api.com/api');
    mockFetch.mockClear();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Constructor behavior', () => {
    it('should use default baseUrl when none provided', () => {
      const defaultClient = new ApiClient();
      expect(defaultClient).toBeInstanceOf(ApiClient);
      // BaseUrl is private, so we test behavior through a method call
    });

    it('should handle custom baseUrl correctly', () => {
      const customClient = new ApiClient('https://custom.api.com');
      expect(customClient).toBeInstanceOf(ApiClient);
    });

    it('should handle empty string baseUrl', () => {
      const emptyClient = new ApiClient('');
      expect(emptyClient).toBeInstanceOf(ApiClient);
    });

    it('should handle baseUrl with trailing slash', () => {
      const trailingSlashClient = new ApiClient('http://api.com/');
      expect(trailingSlashClient).toBeInstanceOf(ApiClient);
    });
  });

  describe('GET method edge cases', () => {
    describe('Parameter validation', () => {
      it('should throw error for empty endpoint', async () => {
        await expect(client.get('')).rejects.toThrow(
          'ApiClient.get: endpoint cannot be empty or whitespace'
        );
      });

      it('should throw error for whitespace-only endpoint', async () => {
        await expect(client.get('   ')).rejects.toThrow(
          'ApiClient.get: endpoint cannot be empty or whitespace'
        );
      });

      it('should throw error for non-string endpoint', async () => {
        // @ts-ignore - Testing runtime validation
        await expect(client.get(123)).rejects.toThrow(
          'ApiClient.get: endpoint must be a non-empty string'
        );
      });

      it('should throw error for null endpoint', async () => {
        // @ts-ignore - Testing runtime validation
        await expect(client.get(null)).rejects.toThrow(
          'ApiClient.get: endpoint must be a non-empty string'
        );
      });

      it('should throw error for undefined endpoint', async () => {
        // @ts-ignore - Testing runtime validation
        await expect(client.get(undefined)).rejects.toThrow(
          'ApiClient.get: endpoint must be a non-empty string'
        );
      });
    });

    describe('Network errors', () => {
      it('should handle network failure', async () => {
        mockFetch.mockRejectedValue(new Error('Network error'));
        
        await expect(client.get('/test')).rejects.toThrow('Network error');
      });

      it('should handle fetch throwing non-Error objects', async () => {
        mockFetch.mockRejectedValue('String error');
        
        await expect(client.get('/test')).rejects.toThrow(
          'ApiClient.get: Unexpected error - String error'
        );
      });

      it('should handle fetch throwing null', async () => {
        mockFetch.mockRejectedValue(null);
        
        await expect(client.get('/test')).rejects.toThrow(
          'ApiClient.get: Unexpected error - null'
        );
      });
    });

    describe('HTTP status codes', () => {
      it('should handle 404 Not Found', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Not Found',
          json: jest.fn().mockResolvedValue({ error: 'Resource not found' })
        });

        await expect(client.get('/nonexistent')).rejects.toThrow('API Error: Not Found');
      });

      it('should handle 500 Internal Server Error', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Internal Server Error',
          json: jest.fn()
        });

        await expect(client.get('/error')).rejects.toThrow('API Error: Internal Server Error');
      });

      it('should handle empty statusText', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: '',
          json: jest.fn()
        });

        await expect(client.get('/test')).rejects.toThrow('API Error: ');
      });

      it('should handle 401 Unauthorized', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Unauthorized',
          json: jest.fn()
        });

        await expect(client.get('/protected')).rejects.toThrow('API Error: Unauthorized');
      });

      it('should handle 429 Too Many Requests', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Too Many Requests',
          json: jest.fn()
        });

        await expect(client.get('/rate-limited')).rejects.toThrow('API Error: Too Many Requests');
      });
    });

    describe('Response parsing errors', () => {
      it('should handle invalid JSON response', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockRejectedValue(new Error('Invalid JSON'))
        });

        await expect(client.get('/invalid-json')).rejects.toThrow('Invalid JSON');
      });

      it('should handle response.json() throwing non-Error', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockRejectedValue('Parse error')
        });

        await expect(client.get('/test')).rejects.toThrow('Parse error');
      });

      it('should handle successful response with null JSON', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue(null)
        });

        const result = await client.get('/null-response');
        expect(result).toBeNull();
      });

      it('should handle successful response with empty object', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({})
        });

        const result = await client.get('/empty-object');
        expect(result).toEqual({});
      });
    });

    describe('URL construction', () => {
      it('should handle endpoint with leading slash', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

        await client.get('/users');
        
        expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users');
      });

      it('should handle endpoint without leading slash', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

        await client.get('users');
        
        expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/apiusers');
      });

      it('should handle complex endpoint paths', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

        await client.get('/users/123/posts?limit=10');
        
        expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users/123/posts?limit=10');
      });
    });
  });

  describe('POST method edge cases', () => {
    describe('Parameter validation', () => {
      it('should throw error for empty endpoint', async () => {
        await expect(client.post('', { data: 'test' })).rejects.toThrow(
          'ApiClient.post: endpoint cannot be empty or whitespace'
        );
      });

      it('should throw error for whitespace-only endpoint', async () => {
        await expect(client.post('   ', { data: 'test' })).rejects.toThrow(
          'ApiClient.post: endpoint cannot be empty or whitespace'
        );
      });

      it('should throw error for non-string endpoint', async () => {
        // @ts-ignore - Testing runtime validation
        await expect(client.post(456, { data: 'test' })).rejects.toThrow(
          'ApiClient.post: endpoint must be a non-empty string'
        );
      });
    });

    describe('Data handling', () => {
      it('should handle null data', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

        await client.post('/test', null);
        
        expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: 'null'
        });
      });

      it('should handle undefined data', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

        await client.post('/test', undefined);
        
        expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: undefined
        });
      });

      it('should handle complex objects', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

        const complexData = {
          nested: { array: [1, 2, 3] },
          string: 'test',
          number: 42,
          boolean: true,
          nullValue: null
        };

        await client.post('/test', complexData);
        
        expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(complexData)
        });
      });

      it('should handle circular reference objects', async () => {
        const circularData: any = { a: 1 };
        circularData.self = circularData;

        // JSON.stringify should throw for circular references
        await expect(client.post('/test', circularData)).rejects.toThrow();
      });
    });

    describe('Network and parsing errors', () => {
      it('should handle POST request network failure', async () => {
        mockFetch.mockRejectedValue(new Error('Network POST error'));
        
        await expect(client.post('/test', { data: 'test' })).rejects.toThrow('Network POST error');
      });

      it('should handle 422 Unprocessable Entity', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Unprocessable Entity',
          json: jest.fn()
        });

        await expect(client.post('/test', { invalid: 'data' })).rejects.toThrow(
          'API Error: Unprocessable Entity'
        );
      });

      it('should handle 413 Payload Too Large', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Payload Too Large',
          json: jest.fn()
        });

        await expect(client.post('/test', { huge: 'data' })).rejects.toThrow(
          'API Error: Payload Too Large'
        );
      });
    });
  });

  describe('DELETE method edge cases', () => {
    describe('Parameter validation', () => {
      it('should throw error for empty endpoint', async () => {
        await expect(client.delete('')).rejects.toThrow(
          'ApiClient.delete: endpoint cannot be empty or whitespace'
        );
      });

      it('should throw error for whitespace-only endpoint', async () => {
        await expect(client.delete('   ')).rejects.toThrow(
          'ApiClient.delete: endpoint cannot be empty or whitespace'
        );
      });

      it('should throw error for non-string endpoint', async () => {
        // @ts-ignore - Testing runtime validation
        await expect(client.delete(789)).rejects.toThrow(
          'ApiClient.delete: endpoint must be a non-empty string'
        );
      });
    });

    describe('DELETE-specific scenarios', () => {
      it('should handle successful DELETE with empty response', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({})
        });

        const result = await client.delete('/users/123');
        expect(result).toEqual({});
      });

      it('should handle 404 for DELETE on non-existent resource', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Not Found',
          json: jest.fn()
        });

        await expect(client.delete('/users/999')).rejects.toThrow('API Error: Not Found');
      });

      it('should handle 405 Method Not Allowed', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Method Not Allowed',
          json: jest.fn()
        });

        await expect(client.delete('/readonly-resource')).rejects.toThrow(
          'API Error: Method Not Allowed'
        );
      });

      it('should handle 409 Conflict (resource in use)', async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          statusText: 'Conflict',
          json: jest.fn()
        });

        await expect(client.delete('/users/admin')).rejects.toThrow('API Error: Conflict');
      });
    });
  });

  describe('Cross-method scenarios', () => {
    it('should handle rapid successive requests', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true })
      });

      const promises = [
        client.get('/test1'),
        client.post('/test2', { data: 'test' }),
        client.delete('/test3'),
        client.get('/test4')
      ];

      await Promise.all(promises);
      expect(mockFetch).toHaveBeenCalledTimes(4);
    });

    it('should handle mixed success and failure requests', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        })
        .mockResolvedValueOnce({
          ok: false,
          statusText: 'Bad Request',
          json: jest.fn()
        });

      const results = await Promise.allSettled([
        client.get('/success'),
        client.get('/failure')
      ]);

      expect(results[0].status).toBe('fulfilled');
      expect(results[1].status).toBe('rejected');
    });

    it('should maintain state across requests', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true })
      });

      // Each call should use the same baseUrl
      await client.get('/endpoint1');
      await client.post('/endpoint2', {});
      await client.delete('/endpoint3');

      expect(mockFetch).toHaveBeenNthCalledWith(1, 'http://test-api.com/api/endpoint1');
      expect(mockFetch).toHaveBeenNthCalledWith(2, 'http://test-api.com/api/endpoint2', expect.any(Object));
      expect(mockFetch).toHaveBeenNthCalledWith(3, 'http://test-api.com/api/endpoint3', expect.any(Object));
    });

    it('should handle timeout scenarios (fetch API limitation)', async () => {
      // Note: fetch API doesn't have built-in timeout, but we test long delays
      const slowResponse = new Promise(resolve => {
        setTimeout(() => resolve({
          ok: true,
          json: jest.fn().mockResolvedValue({ slow: true })
        }), 100);
      });

      mockFetch.mockImplementation(() => slowResponse);
      
      const start = Date.now();
      const result = await client.get('/slow');
      const duration = Date.now() - start;
      
      expect(duration).toBeGreaterThanOrEqual(95); // Allow some timing variance
      expect(result).toEqual({ slow: true });
    });
  });

  describe('Response type handling', () => {
    it('should handle array responses', async () => {
      const arrayResponse = [{ id: 1 }, { id: 2 }];
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(arrayResponse)
      });

      const result = await client.get('/array');
      expect(result).toEqual(arrayResponse);
    });

    it('should handle string responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue('string response')
      });

      const result = await client.get('/string');
      expect(result).toBe('string response');
    });

    it('should handle number responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(42)
      });

      const result = await client.get('/number');
      expect(result).toBe(42);
    });

    it('should handle boolean responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(true)
      });

      const result = await client.get('/boolean');
      expect(result).toBe(true);
    });
  });
});