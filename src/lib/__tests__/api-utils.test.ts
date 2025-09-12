/**
 * API Utilities Test Suite
 * Tests for API client functionality with comprehensive error handling
 */

import { ApiClient, apiClient } from '../api/index';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('API Utils Test Suite', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  describe('ApiClient Constructor', () => {
    it('should create ApiClient with default base URL', () => {
      const client = new ApiClient();
      expect(client).toBeDefined();
    });

    it('should create ApiClient with custom base URL', () => {
      const customUrl = 'https://api.example.com';
      const client = new ApiClient(customUrl);
      expect(client).toBeDefined();
    });

    it('should handle empty string base URL', () => {
      const client = new ApiClient('');
      expect(client).toBeDefined();
    });
  });

  describe('GET Requests', () => {
    let client: ApiClient;

    beforeEach(() => {
      client = new ApiClient('http://localhost:3001/api');
    });

    it('should make successful GET request', async () => {
      const mockResponse = { data: 'test data' };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const result = await client.get('/test');

      expect(fetch).toHaveBeenCalledWith('http://localhost:3001/api/test');
      expect(result).toEqual(mockResponse);
    });

    it('should handle GET request errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Not Found'
      });

      await expect(client.get('/nonexistent')).rejects.toThrow('API Error: Not Found');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(client.get('/test')).rejects.toThrow('Network error');
    });

    it('should validate endpoint parameter', async () => {
      await expect(client.get('')).rejects.toThrow('endpoint cannot be empty or whitespace');
      await expect(client.get('   ')).rejects.toThrow('endpoint cannot be empty or whitespace');
      await expect(client.get(null as any)).rejects.toThrow('endpoint must be a non-empty string');
      await expect(client.get(undefined as any)).rejects.toThrow('endpoint must be a non-empty string');
      await expect(client.get(123 as any)).rejects.toThrow('endpoint must be a non-empty string');
    });

    it('should handle JSON parsing errors', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockRejectedValue(new Error('Invalid JSON'))
      });

      await expect(client.get('/test')).rejects.toThrow('Invalid JSON');
    });

    it('should handle non-Error exceptions', async () => {
      mockFetch.mockRejectedValue('String error');

      await expect(client.get('/test')).rejects.toThrow('ApiClient.get: Unexpected error - String error');
    });
  });

  describe('POST Requests', () => {
    let client: ApiClient;

    beforeEach(() => {
      client = new ApiClient('http://localhost:3001/api');
    });

    it('should make successful POST request', async () => {
      const postData = { name: 'test', value: 123 };
      const mockResponse = { id: 1, ...postData };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const result = await client.post('/users', postData);

      expect(fetch).toHaveBeenCalledWith('http://localhost:3001/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(postData)
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle POST request errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Bad Request'
      });

      await expect(client.post('/users', { data: 'test' })).rejects.toThrow('API Error: Bad Request');
    });

    it('should validate POST endpoint parameter', async () => {
      const data = { test: 'data' };
      
      await expect(client.post('', data)).rejects.toThrow('endpoint cannot be empty or whitespace');
      await expect(client.post('   ', data)).rejects.toThrow('endpoint cannot be empty or whitespace');
      await expect(client.post(null as any, data)).rejects.toThrow('endpoint must be a non-empty string');
      await expect(client.post(undefined as any, data)).rejects.toThrow('endpoint must be a non-empty string');
    });

    it('should handle POST with null/undefined data', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true })
      });

      await expect(client.post('/test', null)).resolves.toBeDefined();
      await expect(client.post('/test', undefined)).resolves.toBeDefined();
    });

    it('should handle POST with complex data types', async () => {
      const complexData = {
        string: 'test',
        number: 123,
        boolean: true,
        array: [1, 2, 3],
        object: { nested: 'value' },
        date: new Date(),
        nullValue: null,
        undefinedValue: undefined
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ received: true })
      });

      const result = await client.post('/complex', complexData);

      expect(fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify(complexData)
        })
      );
      expect(result).toEqual({ received: true });
    });

    it('should handle JSON stringify errors', async () => {
      const circularData = { a: null } as any;
      circularData.a = circularData; // Create circular reference

      await expect(client.post('/test', circularData)).rejects.toThrow();
    });

    it('should handle POST network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Connection timeout'));

      await expect(client.post('/test', { data: 'test' })).rejects.toThrow('Connection timeout');
    });

    it('should handle non-Error exceptions in POST', async () => {
      mockFetch.mockRejectedValue({ error: 'object error' });

      await expect(client.post('/test', {})).rejects.toThrow('ApiClient.post: Unexpected error');
    });
  });

  describe('DELETE Requests', () => {
    let client: ApiClient;

    beforeEach(() => {
      client = new ApiClient('http://localhost:3001/api');
    });

    it('should make successful DELETE request', async () => {
      const mockResponse = { deleted: true };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const result = await client.delete('/users/123');

      expect(fetch).toHaveBeenCalledWith('http://localhost:3001/api/users/123', {
        method: 'DELETE'
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle DELETE request errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Forbidden'
      });

      await expect(client.delete('/users/123')).rejects.toThrow('API Error: Forbidden');
    });

    it('should validate DELETE endpoint parameter', async () => {
      await expect(client.delete('')).rejects.toThrow('endpoint cannot be empty or whitespace');
      await expect(client.delete('   ')).rejects.toThrow('endpoint cannot be empty or whitespace');
      await expect(client.delete(null as any)).rejects.toThrow('endpoint must be a non-empty string');
      await expect(client.delete(undefined as any)).rejects.toThrow('endpoint must be a non-empty string');
    });

    it('should handle DELETE network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Server unavailable'));

      await expect(client.delete('/test')).rejects.toThrow('Server unavailable');
    });

    it('should handle non-Error exceptions in DELETE', async () => {
      mockFetch.mockRejectedValue(404);

      await expect(client.delete('/test')).rejects.toThrow('ApiClient.delete: Unexpected error - 404');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    let client: ApiClient;

    beforeEach(() => {
      client = new ApiClient();
    });

    it('should handle malformed JSON responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockRejectedValue(new SyntaxError('Unexpected token'))
      });

      await expect(client.get('/test')).rejects.toThrow('Unexpected token');
    });

    it('should handle empty responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(null)
      });

      const result = await client.get('/test');
      expect(result).toBeNull();
    });

    it('should handle responses with status 204 (No Content)', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 204,
        json: jest.fn().mockResolvedValue(undefined)
      });

      const result = await client.get('/test');
      expect(result).toBeUndefined();
    });

    it('should handle various HTTP status codes', async () => {
      const statusCodes = [
        { code: 400, text: 'Bad Request' },
        { code: 401, text: 'Unauthorized' },
        { code: 403, text: 'Forbidden' },
        { code: 404, text: 'Not Found' },
        { code: 500, text: 'Internal Server Error' },
        { code: 502, text: 'Bad Gateway' },
        { code: 503, text: 'Service Unavailable' }
      ];

      for (const status of statusCodes) {
        mockFetch.mockResolvedValue({
          ok: false,
          status: status.code,
          statusText: status.text
        });

        await expect(client.get('/test')).rejects.toThrow(`API Error: ${status.text}`);
      }
    });

    it('should handle request timeouts', async () => {
      mockFetch.mockImplementation(() => 
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), 100)
        )
      );

      await expect(client.get('/slow-endpoint')).rejects.toThrow('Timeout');
    });

    it('should handle AbortController cancellation', async () => {
      mockFetch.mockRejectedValue(new DOMException('The user aborted a request.', 'AbortError'));

      await expect(client.get('/test')).rejects.toThrow('The user aborted a request.');
    });
  });

  describe('TypeScript Generic Support', () => {
    let client: ApiClient;

    beforeEach(() => {
      client = new ApiClient();
    });

    it('should support typed GET responses', async () => {
      interface User {
        id: number;
        name: string;
        email: string;
      }

      const mockUser: User = { id: 1, name: 'John', email: 'john@example.com' };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockUser)
      });

      const user = await client.get<User>('/user/1');
      
      // TypeScript should infer the correct type
      expect(user.id).toBe(1);
      expect(user.name).toBe('John');
      expect(user.email).toBe('john@example.com');
    });

    it('should support typed POST requests and responses', async () => {
      interface CreateUserRequest {
        name: string;
        email: string;
      }

      interface CreateUserResponse {
        id: number;
        name: string;
        email: string;
        createdAt: string;
      }

      const requestData: CreateUserRequest = {
        name: 'Jane',
        email: 'jane@example.com'
      };

      const mockResponse: CreateUserResponse = {
        id: 2,
        name: 'Jane',
        email: 'jane@example.com',
        createdAt: '2025-01-01T00:00:00Z'
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const response = await client.post<CreateUserResponse>('/users', requestData);
      
      expect(response.id).toBe(2);
      expect(response.createdAt).toBeDefined();
    });

    it('should support typed DELETE responses', async () => {
      interface DeleteResponse {
        deleted: boolean;
        id: number;
      }

      const mockResponse: DeleteResponse = { deleted: true, id: 123 };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const response = await client.delete<DeleteResponse>('/users/123');
      
      expect(response.deleted).toBe(true);
      expect(response.id).toBe(123);
    });
  });

  describe('Singleton Instance', () => {
    it('should export singleton apiClient', () => {
      expect(apiClient).toBeInstanceOf(ApiClient);
    });

    it('should maintain same instance across imports', () => {
      const { apiClient: apiClient1 } = require('../api/index');
      const { apiClient: apiClient2 } = require('../api/index');
      
      expect(apiClient1).toBe(apiClient2);
    });
  });

  describe('Concurrent Requests', () => {
    let client: ApiClient;

    beforeEach(() => {
      client = new ApiClient();
    });

    it('should handle multiple concurrent GET requests', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ data: 'response1' })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ data: 'response2' })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ data: 'response3' })
        });

      const requests = [
        client.get('/endpoint1'),
        client.get('/endpoint2'),
        client.get('/endpoint3')
      ];

      const results = await Promise.all(requests);

      expect(results).toHaveLength(3);
      expect(results[0]).toEqual({ data: 'response1' });
      expect(results[1]).toEqual({ data: 'response2' });
      expect(results[2]).toEqual({ data: 'response3' });
    });

    it('should handle mixed method concurrent requests', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ data: 'get result' })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ created: true })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ deleted: true })
        });

      const requests = [
        client.get('/data'),
        client.post('/create', { name: 'test' }),
        client.delete('/delete/123')
      ];

      const results = await Promise.all(requests);

      expect(results).toHaveLength(3);
      expect(results[0]).toEqual({ data: 'get result' });
      expect(results[1]).toEqual({ created: true });
      expect(results[2]).toEqual({ deleted: true });
    });

    it('should handle partial failures in concurrent requests', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        })
        .mockResolvedValueOnce({
          ok: false,
          statusText: 'Server Error'
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });

      const requests = [
        client.get('/success1'),
        client.get('/error'),
        client.get('/success2')
      ];

      const results = await Promise.allSettled(requests);

      expect(results[0].status).toBe('fulfilled');
      expect(results[1].status).toBe('rejected');
      expect(results[2].status).toBe('fulfilled');
      
      if (results[1].status === 'rejected') {
        expect(results[1].reason.message).toContain('Server Error');
      }
    });
  });
});