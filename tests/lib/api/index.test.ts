import { ApiClient, apiClient } from '@/lib/api/index';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('ApiClient', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient('http://localhost:3001/api');
    mockFetch.mockClear();
  });

  describe('Constructor', () => {
    it('should use default base URL when none provided', () => {
      const defaultClient = new ApiClient();
      expect(defaultClient['baseUrl']).toBe('http://localhost:3001/api');
    });

    it('should use provided base URL', () => {
      const customClient = new ApiClient('http://custom.api.com');
      expect(customClient['baseUrl']).toBe('http://custom.api.com');
    });
  });

  describe('GET requests', () => {
    it('should make successful GET request', async () => {
      const mockResponse = { data: 'test' };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse),
      });

      const result = await client.get('/test');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/test');
      expect(result).toEqual(mockResponse);
    });

    it('should handle GET request errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Not Found',
      });

      await expect(client.get('/nonexistent')).rejects.toThrow('API Error: Not Found');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(client.get('/test')).rejects.toThrow('Network error');
    });

    it('should handle malformed JSON responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockRejectedValue(new Error('Invalid JSON')),
      });

      await expect(client.get('/test')).rejects.toThrow('Invalid JSON');
    });
  });

  describe('POST requests', () => {
    it('should make successful POST request', async () => {
      const mockResponse = { id: 1, created: true };
      const postData = { name: 'test', value: 42 };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse),
      });

      const result = await client.post('/create', postData);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(postData),
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle POST request errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Bad Request',
      });

      await expect(client.post('/create', {})).rejects.toThrow('API Error: Bad Request');
    });

    it('should handle POST with null/undefined data', async () => {
      const mockResponse = { success: true };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse),
      });

      await expect(client.post('/create', null)).resolves.toEqual(mockResponse);
      await expect(client.post('/create', undefined)).resolves.toEqual(mockResponse);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(null),
      });
    });

    it('should serialize complex objects correctly', async () => {
      const complexData = {
        nested: {
          array: [1, 2, 3],
          boolean: true,
          null: null,
        },
        date: new Date('2023-01-01'),
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({}),
      });

      await client.post('/complex', complexData);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/complex', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(complexData),
      });
    });
  });

  describe('DELETE requests', () => {
    it('should make successful DELETE request', async () => {
      const mockResponse = { deleted: true };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse),
      });

      const result = await client.delete('/item/123');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/item/123', {
        method: 'DELETE',
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle DELETE request errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Forbidden',
      });

      await expect(client.delete('/protected')).rejects.toThrow('API Error: Forbidden');
    });
  });

  describe('URL Construction', () => {
    it('should handle endpoints with leading slash', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({}),
      });

      await client.get('/test');
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/test');
    });

    it('should handle endpoints without leading slash', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({}),
      });

      await client.get('test');
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/apitest');
    });

    it('should handle base URL with trailing slash', async () => {
      const clientWithTrailingSlash = new ApiClient('http://localhost:3001/api/');
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({}),
      });

      await clientWithTrailingSlash.get('/test');
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api//test');
    });
  });

  describe('Response Handling', () => {
    it('should handle empty responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(null),
      });

      const result = await client.get('/empty');
      expect(result).toBeNull();
    });

    it('should handle array responses', async () => {
      const mockArray = [{ id: 1 }, { id: 2 }];
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockArray),
      });

      const result = await client.get('/list');
      expect(result).toEqual(mockArray);
    });

    it('should handle non-JSON responses gracefully', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockRejectedValue(new SyntaxError('Unexpected token')),
      });

      await expect(client.get('/text')).rejects.toThrow('Unexpected token');
    });
  });

  describe('Error Status Codes', () => {
    const errorCodes = [400, 401, 403, 404, 500, 502, 503];

    errorCodes.forEach(code => {
      it(`should handle ${code} status code`, async () => {
        mockFetch.mockResolvedValue({
          ok: false,
          status: code,
          statusText: `Error ${code}`,
        });

        await expect(client.get('/test')).rejects.toThrow(`API Error: Error ${code}`);
      });
    });
  });

  describe('Concurrent Requests', () => {
    it('should handle multiple concurrent requests', async () => {
      const responses = [
        { data: 'response1' },
        { data: 'response2' },
        { data: 'response3' },
      ];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue(responses[0]),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue(responses[1]),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue(responses[2]),
        });

      const promises = [
        client.get('/test1'),
        client.get('/test2'),
        client.get('/test3'),
      ];

      const results = await Promise.all(promises);

      expect(results).toEqual(responses);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should handle mixed request types concurrently', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ get: true }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ post: true }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ delete: true }),
        });

      const promises = [
        client.get('/data'),
        client.post('/create', { name: 'test' }),
        client.delete('/item/1'),
      ];

      const results = await Promise.all(promises);

      expect(results).toEqual([{ get: true }, { post: true }, { delete: true }]);
    });
  });

  describe('Type Safety', () => {
    it('should maintain type information for responses', async () => {
      interface User {
        id: number;
        name: string;
      }

      const mockUser: User = { id: 1, name: 'Test User' };
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockUser),
      });

      const result = await client.get<User>('/user/1');
      expect(result.id).toBe(1);
      expect(result.name).toBe('Test User');
    });
  });

  describe('Default Export', () => {
    it('should export a default client instance', () => {
      expect(apiClient).toBeInstanceOf(ApiClient);
      expect(apiClient['baseUrl']).toBe('http://localhost:3001/api');
    });

    it('should work with default export', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true }),
      });

      const result = await apiClient.get('/test');
      expect(result).toEqual({ success: true });
    });
  });

  describe('Performance', () => {
    it('should handle rapid sequential requests efficiently', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({}),
      });

      const startTime = performance.now();
      
      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(client.get(`/test${i}`));
      }
      
      await Promise.all(promises);
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(100); // Should complete in <100ms
    });
  });
});