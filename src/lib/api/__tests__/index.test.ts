import { ApiClient, apiClient } from '../index';

// Mock fetch globally
global.fetch = jest.fn();
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('ApiClient', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient('http://test-api.com/api');
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should use default baseUrl if none provided', () => {
      const defaultClient = new ApiClient();
      expect(defaultClient['baseUrl']).toBe('http://localhost:3001/api');
    });

    it('should use provided baseUrl', () => {
      expect(client['baseUrl']).toBe('http://test-api.com/api');
    });
  });

  describe('GET requests', () => {
    it('should make successful GET request', async () => {
      const mockData = { id: 1, name: 'test' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      } as Response);

      const result = await client.get('/users');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users');
      expect(result).toEqual(mockData);
    });

    it('should handle GET request errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Not Found',
      } as Response);

      await expect(client.get('/users')).rejects.toThrow('API Error: Not Found');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(client.get('/users')).rejects.toThrow('Network error');
    });

    it('should handle JSON parsing errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.reject(new Error('Invalid JSON')),
      } as Response);

      await expect(client.get('/users')).rejects.toThrow('Invalid JSON');
    });
  });

  describe('POST requests', () => {
    it('should make successful POST request', async () => {
      const mockData = { id: 1, name: 'created' };
      const postData = { name: 'new user' };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      } as Response);

      const result = await client.post('/users', postData);

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(postData),
      });
      expect(result).toEqual(mockData);
    });

    it('should handle POST request errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Bad Request',
      } as Response);

      await expect(client.post('/users', {})).rejects.toThrow('API Error: Bad Request');
    });

    it('should stringify request body', async () => {
      const postData = { name: 'test', nested: { value: 123 } };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response);

      await client.post('/users', postData);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify(postData),
        })
      );
    });

    it('should handle null and undefined data', async () => {
      // Mock responses for both calls
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        } as Response);

      await client.post('/users', null);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: 'null',
        })
      );

      await client.post('/users', undefined);
      expect(mockFetch).toHaveBeenLastCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: undefined,
        })
      );
    });
  });

  describe('DELETE requests', () => {
    it('should make successful DELETE request', async () => {
      const mockData = { success: true };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      } as Response);

      const result = await client.delete('/users/1');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users/1', {
        method: 'DELETE',
      });
      expect(result).toEqual(mockData);
    });

    it('should handle DELETE request errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Forbidden',
      } as Response);

      await expect(client.delete('/users/1')).rejects.toThrow('API Error: Forbidden');
    });

    it('should handle empty response body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(null),
      } as Response);

      const result = await client.delete('/users/1');
      expect(result).toBeNull();
    });
  });

  describe('URL construction', () => {
    it('should handle endpoints with leading slash', () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response);

      client.get('/users');
      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users');
    });

    it('should handle endpoints without leading slash', () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response);

      client.get('users');
      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/apiusers');
    });

    it('should handle empty endpoint', async () => {
      // Empty endpoint should throw error per API design
      await expect(client.get('')).rejects.toThrow('ApiClient.get: endpoint must be a non-empty string');
    });

    it('should handle baseUrl with trailing slash', () => {
      const clientWithSlash = new ApiClient('http://test-api.com/api/');
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response);

      clientWithSlash.get('/users');
      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api//users');
    });

    it('should handle complex endpoint paths', () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response);

      client.get('/api/v1/users/123/posts?include=comments&sort=date');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://test-api.com/api/api/v1/users/123/posts?include=comments&sort=date'
      );
    });

    it('should handle encoded URL parameters', () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response);

      client.get('/search?q=hello%20world&type=user');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://test-api.com/api/search?q=hello%20world&type=user'
      );
    });
  });

  describe('Response handling', () => {
    it('should handle different success status codes', async () => {
      const responses = [200, 201, 204, 299];
      
      for (const status of responses) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status,
          json: () => Promise.resolve({ status }),
        } as Response);

        const result = await client.get('/test');
        expect(result).toEqual({ status });
      }
    });

    it('should handle different error status codes', async () => {
      const errorCodes = [400, 401, 403, 404, 500, 502];
      
      for (const status of errorCodes) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status,
          statusText: `Error ${status}`,
        } as Response);

        await expect(client.get('/test')).rejects.toThrow(`API Error: Error ${status}`);
      }
    });
  });

  describe('Singleton instance', () => {
    it('should export a singleton instance', () => {
      expect(apiClient).toBeInstanceOf(ApiClient);
      expect(apiClient['baseUrl']).toBe('http://localhost:3001/api');
    });

    it('should be the same instance on multiple imports', () => {
      const { apiClient: importedAgain } = require('../index');
      expect(apiClient).toBe(importedAgain);
    });
  });

  describe('Type safety', () => {
    it('should return typed responses for GET requests', async () => {
      interface User {
        id: number;
        name: string;
      }

      const mockUser: User = { id: 1, name: 'John' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockUser),
      } as Response);

      const result = await client.get<User>('/user/1');
      
      // TypeScript should infer the correct type
      expect(result.id).toBe(1);
      expect(result.name).toBe('John');
    });

    it('should return typed responses for POST requests', async () => {
      interface CreateUserResponse {
        id: number;
        created: boolean;
      }

      const mockResponse: CreateUserResponse = { id: 2, created: true };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const result = await client.post<CreateUserResponse>('/users', { name: 'Jane' });
      
      expect(result.id).toBe(2);
      expect(result.created).toBe(true);
    });

    it('should handle generic array responses', async () => {
      interface User {
        id: number;
        name: string;
      }

      const mockUsers: User[] = [
        { id: 1, name: 'John' },
        { id: 2, name: 'Jane' },
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockUsers),
      } as Response);

      const result = await client.get<User[]>('/users');
      
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
      expect(result[0].id).toBe(1);
      expect(result[1].name).toBe('Jane');
    });
  });

  describe('Edge cases and error scenarios', () => {
    it('should handle circular reference in POST data', async () => {
      const circularObj: any = { name: 'test' };
      circularObj.self = circularObj;

      await expect(client.post('/users', circularObj)).rejects.toThrow();
    });

    it('should handle very large response bodies', async () => {
      const largeData = { 
        data: 'x'.repeat(1000000), // 1MB string
        items: Array(10000).fill({ id: 1, name: 'test' })
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(largeData),
      } as Response);

      const result = await client.get('/large-data');
      expect(result.data).toHaveLength(1000000);
      expect(result.items).toHaveLength(10000);
    });

    it('should handle special characters in request data', async () => {
      const specialData = {
        emoji: '🚀🌟',
        unicode: 'café naïve résumé',
        quotes: `"Hello 'world'"`,
        newlines: 'line1\nline2\r\nline3',
        html: '<script>alert("test")</script>',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      } as Response);

      await client.post('/special', specialData);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify(specialData),
        })
      );
    });

    it('should handle response with invalid Content-Type', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Map([['content-type', 'text/plain']]),
        json: () => Promise.resolve({ data: 'test' }),
      } as any);

      const result = await client.get('/text-response');
      expect(result).toEqual({ data: 'test' });
    });

    it('should handle empty response body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(undefined),
      } as Response);

      const result = await client.get('/empty');
      expect(result).toBeUndefined();
    });
  });

  describe('Performance and timeout scenarios', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should handle slow responses', async () => {
      let resolveResponse: (value: any) => void;
      const slowResponsePromise = new Promise((resolve) => {
        resolveResponse = resolve;
      });

      mockFetch.mockReturnValueOnce(slowResponsePromise as any);

      const requestPromise = client.get('/slow');

      // Simulate slow response after 5 seconds
      setTimeout(() => {
        resolveResponse!({
          ok: true,
          json: () => Promise.resolve({ data: 'delayed' }),
        });
      }, 5000);

      jest.advanceTimersByTime(5000);

      const result = await requestPromise;
      expect(result).toEqual({ data: 'delayed' });
    });

    it('should handle timeout errors', async () => {
      mockFetch.mockImplementationOnce(() => 
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Request timeout')), 10000)
        )
      );

      const requestPromise = client.get('/timeout');

      jest.advanceTimersByTime(10000);

      await expect(requestPromise).rejects.toThrow('Request timeout');
    });
  });

  describe('Concurrent requests', () => {
    it('should handle multiple concurrent requests', async () => {
      const responses = [
        { id: 1, name: 'User 1' },
        { id: 2, name: 'User 2' },
        { id: 3, name: 'User 3' },
      ];

      responses.forEach((response) => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(response),
        } as Response);
      });

      const requests = [
        client.get('/users/1'),
        client.get('/users/2'),
        client.get('/users/3'),
      ];

      const results = await Promise.all(requests);

      expect(results).toEqual(responses);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should handle mixed request types concurrently', async () => {
      const getUserResponse = { id: 1, name: 'John' };
      const createResponse = { id: 2, created: true };
      const deleteResponse = { success: true };

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(getUserResponse),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(createResponse),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(deleteResponse),
        } as Response);

      const [getResult, postResult, deleteResult] = await Promise.all([
        client.get('/users/1'),
        client.post('/users', { name: 'Jane' }),
        client.delete('/users/3'),
      ]);

      expect(getResult).toEqual(getUserResponse);
      expect(postResult).toEqual(createResponse);
      expect(deleteResult).toEqual(deleteResponse);
    });
  });

  describe('Environment and configuration', () => {
    it('should work with different base URLs', () => {
      const configs = [
        'http://localhost:3000',
        'https://api.example.com',
        'https://api.example.com/v1',
        'http://192.168.1.100:8080/api',
      ];

      configs.forEach((baseUrl) => {
        const testClient = new ApiClient(baseUrl);
        expect(testClient).toBeInstanceOf(ApiClient);
        expect(testClient['baseUrl']).toBe(baseUrl);
      });
    });

    it('should handle protocol-relative URLs', () => {
      const client = new ApiClient('//api.example.com');
      expect(client['baseUrl']).toBe('//api.example.com');
    });
  });
});