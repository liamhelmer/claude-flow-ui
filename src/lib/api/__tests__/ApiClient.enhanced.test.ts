import { ApiClient } from '../index';

// Mock fetch globally
global.fetch = jest.fn();

const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

describe('ApiClient', () => {
  let apiClient: ApiClient;

  beforeEach(() => {
    apiClient = new ApiClient('http://test-api.com/api');
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should use default base URL when none provided', () => {
      const defaultClient = new ApiClient();
      expect(defaultClient).toBeDefined();
    });

    it('should use provided base URL', () => {
      const customClient = new ApiClient('http://custom-api.com');
      expect(customClient).toBeDefined();
    });
  });

  describe('GET requests', () => {
    it('should make successful GET request', async () => {
      const mockData = { id: 1, name: 'Test' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockData,
      } as Response);

      const result = await apiClient.get('/users/1');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users/1');
      expect(result).toEqual(mockData);
    });

    it('should handle GET request with query parameters', async () => {
      const mockData = [{ id: 1, name: 'Test' }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockData,
      } as Response);

      const result = await apiClient.get('/users?limit=10&page=1');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users?limit=10&page=1');
      expect(result).toEqual(mockData);
    });

    it('should throw error on failed GET request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Not Found',
      } as Response);

      await expect(apiClient.get('/users/999')).rejects.toThrow('API Error: Not Found');
    });

    it('should handle network errors on GET request', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(apiClient.get('/users/1')).rejects.toThrow('Network error');
    });

    it('should handle invalid JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => {
          throw new Error('Invalid JSON');
        },
      } as Response);

      await expect(apiClient.get('/users/1')).rejects.toThrow('Invalid JSON');
    });
  });

  describe('POST requests', () => {
    it('should make successful POST request', async () => {
      const postData = { name: 'New User', email: 'test@example.com' };
      const responseData = { id: 2, ...postData };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.post('/users', postData);

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(postData),
      });
      expect(result).toEqual(responseData);
    });

    it('should handle POST request with complex data', async () => {
      const complexData = {
        user: { name: 'Test', preferences: { theme: 'dark' } },
        metadata: { source: 'test' },
        array: [1, 2, 3],
      };
      const responseData = { id: 3, ...complexData };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.post('/users', complexData);

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(complexData),
      });
      expect(result).toEqual(responseData);
    });

    it('should handle POST request with null/undefined data', async () => {
      const responseData = { message: 'Success' };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.post('/action', null);

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/action', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: 'null',
      });
      expect(result).toEqual(responseData);
    });

    it('should throw error on failed POST request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Bad Request',
      } as Response);

      await expect(apiClient.post('/users', { name: 'Test' })).rejects.toThrow('API Error: Bad Request');
    });

    it('should handle validation errors (422)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Unprocessable Entity',
      } as Response);

      await expect(apiClient.post('/users', { email: 'invalid' })).rejects.toThrow('API Error: Unprocessable Entity');
    });
  });

  describe('DELETE requests', () => {
    it('should make successful DELETE request', async () => {
      const responseData = { message: 'User deleted successfully' };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.delete('/users/1');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users/1', {
        method: 'DELETE',
      });
      expect(result).toEqual(responseData);
    });

    it('should handle DELETE request with query parameters', async () => {
      const responseData = { deletedCount: 5 };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.delete('/users?status=inactive');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users?status=inactive', {
        method: 'DELETE',
      });
      expect(result).toEqual(responseData);
    });

    it('should throw error on failed DELETE request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Forbidden',
      } as Response);

      await expect(apiClient.delete('/users/1')).rejects.toThrow('API Error: Forbidden');
    });

    it('should handle resource not found (404)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Not Found',
      } as Response);

      await expect(apiClient.delete('/users/999')).rejects.toThrow('API Error: Not Found');
    });
  });

  describe('Error Handling', () => {
    it('should handle fetch rejections', async () => {
      const networkError = new Error('Failed to fetch');
      mockFetch.mockRejectedValueOnce(networkError);

      await expect(apiClient.get('/users')).rejects.toThrow('Failed to fetch');
    });

    it('should handle empty response body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => null,
      } as Response);

      const result = await apiClient.get('/empty');
      expect(result).toBeNull();
    });

    it('should handle malformed JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => {
          throw new SyntaxError('Unexpected token');
        },
      } as Response);

      await expect(apiClient.get('/malformed')).rejects.toThrow('Unexpected token');
    });

    it('should handle server errors (500)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Internal Server Error',
      } as Response);

      await expect(apiClient.get('/server-error')).rejects.toThrow('API Error: Internal Server Error');
    });

    it('should handle timeout errors', async () => {
      const timeoutError = new Error('The operation was aborted.');
      mockFetch.mockRejectedValueOnce(timeoutError);

      await expect(apiClient.post('/slow-endpoint', {})).rejects.toThrow('The operation was aborted.');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty endpoint string', async () => {
      // Empty endpoint should throw an error per API design
      await expect(apiClient.get('')).rejects.toThrow('ApiClient.get: endpoint must be a non-empty string');
    });

    it('should handle endpoint starting with slash', async () => {
      const responseData = { data: 'test' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.get('/users');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users');
      expect(result).toEqual(responseData);
    });

    it('should handle endpoint without starting slash', async () => {
      const responseData = { data: 'test' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.get('users');

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/apiusers');
      expect(result).toEqual(responseData);
    });

    it('should handle special characters in data', async () => {
      const specialData = {
        name: 'Test & <User>',
        description: 'User with "quotes" and \\backslashes',
        emoji: '🚀 🎉',
      };
      const responseData = { id: 4, ...specialData };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.post('/users', specialData);

      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(specialData),
      });
      expect(result).toEqual(responseData);
    });

    it('should handle circular reference in POST data', async () => {
      const circularData: any = { name: 'Test' };
      circularData.self = circularData;

      await expect(apiClient.post('/users', circularData)).rejects.toThrow();
    });
  });

  describe('Performance', () => {
    it('should handle multiple concurrent requests', async () => {
      const responses = Array.from({ length: 5 }, (_, i) => ({
        ok: true,
        json: async () => ({ id: i + 1, name: `User ${i + 1}` }),
      }));

      mockFetch
        .mockResolvedValueOnce(responses[0] as Response)
        .mockResolvedValueOnce(responses[1] as Response)
        .mockResolvedValueOnce(responses[2] as Response)
        .mockResolvedValueOnce(responses[3] as Response)
        .mockResolvedValueOnce(responses[4] as Response);

      const promises = Array.from({ length: 5 }, (_, i) => 
        apiClient.get(`/users/${i + 1}`)
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(5);
      expect(mockFetch).toHaveBeenCalledTimes(5);
      results.forEach((result, i) => {
        expect(result).toEqual({ id: i + 1, name: `User ${i + 1}` });
      });
    });

    it('should handle large data payloads', async () => {
      const largeData = {
        items: Array.from({ length: 1000 }, (_, i) => ({
          id: i,
          name: `Item ${i}`,
          data: 'x'.repeat(100),
        })),
      };
      const responseData = { success: true, count: 1000 };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => responseData,
      } as Response);

      const result = await apiClient.post('/bulk-create', largeData);

      expect(result).toEqual(responseData);
      expect(mockFetch).toHaveBeenCalledWith('http://test-api.com/api/bulk-create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(largeData),
      });
    });
  });

  describe('TypeScript type safety', () => {
    it('should work with typed responses', async () => {
      interface User {
        id: number;
        name: string;
        email: string;
      }

      const userData: User = {
        id: 1,
        name: 'John Doe',
        email: 'john@example.com',
      };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => userData,
      } as Response);

      const result = await apiClient.get<User>('/users/1');

      expect(result).toEqual(userData);
      expect(typeof result.id).toBe('number');
      expect(typeof result.name).toBe('string');
      expect(typeof result.email).toBe('string');
    });

    it('should work with array responses', async () => {
      interface Item {
        id: number;
        title: string;
      }

      const items: Item[] = [
        { id: 1, title: 'Item 1' },
        { id: 2, title: 'Item 2' },
      ];
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => items,
      } as Response);

      const result = await apiClient.get<Item[]>('/items');

      expect(result).toEqual(items);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
    });
  });
});
