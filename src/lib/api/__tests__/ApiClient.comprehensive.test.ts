import { ApiClient } from '../index';

// Mock fetch globally
global.fetch = jest.fn();

describe('ApiClient - Comprehensive Test Suite', () => {
  let apiClient: ApiClient;
  let mockFetch: jest.MockedFunction<typeof fetch>;

  beforeEach(() => {
    mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
    mockFetch.mockClear();
    apiClient = new ApiClient();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Constructor', () => {
    it('should use default base URL when none provided', () => {
      const client = new ApiClient();
      expect(client).toBeInstanceOf(ApiClient);
    });

    it('should use provided base URL', () => {
      const customUrl = 'https://api.example.com';
      const client = new ApiClient(customUrl);
      expect(client).toBeInstanceOf(ApiClient);
    });

    it('should handle empty string base URL', () => {
      const client = new ApiClient('');
      expect(client).toBeInstanceOf(ApiClient);
    });
  });

  describe('GET requests', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ data: 'test' }),
      } as any);
    });

    it('should make successful GET request', async () => {
      const result = await apiClient.get('/test');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/test');
      expect(result).toEqual({ data: 'test' });
    });

    it('should handle endpoint with leading slash', async () => {
      await apiClient.get('/api/users');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/api/users');
    });

    it('should handle endpoint without leading slash', async () => {
      await apiClient.get('users');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/apiusers');
    });

    it('should validate endpoint parameter', async () => {
      await expect(apiClient.get('')).rejects.toThrow('ApiClient.get: endpoint must be a non-empty string');
      await expect(apiClient.get('   ')).rejects.toThrow('ApiClient.get: endpoint cannot be empty or whitespace');
      await expect(apiClient.get(null as any)).rejects.toThrow('ApiClient.get: endpoint must be a non-empty string');
      await expect(apiClient.get(undefined as any)).rejects.toThrow('ApiClient.get: endpoint must be a non-empty string');
      await expect(apiClient.get(123 as any)).rejects.toThrow('ApiClient.get: endpoint must be a non-empty string');
    });

    it('should handle HTTP error responses', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Not Found',
      } as any);

      await expect(apiClient.get('/nonexistent')).rejects.toThrow('API Error: Not Found');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(apiClient.get('/test')).rejects.toThrow('Network error');
    });

    it('should handle JSON parsing errors', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockRejectedValue(new Error('Invalid JSON')),
      } as any);

      await expect(apiClient.get('/test')).rejects.toThrow('Invalid JSON');
    });

    it('should handle non-Error exceptions', async () => {
      mockFetch.mockRejectedValue('String error');

      await expect(apiClient.get('/test')).rejects.toThrow('ApiClient.get: Unexpected error - String error');
    });

    it('should handle complex response data', async () => {
      const complexData = {
        users: [
          { id: 1, name: 'John', nested: { value: 'test' } },
          { id: 2, name: 'Jane', nested: { value: 'test2' } },
        ],
        metadata: {
          total: 2,
          page: 1,
        },
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(complexData),
      } as any);

      const result = await apiClient.get('/users');

      expect(result).toEqual(complexData);
    });
  });

  describe('POST requests', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ id: 1, created: true }),
      } as any);
    });

    it('should make successful POST request', async () => {
      const data = { name: 'Test User', email: 'test@example.com' };
      const result = await apiClient.post('/users', data);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      expect(result).toEqual({ id: 1, created: true });
    });

    it('should validate endpoint parameter', async () => {
      const data = { test: 'data' };

      await expect(apiClient.post('', data)).rejects.toThrow('ApiClient.post: endpoint must be a non-empty string');
      await expect(apiClient.post('   ', data)).rejects.toThrow('ApiClient.post: endpoint cannot be empty or whitespace');
      await expect(apiClient.post(null as any, data)).rejects.toThrow('ApiClient.post: endpoint must be a non-empty string');
      await expect(apiClient.post(undefined as any, data)).rejects.toThrow('ApiClient.post: endpoint must be a non-empty string');
    });

    it('should handle null data', async () => {
      await apiClient.post('/users', null);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: 'null',
        })
      );
    });

    it('should handle undefined data', async () => {
      await apiClient.post('/users', undefined);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: undefined,
        })
      );
    });

    it('should handle complex nested data', async () => {
      const complexData = {
        user: {
          name: 'John Doe',
          preferences: {
            theme: 'dark',
            notifications: {
              email: true,
              push: false,
            },
          },
        },
        metadata: {
          source: 'api',
          timestamp: Date.now(),
        },
      };

      await apiClient.post('/users', complexData);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify(complexData),
        })
      );
    });

    it('should handle HTTP error responses', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Bad Request',
      } as any);

      await expect(apiClient.post('/users', {})).rejects.toThrow('API Error: Bad Request');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Connection refused'));

      await expect(apiClient.post('/users', {})).rejects.toThrow('Connection refused');
    });

    it('should handle non-Error exceptions', async () => {
      mockFetch.mockRejectedValue({ code: 'NETWORK_ERROR' });

      await expect(apiClient.post('/users', {})).rejects.toThrow('ApiClient.post: Unexpected error - [object Object]');
    });

    it('should handle array data', async () => {
      const arrayData = [
        { id: 1, name: 'Item 1' },
        { id: 2, name: 'Item 2' },
      ];

      await apiClient.post('/bulk-create', arrayData);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify(arrayData),
        })
      );
    });
  });

  describe('DELETE requests', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ deleted: true }),
      } as any);
    });

    it('should make successful DELETE request', async () => {
      const result = await apiClient.delete('/users/1');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users/1', {
        method: 'DELETE',
      });
      expect(result).toEqual({ deleted: true });
    });

    it('should validate endpoint parameter', async () => {
      await expect(apiClient.delete('')).rejects.toThrow('ApiClient.delete: endpoint must be a non-empty string');
      await expect(apiClient.delete('   ')).rejects.toThrow('ApiClient.delete: endpoint cannot be empty or whitespace');
      await expect(apiClient.delete(null as any)).rejects.toThrow('ApiClient.delete: endpoint must be a non-empty string');
      await expect(apiClient.delete(undefined as any)).rejects.toThrow('ApiClient.delete: endpoint must be a non-empty string');
    });

    it('should handle HTTP error responses', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Forbidden',
      } as any);

      await expect(apiClient.delete('/users/1')).rejects.toThrow('API Error: Forbidden');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Timeout'));

      await expect(apiClient.delete('/users/1')).rejects.toThrow('Timeout');
    });

    it('should handle non-Error exceptions', async () => {
      mockFetch.mockRejectedValue(500);

      await expect(apiClient.delete('/users/1')).rejects.toThrow('ApiClient.delete: Unexpected error - 500');
    });

    it('should handle empty response', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(null),
      } as any);

      const result = await apiClient.delete('/users/1');

      expect(result).toBeNull();
    });

    it('should handle different status codes', async () => {
      // Test 204 No Content
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(undefined),
      } as any);

      const result = await apiClient.delete('/users/1');

      expect(result).toBeUndefined();
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('should handle fetch throwing non-Error objects', async () => {
      mockFetch.mockImplementation(() => {
        throw 'String error';
      });

      await expect(apiClient.get('/test')).rejects.toThrow('ApiClient.get: Unexpected error - String error');
    });

    it('should handle fetch throwing null', async () => {
      mockFetch.mockImplementation(() => {
        throw null;
      });

      await expect(apiClient.get('/test')).rejects.toThrow('ApiClient.get: Unexpected error - null');
    });

    it('should handle response.json() throwing', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockImplementation(() => {
          throw new Error('JSON parse error');
        }),
      } as any);

      await expect(apiClient.get('/test')).rejects.toThrow('JSON parse error');
    });

    it('should handle response with missing json method', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        // Missing json method
      } as any);

      await expect(apiClient.get('/test')).rejects.toThrow();
    });
  });

  describe('Type Safety', () => {
    it('should handle typed responses correctly', async () => {
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

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(userData),
      } as any);

      const result = await apiClient.get<User>('/users/1');

      expect(result).toEqual(userData);
      expect(result.id).toBe(1);
      expect(result.name).toBe('John Doe');
      expect(result.email).toBe('john@example.com');
    });

    it('should handle array responses', async () => {
      interface User {
        id: number;
        name: string;
      }

      const usersData: User[] = [
        { id: 1, name: 'John' },
        { id: 2, name: 'Jane' },
      ];

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(usersData),
      } as any);

      const result = await apiClient.get<User[]>('/users');

      expect(result).toEqual(usersData);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
    });
  });

  describe('Performance and Memory', () => {
    it('should handle large responses efficiently', async () => {
      // Create a large response object
      const largeData = {
        items: Array.from({ length: 10000 }, (_, i) => ({
          id: i,
          name: `Item ${i}`,
          data: `Large data string for item ${i} `.repeat(10),
        })),
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(largeData),
      } as any);

      const result = await apiClient.get('/large-dataset');

      expect(result.items).toHaveLength(10000);
      expect(result.items[0].id).toBe(0);
      expect(result.items[9999].id).toBe(9999);
    });

    it('should handle concurrent requests', async () => {
      mockFetch.mockImplementation((url) => 
        Promise.resolve({
          ok: true,
          json: jest.fn().mockResolvedValue({ url }),
        } as any)
      );

      const promises = [
        apiClient.get('/endpoint1'),
        apiClient.get('/endpoint2'),
        apiClient.get('/endpoint3'),
        apiClient.post('/endpoint4', { data: 'test' }),
        apiClient.delete('/endpoint5'),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(5);
      expect(mockFetch).toHaveBeenCalledTimes(5);
    });

    it('should not leak memory with repeated requests', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ data: 'test' }),
      } as any);

      // Make many requests
      const promises = [];
      for (let i = 0; i < 1000; i++) {
        promises.push(apiClient.get(`/test${i}`));
      }

      const results = await Promise.all(promises);

      expect(results).toHaveLength(1000);
      expect(mockFetch).toHaveBeenCalledTimes(1000);
    });
  });

  describe('Custom Base URL', () => {
    it('should work with different base URLs', async () => {
      const customClient = new ApiClient('https://api.example.com/v1');

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true }),
      } as any);

      await customClient.get('/users');

      expect(mockFetch).toHaveBeenCalledWith('https://api.example.com/v1/users');
    });

    it('should handle base URL without trailing slash', async () => {
      const customClient = new ApiClient('https://api.example.com');

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true }),
      } as any);

      await customClient.get('/users');

      expect(mockFetch).toHaveBeenCalledWith('https://api.example.com/users');
    });

    it('should handle empty base URL', async () => {
      const customClient = new ApiClient('');

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true }),
      } as any);

      await customClient.get('/users');

      expect(mockFetch).toHaveBeenCalledWith('/users');
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete CRUD workflow', async () => {
      const userData = { name: 'John Doe', email: 'john@example.com' };
      const createdUser = { id: 1, ...userData };
      const updatedUser = { ...createdUser, name: 'John Smith' };

      // Create
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue(createdUser),
      } as any);

      const created = await apiClient.post('/users', userData);
      expect(created).toEqual(createdUser);

      // Read
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue(createdUser),
      } as any);

      const fetched = await apiClient.get('/users/1');
      expect(fetched).toEqual(createdUser);

      // Update (using POST for simplicity)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue(updatedUser),
      } as any);

      const updated = await apiClient.post('/users/1', { name: 'John Smith' });
      expect(updated).toEqual(updatedUser);

      // Delete
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({ deleted: true }),
      } as any);

      const deleted = await apiClient.delete('/users/1');
      expect(deleted).toEqual({ deleted: true });

      expect(mockFetch).toHaveBeenCalledTimes(4);
    });

    it('should handle authentication workflow', async () => {
      const credentials = { username: 'user', password: 'pass' };
      const authResponse = { token: 'abc123', user: { id: 1, name: 'User' } };

      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(authResponse),
      } as any);

      const result = await apiClient.post('/auth/login', credentials);

      expect(result).toEqual(authResponse);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3001/api/auth/login',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credentials),
        })
      );
    });
  });
});