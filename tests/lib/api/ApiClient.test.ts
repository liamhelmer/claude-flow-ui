import { ApiClient, apiClient } from '@/lib/api/index';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('ApiClient', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient();
    mockFetch.mockClear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor', () => {
    it('creates instance with default base URL', () => {
      const defaultClient = new ApiClient();
      expect(defaultClient).toBeInstanceOf(ApiClient);
    });

    it('creates instance with custom base URL', () => {
      const customClient = new ApiClient('https://api.example.com');
      expect(customClient).toBeInstanceOf(ApiClient);
    });

    it('exports a default instance', () => {
      expect(apiClient).toBeInstanceOf(ApiClient);
    });
  });

  describe('GET Requests', () => {
    it('makes successful GET request', async () => {
      const mockResponse = { success: true, data: { id: 1, name: 'Test' } };
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await client.get('/users/1');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users/1');
      expect(result).toEqual(mockResponse);
    });

    it('handles API errors with status message', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Not Found',
      });

      await expect(client.get('/users/999')).rejects.toThrow('API Error: Not Found');
    });

    it('handles network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(client.get('/users/1')).rejects.toThrow('Network error');
    });

    it('validates endpoint parameter - null/undefined', async () => {
      await expect(client.get(null as any)).rejects.toThrow(
        'ApiClient.get: endpoint must be a non-empty string'
      );

      await expect(client.get(undefined as any)).rejects.toThrow(
        'ApiClient.get: endpoint must be a non-empty string'
      );
    });

    it('validates endpoint parameter - non-string types', async () => {
      await expect(client.get(123 as any)).rejects.toThrow(
        'ApiClient.get: endpoint must be a non-empty string'
      );

      await expect(client.get({} as any)).rejects.toThrow(
        'ApiClient.get: endpoint must be a non-empty string'
      );

      await expect(client.get([] as any)).rejects.toThrow(
        'ApiClient.get: endpoint must be a non-empty string'
      );
    });

    it('validates endpoint parameter - empty/whitespace strings', async () => {
      await expect(client.get('')).rejects.toThrow(
        'ApiClient.get: endpoint cannot be empty or whitespace'
      );

      await expect(client.get('   ')).rejects.toThrow(
        'ApiClient.get: endpoint cannot be empty or whitespace'
      );

      await expect(client.get('\t\n')).rejects.toThrow(
        'ApiClient.get: endpoint cannot be empty or whitespace'
      );
    });

    it('handles JSON parsing errors', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.reject(new Error('Invalid JSON')),
      });

      await expect(client.get('/users/1')).rejects.toThrow('Invalid JSON');
    });

    it('handles non-Error exceptions in catch block', async () => {
      mockFetch.mockRejectedValue('String error');

      await expect(client.get('/users/1')).rejects.toThrow(
        'ApiClient.get: Unexpected error - String error'
      );
    });

    it('works with different endpoint formats', async () => {
      const mockResponse = { data: 'test' };
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      // Test with leading slash
      await client.get('/users');
      expect(mockFetch).toHaveBeenLastCalledWith('http://localhost:3001/api/users');

      // Test without leading slash
      await client.get('users');
      expect(mockFetch).toHaveBeenLastCalledWith('http://localhost:3001/apiusers');

      // Test with query parameters
      await client.get('/users?limit=10');
      expect(mockFetch).toHaveBeenLastCalledWith('http://localhost:3001/api/users?limit=10');
    });
  });

  describe('POST Requests', () => {
    it('makes successful POST request', async () => {
      const mockResponse = { success: true, id: 1 };
      const postData = { name: 'New User', email: 'user@example.com' };
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await client.post('/users', postData);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(postData),
      });
      expect(result).toEqual(mockResponse);
    });

    it('handles POST request with null data', async () => {
      const mockResponse = { success: true };
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await client.post('/users', null);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: 'null',
      });
      expect(result).toEqual(mockResponse);
    });

    it('handles POST request with complex data', async () => {
      const complexData = {
        user: { name: 'Test', nested: { value: 123 } },
        array: [1, 2, 3],
        boolean: true,
      };
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      await client.post('/users', complexData);

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(complexData),
      });
    });

    it('validates endpoint parameter for POST', async () => {
      await expect(client.post('', { data: 'test' })).rejects.toThrow(
        'ApiClient.post: endpoint cannot be empty or whitespace'
      );

      await expect(client.post(null as any, { data: 'test' })).rejects.toThrow(
        'ApiClient.post: endpoint must be a non-empty string'
      );
    });

    it('handles POST API errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Bad Request',
      });

      await expect(client.post('/users', { invalid: 'data' })).rejects.toThrow(
        'API Error: Bad Request'
      );
    });

    it('handles JSON stringify errors in POST', async () => {
      const circularObj: any = {};
      circularObj.self = circularObj;

      await expect(client.post('/users', circularObj)).rejects.toThrow();
    });

    it('handles non-Error exceptions in POST catch block', async () => {
      mockFetch.mockRejectedValue(404);

      await expect(client.post('/users', {})).rejects.toThrow(
        'ApiClient.post: Unexpected error - 404'
      );
    });
  });

  describe('DELETE Requests', () => {
    it('makes successful DELETE request', async () => {
      const mockResponse = { success: true, deleted: true };
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await client.delete('/users/1');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/api/users/1', {
        method: 'DELETE',
      });
      expect(result).toEqual(mockResponse);
    });

    it('handles DELETE request without response body', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      });

      const result = await client.delete('/users/1');
      expect(result).toEqual({});
    });

    it('validates endpoint parameter for DELETE', async () => {
      await expect(client.delete('')).rejects.toThrow(
        'ApiClient.delete: endpoint cannot be empty or whitespace'
      );

      await expect(client.delete(null as any)).rejects.toThrow(
        'ApiClient.delete: endpoint must be a non-empty string'
      );

      await expect(client.delete(undefined as any)).rejects.toThrow(
        'ApiClient.delete: endpoint must be a non-empty string'
      );
    });

    it('handles DELETE API errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Forbidden',
      });

      await expect(client.delete('/users/1')).rejects.toThrow('API Error: Forbidden');
    });

    it('handles DELETE network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Connection timeout'));

      await expect(client.delete('/users/1')).rejects.toThrow('Connection timeout');
    });

    it('handles non-Error exceptions in DELETE catch block', async () => {
      mockFetch.mockRejectedValue({ error: 'object error' });

      await expect(client.delete('/users/1')).rejects.toThrow(
        'ApiClient.delete: Unexpected error - [object Object]'
      );
    });
  });

  describe('Base URL Configuration', () => {
    it('uses custom base URL', async () => {
      const customClient = new ApiClient('https://api.custom.com/v1');
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ data: 'test' }),
      });

      await customClient.get('/test');

      expect(mockFetch).toHaveBeenCalledWith('https://api.custom.com/v1/test');
    });

    it('handles base URL without trailing slash', async () => {
      const client = new ApiClient('https://api.example.com');
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ data: 'test' }),
      });

      await client.get('/test');

      expect(mockFetch).toHaveBeenCalledWith('https://api.example.com/test');
    });

    it('handles base URL with trailing slash', async () => {
      const client = new ApiClient('https://api.example.com/');
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ data: 'test' }),
      });

      await client.get('/test');

      expect(mockFetch).toHaveBeenCalledWith('https://api.example.com//test');
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('handles fetch throwing non-Error objects', async () => {
      mockFetch.mockImplementation(() => {
        throw 'String error';
      });

      await expect(client.get('/test')).rejects.toThrow(
        'ApiClient.get: Unexpected error - String error'
      );
    });

    it('handles response.json() rejection', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.reject(new Error('JSON parse error')),
      });

      await expect(client.get('/test')).rejects.toThrow('JSON parse error');
    });

    it('handles response with no json method', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: undefined,
      } as any);

      await expect(client.get('/test')).rejects.toThrow();
    });
  });

  describe('Integration and Real-world Scenarios', () => {
    it('handles typical user CRUD operations', async () => {
      const userData = { name: 'John Doe', email: 'john@example.com' };
      const createdUser = { id: 1, ...userData };
      const updatedUser = { ...createdUser, name: 'Jane Doe' };

      // Create user
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(createdUser),
      });

      const created = await client.post('/users', userData);
      expect(created).toEqual(createdUser);

      // Get user
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(createdUser),
      });

      const retrieved = await client.get('/users/1');
      expect(retrieved).toEqual(createdUser);

      // Delete user
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      const deleted = await client.delete('/users/1');
      expect(deleted).toEqual({ success: true });
    });

    it('handles API rate limiting scenarios', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Too Many Requests',
      });

      await expect(client.get('/users')).rejects.toThrow('API Error: Too Many Requests');
    });

    it('handles server errors gracefully', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: 'Internal Server Error',
      });

      await expect(client.post('/users', {})).rejects.toThrow('API Error: Internal Server Error');
    });

    it('works with empty response bodies', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(null),
      });

      const result = await client.get('/status');
      expect(result).toBeNull();
    });
  });

  describe('TypeScript Type Safety', () => {
    it('supports generic type parameters', async () => {
      interface User {
        id: number;
        name: string;
        email: string;
      }

      const mockUser: User = { id: 1, name: 'Test', email: 'test@example.com' };
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockUser),
      });

      const user = await client.get<User>('/users/1');
      
      // TypeScript should infer the correct type
      expect(typeof user.id).toBe('number');
      expect(typeof user.name).toBe('string');
      expect(typeof user.email).toBe('string');
    });

    it('handles void responses', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(undefined),
      });

      const result = await client.delete<void>('/users/1');
      expect(result).toBeUndefined();
    });
  });
});