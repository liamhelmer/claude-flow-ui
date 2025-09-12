import { ApiClient } from '../index';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch as jest.Mock;

describe('ApiClient', () => {
  let apiClient: ApiClient;
  const baseUrl = 'http://localhost:3001/api';

  beforeEach(() => {
    apiClient = new ApiClient(baseUrl);
    mockFetch.mockClear();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('constructor', () => {
    it('should initialize with default baseUrl when none provided', () => {
      const defaultClient = new ApiClient();
      expect(defaultClient).toBeInstanceOf(ApiClient);
    });

    it('should initialize with provided baseUrl', () => {
      const customClient = new ApiClient('http://custom.api');
      expect(customClient).toBeInstanceOf(ApiClient);
    });
  });

  describe('get method', () => {
    it('should make successful GET request and return data', async () => {
      const mockData = { id: 1, name: 'test' };
      const mockResponse = {
        ok: true,
        json: jest.fn().mockResolvedValue(mockData),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await apiClient.get<typeof mockData>('/test');

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test`);
      expect(result).toEqual(mockData);
    });

    it('should throw error when response is not ok', async () => {
      const mockResponse = {
        ok: false,
        statusText: 'Not Found',
        json: jest.fn(),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(apiClient.get('/test')).rejects.toThrow('API Error: Not Found');
      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test`);
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network error');
      mockFetch.mockRejectedValue(networkError);

      await expect(apiClient.get('/test')).rejects.toThrow('Network error');
    });

    it('should handle malformed JSON response', async () => {
      const mockResponse = {
        ok: true,
        json: jest.fn().mockRejectedValue(new Error('Invalid JSON')),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(apiClient.get('/test')).rejects.toThrow('Invalid JSON');
    });
  });

  describe('post method', () => {
    it('should make successful POST request with data', async () => {
      const requestData = { name: 'test', value: 123 };
      const responseData = { id: 1, ...requestData };
      const mockResponse = {
        ok: true,
        json: jest.fn().mockResolvedValue(responseData),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await apiClient.post('/test', requestData);

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      });
      expect(result).toEqual(responseData);
    });

    it('should handle POST request with null data', async () => {
      const responseData = { success: true };
      const mockResponse = {
        ok: true,
        json: jest.fn().mockResolvedValue(responseData),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await apiClient.post('/test', null);

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: 'null',
      });
      expect(result).toEqual(responseData);
    });

    it('should handle POST request with complex nested data', async () => {
      const complexData = {
        user: { id: 1, name: 'John' },
        settings: { theme: 'dark', notifications: true },
        tags: ['test', 'api'],
      };
      const mockResponse = {
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true }),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await apiClient.post('/test', complexData);

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(complexData),
      });
    });

    it('should throw error for failed POST request', async () => {
      const mockResponse = {
        ok: false,
        statusText: 'Bad Request',
        json: jest.fn(),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(apiClient.post('/test', {})).rejects.toThrow('API Error: Bad Request');
    });
  });

  describe('delete method', () => {
    it('should make successful DELETE request', async () => {
      const responseData = { deleted: true };
      const mockResponse = {
        ok: true,
        json: jest.fn().mockResolvedValue(responseData),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await apiClient.delete('/test/1');

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test/1`, {
        method: 'DELETE',
      });
      expect(result).toEqual(responseData);
    });

    it('should throw error for failed DELETE request', async () => {
      const mockResponse = {
        ok: false,
        statusText: 'Forbidden',
        json: jest.fn(),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(apiClient.delete('/test/1')).rejects.toThrow('API Error: Forbidden');
    });

    it('should handle DELETE request with no response body', async () => {
      const mockResponse = {
        ok: true,
        json: jest.fn().mockResolvedValue(null),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await apiClient.delete('/test/1');
      expect(result).toBeNull();
    });
  });

  describe('error handling edge cases', () => {
    it('should handle response with empty statusText', async () => {
      const mockResponse = {
        ok: false,
        statusText: '',
        json: jest.fn(),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(apiClient.get('/test')).rejects.toThrow('API Error: ');
    });

    it('should handle fetch timeout', async () => {
      mockFetch.mockImplementation(() => 
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Request timeout')), 100)
        )
      );

      await expect(apiClient.get('/test')).rejects.toThrow('Request timeout');
    });

    it('should handle invalid URL construction', async () => {
      const invalidClient = new ApiClient('invalid-url');
      mockFetch.mockRejectedValue(new Error('Invalid URL'));

      await expect(invalidClient.get('/test')).rejects.toThrow('Invalid URL');
    });
  });

  describe('different HTTP status codes', () => {
    const statusCodes = [
      { code: 401, text: 'Unauthorized' },
      { code: 403, text: 'Forbidden' },
      { code: 404, text: 'Not Found' },
      { code: 422, text: 'Unprocessable Entity' },
      { code: 500, text: 'Internal Server Error' },
      { code: 502, text: 'Bad Gateway' },
      { code: 503, text: 'Service Unavailable' },
    ];

    statusCodes.forEach(({ code, text }) => {
      it(`should handle ${code} ${text} error`, async () => {
        const mockResponse = {
          ok: false,
          status: code,
          statusText: text,
          json: jest.fn(),
        };
        mockFetch.mockResolvedValue(mockResponse);

        await expect(apiClient.get('/test')).rejects.toThrow(`API Error: ${text}`);
      });
    });
  });

  describe('singleton apiClient instance', () => {
    it('should export a default apiClient instance', () => {
      const { apiClient: defaultInstance } = require('../index');
      expect(defaultInstance).toBeInstanceOf(ApiClient);
    });
  });
});