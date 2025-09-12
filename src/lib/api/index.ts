// API utilities for future REST endpoints
export class ApiClient {
  private baseUrl: string;
  
  constructor(baseUrl?: string) {
    if (baseUrl) {
      this.baseUrl = baseUrl;
    } else if (typeof window !== 'undefined') {
      // Use same origin with /api prefix for relative URLs
      this.baseUrl = `${window.location.origin}/api`;
    } else {
      // Server-side rendering - will be replaced on client
      this.baseUrl = '/api';
    }
  }

  async get<T>(endpoint: string): Promise<T> {
    // CRITICAL FIX: Validate endpoint parameter
    if (!endpoint || typeof endpoint !== 'string') {
      throw new Error('ApiClient.get: endpoint must be a non-empty string');
    }
    
    if (endpoint.trim() === '') {
      throw new Error('ApiClient.get: endpoint cannot be empty or whitespace');
    }
    
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`);
      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }
      return response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`ApiClient.get: Unexpected error - ${String(error)}`);
    }
  }

  async post<T>(endpoint: string, data: any): Promise<T> {
    // CRITICAL FIX: Validate endpoint parameter
    if (!endpoint || typeof endpoint !== 'string') {
      throw new Error('ApiClient.post: endpoint must be a non-empty string');
    }
    
    if (endpoint.trim() === '') {
      throw new Error('ApiClient.post: endpoint cannot be empty or whitespace');
    }
    
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }
      return response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`ApiClient.post: Unexpected error - ${String(error)}`);
    }
  }

  async delete<T>(endpoint: string): Promise<T> {
    // CRITICAL FIX: Validate endpoint parameter
    if (!endpoint || typeof endpoint !== 'string') {
      throw new Error('ApiClient.delete: endpoint must be a non-empty string');
    }
    
    if (endpoint.trim() === '') {
      throw new Error('ApiClient.delete: endpoint cannot be empty or whitespace');
    }
    
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }
      return response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`ApiClient.delete: Unexpected error - ${String(error)}`);
    }
  }
}

export const apiClient = new ApiClient();