/**
 * Terminal Configuration Service
 * 
 * This service fetches terminal configuration from the backend
 * via HTTP, completely independent of the WebSocket connection.
 * This ensures configuration is available before terminal initialization.
 */

export interface TerminalBackendConfig {
  cols: number;
  rows: number;
  fontSize: number;
  fontFamily: string;
  theme: {
    background: string;
    foreground: string;
    cursor: string;
    cursorAccent: string;
    selection: string;
    black: string;
    red: string;
    green: string;
    yellow: string;
    blue: string;
    magenta: string;
    cyan: string;
    white: string;
    brightBlack: string;
    brightRed: string;
    brightGreen: string;
    brightYellow: string;
    brightBlue: string;
    brightMagenta: string;
    brightCyan: string;
    brightWhite: string;
  };
  scrollback: number;
  cursorBlink: boolean;
  cursorStyle: 'block' | 'bar' | 'underline';
  allowTransparency: boolean;
  windowsMode: boolean;
  macOptionIsMeta: boolean;
  rightClickSelectsWord: boolean;
  rendererType: 'canvas' | 'dom' | 'webgl';
  screenReaderMode: boolean;
  convertEol: boolean;
  bellStyle: 'none' | 'sound' | 'visual' | 'both';
  sessionId?: string;
  timestamp?: number;
}

class TerminalConfigService {
  private configCache: Map<string, TerminalBackendConfig> = new Map();
  private configPromises: Map<string, Promise<TerminalBackendConfig>> = new Map();
  private baseUrl: string;

  constructor() {
    if (typeof window !== 'undefined') {
      // Always use the same origin as the current page
      // This ensures all requests go to the same host and port
      this.baseUrl = window.location.origin;
      console.log('[TerminalConfigService] Using same origin:', this.baseUrl);
    } else {
      // Server-side rendering - will be set on client
      this.baseUrl = '';
      console.log('[TerminalConfigService] Server-side rendering - URL will be set on client');
    }
  }

  /**
   * Fetch terminal configuration for a specific session
   * This method ensures only one request is made per session
   */
  async fetchConfig(sessionId: string): Promise<TerminalBackendConfig> {
    console.log(`[TerminalConfigService] Fetching config for session: ${sessionId}`);
    
    // Check cache first
    if (this.configCache.has(sessionId)) {
      console.log(`[TerminalConfigService] Returning cached config for session: ${sessionId}`);
      return this.configCache.get(sessionId)!;
    }

    // Check if a request is already in progress
    if (this.configPromises.has(sessionId)) {
      console.log(`[TerminalConfigService] Request already in progress for session: ${sessionId}`);
      return this.configPromises.get(sessionId)!;
    }

    // Create new request
    const configPromise = this.makeConfigRequest(sessionId);
    this.configPromises.set(sessionId, configPromise);

    try {
      const config = await configPromise;
      this.configCache.set(sessionId, config);
      this.configPromises.delete(sessionId);
      return config;
    } catch (error) {
      this.configPromises.delete(sessionId);
      throw error;
    }
  }

  /**
   * Make the actual HTTP request to fetch configuration
   */
  private async makeConfigRequest(sessionId: string): Promise<TerminalBackendConfig> {
    // Ensure we have a base URL (important for SSR)
    if (!this.baseUrl && typeof window !== 'undefined') {
      this.baseUrl = window.location.origin;
    }
    
    if (!this.baseUrl) {
      throw new Error('No base URL available for configuration request');
    }
    
    const url = `${this.baseUrl}/api/terminal-config/${sessionId}`;
    console.log(`[TerminalConfigService] Making HTTP request to: ${url}`);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        // Add timeout
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch config: ${response.status} ${response.statusText}`);
      }

      const config = await response.json();
      console.log(`[TerminalConfigService] Config received for session ${sessionId}:`, config);
      
      // Validate the configuration
      if (!config.cols || !config.rows) {
        throw new Error('Invalid configuration: missing cols or rows');
      }

      return config as TerminalBackendConfig;
    } catch (error: any) {
      // Handle timeout specifically
      if (error.name === 'AbortError') {
        console.error(`[TerminalConfigService] Request timeout for session: ${sessionId}`);
        throw new Error('Configuration request timeout');
      }
      
      console.error(`[TerminalConfigService] Failed to fetch config for session ${sessionId}:`, error);
      throw error;
    }
  }

  /**
   * Clear cached configuration for a session
   */
  clearCache(sessionId?: string) {
    if (sessionId) {
      this.configCache.delete(sessionId);
      this.configPromises.delete(sessionId);
      console.log(`[TerminalConfigService] Cleared cache for session: ${sessionId}`);
    } else {
      this.configCache.clear();
      this.configPromises.clear();
      console.log('[TerminalConfigService] Cleared all cached configurations');
    }
  }

  /**
   * Check if configuration is available for a session
   */
  hasConfig(sessionId: string): boolean {
    return this.configCache.has(sessionId);
  }

  /**
   * Get cached configuration without making a request
   */
  getCachedConfig(sessionId: string): TerminalBackendConfig | null {
    return this.configCache.get(sessionId) || null;
  }
}

// Export singleton instance
export const terminalConfigService = new TerminalConfigService();