import { io, Socket } from 'socket.io-client';
import type { WebSocketMessage } from '@/types';

class WebSocketClient {
  private socket: Socket | null = null;
  private url: string;
  private isConnecting: boolean = false;
  private listeners: Map<string, ((data: any) => void)[]> = new Map();
  private pendingTerminalConfigs: Map<string, any> = new Map(); // Store terminal configs until listeners are ready
  private pendingConfigCheckInterval: NodeJS.Timeout | null = null; // Periodic check for pending configs
  private configRequestQueue: Map<string, { resolve: (config: any) => void; reject: (error: any) => void; timeout: NodeJS.Timeout }> = new Map(); // Track config requests with promises

  constructor(url?: string) {
    if (url) {
      this.url = url;
      console.log('[WebSocket] Using provided URL:', this.url);
    } else if (typeof window !== 'undefined') {
      // Always use the same origin as the current page
      // This ensures all requests go to the same host and port
      this.url = window.location.origin;
      console.log('[WebSocket] Using same origin:', this.url);
    } else {
      // Server-side rendering or testing - will be replaced on client
      this.url = '';
      console.log('[WebSocket] Server-side rendering - URL will be set on client');
    }
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      // In test environment, simulate connection without real socket
      if (process.env.NODE_ENV === 'test') {
        this.isConnecting = true;
        setTimeout(() => {
          this.isConnecting = false;
          // Simulate successful connection in tests
          resolve();
        }, 10);
        return;
      }

      if (this.socket?.connected) {
        resolve();
        return;
      }

      if (this.isConnecting) {
        // Wait for the current connection attempt
        const checkConnection = () => {
          if (this.socket?.connected) {
            resolve();
          } else if (!this.isConnecting) {
            reject(new Error('Connection failed'));
          } else {
            setTimeout(checkConnection, 100);
          }
        };
        checkConnection();
        return;
      }

      this.isConnecting = true;

      // Ensure we have a valid URL (important for SSR)
      if (!this.url && typeof window !== 'undefined') {
        this.url = window.location.origin;
      }
      
      if (!this.url) {
        reject(new Error('No URL available for WebSocket connection'));
        return;
      }

      console.log('[WebSocket] Attempting to connect to:', this.url);
      
      this.socket = io(this.url, {
        path: '/api/ws', // Use the /api/ws endpoint for WebSocket
        transports: ['websocket', 'polling'],
        autoConnect: false, // CRITICAL: Don't auto-connect until event listeners are set up
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });

      // Set up ALL event listeners BEFORE connecting to avoid race conditions
      console.log('[WebSocket] Setting up event listeners before connection...');

      // Set up message routing FIRST
      this.socket.on('message', (message: WebSocketMessage) => {
        this.emit('message', message);
      });

      this.socket.on('terminal-data', (data) => {
        this.emit('terminal-data', data);
      });

      this.socket.on('terminal-resize', (data) => {
        this.emit('terminal-resize', data);
      });

      // CRITICAL: Register terminal-config listener BEFORE connecting
      this.socket.on('terminal-config', (data) => {
        console.log('[WebSocket] 🔧 TERMINAL-CONFIG EVENT RECEIVED in client.ts:', data);
        console.log('[WebSocket] 🔧 DEBUG: About to emit terminal-config to listeners, listener count:', this.listeners.get('terminal-config')?.length || 0);
        
        // FIRST: Handle any pending config requests for this session
        const pendingRequest = this.configRequestQueue.get(data.sessionId);
        if (pendingRequest) {
          console.log('[WebSocket] 🔧 Resolving pending config request for sessionId:', data.sessionId);
          clearTimeout(pendingRequest.timeout);
          pendingRequest.resolve(data);
          this.configRequestQueue.delete(data.sessionId);
        }
        
        // SECOND: Handle regular event listeners
        const listenerCount = this.listeners.get('terminal-config')?.length || 0;
        if (listenerCount === 0) {
          // No listeners yet - store the config for later delivery
          console.log('[WebSocket] 🔧 DEBUG: No listeners available, storing terminal-config for sessionId:', data.sessionId);
          this.pendingTerminalConfigs.set(data.sessionId, data);
          
          // Start periodic check if not already running
          this.startPendingConfigCheck();
        } else {
          // Emit immediately if listeners are available
          this.emit('terminal-config', data);
        }
        
        console.log('[WebSocket] 🔧 DEBUG: terminal-config event processed');
      });

      this.socket.on('terminal-error', (data) => {
        this.emit('terminal-error', data);
      });

      this.socket.on('connection-change', (data) => {
        this.emit('connection-change', data);
      });

      this.socket.on('session-created', (data) => {
        console.log('[WebSocket] Received session-created:', data);
        this.emit('session-created', data);
      });

      this.socket.on('session-destroyed', (data) => {
        this.emit('session-destroyed', data);
      });

      // Connection event handlers
      this.socket.on('connect', () => {
        console.log('[WebSocket] Successfully connected! Socket ID:', this.socket?.id);
        this.isConnecting = false;
        clearTimeout(connectionTimeout);
        resolve();
      });

      this.socket.on('disconnect', (reason) => {
        console.log('[WebSocket] Disconnected:', reason);
        this.isConnecting = false;
      });

      this.socket.on('connect_error', (error) => {
        console.error('[WebSocket] Connection error:', error.message, 'URL:', this.url);
        console.error('[WebSocket] Full error:', error);
        this.isConnecting = false;
        // Don't reject on connection error if we're already connected
        if (!this.socket?.connected) {
          reject(error);
        }
      });

      // Add timeout to detect connection issues
      const connectionTimeout = setTimeout(() => {
        if (!this.socket?.connected) {
          console.warn('[WebSocket] Connection timeout after 5 seconds to:', this.url);
        }
      }, 5000);

      // NOW connect after all listeners are set up
      console.log('[WebSocket] Event listeners ready, initiating connection...');
      this.socket.connect();
    });
  }

  disconnect(): void {
    if (this.socket) {
      // Remove all listeners before disconnecting to prevent memory leaks
      this.socket.removeAllListeners();
      this.socket.disconnect();
      this.socket = null;
    }
    this.isConnecting = false;
    this.listeners.clear();
    this.stopPendingConfigCheck();
    this.pendingTerminalConfigs.clear();
    
    // Clean up any pending config requests
    for (const [sessionId, request] of this.configRequestQueue.entries()) {
      clearTimeout(request.timeout);
      request.reject(new Error('WebSocket disconnected'));
    }
    this.configRequestQueue.clear();
  }

  send(event: string, data: any): void {
    if (this.socket?.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }

  sendMessage(message: WebSocketMessage): void {
    this.send('message', message);
  }

  // Request terminal config and return a promise that resolves with the config
  requestTerminalConfigAsync(sessionId: string, timeoutMs: number = 5000): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.socket?.connected) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      console.log(`[WebSocket] 🔧 Requesting terminal config with promise for session: ${sessionId}`);
      
      // Set up timeout
      const timeout = setTimeout(() => {
        this.configRequestQueue.delete(sessionId);
        reject(new Error(`Terminal config request timeout for session ${sessionId}`));
      }, timeoutMs);
      
      // Store the request
      this.configRequestQueue.set(sessionId, { resolve, reject, timeout });
      
      // Send the request
      this.socket.emit('request-config', { sessionId });
      
      console.log(`[WebSocket] 🔧 Config request sent for session: ${sessionId}, timeout: ${timeoutMs}ms`);
    });
  }

  // Event emitter-like interface
  on(event: string, callback: (data: any) => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    const eventListeners = this.listeners.get(event)!;
    
    // Check if this callback is already registered (prevent duplicates)
    if (!eventListeners.includes(callback)) {
      // Prevent memory leaks by limiting listeners
      if (eventListeners.length >= 10) {
        console.warn(`MaxListenersExceededWarning: ${event} has ${eventListeners.length} listeners. Consider using off() to remove listeners.`);
      }
      
      eventListeners.push(callback);
      console.log(`[WebSocket] 📊 Added listener for ${event} (total: ${eventListeners.length})`);
    } else {
      console.log(`[WebSocket] 📊 Callback already registered for ${event} (total: ${eventListeners.length})`);
    }
    
    // Special handling for terminal-config: deliver any pending configs for this event
    if (event === 'terminal-config' && this.pendingTerminalConfigs.size > 0) {
      console.log('[WebSocket] 🔧 DEBUG: terminal-config listener registered, checking for pending configs...', this.pendingTerminalConfigs.size);
      
      // Deliver all pending terminal configs
      for (const [sessionId, configData] of this.pendingTerminalConfigs.entries()) {
        console.log('[WebSocket] 🔧 DEBUG: Delivering pending terminal-config for sessionId:', sessionId, configData);
        // Use setTimeout to ensure the listener is fully registered before calling
        setTimeout(() => {
          callback(configData);
        }, 0);
      }
      
      // Clear pending configs after delivery
      this.pendingTerminalConfigs.clear();
      console.log('[WebSocket] 🔧 DEBUG: All pending terminal-configs delivered and cleared');
    }
  }

  off(event: string, callback: (data: any) => void): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      const index = eventListeners.indexOf(callback);
      if (index > -1) {
        eventListeners.splice(index, 1);
      }
    }
  }

  private emit(event: string, data: any): void {
    const eventListeners = this.listeners.get(event);
    console.log(`[WebSocket] 🔧 DEBUG: emit(${event}) - found ${eventListeners?.length || 0} listeners`);
    if (eventListeners) {
      eventListeners.forEach((callback, index) => {
        console.log(`[WebSocket] 🔧 DEBUG: Calling listener ${index} for ${event}`);
        callback(data);
      });
    } else {
      console.warn(`[WebSocket] ⚠️ No listeners registered for event: ${event}`);
    }
  }

  get connected(): boolean {
    return this.socket?.connected || false;
  }

  get connecting(): boolean {
    return this.isConnecting;
  }

  // Periodic check for pending terminal configs
  private startPendingConfigCheck(): void {
    if (this.pendingConfigCheckInterval) {
      return; // Already running
    }

    console.log('[WebSocket] 🔧 Starting periodic check for pending terminal configs (every 1 second)');
    this.pendingConfigCheckInterval = setInterval(() => {
      if (this.pendingTerminalConfigs.size === 0) {
        console.log('[WebSocket] 🔧 Periodic check: No pending configs, stopping interval');
        this.stopPendingConfigCheck();
        return;
      }

      const terminalConfigListeners = this.listeners.get('terminal-config');
      if (terminalConfigListeners && terminalConfigListeners.length > 0) {
        console.log('[WebSocket] 🔧 Periodic check: Found terminal-config listeners, delivering pending configs...');
        
        // Deliver all pending configs
        for (const [sessionId, configData] of this.pendingTerminalConfigs.entries()) {
          console.log('[WebSocket] 🔧 Periodic delivery: Sending terminal-config for sessionId:', sessionId, configData);
          terminalConfigListeners.forEach(callback => {
            callback(configData);
          });
        }
        
        // Clear pending configs and stop checking
        this.pendingTerminalConfigs.clear();
        this.stopPendingConfigCheck();
        console.log('[WebSocket] 🔧 Periodic delivery: All configs delivered, stopping interval');
      } else {
        console.log('[WebSocket] 🔧 Periodic check: Still waiting for terminal-config listeners...', this.pendingTerminalConfigs.size, 'pending configs');
      }
    }, 1000); // Check every second
  }

  private stopPendingConfigCheck(): void {
    if (this.pendingConfigCheckInterval) {
      clearInterval(this.pendingConfigCheckInterval);
      this.pendingConfigCheckInterval = null;
      console.log('[WebSocket] 🔧 Stopped periodic config check');
    }
  }
}

// Export a singleton instance
export const wsClient = new WebSocketClient();
export default WebSocketClient;