/**
 * Enhanced WebSocket Mock for Reliable Testing
 * Addresses flaky test issues and provides realistic simulation
 */

export interface MockWebSocketConfig {
  latency?: number;
  errorRate?: number;
  maxConnections?: number;
  messageBufferSize?: number;
}

export interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: number;
}

export class EnhancedMockWebSocket {
  static instances: EnhancedMockWebSocket[] = [];
  static globalConfig: MockWebSocketConfig = {
    latency: 0,
    errorRate: 0,
    maxConnections: 10,
    messageBufferSize: 1000
  };
  
  // WebSocket properties
  url: string;
  readyState: number = WebSocket.CONNECTING;
  protocol: string = '';
  extensions: string = '';
  binaryType: BinaryType = 'blob';
  bufferedAmount: number = 0;
  
  // Event handlers
  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  
  // Mock-specific properties
  private messageQueue: WebSocketMessage[] = [];
  private isConnected: boolean = false;
  private connectionId: string;
  private eventListeners: Map<string, Function[]> = new Map();
  
  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.connectionId = `ws_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    if (typeof protocols === 'string') {
      this.protocol = protocols;
    } else if (Array.isArray(protocols) && protocols.length > 0) {
      this.protocol = protocols[0];
    }
    
    EnhancedMockWebSocket.instances.push(this);
    
    // Simulate connection with configurable latency
    this.simulateConnection();
  }
  
  private simulateConnection(): void {
    const latency = EnhancedMockWebSocket.globalConfig.latency || 0;
    
    setTimeout(() => {
      if (this.shouldSimulateError()) {
        this.simulateError('Connection failed');
        return;
      }
      
      this.readyState = WebSocket.OPEN;
      this.isConnected = true;
      
      const openEvent = new Event('open');
      if (this.onopen) {
        this.onopen(openEvent);
      }
      this.dispatchEvent('open', openEvent);
    }, latency);
  }
  
  private shouldSimulateError(): boolean {
    const errorRate = EnhancedMockWebSocket.globalConfig.errorRate || 0;
    return Math.random() < errorRate;
  }
  
  
  // WebSocket API methods
  send(data: string | ArrayBuffer | Blob | ArrayBufferView): void {
    if (this.readyState !== WebSocket.OPEN) {
      throw new DOMException('WebSocket is not open', 'InvalidStateError');
    }
    
    // Simulate buffered amount
    if (typeof data === 'string') {
      this.bufferedAmount += data.length;
    } else if (data instanceof ArrayBuffer) {
      this.bufferedAmount += data.byteLength;
    }
    
    // Process message queue
    setTimeout(() => {
      this.bufferedAmount = Math.max(0, this.bufferedAmount - (typeof data === 'string' ? data.length : 0));
    }, 1);
    
    // Store message for potential echoing
    this.messageQueue.push({
      type: 'sent',
      data,
      timestamp: Date.now()
    });
    
    // Trim queue if too large
    if (this.messageQueue.length > (EnhancedMockWebSocket.globalConfig.messageBufferSize || 1000)) {
      this.messageQueue.shift();
    }
  }
  
  close(code?: number, reason?: string): void {
    if (this.readyState === WebSocket.CLOSED || this.readyState === WebSocket.CLOSING) {
      return;
    }
    
    this.readyState = WebSocket.CLOSING;
    
    setTimeout(() => {
      this.readyState = WebSocket.CLOSED;
      this.isConnected = false;
      
      const closeEvent = new CloseEvent('close', {
        code: code || 1000,
        reason: reason || '',
        wasClean: true
      });
      
      if (this.onclose) {
        this.onclose(closeEvent);
      }
      this.dispatchEvent('close', closeEvent);
      
      // Remove from instances
      const index = EnhancedMockWebSocket.instances.indexOf(this);
      if (index > -1) {
        EnhancedMockWebSocket.instances.splice(index, 1);
      }
    }, 1);
  }
  
  // Event listener management
  addEventListener(type: string, listener: (event: any) => void): void {
    if (!this.eventListeners.has(type)) {
      this.eventListeners.set(type, []);
    }
    this.eventListeners.get(type)!.push(listener);
  }
  
  removeEventListener(type: string, listener: (event: any) => void): void {
    const listeners = this.eventListeners.get(type);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }
  
  dispatchEvent(type: string, event: Event): boolean {
    const listeners = this.eventListeners.get(type) || [];
    listeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error(`Error in WebSocket event listener for ${type}:`, error);
      }
    });
    return true;
  }
  
  // Mock-specific methods for testing
  simulateMessage(data: any): void {
    if (this.readyState !== WebSocket.OPEN) {
      console.warn('Cannot simulate message on closed WebSocket');
      return;
    }
    
    const messageEvent = new MessageEvent('message', {
      data,
      origin: this.url,
      lastEventId: '',
      source: null,
      ports: []
    });
    
    if (this.onmessage) {
      this.onmessage(messageEvent);
    }
    this.dispatchEvent('message', messageEvent);
    
    this.messageQueue.push({
      type: 'received',
      data,
      timestamp: Date.now()
    });
  }
  
  simulateError(error?: string): void {
    const errorEvent = new Event('error');
    if (this.onerror) {
      this.onerror(errorEvent);
    }
    this.dispatchEvent('error', errorEvent);
  }
  
  simulateDisconnection(code: number = 1006, reason: string = 'Connection lost'): void {
    this.readyState = WebSocket.CLOSED;
    this.isConnected = false;
    
    const closeEvent = new CloseEvent('close', {
      code,
      reason,
      wasClean: false
    });
    
    if (this.onclose) {
      this.onclose(closeEvent);
    }
    this.dispatchEvent('close', closeEvent);
  }
  
  getMessageHistory(): WebSocketMessage[] {
    return [...this.messageQueue];
  }
  
  clearMessageHistory(): void {
    this.messageQueue = [];
  }
  
  // Static methods for test control
  static setGlobalConfig(config: Partial<MockWebSocketConfig>): void {
    this.globalConfig = { ...this.globalConfig, ...config };
  }
  
  static resetGlobalConfig(): void {
    this.globalConfig = {
      latency: 0,
      errorRate: 0,
      maxConnections: 10,
      messageBufferSize: 1000
    };
  }
  
  static getActiveConnections(): EnhancedMockWebSocket[] {
    return this.instances.filter(instance => instance.isConnected);
  }
  
  static closeAllConnections(): void {
    this.instances.forEach(instance => instance.close());
  }
  
  static reset(): void {
    this.closeAllConnections();
    this.instances = [];
    this.resetGlobalConfig();
  }
  
  static simulateNetworkPartition(duration: number = 1000): Promise<void> {
    const activeInstances = this.getActiveConnections();
    
    // Disconnect all active connections
    activeInstances.forEach(instance => {
      instance.simulateDisconnection(1006, 'Network partition');
    });
    
    return new Promise(resolve => {
      setTimeout(() => {
        // Reconnection would be handled by the application layer
        resolve();
      }, duration);
    });
  }
}

// Test utilities
export const createMockWebSocket = (url: string = 'ws://localhost:8080'): EnhancedMockWebSocket => {
  return new EnhancedMockWebSocket(url);
};

export const createWebSocketTestScenario = (scenario: 'success' | 'error' | 'slow' | 'unstable') => {
  switch (scenario) {
    case 'success':
      EnhancedMockWebSocket.setGlobalConfig({ latency: 0, errorRate: 0 });
      break;
    case 'error':
      EnhancedMockWebSocket.setGlobalConfig({ latency: 0, errorRate: 1 });
      break;
    case 'slow':
      EnhancedMockWebSocket.setGlobalConfig({ latency: 1000, errorRate: 0 });
      break;
    case 'unstable':
      EnhancedMockWebSocket.setGlobalConfig({ latency: 100, errorRate: 0.1 });
      break;
  }
};

export const waitForWebSocketConnection = (ws: EnhancedMockWebSocket, timeout: number = 5000): Promise<void> => {
  return new Promise((resolve, reject) => {
    if (ws.readyState === WebSocket.OPEN) {
      resolve();
      return;
    }
    
    const timeoutId = setTimeout(() => {
      reject(new Error(`WebSocket connection timeout after ${timeout}ms`));
    }, timeout);
    
    const onOpen = () => {
      clearTimeout(timeoutId);
      ws.removeEventListener('open', onOpen);
      ws.removeEventListener('error', onError);
      resolve();
    };
    
    const onError = () => {
      clearTimeout(timeoutId);
      ws.removeEventListener('open', onOpen);
      ws.removeEventListener('error', onError);
      reject(new Error('WebSocket connection failed'));
    };
    
    ws.addEventListener('open', onOpen);
    ws.addEventListener('error', onError);
  });
};

// Global setup for WebSocket testing
export const setupWebSocketTesting = (): void => {
  // Replace global WebSocket with mock
  global.WebSocket = EnhancedMockWebSocket as any;
  
  // WebSocket constants
  Object.defineProperty(global.WebSocket, 'CONNECTING', { value: 0, writable: false });
  Object.defineProperty(global.WebSocket, 'OPEN', { value: 1, writable: false });
  Object.defineProperty(global.WebSocket, 'CLOSING', { value: 2, writable: false });
  Object.defineProperty(global.WebSocket, 'CLOSED', { value: 3, writable: false });
  
  // Reset after each test
  afterEach(() => {
    EnhancedMockWebSocket.reset();
  });
};

export default {
  EnhancedMockWebSocket,
  createMockWebSocket,
  createWebSocketTestScenario,
  waitForWebSocketConnection,
  setupWebSocketTesting
};