/**
 * Comprehensive WebSocket Mock Utilities for Testing
 * Provides realistic WebSocket behavior simulation for complex test scenarios
 */

import type { WebSocketMessage } from '@/types';

// Event listener type
type EventListener = (data: any) => void;

// WebSocket connection states
export enum WebSocketState {
  CONNECTING = 0,
  OPEN = 1,
  CLOSING = 2,
  CLOSED = 3,
}

// Message types for different scenarios
export interface TerminalMessage {
  sessionId: string;
  data?: string;
  error?: string;
  cols?: number;
  rows?: number;
}

export interface SessionMessage {
  sessionId: string;
  action: 'created' | 'destroyed' | 'list';
  sessions?: Array<{ id: string; title: string }>;
}

/**
 * Advanced WebSocket Mock Class
 * Simulates real WebSocket behavior with realistic timing and error scenarios
 */
export class MockWebSocketClient {
  public connected: boolean = false;
  public connecting: boolean = false;
  public readyState: WebSocketState = WebSocketState.CLOSED;
  public url: string;
  
  private listeners: Map<string, EventListener[]> = new Map();
  private connectionDelay: number = 50;
  private messageDelay: number = 10;
  private shouldFailConnection: boolean = false;
  private connectionError: Error | null = null;
  private messageQueue: Array<{ event: string; data: any }> = [];
  private isProcessingQueue: boolean = false;
  private latency: number = 0;
  private dropRate: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectAttempts: number = 0;
  private autoReconnect: boolean = true;

  constructor(url: string = 'ws://localhost:11236') {
    this.url = url;
  }

  // Configuration methods for testing scenarios
  setConnectionDelay(ms: number): void {
    this.connectionDelay = ms;
  }

  setMessageDelay(ms: number): void {
    this.messageDelay = ms;
  }

  setLatency(ms: number): void {
    this.latency = ms;
  }

  setDropRate(rate: number): void {
    this.dropRate = Math.max(0, Math.min(1, rate));
  }

  simulateConnectionFailure(error?: Error): void {
    this.shouldFailConnection = true;
    this.connectionError = error || new Error('Connection failed');
  }

  simulateNetworkInstability(): void {
    this.setLatency(100 + Math.random() * 200);
    this.setDropRate(0.1);
  }

  resetToStable(): void {
    this.shouldFailConnection = false;
    this.connectionError = null;
    this.latency = 0;
    this.dropRate = 0;
    this.connectionDelay = 50;
    this.messageDelay = 10;
  }

  // Core WebSocket API implementation
  async connect(): Promise<void> {
    if (this.connected || this.connecting) {
      return Promise.resolve();
    }

    this.connecting = true;
    this.readyState = WebSocketState.CONNECTING;

    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (this.shouldFailConnection) {
          this.connecting = false;
          this.readyState = WebSocketState.CLOSED;
          this.reconnectAttempts++;
          
          if (this.autoReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
            // Attempt automatic reconnection
            setTimeout(() => {
              this.connect().catch(() => {});
            }, 1000 * this.reconnectAttempts);
          }
          
          reject(this.connectionError);
          return;
        }

        this.connected = true;
        this.connecting = false;
        this.readyState = WebSocketState.OPEN;
        this.reconnectAttempts = 0;
        
        this.emit('connect');
        this.processMessageQueue();
        resolve();
      }, this.connectionDelay);
    });
  }

  disconnect(): void {
    if (!this.connected && !this.connecting) {
      return;
    }

    this.connected = false;
    this.connecting = false;
    this.readyState = WebSocketState.CLOSED;
    this.messageQueue = [];
    
    this.emit('disconnect', 'client_disconnect');
    this.listeners.clear();
  }

  send(event: string, data: any): void {
    if (!this.connected) {
      console.warn('WebSocket not connected, cannot send message');
      return;
    }

    // Simulate message dropping
    if (Math.random() < this.dropRate) {
      console.warn('Message dropped due to simulated network issues');
      return;
    }

    // Add latency simulation
    setTimeout(() => {
      this.handleOutgoingMessage(event, data);
    }, this.latency);
  }

  sendMessage(message: WebSocketMessage): void {
    this.send('message', message);
  }

  on(event: string, callback: EventListener): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  off(event: string, callback: EventListener): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      const index = eventListeners.indexOf(callback);
      if (index > -1) {
        eventListeners.splice(index, 1);
      }
    }
  }

  public emit(event: string, data?: any): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      // Add slight delay to simulate real network behavior
      setTimeout(() => {
        eventListeners.forEach(callback => {
          try {
            callback(data);
          } catch (error) {
            console.error('Error in event listener:', error);
          }
        });
      }, this.messageDelay);
    }
  }

  private handleOutgoingMessage(event: string, data: any): void {
    // Simulate server responses based on event type
    switch (event) {
      case 'create':
        this.simulateSessionCreated(data);
        break;
      case 'destroy':
        this.simulateSessionDestroyed(data);
        break;
      case 'list':
        this.simulateSessionList(data);
        break;
      case 'data':
        this.simulateTerminalResponse(data);
        break;
      case 'resize':
        this.simulateTerminalResize(data);
        break;
      default:
        // Echo back unknown messages
        this.emit('message', { type: 'echo', data });
    }
  }

  private processMessageQueue(): void {
    if (this.isProcessingQueue || this.messageQueue.length === 0) {
      return;
    }

    this.isProcessingQueue = true;
    
    while (this.messageQueue.length > 0) {
      const { event, data } = this.messageQueue.shift()!;
      this.emit(event, data);
    }
    
    this.isProcessingQueue = false;
  }

  // Simulation methods for different message types
  simulateTerminalOutput(sessionId: string, output: string): void {
    const message: TerminalMessage = {
      sessionId,
      data: output,
    };
    
    if (this.connected) {
      this.emit('terminal-data', message);
    } else {
      this.messageQueue.push({ event: 'terminal-data', data: message });
    }
  }

  simulateTerminalError(sessionId: string, error: string): void {
    const message: TerminalMessage = {
      sessionId,
      error,
    };
    
    if (this.connected) {
      this.emit('terminal-error', message);
    } else {
      this.messageQueue.push({ event: 'terminal-error', data: message });
    }
  }

  simulateTerminalConfig(sessionId: string, cols: number, rows: number): void {
    const message: TerminalMessage = {
      sessionId,
      cols,
      rows,
    };
    
    if (this.connected) {
      this.emit('terminal-config', message);
    } else {
      this.messageQueue.push({ event: 'terminal-config', data: message });
    }
  }

  simulateConnectionChange(connected: boolean): void {
    if (this.connected) {
      this.emit('connection-change', connected);
    } else {
      this.messageQueue.push({ event: 'connection-change', data: connected });
    }
  }

  public simulateSessionCreated(data: any): void {
    const sessionId = data?.sessionId || `session-${Date.now()}`;
    const message: SessionMessage = {
      sessionId,
      action: 'created',
    };
    
    setTimeout(() => {
      this.emit('session-created', message);
      // Send initial terminal config
      this.simulateTerminalConfig(sessionId, 80, 24);
    }, 50);
  }

  public simulateSessionDestroyed(data: any): void {
    const message: SessionMessage = {
      sessionId: data?.sessionId || 'unknown',
      action: 'destroyed',
    };
    
    setTimeout(() => {
      this.emit('session-destroyed', message);
    }, 30);
  }

  private simulateSessionList(data: any): void {
    const message: SessionMessage = {
      sessionId: 'list',
      action: 'list',
      sessions: [
        { id: 'session-1', title: 'Main Terminal' },
        { id: 'session-2', title: 'Build Process' },
        { id: 'session-3', title: 'Development Server' },
      ],
    };
    
    setTimeout(() => {
      this.emit('session-list', message);
    }, 20);
  }

  private simulateTerminalResponse(data: any): void {
    const { sessionId, data: inputData } = data;
    
    // Simulate various command responses
    let output = '';
    
    if (inputData?.includes('ls')) {
      output = 'file1.txt  file2.txt  directory1/  directory2/\n';
    } else if (inputData?.includes('pwd')) {
      output = '/home/user/workspace\n';
    } else if (inputData?.includes('echo')) {
      const echoText = inputData.replace(/echo\s+/, '').replace(/["']/g, '');
      output = `${echoText}\n`;
    } else if (inputData?.includes('cat')) {
      output = 'File contents here...\n';
    } else if (inputData?.includes('npm')) {
      output = 'npm command executed successfully\n';
    } else if (inputData?.includes('git')) {
      output = 'Git command completed\n';
    } else if (inputData?.includes('clear')) {
      output = '\x1b[2J\x1b[H'; // Clear screen ANSI sequence
    } else {
      // Echo back the input with a prompt
      output = `Command executed: ${inputData}`;
    }
    
    setTimeout(() => {
      this.simulateTerminalOutput(sessionId, output);
      // Add prompt after command
      setTimeout(() => {
        this.simulateTerminalOutput(sessionId, 'user@localhost:~$ ');
      }, 50);
    }, 100 + Math.random() * 200); // Simulate realistic command execution time
  }

  private simulateTerminalResize(data: any): void {
    const { sessionId, cols, rows } = data;
    
    setTimeout(() => {
      this.emit('terminal-resize', { sessionId, cols, rows });
      // Send updated config
      this.simulateTerminalConfig(sessionId, cols, rows);
    }, 20);
  }

  // Testing utility methods
  getEventListenerCount(event: string): number {
    return this.listeners.get(event)?.length || 0;
  }

  getAllEventTypes(): string[] {
    return Array.from(this.listeners.keys());
  }

  getQueuedMessageCount(): number {
    return this.messageQueue.length;
  }

  clearMessageQueue(): void {
    this.messageQueue = [];
  }

  // Scenario simulation methods
  simulateSlowNetwork(): void {
    this.setConnectionDelay(2000);
    this.setMessageDelay(500);
    this.setLatency(300);
  }

  simulateUnstableNetwork(): void {
    this.setDropRate(0.2);
    this.setLatency(100 + Math.random() * 400);
  }

  simulateHighLatency(): void {
    this.setLatency(800);
    this.setMessageDelay(200);
  }

  simulateServerOverload(): void {
    this.setMessageDelay(1000);
    this.setDropRate(0.1);
  }

  // Batch operations for testing
  simulateBulkTerminalOutput(sessionId: string, lineCount: number): void {
    for (let i = 0; i < lineCount; i++) {
      setTimeout(() => {
        this.simulateTerminalOutput(sessionId, `Line ${i + 1} of bulk output\n`);
      }, i * 10);
    }
  }

  simulateRapidSessionChanges(sessionCount: number): void {
    for (let i = 0; i < sessionCount; i++) {
      setTimeout(() => {
        const sessionId = `rapid-session-${i}`;
        this.simulateSessionCreated({ sessionId });
        
        setTimeout(() => {
          this.simulateSessionDestroyed({ sessionId });
        }, 500);
      }, i * 100);
    }
  }

  simulateErrorRecovery(sessionId: string): void {
    // Simulate error then recovery
    setTimeout(() => {
      this.simulateTerminalError(sessionId, 'Temporary error occurred');
    }, 100);
    
    setTimeout(() => {
      this.simulateTerminalOutput(sessionId, 'Error recovered, connection restored\n');
    }, 1000);
  }
}

/**
 * Factory functions for common test scenarios
 */
export const createMockWebSocket = {
  stable: () => {
    const mock = new MockWebSocketClient();
    mock.resetToStable();
    return mock;
  },
  
  unstable: () => {
    const mock = new MockWebSocketClient();
    mock.simulateUnstableNetwork();
    return mock;
  },
  
  slow: () => {
    const mock = new MockWebSocketClient();
    mock.simulateSlowNetwork();
    return mock;
  },
  
  failing: (error?: Error) => {
    const mock = new MockWebSocketClient();
    mock.simulateConnectionFailure(error);
    return mock;
  },
  
  highLatency: () => {
    const mock = new MockWebSocketClient();
    mock.simulateHighLatency();
    return mock;
  },
};

/**
 * Test scenario builders
 */
export const createTestScenario = {
  terminalSession: (sessionId: string = 'test-session') => ({
    sessionId,
    start: (mock: MockWebSocketClient) => {
      mock.simulateSessionCreated({ sessionId });
      mock.simulateTerminalConfig(sessionId, 80, 24);
      mock.simulateTerminalOutput(sessionId, 'Welcome to terminal\n');
      mock.simulateTerminalOutput(sessionId, 'user@localhost:~$ ');
    },
    sendCommand: (mock: MockWebSocketClient, command: string) => {
      mock.send('data', { sessionId, data: command });
    },
    end: (mock: MockWebSocketClient) => {
      mock.simulateSessionDestroyed({ sessionId });
    },
  }),
  
  connectionDropout: (duration: number = 5000) => ({
    simulate: (mock: MockWebSocketClient) => {
      setTimeout(() => {
        mock.disconnect();
        mock.emit('disconnect', 'network_error');
      }, 1000);
      
      setTimeout(() => {
        mock.connect();
      }, duration);
    },
  }),
  
  bulkDataTransfer: (sessionId: string, dataSize: number) => ({
    simulate: (mock: MockWebSocketClient) => {
      const chunks = Math.ceil(dataSize / 1000);
      for (let i = 0; i < chunks; i++) {
        setTimeout(() => {
          const chunkData = 'x'.repeat(Math.min(1000, dataSize - i * 1000));
          mock.simulateTerminalOutput(sessionId, chunkData);
        }, i * 50);
      }
    },
  }),
};

/**
 * Utility functions for test assertions
 */
export const testHelpers = {
  waitForConnection: (mock: MockWebSocketClient, timeout: number = 5000): Promise<void> => {
    return new Promise((resolve, reject) => {
      if (mock.connected) {
        resolve();
        return;
      }
      
      const timer = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, timeout);
      
      mock.on('connect', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  },
  
  waitForMessage: (mock: MockWebSocketClient, event: string, timeout: number = 5000): Promise<any> => {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Message timeout for event: ${event}`));
      }, timeout);
      
      mock.on(event, (data) => {
        clearTimeout(timer);
        resolve(data);
      });
    });
  },
  
  waitForDisconnection: (mock: MockWebSocketClient, timeout: number = 5000): Promise<void> => {
    return new Promise((resolve, reject) => {
      if (!mock.connected) {
        resolve();
        return;
      }
      
      const timer = setTimeout(() => {
        reject(new Error('Disconnection timeout'));
      }, timeout);
      
      mock.on('disconnect', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  },
};

export default MockWebSocketClient;
