// Enhanced WebSocket mock for comprehensive testing
class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.onopen = null;
    this.onclose = null;
    this.onmessage = null;
    this.onerror = null;
    this.protocol = '';
    this.extensions = '';
    this.binaryType = 'blob';
    this.bufferedAmount = 0;

    // Store instance for testing access
    MockWebSocket.instances.push(this);

    // Simulate async connection
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen({ type: 'open', target: this });
      }
      this.dispatchEvent(new Event('open'));
    }, 10);
  }

  send(data) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }

    // Store sent data for test verification
    MockWebSocket.sentMessages.push(data);

    // Echo back for testing (simulate server response)
    setTimeout(() => {
      if (this.onmessage) {
        this.onmessage({
          type: 'message',
          data: `echo: ${data}`,
          target: this,
        });
      }
    }, 5);
  }

  close(code = 1000, reason = '') {
    this.readyState = MockWebSocket.CLOSING;
    setTimeout(() => {
      this.readyState = MockWebSocket.CLOSED;
      if (this.onclose) {
        this.onclose({
          type: 'close',
          code,
          reason,
          wasClean: code === 1000,
          target: this,
        });
      }
      this.dispatchEvent(new Event('close'));
    }, 5);
  }

  addEventListener(type, listener) {
    switch (type) {
      case 'open':
        this.onopen = listener;
        break;
      case 'close':
        this.onclose = listener;
        break;
      case 'message':
        this.onmessage = listener;
        break;
      case 'error':
        this.onerror = listener;
        break;
    }
  }

  removeEventListener(type, listener) {
    switch (type) {
      case 'open':
        if (this.onopen === listener) this.onopen = null;
        break;
      case 'close':
        if (this.onclose === listener) this.onclose = null;
        break;
      case 'message':
        if (this.onmessage === listener) this.onmessage = null;
        break;
      case 'error':
        if (this.onerror === listener) this.onerror = null;
        break;
    }
  }

  dispatchEvent(event) {
    // Mock event dispatching
    return true;
  }

  // Utility methods for testing
  static simulateMessage(data) {
    MockWebSocket.instances.forEach(instance => {
      if (instance.readyState === MockWebSocket.OPEN && instance.onmessage) {
        instance.onmessage({
          type: 'message',
          data,
          target: instance,
        });
      }
    });
  }

  static simulateError(error = 'Connection failed') {
    MockWebSocket.instances.forEach(instance => {
      if (instance.onerror) {
        instance.onerror({
          type: 'error',
          error,
          message: error,
          target: instance,
        });
      }
    });
  }

  static reset() {
    MockWebSocket.instances = [];
    MockWebSocket.sentMessages = [];
  }

  static getLastInstance() {
    return MockWebSocket.instances[MockWebSocket.instances.length - 1];
  }

  static getSentMessages() {
    return [...MockWebSocket.sentMessages];
  }
}

// WebSocket constants
MockWebSocket.CONNECTING = 0;
MockWebSocket.OPEN = 1;
MockWebSocket.CLOSING = 2;
MockWebSocket.CLOSED = 3;

// Static arrays to track instances and messages
MockWebSocket.instances = [];
MockWebSocket.sentMessages = [];

// Mock Socket.IO client
const mockSocket = {
  connected: false,
  connecting: false,
  id: 'mock-socket-id',

  connect: jest.fn(() => {
    mockSocket.connected = true;
    mockSocket.connecting = false;
    return mockSocket;
  }),

  disconnect: jest.fn(() => {
    mockSocket.connected = false;
    return mockSocket;
  }),

  emit: jest.fn((event, data, callback) => {
    // Store emitted events for testing
    mockSocket._emittedEvents = mockSocket._emittedEvents || [];
    mockSocket._emittedEvents.push({ event, data });

    // Simulate callback if provided
    if (callback && typeof callback === 'function') {
      setTimeout(() => callback(null, { success: true }), 5);
    }
  }),

  on: jest.fn((event, callback) => {
    mockSocket._eventListeners = mockSocket._eventListeners || {};
    mockSocket._eventListeners[event] = mockSocket._eventListeners[event] || [];
    mockSocket._eventListeners[event].push(callback);
  }),

  off: jest.fn((event, callback) => {
    if (mockSocket._eventListeners && mockSocket._eventListeners[event]) {
      const index = mockSocket._eventListeners[event].indexOf(callback);
      if (index > -1) {
        mockSocket._eventListeners[event].splice(index, 1);
      }
    }
  }),

  removeAllListeners: jest.fn((event) => {
    if (event && mockSocket._eventListeners) {
      delete mockSocket._eventListeners[event];
    } else {
      mockSocket._eventListeners = {};
    }
  }),

  // Utility methods for testing
  simulateEvent: (event, data) => {
    if (mockSocket._eventListeners && mockSocket._eventListeners[event]) {
      mockSocket._eventListeners[event].forEach(callback => callback(data));
    }
  },

  reset: () => {
    mockSocket.connected = false;
    mockSocket.connecting = false;
    mockSocket._emittedEvents = [];
    mockSocket._eventListeners = {};
    mockSocket.connect.mockClear();
    mockSocket.disconnect.mockClear();
    mockSocket.emit.mockClear();
    mockSocket.on.mockClear();
    mockSocket.off.mockClear();
    mockSocket.removeAllListeners.mockClear();
  },

  getEmittedEvents: () => mockSocket._emittedEvents || [],
  getEventListeners: (event) => mockSocket._eventListeners?.[event] || [],
};

// Mock socket.io-client
jest.mock('socket.io-client', () => ({
  io: jest.fn(() => mockSocket),
  Socket: MockWebSocket,
}));

// Export mocks
export { MockWebSocket, mockSocket };
export default MockWebSocket;