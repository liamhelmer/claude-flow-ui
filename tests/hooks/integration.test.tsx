import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { MockWebSocketClient } from './__mocks__/websocket-client';

// Mock the useWebSocket hook before importing
const mockWebSocketHook = {
  sendData: jest.fn(),
  resizeTerminal: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
  connected: true,
  connecting: false,
  connect: jest.fn(),
  disconnect: jest.fn(),
  sendMessage: jest.fn(),
  createSession: jest.fn(),
  destroySession: jest.fn(),
  listSessions: jest.fn(),
};

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => mockWebSocketHook,
}));

// Integration tests for useTerminal and useWebSocket working together
describe('useTerminal + useWebSocket Integration', () => {
  let mockWsClient: MockWebSocketClient;

  beforeEach(() => {
    mockWsClient = new MockWebSocketClient();
    jest.clearAllMocks();
    // Reset mock values
    mockWebSocketHook.isConnected = true;
    mockWebSocketHook.connected = true;
    mockWebSocketHook.connecting = false;
  });

  it('should handle complete terminal session lifecycle', async () => {
    const { result } = renderHook(() => useTerminal({
      sessionId: 'integration-test-session',
    }));

    // Verify WebSocket integration
    expect(result.current.isConnected).toBe(true);
    
    // Verify terminal operations work
    expect(() => {
      result.current.writeToTerminal('test');
      result.current.clearTerminal();
      result.current.focusTerminal();
    }).not.toThrow();
  });

  it('should handle WebSocket disconnection gracefully', async () => {
    // Set mock to disconnected state
    mockWebSocketHook.isConnected = false;
    mockWebSocketHook.connected = false;

    const { result } = renderHook(() => useTerminal({
      sessionId: 'disconnected-session',
    }));

    expect(result.current.isConnected).toBe(false);

    // Terminal operations should still work locally
    expect(() => {
      result.current.writeToTerminal('test');
      result.current.clearTerminal();
      result.current.focusTerminal();
    }).not.toThrow();
  });

  it('should handle WebSocket reconnection', async () => {
    // Initially disconnected
    mockWebSocketHook.isConnected = false;
    mockWebSocketHook.connected = false;

    const { result, rerender } = renderHook(() => useTerminal({
      sessionId: 'reconnection-session',
    }));

    // Initially disconnected
    expect(result.current.isConnected).toBe(false);

    // Simulate reconnection
    await act(async () => {
      mockWebSocketHook.isConnected = true;
      mockWebSocketHook.connected = true;
    });

    rerender();

    expect(result.current.isConnected).toBe(true);
  });

  it('should handle terminal data flow correctly', async () => {
    const mockOnData = jest.fn();
    let eventHandlers: { [key: string]: Function } = {};

    // Mock event registration
    mockWebSocketHook.on.mockImplementation((event, handler) => {
      eventHandlers[event] = handler;
    });

    const { result } = renderHook(() => useTerminal({
      sessionId: 'data-flow-session',
      onData: mockOnData,
    }));

    // Verify event handlers were registered
    expect(mockWebSocketHook.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
    expect(mockWebSocketHook.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
    expect(mockWebSocketHook.on).toHaveBeenCalledWith('connection-change', expect.any(Function));

    // Test that terminal operations work
    expect(() => {
      result.current.writeToTerminal('test output');
    }).not.toThrow();
  });

  it('should handle multiple terminal sessions independently', async () => {
    const { result: terminal1 } = renderHook(() => useTerminal({
      sessionId: 'session-1',
    }));

    const { result: terminal2 } = renderHook(() => useTerminal({
      sessionId: 'session-2',
    }));

    // Both terminals should be independent
    expect(terminal1.current.isConnected).toBe(true);
    expect(terminal2.current.isConnected).toBe(true);

    // Operations on one shouldn't affect the other
    act(() => {
      terminal1.current.writeToTerminal('session 1 data');
    });

    act(() => {
      terminal2.current.writeToTerminal('session 2 data');
    });

    // Each should maintain its own state
    expect(terminal1.current.terminalRef).not.toBe(terminal2.current.terminalRef);
  });

  it('should handle error scenarios gracefully', async () => {
    // Set up error conditions
    mockWebSocketHook.isConnected = false;
    mockWebSocketHook.connected = false;
    mockWebSocketHook.sendData.mockImplementation(() => {
      throw new Error('Send failed');
    });

    const { result } = renderHook(() => useTerminal({
      sessionId: 'error-session',
    }));

    // Should handle connection errors gracefully
    expect(result.current.isConnected).toBe(false);

    // Local terminal operations should still work
    expect(() => {
      result.current.clearTerminal();
      result.current.focusTerminal();
      result.current.fitTerminal();
    }).not.toThrow();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });
});