/**
 * Terminal-WebSocket Integration Tests
 * Tests the integration between terminal components and WebSocket communication
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import Terminal from '@/components/terminal/Terminal';
import WebSocketClient from '@/lib/websocket/client';

// Mock xterm.js
const mockTerminal = {
  open: jest.fn(),
  write: jest.fn(),
  writeln: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  blur: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  loadAddon: jest.fn(),
  resize: jest.fn(),
  cols: 80,
  rows: 24,
  element: document.createElement('div')
};

const mockFitAddon = {
  fit: jest.fn(),
  proposeDimensions: jest.fn(() => ({ cols: 80, rows: 24 }))
};

jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => mockTerminal)
}));

jest.mock('@xterm/addon-fit', () => ({
  FitAddon: jest.fn(() => mockFitAddon)
}));

// Mock WebSocket client
jest.mock('@/lib/websocket/client', () => {
  const mockClient = {
    connect: jest.fn(() => Promise.resolve()),
    disconnect: jest.fn(),
    send: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    connected: true,
    connecting: false
  };

  return {
    __esModule: true,
    default: jest.fn(() => mockClient),
    wsClient: mockClient
  };
});

describe('Terminal-WebSocket Integration', () => {
  let httpServer: any;
  let io: SocketIOServer;
  let mockWsClient: any;
  let serverPort: number;

  beforeAll((done) => {
    // Create test WebSocket server
    httpServer = createServer();
    io = new SocketIOServer(httpServer, {
      cors: { origin: "*", methods: ["GET", "POST"] },
      path: '/api/ws'
    });

    httpServer.listen(0, () => {
      serverPort = httpServer.address().port;
      done();
    });

    // Setup server handlers
    io.on('connection', (socket) => {
      socket.on('terminal-input', (data) => {
        socket.emit('terminal-data', {
          sessionId: data.sessionId,
          data: `Response: ${data.input}\r\n`,
          timestamp: Date.now()
        });
      });

      socket.on('create-session', (data) => {
        socket.emit('session-created', {
          sessionId: `session_${Date.now()}`,
          name: data.name || 'default'
        });
      });

      socket.on('resize-terminal', (data) => {
        socket.emit('terminal-resize', {
          sessionId: data.sessionId,
          cols: data.cols,
          rows: data.rows
        });
      });
    });
  });

  afterAll((done) => {
    if (io) io.close();
    if (httpServer) httpServer.close(done);
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockWsClient = require('@/lib/websocket/client').wsClient;

    // Setup mock WebSocket client behavior
    mockWsClient.connect.mockResolvedValue(undefined);
    mockWsClient.connected = true;
    mockWsClient.connecting = false;
  });

  describe('Terminal Component WebSocket Integration', () => {
    it('should establish WebSocket connection on terminal mount', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });
    });

    it('should register WebSocket event listeners for terminal events', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-resize', expect.any(Function));
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
        expect(mockWsClient.on).toHaveBeenCalledWith('connection-change', expect.any(Function));
      });
    });

    it('should send terminal input through WebSocket', async () => {
      const user = userEvent.setup();
      render(<Terminal sessionId="test-session" />);

      // Wait for component to mount and setup
      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });

      // Simulate terminal input by triggering onData callback
      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      act(() => {
        onDataCallback('test input\r');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('terminal-input', {
        sessionId: 'test-session',
        input: 'test input\r'
      });
    });

    it('should handle incoming terminal data and write to xterm', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      // Get the terminal-data event handler
      const terminalDataHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )[1];

      // Simulate incoming terminal data
      act(() => {
        terminalDataHandler({
          sessionId: 'test-session',
          data: 'Hello from server\r\n',
          timestamp: Date.now()
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Hello from server\r\n');
    });

    it('should handle terminal resize events', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-resize', expect.any(Function));
      });

      // Get the terminal-resize event handler
      const resizeHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'terminal-resize'
      )[1];

      // Simulate resize event
      act(() => {
        resizeHandler({
          sessionId: 'test-session',
          cols: 120,
          rows: 40
        });
      });

      expect(mockTerminal.resize).toHaveBeenCalledWith(120, 40);
    });

    it('should send resize events when terminal is resized', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockTerminal.onResize).toHaveBeenCalled();
      });

      // Get the resize callback
      const resizeCallback = mockTerminal.onResize.mock.calls[0][0];

      // Trigger resize
      act(() => {
        resizeCallback({ cols: 100, rows: 30 });
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('resize-terminal', {
        sessionId: 'test-session',
        cols: 100,
        rows: 30
      });
    });
  });

  describe('Multi-Terminal WebSocket Management', () => {
    it('should handle multiple terminals with separate sessions', async () => {
      const { rerender } = render(
        <div>
          <Terminal sessionId="session-1" />
          <Terminal sessionId="session-2" />
        </div>
      );

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });

      // Both terminals should register listeners
      expect(mockWsClient.on).toHaveBeenCalledTimes(8); // 4 events × 2 terminals
    });

    it('should route terminal data to correct terminal instance', async () => {
      const { container } = render(
        <div>
          <Terminal sessionId="session-1" />
          <Terminal sessionId="session-2" />
        </div>
      );

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalled();
      });

      // Get terminal-data handlers for both terminals
      const terminalDataCalls = mockWsClient.on.mock.calls.filter(
        call => call[0] === 'terminal-data'
      );

      expect(terminalDataCalls).toHaveLength(2);

      // Simulate data for session-1
      act(() => {
        terminalDataCalls[0][1]({
          sessionId: 'session-1',
          data: 'Data for session 1',
          timestamp: Date.now()
        });
      });

      // Only first terminal should receive the data
      expect(mockTerminal.write).toHaveBeenCalledWith('Data for session 1');
    });
  });

  describe('WebSocket Error Handling', () => {
    it('should handle WebSocket connection errors', async () => {
      mockWsClient.connect.mockRejectedValue(new Error('Connection failed'));

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });

      // Should handle connection error gracefully
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('should handle terminal errors from server', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      });

      // Get error handler
      const errorHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'terminal-error'
      )[1];

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      // Simulate terminal error
      act(() => {
        errorHandler({
          sessionId: 'test-session',
          error: 'Terminal process crashed',
          code: 1
        });
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Terminal error'),
        expect.any(Object)
      );

      consoleSpy.mockRestore();
    });

    it('should handle connection state changes', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('connection-change', expect.any(Function));
      });

      // Get connection change handler
      const connectionHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'connection-change'
      )[1];

      // Simulate disconnection
      act(() => {
        mockWsClient.connected = false;
        connectionHandler(false);
      });

      // Terminal should show disconnected state
      await waitFor(() => {
        expect(screen.getByText(/disconnected/i)).toBeInTheDocument();
      });
    });
  });

  describe('Terminal Lifecycle Integration', () => {
    it('should cleanup WebSocket listeners on unmount', async () => {
      const { unmount } = render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalled();
      });

      unmount();

      expect(mockWsClient.off).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWsClient.off).toHaveBeenCalledWith('terminal-resize', expect.any(Function));
      expect(mockWsClient.off).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWsClient.off).toHaveBeenCalledWith('connection-change', expect.any(Function));
    });

    it('should handle session ID changes', async () => {
      const { rerender } = render(<Terminal sessionId="session-1" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalled();
      });

      // Change session ID
      rerender(<Terminal sessionId="session-2" />);

      // Should cleanup old listeners and setup new ones
      expect(mockWsClient.off).toHaveBeenCalled();
      expect(mockWsClient.on).toHaveBeenCalledTimes(8); // 4 initial + 4 after rerender
    });
  });

  describe('Real-time Data Flow', () => {
    it('should maintain real-time data streaming', async () => {
      jest.useFakeTimers();

      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      const terminalDataHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )[1];

      // Simulate rapid data streaming
      const messages = Array.from({ length: 10 }, (_, i) => ({
        sessionId: 'test-session',
        data: `Stream data ${i}\r\n`,
        timestamp: Date.now() + i
      }));

      messages.forEach((msg, index) => {
        act(() => {
          jest.advanceTimersByTime(10);
          terminalDataHandler(msg);
        });
      });

      // All messages should be written to terminal
      expect(mockTerminal.write).toHaveBeenCalledTimes(10);
      messages.forEach((msg, index) => {
        expect(mockTerminal.write).toHaveBeenNthCalledWith(index + 1, msg.data);
      });

      jest.useRealTimers();
    });

    it('should handle large data chunks without blocking UI', async () => {
      render(<Terminal sessionId="test-session" />);

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      const terminalDataHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )[1];

      const largeData = 'A'.repeat(10000);

      act(() => {
        terminalDataHandler({
          sessionId: 'test-session',
          data: largeData,
          timestamp: Date.now()
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(largeData);
    });
  });

  describe('Session State Management', () => {
    it('should handle session creation through WebSocket', async () => {
      render(<Terminal />); // No initial session ID

      await waitFor(() => {
        expect(mockWsClient.on).toHaveBeenCalledWith('session-created', expect.any(Function));
      });

      const sessionCreatedHandler = mockWsClient.on.mock.calls.find(
        call => call[0] === 'session-created'
      )[1];

      act(() => {
        sessionCreatedHandler({
          sessionId: 'new-session-123',
          name: 'auto-created-session'
        });
      });

      // Terminal should update with new session ID
      expect(mockWsClient.send).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          sessionId: 'new-session-123'
        })
      );
    });

    it('should maintain session state during reconnection', async () => {
      const { rerender } = render(<Terminal sessionId="persistent-session" />);

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });

      // Simulate disconnection
      mockWsClient.connected = false;

      // Simulate reconnection
      mockWsClient.connected = true;
      rerender(<Terminal sessionId="persistent-session" />);

      // Should attempt to reconnect with same session
      expect(mockWsClient.connect).toHaveBeenCalled();
    });
  });
});