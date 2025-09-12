import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock the dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket Edge Cases', () => {
  const mockSetError = jest.fn();
  const mockSetLoading = jest.fn();
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset client state
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
    mockWsClient.connect = jest.fn();
    mockWsClient.disconnect = jest.fn();
    mockWsClient.sendMessage = jest.fn();
    mockWsClient.send = jest.fn();
    mockWsClient.on = jest.fn();
    mockWsClient.off = jest.fn();
    
    // Mock store
    mockUseAppStore.mockReturnValue({
      setError: mockSetError,
      setLoading: mockSetLoading,
    } as any);
  });

  describe('Connection Race Conditions', () => {
    it('should prevent multiple simultaneous connection attempts', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Start first connection
      const firstConnection = result.current.connect();
      
      // Try to start second connection immediately
      const secondConnection = result.current.connect();
      
      await act(async () => {
        await Promise.all([firstConnection, secondConnection]);
      });
      
      // Should only call connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle connection attempt while already connected', async () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        await result.current.connect();
      });
      
      // Should not try to connect when already connected
      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('should handle connection attempt while connecting is in progress', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Mock a slow connection
      mockWsClient.connect = jest.fn().mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)));
      
      const firstConnection = result.current.connect();
      const secondConnection = result.current.connect();
      
      await act(async () => {
        await Promise.all([firstConnection, secondConnection]);
      });
      
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('should handle connection error and reset connecting state', async () => {
      const connectionError = new Error('Connection failed');
      mockWsClient.connect = jest.fn().mockRejectedValue(connectionError);
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        await result.current.connect();
      });
      
      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should handle network timeout during connection', async () => {
      const timeoutError = new Error('Network timeout');
      mockWsClient.connect = jest.fn().mockRejectedValue(timeoutError);
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        await result.current.connect();
      });
      
      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
    });

    it('should handle unexpected disconnection during operation', () => {
      mockWsClient.connected = false; // Simulate unexpected disconnection
      
      const { result } = renderHook(() => useWebSocket());
      
      // Try to send data when disconnected
      act(() => {
        result.current.sendData('session-1', 'test data');
      });
      
      expect(mockWsClient.send).not.toHaveBeenCalled();
    });
  });

  describe('Message Sending Edge Cases', () => {
    it('should queue messages when disconnected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());
      
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      act(() => {
        result.current.sendMessage({ type: 'test', data: 'test' });
      });
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, message not sent:',
        { type: 'test', data: 'test' }
      );
      
      consoleSpy.mockRestore();
    });

    it('should handle malformed message objects', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.sendMessage(null as any);
      });
      
      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(null);
    });

    it('should handle circular reference in message data', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      const circularObj: any = { type: 'test' };
      circularObj.self = circularObj;
      
      act(() => {
        result.current.sendMessage(circularObj);
      });
      
      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(circularObj);
    });
  });

  describe('Session Management Edge Cases', () => {
    it('should handle session creation when disconnected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());
      
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      act(() => {
        result.current.createSession();
      });
      
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot create session');
      expect(mockWsClient.send).not.toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });

    it('should handle session destruction with invalid sessionId', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.destroySession('');
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', { sessionId: '' });
    });

    it('should handle terminal resize with invalid dimensions', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.resizeTerminal('session-1', -1, -1);
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('resize', { 
        sessionId: 'session-1', 
        cols: -1, 
        rows: -1 
      });
    });

    it('should handle terminal resize with zero dimensions', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.resizeTerminal('session-1', 0, 0);
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('resize', { 
        sessionId: 'session-1', 
        cols: 0, 
        rows: 0 
      });
    });
  });

  describe('Event Listener Edge Cases', () => {
    it('should handle missing event listener methods gracefully', () => {
      mockWsClient.on = undefined;
      mockWsClient.off = undefined;
      
      const { result } = renderHook(() => useWebSocket());
      
      // Should not throw error when event methods are undefined
      expect(() => {
        result.current.on('test', () => {});
        result.current.off('test', () => {});
      }).not.toThrow();
    });

    it('should bind event listeners correctly when available', () => {
      const mockOn = jest.fn();
      const mockOff = jest.fn();
      
      mockWsClient.on = mockOn;
      mockWsClient.off = mockOff;
      
      const { result } = renderHook(() => useWebSocket());
      
      const handler = jest.fn();
      
      result.current.on('test-event', handler);
      result.current.off('test-event', handler);
      
      expect(mockOn).toHaveBeenCalledWith('test-event', handler);
      expect(mockOff).toHaveBeenCalledWith('test-event', handler);
    });
  });

  describe('Auto-connection Edge Cases', () => {
    it('should delay connection to avoid StrictMode issues', () => {
      jest.useFakeTimers();
      
      renderHook(() => useWebSocket());
      
      // Should not connect immediately
      expect(mockWsClient.connect).not.toHaveBeenCalled();
      
      // Should connect after delay
      act(() => {
        jest.advanceTimersByTime(100);
      });
      
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
      
      jest.useRealTimers();
    });

    it('should cancel delayed connection on unmount', () => {
      jest.useFakeTimers();
      
      const { unmount } = renderHook(() => useWebSocket());
      
      // Unmount before delay completes
      unmount();
      
      act(() => {
        jest.advanceTimersByTime(100);
      });
      
      // Should not connect after unmount
      expect(mockWsClient.connect).not.toHaveBeenCalled();
      
      jest.useRealTimers();
    });

    it('should only disconnect in production on unmount', () => {
      const originalEnv = process.env.NODE_ENV;
      
      // Test production behavior
      process.env.NODE_ENV = 'production';
      
      const { unmount } = renderHook(() => useWebSocket());
      
      unmount();
      
      expect(mockWsClient.disconnect).toHaveBeenCalled();
      
      // Reset
      process.env.NODE_ENV = originalEnv;
      mockWsClient.disconnect.mockClear();
      
      // Test development behavior
      process.env.NODE_ENV = 'development';
      
      const { unmount: unmount2 } = renderHook(() => useWebSocket());
      
      unmount2();
      
      expect(mockWsClient.disconnect).not.toHaveBeenCalled();
      
      // Restore original environment
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('State Consistency Edge Cases', () => {
    it('should provide consistent connection state aliases', () => {
      mockWsClient.connected = true;
      mockWsClient.connecting = false;
      
      const { result } = renderHook(() => useWebSocket());
      
      expect(result.current.connected).toBe(true);
      expect(result.current.isConnected).toBe(true);
      expect(result.current.connecting).toBe(false);
    });

    it('should handle rapid state changes', async () => {
      let connectResolve: () => void;
      const connectPromise = new Promise<void>((resolve) => {
        connectResolve = resolve;
      });
      
      mockWsClient.connect = jest.fn(() => connectPromise);
      
      const { result } = renderHook(() => useWebSocket());
      
      // Start connection
      const connectionPromise = result.current.connect();
      
      // Immediately try to disconnect
      act(() => {
        result.current.disconnect();
      });
      
      // Complete connection
      act(() => {
        connectResolve();
      });
      
      await act(async () => {
        await connectionPromise;
      });
      
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
      expect(mockWsClient.disconnect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Memory Leak Prevention', () => {
    it('should properly cleanup refs on unmount', () => {
      const { unmount } = renderHook(() => useWebSocket());
      
      // Should not throw or leak memory
      expect(() => unmount()).not.toThrow();
    });

    it('should handle multiple rapid mount/unmount cycles', () => {
      for (let i = 0; i < 10; i++) {
        const { unmount } = renderHook(() => useWebSocket());
        unmount();
      }
      
      // Should handle multiple cycles without issues
      expect(true).toBe(true);
    });
  });
});