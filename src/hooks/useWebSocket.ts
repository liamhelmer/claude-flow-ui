import { useEffect, useCallback, useRef } from 'react';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';
import type { WebSocketMessage } from '@/types';

export const useWebSocket = () => {
  const { setError, setLoading } = useAppStore();
  const isConnecting = useRef(false);

  const connect = useCallback(async () => {
    if (isConnecting.current || wsClient.connected) {
      console.debug('[useWebSocket] Already connected or connecting');
      return;
    }

    isConnecting.current = true;
    setLoading(true);

    try {
      console.debug('[useWebSocket] Attempting to connect...');
      await wsClient.connect();
      console.debug('[useWebSocket] Connected successfully');
      setError(null);
    } catch (error) {
      console.error('[useWebSocket] Failed to connect to WebSocket:', error);
      setError('Failed to connect to terminal server');
    } finally {
      setLoading(false);
      isConnecting.current = false;
    }
  }, [setError, setLoading]);

  const disconnect = useCallback(() => {
    wsClient.disconnect();
  }, []);

  const sendMessage = useCallback((message: WebSocketMessage) => {
    if (wsClient.connected) {
      wsClient.sendMessage(message);
    } else {
      console.warn('WebSocket not connected, message not sent:', message);
    }
  }, []);

  const sendData = useCallback((sessionId: string, data: string) => {
    if (wsClient.connected) {
      wsClient.send('data', { sessionId, data });
    } else {
      console.warn('WebSocket not connected, cannot send data');
    }
  }, []);

  const resizeTerminal = useCallback((sessionId: string, cols: number, rows: number) => {
    if (wsClient.connected) {
      wsClient.send('resize', { sessionId, cols, rows });
    } else {
      console.warn('WebSocket not connected, cannot resize terminal');
    }
  }, []);

  const createSession = useCallback(() => {
    if (wsClient.connected) {
      wsClient.send('create', {});
    } else {
      console.warn('WebSocket not connected, cannot create session');
    }
  }, []);

  const destroySession = useCallback((sessionId: string) => {
    if (wsClient.connected) {
      wsClient.send('destroy', { sessionId });
    } else {
      console.warn('WebSocket not connected, cannot destroy session');
    }
  }, []);

  const listSessions = useCallback(() => {
    if (wsClient.connected) {
      wsClient.send('list', {});
    } else {
      console.warn('WebSocket not connected, cannot list sessions');
    }
  }, []);

  const requestTerminalConfig = useCallback((sessionId: string) => {
    if (wsClient.connected) {
      console.debug(`[useWebSocket] Requesting terminal config for session: ${sessionId}`);
      wsClient.send('request-config', { sessionId });
    } else {
      console.warn('WebSocket not connected, cannot request terminal config');
    }
  }, []);

  const requestTerminalConfigAsync = useCallback((sessionId: string, timeoutMs: number = 5000): Promise<any> => {
    console.debug(`[useWebSocket] Requesting terminal config async for session: ${sessionId}`);
    return wsClient.requestTerminalConfigAsync(sessionId, timeoutMs);
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    // Delay connection to avoid StrictMode double-mount issues
    const timer = setTimeout(() => {
      console.debug('[useWebSocket] Mounting, attempting to connect...');
      connect();
    }, 100);

    return () => {
      clearTimeout(timer);
      console.debug('[useWebSocket] Unmounting...');
      // Don't disconnect on cleanup in development
      if (process.env.NODE_ENV === 'production') {
        disconnect();
      }
    };
  }, [connect, disconnect]);

  return {
    connected: wsClient.connected,
    connecting: wsClient.connecting,
    isConnected: wsClient.connected, // Alias for compatibility with monitoring panels
    connect,
    disconnect,
    sendMessage,
    sendData,
    resizeTerminal,
    createSession,
    destroySession,
    listSessions,
    requestTerminalConfig,
    requestTerminalConfigAsync,
    on: (event: string, callback: (data: any) => void) => {
      if (process.env.NODE_ENV === 'development') {
        console.debug(`[useWebSocket] 🔧 DEBUG: Registering listener for event: ${event}`);
      }
      if (wsClient.on) {
        wsClient.on(event, callback);
        if (process.env.NODE_ENV === 'development') {
          console.debug(`[useWebSocket] 🔧 DEBUG: Listener registered successfully for: ${event}`);
        }
      } else if (process.env.NODE_ENV === 'development') {
        console.warn(`[useWebSocket] ⚠️ wsClient.on is not available for event: ${event}`);
      }
    },
    off: (event: string, callback: (data: any) => void) => {
      if (process.env.NODE_ENV === 'development') {
        console.debug(`[useWebSocket] 🔧 DEBUG: Removing listener for event: ${event}`);
      }
      if (wsClient.off) {
        wsClient.off(event, callback);
      } else if (process.env.NODE_ENV === 'development') {
        console.warn(`[useWebSocket] ⚠️ wsClient.off is not available for event: ${event}`);
      }
    },
  };
};