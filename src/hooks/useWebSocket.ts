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
      console.debug(`[WebSocket] 📤 Sending data to session ${sessionId}: ${JSON.stringify(data)}`);
      try {
        wsClient.send('data', { sessionId, data, timestamp: Date.now() });
      } catch (error) {
        console.error('[WebSocket] ❌ Failed to send data:', error);
      }
    } else {
      console.warn('WebSocket not connected, cannot send data - attempting reconnection');
      // ENHANCED FIX: More robust reconnection with queue
      if (!wsClient.connecting) {
        connect().then(() => {
          if (wsClient.connected) {
            console.debug('[WebSocket] ✅ Reconnected, resending data');
            try {
              wsClient.send('data', { sessionId, data, timestamp: Date.now() });
            } catch (error) {
              console.error('[WebSocket] ❌ Failed to send data after reconnect:', error);
            }
          }
        }).catch(err => {
          console.error('[WebSocket] ❌ Failed to reconnect for data send:', err);
        });
      } else {
        console.debug('[WebSocket] 🔄 Connection in progress, data send will be queued');
      }
    }
  }, [connect]);

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

  // Terminal config is now fetched via HTTP API, not WebSocket

  const switchSession = useCallback((sessionId: string) => {
    if (wsClient.connected) {
      console.debug(`[useWebSocket] Switching to session: ${sessionId}`);
      wsClient.send('switch-session', { targetSessionId: sessionId });
    } else {
      console.warn('WebSocket not connected, cannot switch session');
    }
  }, []);

  // Production-safe connection management
  useEffect(() => {
    console.debug('[useWebSocket] Hook mounted, waiting for explicit connect call');

    return () => {
      console.debug('[useWebSocket] Unmounting...');
      // PRODUCTION FIX: Only disconnect if this is the last component using the WebSocket
      // In production, aggressive disconnection breaks terminal switching
      if (process.env.NODE_ENV === 'production') {
        // Use a delay to allow terminal switching without disconnection
        const disconnectTimer = setTimeout(() => {
          // Only disconnect if no other terminals are using the connection
          if (wsClient.connected && !document.querySelector('.terminal-container:not(.unmounting)')) {
            console.debug('[useWebSocket] No active terminals found, safe to disconnect');
            disconnect();
          } else {
            console.debug('[useWebSocket] Other terminals active, preserving connection');
          }
        }, 100);

        // Store the timer so it can be cancelled if another terminal mounts quickly
        (wsClient as any)._pendingDisconnect = disconnectTimer;
      }
    };
  }, [disconnect]);

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
    switchSession,
    on: (event: string, callback: (data: any) => void) => {
      const isEssentialEvent = ['terminal-data', 'connection-change', 'terminal-error'].includes(event);
      if (process.env.NODE_ENV === 'development' || isEssentialEvent) {
        console.debug(`[useWebSocket] 🔧 Registering listener for event: ${event}`);
      }

      if (wsClient.on) {
        // ENHANCED FIX: Wrap callback with error handling for streaming stability
        const wrappedCallback = (data: any) => {
          try {
            callback(data);
          } catch (error) {
            console.error(`[useWebSocket] ❌ Error in callback for ${event}:`, error);
          }
        };

        wsClient.on(event, wrappedCallback);
        if (process.env.NODE_ENV === 'development' || isEssentialEvent) {
          console.debug(`[useWebSocket] 🔧 Listener registered successfully for: ${event}`);
        }
      } else {
        console.warn(`[useWebSocket] ⚠️ wsClient.on is not available for event: ${event}`);
      }
    },
    off: (event: string, callback: (data: any) => void) => {
      // PRODUCTION FIX: Add essential logging for production debugging
      const isEssentialEvent = ['terminal-data', 'connection-change', 'terminal-error'].includes(event);
      if (process.env.NODE_ENV === 'development' || isEssentialEvent) {
        console.debug(`[useWebSocket] 🔧 Removing listener for event: ${event}`);
      }
      if (wsClient.off) {
        wsClient.off(event, callback);
      } else {
        // PRODUCTION FIX: Always warn about missing event cleanup
        console.warn(`[useWebSocket] ⚠️ wsClient.off is not available for event: ${event}`);
      }
    },
  };
};