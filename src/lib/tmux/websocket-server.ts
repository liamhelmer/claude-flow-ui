/**
 * Tmux WebSocket Server
 * Provides WebSocket interface for tmux session management
 */

import { Server as SocketIOServer } from 'socket.io';
import { Server as HTTPServer } from 'http';
import TmuxSessionManager, { TmuxSession } from './session-manager';

export interface TmuxWebSocketServerOptions {
  port?: number;
  path?: string;
  cors?: {
    origin: string | string[];
    credentials?: boolean;
  };
}

export class TmuxWebSocketServer {
  private io: SocketIOServer;
  private sessionManager: TmuxSessionManager;
  private activeSessions: Map<string, string> = new Map(); // socketId -> sessionId

  constructor(
    httpServer: HTTPServer, 
    options: TmuxWebSocketServerOptions = {}
  ) {
    this.sessionManager = new TmuxSessionManager();
    
    this.io = new SocketIOServer(httpServer, {
      path: options.path || '/socket.io',
      cors: options.cors || {
        origin: "*",
        credentials: true
      }
    });

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.io.on('connection', (socket) => {
      console.log(`Client connected: ${socket.id}`);

      // Handle session creation
      socket.on('create-session', async (data, callback) => {
        try {
          const session = await this.sessionManager.createSession(data?.name);
          this.activeSessions.set(socket.id, session.id);
          
          socket.join(`session:${session.id}`);
          
          if (callback) {
            callback({ success: true, session });
          }
          
          socket.emit('session-created', session);
        } catch (error) {
          console.error('Error creating session:', error);
          if (callback) {
            callback({ 
              success: false, 
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }
      });

      // Handle session destruction
      socket.on('destroy-session', async (sessionId, callback) => {
        try {
          const success = await this.sessionManager.destroySession(sessionId);
          
          if (success) {
            this.activeSessions.delete(socket.id);
            socket.leave(`session:${sessionId}`);
            socket.emit('session-destroyed', { sessionId });
          }
          
          if (callback) {
            callback({ success });
          }
        } catch (error) {
          console.error('Error destroying session:', error);
          if (callback) {
            callback({ 
              success: false, 
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }
      });

      // Handle command sending
      socket.on('send-command', async (data, callback) => {
        try {
          const { sessionId, command } = data;
          const success = await this.sessionManager.sendCommand(sessionId, command);
          
          if (success) {
            // Broadcast to all clients in the session
            this.io.to(`session:${sessionId}`).emit('command-output', {
              sessionId,
              command,
              timestamp: new Date()
            });
          }
          
          if (callback) {
            callback({ success });
          }
        } catch (error) {
          console.error('Error sending command:', error);
          if (callback) {
            callback({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
          }
        }
      });

      // Handle session resize
      socket.on('resize-session', async (data, callback) => {
        try {
          const { sessionId, width, height } = data;
          const success = await this.sessionManager.resizeSession(sessionId, width, height);
          
          if (callback) {
            callback({ success });
          }
        } catch (error) {
          console.error('Error resizing session:', error);
          if (callback) {
            callback({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
          }
        }
      });

      // Handle session list request
      socket.on('list-sessions', (callback) => {
        try {
          const sessions = this.sessionManager.listSessions();
          if (callback) {
            callback({ success: true, sessions });
          }
        } catch (error) {
          console.error('Error listing sessions:', error);
          if (callback) {
            callback({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
          }
        }
      });

      // Handle session join
      socket.on('join-session', (sessionId, callback) => {
        try {
          const session = this.sessionManager.getSession(sessionId);
          if (session) {
            socket.join(`session:${sessionId}`);
            this.activeSessions.set(socket.id, sessionId);
            
            if (callback) {
              callback({ success: true, session });
            }
          } else {
            if (callback) {
              callback({ success: false, error: 'Session not found' });
            }
          }
        } catch (error) {
          console.error('Error joining session:', error);
          if (callback) {
            callback({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
          }
        }
      });

      // Handle disconnect
      socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`);
        const sessionId = this.activeSessions.get(socket.id);
        if (sessionId) {
          socket.leave(`session:${sessionId}`);
          this.activeSessions.delete(socket.id);
        }
      });

      // Handle ping/pong for connection health
      socket.on('ping', (callback) => {
        if (callback) {
          callback({ pong: true, timestamp: Date.now() });
        }
      });
    });

    // Set up session manager event forwarding
    this.sessionManager.on('session:created', (session: TmuxSession) => {
      this.io.emit('session-created', session);
    });

    this.sessionManager.on('session:destroyed', (session: TmuxSession) => {
      this.io.emit('session-destroyed', { sessionId: session.id });
    });

    this.sessionManager.on('command:sent', (data: any) => {
      this.io.to(`session:${data.sessionId}`).emit('command-executed', data);
    });

    this.sessionManager.on('activity:updated', (data: any) => {
      this.io.to(`session:${data.sessionId}`).emit('activity-update', data);
    });
  }

  /**
   * Get connected clients count
   */
  getConnectedClientsCount(): number {
    return this.io.sockets.sockets.size;
  }

  /**
   * Get active sessions count
   */
  getActiveSessionsCount(): number {
    return this.sessionManager.listSessions().length;
  }

  /**
   * Broadcast message to all clients
   */
  broadcast(event: string, data?: any): void {
    this.io.emit(event, data);
  }

  /**
   * Send message to specific session
   */
  sendToSession(sessionId: string, event: string, data?: any): void {
    this.io.to(`session:${sessionId}`).emit(event, data);
  }

  /**
   * Cleanup and close server
   */
  close(): void {
    this.sessionManager.cleanup();
    this.io.close();
  }
}

export default TmuxWebSocketServer;