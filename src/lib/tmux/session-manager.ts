/**
 * Tmux Session Manager
 * Handles tmux session creation, management, and monitoring
 */

export interface TmuxSession {
  id: string;
  name: string;
  created: Date;
  lastActivity: Date;
  pids: number[];
  windowCount: number;
  status: 'active' | 'inactive' | 'suspended';
}

export interface TmuxWindow {
  id: string;
  sessionId: string;
  name: string;
  index: number;
  isActive: boolean;
  panes: TmuxPane[];
}

export interface TmuxPane {
  id: string;
  windowId: string;
  index: number;
  isActive: boolean;
  command?: string;
  pid?: number;
}

export class TmuxSessionManager {
  private sessions: Map<string, TmuxSession> = new Map();
  private windows: Map<string, TmuxWindow> = new Map();
  private eventListeners: Map<string, Function[]> = new Map();

  constructor() {
    this.initializeManager();
  }

  private initializeManager() {
    // Initialize tmux session management
    console.log('Tmux Session Manager initialized');
  }

  /**
   * Create a new tmux session
   */
  async createSession(name?: string): Promise<TmuxSession> {
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const sessionName = name || `terminal_${this.sessions.size + 1}`;

    const session: TmuxSession = {
      id: sessionId,
      name: sessionName,
      created: new Date(),
      lastActivity: new Date(),
      pids: [],
      windowCount: 1,
      status: 'active'
    };

    this.sessions.set(sessionId, session);
    this.emit('session:created', session);

    return session;
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): TmuxSession | null {
    return this.sessions.get(sessionId) || null;
  }

  /**
   * List all sessions
   */
  listSessions(): TmuxSession[] {
    return Array.from(this.sessions.values());
  }

  /**
   * Destroy a session
   */
  async destroySession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    this.sessions.delete(sessionId);
    this.emit('session:destroyed', session);
    return true;
  }

  /**
   * Create a new window in a session
   */
  async createWindow(sessionId: string, name?: string): Promise<TmuxWindow | null> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }

    const windowId = `window_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const windowName = name || `window_${session.windowCount + 1}`;

    const window: TmuxWindow = {
      id: windowId,
      sessionId,
      name: windowName,
      index: session.windowCount,
      isActive: true,
      panes: []
    };

    session.windowCount++;
    this.windows.set(windowId, window);
    this.emit('window:created', window);

    return window;
  }

  /**
   * Send command to session
   */
  async sendCommand(sessionId: string, command: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    session.lastActivity = new Date();
    this.emit('command:sent', { sessionId, command });
    return true;
  }

  /**
   * Resize session
   */
  async resizeSession(sessionId: string, width: number, height: number): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    this.emit('session:resized', { sessionId, width, height });
    return true;
  }

  /**
   * Get session status
   */
  getSessionStatus(sessionId: string): string | null {
    const session = this.sessions.get(sessionId);
    return session ? session.status : null;
  }

  /**
   * Update session activity
   */
  updateActivity(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastActivity = new Date();
      this.emit('activity:updated', { sessionId, timestamp: session.lastActivity });
    }
  }

  /**
   * Event handling
   */
  on(event: string, listener: Function): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)!.push(listener);
  }

  off(event: string, listener: Function): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  private emit(event: string, data?: any): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.forEach(listener => {
        try {
          listener(data);
        } catch (error) {
          console.error(`Error in event listener for ${event}:`, error);
        }
      });
    }
  }

  /**
   * Cleanup all resources
   */
  cleanup(): void {
    this.sessions.clear();
    this.windows.clear();
    this.eventListeners.clear();
  }
}

export default TmuxSessionManager;