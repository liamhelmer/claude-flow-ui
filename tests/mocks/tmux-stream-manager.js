/**
 * Mock implementation of TmuxStreamManager
 * Provides comprehensive mocking for testing
 */

class MockTmuxStreamManager {
  constructor() {
    this.sessions = new Map();
    this.clientStreams = new Map();
    this.disconnectTimers = new Map();
    this.DISCONNECT_GRACE_PERIOD = 1000; // Shorter for testing
    this.STREAM_INTERVAL = 10; // Faster for testing
    this.platformCompat = {
      getTmuxCommandAdjustments: jest.fn(() => ({}))
    };
    this.captureStrategies = null;
    this.platformAdjustments = {};
  }

  /**
   * Mock session creation
   */
  async createSession(sessionName = null, initialCommand = null) {
    const name = sessionName || `terminal-${Date.now()}`;
    const sessionId = `session-${name}-${Date.now()}`;
    const socketPath = `/tmp/tmux-${sessionId}`;

    const session = {
      sessionId,
      sessionName: name,
      socketPath,
      command: initialCommand || 'bash',
      status: 'active',
      created: new Date().toISOString(),
      clients: new Set(),
      pid: Math.floor(Math.random() * 10000) + 1000
    };

    this.sessions.set(sessionId, session);

    // Simulate session startup delay
    await new Promise(resolve => setTimeout(resolve, 10));

    return session;
  }

  /**
   * Mock client attachment
   */
  async attachClient(sessionId, clientId, options = {}) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    const clientInfo = {
      clientId,
      sessionId,
      attachedAt: new Date().toISOString(),
      ...options
    };

    this.clientStreams.set(clientId, clientInfo);
    session.clients.add(clientId);

    // Simulate attachment delay
    await new Promise(resolve => setTimeout(resolve, 5));

    return clientInfo;
  }

  /**
   * Mock client detachment
   */
  async detachClient(clientId, graceful = true) {
    const clientInfo = this.clientStreams.get(clientId);
    if (!clientInfo) {
      return false;
    }

    const session = this.sessions.get(clientInfo.sessionId);
    if (session) {
      session.clients.delete(clientId);
    }

    this.clientStreams.delete(clientId);

    // Clear any disconnect timers
    const timer = this.disconnectTimers.get(clientId);
    if (timer) {
      clearTimeout(timer);
      this.disconnectTimers.delete(clientId);
    }

    return true;
  }

  /**
   * Mock session termination
   */
  async killSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    // Detach all clients
    const clientPromises = Array.from(session.clients).map(clientId =>
      this.detachClient(clientId)
    );
    await Promise.all(clientPromises);

    // Remove session
    this.sessions.delete(sessionId);

    return true;
  }

  /**
   * Mock session listing
   */
  async listSessions() {
    return Array.from(this.sessions.values()).map(session => ({
      sessionId: session.sessionId,
      sessionName: session.sessionName,
      status: session.status,
      clientCount: session.clients.size,
      created: session.created
    }));
  }

  /**
   * Mock command execution
   */
  async executeCommand(sessionId, command) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    // Simulate command execution
    await new Promise(resolve => setTimeout(resolve, 5));

    return {
      sessionId,
      command,
      output: `Mock output for: ${command}`,
      exitCode: 0,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Mock session capture
   */
  async captureSession(sessionId, options = {}) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    const mockContent = `Mock session capture for ${sessionId}\n` +
      `Command: ${session.command}\n` +
      `Status: ${session.status}\n` +
      `Clients: ${session.clients.size}\n`;

    return {
      sessionId,
      content: mockContent,
      timestamp: new Date().toISOString(),
      ...options
    };
  }

  /**
   * Mock session resize
   */
  async resizeSession(sessionId, cols, rows) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    session.cols = cols;
    session.rows = rows;

    return {
      sessionId,
      cols,
      rows,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Mock session status check
   */
  async getSessionStatus(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }

    return {
      sessionId,
      status: session.status,
      uptime: Date.now() - new Date(session.created).getTime(),
      clientCount: session.clients.size,
      memoryUsage: Math.floor(Math.random() * 100) + 10, // MB
      cpuUsage: Math.random() * 100 // percentage
    };
  }

  /**
   * Mock cleanup
   */
  async cleanup() {
    // Kill all sessions
    const sessionIds = Array.from(this.sessions.keys());
    const killPromises = sessionIds.map(id => this.killSession(id));
    await Promise.all(killPromises);

    // Clear all timers
    this.disconnectTimers.forEach(timer => clearTimeout(timer));
    this.disconnectTimers.clear();

    return true;
  }

  /**
   * Mock error simulation
   */
  simulateError(type = 'general', sessionId = null) {
    switch (type) {
      case 'session_not_found':
        throw new Error(`Session ${sessionId || 'unknown'} not found`);
      case 'connection_failed':
        throw new Error('Failed to connect to tmux session');
      case 'permission_denied':
        throw new Error('Permission denied accessing session');
      case 'timeout':
        throw new Error('Operation timed out');
      default:
        throw new Error('Mock error for testing');
    }
  }
}

// Export both the class and a factory function
module.exports = MockTmuxStreamManager;
module.exports.createMockManager = () => new MockTmuxStreamManager();