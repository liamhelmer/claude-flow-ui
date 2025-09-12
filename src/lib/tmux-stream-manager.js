/**
 * Streaming Tmux Manager
 * Manages tmux sessions with per-client streaming buffers and automatic reconnection
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { v4: uuidv4 } = require('uuid');

class TmuxStreamManager {
  constructor() {
    this.sessions = new Map(); // sessionId -> session info
    this.clientStreams = new Map(); // clientId -> stream info
    this.disconnectTimers = new Map(); // clientId -> disconnect timer
    this.DISCONNECT_GRACE_PERIOD = 10000; // 10 seconds
    this.STREAM_INTERVAL = 50; // Stream update interval in ms
  }

  /**
   * Create a new tmux session with streaming
   */
  async createSession(sessionName = null, initialCommand = null) {
    const name = sessionName || `terminal-${Date.now()}`;
    const socketPath = path.join(os.tmpdir(), `tmux-${name}.sock`);
    
    // Kill any existing session with same name
    await this.killSession(name).catch(() => {});
    
    // Create new tmux session
    const tmuxArgs = [
      '-S', socketPath,
      'new-session',
      '-d',
      '-s', name,
      '-x', '120',
      '-y', '40'
    ];
    
    if (initialCommand) {
      tmuxArgs.push('-c', process.cwd());
      tmuxArgs.push(initialCommand);
    }
    
    await new Promise((resolve, reject) => {
      const proc = spawn('tmux', tmuxArgs, { stdio: 'pipe' });
      proc.on('exit', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`Failed to create tmux session: ${code}`));
      });
      proc.on('error', reject);
    });
    
    // Set up session info
    const sessionInfo = {
      name,
      socketPath,
      created: Date.now(),
      clients: new Set(),
      historyBuffer: '',
      lastCapture: '',
      streaming: false,
      streamProcess: null
    };
    
    this.sessions.set(name, sessionInfo);
    
    // Start streaming for this session
    this.startSessionStream(name);
    
    console.log(`✅ Created tmux session: ${name}`);
    return { name, socketPath };
  }

  /**
   * Start streaming tmux output for a session
   */
  startSessionStream(sessionName) {
    const session = this.sessions.get(sessionName);
    if (!session || session.streaming) return;
    
    session.streaming = true;
    
    // Use tmux pipe-pane to stream output continuously
    const streamProcess = spawn('tmux', [
      '-S', session.socketPath,
      'pipe-pane',
      '-t', sessionName,
      '-o',
      'cat >> /dev/stdout'
    ], { stdio: 'pipe' });
    
    // Accumulate streamed data
    streamProcess.stdout.on('data', (chunk) => {
      session.historyBuffer += chunk.toString();
      
      // Broadcast to all connected clients for this session
      for (const clientId of session.clients) {
        const clientStream = this.clientStreams.get(clientId);
        if (clientStream && clientStream.callback) {
          clientStream.callback(chunk.toString());
        }
      }
    });
    
    streamProcess.on('error', (err) => {
      console.error(`Stream error for session ${sessionName}:`, err);
      session.streaming = false;
    });
    
    streamProcess.on('exit', () => {
      console.log(`Stream ended for session ${sessionName}`);
      session.streaming = false;
    });
    
    session.streamProcess = streamProcess;
    
    // Also set up periodic capture for full screen state
    const captureInterval = setInterval(async () => {
      if (!this.sessions.has(sessionName)) {
        clearInterval(captureInterval);
        return;
      }
      
      try {
        const capture = await this.captureFullScreen(sessionName, session.socketPath);
        if (capture !== session.lastCapture) {
          session.lastCapture = capture;
          session.historyBuffer = capture; // Update history with latest full state
          
          // Send full update to all clients
          for (const clientId of session.clients) {
            const clientStream = this.clientStreams.get(clientId);
            if (clientStream && clientStream.callback) {
              // Send clear + full content to ensure sync
              clientStream.callback('\x1b[2J\x1b[H' + capture);
            }
          }
        }
      } catch (err) {
        console.error(`Capture error for session ${sessionName}:`, err);
      }
    }, this.STREAM_INTERVAL);
    
    session.captureInterval = captureInterval;
  }

  /**
   * Connect a client to a session stream
   */
  connectClient(clientId, sessionName, callback) {
    const session = this.sessions.get(sessionName);
    if (!session) {
      throw new Error(`Session ${sessionName} not found`);
    }
    
    // Clear any pending disconnect timer
    if (this.disconnectTimers.has(clientId)) {
      clearTimeout(this.disconnectTimers.get(clientId));
      this.disconnectTimers.delete(clientId);
      console.log(`🔄 Client ${clientId} reconnected within grace period`);
    }
    
    // Add client to session
    session.clients.add(clientId);
    
    // Set up client stream
    const clientStream = {
      clientId,
      sessionName,
      callback,
      connected: Date.now(),
      buffer: ''
    };
    
    this.clientStreams.set(clientId, clientStream);
    
    // Send full history immediately
    if (session.historyBuffer) {
      callback('\x1b[2J\x1b[H' + session.historyBuffer);
    }
    
    console.log(`👤 Client ${clientId} connected to session ${sessionName}`);
    
    return {
      sessionName,
      write: (data) => this.sendInput(sessionName, data),
      resize: (cols, rows) => this.resizeSession(sessionName, cols, rows),
      refresh: () => this.refreshClient(clientId),
      disconnect: () => this.disconnectClient(clientId)
    };
  }

  /**
   * Disconnect a client with grace period
   */
  disconnectClient(clientId) {
    const clientStream = this.clientStreams.get(clientId);
    if (!clientStream) return;
    
    console.log(`👋 Client ${clientId} disconnecting, starting ${this.DISCONNECT_GRACE_PERIOD}ms grace period`);
    
    // Start disconnect timer
    const timer = setTimeout(() => {
      // Actually disconnect after grace period
      this.finalDisconnect(clientId);
    }, this.DISCONNECT_GRACE_PERIOD);
    
    this.disconnectTimers.set(clientId, timer);
  }

  /**
   * Final disconnect after grace period
   */
  finalDisconnect(clientId) {
    const clientStream = this.clientStreams.get(clientId);
    if (!clientStream) return;
    
    const session = this.sessions.get(clientStream.sessionName);
    if (session) {
      session.clients.delete(clientId);
      
      // If no more clients, consider stopping the stream
      if (session.clients.size === 0) {
        console.log(`📍 No more clients for session ${clientStream.sessionName}, keeping session alive`);
        // We keep the session alive but could stop streaming to save resources
        if (session.captureInterval) {
          clearInterval(session.captureInterval);
          session.captureInterval = null;
        }
        if (session.streamProcess) {
          session.streamProcess.kill();
          session.streamProcess = null;
        }
        session.streaming = false;
      }
    }
    
    this.clientStreams.delete(clientId);
    this.disconnectTimers.delete(clientId);
    
    console.log(`❌ Client ${clientId} fully disconnected`);
  }

  /**
   * Refresh client by reconnecting to a new session
   */
  async refreshClient(clientId) {
    const clientStream = this.clientStreams.get(clientId);
    if (!clientStream) return;
    
    const oldSessionName = clientStream.sessionName;
    const oldSession = this.sessions.get(oldSessionName);
    
    // Disconnect from old session
    if (oldSession) {
      oldSession.clients.delete(clientId);
    }
    
    // Create new session
    const newSession = await this.createSession();
    
    // Reconnect client to new session
    this.connectClient(clientId, newSession.name, clientStream.callback);
    
    console.log(`🔄 Client ${clientId} refreshed from ${oldSessionName} to ${newSession.name}`);
    
    // Clean up old session if no clients
    if (oldSession && oldSession.clients.size === 0) {
      await this.cleanupSession(oldSessionName);
    }
    
    return newSession;
  }

  /**
   * Send input to a tmux session
   */
  sendInput(sessionName, data) {
    const session = this.sessions.get(sessionName);
    if (!session) return;
    
    spawn('tmux', [
      '-S', session.socketPath,
      'send-keys',
      '-t', sessionName,
      '-l',
      data
    ], { stdio: 'ignore' });
  }

  /**
   * Resize a tmux session
   */
  resizeSession(sessionName, cols, rows) {
    const session = this.sessions.get(sessionName);
    if (!session) return;
    
    spawn('tmux', [
      '-S', session.socketPath,
      'resize-window',
      '-t', sessionName,
      '-x', cols.toString(),
      '-y', rows.toString()
    ], { stdio: 'ignore' });
  }

  /**
   * Capture full screen content from tmux
   */
  async captureFullScreen(sessionName, socketPath) {
    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-S', '-',    // Start from beginning of history
        '-E', '-',    // End at end of history
        '-e',         // Include escape sequences
        '-p'          // Print to stdout
      ], { stdio: 'pipe' });

      let output = '';
      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          resolve(output);
        } else {
          reject(new Error(`Failed to capture screen: ${code}`));
        }
      });

      tmux.on('error', reject);
    });
  }

  /**
   * Kill a tmux session
   */
  async killSession(sessionName) {
    const session = this.sessions.get(sessionName);
    if (!session) return;
    
    // Stop streaming
    if (session.captureInterval) {
      clearInterval(session.captureInterval);
    }
    if (session.streamProcess) {
      session.streamProcess.kill();
    }
    
    // Kill tmux session
    await new Promise((resolve) => {
      const proc = spawn('tmux', [
        '-S', session.socketPath,
        'kill-session',
        '-t', sessionName
      ], { stdio: 'pipe' });
      
      proc.on('exit', () => resolve());
      proc.on('error', () => resolve());
    });
    
    // Clean up socket
    try {
      if (fs.existsSync(session.socketPath)) {
        fs.unlinkSync(session.socketPath);
      }
    } catch (err) {
      console.error(`Failed to clean up socket: ${err}`);
    }
    
    this.sessions.delete(sessionName);
    console.log(`💀 Killed session ${sessionName}`);
  }

  /**
   * Clean up a session
   */
  async cleanupSession(sessionName) {
    await this.killSession(sessionName);
  }

  /**
   * Clean up all sessions
   */
  async cleanup() {
    // Clear all disconnect timers
    for (const timer of this.disconnectTimers.values()) {
      clearTimeout(timer);
    }
    this.disconnectTimers.clear();
    
    // Kill all sessions
    for (const sessionName of this.sessions.keys()) {
      await this.killSession(sessionName);
    }
    
    this.clientStreams.clear();
    console.log('🧹 Cleaned up all tmux sessions');
  }
}

module.exports = TmuxStreamManager;