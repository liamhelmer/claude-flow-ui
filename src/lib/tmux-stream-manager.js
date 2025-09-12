/**
 * Streaming Tmux Manager
 * Manages tmux sessions with per-client streaming buffers and automatic reconnection
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const PlatformCompatibility = require('./platform-compatibility');

class TmuxStreamManager {
  constructor() {
    this.sessions = new Map(); // sessionId -> session info
    this.clientStreams = new Map(); // clientId -> stream info
    this.disconnectTimers = new Map(); // clientId -> disconnect timer
    this.DISCONNECT_GRACE_PERIOD = 10000; // 10 seconds
    this.STREAM_INTERVAL = 50; // Stream update interval in ms
    this.platformCompat = new PlatformCompatibility();
    this.captureStrategies = null; // Will be initialized async
    this.platformAdjustments = this.platformCompat.getTmuxCommandAdjustments();
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
      
      // Only capture if there are active clients
      if (session.clients.size === 0) {
        return; // Skip capture when no clients are connected
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
   * Capture full screen content from tmux with robust error handling
   */
  async captureFullScreen(sessionName, socketPath, retryCount = 0) {
    const maxRetries = 3;
    const timeout = 5000; // 5 second timeout
    
    return new Promise((resolve, reject) => {
      // First validate that the session exists
      this.validateSession(sessionName, socketPath)
        .then(() => {
          // Only log capture attempts in debug mode or on retries
          if (process.env.DEBUG_TMUX || retryCount > 0) {
            console.log(`[TmuxStream] Capturing screen for session ${sessionName} (attempt ${retryCount + 1}/${maxRetries + 1})`);
          }
          
          const tmuxArgs = [
            '-S', socketPath,
            'capture-pane',
            '-t', sessionName,
            '-S', '-',    // Start from beginning of history
            '-E', '-',    // End at end of history
            '-e',         // Include escape sequences
            '-p'          // Print to stdout
          ];
          
          const tmux = spawn('tmux', tmuxArgs, { 
            stdio: 'pipe',
            timeout: timeout
          });

          let output = '';
          let errorOutput = '';
          let timeoutHandle = null;
          let processCompleted = false;

          // Set up timeout
          timeoutHandle = setTimeout(() => {
            if (!processCompleted) {
              console.warn(`[TmuxStream] Tmux capture timed out for session ${sessionName}, killing process`);
              tmux.kill('SIGKILL');
              processCompleted = true;
              
              // Try fallback capture method
              this.fallbackCapture(sessionName, socketPath)
                .then(fallbackOutput => {
                  console.log(`[TmuxStream] Fallback capture succeeded for session ${sessionName}`);
                  resolve(fallbackOutput);
                })
                .catch(fallbackError => {
                  console.error(`[TmuxStream] Fallback capture also failed: ${fallbackError.message}`);
                  if (retryCount < maxRetries) {
                    console.log(`[TmuxStream] Retrying capture for session ${sessionName} (${retryCount + 1}/${maxRetries})`);
                    setTimeout(() => {
                      this.captureFullScreen(sessionName, socketPath, retryCount + 1)
                        .then(resolve)
                        .catch(reject);
                    }, 1000 * (retryCount + 1)); // Exponential backoff
                  } else {
                    reject(new Error(`Failed to capture screen after ${maxRetries} retries: timeout`));
                  }
                });
            }
          }, timeout);

          tmux.stdout.on('data', (data) => {
            output += data.toString();
          });
          
          tmux.stderr.on('data', (data) => {
            errorOutput += data.toString();
          });

          tmux.on('exit', (code) => {
            if (processCompleted) return;
            processCompleted = true;
            clearTimeout(timeoutHandle);
            
            if (code === 0) {
              // Only log in debug mode to avoid spamming logs
              if (process.env.DEBUG_TMUX) {
                console.log(`[TmuxStream] Screen capture successful for session ${sessionName} (${output.length} bytes)`);
              }
              resolve(output);
            } else {
              console.error(`[TmuxStream] Tmux capture failed with code ${code} for session ${sessionName}: ${errorOutput}`);
              
              // Try fallback methods before failing
              this.fallbackCapture(sessionName, socketPath)
                .then(fallbackOutput => {
                  console.log(`[TmuxStream] Fallback capture succeeded after tmux failed with code ${code}`);
                  resolve(fallbackOutput);
                })
                .catch(fallbackError => {
                  console.error(`[TmuxStream] Fallback capture also failed: ${fallbackError.message}`);
                  if (retryCount < maxRetries && this.shouldRetryError(code, errorOutput)) {
                    console.log(`[TmuxStream] Retrying capture for session ${sessionName} due to recoverable error`);
                    setTimeout(() => {
                      this.captureFullScreen(sessionName, socketPath, retryCount + 1)
                        .then(resolve)
                        .catch(reject);
                    }, 1000 * (retryCount + 1)); // Exponential backoff
                  } else {
                    reject(new Error(`Failed to capture screen: code ${code}, error: ${errorOutput || 'unknown error'}`));
                  }
                });
            }
          });

          tmux.on('error', (err) => {
            if (processCompleted) return;
            processCompleted = true;
            clearTimeout(timeoutHandle);
            
            console.error(`[TmuxStream] Tmux spawn error for session ${sessionName}: ${err.message}`);
            
            // Try fallback capture on spawn error
            this.fallbackCapture(sessionName, socketPath)
              .then(fallbackOutput => {
                console.log(`[TmuxStream] Fallback capture succeeded after spawn error`);
                resolve(fallbackOutput);
              })
              .catch(fallbackError => {
                console.error(`[TmuxStream] Fallback capture also failed: ${fallbackError.message}`);
                if (retryCount < maxRetries) {
                  console.log(`[TmuxStream] Retrying capture for session ${sessionName} after spawn error`);
                  setTimeout(() => {
                    this.captureFullScreen(sessionName, socketPath, retryCount + 1)
                      .then(resolve)
                      .catch(reject);
                  }, 2000 * (retryCount + 1)); // Longer delay for spawn errors
                } else {
                  reject(new Error(`Failed to capture screen after ${maxRetries} retries: ${err.message}`));
                }
              });
          });
          
        })
        .catch(validationError => {
          console.error(`[TmuxStream] Session validation failed for ${sessionName}: ${validationError.message}`);
          reject(new Error(`Session validation failed: ${validationError.message}`));
        });
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

  /**
   * Validate that a tmux session exists and is accessible
   */
  async validateSession(sessionName, socketPath) {
    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'has-session',
        '-t', sessionName
      ], { stdio: 'pipe', timeout: 3000 });

      let timeoutHandle = setTimeout(() => {
        tmux.kill('SIGKILL');
        reject(new Error('Session validation timed out'));
      }, 3000);

      tmux.on('exit', (code) => {
        clearTimeout(timeoutHandle);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Session ${sessionName} does not exist or is not accessible`));
        }
      });

      tmux.on('error', (err) => {
        clearTimeout(timeoutHandle);
        reject(new Error(`Failed to validate session: ${err.message}`));
      });
    });
  }

  /**
   * Fallback capture method using platform-specific strategies
   */
  async fallbackCapture(sessionName, socketPath) {
    console.log(`[TmuxStream] Attempting platform-specific fallback capture methods for session ${sessionName}`);
    
    // Get platform-specific strategies if not already loaded
    if (!this.captureStrategies) {
      this.captureStrategies = this.platformCompat.getRecommendedCaptureStrategy();
    }
    
    // Try platform-optimized strategies first
    for (const strategy of this.captureStrategies) {
      try {
        console.log(`[TmuxStream] Trying fallback strategy: ${strategy.name} - ${strategy.description}`);
        
        // Replace template variables in args
        const args = strategy.args.map(arg => 
          arg.replace('{socketPath}', socketPath).replace('{sessionName}', sessionName)
        );
        
        const output = await this.executeWithTimeout('tmux', args, strategy.timeout);
        if (output && output.trim()) {
          console.log(`[TmuxStream] Fallback strategy ${strategy.name} succeeded (${output.length} bytes)`);
          return output;
        }
      } catch (error) {
        console.warn(`[TmuxStream] Fallback strategy ${strategy.name} failed: ${error.message}`);
        continue;
      }
    }
    
    // If all strategies fail, return a minimal error message with platform info
    const platformInfo = this.platformCompat.getPlatformInfo();
    throw new Error(`All fallback capture strategies failed on ${platformInfo.platform} ${platformInfo.arch}`);
  }

  /**
   * Execute a command with timeout
   */
  async executeWithTimeout(command, args, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args, { stdio: 'pipe' });
      let output = '';
      let errorOutput = '';
      let completed = false;

      const timeoutHandle = setTimeout(() => {
        if (!completed) {
          completed = true;
          process.kill('SIGKILL');
          reject(new Error('Command execution timed out'));
        }
      }, timeoutMs);

      process.stdout.on('data', (data) => {
        output += data.toString();
      });

      process.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      process.on('exit', (code) => {
        if (completed) return;
        completed = true;
        clearTimeout(timeoutHandle);
        
        if (code === 0) {
          resolve(output);
        } else {
          reject(new Error(`Command failed with code ${code}: ${errorOutput}`));
        }
      });

      process.on('error', (err) => {
        if (completed) return;
        completed = true;
        clearTimeout(timeoutHandle);
        reject(err);
      });
    });
  }

  /**
   * Determine if an error is retryable
   */
  shouldRetryError(exitCode, errorOutput) {
    // Retry on common temporary errors
    const retryableErrors = [
      'resource temporarily unavailable',
      'no such file or directory',
      'connection refused',
      'broken pipe',
      'input/output error'
    ];
    
    const retryableCodes = [1, 2, 127]; // Common temporary failure codes
    
    if (retryableCodes.includes(exitCode)) {
      return true;
    }
    
    if (errorOutput) {
      const lowerError = errorOutput.toLowerCase();
      return retryableErrors.some(error => lowerError.includes(error));
    }
    
    return false;
  }
}

module.exports = TmuxStreamManager;