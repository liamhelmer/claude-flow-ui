/**
 * Streaming Tmux Manager
 * Manages tmux sessions with per-client streaming buffers and automatic reconnection
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const uniqueFilename = require('unique-filename');
const PlatformCompatibility = require('./platform-compatibility');
const { getInstance: getSecureTempDir } = require('./secure-temp-dir');

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
    const requestedName = sessionName || `terminal-${Date.now()}`;

    // Use secure temp directory for socket and output file
    const secureTempDir = getSecureTempDir();
    const socketDir = secureTempDir.getSocketDir();

    // Generate a unique socket path using unique-filename with shorter prefix
    // Use just 'tmux' as prefix to avoid path length issues
    const uniqueSocketPath = uniqueFilename(socketDir, 'tmux') + '.sock';
    const socketPath = uniqueSocketPath;

    // Extract the actual session name from the socket path
    // This ensures the session name matches the socket file
    const socketBasename = path.basename(socketPath, '.sock');
    const actualSessionName = socketBasename;

    const outputFile = initialCommand ? path.join(socketDir, `${actualSessionName}.output`) : null;

    console.log(`[TmuxStream] Session creation: requested="${requestedName}", actual="${actualSessionName}", socket="${socketPath}"`);
    
    if (process.env.DEBUG_TMUX) {
      console.log(`[TmuxStream] Creating session ${actualSessionName}`);
      console.log(`[TmuxStream] Socket path: ${socketPath}`);
      console.log(`[TmuxStream] Socket length: ${socketPath.length} chars`);
      console.log(`[TmuxStream] Command: ${initialCommand || 'default shell'}`);
    }
    
    // Kill any existing session with same name
    await this.killSession(actualSessionName).catch(() => {});
    
    // Create new tmux session
    // Important: When using custom socket path, tmux needs to keep the server alive
    const tmuxArgs = [
      '-S', socketPath,
      'new-session',
      '-d',
      '-s', actualSessionName,  // Use the actual session name that matches the socket
      '-x', '120',
      '-y', '40'
    ];
    
    // Always start with a shell
    const shell = process.env.SHELL || '/bin/bash';

    if (initialCommand) {
      // Check if the command is a shell (bash, zsh, sh, etc.)
      const isShell = /^\/(bin|usr\/bin)\/(bash|zsh|sh|fish|tcsh|csh)(\s|$)/.test(initialCommand);

      if (isShell) {
        // Start an interactive shell session
        tmuxArgs.push('-c', process.cwd());
        // Split the command to handle arguments like --login
        const shellParts = initialCommand.split(/\s+/);
        tmuxArgs.push(...shellParts);
      } else {
        // Run command with tee to capture output, then exit immediately
        tmuxArgs.push('-c', process.cwd());
        // Capture only stderr and exit code, then exit the session
        const shellCmd = `${initialCommand} 2> >(tee '${outputFile}' >&2); EXIT_CODE=$?; echo "EXIT_CODE:$EXIT_CODE" >> '${outputFile}'; exit $EXIT_CODE`;
        tmuxArgs.push('bash', '-c', shellCmd);
      }
    } else {
      // Just start an interactive shell for non-command sessions
      tmuxArgs.push('-c', process.cwd());
      tmuxArgs.push(shell);
    }
    
    await new Promise((resolve, reject) => {
      const proc = spawn('tmux', tmuxArgs, { stdio: 'pipe' });
      let errorOutput = '';
      let stdOutput = '';
      
      proc.stdout.on('data', (data) => {
        stdOutput += data.toString();
      });
      
      proc.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      proc.on('exit', (code) => {
        if (code === 0) {
          if (process.env.DEBUG_TMUX) {
            console.log(`[TmuxStream] Successfully created tmux session ${actualSessionName}`);
            console.log(`[TmuxStream] Session created with socket: ${socketPath}`);
          }
          // Log success if debug is enabled
          if (process.env.DEBUG_TMUX || process.env.DEBUG) {
            console.log(`[TmuxStream] Successfully created tmux session ${actualSessionName}`);
          }
          
          // Verify the session actually exists after creation
          const verifyProc = spawn('tmux', ['-S', socketPath, 'has-session', '-t', actualSessionName]);
          verifyProc.on('exit', (verifyCode) => {
            if (verifyCode === 0) {
              if (process.env.DEBUG_TMUX || process.env.DEBUG) {
                console.log(`[TmuxStream] Verified session ${actualSessionName} exists`);
              }
              
              // Don't set remain-on-exit so pane can die when command completes
              // This allows proper termination detection
              
              resolve();
            } else {
              console.error(`[TmuxStream] Session ${actualSessionName} verification failed after creation`);
              console.error(`[TmuxStream] Socket: ${socketPath}, exists: ${require('fs').existsSync(socketPath)}`);
              reject(new Error(`Session verification failed after creation`));
            }
          });
          verifyProc.on('error', (err) => {
            console.error(`[TmuxStream] Failed to verify session: ${err.message}`);
            reject(err);
          });
        } else {
          console.error(`[TmuxStream] Failed to create tmux session ${actualSessionName}: exit code ${code}`);
          console.error(`[TmuxStream] Socket path attempted: ${socketPath}`);
          console.error(`[TmuxStream] Command was: tmux ${tmuxArgs.join(' ')}`);
          if (errorOutput) {
            console.error(`[TmuxStream] Stderr: ${errorOutput}`);
          }
          if (stdOutput) {
            console.error(`[TmuxStream] Stdout: ${stdOutput}`);
          }
          reject(new Error(`Failed to create tmux session: ${code} - ${errorOutput}`));
        }
      });
      proc.on('error', (err) => {
        console.error(`[TmuxStream] Failed to spawn tmux: ${err.message}`);
        reject(err);
      });
    });
    
    // Set up session info
    const sessionInfo = {
      name: actualSessionName,  // Use actual session name
      socketPath,
      outputFile,  // Store output file path for commands
      created: Date.now(),
      clients: new Set(),
      historyBuffer: '',
      lastCapture: '',
      lastCaptureLines: [],
      streaming: false,
      captureInterval: null,
      initialCapturesSent: new Set(), // Track which clients have received initial capture
      lastActivityTime: Date.now(),
      lastDebugLog: 0
    }
    
    // Store with the actual session name that matches the socket
    this.sessions.set(actualSessionName, sessionInfo);

    // Start streaming for this session
    this.startSessionStream(actualSessionName);

    // For interactive shells, send a refresh to trigger prompt display
    if (initialCommand) {
      const isShell = /^\/(bin|usr\/bin)\/(bash|zsh|sh|fish|tcsh|csh)(\s|$)/.test(initialCommand);
      if (isShell) {
        // Send Enter key to refresh the prompt after a short delay
        setTimeout(() => {
          // Use sendKey instead of sendInput for special keys
          const session = this.sessions.get(name);
          if (session) {
            spawn('tmux', [
              '-S', session.socketPath,
              'send-keys',
              '-t', actualSessionName,
              'Enter'
            ], { stdio: 'ignore' });
          }
        }, 100);
      }
    }

    if (process.env.DEBUG_TMUX || process.env.DEBUG) {
      console.log(`✅ Created tmux session: ${actualSessionName} (requested: ${requestedName}`);
    }
    return { name: actualSessionName, socketPath, outputFile };  // Return actual session name
  }

  /**
   * Start streaming tmux output for a session
   */
  startSessionStream(sessionName) {
    const session = this.sessions.get(sessionName);
    if (!session) {
      console.error(`[TmuxStream] Cannot start stream - session ${sessionName} not found`);
      return;
    }

    if (session.streaming && session.captureInterval) {
      console.log(`[TmuxStream] Stream already active for session ${sessionName}`);
      return;
    }

    session.streaming = true;
    console.log(`[TmuxStream] 🎬 Starting stream for session ${sessionName} with socket: ${session.socketPath}`);
    
    // Don't use pipe-pane as it can interfere with the session
    // Instead, rely on periodic capture for updates
    if (process.env.DEBUG_TMUX) {
      console.log(`[TmuxStream] Starting capture-based streaming for session ${sessionName}`);
      const session = this.sessions.get(sessionName);
      if (session) {
        console.log(`[TmuxStream] Session info:`, {
          name: session.name,
          socketPath: session.socketPath,
          socketExists: require('fs').existsSync(session.socketPath),
          created: new Date(session.created).toISOString()
        });
      }
    }
    
    // No pipe-pane process needed - we'll use periodic capture instead
    
    // Track capture skip count to reduce unnecessary captures
    let captureSkipCount = 0;
    
    // Set up periodic capture for screen state
    const captureInterval = setInterval(async () => {
      if (!this.sessions.has(sessionName)) {
        clearInterval(captureInterval);
        return;
      }
      
      // CRITICAL: Check if socket file still exists
      if (!fs.existsSync(session.socketPath)) {
        console.log(`🔌 [CRITICAL] Socket file deleted for session ${sessionName} - initiating shutdown`);
        clearInterval(captureInterval);
        session.streaming = false;
        
        // Notify all clients that session is terminating
        for (const clientId of session.clients) {
          const clientStream = this.clientStreams.get(clientId);
          if (clientStream && clientStream.callback) {
            clientStream.callback('\r\n🛑 Tmux socket terminated - shutting down...\r\n');
          }
        }
        
        // Clean up session (don't await to avoid hanging)
        this.cleanupSession(sessionName).catch(err => {
          console.error('Error during cleanup:', err);
        });
        
        // Trigger graceful application shutdown
        console.log('🛑 Socket terminated - shutting down application...');

        // Store exit code for the shutdown handler to use
        process.exitCode = 0;

        // Trigger graceful shutdown via SIGTERM
        process.kill(process.pid, 'SIGTERM');
        return;
      }
      
      // ALWAYS check if pane is dead first (even with no clients)
      try {
        // Check if pane is dead (command completed)
        if (process.env.DEBUG_TMUX) {
          console.log(`[TmuxStream] Checking if pane is dead for session ${sessionName}...`);
        }
        const paneStatus = await this.isPaneDead(sessionName, session.socketPath);
        if (process.env.DEBUG_TMUX) {
          console.log(`[TmuxStream] Pane status for ${sessionName}:`, paneStatus);
        }
        if (paneStatus.isDead) {
          let exitCode = paneStatus.exitCode || 0;
          console.log(`🔌 [DEBUG] Command completed in session ${sessionName} - pane is dead with exit code: ${exitCode}`);
          clearInterval(captureInterval);
          session.streaming = false;

          // Read captured output from file if available (server console only)
          if (session.outputFile && fs.existsSync(session.outputFile)) {
            try {
              const capturedOutput = fs.readFileSync(session.outputFile, 'utf8');
              console.log('\n📄 [SERVER] Captured command output from file:');
              console.log('─'.repeat(60));

              // Extract exit code from file
              const exitCodeMatch = capturedOutput.match(/EXIT_CODE:(\d+)/m);
              if (exitCodeMatch) {
                exitCode = parseInt(exitCodeMatch[1], 10);
                const outputWithoutExit = capturedOutput.replace(/\nEXIT_CODE:\d+\s*$/, '');
                console.log(outputWithoutExit);
              } else {
                console.log(capturedOutput);
              }

              console.log('─'.repeat(60));
              console.log(`📊 [SERVER] Command exit code: ${exitCode}`);
            } catch (err) {
              console.error(`[SERVER] Failed to read output file: ${err.message}`);
            }
          } else {
            console.log(`📊 [SERVER] Command exit code: ${exitCode}`);
          }

          // Store exit code in session
          session.exitCode = exitCode;
          session.commandCompleted = true;
          session.completedAt = Date.now();

          // Notify all clients - terminal closes
          for (const clientId of session.clients) {
            const clientStream = this.clientStreams.get(clientId);
            if (clientStream && clientStream.callback) {
              // Just send a newline to let the terminal close cleanly
              clientStream.callback('\r\n');
            }
          }

          // Clean up output file
          if (session.outputFile && fs.existsSync(session.outputFile)) {
            try {
              fs.unlinkSync(session.outputFile);
              console.log(`🧹 [SERVER] Cleaned up output file: ${session.outputFile}`);
            } catch (err) {
              console.warn(`⚠️ [SERVER] Failed to clean up output file: ${err.message}`);
            }
          }

          // Clean up session (don't await to avoid hanging)
          this.cleanupSession(sessionName).catch(err => {
            console.error('Error during cleanup:', err);
          });

          // Trigger graceful application shutdown
          console.log(`🛑 [SERVER] Command completed with exit code ${exitCode} - shutting down application...`);

          // Store exit code for the shutdown handler to use
          process.exitCode = exitCode;

          // Trigger graceful shutdown via SIGTERM
          process.kill(process.pid, 'SIGTERM');
          return;
        }

        // Only capture if there are active clients
        if (session.clients.size === 0) {
          return; // Skip capture when no clients are connected
        }

        // Skip some captures if there's been no recent activity AND no new clients
        const timeSinceActivity = Date.now() - (session.lastActivityTime || Date.now());
        // Don't skip if we have clients that haven't received initial capture
        const hasUninitializedClients = Array.from(session.clients).some(
          clientId => !session.initialCapturesSent.has(clientId)
        );
        const shouldSkip = !hasUninitializedClients && timeSinceActivity > 1000 && captureSkipCount < 10;
        
        if (shouldSkip) {
          captureSkipCount++;
          if (process.env.DEBUG_TMUX && captureSkipCount === 1) {
            console.log(`[TmuxStream] Skipping captures due to inactivity for session ${sessionName}`);
          }
          return; // Skip this capture cycle
        }
        
        captureSkipCount = 0;
        
        // Capture current pane content (not full history)
        const capture = await this.capturePane(sessionName, session.socketPath);

        if (process.env.DEBUG_TMUX) {
          console.log(`[TmuxStream] 📸 Captured ${capture ? capture.length : 0} bytes from session ${sessionName}`);
        }
        
        if (process.env.DEBUG_TMUX && session.clients.size > 0) {
          // Only log occasionally to reduce spam
          const now = Date.now();
          if (!session.lastDebugLog || now - session.lastDebugLog > 5000) {
            console.log(`[TmuxStream] Capturing screen for session ${sessionName} (${session.clients.size} clients)`);
            session.lastDebugLog = now;
          }
        }
        
        if (capture !== session.lastCapture) {
          session.lastActivityTime = Date.now(); // Reset activity timer on changes
          // Calculate the difference
          const currentLines = capture.split('\n');
          const previousLines = session.lastCaptureLines;
          
          // For new content, only send what's changed
          let hasChanges = false;
          let updateData = '';
          
          // If this is completely different content (like after a clear), send full update
          if (previousLines.length === 0 || currentLines.length !== previousLines.length) {
            hasChanges = true;
            updateData = '\x1b[2J\x1b[H' + capture; // Clear and full content
          } else {
            // Check for line-by-line changes and only send differences
            for (let i = 0; i < currentLines.length; i++) {
              if (currentLines[i] !== previousLines[i]) {
                hasChanges = true;
                // Move cursor to line and update it
                updateData += `\x1b[${i + 1};1H\x1b[2K${currentLines[i]}\n`;
              }
            }
          }
          
          if (hasChanges) {
            session.lastCapture = capture;
            session.lastCaptureLines = currentLines;
            session.historyBuffer = capture; // Keep full state for new clients
            
            // Send updates to all clients
            if (process.env.DEBUG_TMUX && session.clients.size > 0) {
              console.log(`[TmuxStream] 📤 Sending ${updateData.length} bytes to ${session.clients.size} clients`);
            }

            for (const clientId of session.clients) {
              const clientStream = this.clientStreams.get(clientId);
              if (clientStream && clientStream.callback) {
                // Send updates to initialized clients
                if (session.initialCapturesSent.has(clientId)) {
                  try {
                    clientStream.callback(updateData);
                    if (process.env.DEBUG_TMUX) {
                      console.log(`[TmuxStream] ✉️ Sent update to client ${clientId}`);
                    }
                  } catch (err) {
                    console.error(`[TmuxStream] Failed to send to client ${clientId}:`, err);
                  }
                } else if (process.env.DEBUG_TMUX) {
                  console.log(`[TmuxStream] ⏳ Client ${clientId} not initialized, skipping`);
                }
              }
            }
          }
        }
      } catch (err) {
        // Check for fatal errors that should trigger shutdown
        const errorMessage = err.message || '';
        const isFatalError = errorMessage.includes('no server running') || 
                            errorMessage.includes('can\'t find session') ||
                            errorMessage.includes('session not found') ||
                            errorMessage.includes('server not found');
        
        if (isFatalError) {
          // Before treating as fatal, check if we have an output file (command might have completed)
          if (session.outputFile && fs.existsSync(session.outputFile)) {
            console.log(`📄 [SERVER] Session exited, checking output file...`);

            let exitCode = 0;
            try {
              const capturedOutput = fs.readFileSync(session.outputFile, 'utf8');
              console.log('\n📄 [SERVER] Captured command output from file:');
              console.log('─'.repeat(60));

              // Extract exit code from file
              const exitCodeMatch = capturedOutput.match(/EXIT_CODE:(\d+)/m);
              if (exitCodeMatch) {
                exitCode = parseInt(exitCodeMatch[1], 10);
                const outputWithoutExit = capturedOutput.replace(/\nEXIT_CODE:\d+\s*$/, '');
                console.log(outputWithoutExit);
              } else {
                console.log(capturedOutput);
              }

              console.log('─'.repeat(60));
              console.log(`📊 [SERVER] Command exit code: ${exitCode}`);

              // Clean up output file
              fs.unlinkSync(session.outputFile);
              console.log(`🧹 [SERVER] Cleaned up output file: ${session.outputFile}`);
            } catch (err) {
              console.error(`[SERVER] Failed to read output file: ${err.message}`);
            }

            // Clear interval to stop further attempts
            clearInterval(captureInterval);
            session.streaming = false;

            // Clean up session
            this.cleanupSession(sessionName).catch(err => {
              console.error('Error during cleanup:', err);
            });

            // Trigger graceful shutdown with the actual command exit code
            console.log(`🛑 [SERVER] Command completed with exit code ${exitCode} - shutting down application...`);

            // Store exit code for the shutdown handler to use
            process.exitCode = exitCode;

            // Trigger graceful shutdown via SIGTERM
            process.kill(process.pid, 'SIGTERM');
            return;
          }

          // It's a real fatal error (not just a completed command)
          console.error(`🔴 [FATAL] Tmux capture failed for session ${sessionName}: ${errorMessage}`);
          console.error('🛑 Fatal tmux error - initiating shutdown...');

          // Clear interval to stop further attempts
          clearInterval(captureInterval);
          session.streaming = false;

          // Notify all clients
          for (const clientId of session.clients) {
            const clientStream = this.clientStreams.get(clientId);
            if (clientStream && clientStream.callback) {
              clientStream.callback('\r\n🔴 Fatal error: Tmux server terminated\r\n');
            }
          }

          // Clean up session (don't await to avoid hanging)
          this.cleanupSession(sessionName).catch(err => {
            console.error('Error during cleanup:', err);
          });

          // Trigger graceful shutdown with error code
          process.exitCode = 1;
          process.kill(process.pid, 'SIGTERM');
          return;
        }
        
        // Non-fatal errors are just logged
        if (process.env.DEBUG_TMUX) {
          console.error(`[TmuxStream] Capture error for session ${sessionName}:`, err.message);
          console.error(`[TmuxStream] Socket path: ${session.socketPath}`);
          console.error(`[TmuxStream] Socket exists: ${require('fs').existsSync(session.socketPath)}`);
        } else {
          console.error(`Capture error for session ${sessionName}:`, err.message);
        }
      }
    }, 100); // Check every 100ms for responsive updates
    
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
      if (process.env.DEBUG_TMUX || process.env.DEBUG) {
        console.log(`🔄 Client ${clientId} reconnected within grace period`);
      }
    }
    
    // Add client to session
    session.clients.add(clientId);

    // Reset activity timer when new client connects to ensure captures resume
    session.lastActivityTime = Date.now();

    // CRITICAL: Restart capture if it was stopped when all clients disconnected
    if (!session.streaming && !session.captureInterval) {
      console.log(`[TmuxStream] 🔄 Restarting capture for session ${sessionName} - client reconnected`);
      // Call the correct method to restart streaming
      this.startSessionStream(sessionName);
    }
    
    // Set up client stream
    const clientStream = {
      clientId,
      sessionName,
      callback,
      connected: Date.now(),
      buffer: ''
    };
    
    this.clientStreams.set(clientId, clientStream);
    
    // Capture current screen state for new client
    this.captureFullScreen(sessionName, session.socketPath)
      .then(currentScreen => {
        // CRITICAL: Always mark client as initialized to ensure they receive future updates
        session.initialCapturesSent.add(clientId);

        if (currentScreen && currentScreen.trim()) {
          // Send current screen to new client
          callback('\x1b[2J\x1b[H' + currentScreen);
          session.historyBuffer = currentScreen; // Update history buffer
          session.lastCapture = currentScreen;
          session.lastCaptureLines = currentScreen.split('\n');

          if (process.env.DEBUG_TMUX || process.env.DEBUG) {
            console.log(`📦 Sent initial screen to client ${clientId}: ${currentScreen.length} bytes`);
          }
        } else if (session.historyBuffer) {
          // Fallback to history buffer if capture is empty
          callback('\x1b[2J\x1b[H' + session.historyBuffer);
          console.log(`📦 Sent history buffer to client ${clientId}`);
        } else {
          // Even if no content, send clear screen to initialize terminal
          callback('\x1b[2J\x1b[H');
          console.log(`📦 Sent clear screen to client ${clientId} (empty initial state)`);
        }
      })
      .catch(err => {
        console.error(`Failed to capture initial screen for client ${clientId}:`, err);
        // CRITICAL: Always mark client as initialized even on error
        session.initialCapturesSent.add(clientId);

        // Try to send whatever we have in history
        if (session.historyBuffer) {
          callback('\x1b[2J\x1b[H' + session.historyBuffer);
        } else {
          // Send clear screen at minimum to initialize
          callback('\x1b[2J\x1b[H');
        }
      });
    
    if (process.env.DEBUG_TMUX || process.env.DEBUG) {
      console.log(`👤 Client ${clientId} connected to session ${sessionName}`);
    }
    
    return {
      sessionName,
      write: (data) => this.sendInput(sessionName, data),
      resize: (cols, rows) => this.resizeSession(sessionName, cols, rows),
      refresh: () => this.refreshClient(clientId),
      disconnect: (immediate = false) => this.disconnectClient(clientId, immediate)
    };
  }

  /**
   * Disconnect a client with grace period
   */
  disconnectClient(clientId, immediate = false) {
    const clientStream = this.clientStreams.get(clientId);
    if (!clientStream) return;

    if (immediate) {
      // Immediate disconnect without grace period (for session switching)
      console.log(`⚡ Client ${clientId} disconnecting immediately (session switch)`);
      this.finalDisconnect(clientId);
    } else {
      console.log(`👋 Client ${clientId} disconnecting, starting ${this.DISCONNECT_GRACE_PERIOD}ms grace period`);

      // Start disconnect timer
      const timer = setTimeout(() => {
        // Actually disconnect after grace period
        this.finalDisconnect(clientId);
      }, this.DISCONNECT_GRACE_PERIOD);

      this.disconnectTimers.set(clientId, timer);
    }
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
      session.initialCapturesSent.delete(clientId); // Clean up initial capture tracking
      
      // If no more clients, consider stopping the stream
      if (session.clients.size === 0) {
        console.log(`📍 No more clients for session ${clientStream.sessionName}, keeping session alive`);
        // We keep the session alive but could stop streaming to save resources
        if (session.captureInterval) {
          clearInterval(session.captureInterval);
          session.captureInterval = null;
        }
        session.streaming = false;
      }
    }
    
    this.clientStreams.delete(clientId);
    this.disconnectTimers.delete(clientId);
    
    console.log(`❌ Client ${clientId} fully disconnected`);
  }

  /**
   * Refresh client by restarting the capture for current session
   */
  async refreshClient(clientId) {
    const clientStream = this.clientStreams.get(clientId);
    if (!clientStream) return;

    const sessionName = clientStream.sessionName;
    const session = this.sessions.get(sessionName);
    if (!session) return;

    // Restart capture for this session to get fresh data
    console.log(`[TmuxStream] 🔄 Restarting capture for session ${sessionName} - client reconnected`);

    // Stop existing stream if any
    if (session.captureInterval) {
      clearInterval(session.captureInterval);
      session.captureInterval = null;
    }

    // Get fresh capture and send to client
    try {
      const currentCapture = await this.capturePane(sessionName, session.socketPath);
      if (currentCapture && clientStream.callback) {
        // Send the current terminal state to the client
        clientStream.callback(currentCapture);
      }
    } catch (error) {
      console.error(`[TmuxStream] Failed to capture session during refresh:`, error);
    }

    // Restart streaming
    this.startSessionStream(sessionName);

    if (process.env.DEBUG_TMUX || process.env.DEBUG) {
      console.log(`🔄 Client ${clientId} refreshed session ${sessionName}`);
    }

    return session;
  }

  /**
   * Send input to a tmux session
   */
  sendInput(sessionName, data) {
    const session = this.sessions.get(sessionName);
    if (!session) return;
    
    // Mark session as active to trigger captures
    session.lastActivityTime = Date.now();
    
    if (process.env.DEBUG_TMUX) {
      console.log(`[TmuxStream] Sending input to ${sessionName}: ${data.substring(0, 50)}${data.length > 50 ? '...' : ''}`);
    }
    
    const sendKeysProcess = spawn('tmux', [
      '-S', session.socketPath,
      'send-keys',
      '-t', sessionName,
      '-l',
      data
    ], { stdio: 'pipe' });

    console.log(`[TmuxStream] 📝 Sent input to tmux session ${sessionName}: "${data}"`);

    sendKeysProcess.on('error', (err) => {
      console.error(`[TmuxStream] ❌ Error sending input to tmux: ${err.message}`);
    });
  }

  /**
   * Resize a tmux session
   */
  resizeSession(sessionName, cols, rows) {
    const session = this.sessions.get(sessionName);
    if (!session) return;
    
    if (process.env.DEBUG_TMUX) {
      console.log(`[TmuxStream] Resizing ${sessionName} to ${cols}x${rows}`);
    }
    
    spawn('tmux', [
      '-S', session.socketPath,
      'resize-window',
      '-t', sessionName,
      '-x', cols.toString(),
      '-y', rows.toString()
    ], { stdio: 'ignore' });
  }

  /**
   * Capture current pane content (visible area only)
   */
  async capturePane(sessionName, socketPath) {
    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-e',  // Include escape sequences
        '-p'   // Print to stdout
      ], { stdio: 'pipe' });

      let output = '';
      let errorOutput = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          resolve(output);
        } else {
          reject(new Error(`Failed to capture pane: ${errorOutput}`));
        }
      });

      tmux.on('error', (err) => {
        reject(err);
      });
    });
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
          // Enhanced debug logging
          if (process.env.DEBUG_TMUX) {
            console.log(`[TmuxStream] Capture attempt ${retryCount + 1}/${maxRetries + 1} for ${sessionName}`);
            console.log(`[TmuxStream] Using socket: ${socketPath}`);
            console.log(`[TmuxStream] Tmux command: tmux -S "${socketPath}" capture-pane -t "${sessionName}" -p -e`);
          } else if (retryCount > 0 && (process.env.DEBUG_TMUX || process.env.DEBUG)) {
            console.log(`[TmuxStream] Retry ${retryCount}/${maxRetries} for session ${sessionName}`);
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
                console.log(`[TmuxStream] Capture successful: ${output.length} bytes`);
                const preview = output.substring(0, 100).replace(/\n/g, '\\n').replace(/\r/g, '\\r');
                console.log(`[TmuxStream] First 100 chars: ${preview}`);
              }
              resolve(output);
            } else {
              // Enhanced error logging for debugging
              console.error(`[TmuxStream] Tmux capture failed with code ${code} for session ${sessionName}`);
              console.error(`[TmuxStream] Socket path: ${socketPath}`);
              console.error(`[TmuxStream] Error output: ${errorOutput || '(no error output)'}`);
              
              // Check if socket exists
              if (!require('fs').existsSync(socketPath)) {
                console.error(`[TmuxStream] Socket file does not exist: ${socketPath}`);
              }
              
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
    if (!session) {
      // Try to kill by name anyway in case it exists but isn't tracked
      const secureTempDir = getSecureTempDir();
      try {
        const socketPath = secureTempDir.getSocketPath(sessionName);
        if (fs.existsSync(socketPath)) {
          await new Promise((resolve) => {
            const proc = spawn('tmux', [
              '-S', socketPath,
              'kill-session',
              '-t', sessionName
            ], { stdio: 'pipe' });
            proc.on('exit', () => resolve());
            proc.on('error', () => resolve());
          });
          try {
            fs.unlinkSync(socketPath);
          } catch (err) {
            // Ignore cleanup errors
          }
        }
      } catch (err) {
        // Socket path not found, session doesn't exist
      }
      return;
    }
    
    // Stop streaming
    if (session.captureInterval) {
      clearInterval(session.captureInterval);
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
    if (process.env.DEBUG_TMUX || process.env.DEBUG) {
      console.log(`💀 Killed session ${sessionName}`);
    }
  }

  /**
   * Clean up a session
   */
  async cleanupSession(sessionName) {
    const session = this.sessions.get(sessionName);

    // Clean up output file if exists
    if (session && session.outputFile && fs.existsSync(session.outputFile)) {
      try {
        fs.unlinkSync(session.outputFile);
        console.log(`🧹 [SERVER] Cleaned up output file during session cleanup: ${session.outputFile}`);
      } catch (err) {
        console.warn(`⚠️ [SERVER] Failed to clean up output file: ${err.message}`);
      }
    }

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
    // First check if socket file exists
    if (!fs.existsSync(socketPath)) {
      if (process.env.DEBUG_TMUX) {
        console.error(`[TmuxStream] Socket validation failed:`);
        console.error(`  Session: ${sessionName}`);
        console.error(`  Socket path: ${socketPath}`);
        console.error(`  Socket exists: false`);
        console.error(`  Parent dir: ${require('path').dirname(socketPath)}`);
        console.error(`  Parent exists: ${fs.existsSync(require('path').dirname(socketPath))}`);
      }
      return Promise.reject(new Error(`Socket path does not exist: ${socketPath}`));
    }
    
    if (process.env.DEBUG_TMUX) {
      console.log(`[TmuxStream] Validating session ${sessionName} at ${socketPath}`);
    }
    
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
          if (process.env.DEBUG_TMUX) {
            console.log(`[TmuxStream] Session ${sessionName} validated successfully`);
          }
          resolve();
        } else {
          if (process.env.DEBUG_TMUX) {
            console.error(`[TmuxStream] Session validation failed with code ${code}`);
          }
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
    if (process.env.DEBUG_TMUX) {
      console.log(`[TmuxStream] Attempting fallback capture methods for session ${sessionName}`);
      console.log(`[TmuxStream] Socket: ${socketPath}`);
    }
    
    // First, let's verify the session actually exists
    const sessionCheck = await new Promise((resolve) => {
      const check = spawn('tmux', [
        '-S', socketPath,
        'list-sessions'
      ], { stdio: 'pipe' });
      
      let output = '';
      check.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      check.on('exit', (code) => {
        if (code === 0) {
          if (process.env.DEBUG_TMUX) {
            console.log(`[TmuxStream] Active sessions on socket ${socketPath}: ${output.trim()}`);
          }
          resolve(output.includes(sessionName));
        } else {
          if (process.env.DEBUG_TMUX) {
            console.error(`[TmuxStream] Could not list sessions on socket ${socketPath} (exit code: ${code})`);
          }
          resolve(false);
        }
      });
      
      check.on('error', () => resolve(false));
    });
    
    if (!sessionCheck) {
      throw new Error(`Session ${sessionName} not found on socket ${socketPath}`);
    }
    
    // Get platform-specific strategies if not already loaded
    if (!this.captureStrategies) {
      this.captureStrategies = this.platformCompat.getRecommendedCaptureStrategy();
    }
    
    // Try platform-optimized strategies first
    for (const strategy of this.captureStrategies) {
      try {
        if (process.env.DEBUG_TMUX) {
          console.log(`[TmuxStream] Trying fallback strategy: ${strategy.name} - ${strategy.description}`);
          const args = strategy.args.map(arg => 
            arg.replace('{socketPath}', socketPath).replace('{sessionName}', sessionName)
          );
          console.log(`[TmuxStream] Command: tmux ${args.join(' ')}`);
        }
        
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

  /**
   * Check if a pane is dead (command has completed) and capture exit code
   */
  async isPaneDead(sessionName, socketPath) {
    return new Promise((resolve) => {
      const { spawn } = require('child_process');
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'list-panes',
        '-t', sessionName,
        '-F', '#{pane_dead},#{pane_dead_status}'
      ], { stdio: 'pipe' });

      let output = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          // Output will be '1,exitcode' if pane is dead, '0,' if alive
          const [deadStatus, exitStatus] = output.trim().split(',');
          const isDead = deadStatus === '1';

          if (isDead) {
            const exitCode = exitStatus ? parseInt(exitStatus, 10) : 0;
            if (process.env.DEBUG_TMUX || process.env.DEBUG) {
              console.log(`💀 Pane is dead in session ${sessionName} with exit code: ${exitCode}`);
            }
            resolve({ isDead: true, exitCode });
          } else {
            resolve({ isDead: false, exitCode: null });
          }
        } else {
          // If we can't check pane status, the server likely exited (command completed)
          if (process.env.DEBUG_TMUX || process.env.DEBUG) {
            console.log(`⚠️ Failed to check pane status for ${sessionName} (exit code: ${code}) - server likely exited`);
          }
          // When tmux server exits, treat as dead pane (command completed)
          resolve({ isDead: true, exitCode: 0 });
        }
      });

      tmux.on('error', () => {
        // On error checking pane status, server likely exited
        if (process.env.DEBUG_TMUX || process.env.DEBUG) {
          console.log(`⚠️ Error checking pane status for ${sessionName} - server likely exited`);
        }
        resolve({ isDead: true, exitCode: 0 });
      });
    });
  }
}

module.exports = TmuxStreamManager;