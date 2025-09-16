#!/usr/bin/env node

/**
 * Tmux Session Manager
 * Handles creating, managing, and connecting to tmux sessions for claude-flow UI
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { getInstance: getSecureTempDir } = require('./secure-temp-dir');

class TmuxManager {
  constructor(workingDir = process.cwd()) {
    this.workingDir = workingDir;
    this.sessionPrefix = 'cf'; // Shorter prefix to avoid path length issues
    this.activeSessions = new Map();
    
    // Use secure temp directory for sockets
    this.secureTempDir = getSecureTempDir();
    this.socketDir = this.secureTempDir.getSocketDir();
    console.log(`📁 Using secure socket directory: ${this.socketDir}`);
  }

  /**
   * Ensure the socket directory exists (now handled by SecureTempDir)
   */
  ensureSocketDir() {
    // No longer needed - SecureTempDir handles this
    // Kept for backward compatibility
  }

  /**
   * Check if tmux is available on the system
   */
  async isTmuxAvailable() {
    return new Promise((resolve) => {
      const tmux = spawn('tmux', ['-V'], { stdio: 'pipe' });
      tmux.on('exit', (code) => {
        resolve(code === 0);
      });
      tmux.on('error', () => {
        resolve(false);
      });
    });
  }

  /**
   * Generate a unique session name
   */
  generateSessionName() {
    const timestamp = Date.now();
    const randomId = crypto.randomBytes(2).toString('hex'); // Shorter random ID
    return `${this.sessionPrefix}-${timestamp}-${randomId}`;
  }

  /**
   * Get the socket path for a session
   */
  getSocketPath(sessionName) {
    return this.secureTempDir.getSocketPath(sessionName);
  }

  /**
   * Create a new tmux session
   */
  async createSession(sessionName = null, command = null, args = [], cols = 80, rows = 24) {
    if (!sessionName) {
      sessionName = this.generateSessionName();
    }

    const socketPath = this.getSocketPath(sessionName);

    // Create output capture file for this session
    const outputFile = path.join(this.socketDir, `${sessionName}.output`);
    
    // Create tmux session with custom socket and configurable size
    const tmuxArgs = [
      '-S', socketPath,  // Custom socket
      'new-session',
      '-d',              // Detached
      '-s', sessionName, // Session name
      '-x', cols.toString(),       // Width (configurable)
      '-y', rows.toString(),       // Height (configurable)
      '-c', this.workingDir  // Working directory
    ];

    // If command is provided, wrap it with tee to capture output
    if (command) {
      // Create a wrapper script that ensures the pane exits after command completes
      let fullCommand;

      if (Array.isArray(args) && args.length > 0) {
        // Escape arguments for shell
        const escapedArgs = args.map(arg => `'${arg.replace(/'/g, "'\\''")}' `).join('');
        // Run command, capture only stderr, save exit code, then exit immediately
        fullCommand = `${command} ${escapedArgs}2> >(tee '${outputFile}' >&2); EXIT_CODE=$?; echo "EXIT_CODE:$EXIT_CODE" >> '${outputFile}'; exit $EXIT_CODE`;
      } else {
        // Run command, capture only stderr, save exit code, then exit immediately
        fullCommand = `${command} 2> >(tee '${outputFile}' >&2); EXIT_CODE=$?; echo "EXIT_CODE:$EXIT_CODE" >> '${outputFile}'; exit $EXIT_CODE`;
      }

      // Use bash -c to run the command and ensure it exits
      tmuxArgs.push('bash', '-c', fullCommand);
    } else {
      // No command provided, use default shell
      const shell = process.env.SHELL || '/bin/bash';
      tmuxArgs.push(shell);
    }

    return new Promise((resolve, reject) => {
      console.log(`🔧 [DEBUG] Creating tmux session: ${sessionName}`);
      console.log(`📂 [DEBUG] Socket path: ${socketPath}`);
      console.log(`💾 [DEBUG] Working directory: ${this.workingDir}`);
      console.log(`🎨 [DEBUG] Terminal size: ${cols}x${rows} with 256 colors`);
      
      if (command) {
        console.log(`🚀 [DEBUG] Command: ${command} ${args.join(' ')}`);
      }
      
      console.log(`🔍 [DEBUG] Full tmux command: tmux ${tmuxArgs.join(' ')}`);

      const tmux = spawn('tmux', tmuxArgs, {
        stdio: 'pipe',
        cwd: this.workingDir,
        env: {
          ...process.env,
          TERM: 'xterm-256color',
          COLORTERM: 'truecolor',
          COLUMNS: cols.toString(),
          LINES: rows.toString(),
          TERMINAL_WIDTH: cols.toString(),
          TERMINAL_HEIGHT: rows.toString()
        }
      });

      let output = '';
      let error = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        error += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          const sessionInfo = {
            name: sessionName,
            socketPath: socketPath,
            outputFile: command ? outputFile : null,
            created: Date.now(),
            workingDir: this.workingDir,
            command: command,
            args: args
          };
          
          this.activeSessions.set(sessionName, sessionInfo);
          console.log(`✅ [DEBUG] Tmux session created successfully: ${sessionName}`);
          console.log(`🔧 [DEBUG] Active sessions count: ${this.activeSessions.size}`);
          resolve(sessionInfo);
        } else {
          console.error(`❌ [DEBUG] Failed to create tmux session (code: ${code}): ${error || 'Unknown error'}`);
          console.error(`📝 [DEBUG] Tmux output: ${output}`);
          reject(new Error(`Tmux session creation failed: ${error || output || 'Unknown error'}`));
        }
      });

      tmux.on('error', (err) => {
        console.error(`❌ Tmux spawn error: ${err.message}`);
        reject(err);
      });
    });
  }

  /**
   * Connect to an existing tmux session and return a PTY-like interface
   * Uses send-keys for input and capture-pane for output to keep session alive
   */
  async connectToSession(sessionName) {
    const sessionInfo = this.activeSessions.get(sessionName);
    if (!sessionInfo) {
      throw new Error(`Session ${sessionName} not found`);
    }

    const socketPath = sessionInfo.socketPath;
    
    // Verify session still exists
    const exists = await this.sessionExists(sessionName, socketPath);
    if (!exists) {
      this.activeSessions.delete(sessionName);
      throw new Error(`Session ${sessionName} no longer exists`);
    }

    console.log(`🔗 Connecting to tmux session: ${sessionName}`);

    // Use send-keys/capture-pane approach to keep session alive
    let isActive = true;
    let dataCallbacks = [];
    let exitCallbacks = [];
    let lastOutput = '';
    let currentScreenBuffer = '';
    let commandCompletedDetected = false;
    
    console.log(`🔌 [DEBUG] Starting tmux connection polling for session: ${sessionName}`);
    
    // Polling function to get session output
    const pollOutput = async () => {
      if (!isActive) return;
      
      try {
        // CRITICAL: Check if socket file still exists
        if (!fs.existsSync(socketPath)) {
          console.log(`🔌 [CRITICAL] Socket file deleted for session ${sessionName} - initiating shutdown`);
          isActive = false;

          // Try to read output file before cleanup (server console only)
          if (sessionInfo && sessionInfo.outputFile && fs.existsSync(sessionInfo.outputFile)) {
            try {
              const capturedOutput = fs.readFileSync(sessionInfo.outputFile, 'utf8');
              console.log('\n📄 [SERVER] Captured command output from file (socket deleted):');
              console.log('─'.repeat(60));
              const exitCodeMatch = capturedOutput.match(/EXIT_CODE:(\d+)/m);
              if (exitCodeMatch) {
                const exitCode = parseInt(exitCodeMatch[1], 10);
                const outputWithoutExit = capturedOutput.replace(/\nEXIT_CODE:\d+\s*$/, '');
                console.log(outputWithoutExit);
                console.log('─'.repeat(60));
                console.log(`📊 [SERVER] Command exit code: ${exitCode}`);
              } else {
                console.log(capturedOutput);
                console.log('─'.repeat(60));
              }
            } catch (err) {
              console.error(`[SERVER] Failed to read output file: ${err.message}`);
            }
          }

          this.activeSessions.delete(sessionName);
          this.cleanupOutputFile(sessionInfo);
          exitCallbacks.forEach(callback => callback({ exitCode: 0, signal: 'SOCKET_TERMINATED' }));
          // Trigger full application shutdown
          console.log('🛑 [SERVER] Socket terminated - shutting down application...');
          process.exit(0);
          return;
        }
        
        // Check if session still exists in tmux
        const exists = await this.sessionExists(sessionName, socketPath);
        if (!exists) {
          console.log(`🔌 [DEBUG] Session ${sessionName} no longer exists - terminating`);
          isActive = false;

          // Try to read output file before cleanup (server console only)
          let exitCode = 0;
          if (sessionInfo && sessionInfo.outputFile && fs.existsSync(sessionInfo.outputFile)) {
            try {
              const capturedOutput = fs.readFileSync(sessionInfo.outputFile, 'utf8');
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

              // Don't send captured output to terminal clients - let terminal close naturally
            } catch (err) {
              console.error(`[SERVER] Failed to read output file: ${err.message}`);
            }
          } else {
            console.log(`📊 [SERVER] Command exit code: ${exitCode}`);
          }

          this.activeSessions.delete(sessionName);
          this.cleanupSocket(socketPath);
          this.cleanupOutputFile(sessionInfo);
          exitCallbacks.forEach(callback => callback({ exitCode, signal: null }));
          // Trigger application shutdown when session ends
          console.log(`🛑 [SERVER] Tmux session terminated - shutting down application with exit code ${exitCode}...`);
          process.exit(exitCode);
          return;
        }
        
        // Check if the command has completed (pane is dead)
        const paneStatus = await this.isPaneDead(sessionName, socketPath);
        if (paneStatus.isDead && !commandCompletedDetected) {
          commandCompletedDetected = true;
          let exitCode = paneStatus.exitCode || 0;
          console.log(`🔌 [DEBUG] Command completed in session ${sessionName} - pane is dead`);

          // Read captured output from file if available (server console only)
          if (sessionInfo && sessionInfo.outputFile) {
            try {
              if (fs.existsSync(sessionInfo.outputFile)) {
                const capturedOutput = fs.readFileSync(sessionInfo.outputFile, 'utf8');
                console.log('\n📄 [SERVER] Captured command output from file:');
                console.log('─'.repeat(60));

                // Extract exit code from file (look for EXIT_CODE:N line)
                const exitCodeMatch = capturedOutput.match(/EXIT_CODE:(\d+)/m);
                if (exitCodeMatch) {
                  exitCode = parseInt(exitCodeMatch[1], 10);
                  // Display output without the EXIT_CODE line in server console
                  const outputWithoutExit = capturedOutput.replace(/\nEXIT_CODE:\d+\s*$/, '');
                  console.log(outputWithoutExit);
                } else {
                  console.log(capturedOutput);
                }

                console.log('─'.repeat(60));
                console.log(`📊 [SERVER] Claude-flow exit code: ${exitCode}`);

                // Don't send captured output to terminal - let it close naturally
              } else {
                console.log(`⚠️  [SERVER] Output file not found: ${sessionInfo.outputFile}`);
              }
            } catch (err) {
              console.error(`❌ [SERVER] Failed to read output file: ${err.message}`);
            }
          } else {
            console.log(`📊 [SERVER] Command exit code: ${exitCode}`);
          }

          // Command completed - trigger shutdown
          isActive = false;
          this.activeSessions.delete(sessionName);
          this.cleanupSocket(socketPath);
          this.cleanupOutputFile(sessionInfo);
          exitCallbacks.forEach(callback => callback({ exitCode, signal: 'COMMAND_COMPLETED' }));

          // Trigger full application shutdown
          console.log(`🛑 [SERVER] Command in tmux completed with exit code ${exitCode} - shutting down application...`);
          process.exit(exitCode); // Exit with the actual command exit code
          return;
        } else if (process.env.DEBUG_TMUX) {
          console.log(`🔌 [DEBUG] Pane status check: dead=${paneStatus.isDead}, session=${sessionName}`);
        }
        
        // Get current session output
        const output = await this.capturePane(sessionName, socketPath);
        
        // Update screen buffer for new connections
        currentScreenBuffer = await this.captureFullScreen(sessionName, socketPath);
        
        // FIXED: Send the entire screen on every update to handle overwrites and cursor movements
        // This ensures that any line modifications, including truncations or overwrites, are properly displayed
        if (output !== lastOutput) {
          // Clear the terminal and send the full current state
          // This handles cases where lines are overwritten or modified in place
          console.log(`🔌 [DEBUG] Screen changed, sending full update: ${output.length} bytes to ${dataCallbacks.length} clients`);
          
          // Send clear sequence followed by the full screen content
          // This ensures the terminal is in sync with the backend
          const clearAndUpdate = '\x1b[2J\x1b[H' + output; // Clear screen + move cursor home + full content
          dataCallbacks.forEach(callback => callback(clearAndUpdate));
          
          lastOutput = output;
        }
        
        // Continue polling
        setTimeout(pollOutput, 100);
      } catch (error) {
        console.error(`🔌 [DEBUG] Error polling session ${sessionName}: ${error.message}`);
        console.error(`🔌 [DEBUG] Error stack: ${error.stack}`);
        isActive = false;
        exitCallbacks.forEach(callback => callback({ exitCode: 1, signal: null }));
      }
    };

    // Create PTY-like interface
    const ptyInterface = {
      sessionName: sessionName,
      socketPath: socketPath,
      
      // Send input to tmux session
      write: (data) => {
        if (isActive) {
          console.log(`🔌 [DEBUG] Sending input to session ${sessionName}: ${data.length} bytes`);
          this.sendKeysToSession(sessionName, socketPath, data);
        } else {
          console.warn(`🔌 [DEBUG] Attempted to write to inactive session ${sessionName}`);
        }
      },
      
      // Handle data from tmux session
      onData: (callback) => {
        console.log(`🔌 [DEBUG] Adding data callback for session ${sessionName} (total: ${dataCallbacks.length + 1})`);
        dataCallbacks.push(callback);
        
        // Send current screen buffer to new connection immediately
        this.captureFullScreen(sessionName, socketPath)
          .then(screenBuffer => {
            if (screenBuffer && screenBuffer.trim()) {
              console.log(`🔌 [DEBUG] Sending current screen buffer to new client: ${screenBuffer.length} bytes`);
              callback(screenBuffer);
            }
          })
          .catch(err => {
            console.warn(`🔌 [DEBUG] Failed to capture screen buffer for new client: ${err.message}`);
          });
        
        // Start polling on first callback
        if (dataCallbacks.length === 1) {
          console.log(`🔌 [DEBUG] Starting polling for session ${sessionName}`);
          setTimeout(pollOutput, 100);
        }
      },
      
      // Handle session exit
      onExit: (callback) => {
        exitCallbacks.push(callback);
      },
      
      // Resize tmux session
      resize: (cols, rows) => {
        if (isActive) {
          console.log(`🔧 [DEBUG] Resizing tmux session ${sessionName} to ${cols}x${rows}`);
          spawn('tmux', [
            '-S', socketPath,
            'resize-window',
            '-t', sessionName,
            '-x', cols.toString(),
            '-y', rows.toString()
          ], { stdio: 'ignore' });
        } else {
          console.warn(`⚠️ [DEBUG] Cannot resize inactive session ${sessionName}`);
        }
      },
      
      // Clean shutdown
      cleanup: () => {
        console.log(`🔌 [DEBUG] Cleaning up session ${sessionName}`);
        isActive = false;
        dataCallbacks = [];
        exitCallbacks = [];
      }
    };

    return ptyInterface;
  }

  /**
   * Capture pane content from tmux session with error handling
   */
  async capturePane(sessionName, socketPath) {
    return new Promise((resolve, reject) => {
      // First validate session exists
      this.sessionExists(sessionName, socketPath)
        .then(exists => {
          if (!exists) {
            throw new Error(`Session ${sessionName} does not exist`);
          }
          
          const tmux = spawn('tmux', [
            '-S', socketPath,
            'capture-pane',
            '-t', sessionName,
            '-e',  // Include escape sequences for color/formatting preservation
            '-p'
          ], { stdio: 'pipe', timeout: 3000 });

          let output = '';
          let errorOutput = '';

          const timeoutHandle = setTimeout(() => {
            tmux.kill('SIGKILL');
            reject(new Error('Capture pane timed out'));
          }, 3000);

          tmux.stdout.on('data', (data) => {
            output += data.toString();
          });

          tmux.stderr.on('data', (data) => {
            errorOutput += data.toString();
          });

          tmux.on('exit', (code) => {
            clearTimeout(timeoutHandle);
            if (code === 0) {
              // Only log in debug mode to avoid spamming logs
              if (process.env.DEBUG_TMUX) {
                console.log(`[TmuxManager] Pane capture successful for session ${sessionName} (${output.length} bytes)`);
              }
              resolve(output);
            } else {
              console.error(`[TmuxManager] Pane capture failed with code ${code}: ${errorOutput}`);
              reject(new Error(`Failed to capture pane: code ${code}, error: ${errorOutput || 'unknown error'}`));
            }
          });

          tmux.on('error', (err) => {
            clearTimeout(timeoutHandle);
            console.error(`[TmuxManager] Pane capture spawn error: ${err.message}`);
            reject(err);
          });
        })
        .catch(validationError => {
          console.error(`[TmuxManager] Pane capture session validation failed: ${validationError.message}`);
          reject(validationError);
        });
    });
  }

  /**
   * Capture the full terminal history from tmux session with robust error handling
   */
  async captureFullScreen(sessionName, socketPath, rows = 40, retryCount = 0) {
    const maxRetries = 3;
    const timeout = 5000; // 5 second timeout
    
    return new Promise((resolve, reject) => {
      // First validate that the session exists
      this.sessionExists(sessionName, socketPath)
        .then(exists => {
          if (!exists) {
            throw new Error(`Session ${sessionName} does not exist`);
          }
          
          // Only log capture attempts in debug mode or on retries
          if (process.env.DEBUG_TMUX || retryCount > 0) {
            console.log(`[TmuxManager] Capturing full screen for session ${sessionName} (attempt ${retryCount + 1}/${maxRetries + 1})`);
          }
          
          const tmuxArgs = [
            '-S', socketPath,
            'capture-pane',
            '-t', sessionName,
            '-S', '-',    // Start from beginning of history
            '-E', '-',    // End at end of history (entire scrollback)
            '-e',         // Include escape sequences for color/formatting preservation
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
              console.warn(`[TmuxManager] Tmux capture timed out for session ${sessionName}, killing process`);
              tmux.kill('SIGKILL');
              processCompleted = true;
              
              // Try fallback capture method
              this.fallbackCapture(sessionName, socketPath)
                .then(fallbackOutput => {
                  console.log(`[TmuxManager] Fallback capture succeeded for session ${sessionName}`);
                  resolve(fallbackOutput);
                })
                .catch(fallbackError => {
                  console.error(`[TmuxManager] Fallback capture also failed: ${fallbackError.message}`);
                  if (retryCount < maxRetries) {
                    console.log(`[TmuxManager] Retrying capture for session ${sessionName} (${retryCount + 1}/${maxRetries})`);
                    setTimeout(() => {
                      this.captureFullScreen(sessionName, socketPath, rows, retryCount + 1)
                        .then(resolve)
                        .catch(reject);
                    }, 1000 * (retryCount + 1)); // Exponential backoff
                  } else {
                    reject(new Error(`Failed to capture full screen after ${maxRetries} retries: timeout`));
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
                console.log(`[TmuxManager] Full screen capture successful for session ${sessionName} (${output.length} bytes)`);
              }
              resolve(output);
            } else {
              console.error(`[TmuxManager] Tmux capture failed with code ${code} for session ${sessionName}: ${errorOutput}`);
              
              // Try fallback methods before failing
              this.fallbackCapture(sessionName, socketPath)
                .then(fallbackOutput => {
                  console.log(`[TmuxManager] Fallback capture succeeded after tmux failed with code ${code}`);
                  resolve(fallbackOutput);
                })
                .catch(fallbackError => {
                  console.error(`[TmuxManager] Fallback capture also failed: ${fallbackError.message}`);
                  if (retryCount < maxRetries && this.shouldRetryError(code, errorOutput)) {
                    console.log(`[TmuxManager] Retrying capture for session ${sessionName} due to recoverable error`);
                    setTimeout(() => {
                      this.captureFullScreen(sessionName, socketPath, rows, retryCount + 1)
                        .then(resolve)
                        .catch(reject);
                    }, 1000 * (retryCount + 1)); // Exponential backoff
                  } else {
                    reject(new Error(`Failed to capture full screen: code ${code}, error: ${errorOutput || 'unknown error'}`));
                  }
                });
            }
          });

          tmux.on('error', (err) => {
            if (processCompleted) return;
            processCompleted = true;
            clearTimeout(timeoutHandle);
            
            console.error(`[TmuxManager] Tmux spawn error for session ${sessionName}: ${err.message}`);
            
            // Try fallback capture on spawn error
            this.fallbackCapture(sessionName, socketPath)
              .then(fallbackOutput => {
                console.log(`[TmuxManager] Fallback capture succeeded after spawn error`);
                resolve(fallbackOutput);
              })
              .catch(fallbackError => {
                console.error(`[TmuxManager] Fallback capture also failed: ${fallbackError.message}`);
                if (retryCount < maxRetries) {
                  console.log(`[TmuxManager] Retrying capture for session ${sessionName} after spawn error`);
                  setTimeout(() => {
                    this.captureFullScreen(sessionName, socketPath, rows, retryCount + 1)
                      .then(resolve)
                      .catch(reject);
                  }, 2000 * (retryCount + 1)); // Longer delay for spawn errors
                } else {
                  reject(new Error(`Failed to capture full screen after ${maxRetries} retries: ${err.message}`));
                }
              });
          });
        })
        .catch(validationError => {
          console.error(`[TmuxManager] Session validation failed for ${sessionName}: ${validationError.message}`);
          reject(new Error(`Session validation failed: ${validationError.message}`));
        });
    });
  }

  /**
   * Send keys to tmux session
   */
  sendKeysToSession(sessionName, socketPath, data) {
    spawn('tmux', [
      '-S', socketPath,
      'send-keys',
      '-t', sessionName,
      '-l',
      data
    ], { stdio: 'ignore' });
  }

  // Remove capture and send-keys methods - direct attach handles this

  /**
   * Check if a tmux session exists
   */
  async sessionExists(sessionName, socketPath) {
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'has-session',
        '-t', sessionName
      ], { stdio: 'pipe' });

      tmux.on('exit', (code) => {
        resolve(code === 0);
      });

      tmux.on('error', () => {
        resolve(false);
      });
    });
  }

  /**
   * Kill a tmux session
   */
  async killSession(sessionName) {
    const sessionInfo = this.activeSessions.get(sessionName);
    if (!sessionInfo) {
      console.warn(`Session ${sessionName} not found in active sessions`);
      return;
    }

    const socketPath = sessionInfo.socketPath;

    return new Promise((resolve) => {
      console.log(`🔥 Killing tmux session: ${sessionName}`);
      
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'kill-session',
        '-t', sessionName
      ], { stdio: 'pipe' });

      tmux.on('exit', (code) => {
        this.activeSessions.delete(sessionName);
        this.cleanupSocket(socketPath);
        console.log(`✅ Tmux session ${sessionName} killed (code: ${code})`);
        resolve();
      });

      tmux.on('error', (err) => {
        console.error(`❌ Error killing tmux session: ${err.message}`);
        resolve(); // Don't fail, just continue cleanup
      });
    });
  }

  /**
   * Clean up socket file
   */
  cleanupSocket(socketPath) {
    try {
      if (fs.existsSync(socketPath)) {
        fs.unlinkSync(socketPath);
        console.log(`🧹 Cleaned up socket: ${socketPath}`);
      }
    } catch (error) {
      console.warn(`⚠️  Failed to clean up socket ${socketPath}: ${error.message}`);
    }
  }

  /**
   * Clean up output file
   */
  cleanupOutputFile(sessionInfo) {
    if (!sessionInfo || !sessionInfo.outputFile) return;

    try {
      if (fs.existsSync(sessionInfo.outputFile)) {
        fs.unlinkSync(sessionInfo.outputFile);
        console.log(`🧹 Cleaned up output file: ${sessionInfo.outputFile}`);
      }
    } catch (error) {
      console.warn(`⚠️  Failed to clean up output file ${sessionInfo.outputFile}: ${error.message}`);
    }
  }

  /**
   * List all active sessions
   */
  getActiveSessions() {
    return Array.from(this.activeSessions.values());
  }

  /**
   * Clean up all sessions and sockets
   */
  async cleanup() {
    console.log('🧹 Cleaning up all tmux sessions...');
    
    // Set a timeout for cleanup to prevent hanging
    const cleanupTimeout = setTimeout(() => {
      console.log('⚠️ Cleanup timeout reached, forcing exit...');
      process.exit(1);
    }, 3000); // 3 second timeout for cleanup
    
    try {
      const sessions = Array.from(this.activeSessions.keys());
      
      // Kill all sessions in parallel with timeout
      const killPromises = sessions.map(sessionName => {
        return Promise.race([
          this.killSession(sessionName).catch(err => {
            console.error(`Error killing session ${sessionName}:`, err.message);
          }),
          new Promise(resolve => setTimeout(resolve, 1000)) // 1 second timeout per session
        ]);
      });
      
      await Promise.all(killPromises);

      // SecureTempDir will handle cleanup of socket directory
      // Just clean up any remaining socket files and output files we know about
      for (const [sessionName, sessionInfo] of this.activeSessions) {
        try {
          this.cleanupSocket(sessionInfo.socketPath);
          this.cleanupOutputFile(sessionInfo);
        } catch (err) {
          // Ignore cleanup errors during shutdown
        }
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    } finally {
      clearTimeout(cleanupTimeout);
    }
  }

  /**
   * Send a command to an existing tmux session
   */
  async sendCommand(sessionName, command) {
    const sessionInfo = this.activeSessions.get(sessionName);
    if (!sessionInfo) {
      throw new Error(`Session ${sessionName} not found`);
    }

    const socketPath = sessionInfo.socketPath;

    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'send-keys',
        '-t', sessionName,
        command,
        'Enter'
      ], { stdio: 'pipe' });

      tmux.on('exit', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Failed to send command to session ${sessionName}`));
        }
      });
    });
  }

  /**
   * Fallback capture method using different tmux options
   */
  async fallbackCapture(sessionName, socketPath) {
    console.log(`[TmuxManager] Attempting fallback capture methods for session ${sessionName}`);
    
    // Try different capture strategies in order of preference
    const strategies = [
      // Strategy 1: Basic capture without history
      {
        name: 'basic-capture',
        args: ['-S', socketPath, 'capture-pane', '-t', sessionName, '-p']
      },
      // Strategy 2: Capture with limited history
      {
        name: 'limited-history',
        args: ['-S', socketPath, 'capture-pane', '-t', sessionName, '-S', '-10', '-p']
      },
      // Strategy 3: Capture current screen only
      {
        name: 'current-screen',
        args: ['-S', socketPath, 'capture-pane', '-t', sessionName, '-S', '0', '-E', '0', '-p']
      },
      // Strategy 4: List windows as last resort
      {
        name: 'list-windows',
        args: ['-S', socketPath, 'list-windows', '-t', sessionName]
      }
    ];

    for (const strategy of strategies) {
      try {
        console.log(`[TmuxManager] Trying fallback strategy: ${strategy.name}`);
        const output = await this.executeWithTimeout('tmux', strategy.args, 3000);
        if (output && output.trim()) {
          console.log(`[TmuxManager] Fallback strategy ${strategy.name} succeeded (${output.length} bytes)`);
          return output;
        }
      } catch (error) {
        console.warn(`[TmuxManager] Fallback strategy ${strategy.name} failed: ${error.message}`);
        continue;
      }
    }
    
    // If all strategies fail, return a minimal error message
    throw new Error('All fallback capture strategies failed');
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
            console.log(`💀 Pane is dead in session ${sessionName} with exit code: ${exitCode}`);

            // Store exit code in session info
            const sessionInfo = this.activeSessions.get(sessionName);
            if (sessionInfo) {
              sessionInfo.exitCode = exitCode;
              sessionInfo.commandCompleted = true;
              sessionInfo.completedAt = Date.now();
            }

            resolve({ isDead: true, exitCode });
          } else {
            resolve({ isDead: false, exitCode: null });
          }
        } else {
          // If we can't check pane status, assume it's still alive
          resolve({ isDead: false, exitCode: null });
        }
      });

      tmux.on('error', () => {
        // On error, assume pane is still alive
        resolve({ isDead: false, exitCode: null });
      });
    });
  }

  /**
   * Monitor socket file for deletion
   */
  monitorSocketFile(socketPath, callback) {
    const checkInterval = setInterval(() => {
      if (!fs.existsSync(socketPath)) {
        clearInterval(checkInterval);
        console.log(`🔌 Socket file deleted: ${socketPath}`);
        callback();
      }
    }, 500); // Check every 500ms
    
    return checkInterval;
  }
}

module.exports = TmuxManager;