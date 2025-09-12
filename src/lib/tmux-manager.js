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

class TmuxManager {
  constructor(workingDir = process.cwd()) {
    this.workingDir = workingDir;
    // Use /tmp for sockets to avoid path length issues
    this.socketDir = path.join('/tmp', '.claude-flow-sockets');
    this.sessionPrefix = 'cf'; // Shorter prefix to avoid path length issues
    this.activeSessions = new Map();
    
    // Ensure socket directory exists
    this.ensureSocketDir();
  }

  /**
   * Ensure the socket directory exists
   */
  ensureSocketDir() {
    if (!fs.existsSync(this.socketDir)) {
      fs.mkdirSync(this.socketDir, { recursive: true });
      console.log(`📁 Created tmux socket directory: ${this.socketDir}`);
    }
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
    return path.join(this.socketDir, `${sessionName}.sock`);
  }

  /**
   * Create a new tmux session
   */
  async createSession(sessionName = null, command = null, args = [], cols = 80, rows = 24) {
    if (!sessionName) {
      sessionName = this.generateSessionName();
    }

    const socketPath = this.getSocketPath(sessionName);
    
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

    // If command is provided, run it in a shell that stays open after completion
    if (command) {
      const shell = process.env.SHELL || '/bin/bash';
      if (Array.isArray(args) && args.length > 0) {
        // Create a command that runs the specified command then keeps shell open
        // Use exec to replace the shell process but keep it interactive
        const fullCommand = `${command} ${args.map(arg => `"${arg}"`).join(' ')}; echo "\\n🔄 Command completed. Shell remains open for interaction."; exec ${shell} -i`;
        tmuxArgs.push(shell, '-c', fullCommand);
      } else {
        const fullCommand = `${command}; echo "\\n🔄 Command completed. Shell remains open for interaction."; exec ${shell} -i`;
        tmuxArgs.push(shell, '-c', fullCommand);
      }
    }

    return new Promise((resolve, reject) => {
      console.log(`🔧 [DEBUG] Creating tmux session: ${sessionName}`);
      console.log(`📂 [DEBUG] Socket path: ${socketPath}`);
      console.log(`💾 [DEBUG] Working directory: ${this.workingDir}`);
      console.log(`🎨 [DEBUG] Terminal size: ${cols}x${rows} with 256 colors`);
      
      if (command) {
        console.log(`🚀 [DEBUG] Command: ${command} ${args.join(' ')}`);
      }

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
    
    console.log(`🔌 [DEBUG] Starting tmux connection polling for session: ${sessionName}`);
    
    // Polling function to get session output
    const pollOutput = async () => {
      if (!isActive) return;
      
      try {
        // Check if session still exists
        const exists = await this.sessionExists(sessionName, socketPath);
        if (!exists) {
          console.log(`🔌 [DEBUG] Session ${sessionName} no longer exists - terminating`);
          isActive = false;
          this.activeSessions.delete(sessionName);
          this.cleanupSocket(socketPath);
          exitCallbacks.forEach(callback => callback({ exitCode: 0, signal: null }));
          return;
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
   * Capture pane content from tmux session
   */
  async capturePane(sessionName, socketPath) {
    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-e',  // Include escape sequences for color/formatting preservation
        '-p'
      ], { stdio: 'pipe' });

      let output = '';
      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          resolve(output);
        } else {
          reject(new Error(`Failed to capture pane`));
        }
      });

      tmux.on('error', reject);
    });
  }

  /**
   * Capture the full terminal history from tmux session
   */
  async captureFullScreen(sessionName, socketPath, rows = 40) {
    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-S', '-',    // Start from beginning of history
        '-E', '-',    // End at end of history (entire scrollback)
        '-e',         // Include escape sequences for color/formatting preservation
        '-p'          // Print to stdout
      ], { stdio: 'pipe' });

      let output = '';
      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          // Return entire terminal history without trimming
          resolve(output);
        } else {
          reject(new Error(`Failed to capture full screen`));
        }
      });

      tmux.on('error', reject);
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
    
    const sessions = Array.from(this.activeSessions.keys());
    for (const sessionName of sessions) {
      await this.killSession(sessionName);
    }

    // Clean up any remaining socket files
    try {
      if (fs.existsSync(this.socketDir)) {
        const files = fs.readdirSync(this.socketDir);
        for (const file of files) {
          if (file.endsWith('.sock')) {
            const socketPath = path.join(this.socketDir, file);
            this.cleanupSocket(socketPath);
          }
        }
      }
    } catch (error) {
      console.warn(`⚠️  Error during socket cleanup: ${error.message}`);
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
}

module.exports = TmuxManager;