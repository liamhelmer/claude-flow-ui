/**
 * Secure Temporary Directory Management
 * Creates and manages secure temporary directories with proper permissions
 * and collision detection for socket files and other temporary data
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class SecureTempDir {
  constructor() {
    this.baseDir = null;
    this.sessionDir = null;
    this.initialized = false;
    this.sessionId = this.generateSessionId();
  }

  /**
   * Generate a unique session ID for this instance
   */
  generateSessionId() {
    // Simpler, shorter session ID: sess-XXXXXXXX
    return `sess-${crypto.randomBytes(4).toString('hex')}`;
  }

  /**
   * Get OS-specific temp directory paths in order of preference
   */
  getTempDirCandidates() {
    const candidates = [];
    
    // 1. Use TMPDIR environment variable if set
    if (process.env.TMPDIR) {
      candidates.push(process.env.TMPDIR);
    }
    
    // 2. Use TEMP or TMP on Windows
    if (process.platform === 'win32') {
      if (process.env.TEMP) candidates.push(process.env.TEMP);
      if (process.env.TMP) candidates.push(process.env.TMP);
    }
    
    // 3. Use XDG_RUNTIME_DIR on Linux (more secure for sockets)
    if (process.env.XDG_RUNTIME_DIR) {
      candidates.push(process.env.XDG_RUNTIME_DIR);
    }
    
    // 4. Use Node's os.tmpdir() as fallback
    candidates.push(os.tmpdir());
    
    // 5. Platform-specific fallbacks
    if (process.platform === 'darwin' || process.platform === 'linux') {
      candidates.push('/tmp');
      candidates.push('/var/tmp');
    }
    
    // 6. User home directory as last resort
    const homeDir = os.homedir();
    if (homeDir) {
      candidates.push(path.join(homeDir, '.cache'));
      candidates.push(path.join(homeDir, '.tmp'));
    }
    
    // Remove duplicates and non-existent directories
    const unique = [...new Set(candidates)];
    return unique.filter(dir => {
      try {
        return fs.existsSync(dir) && fs.statSync(dir).isDirectory();
      } catch {
        return false;
      }
    });
  }

  /**
   * Check if a directory is writable and has proper permissions
   */
  isDirectorySecure(dirPath) {
    try {
      // Check if directory exists and is writable
      fs.accessSync(dirPath, fs.constants.W_OK | fs.constants.R_OK | fs.constants.X_OK);
      
      const stats = fs.statSync(dirPath);
      
      // Check ownership (should be owned by current user)
      if (process.platform !== 'win32') {
        if (stats.uid !== process.getuid()) {
          console.warn(`[SecureTemp] Directory ${dirPath} not owned by current user`);
          return false;
        }
      }
      
      // Check permissions (should not be world-writable)
      const mode = stats.mode & parseInt('777', 8);
      if (mode & 0o002) {
        console.warn(`[SecureTemp] Directory ${dirPath} is world-writable (mode: ${mode.toString(8)})`);
      }
      
      return true;
    } catch (error) {
      console.error(`[SecureTemp] Cannot access directory ${dirPath}: ${error.message}`);
      return false;
    }
  }

  /**
   * Create a secure directory with proper permissions
   */
  createSecureDirectory(dirPath, mode = 0o700) {
    try {
      if (!fs.existsSync(dirPath)) {
        // Create directory with restricted permissions
        fs.mkdirSync(dirPath, { 
          recursive: true, 
          mode: mode 
        });
        
        // Double-check permissions were set correctly
        if (process.platform !== 'win32') {
          fs.chmodSync(dirPath, mode);
        }
        
        console.log(`[SecureTemp] Created secure directory: ${dirPath} (mode: ${mode.toString(8)})`);
      } else {
        // Directory exists, ensure permissions are correct
        if (process.platform !== 'win32') {
          const stats = fs.statSync(dirPath);
          const currentMode = stats.mode & parseInt('777', 8);
          if (currentMode !== mode) {
            fs.chmodSync(dirPath, mode);
            console.log(`[SecureTemp] Fixed permissions on ${dirPath}: ${currentMode.toString(8)} -> ${mode.toString(8)}`);
          }
        }
      }
      
      return true;
    } catch (error) {
      console.error(`[SecureTemp] Failed to create secure directory ${dirPath}: ${error.message}`);
      return false;
    }
  }

  /**
   * Find or create a secure base directory for Claude Flow
   */
  initializeBaseDir() {
    if (this.baseDir && fs.existsSync(this.baseDir)) {
      return this.baseDir;
    }
    
    const candidates = this.getTempDirCandidates();
    
    for (const candidate of candidates) {
      if (!this.isDirectorySecure(candidate)) {
        continue;
      }
      
      // Use simpler directory structure: tmux-term
      const tmuxTermDir = path.join(candidate, 'tmux-term');
      
      try {
        // Try to create or use existing directory
        if (!fs.existsSync(tmuxTermDir)) {
          if (this.createSecureDirectory(tmuxTermDir, 0o700)) {
            this.baseDir = tmuxTermDir;
            if (process.env.DEBUG_TMUX) {
              console.log(`[SecureTemp] Created base directory: ${this.baseDir}`);
            }
            return this.baseDir;
          }
        } else if (this.isDirectorySecure(tmuxTermDir)) {
          // Directory exists and is secure, use it
          this.baseDir = tmuxTermDir;
          if (process.env.DEBUG_TMUX) {
            console.log(`[SecureTemp] Using existing base directory: ${this.baseDir}`);
          }
          return this.baseDir;
        }
      } catch (error) {
        console.warn(`[SecureTemp] Failed to use ${tmuxTermDir}: ${error.message}`);
      }
    }
    
    throw new Error('Failed to create secure temporary directory after trying all candidates');
  }

  /**
   * Initialize session-specific directory
   */
  initializeSessionDir() {
    if (!this.baseDir) {
      this.initializeBaseDir();
    }
    
    if (this.sessionDir && fs.existsSync(this.sessionDir)) {
      return this.sessionDir;
    }
    
    // Simpler structure: directly under base dir with session ID
    const sessionPath = path.join(this.baseDir, this.sessionId);
    
    if (this.createSecureDirectory(sessionPath, 0o700)) {
      this.sessionDir = sessionPath;
      if (process.env.DEBUG_TMUX) {
        console.log(`[SecureTemp] Created session directory: ${this.sessionDir}`);
      }
      
      // Simplified: no subdirectories, use session dir directly
      
      return this.sessionDir;
    }
    
    throw new Error(`Failed to create session directory: ${sessionPath}`);
  }

  /**
   * Get the socket directory for tmux and other IPC
   */
  getSocketDir() {
    if (!this.sessionDir) {
      this.initializeSessionDir();
    }
    // Use session directory directly for sockets
    return this.sessionDir;
  }

  /**
   * Get the logs directory
   */
  getLogDir() {
    if (!this.sessionDir) {
      this.initializeSessionDir();
    }
    // Use session directory directly
    return this.sessionDir;
  }

  /**
   * Get the cache directory
   */
  getCacheDir() {
    if (!this.sessionDir) {
      this.initializeSessionDir();
    }
    // Use session directory directly
    return this.sessionDir;
  }

  /**
   * Create a unique temporary file with collision detection
   */
  createTempFile(prefix = 'tmp', extension = '') {
    const dir = this.getCacheDir();
    
    for (let attempt = 0; attempt < 100; attempt++) {
      const filename = `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${extension}`;
      const filepath = path.join(dir, filename);
      
      try {
        // Use exclusive flag to prevent overwriting
        const fd = fs.openSync(filepath, 'wx', 0o600);
        fs.closeSync(fd);
        return filepath;
      } catch (error) {
        if (error.code !== 'EEXIST') {
          throw error;
        }
        // File exists, try again with different name
      }
    }
    
    throw new Error('Failed to create unique temp file after 100 attempts');
  }

  /**
   * Clean up old session directories (older than 24 hours)
   */
  cleanupOldSessions() {
    if (!this.baseDir) {
      return;
    }
    
    // Sessions are now directly under base dir
    const sessionsDir = this.baseDir;
    if (!fs.existsSync(sessionsDir)) {
      return;
    }
    
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    try {
      const sessions = fs.readdirSync(sessionsDir);
      
      for (const session of sessions) {
        if (session === this.sessionId) {
          continue; // Don't delete current session
        }
        
        const sessionPath = path.join(sessionsDir, session);
        const stats = fs.statSync(sessionPath);
        
        if (now - stats.mtimeMs > maxAge) {
          this.removeDirectory(sessionPath);
          if (process.env.DEBUG_TMUX) {
            console.log(`[SecureTemp] Cleaned up old session: ${session}`);
          }
        }
      }
    } catch (error) {
      console.warn(`[SecureTemp] Error during cleanup: ${error.message}`);
    }
  }

  /**
   * Recursively remove a directory
   */
  removeDirectory(dirPath) {
    if (fs.existsSync(dirPath)) {
      fs.readdirSync(dirPath).forEach(file => {
        const curPath = path.join(dirPath, file);
        if (fs.lstatSync(curPath).isDirectory()) {
          this.removeDirectory(curPath);
        } else {
          fs.unlinkSync(curPath);
        }
      });
      fs.rmdirSync(dirPath);
    }
  }

  /**
   * Clean up current session on exit
   */
  cleanup() {
    if (this.sessionDir && fs.existsSync(this.sessionDir)) {
      try {
        this.removeDirectory(this.sessionDir);
        if (process.env.DEBUG_TMUX) {
          console.log(`[SecureTemp] Cleaned up session directory: ${this.sessionDir}`);
        }
      } catch (error) {
        console.error(`[SecureTemp] Failed to cleanup session: ${error.message}`);
      }
    }
  }

  /**
   * Get platform-specific socket name with collision detection
   */
  getSocketPath(name) {
    const socketDir = this.getSocketDir();
    
    // Ensure socket name is safe and unique
    const safeName = name.replace(/[^a-zA-Z0-9-_]/g, '-');
    
    // Check if we need to use a shorter path due to Unix socket limitations
    const baseSocketPath = path.join(socketDir, `${safeName}.sock`);
    
    // Unix socket path limit is typically 104-108 characters
    if (baseSocketPath.length > 100 && process.platform !== 'win32') {
      // Use /tmp/tmux-term directly for shorter paths
      const shortDir = '/tmp/tmux-term';
      if (!fs.existsSync(shortDir)) {
        this.createSecureDirectory(shortDir, 0o700);
      }
      
      // Use simpler naming: first 8 chars of session ID + counter
      const shortName = `${this.sessionId.substring(0, 8)}-${safeName.substring(0, 8)}`;
      const shortPath = path.join(shortDir, `${shortName}.sock`);
      
      if (process.env.DEBUG_TMUX) {
        console.log(`[SecureTemp] Path too long (${baseSocketPath.length} chars), using: ${shortPath}`);
      }
      return shortPath;
    }
    
    for (let attempt = 0; attempt < 10; attempt++) {
      const suffix = attempt === 0 ? '' : `-${attempt}`;
      const socketName = `${safeName}${suffix}.sock`;
      const socketPath = path.join(socketDir, socketName);
      
      if (!fs.existsSync(socketPath)) {
        return socketPath;
      }
      
      // Socket exists, check if it's stale
      try {
        // Try to connect to see if it's active
        const net = require('net');
        const client = net.createConnection(socketPath);
        
        client.on('error', () => {
          // Socket is stale, remove it
          try {
            fs.unlinkSync(socketPath);
            if (process.env.DEBUG_TMUX) {
              console.log(`[SecureTemp] Removed stale socket: ${socketPath}`);
            }
          } catch {
            // Ignore cleanup errors
          }
        });
        
        client.destroy();
      } catch {
        // Ignore connection test errors
      }
    }
    
    throw new Error(`Failed to find available socket name for ${name}`);
  }

  /**
   * Get information about the temp directory setup
   */
  getInfo() {
    return {
      sessionId: this.sessionId,
      baseDir: this.baseDir,
      sessionDir: this.sessionDir,
      socketDir: this.getSocketDir(),
      logDir: this.getLogDir(),
      cacheDir: this.getCacheDir(),
      platform: process.platform,
      tempDirCandidates: this.getTempDirCandidates()
    };
  }
}

// Create singleton instance
let instance = null;

module.exports = {
  /**
   * Get the singleton instance of SecureTempDir
   */
  getInstance: () => {
    if (!instance) {
      instance = new SecureTempDir();
      
      // Set up cleanup on exit
      process.on('exit', () => {
        if (instance) {
          instance.cleanup();
        }
      });
      
      process.on('SIGINT', () => {
        if (instance) {
          instance.cleanup();
        }
        process.exit(0);
      });
      
      process.on('SIGTERM', () => {
        if (instance) {
          instance.cleanup();
        }
        process.exit(0);
      });
      
      // Run cleanup of old sessions periodically
      setInterval(() => {
        if (instance) {
          instance.cleanupOldSessions();
        }
      }, 60 * 60 * 1000); // Every hour
    }
    return instance;
  },
  
  SecureTempDir
};