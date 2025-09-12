#!/usr/bin/env node

/**
 * Enhanced Screen Capture Module
 * 
 * This module provides robust screen capture functionality with comprehensive
 * error handling, fallback strategies, and cross-platform compatibility.
 * 
 * Addresses the "Failed to capture screen: 1" error with:
 * 1. Session validation before capture attempts
 * 2. Multiple fallback capture strategies
 * 3. Retry logic with exponential backoff
 * 4. Graceful degradation
 * 5. Detailed error reporting
 * 6. Platform-specific optimizations
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

class EnhancedScreenCapture {
  constructor(options = {}) {
    this.options = {
      maxRetries: options.maxRetries || 3,
      retryDelay: options.retryDelay || 100, // Base delay in ms
      timeout: options.timeout || 5000, // Command timeout in ms
      fallbackEnabled: options.fallbackEnabled !== false,
      logLevel: options.logLevel || 'info', // 'debug', 'info', 'warn', 'error'
      sessionValidation: options.sessionValidation !== false,
      ...options
    };
    
    // Platform-specific optimizations
    this.isWindows = process.platform === 'win32';
    this.isDarwin = process.platform === 'darwin';
    this.isLinux = process.platform === 'linux';
    
    // Capture statistics
    this.stats = {
      totalCaptures: 0,
      successfulCaptures: 0,
      failedCaptures: 0,
      fallbackUsed: 0,
      retriesUsed: 0,
      avgCaptureTime: 0
    };
  }

  /**
   * Log messages based on log level
   */
  log(level, message, ...args) {
    const levels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = levels.indexOf(this.options.logLevel);
    const messageLevelIndex = levels.indexOf(level);
    
    if (messageLevelIndex >= currentLevelIndex) {
      const prefix = `[EnhancedCapture] ${level.toUpperCase()}:`;
      console.log(prefix, message, ...args);
    }
  }

  /**
   * Validate session exists and is accessible
   */
  async validateSession(sessionName, socketPath) {
    this.log('debug', `Validating session: ${sessionName}`);
    
    try {
      // Check if socket exists
      if (!fs.existsSync(socketPath)) {
        throw new Error(`Socket file does not exist: ${socketPath}`);
      }

      // Check socket permissions
      try {
        fs.accessSync(socketPath, fs.constants.R_OK | fs.constants.W_OK);
      } catch (err) {
        throw new Error(`Socket is not accessible: ${socketPath} - ${err.message}`);
      }

      // Check if tmux session exists
      const hasSession = await this.checkSessionExists(sessionName, socketPath);
      if (!hasSession) {
        throw new Error(`Session does not exist: ${sessionName}`);
      }

      this.log('debug', `Session validation successful: ${sessionName}`);
      return true;
    } catch (err) {
      this.log('warn', `Session validation failed: ${err.message}`);
      throw err;
    }
  }

  /**
   * Check if tmux session exists
   */
  async checkSessionExists(sessionName, socketPath) {
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', socketPath,
        'has-session',
        '-t', sessionName
      ], { 
        stdio: 'pipe',
        timeout: this.options.timeout
      });

      const timer = setTimeout(() => {
        tmux.kill('SIGKILL');
        resolve(false);
      }, this.options.timeout);

      tmux.on('exit', (code) => {
        clearTimeout(timer);
        resolve(code === 0);
      });

      tmux.on('error', () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
  }

  /**
   * Execute tmux command with timeout and error handling
   */
  async executeTmuxCommand(args, description = 'tmux command') {
    return new Promise((resolve, reject) => {
      this.log('debug', `Executing ${description}:`, args.join(' '));
      
      const startTime = Date.now();
      const tmux = spawn('tmux', args, { 
        stdio: 'pipe',
        timeout: this.options.timeout
      });

      let output = '';
      let errorOutput = '';
      let resolved = false;

      // Set up timeout
      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          tmux.kill('SIGKILL');
          reject(new Error(`Command timeout after ${this.options.timeout}ms: ${description}`));
        }
      }, this.options.timeout);

      // Collect stdout
      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      // Collect stderr
      tmux.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      // Handle exit
      tmux.on('exit', (code) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          
          const duration = Date.now() - startTime;
          this.log('debug', `Command completed in ${duration}ms with code ${code}`);
          
          if (code === 0) {
            resolve({ output, duration, code });
          } else {
            const error = new Error(`Command failed with code ${code}: ${errorOutput || 'No error details'}`);
            error.code = code;
            error.stderr = errorOutput;
            error.stdout = output;
            reject(error);
          }
        }
      });

      // Handle spawn errors
      tmux.on('error', (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          reject(new Error(`Command spawn error: ${err.message}`));
        }
      });
    });
  }

  /**
   * Primary capture strategy - full history with escape sequences
   */
  async primaryCapture(sessionName, socketPath) {
    this.log('debug', `Primary capture for session: ${sessionName}`);
    
    const args = [
      '-S', socketPath,
      'capture-pane',
      '-t', sessionName,
      '-S', '-',    // Start from beginning of history
      '-E', '-',    // End at end of history
      '-e',         // Include escape sequences
      '-p'          // Print to stdout
    ];

    const result = await this.executeTmuxCommand(args, 'primary capture');
    return result.output;
  }

  /**
   * Fallback capture strategies
   */
  async fallbackCapture(sessionName, socketPath, strategy) {
    this.log('info', `Attempting fallback strategy: ${strategy}`);
    
    const strategies = {
      'basic-capture': [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-p'
      ],
      
      'limited-history': [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-S', '-100',  // Last 100 lines
        '-E', '-1',    // Until second to last line
        '-p'
      ],
      
      'current-screen': [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-S', '0',     // Current screen only
        '-E', '-1',
        '-p'
      ],
      
      'no-escape-sequences': [
        '-S', socketPath,
        'capture-pane',
        '-t', sessionName,
        '-S', '-',
        '-E', '-',
        '-p'           // No -e flag
      ],
      
      'list-windows': [
        '-S', socketPath,
        'list-windows',
        '-t', sessionName,
        '-F', '#{window_name}: #{window_active}'
      ]
    };

    if (!strategies[strategy]) {
      throw new Error(`Unknown fallback strategy: ${strategy}`);
    }

    try {
      const result = await this.executeTmuxCommand(strategies[strategy], `fallback ${strategy}`);
      this.stats.fallbackUsed++;
      return result.output;
    } catch (err) {
      this.log('warn', `Fallback strategy ${strategy} failed: ${err.message}`);
      throw err;
    }
  }

  /**
   * Execute capture with retry logic
   */
  async captureWithRetry(sessionName, socketPath, attempt = 1) {
    try {
      this.log('debug', `Capture attempt ${attempt}/${this.options.maxRetries + 1}`);
      
      // Use primary capture strategy
      const output = await this.primaryCapture(sessionName, socketPath);
      
      this.log('info', `Screen capture successful for session ${sessionName} (${output.length} bytes)`);
      return output;
      
    } catch (err) {
      this.log('warn', `Capture attempt ${attempt} failed: ${err.message}`);
      
      if (attempt <= this.options.maxRetries) {
        // Calculate exponential backoff delay
        const delay = this.options.retryDelay * Math.pow(2, attempt - 1);
        this.log('debug', `Retrying in ${delay}ms...`);
        
        await new Promise(resolve => setTimeout(resolve, delay));
        this.stats.retriesUsed++;
        
        return this.captureWithRetry(sessionName, socketPath, attempt + 1);
      } else {
        throw err;
      }
    }
  }

  /**
   * Main capture method with full error handling and fallback
   */
  async captureScreen(sessionName, socketPath) {
    const startTime = Date.now();
    this.stats.totalCaptures++;
    
    this.log('info', `Capturing screen for session ${sessionName} (attempt 1/${this.options.maxRetries + 1})`);
    
    try {
      // Step 1: Validate session if enabled
      if (this.options.sessionValidation) {
        await this.validateSession(sessionName, socketPath);
      }

      // Step 2: Attempt capture with retry
      const output = await this.captureWithRetry(sessionName, socketPath);
      
      // Update statistics
      const duration = Date.now() - startTime;
      this.stats.successfulCaptures++;
      this.stats.avgCaptureTime = ((this.stats.avgCaptureTime * (this.stats.successfulCaptures - 1)) + duration) / this.stats.successfulCaptures;
      
      return output;
      
    } catch (primaryError) {
      this.log('error', `Primary capture failed: ${primaryError.message}`);
      
      // Step 3: Try fallback strategies if enabled
      if (this.options.fallbackEnabled) {
        const fallbackStrategies = [
          'basic-capture',
          'limited-history', 
          'current-screen',
          'no-escape-sequences',
          'list-windows'
        ];
        
        for (const strategy of fallbackStrategies) {
          try {
            this.log('info', `Trying fallback strategy: ${strategy}`);
            const output = await this.fallbackCapture(sessionName, socketPath, strategy);
            
            this.log('info', `Fallback capture successful with strategy: ${strategy} (${output.length} bytes)`);
            
            // Update statistics
            const duration = Date.now() - startTime;
            this.stats.successfulCaptures++;
            this.stats.avgCaptureTime = ((this.stats.avgCaptureTime * (this.stats.successfulCaptures - 1)) + duration) / this.stats.successfulCaptures;
            
            return output;
            
          } catch (fallbackError) {
            this.log('warn', `Fallback strategy ${strategy} failed: ${fallbackError.message}`);
            continue;
          }
        }
        
        // All fallback strategies failed
        this.stats.failedCaptures++;
        throw new Error('All fallback capture strategies failed');
        
      } else {
        // Fallbacks disabled, return primary error
        this.stats.failedCaptures++;
        throw primaryError;
      }
    }
  }

  /**
   * Get capture statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      successRate: this.stats.totalCaptures > 0 
        ? (this.stats.successfulCaptures / this.stats.totalCaptures * 100).toFixed(2) + '%'
        : 'N/A',
      fallbackRate: this.stats.totalCaptures > 0
        ? (this.stats.fallbackUsed / this.stats.totalCaptures * 100).toFixed(2) + '%'
        : 'N/A'
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.stats = {
      totalCaptures: 0,
      successfulCaptures: 0,
      failedCaptures: 0,
      fallbackUsed: 0,
      retriesUsed: 0,
      avgCaptureTime: 0
    };
  }

  /**
   * Health check for the capture system
   */
  async healthCheck() {
    this.log('info', 'Performing enhanced screen capture health check');
    
    const health = {
      tmuxAvailable: false,
      platformSupported: true,
      recommendedSettings: {},
      warnings: [],
      errors: []
    };

    try {
      // Check tmux availability
      const tmuxResult = await this.executeTmuxCommand(['-V'], 'version check');
      health.tmuxAvailable = true;
      health.tmuxVersion = tmuxResult.output.trim();
      this.log('info', `Tmux version: ${health.tmuxVersion}`);
    } catch (err) {
      health.errors.push('Tmux is not available or not working properly');
    }

    // Platform-specific checks
    if (this.isWindows) {
      health.warnings.push('Windows support is experimental');
      health.recommendedSettings.timeout = 10000; // Longer timeout for Windows
    }

    // System resource checks
    const tmpDir = os.tmpdir();
    try {
      fs.accessSync(tmpDir, fs.constants.R_OK | fs.constants.W_OK);
    } catch (err) {
      health.errors.push(`Temporary directory not accessible: ${tmpDir}`);
    }

    return health;
  }
}

// Export the class
module.exports = EnhancedScreenCapture;

// If run directly, perform a demo
if (require.main === module) {
  console.log('🧪 Enhanced Screen Capture Demo\n');
  
  const capture = new EnhancedScreenCapture({
    logLevel: 'debug',
    maxRetries: 2
  });
  
  capture.healthCheck().then(health => {
    console.log('Health Check Results:', JSON.stringify(health, null, 2));
    console.log('\n📊 Statistics:', capture.getStatistics());
  }).catch(err => {
    console.error('Health check failed:', err);
  });
}