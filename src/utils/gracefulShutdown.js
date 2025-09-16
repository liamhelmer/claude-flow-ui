const logger = require('../config/logger');
const config = require('../config/environment');
const TmuxManager = require('../lib/tmux-manager');
const TmuxStreamManager = require('../lib/tmux-stream-manager');

/**
 * Enhanced Graceful Shutdown Handler with Tmux Integration
 *
 * Ensures the server shuts down cleanly with proper coordination of:
 * - HTTP server connection cleanup
 * - Tmux session termination and socket cleanup
 * - Exit code reporting for all operations
 * - Prevention of external process.exit calls during shutdown
 *
 * Features:
 * - Automatic registration and cleanup of TmuxManager instances
 * - Robust error handling with individual operation timeouts
 * - Exit code tracking and reporting for debugging
 * - Process.exit override to prevent race conditions
 *
 * Usage:
 *   const gracefulShutdown = require('./utils/gracefulShutdown');
 *
 *   // Initialize with server
 *   gracefulShutdown.init(server);
 *
 *   // Register tmux managers for automatic cleanup
 *   const tmux = gracefulShutdown.createTmuxManager('/working/dir', 'MyTmux');
 *   // OR register existing instances:
 *   gracefulShutdown.registerTmuxManager(existingTmux, 'ExistingTmux');
 */
class GracefulShutdown {
  constructor() {
    this.server = null;
    this.connections = new Set();
    this.isShuttingDown = false;
    this.tmuxManagers = new Set(); // Track registered tmux managers
    this.exitCodes = new Map(); // Track exit codes during shutdown
  }

  /**
   * Initialize graceful shutdown for the server
   * @param {Object} server - HTTP server instance
   */
  init(server) {
    this.server = server;

    // Track all connections
    server.on('connection', (connection) => {
      this.connections.add(connection);

      connection.on('close', () => {
        this.connections.delete(connection);
      });
    });

    // Setup signal handlers
    this.setupSignalHandlers();

    logger.info('Graceful shutdown initialized');
  }

  /**
   * Register a tmux manager for cleanup during shutdown
   * @param {Object} tmuxManager - TmuxManager or TmuxStreamManager instance
   * @param {string} name - Descriptive name for logging
   */
  registerTmuxManager(tmuxManager, name = 'TmuxManager') {
    if (tmuxManager && typeof tmuxManager.cleanup === 'function') {
      this.tmuxManagers.add({ manager: tmuxManager, name });
      logger.info('Tmux manager registered for graceful shutdown', { name });
    } else {
      logger.warn('Invalid tmux manager provided - must have cleanup method', { name });
    }
  }

  /**
   * Unregister a tmux manager
   * @param {Object} tmuxManager - TmuxManager or TmuxStreamManager instance
   */
  unregisterTmuxManager(tmuxManager) {
    for (const entry of this.tmuxManagers) {
      if (entry.manager === tmuxManager) {
        this.tmuxManagers.delete(entry);
        logger.info('Tmux manager unregistered', { name: entry.name });
        break;
      }
    }
  }

  /**
   * Override process.exit during shutdown to prevent tmux managers from terminating the process
   */
  preventExternalExit() {
    if (this.originalProcessExit) return; // Already overridden

    this.originalProcessExit = process.exit;
    process.exit = (code = 0) => {
      if (this.isShuttingDown) {
        logger.info('External process.exit call blocked during graceful shutdown', {
          requestedExitCode: code,
          stack: new Error().stack
        });
        return; // Block the exit
      }
      // If not shutting down, allow normal exit
      this.originalProcessExit(code);
    };
    logger.info('Process.exit override installed for shutdown coordination');
  }

  /**
   * Restore original process.exit
   */
  restoreProcessExit() {
    if (this.originalProcessExit) {
      process.exit = this.originalProcessExit;
      this.originalProcessExit = null;
      logger.info('Process.exit override removed');
    }
  }

  /**
   * Create and register a TmuxManager instance for automatic cleanup
   * @param {string} workingDir - Working directory for tmux sessions
   * @param {string} name - Descriptive name for logging
   * @returns {Object} TmuxManager instance
   */
  createTmuxManager(workingDir = process.cwd(), name = 'TmuxManager') {
    const tmuxManager = new TmuxManager(workingDir);
    this.registerTmuxManager(tmuxManager, name);
    return tmuxManager;
  }

  /**
   * Create and register a TmuxStreamManager instance for automatic cleanup
   * @param {string} name - Descriptive name for logging
   * @returns {Object} TmuxStreamManager instance
   */
  createTmuxStreamManager(name = 'TmuxStreamManager') {
    const tmuxStreamManager = new TmuxStreamManager();
    this.registerTmuxManager(tmuxStreamManager, name);
    return tmuxStreamManager;
  }

  /**
   * Setup signal handlers for graceful shutdown
   */
  setupSignalHandlers() {
    // Handle SIGTERM (Docker, Kubernetes, etc.)
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, starting graceful shutdown');
      this.shutdown('SIGTERM');
    });

    // Handle SIGINT (Ctrl+C)
    process.on('SIGINT', () => {
      logger.info('SIGINT received, starting graceful shutdown');
      this.shutdown('SIGINT');
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception occurred', { error: error.message, stack: error.stack });
      this.shutdown('uncaughtException', 1);
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled rejection occurred', {
        reason: reason instanceof Error ? reason.message : reason,
        stack: reason instanceof Error ? reason.stack : null,
        promise
      });
      this.shutdown('unhandledRejection', 1);
    });
  }

  /**
   * Perform graceful shutdown
   * @param {string} signal - The signal that triggered the shutdown
   * @param {number} exitCode - Exit code (default: 0)
   */
  async shutdown(signal, exitCode = 0) {
    if (this.isShuttingDown) {
      logger.warn('Shutdown already in progress, ignoring signal', { signal });
      return;
    }

    this.isShuttingDown = true;
    this.exitCodes.set('initial', exitCode);
    logger.info('Starting graceful shutdown process', { signal, exitCode });

    // Install process.exit override to prevent tmux managers from terminating the process
    this.preventExternalExit();

    // Set a timeout for forceful shutdown
    const forceShutdownTimer = setTimeout(() => {
      logger.error('Graceful shutdown timeout exceeded, forcing exit');
      this.exitCodes.set('force_shutdown', 1);
      this.reportExitCodes();
      this.restoreProcessExit();
      process.exit(1);
    }, config.gracefulShutdownTimeout);

    try {
      // Stop accepting new connections
      if (this.server) {
        logger.info('Stopping server from accepting new connections');
        this.server.close(() => {
          logger.info('Server stopped accepting new connections');
        });
      }

      // Close existing connections
      logger.info(`Closing ${this.connections.size} active connections`);
      for (const connection of this.connections) {
        connection.destroy();
      }

      // Wait a bit for connections to close gracefully
      await this.wait(1000);

      // Perform any cleanup operations here
      await this.cleanup();

      clearTimeout(forceShutdownTimer);

      // Report all collected exit codes
      this.reportExitCodes();

      // Restore process.exit and complete shutdown
      this.restoreProcessExit();
      logger.info('Graceful shutdown completed successfully');

      process.exit(exitCode);
    } catch (error) {
      logger.error('Error during graceful shutdown', { error: error.message, stack: error.stack });
      this.exitCodes.set('shutdown_error', 1);

      // Report exit codes even if shutdown failed
      this.reportExitCodes();

      // Restore process.exit and force exit
      this.restoreProcessExit();
      clearTimeout(forceShutdownTimer);
      process.exit(1);
    }
  }

  /**
   * Perform cleanup operations
   */
  async cleanup() {
    logger.info('Performing cleanup operations');

    // Clean up registered tmux managers first
    await this.cleanupTmuxManagers();

    // Add any cleanup logic here:
    // - Close database connections
    // - Clean up temporary files
    // - Flush logs
    // - Close external service connections

    // Flush Winston logs
    await new Promise((resolve) => {
      logger.on('finish', resolve);
      logger.end();
    });
  }

  /**
   * Clean up all registered tmux managers with proper error handling
   */
  async cleanupTmuxManagers() {
    if (this.tmuxManagers.size === 0) {
      logger.info('No tmux managers to clean up');
      return;
    }

    logger.info(`Cleaning up ${this.tmuxManagers.size} tmux manager(s)`);

    const cleanupPromises = Array.from(this.tmuxManagers).map(async ({ manager, name }) => {
      try {
        logger.info(`Starting cleanup for ${name}`);
        const startTime = Date.now();

        // Create a timeout for each manager cleanup
        const cleanupPromise = manager.cleanup();
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Cleanup timeout')), 5000); // 5 second timeout per manager
        });

        await Promise.race([cleanupPromise, timeoutPromise]);

        const duration = Date.now() - startTime;
        this.exitCodes.set(`${name}_cleanup`, 0);
        logger.info(`${name} cleanup completed successfully`, { duration: `${duration}ms` });

      } catch (error) {
        const errorCode = error.message.includes('timeout') ? 124 : 1;
        this.exitCodes.set(`${name}_cleanup`, errorCode);
        logger.error(`${name} cleanup failed`, {
          error: error.message,
          stack: error.stack,
          exitCode: errorCode
        });

        // Continue with other cleanups even if one fails
        // This ensures we attempt to clean up all tmux managers
      }
    });

    // Wait for all cleanup operations to complete (or fail)
    await Promise.allSettled(cleanupPromises);

    logger.info('Tmux manager cleanup phase completed');
  }

  /**
   * Report all collected exit codes during shutdown
   */
  reportExitCodes() {
    logger.info('Shutdown exit code summary:', {
      exitCodes: Object.fromEntries(this.exitCodes),
      totalOperations: this.exitCodes.size
    });

    // Display exit codes in a user-friendly format
    for (const [operation, code] of this.exitCodes) {
      const status = code === 0 ? 'SUCCESS' : 'FAILED';
      const emoji = code === 0 ? '✅' : '❌';
      logger.info(`${emoji} ${operation}: ${status} (exit code: ${code})`);
    }
  }

  /**
   * Wait for a specified amount of time (enhanced with cancellation support)
   * @param {number} ms - Milliseconds to wait
   * @param {AbortSignal} signal - Optional abort signal for cancellation
   */
  wait(ms, signal) {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(resolve, ms);

      if (signal) {
        if (signal.aborted) {
          clearTimeout(timeoutId);
          reject(new Error('Wait cancelled'));
          return;
        }

        signal.addEventListener('abort', () => {
          clearTimeout(timeoutId);
          reject(new Error('Wait cancelled'));
        });
      }
    });
  }

  /**
   * Wait for cleanup operations to complete with enhanced monitoring
   * @param {Array<Promise>} cleanupPromises - Array of cleanup promises
   * @param {number} timeout - Overall timeout for all operations
   * @returns {Promise<Array>}
   */
  async waitForCleanupOperations(cleanupPromises, timeout = 10000) {
    const startTime = Date.now();

    // Create timeout promise
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Cleanup operations timed out after ${timeout}ms`));
      }, timeout);
    });

    try {
      // Race the cleanup promises against the timeout
      const results = await Promise.race([
        Promise.allSettled(cleanupPromises),
        timeoutPromise
      ]);

      const duration = Date.now() - startTime;
      logger.info('Cleanup operations completed', {
        duration: `${duration}ms`,
        totalOperations: cleanupPromises.length
      });

      return results;
    } catch (error) {
      logger.error('Cleanup operations failed or timed out', {
        error: error.message,
        duration: `${Date.now() - startTime}ms`
      });
      throw error;
    }
  }
}

module.exports = new GracefulShutdown();