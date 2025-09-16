/**
 * Wait Helper Utilities for Tmux Operations
 *
 * Specialized wait functions for tmux session management,
 * process monitoring, and system-level operations.
 */

const { wait, waitUntil, retry, waitWithTimeout } = require('./wait');
const { spawn } = require('child_process');
const fs = require('fs');

/**
 * Wait for tmux session to be available and responsive
 * @param {string} sessionName - Session name
 * @param {string} socketPath - Socket path
 * @param {Object} options - Wait options
 * @returns {Promise<void>}
 */
async function waitForTmuxSession(sessionName, socketPath, options = {}) {
  const { timeout = 10000, interval = 500 } = options;

  const checkSession = async () => {
    return new Promise((resolve) => {
      const tmux = spawn('tmux', ['-S', socketPath, 'has-session', '-t', sessionName], {
        stdio: 'pipe'
      });

      tmux.on('exit', (code) => {
        resolve(code === 0);
      });

      tmux.on('error', () => {
        resolve(false);
      });
    });
  };

  await waitUntil(checkSession, {
    timeout,
    interval,
    message: `Tmux session ${sessionName} not available`
  });
}

/**
 * Wait for tmux session to terminate
 * @param {string} sessionName - Session name
 * @param {string} socketPath - Socket path
 * @param {Object} options - Wait options
 * @returns {Promise<void>}
 */
async function waitForTmuxSessionTermination(sessionName, socketPath, options = {}) {
  const { timeout = 30000, interval = 1000 } = options;

  const checkTermination = async () => {
    return new Promise((resolve) => {
      const tmux = spawn('tmux', ['-S', socketPath, 'has-session', '-t', sessionName], {
        stdio: 'pipe'
      });

      tmux.on('exit', (code) => {
        resolve(code !== 0); // Session terminated when has-session fails
      });

      tmux.on('error', () => {
        resolve(true); // Error likely means session is gone
      });
    });
  };

  await waitUntil(checkTermination, {
    timeout,
    interval,
    message: `Tmux session ${sessionName} did not terminate`
  });
}

/**
 * Wait for socket file to exist
 * @param {string} socketPath - Path to socket file
 * @param {Object} options - Wait options
 * @returns {Promise<void>}
 */
async function waitForSocket(socketPath, options = {}) {
  const { timeout = 5000, interval = 200 } = options;

  const checkSocket = () => {
    try {
      return fs.existsSync(socketPath);
    } catch {
      return false;
    }
  };

  await waitUntil(checkSocket, {
    timeout,
    interval,
    message: `Socket ${socketPath} not available`
  });
}

/**
 * Wait for socket file to be deleted
 * @param {string} socketPath - Path to socket file
 * @param {Object} options - Wait options
 * @returns {Promise<void>}
 */
async function waitForSocketDeletion(socketPath, options = {}) {
  const { timeout = 10000, interval = 500 } = options;

  const checkDeletion = () => {
    try {
      return !fs.existsSync(socketPath);
    } catch {
      return true; // If we can't check, assume it's gone
    }
  };

  await waitUntil(checkDeletion, {
    timeout,
    interval,
    message: `Socket ${socketPath} was not deleted`
  });
}

/**
 * Wait for tmux pane to become dead (command completed)
 * @param {string} sessionName - Session name
 * @param {string} socketPath - Socket path
 * @param {Object} options - Wait options
 * @returns {Promise<{isDead: boolean, exitCode: number}>}
 */
async function waitForPaneDeath(sessionName, socketPath, options = {}) {
  const { timeout = 60000, interval = 1000 } = options;

  let lastStatus = null;

  const checkPaneDeath = async () => {
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
          const [deadStatus, exitStatus] = output.trim().split(',');
          const isDead = deadStatus === '1';
          const exitCode = exitStatus ? parseInt(exitStatus, 10) : 0;

          lastStatus = { isDead, exitCode };
          resolve(isDead);
        } else {
          // If we can't check pane status, assume command completed
          lastStatus = { isDead: true, exitCode: 0 };
          resolve(true);
        }
      });

      tmux.on('error', () => {
        // On error, assume pane is dead
        lastStatus = { isDead: true, exitCode: 0 };
        resolve(true);
      });
    });
  };

  await waitUntil(checkPaneDeath, {
    timeout,
    interval,
    message: `Pane in session ${sessionName} did not complete`
  });

  return lastStatus || { isDead: true, exitCode: 0 };
}

/**
 * Wait for process to exit with specific exit code
 * @param {ChildProcess} process - Child process to monitor
 * @param {number} expectedExitCode - Expected exit code (optional)
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<number>}
 */
async function waitForProcessExit(process, expectedExitCode = null, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Process did not exit within ${timeout}ms`));
    }, timeout);

    process.on('exit', (code) => {
      clearTimeout(timeoutId);

      if (expectedExitCode !== null && code !== expectedExitCode) {
        reject(new Error(`Process exited with code ${code}, expected ${expectedExitCode}`));
      } else {
        resolve(code);
      }
    });

    process.on('error', (error) => {
      clearTimeout(timeoutId);
      reject(error);
    });
  });
}

/**
 * Wait for multiple tmux operations with coordinated timeouts
 * @param {Array<Function>} operations - Array of async operations
 * @param {Object} options - Configuration options
 * @returns {Promise<Array>}
 */
async function waitForTmuxOperations(operations, options = {}) {
  const {
    individualTimeout = 5000,
    totalTimeout = 15000,
    failFast = false
  } = options;

  const startTime = Date.now();

  const wrappedOperations = operations.map((operation, index) =>
    waitWithTimeout(
      operation(),
      individualTimeout,
      `Tmux operation ${index} timed out`
    ).catch(error => {
      if (failFast) {
        throw error;
      }
      return { error, index };
    })
  );

  // Race against total timeout
  const totalTimeoutPromise = new Promise((_, reject) => {
    setTimeout(() => {
      reject(new Error(`All tmux operations timed out after ${totalTimeout}ms`));
    }, totalTimeout);
  });

  try {
    const results = await Promise.race([
      failFast ? Promise.all(wrappedOperations) : Promise.allSettled(wrappedOperations),
      totalTimeoutPromise
    ]);

    const duration = Date.now() - startTime;
    console.log(`Tmux operations completed in ${duration}ms`);

    return results;
  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`Tmux operations failed after ${duration}ms:`, error.message);
    throw error;
  }
}

/**
 * Retry tmux operation with exponential backoff
 * @param {Function} operation - Tmux operation to retry
 * @param {Object} options - Retry options
 * @returns {Promise<any>}
 */
async function retryTmuxOperation(operation, options = {}) {
  const retryOptions = {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 5000,
    shouldRetry: (error) => {
      // Retry on common tmux errors
      return error.message.includes('server not found') ||
             error.message.includes('no server running') ||
             error.message.includes('connection refused') ||
             error.message.includes('temporarily unavailable');
    },
    onRetry: (error, attempt) => {
      console.log(`Retrying tmux operation (attempt ${attempt + 1}): ${error.message}`);
    },
    ...options
  };

  return retry(operation, retryOptions);
}

/**
 * Wait for tmux server to be responsive
 * @param {string} socketPath - Socket path (optional)
 * @param {Object} options - Wait options
 * @returns {Promise<void>}
 */
async function waitForTmuxServer(socketPath = null, options = {}) {
  const { timeout = 10000, interval = 1000 } = options;

  const checkServer = async () => {
    return new Promise((resolve) => {
      const args = socketPath ? ['-S', socketPath, 'list-sessions'] : ['list-sessions'];
      const tmux = spawn('tmux', args, { stdio: 'pipe' });

      tmux.on('exit', (code) => {
        resolve(code === 0);
      });

      tmux.on('error', () => {
        resolve(false);
      });
    });
  };

  await waitUntil(checkServer, {
    timeout,
    interval,
    message: 'Tmux server not responsive'
  });
}

module.exports = {
  waitForTmuxSession,
  waitForTmuxSessionTermination,
  waitForSocket,
  waitForSocketDeletion,
  waitForPaneDeath,
  waitForProcessExit,
  waitForTmuxOperations,
  retryTmuxOperation,
  waitForTmuxServer
};