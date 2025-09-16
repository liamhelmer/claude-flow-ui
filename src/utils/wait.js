/**
 * Enhanced Wait Utilities for Claude Flow UI
 *
 * Provides comprehensive async waiting functionality with:
 * - Basic delay/sleep operations
 * - Retry mechanisms with exponential backoff
 * - Timeout handling for promises
 * - Health check waiting
 * - Graceful cancellation support
 * - Error recovery patterns
 */

const logger = require('../config/logger');

/**
 * Basic wait/delay utility
 * @param {number} ms - Milliseconds to wait
 * @returns {Promise<void>}
 */
function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Wait with cancellation support
 * @param {number} ms - Milliseconds to wait
 * @param {AbortSignal} signal - Optional abort signal for cancellation
 * @returns {Promise<void>}
 */
function waitWithCancel(ms, signal) {
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
 * Wait until a condition is true
 * @param {Function} condition - Function that returns boolean or Promise<boolean>
 * @param {Object} options - Configuration options
 * @param {number} options.timeout - Maximum time to wait (ms, default: 30000)
 * @param {number} options.interval - Check interval (ms, default: 100)
 * @param {string} options.message - Error message if timeout
 * @param {AbortSignal} options.signal - Optional abort signal
 * @returns {Promise<void>}
 */
async function waitUntil(condition, options = {}) {
  const {
    timeout = 30000,
    interval = 100,
    message = 'Condition not met within timeout',
    signal
  } = options;

  const startTime = Date.now();

  while (true) {
    if (signal?.aborted) {
      throw new Error('Wait cancelled');
    }

    const elapsed = Date.now() - startTime;
    if (elapsed >= timeout) {
      throw new Error(`${message} (timeout: ${timeout}ms)`);
    }

    try {
      const result = await condition();
      if (result) {
        return;
      }
    } catch (error) {
      logger.debug('Condition check failed', { error: error.message, elapsed });
    }

    await waitWithCancel(interval, signal);
  }
}

/**
 * Wait for a promise with timeout
 * @param {Promise} promise - Promise to wait for
 * @param {number} timeout - Timeout in milliseconds
 * @param {string} message - Optional timeout error message
 * @returns {Promise<any>}
 */
function waitWithTimeout(promise, timeout, message = 'Operation timed out') {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${message} (${timeout}ms)`)), timeout);
    })
  ]);
}

/**
 * Retry an operation with exponential backoff
 * @param {Function} operation - Async operation to retry
 * @param {Object} options - Retry configuration
 * @param {number} options.maxRetries - Maximum number of retries (default: 3)
 * @param {number} options.baseDelay - Base delay in ms (default: 1000)
 * @param {number} options.maxDelay - Maximum delay in ms (default: 30000)
 * @param {number} options.backoffFactor - Exponential backoff factor (default: 2)
 * @param {Function} options.shouldRetry - Function to determine if error should trigger retry
 * @param {Function} options.onRetry - Callback called before each retry
 * @param {AbortSignal} options.signal - Optional abort signal
 * @returns {Promise<any>}
 */
async function retry(operation, options = {}) {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 30000,
    backoffFactor = 2,
    shouldRetry = () => true,
    onRetry = () => {},
    signal
  } = options;

  let lastError;
  let delay = baseDelay;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (signal?.aborted) {
      throw new Error('Operation cancelled');
    }

    try {
      return await operation();
    } catch (error) {
      lastError = error;

      if (attempt === maxRetries) {
        break;
      }

      if (!shouldRetry(error, attempt)) {
        throw error;
      }

      logger.debug('Retrying operation', {
        attempt: attempt + 1,
        maxRetries,
        delay,
        error: error.message
      });

      onRetry(error, attempt);

      await waitWithCancel(delay, signal);
      delay = Math.min(delay * backoffFactor, maxDelay);
    }
  }

  throw lastError;
}

/**
 * Wait for multiple promises with individual timeouts
 * @param {Array<Promise>} promises - Array of promises
 * @param {number} timeout - Timeout per promise
 * @param {boolean} failFast - Whether to fail on first timeout (default: false)
 * @returns {Promise<Array>}
 */
async function waitForAll(promises, timeout, failFast = false) {
  const wrappedPromises = promises.map((promise, index) =>
    waitWithTimeout(promise, timeout, `Promise ${index} timed out`)
      .catch(error => {
        if (failFast) {
          throw error;
        }
        return { error, index };
      })
  );

  if (failFast) {
    return Promise.all(wrappedPromises);
  }

  const results = await Promise.allSettled(wrappedPromises);
  return results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return result.value;
    }
    return { error: result.reason, index };
  });
}

/**
 * Wait for any promise to resolve, with timeout for each
 * @param {Array<Promise>} promises - Array of promises
 * @param {number} timeout - Timeout per promise
 * @returns {Promise<any>}
 */
function waitForAny(promises, timeout) {
  const wrappedPromises = promises.map(promise =>
    waitWithTimeout(promise, timeout)
  );

  return Promise.race(wrappedPromises);
}

/**
 * Wait for a service to be healthy
 * @param {Function} healthCheck - Function that returns true if service is healthy
 * @param {Object} options - Configuration options
 * @param {number} options.timeout - Maximum time to wait (default: 60000)
 * @param {number} options.interval - Check interval (default: 2000)
 * @param {string} options.serviceName - Service name for logging
 * @param {AbortSignal} options.signal - Optional abort signal
 * @returns {Promise<void>}
 */
async function waitForService(healthCheck, options = {}) {
  const {
    timeout = 60000,
    interval = 2000,
    serviceName = 'service',
    signal
  } = options;

  logger.info(`Waiting for ${serviceName} to be healthy`, { timeout, interval });

  try {
    await waitUntil(healthCheck, {
      timeout,
      interval,
      message: `${serviceName} did not become healthy`,
      signal
    });

    logger.info(`${serviceName} is healthy`);
  } catch (error) {
    logger.error(`Failed waiting for ${serviceName}`, { error: error.message });
    throw error;
  }
}

/**
 * Wait for file system operations (file exists, readable, etc.)
 * @param {string} path - File path to check
 * @param {Object} options - Configuration options
 * @param {string} options.operation - 'exists', 'readable', 'writable' (default: 'exists')
 * @param {number} options.timeout - Maximum time to wait (default: 10000)
 * @param {number} options.interval - Check interval (default: 500)
 * @param {AbortSignal} options.signal - Optional abort signal
 * @returns {Promise<void>}
 */
async function waitForFile(path, options = {}) {
  const fs = require('fs').promises;
  const {
    operation = 'exists',
    timeout = 10000,
    interval = 500,
    signal
  } = options;

  const checkFile = async () => {
    try {
      const stats = await fs.stat(path);

      switch (operation) {
        case 'exists':
          return true;
        case 'readable':
          await fs.access(path, fs.constants.R_OK);
          return true;
        case 'writable':
          await fs.access(path, fs.constants.W_OK);
          return true;
        default:
          return stats.isFile();
      }
    } catch {
      return false;
    }
  };

  await waitUntil(checkFile, {
    timeout,
    interval,
    message: `File ${path} ${operation} check failed`,
    signal
  });
}

/**
 * Wait for a TCP port to be available
 * @param {number} port - Port number to check
 * @param {string} host - Host to check (default: 'localhost')
 * @param {Object} options - Configuration options
 * @param {number} options.timeout - Maximum time to wait (default: 30000)
 * @param {number} options.interval - Check interval (default: 1000)
 * @param {AbortSignal} options.signal - Optional abort signal
 * @returns {Promise<void>}
 */
async function waitForPort(port, host = 'localhost', options = {}) {
  const net = require('net');
  const {
    timeout = 30000,
    interval = 1000,
    signal
  } = options;

  const checkPort = () => {
    return new Promise((resolve) => {
      const socket = new net.Socket();

      socket.setTimeout(5000);

      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(port, host);
    });
  };

  await waitUntil(checkPort, {
    timeout,
    interval,
    message: `Port ${port} on ${host} not available`,
    signal
  });
}

/**
 * Wait with jitter to avoid thundering herd
 * @param {number} baseMs - Base delay in milliseconds
 * @param {number} jitterPercent - Jitter percentage (0-100, default: 20)
 * @returns {Promise<void>}
 */
function waitWithJitter(baseMs, jitterPercent = 20) {
  const jitter = baseMs * (jitterPercent / 100);
  const actualMs = baseMs + (Math.random() * jitter * 2 - jitter);
  return wait(Math.max(0, actualMs));
}

/**
 * Create a waiter that can be resolved externally
 * @returns {Object} Object with promise and resolve function
 */
function createWaiter() {
  let resolve;
  const promise = new Promise(r => {
    resolve = r;
  });

  return { promise, resolve };
}

/**
 * Wait for multiple conditions with different timeouts
 * @param {Array<Object>} conditions - Array of {condition, timeout, name}
 * @param {Object} options - Options
 * @param {boolean} options.all - Wait for all conditions (default: true)
 * @param {AbortSignal} options.signal - Optional abort signal
 * @returns {Promise<void>}
 */
async function waitForConditions(conditions, options = {}) {
  const { all = true, signal } = options;

  const waitPromises = conditions.map(({ condition, timeout = 30000, name = 'condition' }) =>
    waitUntil(condition, {
      timeout,
      message: `${name} not met`,
      signal
    }).catch(error => {
      error.conditionName = name;
      throw error;
    })
  );

  if (all) {
    await Promise.all(waitPromises);
  } else {
    await Promise.race(waitPromises);
  }
}

module.exports = {
  wait,
  waitWithCancel,
  waitUntil,
  waitWithTimeout,
  retry,
  waitForAll,
  waitForAny,
  waitForService,
  waitForFile,
  waitForPort,
  waitWithJitter,
  createWaiter,
  waitForConditions,

  // Common retry configurations
  retryConfig: {
    quick: { maxRetries: 2, baseDelay: 500, maxDelay: 2000 },
    normal: { maxRetries: 3, baseDelay: 1000, maxDelay: 10000 },
    persistent: { maxRetries: 5, baseDelay: 2000, maxDelay: 30000 },
    network: { maxRetries: 3, baseDelay: 1000, maxDelay: 5000,
      shouldRetry: (error) => error.code === 'ECONNRESET' || error.code === 'ENOTFOUND' }
  }
};