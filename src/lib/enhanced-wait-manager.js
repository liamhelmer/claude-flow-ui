/**
 * Enhanced Wait Manager for Complex Async Operations
 *
 * Provides high-level orchestration of wait operations with:
 * - Operation grouping and dependencies
 * - Circuit breaker patterns
 * - Metrics and monitoring
 * - Recovery strategies
 */

const EventEmitter = require('events');
const { wait, retry, waitUntil } = require('../utils/wait');
const logger = require('../config/logger');

class WaitManager extends EventEmitter {
  constructor(options = {}) {
    super();

    this.operations = new Map();
    this.metrics = {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      averageWaitTime: 0,
      timeouts: 0
    };

    this.circuitBreakers = new Map();
    this.defaultOptions = {
      timeout: 30000,
      retries: 3,
      backoffMultiplier: 2,
      ...options
    };
  }

  /**
   * Register a wait operation with dependencies
   * @param {string} name - Operation name
   * @param {Function} operation - Async operation
   * @param {Object} options - Operation options
   * @returns {Promise<any>}
   */
  async waitFor(name, operation, options = {}) {
    const config = { ...this.defaultOptions, ...options };
    const startTime = Date.now();

    this.operations.set(name, {
      status: 'pending',
      startTime,
      config
    });

    this.emit('operationStarted', { name, config });
    this.metrics.totalOperations++;

    try {
      // Check circuit breaker
      if (this.isCircuitOpen(name)) {
        throw new Error(`Circuit breaker open for operation: ${name}`);
      }

      // Wait for dependencies
      if (config.dependencies) {
        await this.waitForDependencies(config.dependencies);
      }

      // Execute operation with retry logic
      const result = await retry(operation, {
        maxRetries: config.retries,
        baseDelay: config.baseDelay || 1000,
        backoffFactor: config.backoffMultiplier,
        shouldRetry: config.shouldRetry,
        onRetry: (error, attempt) => {
          this.emit('operationRetry', { name, attempt, error: error.message });
        }
      });

      // Update metrics and status
      const duration = Date.now() - startTime;
      this.updateOperationSuccess(name, duration);
      this.recordCircuitBreakerSuccess(name);

      this.emit('operationCompleted', { name, duration, result });
      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      this.updateOperationFailure(name, duration, error);
      this.recordCircuitBreakerFailure(name);

      this.emit('operationFailed', { name, duration, error: error.message });
      throw error;
    }
  }

  /**
   * Wait for multiple operations in parallel
   * @param {Array<Object>} operations - Array of {name, operation, options}
   * @param {Object} options - Global options
   * @returns {Promise<Array>}
   */
  async waitForAll(operations, options = {}) {
    const { failFast = false, timeout = 60000 } = options;

    const promises = operations.map(({ name, operation, options: opOptions }) =>
      this.waitFor(name, operation, opOptions)
    );

    if (failFast) {
      return Promise.all(promises);
    }

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`WaitForAll timed out after ${timeout}ms`)), timeout);
    });

    return Promise.race([
      Promise.allSettled(promises),
      timeoutPromise
    ]);
  }

  /**
   * Wait for dependencies to complete
   * @param {Array<string>} dependencies - Array of operation names
   * @returns {Promise<void>}
   */
  async waitForDependencies(dependencies) {
    await waitUntil(() => {
      return dependencies.every(dep => {
        const operation = this.operations.get(dep);
        return operation && operation.status === 'completed';
      });
    }, {
      timeout: 30000,
      interval: 500,
      message: `Dependencies not satisfied: ${dependencies.join(', ')}`
    });
  }

  /**
   * Create a circuit breaker for an operation
   * @param {string} name - Operation name
   * @param {Object} options - Circuit breaker options
   */
  createCircuitBreaker(name, options = {}) {
    const {
      failureThreshold = 5,
      resetTimeout = 60000,
      monitoringPeriod = 600000 // 10 minutes
    } = options;

    this.circuitBreakers.set(name, {
      failures: 0,
      successes: 0,
      lastFailureTime: 0,
      state: 'closed', // closed, open, half-open
      failureThreshold,
      resetTimeout,
      monitoringPeriod
    });
  }

  /**
   * Check if circuit breaker is open
   * @param {string} name - Operation name
   * @returns {boolean}
   */
  isCircuitOpen(name) {
    const breaker = this.circuitBreakers.get(name);
    if (!breaker) return false;

    const now = Date.now();

    // Reset if enough time has passed
    if (breaker.state === 'open' &&
        now - breaker.lastFailureTime > breaker.resetTimeout) {
      breaker.state = 'half-open';
      breaker.failures = 0;
    }

    return breaker.state === 'open';
  }

  /**
   * Record circuit breaker success
   * @param {string} name - Operation name
   */
  recordCircuitBreakerSuccess(name) {
    const breaker = this.circuitBreakers.get(name);
    if (!breaker) return;

    breaker.successes++;

    if (breaker.state === 'half-open') {
      breaker.state = 'closed';
      breaker.failures = 0;
    }
  }

  /**
   * Record circuit breaker failure
   * @param {string} name - Operation name
   */
  recordCircuitBreakerFailure(name) {
    const breaker = this.circuitBreakers.get(name);
    if (!breaker) return;

    breaker.failures++;
    breaker.lastFailureTime = Date.now();

    if (breaker.failures >= breaker.failureThreshold) {
      breaker.state = 'open';
      this.emit('circuitBreakerOpen', { name, failures: breaker.failures });
    }
  }

  /**
   * Update operation success metrics
   * @param {string} name - Operation name
   * @param {number} duration - Operation duration
   */
  updateOperationSuccess(name, duration) {
    const operation = this.operations.get(name);
    if (operation) {
      operation.status = 'completed';
      operation.duration = duration;
    }

    this.metrics.successfulOperations++;
    this.updateAverageWaitTime(duration);
  }

  /**
   * Update operation failure metrics
   * @param {string} name - Operation name
   * @param {number} duration - Operation duration
   * @param {Error} error - Error that occurred
   */
  updateOperationFailure(name, duration, error) {
    const operation = this.operations.get(name);
    if (operation) {
      operation.status = 'failed';
      operation.duration = duration;
      operation.error = error.message;
    }

    this.metrics.failedOperations++;

    if (error.message.includes('timed out')) {
      this.metrics.timeouts++;
    }
  }

  /**
   * Update average wait time
   * @param {number} duration - Operation duration
   */
  updateAverageWaitTime(duration) {
    const totalOps = this.metrics.successfulOperations + this.metrics.failedOperations;
    this.metrics.averageWaitTime = (
      (this.metrics.averageWaitTime * (totalOps - 1) + duration) / totalOps
    );
  }

  /**
   * Get current metrics
   * @returns {Object}
   */
  getMetrics() {
    return {
      ...this.metrics,
      successRate: this.metrics.totalOperations > 0 ?
        (this.metrics.successfulOperations / this.metrics.totalOperations) * 100 : 0,
      operations: Array.from(this.operations.entries()).map(([name, op]) => ({
        name,
        ...op
      })),
      circuitBreakers: Array.from(this.circuitBreakers.entries()).map(([name, breaker]) => ({
        name,
        ...breaker
      }))
    };
  }

  /**
   * Reset all metrics and operations
   */
  reset() {
    this.operations.clear();
    this.circuitBreakers.clear();
    this.metrics = {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      averageWaitTime: 0,
      timeouts: 0
    };

    this.emit('reset');
  }

  /**
   * Wait for a health check with circuit breaker
   * @param {string} serviceName - Service name
   * @param {Function} healthCheck - Health check function
   * @param {Object} options - Options
   * @returns {Promise<void>}
   */
  async waitForHealthCheck(serviceName, healthCheck, options = {}) {
    // Create circuit breaker if it doesn't exist
    if (!this.circuitBreakers.has(serviceName)) {
      this.createCircuitBreaker(serviceName, options.circuitBreaker);
    }

    return this.waitFor(`healthCheck_${serviceName}`, async () => {
      await waitUntil(healthCheck, {
        timeout: options.timeout || 60000,
        interval: options.interval || 2000,
        message: `${serviceName} health check failed`
      });
    }, options);
  }

  /**
   * Create a wait operation group
   * @param {string} groupName - Group name
   * @param {Array<Object>} operations - Operations in the group
   * @param {Object} options - Group options
   * @returns {Promise<Array>}
   */
  async waitForGroup(groupName, operations, options = {}) {
    const {
      sequential = false,
      stopOnFirstFailure = false,
      timeout = 120000
    } = options;

    this.emit('groupStarted', { groupName, operations: operations.length });

    try {
      let results;

      if (sequential) {
        results = [];
        for (const op of operations) {
          const result = await this.waitFor(`${groupName}_${op.name}`, op.operation, op.options);
          results.push(result);

          if (stopOnFirstFailure && result instanceof Error) {
            break;
          }
        }
      } else {
        results = await this.waitForAll(
          operations.map(op => ({
            ...op,
            name: `${groupName}_${op.name}`
          })),
          { failFast: stopOnFirstFailure, timeout }
        );
      }

      this.emit('groupCompleted', { groupName, results });
      return results;

    } catch (error) {
      this.emit('groupFailed', { groupName, error: error.message });
      throw error;
    }
  }
}

module.exports = WaitManager;