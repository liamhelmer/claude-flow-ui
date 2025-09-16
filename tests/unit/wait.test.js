/**
 * Comprehensive Tests for Wait Utilities
 */

const {
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
  retryConfig
} = require('../../src/utils/wait');

const fs = require('fs').promises;
const path = require('path');
const net = require('net');

describe('Wait Utilities', () => {

  describe('Basic wait functionality', () => {
    test('wait should delay for specified time', async () => {
      const start = Date.now();
      await wait(100);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(90);
      expect(elapsed).toBeLessThan(150);
    });

    test('waitWithCancel should support cancellation', async () => {
      const controller = new AbortController();

      setTimeout(() => controller.abort(), 50);

      await expect(waitWithCancel(200, controller.signal))
        .rejects.toThrow('Wait cancelled');
    });

    test('waitWithCancel should complete normally without signal', async () => {
      const start = Date.now();
      await waitWithCancel(100);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(90);
    });
  });

  describe('Conditional waiting', () => {
    test('waitUntil should wait for condition to be true', async () => {
      let counter = 0;
      const condition = () => ++counter >= 3;

      await waitUntil(condition, { interval: 10 });
      expect(counter).toBe(3);
    });

    test('waitUntil should timeout if condition never met', async () => {
      const condition = () => false;

      await expect(waitUntil(condition, { timeout: 100, interval: 10 }))
        .rejects.toThrow('Condition not met within timeout');
    });

    test('waitUntil should support async conditions', async () => {
      let counter = 0;
      const condition = async () => {
        await wait(10);
        return ++counter >= 2;
      };

      await waitUntil(condition, { interval: 20 });
      expect(counter).toBe(2);
    });

    test('waitUntil should handle condition errors gracefully', async () => {
      let attempts = 0;
      const condition = () => {
        attempts++;
        if (attempts < 3) {
          throw new Error('Not ready yet');
        }
        return true;
      };

      await waitUntil(condition, { interval: 10 });
      expect(attempts).toBe(3);
    });
  });

  describe('Timeout handling', () => {
    test('waitWithTimeout should resolve when promise completes', async () => {
      const promise = wait(50).then(() => 'success');
      const result = await waitWithTimeout(promise, 100);
      expect(result).toBe('success');
    });

    test('waitWithTimeout should reject on timeout', async () => {
      const promise = wait(200).then(() => 'success');

      await expect(waitWithTimeout(promise, 100))
        .rejects.toThrow('Operation timed out');
    });

    test('waitWithTimeout should use custom timeout message', async () => {
      const promise = wait(200);

      await expect(waitWithTimeout(promise, 100, 'Custom timeout'))
        .rejects.toThrow('Custom timeout');
    });
  });

  describe('Retry mechanism', () => {
    test('retry should succeed on first attempt', async () => {
      const operation = jest.fn().mockResolvedValue('success');

      const result = await retry(operation);
      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(1);
    });

    test('retry should retry on failure and eventually succeed', async () => {
      const operation = jest.fn()
        .mockRejectedValueOnce(new Error('Attempt 1'))
        .mockRejectedValueOnce(new Error('Attempt 2'))
        .mockResolvedValue('success');

      const result = await retry(operation, { maxRetries: 3, baseDelay: 10 });
      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(3);
    });

    test('retry should respect maxRetries limit', async () => {
      const operation = jest.fn().mockRejectedValue(new Error('Always fails'));

      await expect(retry(operation, { maxRetries: 2, baseDelay: 10 }))
        .rejects.toThrow('Always fails');
      expect(operation).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    test('retry should use shouldRetry function', async () => {
      const operation = jest.fn()
        .mockRejectedValueOnce(new Error('Retryable'))
        .mockRejectedValue(new Error('Non-retryable'));

      const shouldRetry = (error) => error.message === 'Retryable';

      await expect(retry(operation, { maxRetries: 3, baseDelay: 10, shouldRetry }))
        .rejects.toThrow('Non-retryable');
      expect(operation).toHaveBeenCalledTimes(2);
    });

    test('retry should call onRetry callback', async () => {
      const operation = jest.fn()
        .mockRejectedValueOnce(new Error('First fail'))
        .mockResolvedValue('success');

      const onRetry = jest.fn();

      await retry(operation, { maxRetries: 2, baseDelay: 10, onRetry });
      expect(onRetry).toHaveBeenCalledWith(expect.any(Error), 0);
    });
  });

  describe('Multiple promise handling', () => {
    test('waitForAll should handle all promises succeeding', async () => {
      const promises = [
        wait(50).then(() => 'result1'),
        wait(30).then(() => 'result2'),
        wait(70).then(() => 'result3')
      ];

      const results = await waitForAll(promises, 200);
      expect(results).toEqual(['result1', 'result2', 'result3']);
    });

    test('waitForAll should handle timeouts without failFast', async () => {
      const promises = [
        wait(50).then(() => 'result1'),
        wait(200).then(() => 'result2'), // This will timeout
        wait(30).then(() => 'result3')
      ];

      const results = await waitForAll(promises, 100, false);
      expect(results[0]).toBe('result1');
      expect(results[1]).toHaveProperty('error');
      expect(results[2]).toBe('result3');
    });

    test('waitForAny should resolve with first completing promise', async () => {
      const promises = [
        wait(100).then(() => 'slow'),
        wait(50).then(() => 'fast'),
        wait(150).then(() => 'slower')
      ];

      const result = await waitForAny(promises, 200);
      expect(result).toBe('fast');
    });
  });

  describe('Service waiting', () => {
    test('waitForService should wait for service to be healthy', async () => {
      let isHealthy = false;
      setTimeout(() => { isHealthy = true; }, 100);

      const healthCheck = () => isHealthy;

      await waitForService(healthCheck, {
        timeout: 500,
        interval: 50,
        serviceName: 'test-service'
      });

      expect(isHealthy).toBe(true);
    });

    test('waitForService should timeout if service never becomes healthy', async () => {
      const healthCheck = () => false;

      await expect(waitForService(healthCheck, {
        timeout: 100,
        interval: 20,
        serviceName: 'test-service'
      })).rejects.toThrow('test-service did not become healthy');
    });
  });

  describe('File system waiting', () => {
    const testFile = path.join(__dirname, 'test-wait-file.txt');

    afterEach(async () => {
      try {
        await fs.unlink(testFile);
      } catch (error) {
        // File might not exist, ignore
      }
    });

    test('waitForFile should wait for file to exist', async () => {
      setTimeout(async () => {
        await fs.writeFile(testFile, 'test content');
      }, 100);

      await waitForFile(testFile, { timeout: 500, interval: 50 });

      const exists = await fs.access(testFile).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });

    test('waitForFile should timeout if file never appears', async () => {
      await expect(waitForFile('/non/existent/file', { timeout: 100, interval: 20 }))
        .rejects.toThrow('File /non/existent/file exists check failed');
    });
  });

  describe('Port waiting', () => {
    let server;

    afterEach((done) => {
      if (server) {
        server.close(done);
      } else {
        done();
      }
    });

    test('waitForPort should wait for port to be available', async () => {
      const port = 13579; // Use a specific port for testing

      setTimeout(() => {
        server = net.createServer();
        server.listen(port);
      }, 100);

      await waitForPort(port, 'localhost', { timeout: 500, interval: 50 });

      // Port should now be available
      expect(server.listening).toBe(true);
    });

    test('waitForPort should timeout if port never becomes available', async () => {
      const port = 23579; // Different port that won't be opened

      await expect(waitForPort(port, 'localhost', { timeout: 100, interval: 20 }))
        .rejects.toThrow(`Port ${port} on localhost not available`);
    });
  });

  describe('Utility functions', () => {
    test('waitWithJitter should add randomness to wait time', async () => {
      const baseMs = 100;
      const times = [];

      // Run multiple times to test jitter
      for (let i = 0; i < 5; i++) {
        const start = Date.now();
        await waitWithJitter(baseMs, 50); // 50% jitter
        times.push(Date.now() - start);
      }

      // Times should vary due to jitter
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);
      expect(maxTime - minTime).toBeGreaterThan(20); // Some variation expected
    });

    test('createWaiter should create externally resolvable promise', async () => {
      const waiter = createWaiter();

      setTimeout(() => waiter.resolve('resolved'), 50);

      const result = await waiter.promise;
      expect(result).toBe('resolved');
    });

    test('waitForConditions should wait for all conditions by default', async () => {
      let condition1Met = false;
      let condition2Met = false;

      setTimeout(() => { condition1Met = true; }, 50);
      setTimeout(() => { condition2Met = true; }, 100);

      const conditions = [
        { condition: () => condition1Met, name: 'condition1' },
        { condition: () => condition2Met, name: 'condition2' }
      ];

      await waitForConditions(conditions, { timeout: 200 });

      expect(condition1Met).toBe(true);
      expect(condition2Met).toBe(true);
    });

    test('waitForConditions should support any mode', async () => {
      let condition1Met = false;
      let condition2Met = false;

      setTimeout(() => { condition1Met = true; }, 50);
      // condition2Met stays false

      const conditions = [
        { condition: () => condition1Met, name: 'condition1' },
        { condition: () => condition2Met, name: 'condition2' }
      ];

      await waitForConditions(conditions, { all: false, timeout: 200 });

      expect(condition1Met).toBe(true);
      expect(condition2Met).toBe(false);
    });
  });

  describe('Retry configurations', () => {
    test('retryConfig should provide predefined configurations', () => {
      expect(retryConfig.quick).toEqual({
        maxRetries: 2,
        baseDelay: 500,
        maxDelay: 2000
      });

      expect(retryConfig.normal).toEqual({
        maxRetries: 3,
        baseDelay: 1000,
        maxDelay: 10000
      });

      expect(retryConfig.persistent).toEqual({
        maxRetries: 5,
        baseDelay: 2000,
        maxDelay: 30000
      });

      expect(retryConfig.network).toHaveProperty('shouldRetry');
    });

    test('network retry config should retry on network errors', () => {
      const shouldRetry = retryConfig.network.shouldRetry;

      expect(shouldRetry({ code: 'ECONNRESET' })).toBe(true);
      expect(shouldRetry({ code: 'ENOTFOUND' })).toBe(true);
      expect(shouldRetry({ code: 'EACCES' })).toBe(false);
    });
  });

  describe('Cancellation support', () => {
    test('operations should support AbortSignal', async () => {
      const controller = new AbortController();

      setTimeout(() => controller.abort(), 50);

      const condition = () => false; // Never true

      await expect(waitUntil(condition, {
        timeout: 1000,
        interval: 10,
        signal: controller.signal
      })).rejects.toThrow('Wait cancelled');
    });
  });
});