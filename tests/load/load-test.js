/**
 * Load Testing Suite
 * Comprehensive load testing using Artillery and custom Node.js scripts
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

class LoadTester {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || 'http://localhost:3000';
    this.concurrency = options.concurrency || 10;
    this.duration = options.duration || 60; // seconds
    this.rampUp = options.rampUp || 10; // seconds
    this.reportDir = options.reportDir || './load-test-reports';
    this.results = {
      requests: 0,
      responses: 0,
      errors: 0,
      timeouts: 0,
      responseTimes: [],
      startTime: null,
      endTime: null
    };
  }

  /**
   * Initialize load testing environment
   */
  async setup() {
    // Create report directory
    if (!fs.existsSync(this.reportDir)) {
      fs.mkdirSync(this.reportDir, { recursive: true });
    }

    // Check if target server is running
    try {
      await axios.get(`${this.baseUrl}/health`);
      console.log('✓ Target server is running');
    } catch (error) {
      throw new Error(`Target server not available: ${error.message}`);
    }
  }

  /**
   * Run Artillery load test
   */
  async runArtilleryTest() {
    return new Promise((resolve, reject) => {
      const configPath = path.join(__dirname, 'artillery-config.yml');
      const reportPath = path.join(this.reportDir, `artillery-report-${Date.now()}.json`);

      const args = [
        'run',
        '--config', configPath,
        '--output', reportPath
      ];

      console.log('Starting Artillery load test...');
      const artillery = spawn('artillery', args, {
        stdio: 'inherit',
        env: { ...process.env, TARGET_URL: this.baseUrl }
      });

      artillery.on('close', (code) => {
        if (code === 0) {
          console.log('✓ Artillery load test completed');

          // Generate HTML report
          this.generateArtilleryReport(reportPath)
            .then(() => resolve(reportPath))
            .catch(reject);
        } else {
          reject(new Error(`Artillery exited with code ${code}`));
        }
      });

      artillery.on('error', (error) => {
        reject(new Error(`Failed to start Artillery: ${error.message}`));
      });
    });
  }

  /**
   * Generate Artillery HTML report
   */
  async generateArtilleryReport(jsonReportPath) {
    return new Promise((resolve, reject) => {
      const htmlReportPath = jsonReportPath.replace('.json', '.html');

      const args = [
        'report',
        '--output', htmlReportPath,
        jsonReportPath
      ];

      const artillery = spawn('artillery', args);

      artillery.on('close', (code) => {
        if (code === 0) {
          console.log(`✓ HTML report generated: ${htmlReportPath}`);
          resolve(htmlReportPath);
        } else {
          reject(new Error(`Artillery report generation failed with code ${code}`));
        }
      });
    });
  }

  /**
   * Custom HTTP load test
   */
  async runHttpLoadTest() {
    console.log('Starting custom HTTP load test...');
    this.results.startTime = Date.now();

    const promises = [];
    const endpoints = [
      '/health',
      '/api/system',
      '/api/terminals'
    ];

    // Create concurrent workers
    for (let i = 0; i < this.concurrency; i++) {
      promises.push(this.httpWorker(i, endpoints));
    }

    // Wait for all workers to complete
    await Promise.all(promises);

    this.results.endTime = Date.now();
    return this.analyzeResults();
  }

  /**
   * HTTP worker for load testing
   */
  async httpWorker(workerId, endpoints) {
    const workerStartTime = Date.now();
    const workerEndTime = workerStartTime + (this.duration * 1000);

    console.log(`Worker ${workerId} started`);

    while (Date.now() < workerEndTime) {
      for (const endpoint of endpoints) {
        try {
          const startTime = Date.now();

          let response;
          if (endpoint === '/api/terminals') {
            // POST request for terminal creation
            response = await axios.post(`${this.baseUrl}${endpoint}`, {
              sessionName: `load-test-${workerId}-${Date.now()}`,
              command: 'echo "load test"',
              cols: 80,
              rows: 24
            }, { timeout: 5000 });
          } else {
            // GET request for other endpoints
            response = await axios.get(`${this.baseUrl}${endpoint}`, { timeout: 5000 });
          }

          const responseTime = Date.now() - startTime;
          this.results.requests++;
          this.results.responses++;
          this.results.responseTimes.push(responseTime);

          // If we created a terminal, clean it up
          if (endpoint === '/api/terminals' && response.data.sessionId) {
            try {
              await axios.delete(`${this.baseUrl}/api/terminals/${response.data.sessionId}`, { timeout: 2000 });
            } catch (cleanupError) {
              // Ignore cleanup errors
            }
          }

        } catch (error) {
          this.results.requests++;
          if (error.code === 'ECONNABORTED') {
            this.results.timeouts++;
          } else {
            this.results.errors++;
          }
        }

        // Small delay between requests
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }

    console.log(`Worker ${workerId} completed`);
  }

  /**
   * WebSocket load test
   */
  async runWebSocketLoadTest() {
    console.log('Starting WebSocket load test...');

    const WebSocket = require('ws');
    const promises = [];

    for (let i = 0; i < this.concurrency; i++) {
      promises.push(this.wsWorker(i));
    }

    await Promise.all(promises);
    console.log('✓ WebSocket load test completed');
  }

  /**
   * WebSocket worker
   */
  async wsWorker(workerId) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://localhost:3000`);
      let messageCount = 0;
      const maxMessages = 100;

      ws.on('open', () => {
        console.log(`WebSocket worker ${workerId} connected`);

        // Send test messages
        const interval = setInterval(() => {
          if (messageCount >= maxMessages) {
            clearInterval(interval);
            ws.close();
            return;
          }

          ws.send(JSON.stringify({
            type: 'terminal-input',
            data: {
              terminalId: `ws-test-${workerId}`,
              data: `echo "WebSocket message ${messageCount}"\n`
            }
          }));

          messageCount++;
        }, 50);
      });

      ws.on('message', (data) => {
        // Handle responses
        try {
          const message = JSON.parse(data);
          // Process message if needed
        } catch (error) {
          // Ignore parsing errors
        }
      });

      ws.on('close', () => {
        console.log(`WebSocket worker ${workerId} disconnected`);
        resolve();
      });

      ws.on('error', (error) => {
        console.error(`WebSocket worker ${workerId} error:`, error.message);
        resolve(); // Don't reject to avoid failing the entire test
      });

      // Timeout after duration
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      }, this.duration * 1000);
    });
  }

  /**
   * Analyze test results
   */
  analyzeResults() {
    const duration = (this.results.endTime - this.results.startTime) / 1000;
    const successRate = ((this.results.responses / this.results.requests) * 100).toFixed(2);
    const avgResponseTime = this.results.responseTimes.length > 0
      ? (this.results.responseTimes.reduce((a, b) => a + b, 0) / this.results.responseTimes.length).toFixed(2)
      : 0;

    const p95ResponseTime = this.results.responseTimes.length > 0
      ? this.percentile(this.results.responseTimes, 95).toFixed(2)
      : 0;

    const p99ResponseTime = this.results.responseTimes.length > 0
      ? this.percentile(this.results.responseTimes, 99).toFixed(2)
      : 0;

    const results = {
      duration: duration,
      totalRequests: this.results.requests,
      successfulResponses: this.results.responses,
      errors: this.results.errors,
      timeouts: this.results.timeouts,
      successRate: successRate,
      requestsPerSecond: (this.results.requests / duration).toFixed(2),
      avgResponseTime: avgResponseTime,
      p95ResponseTime: p95ResponseTime,
      p99ResponseTime: p99ResponseTime,
      minResponseTime: Math.min(...this.results.responseTimes),
      maxResponseTime: Math.max(...this.results.responseTimes)
    };

    // Save results to file
    const reportPath = path.join(this.reportDir, `load-test-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));

    console.log('\n=== Load Test Results ===');
    console.log(`Duration: ${results.duration}s`);
    console.log(`Total Requests: ${results.totalRequests}`);
    console.log(`Successful Responses: ${results.successfulResponses}`);
    console.log(`Errors: ${results.errors}`);
    console.log(`Timeouts: ${results.timeouts}`);
    console.log(`Success Rate: ${results.successRate}%`);
    console.log(`Requests/Second: ${results.requestsPerSecond}`);
    console.log(`Avg Response Time: ${results.avgResponseTime}ms`);
    console.log(`95th Percentile: ${results.p95ResponseTime}ms`);
    console.log(`99th Percentile: ${results.p99ResponseTime}ms`);
    console.log(`Report saved to: ${reportPath}`);

    return results;
  }

  /**
   * Calculate percentile
   */
  percentile(arr, p) {
    const sorted = arr.slice().sort((a, b) => a - b);
    const index = (p / 100) * (sorted.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    const weight = index % 1;

    if (upper >= sorted.length) return sorted[sorted.length - 1];
    return sorted[lower] * (1 - weight) + sorted[upper] * weight;
  }

  /**
   * Run all load tests
   */
  async runAllTests() {
    await this.setup();

    console.log('Running comprehensive load tests...\n');

    try {
      // Run Artillery test
      await this.runArtilleryTest();
      console.log('');

      // Run custom HTTP load test
      await this.runHttpLoadTest();
      console.log('');

      // Run WebSocket load test
      await this.runWebSocketLoadTest();
      console.log('');

      console.log('✓ All load tests completed successfully');
    } catch (error) {
      console.error('Load test failed:', error.message);
      throw error;
    }
  }
}

// CLI interface
if (require.main === module) {
  const loadTester = new LoadTester({
    baseUrl: process.env.TARGET_URL || 'http://localhost:3000',
    concurrency: parseInt(process.env.CONCURRENCY) || 10,
    duration: parseInt(process.env.DURATION) || 60
  });

  loadTester.runAllTests()
    .then(() => {
      console.log('Load testing completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Load testing failed:', error);
      process.exit(1);
    });
}

module.exports = LoadTester;