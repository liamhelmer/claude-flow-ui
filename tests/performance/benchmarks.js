/**
 * Performance Benchmarking Suite
 * Comprehensive performance tests and benchmarks
 */

const Benchmark = require('benchmark');
const fs = require('fs');
const path = require('path');
const { performance, PerformanceObserver } = require('perf_hooks');

class PerformanceBenchmarks {
  constructor() {
    this.results = [];
    this.suite = new Benchmark.Suite();
    this.startTime = Date.now();
    this.memoryBaseline = process.memoryUsage();
  }

  /**
   * Initialize performance observer
   */
  initializeObserver() {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        this.results.push({
          name: entry.name,
          duration: entry.duration,
          startTime: entry.startTime,
          type: entry.entryType
        });
      }
    });

    observer.observe({ type: 'measure', buffered: true });
    observer.observe({ type: 'mark', buffered: true });

    return observer;
  }

  /**
   * Memory usage benchmark
   */
  benchmarkMemoryUsage() {
    const suite = new Benchmark.Suite('Memory Usage');

    // Baseline memory measurement
    suite.add('Memory Baseline', () => {
      const usage = process.memoryUsage();
      return usage;
    });

    // Array creation benchmark
    suite.add('Array Creation (1000 items)', () => {
      const arr = new Array(1000).fill(0).map((_, i) => i);
      return arr;
    });

    // Object creation benchmark
    suite.add('Object Creation (1000 objects)', () => {
      const objects = [];
      for (let i = 0; i < 1000; i++) {
        objects.push({ id: i, name: `Object ${i}`, data: Math.random() });
      }
      return objects;
    });

    // String manipulation benchmark
    suite.add('String Concatenation (1000 ops)', () => {
      let str = '';
      for (let i = 0; i < 1000; i++) {
        str += `Item ${i} `;
      }
      return str;
    });

    // JSON operations benchmark
    suite.add('JSON Parse/Stringify (100 objects)', () => {
      const objects = Array(100).fill(0).map((_, i) => ({
        id: i,
        name: `Object ${i}`,
        data: { nested: true, value: Math.random() }
      }));

      const json = JSON.stringify(objects);
      const parsed = JSON.parse(json);
      return parsed;
    });

    return this.runSuite(suite);
  }

  /**
   * CPU intensive operations benchmark
   */
  benchmarkCPUOperations() {
    const suite = new Benchmark.Suite('CPU Operations');

    // Fibonacci calculation
    suite.add('Fibonacci (30)', () => {
      function fibonacci(n) {
        if (n <= 1) return n;
        return fibonacci(n - 1) + fibonacci(n - 2);
      }
      return fibonacci(30);
    });

    // Prime number calculation
    suite.add('Prime Numbers (up to 1000)', () => {
      function isPrime(n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 === 0 || n % 3 === 0) return false;
        for (let i = 5; i * i <= n; i += 6) {
          if (n % i === 0 || n % (i + 2) === 0) return false;
        }
        return true;
      }

      const primes = [];
      for (let i = 2; i <= 1000; i++) {
        if (isPrime(i)) primes.push(i);
      }
      return primes;
    });

    // Sorting operations
    suite.add('Array Sort (10000 items)', () => {
      const arr = Array(10000).fill(0).map(() => Math.random());
      return arr.sort((a, b) => a - b);
    });

    // Mathematical operations
    suite.add('Mathematical Operations (10000 ops)', () => {
      let result = 0;
      for (let i = 0; i < 10000; i++) {
        result += Math.sin(i) * Math.cos(i) * Math.sqrt(i);
      }
      return result;
    });

    return this.runSuite(suite);
  }

  /**
   * I/O operations benchmark
   */
  async benchmarkIOOperations() {
    const suite = new Benchmark.Suite('I/O Operations');

    // File system operations
    suite.add('File Read/Write (small file)', {
      defer: true,
      fn: (deferred) => {
        const content = 'Test content for performance benchmark';
        const filePath = path.join(__dirname, 'temp-benchmark-file.txt');

        fs.writeFile(filePath, content, (err) => {
          if (err) throw err;
          fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) throw err;
            fs.unlink(filePath, () => {
              deferred.resolve();
            });
          });
        });
      }
    });

    // Buffer operations
    suite.add('Buffer Operations (1MB)', () => {
      const size = 1024 * 1024; // 1MB
      const buffer = Buffer.alloc(size);
      buffer.fill('A');
      const string = buffer.toString();
      const newBuffer = Buffer.from(string);
      return newBuffer;
    });

    return this.runSuite(suite);
  }

  /**
   * HTTP/WebSocket simulation benchmark
   */
  benchmarkNetworkOperations() {
    const suite = new Benchmark.Suite('Network Simulation');

    // HTTP request simulation
    suite.add('HTTP Request Simulation', () => {
      // Simulate HTTP request processing
      const requestData = {
        method: 'POST',
        url: '/api/terminals',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionName: 'benchmark-session',
          command: 'echo "performance test"'
        })
      };

      // Simulate request processing
      const processed = {
        ...requestData,
        timestamp: Date.now(),
        id: Math.random().toString(36).substr(2, 9)
      };

      // Simulate response
      const response = {
        status: 200,
        data: {
          success: true,
          sessionId: processed.id,
          timestamp: processed.timestamp
        }
      };

      return response;
    });

    // WebSocket message simulation
    suite.add('WebSocket Message Simulation', () => {
      const messages = [];

      // Simulate 100 WebSocket messages
      for (let i = 0; i < 100; i++) {
        const message = {
          type: 'terminal-input',
          data: {
            terminalId: `terminal-${i}`,
            data: `echo "Message ${i}"\n`,
            timestamp: Date.now()
          }
        };

        // Simulate message processing
        const processed = {
          ...message,
          id: Math.random().toString(36).substr(2, 9),
          processed: true
        };

        messages.push(processed);
      }

      return messages;
    });

    return this.runSuite(suite);
  }

  /**
   * Terminal operations benchmark
   */
  benchmarkTerminalOperations() {
    const suite = new Benchmark.Suite('Terminal Operations');

    // Terminal session simulation
    suite.add('Terminal Session Management', () => {
      const sessions = new Map();

      // Create sessions
      for (let i = 0; i < 100; i++) {
        const sessionId = `session-${i}`;
        sessions.set(sessionId, {
          id: sessionId,
          created: Date.now(),
          lastActivity: Date.now(),
          commands: [],
          output: []
        });
      }

      // Process commands
      sessions.forEach((session, id) => {
        for (let j = 0; j < 10; j++) {
          const command = `echo "Command ${j} in ${id}"`;
          session.commands.push({
            command,
            timestamp: Date.now(),
            exitCode: 0
          });

          session.output.push({
            data: `Output for command ${j}`,
            timestamp: Date.now()
          });
        }
      });

      // Cleanup old sessions
      const cutoff = Date.now() - 60000; // 1 minute ago
      const toDelete = [];
      sessions.forEach((session, id) => {
        if (session.lastActivity < cutoff) {
          toDelete.push(id);
        }
      });

      toDelete.forEach(id => sessions.delete(id));

      return sessions.size;
    });

    // ANSI escape sequence processing
    suite.add('ANSI Escape Sequence Processing', () => {
      const ansiSequences = [
        '\x1b[31mRed text\x1b[0m',
        '\x1b[32mGreen text\x1b[0m',
        '\x1b[33mYellow text\x1b[0m',
        '\x1b[1mBold text\x1b[0m',
        '\x1b[4mUnderlined text\x1b[0m',
        '\x1b[2J\x1b[H',  // Clear screen
        '\x1b[10;20H',    // Move cursor
      ];

      const processed = [];
      for (let i = 0; i < 1000; i++) {
        const sequence = ansiSequences[i % ansiSequences.length];
        // Simulate ANSI processing
        const processed_seq = sequence.replace(/\x1b\[[0-9;]*m/g, '');
        processed.push(processed_seq);
      }

      return processed;
    });

    return this.runSuite(suite);
  }

  /**
   * Run a benchmark suite
   */
  runSuite(suite) {
    return new Promise((resolve) => {
      const results = [];

      suite
        .on('cycle', (event) => {
          const benchmark = event.target;
          results.push({
            name: benchmark.name,
            hz: benchmark.hz,
            rme: benchmark.stats.rme,
            sample: benchmark.stats.sample.length,
            mean: benchmark.stats.mean,
            deviation: benchmark.stats.deviation
          });

          console.log(`  ${benchmark.name}: ${benchmark.hz.toFixed(2)} ops/sec ±${benchmark.stats.rme.toFixed(2)}%`);
        })
        .on('complete', () => {
          const fastest = suite.filter('fastest').map('name');
          console.log(`  Fastest: ${fastest.join(', ')}`);
          resolve(results);
        })
        .run({ async: true });
    });
  }

  /**
   * Memory leak detection
   */
  async detectMemoryLeaks() {
    console.log('Running memory leak detection...');

    const iterations = 100;
    const memorySnapshots = [];

    for (let i = 0; i < iterations; i++) {
      // Simulate operations that might leak memory
      const largeArray = new Array(10000).fill(0).map((_, idx) => ({
        id: idx,
        data: Math.random(),
        timestamp: Date.now()
      }));

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      // Take memory snapshot
      const memUsage = process.memoryUsage();
      memorySnapshots.push({
        iteration: i,
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external,
        rss: memUsage.rss
      });

      // Clean up
      largeArray.length = 0;

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // Analyze memory growth
    const startHeap = memorySnapshots[0].heapUsed;
    const endHeap = memorySnapshots[memorySnapshots.length - 1].heapUsed;
    const memoryGrowth = endHeap - startHeap;
    const growthPercentage = (memoryGrowth / startHeap) * 100;

    return {
      startHeap,
      endHeap,
      memoryGrowth,
      growthPercentage,
      snapshots: memorySnapshots,
      potentialLeak: growthPercentage > 50 // Threshold for potential leak
    };
  }

  /**
   * Generate performance report
   */
  generateReport(benchmarkResults, memoryLeakResults) {
    const report = {
      timestamp: new Date().toISOString(),
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        cpus: require('os').cpus().length,
        totalMemory: require('os').totalmem(),
        freeMemory: require('os').freemem()
      },
      memoryBaseline: this.memoryBaseline,
      benchmarks: benchmarkResults,
      memoryLeak: memoryLeakResults,
      duration: Date.now() - this.startTime
    };

    // Save report to file
    const reportPath = path.join(__dirname, `performance-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    console.log(`\nPerformance report saved to: ${reportPath}`);
    return report;
  }

  /**
   * Run all benchmarks
   */
  async runAllBenchmarks() {
    console.log('🚀 Starting Performance Benchmarks...\n');

    const observer = this.initializeObserver();
    const benchmarkResults = {};

    try {
      console.log('📊 Memory Usage Benchmarks:');
      benchmarkResults.memory = await this.benchmarkMemoryUsage();

      console.log('\n⚡ CPU Operations Benchmarks:');
      benchmarkResults.cpu = await this.benchmarkCPUOperations();

      console.log('\n💾 I/O Operations Benchmarks:');
      benchmarkResults.io = await this.benchmarkIOOperations();

      console.log('\n🌐 Network Operations Benchmarks:');
      benchmarkResults.network = await this.benchmarkNetworkOperations();

      console.log('\n🖥️  Terminal Operations Benchmarks:');
      benchmarkResults.terminal = await this.benchmarkTerminalOperations();

      console.log('\n🔍 Memory Leak Detection:');
      const memoryLeakResults = await this.detectMemoryLeaks();

      if (memoryLeakResults.potentialLeak) {
        console.log(`⚠️  Potential memory leak detected! Growth: ${memoryLeakResults.growthPercentage.toFixed(2)}%`);
      } else {
        console.log(`✅ No significant memory leaks detected. Growth: ${memoryLeakResults.growthPercentage.toFixed(2)}%`);
      }

      // Generate comprehensive report
      const report = this.generateReport(benchmarkResults, memoryLeakResults);

      observer.disconnect();

      console.log('\n✅ Performance benchmarks completed!');
      return report;

    } catch (error) {
      observer.disconnect();
      console.error('❌ Benchmark failed:', error);
      throw error;
    }
  }
}

// CLI interface
if (require.main === module) {
  const benchmarks = new PerformanceBenchmarks();

  benchmarks.runAllBenchmarks()
    .then((report) => {
      console.log('\n📈 Benchmark Summary:');
      console.log(`   Duration: ${report.duration}ms`);
      console.log(`   Memory Growth: ${report.memoryLeak.growthPercentage.toFixed(2)}%`);
      console.log(`   Platform: ${report.environment.platform} ${report.environment.arch}`);
      console.log(`   Node.js: ${report.environment.nodeVersion}`);
      process.exit(0);
    })
    .catch((error) => {
      console.error('Benchmarks failed:', error);
      process.exit(1);
    });
}

module.exports = PerformanceBenchmarks;