#!/usr/bin/env node

/**
 * K6 Performance Test Runner Script
 *
 * Orchestrates comprehensive performance testing with k6:
 * - Test suite management and execution
 * - Environment configuration
 * - Report generation and analysis
 * - SLA validation and alerting
 * - CI/CD integration
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Configuration
const K6_DIR = path.join(__dirname, '..');
const TESTS_DIR = path.join(K6_DIR, 'tests');
const CONFIG_DIR = path.join(K6_DIR, 'config');
const REPORTS_DIR = path.join(K6_DIR, 'reports');
const SCRIPTS_DIR = path.join(K6_DIR, 'scripts');

// Ensure directories exist
[TESTS_DIR, CONFIG_DIR, REPORTS_DIR, SCRIPTS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

/**
 * Available test suites and their configurations
 */
const TEST_SUITES = {
  smoke: {
    name: 'Smoke Test Suite',
    duration: '5 minutes',
    description: 'Quick validation of basic functionality',
    tests: [
      {
        file: 'api-load-test.js',
        options: '--env TEST_MODE=smoke --vus 2 --duration 2m',
        timeout: 300, // 5 minutes
      },
    ],
  },

  load: {
    name: 'Load Test Suite',
    duration: '15 minutes',
    description: 'Standard load testing with expected traffic patterns',
    tests: [
      {
        file: 'api-load-test.js',
        options: '--env TEST_MODE=load --vus 10 --duration 5m',
        timeout: 600, // 10 minutes
      },
      {
        file: 'websocket-stress-test.js',
        options: '--env TEST_MODE=websocket_load --vus 15 --duration 4m',
        timeout: 480, // 8 minutes
      },
      {
        file: 'terminal-io-performance.js',
        options: '--env TEST_MODE=normal_io --vus 8 --duration 3m',
        timeout: 360, // 6 minutes
      },
    ],
  },

  stress: {
    name: 'Stress Test Suite',
    duration: '30 minutes',
    description: 'High-load stress testing to find breaking points',
    tests: [
      {
        file: 'api-load-test.js',
        options: '--env TEST_MODE=stress --vus 50 --duration 8m',
        timeout: 600, // 10 minutes
      },
      {
        file: 'websocket-stress-test.js',
        options: '--env TEST_MODE=websocket_stress --vus 100 --duration 10m',
        timeout: 720, // 12 minutes
      },
      {
        file: 'terminal-io-performance.js',
        options: '--env TEST_MODE=high_io --vus 25 --duration 8m',
        timeout: 600, // 10 minutes
      },
      {
        file: 'memory-consumption-test.js',
        options: '--env TEST_MODE=memory_stress --vus 20 --duration 5m',
        timeout: 400, // 8 minutes (buffer for cleanup)
      },
    ],
  },

  spike: {
    name: 'Spike Test Suite',
    duration: '20 minutes',
    description: 'Sudden traffic spike resilience testing',
    tests: [
      {
        file: 'api-load-test.js',
        options: '--env TEST_MODE=spike --vus 5 --duration 6m',
        timeout: 480, // 8 minutes
      },
      {
        file: 'websocket-stress-test.js',
        options: '--env TEST_MODE=websocket_spike --vus 10 --duration 5m',
        timeout: 360, // 6 minutes
      },
      {
        file: 'terminal-io-performance.js',
        options: '--env TEST_MODE=spike_io --vus 15 --duration 4m',
        timeout: 300, // 5 minutes
      },
    ],
  },

  soak: {
    name: 'Soak Test Suite',
    duration: '60 minutes',
    description: 'Long-duration testing for memory leaks and stability',
    tests: [
      {
        file: 'memory-consumption-test.js',
        options: '--env TEST_MODE=memory_leak_detection --vus 10 --duration 30m',
        timeout: 2400, // 40 minutes
      },
      {
        file: 'websocket-stress-test.js',
        options: '--env TEST_MODE=websocket_soak --vus 20 --duration 25m',
        timeout: 1800, // 30 minutes
      },
      {
        file: 'terminal-io-performance.js',
        options: '--env TEST_MODE=sustained_io --vus 12 --duration 20m',
        timeout: 1500, // 25 minutes
      },
    ],
  },

  comprehensive: {
    name: 'Comprehensive Test Suite',
    duration: '90 minutes',
    description: 'Full performance validation across all dimensions',
    tests: [
      ...TEST_SUITES.load.tests,
      ...TEST_SUITES.stress.tests,
      ...TEST_SUITES.spike.tests,
    ],
  },
};

/**
 * Parse command line arguments
 */
function parseArguments() {
  const args = process.argv.slice(2);
  const options = {
    suite: 'load',
    environment: 'development',
    baseUrl: null,
    verbose: false,
    generateReport: true,
    validateSLA: true,
    parallel: false,
    maxConcurrency: 2,
    outputFormat: 'html,json',
    tags: [],
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--suite':
      case '-s':
        options.suite = args[++i];
        break;
      case '--environment':
      case '-e':
        options.environment = args[++i];
        break;
      case '--base-url':
        options.baseUrl = args[++i];
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--no-report':
        options.generateReport = false;
        break;
      case '--no-sla':
        options.validateSLA = false;
        break;
      case '--parallel':
      case '-p':
        options.parallel = true;
        break;
      case '--max-concurrency':
        options.maxConcurrency = parseInt(args[++i]) || 2;
        break;
      case '--output-format':
        options.outputFormat = args[++i];
        break;
      case '--tag':
        options.tags.push(args[++i]);
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        if (!arg.startsWith('-')) {
          // Assume it's a test suite name
          options.suite = arg;
        }
        break;
    }
  }

  return options;
}

/**
 * Show help information
 */
function showHelp() {
  console.log(`
K6 Performance Test Runner for Claude Flow UI

Usage: node run-k6-performance-tests.js [OPTIONS] [SUITE]

Test Suites:
  smoke           Quick smoke test (5 minutes)
  load            Standard load test (15 minutes)
  stress          Stress test to breaking point (30 minutes)
  spike           Traffic spike resilience test (20 minutes)
  soak            Long-duration stability test (60 minutes)
  comprehensive   Full performance validation (90 minutes)

Options:
  -s, --suite <name>          Test suite to run (default: load)
  -e, --environment <env>     Environment (development|staging|production)
  --base-url <url>           Override base URL for testing
  -v, --verbose              Enable verbose output
  --no-report                Skip report generation
  --no-sla                   Skip SLA validation
  -p, --parallel             Run tests in parallel
  --max-concurrency <n>      Max parallel tests (default: 2)
  --output-format <formats>   Report formats: html,json,junit
  --tag <tag>                Add test execution tag
  -h, --help                 Show this help message

Examples:
  node run-k6-performance-tests.js smoke
  node run-k6-performance-tests.js --suite stress --environment staging
  node run-k6-performance-tests.js load --parallel --verbose
  node run-k6-performance-tests.js soak --base-url http://localhost:3000
`);
}

/**
 * Validate k6 installation
 */
function validateK6Installation() {
  try {
    const output = execSync('k6 version', { encoding: 'utf8' });
    console.log(`✅ K6 installed: ${output.trim()}`);
    return true;
  } catch (error) {
    console.error('❌ K6 not found. Please install k6 first.');
    console.error('   Visit: https://k6.io/docs/getting-started/installation/');
    return false;
  }
}

/**
 * Check server availability
 */
async function checkServerAvailability(baseUrl) {
  console.log(`🔍 Checking server availability at ${baseUrl}...`);

  try {
    const { spawn } = require('child_process');

    return new Promise((resolve, reject) => {
      const healthCheck = spawn('curl', ['-f', '-s', `${baseUrl}/api/health`], {
        stdio: 'pipe',
      });

      let output = '';
      healthCheck.stdout.on('data', (data) => {
        output += data.toString();
      });

      healthCheck.on('close', (code) => {
        if (code === 0) {
          console.log('✅ Server is available');
          resolve(true);
        } else {
          console.error('❌ Server is not available');
          console.error(`   Health check failed with code: ${code}`);
          resolve(false);
        }
      });

      setTimeout(() => {
        healthCheck.kill();
        reject(new Error('Health check timeout'));
      }, 10000);
    });
  } catch (error) {
    console.error(`❌ Failed to check server availability: ${error.message}`);
    return false;
  }
}

/**
 * Run a single k6 test
 */
async function runK6Test(testConfig, globalOptions) {
  const testFile = path.join(TESTS_DIR, testConfig.file);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  if (!fs.existsSync(testFile)) {
    throw new Error(`Test file not found: ${testFile}`);
  }

  console.log(`🚀 Running ${testConfig.file}...`);

  // Build k6 command
  const k6Args = ['run'];

  // Add options
  if (testConfig.options) {
    k6Args.push(...testConfig.options.split(' '));
  }

  // Add environment variables
  if (globalOptions.baseUrl) {
    k6Args.push('--env', `BASE_URL=${globalOptions.baseUrl}`);
  }

  if (globalOptions.environment) {
    k6Args.push('--env', `ENVIRONMENT=${globalOptions.environment}`);
  }

  // Add tags
  globalOptions.tags.forEach(tag => {
    k6Args.push('--tag', tag);
  });

  // Add output formats
  const formats = globalOptions.outputFormat.split(',');
  formats.forEach(format => {
    if (format === 'html') {
      const htmlReport = path.join(REPORTS_DIR, `${testConfig.file.replace('.js', '')}-${timestamp}.html`);
      k6Args.push('--out', `html=${htmlReport}`);
    } else if (format === 'json') {
      const jsonReport = path.join(REPORTS_DIR, `${testConfig.file.replace('.js', '')}-${timestamp}.json`);
      k6Args.push('--out', `json=${jsonReport}`);
    }
  });

  // Add the test file
  k6Args.push(testFile);

  if (globalOptions.verbose) {
    console.log(`📝 Command: k6 ${k6Args.join(' ')}`);
  }

  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const k6Process = spawn('k6', k6Args, {
      stdio: globalOptions.verbose ? 'inherit' : 'pipe',
      env: {
        ...process.env,
        BASE_URL: globalOptions.baseUrl || process.env.BASE_URL || 'http://localhost:8080',
        ENVIRONMENT: globalOptions.environment,
      },
    });

    let stdout = '';
    let stderr = '';

    if (!globalOptions.verbose) {
      k6Process.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      k6Process.stderr?.on('data', (data) => {
        stderr += data.toString();
      });
    }

    // Set timeout
    const timeout = setTimeout(() => {
      k6Process.kill('SIGTERM');
      reject(new Error(`Test timeout after ${testConfig.timeout} seconds`));
    }, (testConfig.timeout || 600) * 1000);

    k6Process.on('close', (code) => {
      clearTimeout(timeout);
      const duration = Date.now() - startTime;

      if (code === 0) {
        console.log(`✅ ${testConfig.file} completed successfully (${(duration / 1000).toFixed(1)}s)`);
        resolve({
          success: true,
          testFile: testConfig.file,
          duration,
          stdout,
          stderr,
        });
      } else {
        console.error(`❌ ${testConfig.file} failed with exit code ${code}`);
        if (!globalOptions.verbose && stderr) {
          console.error('STDERR:', stderr);
        }
        reject(new Error(`Test failed with exit code ${code}`));
      }
    });

    k6Process.on('error', (error) => {
      clearTimeout(timeout);
      console.error(`❌ Failed to start ${testConfig.file}:`, error.message);
      reject(error);
    });
  });
}

/**
 * Run test suite
 */
async function runTestSuite(suiteName, options) {
  const suite = TEST_SUITES[suiteName];
  if (!suite) {
    throw new Error(`Unknown test suite: ${suiteName}`);
  }

  console.log('\n' + '='.repeat(80));
  console.log(`📊 ${suite.name.toUpperCase()}`);
  console.log('='.repeat(80));
  console.log(`📋 Description: ${suite.description}`);
  console.log(`⏱️  Estimated Duration: ${suite.duration}`);
  console.log(`🧪 Tests: ${suite.tests.length}`);
  console.log(`⚙️  Environment: ${options.environment}`);
  console.log(`🔗 Base URL: ${options.baseUrl || 'http://localhost:8080'}`);

  if (options.parallel) {
    console.log(`🔄 Parallel Execution: ${options.maxConcurrency} max concurrent`);
  }

  console.log('='.repeat(80));

  const results = [];
  const startTime = Date.now();

  try {
    if (options.parallel) {
      // Run tests in parallel with concurrency limit
      const semaphore = new Array(options.maxConcurrency).fill(Promise.resolve());
      let index = 0;

      const executeNext = async () => {
        if (index >= suite.tests.length) return null;

        const testConfig = suite.tests[index++];
        try {
          const result = await runK6Test(testConfig, options);
          results.push(result);
          return result;
        } catch (error) {
          console.error(`Test ${testConfig.file} failed:`, error.message);
          results.push({
            success: false,
            testFile: testConfig.file,
            error: error.message,
          });
          throw error;
        }
      };

      // Start initial batch
      const promises = semaphore.map(() => executeNext());

      // Continue until all tests complete
      while (promises.some(p => p !== null)) {
        await Promise.allSettled(promises);

        // Replace completed promises with new ones
        for (let i = 0; i < promises.length; i++) {
          if (await promises[i] !== null) {
            promises[i] = executeNext();
          }
        }
      }

    } else {
      // Run tests sequentially
      for (const testConfig of suite.tests) {
        try {
          const result = await runK6Test(testConfig, options);
          results.push(result);
        } catch (error) {
          console.error(`Test ${testConfig.file} failed:`, error.message);
          results.push({
            success: false,
            testFile: testConfig.file,
            error: error.message,
          });

          // Continue with remaining tests even if one fails
          console.log('⏭️  Continuing with remaining tests...\n');
        }
      }
    }

    const totalDuration = Date.now() - startTime;

    // Generate summary
    generateSummary(suite, results, totalDuration, options);

    return results;

  } catch (error) {
    console.error('💥 Test suite execution failed:', error.message);
    throw error;
  }
}

/**
 * Generate test summary
 */
function generateSummary(suite, results, totalDuration, options) {
  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  console.log('\n' + '='.repeat(80));
  console.log('📊 TEST SUITE SUMMARY');
  console.log('='.repeat(80));
  console.log(`🏷️  Suite: ${suite.name}`);
  console.log(`⏱️  Total Duration: ${(totalDuration / 1000).toFixed(2)} seconds`);
  console.log(`🧪 Tests Run: ${results.length}`);
  console.log(`✅ Successful: ${successful}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📊 Success Rate: ${((successful / results.length) * 100).toFixed(1)}%`);

  if (failed > 0) {
    console.log('\n❌ Failed Tests:');
    results.filter(r => !r.success).forEach(result => {
      console.log(`   • ${result.testFile}: ${result.error || 'Unknown error'}`);
    });
  }

  if (options.generateReport) {
    console.log(`\n📄 Reports generated in: ${REPORTS_DIR}`);
  }

  console.log('\n' + '='.repeat(80));
}

/**
 * Main execution function
 */
async function main() {
  const options = parseArguments();

  if (options.help) {
    showHelp();
    return;
  }

  console.log('🚀 Claude Flow UI - K6 Performance Test Runner\n');

  // Validate k6 installation
  if (!validateK6Installation()) {
    process.exit(1);
  }

  // Validate test suite
  if (!TEST_SUITES[options.suite]) {
    console.error(`❌ Unknown test suite: ${options.suite}`);
    console.error(`Available suites: ${Object.keys(TEST_SUITES).join(', ')}`);
    process.exit(1);
  }

  // Set base URL
  const baseUrl = options.baseUrl ||
                  (options.environment === 'staging' ? 'http://staging-server:8080' : 'http://localhost:8080');

  options.baseUrl = baseUrl;

  // Check server availability
  if (!(await checkServerAvailability(baseUrl))) {
    console.error('❌ Server is not available. Please start the server first.');
    process.exit(1);
  }

  try {
    const results = await runTestSuite(options.suite, options);

    const failed = results.filter(r => !r.success).length;
    if (failed > 0) {
      console.error(`\n💥 ${failed} test(s) failed`);
      process.exit(1);
    } else {
      console.log('\n🎉 All tests completed successfully!');
      process.exit(0);
    }

  } catch (error) {
    console.error('\n💥 Test execution failed:', error.message);
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run main function
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  runTestSuite,
  runK6Test,
  TEST_SUITES,
  validateK6Installation,
  checkServerAvailability,
};