#!/usr/bin/env node

/**
 * Master Test Runner
 * Runs all test suites for the embedded static build solution
 * 
 * Usage: node run-all-tests.js [--suite=suiteName] [--parallel] [--verbose]
 */

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

// Import test suites
const GlobalInstallTester = require('./test-global-install');
const StaticServeTester = require('./test-static-serve');
const ProductionModeTester = require('./test-production-mode');
const E2EWorkflowTester = require('./test-e2e-workflow');
const NpmRegistryTester = require('./test-npm-registry');
const PackageValidator = require('./validate-package');

class MasterTestRunner {
  constructor(options = {}) {
    this.options = {
      suite: options.suite || 'all',
      parallel: options.parallel || false,
      verbose: options.verbose || false,
      saveResults: options.saveResults !== false
    };
    
    this.testSuites = {
      'global-install': GlobalInstallTester,
      'static-serve': StaticServeTester,
      'production-mode': ProductionModeTester,
      'e2e-workflow': E2EWorkflowTester,
      'npm-registry': NpmRegistryTester,
      'package-validation': PackageValidator
    };
    
    this.results = {
      timestamp: new Date().toISOString(),
      totalTime: 0,
      suites: {},
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0
      }
    };
    
    this.projectRoot = path.join(__dirname, '..');
  }

  log(message) {
    console.log(`[MasterTestRunner] ${message}`);
  }

  error(message) {
    console.error(`[MasterTestRunner ERROR] ${message}`);
  }

  verbose(message) {
    if (this.options.verbose) {
      console.log(`[VERBOSE] ${message}`);
    }
  }

  async runSuite(suiteName, SuiteClass) {
    const startTime = performance.now();
    this.log(`\n${'='.repeat(60)}`);
    this.log(`🧪 Running ${suiteName} test suite...`);
    this.log(`${'='.repeat(60)}`);
    
    try {
      const tester = new SuiteClass();
      const result = await tester.run();
      
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);
      
      this.results.suites[suiteName] = {
        ...result,
        duration,
        startTime: new Date(Date.now() - duration).toISOString(),
        endTime: new Date().toISOString()
      };
      
      // Update summary
      this.results.summary.total++;
      if (result.success) {
        this.results.summary.passed++;
        this.log(`✅ ${suiteName} test suite PASSED (${duration}ms)`);
      } else {
        this.results.summary.failed++;
        this.log(`❌ ${suiteName} test suite FAILED (${duration}ms)`);
      }
      
      // Log individual test results if verbose
      if (this.options.verbose && result.results && result.results.tests) {
        this.verbose(`${suiteName} detailed results:`);
        result.results.tests.forEach(test => {
          this.verbose(`  ${test.status === 'PASSED' ? '✅' : '❌'} ${test.name}`);
          if (test.status === 'FAILED' && test.error) {
            this.verbose(`    Error: ${test.error}`);
          }
        });
      }
      
      return result;
      
    } catch (error) {
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);
      
      this.results.suites[suiteName] = {
        success: false,
        error: error.message,
        duration,
        startTime: new Date(Date.now() - duration).toISOString(),
        endTime: new Date().toISOString()
      };
      
      this.results.summary.total++;
      this.results.summary.failed++;
      this.error(`❌ ${suiteName} test suite ERROR (${duration}ms): ${error.message}`);
      
      return { success: false, error: error.message };
    }
  }

  async runSequential() {
    this.log('Running test suites sequentially...');
    
    const suitesToRun = this.options.suite === 'all' 
      ? Object.keys(this.testSuites)
      : [this.options.suite];
    
    for (const suiteName of suitesToRun) {
      if (this.testSuites[suiteName]) {
        await this.runSuite(suiteName, this.testSuites[suiteName]);
      } else {
        this.error(`Unknown test suite: ${suiteName}`);
        this.results.summary.total++;
        this.results.summary.skipped++;
      }
    }
  }

  async runParallel() {
    this.log('Running test suites in parallel...');
    
    const suitesToRun = this.options.suite === 'all' 
      ? Object.keys(this.testSuites)
      : [this.options.suite];
    
    const suitePromises = suitesToRun.map(suiteName => {
      if (this.testSuites[suiteName]) {
        return this.runSuite(suiteName, this.testSuites[suiteName]);
      } else {
        this.error(`Unknown test suite: ${suiteName}`);
        this.results.summary.total++;
        this.results.summary.skipped++;
        return Promise.resolve({ success: false, error: 'Unknown suite' });
      }
    });
    
    await Promise.all(suitePromises);
  }

  generateReport() {
    const report = {
      ...this.results,
      totalTime: this.results.totalTime,
      summary: {
        ...this.results.summary,
        successRate: this.results.summary.total > 0 
          ? Math.round((this.results.summary.passed / this.results.summary.total) * 100)
          : 0
      }
    };

    // Add detailed statistics
    report.statistics = {
      averageDuration: this.results.summary.total > 0 
        ? Math.round(Object.values(this.results.suites).reduce((sum, suite) => sum + (suite.duration || 0), 0) / this.results.summary.total)
        : 0,
      
      slowestSuite: Object.entries(this.results.suites).reduce((slowest, [name, suite]) => {
        if (!slowest || (suite.duration && suite.duration > (slowest.duration || 0))) {
          return { name, duration: suite.duration };
        }
        return slowest;
      }, null),
      
      fastestSuite: Object.entries(this.results.suites).reduce((fastest, [name, suite]) => {
        if (!fastest || (suite.duration && suite.duration < (fastest.duration || Infinity))) {
          return { name, duration: suite.duration };
        }
        return fastest;
      }, null)
    };

    // Add test counts from individual suites
    report.testCounts = {
      totalTests: 0,
      passedTests: 0,
      failedTests: 0
    };

    Object.values(this.results.suites).forEach(suite => {
      if (suite.results && suite.results.tests) {
        report.testCounts.totalTests += suite.results.tests.length;
        report.testCounts.passedTests += suite.results.tests.filter(t => t.status === 'PASSED').length;
        report.testCounts.failedTests += suite.results.tests.filter(t => t.status === 'FAILED').length;
      }
    });

    return report;
  }

  printSummary() {
    this.log('\n' + '='.repeat(80));
    this.log('🎯 TEST EXECUTION SUMMARY');
    this.log('='.repeat(80));
    
    this.log(`⏱️  Total Time: ${this.results.totalTime}ms`);
    this.log(`📊 Test Suites: ${this.results.summary.total}`);
    this.log(`✅ Passed: ${this.results.summary.passed}`);
    this.log(`❌ Failed: ${this.results.summary.failed}`);
    this.log(`⏭️  Skipped: ${this.results.summary.skipped}`);
    
    const successRate = this.results.summary.total > 0 
      ? Math.round((this.results.summary.passed / this.results.summary.total) * 100)
      : 0;
    
    this.log(`📈 Success Rate: ${successRate}%`);
    
    // Suite breakdown
    this.log('\n📋 Suite Breakdown:');
    Object.entries(this.results.suites).forEach(([name, suite]) => {
      const status = suite.success ? '✅ PASS' : '❌ FAIL';
      const duration = suite.duration ? `${suite.duration}ms` : 'N/A';
      this.log(`   ${status} ${name.padEnd(20)} (${duration})`);
      
      if (suite.results && suite.results.tests && this.options.verbose) {
        const passed = suite.results.tests.filter(t => t.status === 'PASSED').length;
        const failed = suite.results.tests.filter(t => t.status === 'FAILED').length;
        this.log(`      Individual tests: ${passed}✅ ${failed}❌`);
      }
    });
    
    // Final verdict
    this.log('\n' + '='.repeat(80));
    if (this.results.summary.failed === 0) {
      this.log('🎉 ALL TESTS PASSED! Package is ready for deployment.');
    } else {
      this.log('💥 SOME TESTS FAILED! Please review and fix issues before deployment.');
    }
    this.log('='.repeat(80));
  }

  async saveResults() {
    if (!this.options.saveResults) return;

    const report = this.generateReport();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportPath = path.join(this.projectRoot, `test-results-${timestamp}.json`);
    
    try {
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      this.log(`📄 Test results saved to: ${reportPath}`);
    } catch (error) {
      this.error(`Failed to save test results: ${error.message}`);
    }
  }

  async run() {
    const startTime = performance.now();
    
    this.log('🚀 Starting comprehensive test execution...');
    this.log(`Mode: ${this.options.parallel ? 'Parallel' : 'Sequential'}`);
    this.log(`Suite: ${this.options.suite}`);
    this.log(`Verbose: ${this.options.verbose}`);
    
    try {
      if (this.options.parallel) {
        await this.runParallel();
      } else {
        await this.runSequential();
      }
      
      const endTime = performance.now();
      this.results.totalTime = Math.round(endTime - startTime);
      
      await this.saveResults();
      this.printSummary();
      
      return this.results.summary.failed === 0;
      
    } catch (error) {
      this.error(`Test execution failed: ${error.message}`);
      return false;
    }
  }
}

// CLI argument parsing
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {};
  
  args.forEach(arg => {
    if (arg.startsWith('--suite=')) {
      options.suite = arg.split('=')[1];
    } else if (arg === '--parallel') {
      options.parallel = true;
    } else if (arg === '--verbose') {
      options.verbose = true;
    } else if (arg === '--no-save') {
      options.saveResults = false;
    } else if (arg === '--help') {
      console.log(`
Test Runner Usage:
  node run-all-tests.js [options]

Options:
  --suite=NAME     Run specific test suite (global-install, static-serve, production-mode, e2e-workflow, npm-registry, package-validation)
  --parallel       Run test suites in parallel
  --verbose        Show detailed test output
  --no-save        Don't save test results to file
  --help           Show this help

Examples:
  node run-all-tests.js                           # Run all tests sequentially
  node run-all-tests.js --parallel --verbose      # Run all tests in parallel with verbose output
  node run-all-tests.js --suite=global-install    # Run only global installation tests
      `);
      process.exit(0);
    }
  });
  
  return options;
}

// Run tests if this file is executed directly
if (require.main === module) {
  const options = parseArgs();
  const runner = new MasterTestRunner(options);
  
  runner.run()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Test runner error:', error);
      process.exit(1);
    });
}

module.exports = MasterTestRunner;