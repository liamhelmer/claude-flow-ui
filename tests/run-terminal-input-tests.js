#!/usr/bin/env node

/**
 * Terminal Input Test Runner
 * Runs all terminal input tests and provides comprehensive reporting
 */

const { spawn } = require('child_process');
const path = require('path');

class TerminalInputTestRunner {
  constructor() {
    this.results = {
      unitTests: null,
      verificationTests: null,
      stressTests: null,
      manualTests: null
    };
    this.startTime = Date.now();
  }

  async runCommand(command, args = [], options = {}) {
    return new Promise((resolve, reject) => {
      console.log(`🔧 Running: ${command} ${args.join(' ')}`);

      const process = spawn(command, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        ...options
      });

      let stdout = '';
      let stderr = '';

      process.stdout.on('data', (data) => {
        const text = data.toString();
        stdout += text;
        console.log(text.trim());
      });

      process.stderr.on('data', (data) => {
        const text = data.toString();
        stderr += text;
        console.error(text.trim());
      });

      process.on('close', (code) => {
        resolve({
          code,
          stdout,
          stderr,
          success: code === 0
        });
      });

      process.on('error', reject);
    });
  }

  async runUnitTests() {
    console.log('\n🧪 Running Unit Tests...');
    console.log('=' .repeat(50));

    try {
      // Check if Jest is available
      const jestResult = await this.runCommand('npx', [
        'jest',
        'tests/terminal-input-unit.test.ts',
        '--verbose',
        '--no-cache'
      ]);

      this.results.unitTests = {
        success: jestResult.success,
        output: jestResult.stdout,
        errors: jestResult.stderr,
        details: this.parseJestOutput(jestResult.stdout)
      };

      console.log(`Unit Tests: ${jestResult.success ? '✅ PASS' : '❌ FAIL'}`);

    } catch (error) {
      console.log('⚠️ Jest not available, skipping unit tests');
      this.results.unitTests = {
        success: false,
        skipped: true,
        reason: 'Jest not configured'
      };
    }
  }

  async runVerificationTests() {
    console.log('\n🔍 Running Verification Tests...');
    console.log('=' .repeat(50));

    try {
      const verificationResult = await this.runCommand('node', [
        'tests/terminal-input-verification.test.js'
      ]);

      this.results.verificationTests = {
        success: verificationResult.success,
        output: verificationResult.stdout,
        errors: verificationResult.stderr,
        details: this.parseVerificationOutput(verificationResult.stdout)
      };

      console.log(`Verification Tests: ${verificationResult.success ? '✅ PASS' : '❌ FAIL'}`);

    } catch (error) {
      console.error('💥 Verification tests failed to run:', error.message);
      this.results.verificationTests = {
        success: false,
        error: error.message
      };
    }
  }

  async runStressTests() {
    console.log('\n💪 Running Stress Tests...');
    console.log('=' .repeat(50));

    try {
      const stressResult = await this.runCommand('node', [
        'tests/terminal-input-stress-test.js'
      ]);

      this.results.stressTests = {
        success: stressResult.success,
        output: stressResult.stdout,
        errors: stressResult.stderr,
        details: this.parseStressOutput(stressResult.stdout)
      };

      console.log(`Stress Tests: ${stressResult.success ? '✅ PASS' : '❌ FAIL'}`);

    } catch (error) {
      console.error('💥 Stress tests failed to run:', error.message);
      this.results.stressTests = {
        success: false,
        error: error.message
      };
    }
  }

  async runExistingTests() {
    console.log('\n🔄 Running Existing Regression Tests...');
    console.log('=' .repeat(50));

    const existingTests = [
      'tests/simple-input-test.js',
      'tests/terminal-input-regression.test.js'
    ];

    const existingResults = [];

    for (const testFile of existingTests) {
      try {
        console.log(`\n📋 Running ${testFile}...`);
        const result = await this.runCommand('node', [testFile]);

        existingResults.push({
          file: testFile,
          success: result.success,
          output: result.stdout,
          errors: result.stderr
        });

        console.log(`${testFile}: ${result.success ? '✅ PASS' : '❌ FAIL'}`);

      } catch (error) {
        console.error(`💥 ${testFile} failed:`, error.message);
        existingResults.push({
          file: testFile,
          success: false,
          error: error.message
        });
      }
    }

    this.results.existingTests = existingResults;
  }

  parseJestOutput(output) {
    const details = {
      testsRun: 0,
      testsPassed: 0,
      testsFailed: 0,
      suites: []
    };

    // Extract test results from Jest output
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('Tests:')) {
        const match = line.match(/(\d+) passed.*?(\d+) total/);
        if (match) {
          details.testsPassed = parseInt(match[1]);
          details.testsRun = parseInt(match[2]);
          details.testsFailed = details.testsRun - details.testsPassed;
        }
      }
    }

    return details;
  }

  parseVerificationOutput(output) {
    const details = {
      overallSuccess: false,
      testsRun: 0,
      testsPassed: 0,
      specificResults: {}
    };

    // Extract results from verification test output
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('Overall Success:')) {
        details.overallSuccess = line.includes('✅ PASS');
      }
      if (line.includes('Tests Passed:')) {
        const match = line.match(/(\d+)\/(\d+)/);
        if (match) {
          details.testsPassed = parseInt(match[1]);
          details.testsRun = parseInt(match[2]);
        }
      }
      // Parse individual test results
      if (line.includes(': ✅') || line.includes(': ❌')) {
        const parts = line.split(':');
        if (parts.length >= 2) {
          const testName = parts[0].trim();
          const passed = line.includes('✅');
          details.specificResults[testName] = passed;
        }
      }
    }

    return details;
  }

  parseStressOutput(output) {
    const details = {
      overallSuccess: false,
      successRate: 0,
      performanceMetrics: {}
    };

    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('Overall Success Rate:')) {
        const match = line.match(/([\d.]+)%/);
        if (match) {
          details.successRate = parseFloat(match[1]);
        }
      }
      if (line.includes('OVERALL STRESS TEST:')) {
        details.overallSuccess = line.includes('✅ PASS');
      }
    }

    return details;
  }

  generateReport() {
    const duration = Date.now() - this.startTime;
    const report = {
      timestamp: new Date().toISOString(),
      duration: `${(duration / 1000).toFixed(1)}s`,
      summary: {
        overallSuccess: this.calculateOverallSuccess(),
        testsCompleted: this.countCompletedTests(),
        testsPassed: this.countPassedTests()
      },
      details: this.results,
      recommendations: this.generateRecommendations()
    };

    return report;
  }

  calculateOverallSuccess() {
    const results = Object.values(this.results).filter(r => r !== null);
    if (results.length === 0) return false;

    const successCount = results.filter(r => r.success && !r.skipped).length;
    const totalCount = results.filter(r => !r.skipped).length;

    return totalCount > 0 && (successCount / totalCount) >= 0.7; // 70% pass rate
  }

  countCompletedTests() {
    return Object.values(this.results).filter(r => r !== null && !r.skipped).length;
  }

  countPassedTests() {
    return Object.values(this.results).filter(r => r !== null && r.success).length;
  }

  generateRecommendations() {
    const recommendations = [];

    if (this.results.unitTests && !this.results.unitTests.success && !this.results.unitTests.skipped) {
      recommendations.push('Fix failing unit tests - these indicate fundamental issues with terminal input handling');
    }

    if (this.results.verificationTests && !this.results.verificationTests.success) {
      recommendations.push('Address verification test failures - these represent real-world usage scenarios');
    }

    if (this.results.stressTests && !this.results.stressTests.success) {
      recommendations.push('Improve performance and stability under stress conditions');
    }

    if (this.results.existingTests) {
      const failedExisting = this.results.existingTests.filter(t => !t.success);
      if (failedExisting.length > 0) {
        recommendations.push(`Fix existing regression tests: ${failedExisting.map(t => path.basename(t.file)).join(', ')}`);
      }
    }

    if (recommendations.length === 0) {
      recommendations.push('All tests passed! Terminal input functionality appears to be working correctly.');
    }

    return recommendations;
  }

  printReport(report) {
    console.log('\n' + '🎯 TERMINAL INPUT TEST REPORT'.padStart(50));
    console.log('=' .repeat(80));
    console.log(`Test Duration: ${report.duration}`);
    console.log(`Overall Success: ${report.summary.overallSuccess ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`Tests Completed: ${report.summary.testsCompleted}`);
    console.log(`Tests Passed: ${report.summary.testsPassed}`);

    console.log('\n📋 Test Results Summary:');
    Object.entries(this.results).forEach(([testType, result]) => {
      if (result === null) {
        console.log(`  ${testType}: ⏭️ Skipped`);
      } else if (result.skipped) {
        console.log(`  ${testType}: ⏭️ Skipped (${result.reason})`);
      } else {
        console.log(`  ${testType}: ${result.success ? '✅ PASS' : '❌ FAIL'}`);
      }
    });

    if (report.recommendations.length > 0) {
      console.log('\n💡 Recommendations:');
      report.recommendations.forEach((rec, i) => {
        console.log(`  ${i + 1}. ${rec}`);
      });
    }

    // Detailed results for debugging
    if (!report.summary.overallSuccess) {
      console.log('\n🔍 Detailed Failure Analysis:');

      Object.entries(this.results).forEach(([testType, result]) => {
        if (result && !result.success && !result.skipped) {
          console.log(`\n❌ ${testType} Failures:`);
          if (result.errors) {
            console.log(`   Errors: ${result.errors.substring(0, 200)}...`);
          }
          if (result.details) {
            console.log(`   Details:`, JSON.stringify(result.details, null, 2));
          }
        }
      });
    }

    console.log('\n' + '=' .repeat(80));
  }

  async runAllTests() {
    console.log('🚀 Starting Terminal Input Test Suite');
    console.log('This will test all aspects of terminal input functionality');
    console.log('=' .repeat(80));

    // Run all test categories
    await this.runUnitTests();
    await this.runVerificationTests();
    await this.runStressTests();
    await this.runExistingTests();

    // Generate and print report
    const report = this.generateReport();
    this.printReport(report);

    return report;
  }
}

// Main execution
async function main() {
  const runner = new TerminalInputTestRunner();

  try {
    const report = await runner.runAllTests();

    // Save report to file
    const fs = require('fs');
    fs.writeFileSync(
      path.join(__dirname, 'terminal-input-test-report.json'),
      JSON.stringify(report, null, 2)
    );

    console.log('\n📄 Full report saved to: tests/terminal-input-test-report.json');

    process.exit(report.summary.overallSuccess ? 0 : 1);

  } catch (error) {
    console.error('💥 Test runner failed:', error);
    process.exit(1);
  }
}

// Export for use in other scripts
module.exports = { TerminalInputTestRunner };

// Run if called directly
if (require.main === module) {
  main();
}