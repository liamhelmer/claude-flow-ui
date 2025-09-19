#!/usr/bin/env node

/**
 * COMPREHENSIVE REGRESSION TEST RUNNER
 *
 * Orchestrates execution of all terminal regression tests:
 * 1. Terminal Refresh Regression Test
 * 2. Terminal Switching Regression Test
 * 3. Terminal Workaround Validation Test
 *
 * Provides unified reporting and analysis of regression issues
 */

const fs = require('fs');
const path = require('path');

// Import test classes
const TerminalRefreshRegressionTest = require('./terminal-refresh-regression.test.js');
const TerminalSwitchingRegressionTest = require('./terminal-switching-regression.test.js');
const TerminalWorkaroundValidationTest = require('./terminal-workaround-validation.test.js');

class RegressionTestRunner {
  constructor() {
    this.results = {
      refreshTest: null,
      switchingTest: null,
      workaroundTest: null,
      overallStatus: null
    };
    this.startTime = Date.now();
    this.testConfig = {
      runRefreshTest: true,
      runSwitchingTest: true,
      runWorkaroundTest: true,
      generateReport: true,
      exitOnFirstFailure: false
    };
  }

  parseCommandLineArgs() {
    const args = process.argv.slice(2);

    args.forEach(arg => {
      switch (arg) {
        case '--refresh-only':
          this.testConfig.runSwitchingTest = false;
          this.testConfig.runWorkaroundTest = false;
          break;
        case '--switching-only':
          this.testConfig.runRefreshTest = false;
          this.testConfig.runWorkaroundTest = false;
          break;
        case '--workaround-only':
          this.testConfig.runRefreshTest = false;
          this.testConfig.runSwitchingTest = false;
          break;
        case '--no-report':
          this.testConfig.generateReport = false;
          break;
        case '--exit-on-failure':
          this.testConfig.exitOnFirstFailure = true;
          break;
        case '--help':
          this.printUsage();
          process.exit(0);
          break;
      }
    });
  }

  printUsage() {
    console.log(`
🧪 TERMINAL REGRESSION TEST RUNNER

Usage: node run-regression-tests.js [OPTIONS]

OPTIONS:
  --refresh-only        Run only terminal refresh regression test
  --switching-only      Run only terminal switching regression test
  --workaround-only     Run only workaround validation test
  --no-report          Skip generating comprehensive report
  --exit-on-failure    Exit immediately if any test fails
  --help               Show this help message

TESTS:
  🔴 Refresh Test       Reproduces input-not-appearing issue
  🔄 Switching Test     Validates multi-terminal session isolation
  🔧 Workaround Test    Confirms temporary fix effectiveness

EXAMPLE:
  node run-regression-tests.js                    # Run all tests
  node run-regression-tests.js --refresh-only     # Test only refresh issue
  node run-regression-tests.js --exit-on-failure  # Stop on first failure
`);
  }

  async runAllTests() {
    console.log('🚀 STARTING COMPREHENSIVE TERMINAL REGRESSION TESTS');
    console.log('='.repeat(70));
    console.log(`📅 Started: ${new Date().toISOString()}`);
    console.log(`🔧 Configuration:`, this.testConfig);
    console.log('='.repeat(70));

    let totalTests = 0;
    let passedTests = 0;
    let failedTests = 0;

    // Test 1: Terminal Refresh Regression
    if (this.testConfig.runRefreshTest) {
      console.log('\n🔴 TEST 1: TERMINAL REFRESH REGRESSION');
      console.log('-'.repeat(50));

      try {
        totalTests++;
        const refreshTest = new TerminalRefreshRegressionTest();
        this.results.refreshTest = await refreshTest.run();

        if (this.results.refreshTest.success) {
          passedTests++;
          console.log('✅ Terminal Refresh Test: PASSED');
        } else {
          failedTests++;
          console.log('❌ Terminal Refresh Test: FAILED');

          if (this.testConfig.exitOnFirstFailure) {
            console.log('🛑 Exiting due to --exit-on-failure flag');
            process.exit(1);
          }
        }
      } catch (error) {
        failedTests++;
        console.error('💥 Terminal Refresh Test crashed:', error.message);
        this.results.refreshTest = { success: false, error: error.message };

        if (this.testConfig.exitOnFirstFailure) {
          process.exit(1);
        }
      }

      // Wait between tests to avoid port conflicts
      console.log('⏳ Waiting 5 seconds before next test...');
      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    // Test 2: Terminal Switching Regression
    if (this.testConfig.runSwitchingTest) {
      console.log('\n🔄 TEST 2: TERMINAL SWITCHING REGRESSION');
      console.log('-'.repeat(50));

      try {
        totalTests++;
        const switchingTest = new TerminalSwitchingRegressionTest();
        this.results.switchingTest = await switchingTest.run();

        if (this.results.switchingTest.success) {
          passedTests++;
          console.log('✅ Terminal Switching Test: PASSED');
        } else {
          failedTests++;
          console.log('❌ Terminal Switching Test: FAILED');

          if (this.testConfig.exitOnFirstFailure) {
            console.log('🛑 Exiting due to --exit-on-failure flag');
            process.exit(1);
          }
        }
      } catch (error) {
        failedTests++;
        console.error('💥 Terminal Switching Test crashed:', error.message);
        this.results.switchingTest = { success: false, error: error.message };

        if (this.testConfig.exitOnFirstFailure) {
          process.exit(1);
        }
      }

      // Wait between tests
      console.log('⏳ Waiting 5 seconds before next test...');
      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    // Test 3: Workaround Validation
    if (this.testConfig.runWorkaroundTest) {
      console.log('\n🔧 TEST 3: WORKAROUND VALIDATION');
      console.log('-'.repeat(50));

      try {
        totalTests++;
        const workaroundTest = new TerminalWorkaroundValidationTest();
        this.results.workaroundTest = await workaroundTest.run();

        if (this.results.workaroundTest.success) {
          passedTests++;
          console.log('✅ Workaround Validation Test: PASSED');
        } else {
          failedTests++;
          console.log('❌ Workaround Validation Test: FAILED');

          if (this.testConfig.exitOnFirstFailure) {
            console.log('🛑 Exiting due to --exit-on-failure flag');
            process.exit(1);
          }
        }
      } catch (error) {
        failedTests++;
        console.error('💥 Workaround Validation Test crashed:', error.message);
        this.results.workaroundTest = { success: false, error: error.message };

        if (this.testConfig.exitOnFirstFailure) {
          process.exit(1);
        }
      }
    }

    // Calculate overall status
    this.results.overallStatus = {
      totalTests,
      passedTests,
      failedTests,
      successRate: totalTests > 0 ? (passedTests / totalTests) * 100 : 0,
      duration: Date.now() - this.startTime
    };

    return this.results;
  }

  async generateComprehensiveReport() {
    if (!this.testConfig.generateReport) {
      console.log('📋 Report generation skipped (--no-report flag)');
      return null;
    }

    console.log('\n📋 GENERATING COMPREHENSIVE REGRESSION REPORT');
    console.log('-'.repeat(50));

    const report = {
      summary: {
        testSuite: 'Terminal Regression Tests',
        timestamp: new Date().toISOString(),
        duration: this.results.overallStatus.duration,
        durationFormatted: this.formatDuration(this.results.overallStatus.duration),
        overallStatus: this.results.overallStatus,
        regressionIssuesFound: this.countRegressionIssues(),
        criticalIssues: this.identifyCriticalIssues()
      },
      testResults: {
        refresh: this.summarizeRefreshTest(),
        switching: this.summarizeSwitchingTest(),
        workaround: this.summarizeWorkaroundTest()
      },
      analysis: this.analyzeResults(),
      recommendations: this.generateRecommendations(),
      technicalDetails: {
        testConfiguration: this.testConfig,
        environment: this.getEnvironmentInfo(),
        rawResults: this.results
      }
    };

    // Save report to file
    const reportPath = path.join(__dirname, `regression-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    console.log(`📄 Detailed report saved: ${reportPath}`);

    // Print summary to console
    this.printReportSummary(report);

    return report;
  }

  countRegressionIssues() {
    let count = 0;

    if (this.results.refreshTest?.regressionDetected) count++;
    if (this.results.switchingTest?.regressionDetected) count++;
    if (this.results.workaroundTest?.regressionExists) count++;

    return count;
  }

  identifyCriticalIssues() {
    const critical = [];

    if (this.results.refreshTest?.regressionDetected) {
      critical.push({
        type: 'Terminal Refresh Failure',
        severity: 'HIGH',
        description: 'Input reaches backend but display not updated'
      });
    }

    if (this.results.switchingTest?.regressionDetected) {
      critical.push({
        type: 'Terminal Switching Failure',
        severity: 'MEDIUM',
        description: 'Wrong terminal content displayed when switching'
      });
    }

    if (this.results.workaroundTest?.regressionExists &&
        !this.results.workaroundTest?.workaroundValidated) {
      critical.push({
        type: 'No Working Workaround',
        severity: 'CRITICAL',
        description: 'Users have no temporary solution for terminal issues'
      });
    }

    return critical;
  }

  summarizeRefreshTest() {
    if (!this.results.refreshTest) return { status: 'NOT_RUN' };

    return {
      status: this.results.refreshTest.success ? 'PASSED' : 'FAILED',
      regressionDetected: this.results.refreshTest.regressionDetected || false,
      key_findings: this.results.refreshTest.regressionDetected ? [
        'Backend receives input correctly',
        'Terminal display does not update',
        'Manual refresh operations ineffective'
      ] : [
        'Terminal refresh working normally',
        'Input appears in display as expected'
      ]
    };
  }

  summarizeSwitchingTest() {
    if (!this.results.switchingTest) return { status: 'NOT_RUN' };

    return {
      status: this.results.switchingTest.success ? 'PASSED' : 'FAILED',
      regressionDetected: this.results.switchingTest.regressionDetected || false,
      terminalsCreated: this.results.switchingTest.terminalsCreated || 0,
      key_findings: this.results.switchingTest.regressionDetected ? [
        'Wrong terminal content displayed when switching',
        'Session isolation compromised',
        'Terminal routing logic needs investigation'
      ] : [
        'Terminal switching working correctly',
        'Proper session isolation maintained'
      ]
    };
  }

  summarizeWorkaroundTest() {
    if (!this.results.workaroundTest) return { status: 'NOT_RUN' };

    return {
      status: this.results.workaroundTest.success ? 'PASSED' : 'FAILED',
      regressionExists: this.results.workaroundTest.regressionExists || false,
      workaroundValidated: this.results.workaroundTest.workaroundValidated || false,
      workaroundReliable: this.results.workaroundTest.workaroundReliable || false,
      key_findings: this.results.workaroundTest.regressionExists ? [
        this.results.workaroundTest.workaroundValidated ?
          'Workaround (new terminal + switch back) is effective' :
          'Workaround does not resolve the issue',
        this.results.workaroundTest.workaroundReliable ?
          'Workaround is reliable and can be documented' :
          'Workaround effectiveness varies'
      ] : [
        'No regression issue detected',
        'Terminal functionality working normally'
      ]
    };
  }

  analyzeResults() {
    const analysis = [];

    // Overall system health
    const regressionCount = this.countRegressionIssues();
    if (regressionCount === 0) {
      analysis.push('✅ Terminal system is functioning correctly with no regressions detected');
    } else {
      analysis.push(`🔴 ${regressionCount} regression issue(s) detected requiring attention`);
    }

    // Specific issue analysis
    if (this.results.refreshTest?.regressionDetected) {
      analysis.push('🔍 Root cause appears to be in display update logic - WebSocket communication works but UI doesn\'t refresh');
    }

    if (this.results.switchingTest?.regressionDetected) {
      analysis.push('🔍 Session management logic needs review - terminals not properly isolated or switched');
    }

    if (this.results.workaroundTest?.workaroundValidated) {
      analysis.push('💡 Workaround effectiveness suggests issue is in terminal initialization/refresh logic');
    }

    return analysis;
  }

  generateRecommendations() {
    const recommendations = [];

    if (this.countRegressionIssues() === 0) {
      recommendations.push('Continue monitoring terminal functionality with regular regression testing');
      recommendations.push('Consider adding automated regression tests to CI/CD pipeline');
      return recommendations;
    }

    // Priority recommendations based on issues found
    if (this.results.refreshTest?.regressionDetected) {
      recommendations.push('HIGH PRIORITY: Investigate terminal display update logic');
      recommendations.push('Focus on WebSocket event handling and terminal DOM manipulation');
      recommendations.push('Review terminal rendering and viewport update mechanisms');
    }

    if (this.results.switchingTest?.regressionDetected) {
      recommendations.push('MEDIUM PRIORITY: Review session management and terminal routing');
      recommendations.push('Ensure proper session isolation between multiple terminals');
      recommendations.push('Test terminal switching with different session ID formats');
    }

    if (this.results.workaroundTest?.workaroundValidated) {
      recommendations.push('Document workaround for users as temporary solution');
      recommendations.push('Investigate why creating new terminal + switching back fixes the issue');
      recommendations.push('This suggests the issue is in terminal lifecycle management');
    } else if (this.results.workaroundTest?.regressionExists) {
      recommendations.push('CRITICAL: No working workaround available for users');
      recommendations.push('Investigate alternative temporary solutions');
    }

    // General recommendations
    recommendations.push('Add comprehensive logging to terminal event handlers for debugging');
    recommendations.push('Consider implementing terminal health checks and auto-recovery');
    recommendations.push('Schedule follow-up regression testing after fixes are implemented');

    return recommendations;
  }

  getEnvironmentInfo() {
    return {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      timestamp: new Date().toISOString(),
      testRunner: 'Terminal Regression Test Suite v1.0'
    };
  }

  formatDuration(ms) {
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  }

  printReportSummary(report) {
    console.log('\n' + '='.repeat(70));
    console.log('📊 TERMINAL REGRESSION TEST SUMMARY');
    console.log('='.repeat(70));

    console.log(`📅 Completed: ${report.summary.timestamp}`);
    console.log(`⏱️  Duration: ${report.summary.durationFormatted}`);
    console.log(`🧪 Tests Run: ${report.summary.overallStatus.totalTests}`);
    console.log(`✅ Passed: ${report.summary.overallStatus.passedTests}`);
    console.log(`❌ Failed: ${report.summary.overallStatus.failedTests}`);
    console.log(`📈 Success Rate: ${report.summary.overallStatus.successRate.toFixed(1)}%`);

    console.log('\n🔍 REGRESSION ISSUES FOUND:');
    if (report.summary.regressionIssuesFound === 0) {
      console.log('   🟢 No regression issues detected');
    } else {
      console.log(`   🔴 ${report.summary.regressionIssuesFound} regression issue(s) detected`);

      report.summary.criticalIssues.forEach(issue => {
        console.log(`   - ${issue.type} (${issue.severity}): ${issue.description}`);
      });
    }

    console.log('\n💡 KEY RECOMMENDATIONS:');
    report.recommendations.slice(0, 3).forEach(rec => {
      console.log(`   • ${rec}`);
    });

    if (report.recommendations.length > 3) {
      console.log(`   ... and ${report.recommendations.length - 3} more (see detailed report)`);
    }

    console.log('='.repeat(70));
  }

  async run() {
    this.parseCommandLineArgs();

    try {
      const results = await this.runAllTests();
      const report = await this.generateComprehensiveReport();

      const hasRegressions = this.countRegressionIssues() > 0;
      const hasFailures = results.overallStatus.failedTests > 0;

      if (hasRegressions) {
        console.log('\n🔴 REGRESSION ISSUES DETECTED - IMMEDIATE ATTENTION REQUIRED');
        process.exit(1);
      } else if (hasFailures) {
        console.log('\n⚠️ SOME TESTS FAILED - PLEASE INVESTIGATE');
        process.exit(1);
      } else {
        console.log('\n🟢 ALL TESTS PASSED - TERMINAL FUNCTIONALITY IS HEALTHY');
        process.exit(0);
      }

    } catch (error) {
      console.error('\n💥 REGRESSION TEST RUNNER CRASHED:', error);
      console.error('Stack trace:', error.stack);
      process.exit(1);
    }
  }
}

// Handle cleanup on exit
process.on('SIGINT', () => {
  console.log('\n🛑 Regression tests interrupted by user');
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Regression tests terminated');
  process.exit(1);
});

// Export for programmatic use
module.exports = RegressionTestRunner;

// Run if called directly
if (require.main === module) {
  const runner = new RegressionTestRunner();
  runner.run();
}