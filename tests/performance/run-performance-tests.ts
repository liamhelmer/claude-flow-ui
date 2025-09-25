#!/usr/bin/env ts-node

/**
 * Performance Test Runner Script
 *
 * Command-line interface for running performance tests.
 * Usage:
 *   npm run test:performance
 *   npm run test:performance:ci
 *   npm run test:performance:quick
 */

import { PerformanceTestRunner } from './PerformanceTestRunner';
import * as fs from 'fs';

interface CLIOptions {
  mode: 'full' | 'ci' | 'quick';
  benchmarks: boolean;
  stress: boolean;
  bundle: boolean;
  lighthouse: boolean;
  monitoring: boolean;
  save: boolean;
  report: boolean;
  verbose: boolean;
  environment: 'development' | 'production' | 'ci';
}

function parseArgs(): CLIOptions {
  const args = process.argv.slice(2);
  const options: CLIOptions = {
    mode: 'full',
    benchmarks: true,
    stress: true,
    bundle: true,
    lighthouse: false,
    monitoring: true,
    save: true,
    report: true,
    verbose: false,
    environment: 'development'
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--mode':
      case '-m':
        options.mode = args[++i] as CLIOptions['mode'];
        break;
      case '--environment':
      case '-e':
        options.environment = args[++i] as CLIOptions['environment'];
        break;
      case '--no-benchmarks':
        options.benchmarks = false;
        break;
      case '--no-stress':
        options.stress = false;
        break;
      case '--no-bundle':
        options.bundle = false;
        break;
      case '--lighthouse':
        options.lighthouse = true;
        break;
      case '--no-monitoring':
        options.monitoring = false;
        break;
      case '--no-save':
        options.save = false;
        break;
      case '--no-report':
        options.report = false;
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--help':
      case '-h':
        showHelp();
        process.exit(0);
        break;
    }
  }

  return options;
}

function showHelp(): void {
  console.log(`
Performance Test Runner

Usage: npm run test:performance [options]

Modes:
  --mode full         Run all performance tests (default)
  --mode ci           Run CI-optimized tests (faster)
  --mode quick        Run essential tests only

Options:
  --environment       Test environment (development|production|ci)
  --no-benchmarks     Skip benchmark tests
  --no-stress         Skip stress tests
  --no-bundle         Skip bundle analysis
  --lighthouse        Enable Lighthouse tests (requires setup)
  --no-monitoring     Skip performance monitoring
  --no-save           Don't save results to files
  --no-report         Don't generate markdown report
  --verbose, -v       Enable verbose logging
  --help, -h          Show this help message

Examples:
  npm run test:performance                    # Full test suite
  npm run test:performance -- --mode ci      # CI mode
  npm run test:performance -- --mode quick   # Quick check
  npm run test:performance -- --no-stress --verbose
`);
}

async function main(): Promise<void> {
  console.log('🚀 Claude Flow UI Performance Test Suite\n');

  const options = parseArgs();

  if (options.verbose) {
    console.log('Configuration:', JSON.stringify(options, null, 2));
  }

  // Validate environment
  if (!fs.existsSync('/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/package.json')) {
    console.error('❌ Error: Must be run from the project root directory');
    process.exit(1);
  }

  // Create runner with configuration
  const runner = new PerformanceTestRunner({
    runBenchmarks: options.benchmarks,
    runStressTests: options.stress,
    runBundleAnalysis: options.bundle,
    enableLighthouse: options.lighthouse,
    enableMonitoring: options.monitoring,
    saveResults: options.save,
    generateReport: options.report,
    detectRegressions: true,
    testEnvironment: options.environment
  });

  try {
    let results;

    switch (options.mode) {
      case 'ci':
        console.log('Running in CI mode (optimized for speed)...\n');
        results = await runner.runCITests();
        break;
      case 'quick':
        console.log('Running quick performance check...\n');
        results = await runner.runQuickCheck();
        break;
      default:
        console.log('Running full performance test suite...\n');
        results = await runner.runAllTests();
        break;
    }

    // Print summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 PERFORMANCE TEST RESULTS SUMMARY');
    console.log('='.repeat(60));

    const summary = results.summary;
    console.log(`Overall Score:     ${summary.overallScore.toFixed(1)}/100`);
    console.log(`Tests Run:         ${summary.testsRun}`);
    console.log(`Success Rate:      ${((summary.testsSuccessful / summary.testsRun) * 100).toFixed(1)}%`);
    console.log(`Duration:          ${(summary.duration / 1000).toFixed(2)} seconds`);
    console.log(`Environment:       ${summary.environment}`);

    if (summary.regressions > 0) {
      console.log(`⚠️  Regressions:     ${summary.regressions}`);
      console.log('\nRegression Details:');
      results.regressions.forEach(regression => {
        console.log(`   - ${regression}`);
      });
    }

    if (results.recommendations.length > 0) {
      console.log('\n💡 Top Recommendations:');
      results.recommendations.slice(0, 5).forEach(rec => {
        console.log(`   - ${rec}`);
      });
    }

    // Set exit code based on results
    const hasFailures = summary.testsFailed > 0;
    const hasRegressions = summary.regressions > 0;
    const lowScore = summary.overallScore < 70;

    if (hasFailures || hasRegressions || lowScore) {
      console.log('\n❌ Performance tests completed with issues');
      process.exit(1);
    } else {
      console.log('\n✅ All performance tests passed');
      process.exit(0);
    }

  } catch (error) {
    console.error('\n💥 Performance test suite failed:', error);

    if (options.verbose && error instanceof Error) {
      console.error('\nStack trace:', error.stack);
    }

    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run main function
if (require.main === module) {
  main().catch(console.error);
}