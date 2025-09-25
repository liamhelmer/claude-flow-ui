#!/usr/bin/env ts-node

/**
 * Example Performance Benchmark Runner
 *
 * Demonstrates how to use the performance benchmarking suite with
 * practical examples and different test scenarios.
 */

import { PerformanceTestRunner } from '../PerformanceTestRunner';
import { PerformanceBenchmarkSuite } from '../benchmarks/PerformanceBenchmarkSuite';
import { StressTestSuite } from '../stress/StressTestSuite';

async function runExampleBenchmarks() {
  console.log('🎯 Running Example Performance Benchmarks for Claude Flow UI\n');

  try {
    // Example 1: Quick Performance Check
    console.log('📊 Example 1: Quick Performance Check');
    console.log('=' .repeat(50));

    const quickRunner = new PerformanceTestRunner({
      runBenchmarks: true,
      runStressTests: false,
      runBundleAnalysis: true,
      enableMonitoring: false,
      saveResults: false,
      generateReport: false,
      testEnvironment: 'development'
    });

    const quickResults = await quickRunner.runQuickCheck();
    console.log(`Quick check score: ${quickResults.summary.overallScore.toFixed(1)}/100`);
    console.log(`Tests completed in ${(quickResults.summary.duration / 1000).toFixed(2)}s\n`);

    // Example 2: Individual Benchmark Components
    console.log('🔧 Example 2: Individual Component Benchmarks');
    console.log('=' .repeat(50));

    const benchmarkSuite = new PerformanceBenchmarkSuite();

    // Terminal rendering benchmark
    console.log('Testing terminal rendering performance...');
    const terminalResult = await benchmarkSuite.benchmarkTerminalRendering();
    console.log(`Terminal benchmark: ${terminalResult.success ? '✅' : '❌'} (${terminalResult.duration.toFixed(2)}ms)`);

    if (terminalResult.success && terminalResult.metrics.linesPerSecond) {
      console.log(`  • Rendering speed: ${terminalResult.metrics.linesPerSecond.toFixed(0)} lines/sec`);
      console.log(`  • Canvas vs WebGL ratio: ${terminalResult.metrics.canvasVsWebglRatio?.toFixed(2) || 'N/A'}`);
    }

    // WebSocket performance benchmark
    console.log('\nTesting WebSocket performance...');
    const wsResult = await benchmarkSuite.benchmarkWebSocketPerformance();
    console.log(`WebSocket benchmark: ${wsResult.success ? '✅' : '❌'} (${wsResult.duration.toFixed(2)}ms)`);

    if (wsResult.success && wsResult.metrics.messagesPerSecond) {
      console.log(`  • Throughput: ${wsResult.metrics.messagesPerSecond.toFixed(0)} msgs/sec`);
      console.log(`  • Average latency: ${wsResult.metrics.averageLatency?.toFixed(2) || 'N/A'}ms`);
    }

    // Memory leak detection
    console.log('\nTesting memory leak detection...');
    const memoryResult = await benchmarkSuite.benchmarkMemoryLeakDetection();
    console.log(`Memory benchmark: ${memoryResult.success ? '✅' : '❌'} (${memoryResult.duration.toFixed(2)}ms)`);

    if (memoryResult.success && memoryResult.metrics.heapGrowth !== undefined) {
      console.log(`  • Heap growth: ${(memoryResult.metrics.heapGrowth / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  • Memory leak suspected: ${memoryResult.metrics.memoryLeakSuspected ? 'Yes' : 'No'}`);
    }

    // Example 3: Stress Testing Scenarios
    console.log('\n⚡ Example 3: Stress Testing Scenarios');
    console.log('=' .repeat(50));

    const stressTestSuite = new StressTestSuite();

    // Quick stress test
    console.log('Running quick stress test (100 connections, 30s)...');
    const quickStressResult = await stressTestSuite.runQuickStressTest();
    console.log(`Quick stress test: ${quickStressResult.success ? '✅' : '❌'}`);

    if (quickStressResult.success) {
      console.log(`  • Max connections: ${quickStressResult.connections.successful}`);
      console.log(`  • Message throughput: ${quickStressResult.messages.throughput.toFixed(0)} msgs/sec`);
      console.log(`  • Average latency: ${quickStressResult.messages.averageLatency.toFixed(2)}ms`);
      console.log(`  • Performance score: ${quickStressResult.performance.score.toFixed(1)}/100`);
    }

    // Example 4: Performance Monitoring Demo
    console.log('\n📈 Example 4: Performance Monitoring Demo');
    console.log('=' .repeat(50));

    const { PerformanceMonitor } = await import('../monitoring/PerformanceMonitor');
    const monitor = new PerformanceMonitor({
      sampleInterval: 500, // 500ms sampling
      maxHistorySize: 20,
      enableRealTimeAlerts: true
    });

    monitor.startMonitoring();

    // Simulate some work to generate metrics
    console.log('Simulating workload for monitoring...');
    for (let i = 0; i < 10; i++) {
      // Simulate CPU work
      const start = Date.now();
      while (Date.now() - start < 50) {
        Math.sqrt(Math.random() * 1000000);
      }

      // Record custom metrics
      monitor.recordCustomMetric('simulated-operation-time', 50 + Math.random() * 20);
      monitor.recordCustomMetric('simulated-memory-usage', 1024 * 1024 * (10 + Math.random() * 5));

      await new Promise(resolve => setTimeout(resolve, 100));
    }

    monitor.stopMonitoring();

    const monitoringReport = monitor.generateReport();
    console.log(`Monitoring duration: ${(monitoringReport.summary.monitoringDuration / 1000).toFixed(1)}s`);
    console.log(`Performance score: ${monitoringReport.summary.performanceScore}/100`);
    console.log(`Alerts generated: ${monitoringReport.summary.totalAlerts}`);

    if (monitoringReport.recommendations.length > 0) {
      console.log('Recommendations:');
      monitoringReport.recommendations.slice(0, 3).forEach(rec => {
        console.log(`  • ${rec}`);
      });
    }

    // Example 5: Bundle Analysis Demo
    console.log('\n📦 Example 5: Bundle Analysis Demo');
    console.log('=' .repeat(50));

    const { BundleAnalyzer } = await import('../analysis/BundleAnalyzer');
    const bundleAnalyzer = new BundleAnalyzer();

    try {
      const bundleAnalysis = await bundleAnalyzer.analyzeBundles();
      console.log(`Total bundle size: ${bundleAnalyzer['formatBytes'](bundleAnalysis.totalSize)}`);
      console.log(`Gzipped size: ${bundleAnalyzer['formatBytes'](bundleAnalysis.gzippedSize)}`);
      console.log(`Code splitting effectiveness: ${(bundleAnalysis.codeSplitting.effectiveness * 100).toFixed(1)}%`);
      console.log(`Number of chunks: ${bundleAnalysis.chunks.length}`);

      if (bundleAnalysis.recommendations.length > 0) {
        console.log('Top recommendations:');
        bundleAnalysis.recommendations.slice(0, 3).forEach(rec => {
          console.log(`  • ${rec}`);
        });
      }
    } catch (error) {
      console.log('Bundle analysis skipped (build not found or error occurred)');
    }

    // Example 6: Complete Performance Suite (CI Mode)
    console.log('\n🚀 Example 6: Complete Performance Suite (CI Mode)');
    console.log('=' .repeat(50));

    const ciRunner = new PerformanceTestRunner({
      testEnvironment: 'ci'
    });

    const fullResults = await ciRunner.runCITests();

    console.log(`\nComplete Performance Results:`);
    console.log(`Overall Score: ${fullResults.summary.overallScore.toFixed(1)}/100`);
    console.log(`Success Rate: ${((fullResults.summary.testsSuccessful / fullResults.summary.testsRun) * 100).toFixed(1)}%`);
    console.log(`Duration: ${(fullResults.summary.duration / 1000).toFixed(2)} seconds`);

    if (fullResults.regressions.length > 0) {
      console.log(`\n⚠️  Performance Regressions Detected:`);
      fullResults.regressions.forEach(regression => {
        console.log(`  • ${regression}`);
      });
    }

    if (fullResults.recommendations.length > 0) {
      console.log(`\n💡 Optimization Recommendations:`);
      fullResults.recommendations.slice(0, 5).forEach(rec => {
        console.log(`  • ${rec}`);
      });
    }

    // Store results in memory as requested
    console.log('\n💾 Storing performance results in memory...');

    const memoryData = {
      timestamp: Date.now(),
      environment: 'example-run',
      overall_score: fullResults.summary.overallScore,
      tests_run: fullResults.summary.testsRun,
      success_rate: ((fullResults.summary.testsSuccessful / fullResults.summary.testsRun) * 100),
      duration_seconds: fullResults.summary.duration / 1000,
      regressions_count: fullResults.regressions.length,
      key_metrics: fullResults.metrics,
      recommendations: fullResults.recommendations.slice(0, 10),
      example_run: true
    };

    // Save to memory file (simulates claude-flow memory storage)
    const fs = require('fs');
    const memoryDir = '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/memory';
    if (!fs.existsSync(memoryDir)) {
      fs.mkdirSync(memoryDir, { recursive: true });
    }

    fs.writeFileSync(
      `${memoryDir}/performance_benchmarks_complete.json`,
      JSON.stringify(memoryData, null, 2)
    );

    console.log(`✅ Performance benchmarks stored with key: performance_benchmarks_complete`);
    console.log(`📁 Results saved to: ${memoryDir}/performance_benchmarks_complete.json`);

    console.log('\n🎯 Example Performance Benchmarks Completed Successfully!');
    console.log(`\nFinal Summary:`);
    console.log(`• Overall Performance Score: ${fullResults.summary.overallScore.toFixed(1)}/100`);
    console.log(`• Total Tests Run: ${fullResults.summary.testsRun}`);
    console.log(`• Success Rate: ${((fullResults.summary.testsSuccessful / fullResults.summary.testsRun) * 100).toFixed(1)}%`);
    console.log(`• Performance Regressions: ${fullResults.regressions.length}`);
    console.log(`• Execution Time: ${(fullResults.summary.duration / 1000).toFixed(2)} seconds`);

  } catch (error) {
    console.error('\n❌ Example benchmark run failed:', error);
    if (error instanceof Error) {
      console.error('Stack trace:', error.stack);
    }
    process.exit(1);
  }
}

// Helper function for formatting
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Run examples if this file is executed directly
if (require.main === module) {
  runExampleBenchmarks().catch(console.error);
}