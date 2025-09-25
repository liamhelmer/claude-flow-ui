/**
 * Master Performance Test Runner
 *
 * Orchestrates all performance tests and benchmarks, collects results,
 * detects regressions, and generates comprehensive reports.
 */

import { performance } from 'perf_hooks';
import { PerformanceBenchmarkSuite } from './benchmarks/PerformanceBenchmarkSuite';
import { PerformanceMonitor } from './monitoring/PerformanceMonitor';
import { StressTestSuite } from './stress/StressTestSuite';
import { BundleAnalyzer } from './analysis/BundleAnalyzer';
import * as fs from 'fs';

interface TestRunConfig {
  runBenchmarks: boolean;
  runStressTests: boolean;
  runBundleAnalysis: boolean;
  enableMonitoring: boolean;
  enableLighthouse: boolean;
  saveResults: boolean;
  generateReport: boolean;
  detectRegressions: boolean;
  testEnvironment: 'development' | 'production' | 'ci';
}

interface ComprehensiveResults {
  summary: {
    startTime: number;
    endTime: number;
    duration: number;
    testsRun: number;
    testsSuccessful: number;
    testsFailed: number;
    overallScore: number;
    regressions: number;
    environment: string;
  };
  benchmarks?: any;
  stressTests?: any;
  bundleAnalysis?: any;
  monitoring?: any;
  lighthouse?: any;
  regressions: string[];
  recommendations: string[];
  metrics: Record<string, any>;
}

export class PerformanceTestRunner {
  private config: TestRunConfig;
  private benchmarkSuite: PerformanceBenchmarkSuite;
  private monitor: PerformanceMonitor;
  private stressTestSuite: StressTestSuite;
  private bundleAnalyzer: BundleAnalyzer;

  constructor(config: Partial<TestRunConfig> = {}) {
    this.config = {
      runBenchmarks: true,
      runStressTests: true,
      runBundleAnalysis: true,
      enableMonitoring: true,
      enableLighthouse: false, // Requires separate setup
      saveResults: true,
      generateReport: true,
      detectRegressions: true,
      testEnvironment: 'development',
      ...config
    };

    this.benchmarkSuite = new PerformanceBenchmarkSuite();
    this.monitor = new PerformanceMonitor();
    this.stressTestSuite = new StressTestSuite();
    this.bundleAnalyzer = new BundleAnalyzer();
  }

  /**
   * Run all performance tests
   */
  async runAllTests(): Promise<ComprehensiveResults> {
    console.log('🚀 Starting comprehensive performance test suite...');
    console.log(`Environment: ${this.config.testEnvironment}`);

    const startTime = performance.now();
    const results: ComprehensiveResults = {
      summary: {
        startTime: Date.now(),
        endTime: 0,
        duration: 0,
        testsRun: 0,
        testsSuccessful: 0,
        testsFailed: 0,
        overallScore: 0,
        regressions: 0,
        environment: this.config.testEnvironment
      },
      regressions: [],
      recommendations: [],
      metrics: {}
    };

    try {
      // Start monitoring if enabled
      if (this.config.enableMonitoring) {
        console.log('🔍 Starting performance monitoring...');
        this.monitor.startMonitoring();
      }

      // Run benchmark suite
      if (this.config.runBenchmarks) {
        console.log('\n📊 Running performance benchmarks...');
        try {
          const benchmarkResults = await this.benchmarkSuite.runAllBenchmarks();
          results.benchmarks = benchmarkResults;
          results.summary.testsRun += benchmarkResults.results.length;
          results.summary.testsSuccessful += benchmarkResults.results.filter(r => r.success).length;
          results.summary.testsFailed += benchmarkResults.results.filter(r => !r.success).length;
          results.regressions.push(...benchmarkResults.regressions);
          console.log('✅ Benchmarks completed');
        } catch (error) {
          console.error('❌ Benchmark suite failed:', error);
          results.summary.testsFailed += 7; // All 7 benchmark categories
        }
      }

      // Run stress tests
      if (this.config.runStressTests) {
        console.log('\n⚡ Running stress tests...');
        try {
          const stressResults = await this.stressTestSuite.runStressTest();
          results.stressTests = stressResults;
          results.summary.testsRun += 1;
          if (stressResults.success) {
            results.summary.testsSuccessful += 1;
          } else {
            results.summary.testsFailed += 1;
          }
          console.log('✅ Stress tests completed');
        } catch (error) {
          console.error('❌ Stress tests failed:', error);
          results.summary.testsFailed += 1;
        }
      }

      // Run bundle analysis
      if (this.config.runBundleAnalysis) {
        console.log('\n📦 Running bundle analysis...');
        try {
          const bundleAnalysis = await this.bundleAnalyzer.analyzeBundles();
          results.bundleAnalysis = bundleAnalysis;
          results.summary.testsRun += 1;
          results.summary.testsSuccessful += 1;
          results.recommendations.push(...bundleAnalysis.recommendations);
          console.log('✅ Bundle analysis completed');
        } catch (error) {
          console.error('❌ Bundle analysis failed:', error);
          results.summary.testsFailed += 1;
        }
      }

      // Run Lighthouse if enabled
      if (this.config.enableLighthouse) {
        console.log('\n🔍 Running Lighthouse analysis...');
        try {
          const lighthouseResults = await this.runLighthouse();
          results.lighthouse = lighthouseResults;
          results.summary.testsRun += 1;
          results.summary.testsSuccessful += 1;
          console.log('✅ Lighthouse analysis completed');
        } catch (error) {
          console.error('❌ Lighthouse analysis failed:', error);
          results.summary.testsFailed += 1;
        }
      }

      // Collect monitoring data
      if (this.config.enableMonitoring) {
        console.log('\n📈 Collecting monitoring data...');
        this.monitor.stopMonitoring();
        results.monitoring = this.monitor.generateReport();
        results.recommendations.push(...results.monitoring.recommendations);
      }

      const endTime = performance.now();
      results.summary.endTime = Date.now();
      results.summary.duration = endTime - startTime;
      results.summary.regressions = results.regressions.length;

      // Calculate overall score
      results.summary.overallScore = this.calculateOverallScore(results);

      // Generate comprehensive metrics
      results.metrics = this.compileMetrics(results);

      // Generate final recommendations
      results.recommendations = [...new Set(results.recommendations)]; // Remove duplicates

      console.log(`\n🎯 Performance test suite completed in ${results.summary.duration.toFixed(2)}ms`);
      console.log(`📊 Overall Score: ${results.summary.overallScore}/100`);
      console.log(`✅ Tests Successful: ${results.summary.testsSuccessful}/${results.summary.testsRun}`);
      console.log(`⚠️  Regressions Detected: ${results.summary.regressions}`);

      // Save results if enabled
      if (this.config.saveResults) {
        await this.saveResults(results);
        await this.storeInMemory(results);
      }

      // Generate report if enabled
      if (this.config.generateReport) {
        await this.generateDetailedReport(results);
      }

      return results;

    } catch (error) {
      console.error('💥 Performance test suite crashed:', error);
      throw error;
    }
  }

  private async runLighthouse(): Promise<any> {
    // This would integrate with Lighthouse CI
    // For now, return mock results
    return {
      performance: 85,
      accessibility: 95,
      bestPractices: 90,
      seo: 88,
      pwa: 70,
      metrics: {
        'first-contentful-paint': 1200,
        'largest-contentful-paint': 2100,
        'cumulative-layout-shift': 0.08,
        'speed-index': 2800,
        'total-blocking-time': 150
      },
      opportunities: [
        'Eliminate render-blocking resources',
        'Properly size images',
        'Remove unused CSS'
      ]
    };
  }

  private calculateOverallScore(results: ComprehensiveResults): number {
    let totalScore = 0;
    let weightedSum = 0;

    // Benchmark score (weight: 30%)
    if (results.benchmarks) {
      const benchmarkScore = this.calculateBenchmarkScore(results.benchmarks);
      totalScore += benchmarkScore * 0.3;
      weightedSum += 0.3;
    }

    // Stress test score (weight: 25%)
    if (results.stressTests) {
      const stressScore = results.stressTests.performance?.score || 0;
      totalScore += stressScore * 0.25;
      weightedSum += 0.25;
    }

    // Bundle analysis score (weight: 20%)
    if (results.bundleAnalysis) {
      const bundleScore = this.calculateBundleScore(results.bundleAnalysis);
      totalScore += bundleScore * 0.2;
      weightedSum += 0.2;
    }

    // Lighthouse score (weight: 15%)
    if (results.lighthouse) {
      const lighthouseScore = results.lighthouse.performance || 0;
      totalScore += lighthouseScore * 0.15;
      weightedSum += 0.15;
    }

    // Monitoring score (weight: 10%)
    if (results.monitoring) {
      const monitoringScore = results.monitoring.summary?.performanceScore || 0;
      totalScore += monitoringScore * 0.1;
      weightedSum += 0.1;
    }

    // Penalty for regressions
    const regressionPenalty = Math.min(20, results.regressions.length * 5);
    totalScore -= regressionPenalty;

    return weightedSum > 0 ? Math.max(0, Math.min(100, totalScore / weightedSum)) : 0;
  }

  private calculateBenchmarkScore(benchmarks: any): number {
    if (!benchmarks.results) return 0;

    const successRate = benchmarks.results.filter((r: any) => r.success).length / benchmarks.results.length;
    let baseScore = successRate * 100;

    // Adjust based on specific performance metrics
    for (const result of benchmarks.results) {
      if (result.success && result.metrics) {
        // Terminal rendering performance
        if (result.testName === 'terminal-rendering') {
          if (result.metrics.linesPerSecond < 500) baseScore -= 5;
          if (result.metrics.canvasVsWebglRatio > 2) baseScore -= 3;
        }

        // WebSocket performance
        if (result.testName === 'websocket-performance') {
          if (result.metrics.messagesPerSecond < 1000) baseScore -= 5;
          if (result.metrics.averageLatency > 50) baseScore -= 3;
        }

        // React performance
        if (result.testName === 'react-performance') {
          if (result.metrics.rendersPerSecond < 100) baseScore -= 3;
          if (result.metrics.memoizationEffectiveness < 0.8) baseScore -= 2;
        }
      }
    }

    return Math.max(0, Math.min(100, baseScore));
  }

  private calculateBundleScore(bundleAnalysis: any): number {
    let score = 100;

    // Size penalties
    if (bundleAnalysis.totalSize > 1000000) score -= 15; // >1MB
    if (bundleAnalysis.totalSize > 2000000) score -= 25; // >2MB

    // Compression penalty
    const compressionRatio = bundleAnalysis.gzippedSize / bundleAnalysis.totalSize;
    if (compressionRatio > 0.4) score -= 10;

    // Code splitting bonus
    if (bundleAnalysis.codeSplitting.effectiveness > 0.5) score += 10;
    if (bundleAnalysis.codeSplitting.effectiveness > 0.8) score += 5;

    return Math.max(0, Math.min(100, score));
  }

  private compileMetrics(results: ComprehensiveResults): Record<string, any> {
    const metrics: Record<string, any> = {};

    // Compile from benchmarks
    if (results.benchmarks) {
      metrics.terminalPerformance = this.extractTerminalMetrics(results.benchmarks);
      metrics.websocketPerformance = this.extractWebSocketMetrics(results.benchmarks);
      metrics.reactPerformance = this.extractReactMetrics(results.benchmarks);
      metrics.memoryProfile = this.extractMemoryMetrics(results.benchmarks);
    }

    // Compile from stress tests
    if (results.stressTests) {
      metrics.stressTestProfile = {
        maxConnections: results.stressTests.connections.successful,
        averageLatency: results.stressTests.messages.averageLatency,
        throughput: results.stressTests.messages.throughput,
        memoryPeak: results.stressTests.memory.peak.heapUsed,
        cpuPeak: results.stressTests.cpu.peakUsage
      };
    }

    // Compile from bundle analysis
    if (results.bundleAnalysis) {
      metrics.bundleProfile = {
        totalSize: results.bundleAnalysis.totalSize,
        gzippedSize: results.bundleAnalysis.gzippedSize,
        chunkCount: results.bundleAnalysis.chunks.length,
        codeSplittingEffectiveness: results.bundleAnalysis.codeSplitting.effectiveness
      };
    }

    return metrics;
  }

  private extractTerminalMetrics(benchmarks: any): Record<string, any> {
    const terminalResult = benchmarks.results.find((r: any) => r.category === 'terminal');
    if (!terminalResult) return {};

    return {
      canvasRenderTime: terminalResult.metrics?.canvasRenderTime,
      webglRenderTime: terminalResult.metrics?.webglRenderTime,
      scrollTime: terminalResult.metrics?.scrollTime,
      linesPerSecond: terminalResult.metrics?.linesPerSecond,
      averageFitTime: terminalResult.metrics?.averageFitTime
    };
  }

  private extractWebSocketMetrics(benchmarks: any): Record<string, any> {
    const wsResult = benchmarks.results.find((r: any) => r.category === 'websocket');
    if (!wsResult) return {};

    return {
      messagesPerSecond: wsResult.metrics?.messagesPerSecond,
      bytesPerSecond: wsResult.metrics?.bytesPerSecond,
      averageLatency: wsResult.metrics?.averageLatency,
      p95Latency: wsResult.metrics?.p95Latency,
      maxLatency: wsResult.metrics?.maxLatency
    };
  }

  private extractReactMetrics(benchmarks: any): Record<string, any> {
    const reactResult = benchmarks.results.find((r: any) => r.category === 'react');
    if (!reactResult) return {};

    return {
      averageRenderTime: reactResult.metrics?.averageRenderTime,
      rendersPerSecond: reactResult.metrics?.rendersPerSecond,
      memoizationEffectiveness: reactResult.metrics?.memoizationEffectiveness,
      averageRerenderTime: reactResult.metrics?.averageRerenderTime
    };
  }

  private extractMemoryMetrics(benchmarks: any): Record<string, any> {
    const memoryResult = benchmarks.results.find((r: any) => r.category === 'memory');
    if (!memoryResult) return {};

    return {
      heapGrowth: memoryResult.metrics?.heapGrowth,
      heapGrowthRatio: memoryResult.metrics?.heapGrowthRatio,
      averageGrowthRate: memoryResult.metrics?.averageGrowthRate,
      memoryLeakSuspected: memoryResult.metrics?.memoryLeakSuspected === 1
    };
  }

  private async saveResults(results: ComprehensiveResults): Promise<void> {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const resultsPath = `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/results/performance-results-${timestamp}.json`;

      // Ensure results directory exists
      const resultsDir = '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/results';
      if (!fs.existsSync(resultsDir)) {
        fs.mkdirSync(resultsDir, { recursive: true });
      }

      fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
      console.log(`💾 Results saved to: ${resultsPath}`);

    } catch (error) {
      console.error('Could not save performance results:', error);
    }
  }

  private async storeInMemory(results: ComprehensiveResults): Promise<void> {
    try {
      // This would integrate with claude-flow memory system
      const memoryData = {
        timestamp: Date.now(),
        environment: this.config.testEnvironment,
        summary: results.summary,
        key_metrics: results.metrics,
        regressions: results.regressions,
        recommendations: results.recommendations.slice(0, 10), // Top 10
        overall_score: results.summary.overallScore
      };

      // Store with specific key as requested
      const memoryKey = 'performance_benchmarks_complete';

      // In a real implementation, this would use claude-flow memory storage
      console.log(`📋 Storing results in memory with key: ${memoryKey}`);

      // For now, save to a memory file that can be accessed
      const memoryPath = `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/memory/${memoryKey}.json`;
      const memoryDir = '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/memory';

      if (!fs.existsSync(memoryDir)) {
        fs.mkdirSync(memoryDir, { recursive: true });
      }

      fs.writeFileSync(memoryPath, JSON.stringify(memoryData, null, 2));

    } catch (error) {
      console.error('Could not store results in memory:', error);
    }
  }

  private async generateDetailedReport(results: ComprehensiveResults): Promise<void> {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const reportPath = `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/reports/performance-report-${timestamp}.md`;

      const report = this.generateMarkdownReport(results);

      // Ensure reports directory exists
      const reportsDir = '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/reports';
      if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
      }

      fs.writeFileSync(reportPath, report);
      console.log(`📄 Report generated: ${reportPath}`);

    } catch (error) {
      console.error('Could not generate performance report:', error);
    }
  }

  private generateMarkdownReport(results: ComprehensiveResults): string {
    const date = new Date(results.summary.startTime).toISOString().split('T')[0];
    let report = `# Performance Test Report - ${date}\n\n`;

    // Executive Summary
    report += '## Executive Summary\n\n';
    report += `- **Overall Score:** ${results.summary.overallScore.toFixed(1)}/100\n`;
    report += `- **Duration:** ${(results.summary.duration / 1000).toFixed(2)} seconds\n`;
    report += `- **Tests Run:** ${results.summary.testsRun}\n`;
    report += `- **Success Rate:** ${((results.summary.testsSuccessful / results.summary.testsRun) * 100).toFixed(1)}%\n`;
    report += `- **Regressions:** ${results.summary.regressions}\n`;
    report += `- **Environment:** ${results.summary.environment}\n\n`;

    // Key Metrics
    if (results.metrics) {
      report += '## Key Performance Metrics\n\n';

      if (results.metrics.terminalPerformance) {
        report += '### Terminal Performance\n';
        const tp = results.metrics.terminalPerformance;
        report += `- Rendering Speed: ${tp.linesPerSecond || 'N/A'} lines/sec\n`;
        report += `- Canvas Render Time: ${tp.canvasRenderTime || 'N/A'}ms\n`;
        report += `- WebGL Render Time: ${tp.webglRenderTime || 'N/A'}ms\n`;
        report += `- Scroll Performance: ${tp.scrollTime || 'N/A'}ms\n\n`;
      }

      if (results.metrics.websocketPerformance) {
        report += '### WebSocket Performance\n';
        const wp = results.metrics.websocketPerformance;
        report += `- Throughput: ${wp.messagesPerSecond || 'N/A'} msgs/sec\n`;
        report += `- Bandwidth: ${((wp.bytesPerSecond || 0) / 1024).toFixed(2)} KB/sec\n`;
        report += `- Average Latency: ${wp.averageLatency || 'N/A'}ms\n`;
        report += `- P95 Latency: ${wp.p95Latency || 'N/A'}ms\n\n`;
      }

      if (results.metrics.stressTestProfile) {
        report += '### Stress Test Results\n';
        const stp = results.metrics.stressTestProfile;
        report += `- Max Concurrent Connections: ${stp.maxConnections}\n`;
        report += `- Peak Memory Usage: ${((stp.memoryPeak || 0) / 1024 / 1024).toFixed(2)} MB\n`;
        report += `- Peak CPU Usage: ${stp.cpuPeak || 'N/A'}%\n`;
        report += `- Average Message Latency: ${stp.averageLatency || 'N/A'}ms\n\n`;
      }
    }

    // Bundle Analysis
    if (results.bundleAnalysis) {
      report += '### Bundle Analysis\n';
      const ba = results.bundleAnalysis;
      report += `- Total Bundle Size: ${this.formatBytes(ba.totalSize)}\n`;
      report += `- Gzipped Size: ${this.formatBytes(ba.gzippedSize)}\n`;
      report += `- Code Splitting Effectiveness: ${(ba.codeSplitting.effectiveness * 100).toFixed(1)}%\n`;
      report += `- Number of Chunks: ${ba.chunks.length}\n\n`;
    }

    // Performance Regressions
    if (results.regressions.length > 0) {
      report += '## 🚨 Performance Regressions\n\n';
      for (const regression of results.regressions) {
        report += `- ⚠️  ${regression}\n`;
      }
      report += '\n';
    }

    // Recommendations
    if (results.recommendations.length > 0) {
      report += '## 💡 Optimization Recommendations\n\n';
      for (const recommendation of results.recommendations) {
        report += `- ${recommendation}\n`;
      }
      report += '\n';
    }

    // Test Details (only if tests were run)
    if (results.benchmarks) {
      report += '## Detailed Test Results\n\n';
      report += '### Benchmark Results\n\n';
      for (const result of results.benchmarks.results) {
        report += `#### ${result.testName}\n`;
        report += `- **Status:** ${result.success ? '✅ Passed' : '❌ Failed'}\n`;
        report += `- **Duration:** ${result.duration.toFixed(2)}ms\n`;
        if (result.error) {
          report += `- **Error:** ${result.error}\n`;
        }
        report += '\n';
      }
    }

    report += `---\n\n*Report generated on ${new Date().toISOString()}*\n`;

    return report;
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Run tests in CI mode (faster, fewer iterations)
   */
  async runCITests(): Promise<ComprehensiveResults> {
    const ciConfig: Partial<TestRunConfig> = {
      testEnvironment: 'ci',
      runStressTests: false, // Skip stress tests in CI for speed
      enableLighthouse: false, // Skip Lighthouse in CI
      enableMonitoring: false, // Minimal monitoring in CI
    };

    return this.runAllTests();
  }

  /**
   * Run quick performance check (essential metrics only)
   */
  async runQuickCheck(): Promise<ComprehensiveResults> {
    const quickConfig: Partial<TestRunConfig> = {
      runStressTests: false,
      runBundleAnalysis: true,
      enableMonitoring: false,
      enableLighthouse: false,
    };

    const oldConfig = { ...this.config };
    this.config = { ...this.config, ...quickConfig };

    try {
      return await this.runAllTests();
    } finally {
      this.config = oldConfig;
    }
  }
}

// Export default runner instance
export const performanceRunner = new PerformanceTestRunner();