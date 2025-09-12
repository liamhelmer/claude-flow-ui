/**
 * CI/CD Testing Pipeline Optimizations
 * Performance improvements and configuration for continuous integration
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

// Environment detection
const isCI = process.env.CI === 'true';
const isGitHubActions = process.env.GITHUB_ACTIONS === 'true';
const isLocal = !isCI;

// Performance configuration based on environment
const getOptimalWorkerCount = () => {
  const cpuCount = os.cpus().length;
  
  if (isCI) {
    // Conservative worker count for CI to avoid resource contention
    return Math.min(2, cpuCount);
  }
  
  if (isLocal) {
    // Use 50% of available cores locally for better responsiveness
    return Math.max(1, Math.floor(cpuCount * 0.5));
  }
  
  return 1;
};

const getTestTimeout = () => {
  if (isCI) {
    // Longer timeout in CI due to potentially slower environments
    return 30000; // 30 seconds
  }
  
  return 15000; // 15 seconds locally
};

const shouldRunInBand = () => {
  // Run tests serially in CI for more predictable results
  return isCI;
};

// Test categorization for parallel execution
const testCategories = {
  unit: {
    pattern: '**/__tests__/**/*.test.{js,jsx,ts,tsx}',
    exclude: ['**/integration/**', '**/e2e/**', '**/performance/**'],
    timeout: 10000,
    priority: 1,
  },
  integration: {
    pattern: '**/integration/**/*.test.{js,jsx,ts,tsx}',
    timeout: 20000,
    priority: 2,
  },
  accessibility: {
    pattern: '**/accessibility/**/*.test.{js,jsx,ts,tsx}',
    timeout: 15000,
    priority: 3,
  },
  performance: {
    pattern: '**/performance/**/*.test.{js,jsx,ts,tsx}',
    timeout: 30000,
    priority: 4,
  },
};

// Jest configuration optimizations
const getOptimizedJestConfig = (category = 'all') => {
  const baseConfig = {
    // Performance optimizations
    maxWorkers: getOptimalWorkerCount(),
    testTimeout: getTestTimeout(),
    runInBand: shouldRunInBand(),
    
    // Memory management
    logHeapUsage: isCI,
    detectOpenHandles: !isCI, // Disable in CI to prevent hanging
    forceExit: isCI,
    
    // Cache optimizations
    cache: !isCI, // Disable cache in CI for clean builds
    cacheDirectory: isLocal ? '<rootDir>/.jest-cache' : undefined,
    
    // Coverage optimizations
    collectCoverage: true,
    coverageReporters: isCI 
      ? ['text-summary', 'lcov', 'json-summary']
      : ['text', 'html'],
    
    // Reporter optimizations
    reporters: [
      'default',
      ...(isCI ? [
        ['jest-junit', {
          outputDirectory: 'test-results',
          outputName: `results-${category}.xml`,
          classNameTemplate: '{classname}',
          titleTemplate: '{title}',
        }]
      ] : []),
    ],
    
    // Environment optimizations
    testEnvironment: 'jsdom',
    testEnvironmentOptions: {
      url: 'http://localhost',
      userAgent: 'jest-test-runner',
    },
    
    // Module handling optimizations
    transformIgnorePatterns: [
      'node_modules/(?!(socket.io-client|@xterm/xterm|@xterm/addon-fit|uuid|react-tabs)/)',
    ],
    
    // Watch mode optimizations (local only)
    ...(isLocal && {
      watchPathIgnorePatterns: [
        '<rootDir>/node_modules/',
        '<rootDir>/.next/',
        '<rootDir>/coverage/',
        '<rootDir>/.swarm/',
        '<rootDir>/test-results/',
      ],
    }),
  };
  
  // Category-specific configurations
  if (category !== 'all' && testCategories[category]) {
    const categoryConfig = testCategories[category];
    return {
      ...baseConfig,
      testMatch: [categoryConfig.pattern],
      testPathIgnorePatterns: categoryConfig.exclude || [],
      testTimeout: categoryConfig.timeout,
    };
  }
  
  return baseConfig;
};

// Test execution strategies
const getExecutionStrategy = () => {
  if (isCI) {
    return {
      strategy: 'sequential',
      categories: ['unit', 'integration', 'accessibility', 'performance'],
      parallelCategories: false,
      failFast: true,
    };
  }
  
  return {
    strategy: 'parallel',
    categories: ['unit', 'integration'],
    parallelCategories: true,
    failFast: false,
  };
};

// Resource monitoring
const monitorResources = () => {
  const startTime = Date.now();
  const startMemory = process.memoryUsage();
  
  return {
    getMetrics: () => {
      const endTime = Date.now();
      const endMemory = process.memoryUsage();
      
      return {
        duration: endTime - startTime,
        memoryDelta: {
          rss: endMemory.rss - startMemory.rss,
          heapUsed: endMemory.heapUsed - startMemory.heapUsed,
          heapTotal: endMemory.heapTotal - startMemory.heapTotal,
          external: endMemory.external - startMemory.external,
        },
        cpuUsage: process.cpuUsage(),
      };
    },
  };
};

// Test result aggregation
const aggregateTestResults = (results) => {
  const summary = {
    total: 0,
    passed: 0,
    failed: 0,
    skipped: 0,
    duration: 0,
    coverage: {
      statements: 0,
      branches: 0,
      functions: 0,
      lines: 0,
    },
  };
  
  results.forEach(result => {
    summary.total += result.numTotalTests;
    summary.passed += result.numPassedTests;
    summary.failed += result.numFailedTests;
    summary.skipped += result.numPendingTests;
    summary.duration += result.testExecError ? 0 : result.perfStats.end - result.perfStats.start;
    
    if (result.coverageMap) {
      const coverageSummary = result.coverageMap.getCoverageSummary();
      summary.coverage.statements += coverageSummary.statements.pct;
      summary.coverage.branches += coverageSummary.branches.pct;
      summary.coverage.functions += coverageSummary.functions.pct;
      summary.coverage.lines += coverageSummary.lines.pct;
    }
  });
  
  // Average coverage percentages
  const resultCount = results.length;
  if (resultCount > 0) {
    summary.coverage.statements /= resultCount;
    summary.coverage.branches /= resultCount;
    summary.coverage.functions /= resultCount;
    summary.coverage.lines /= resultCount;
  }
  
  return summary;
};

// Cache management
const manageCacheOptimization = () => {
  const cacheDir = path.join(process.cwd(), '.jest-cache');
  
  return {
    clear: () => {
      if (fs.existsSync(cacheDir)) {
        fs.rmSync(cacheDir, { recursive: true, force: true });
      }
    },
    
    size: () => {
      if (!fs.existsSync(cacheDir)) return 0;
      
      const getDirectorySize = (dirPath) => {
        let size = 0;
        const files = fs.readdirSync(dirPath);
        
        files.forEach(file => {
          const filePath = path.join(dirPath, file);
          const stats = fs.statSync(filePath);
          
          if (stats.isDirectory()) {
            size += getDirectorySize(filePath);
          } else {
            size += stats.size;
          }
        });
        
        return size;
      };
      
      return getDirectorySize(cacheDir);
    },
    
    optimize: () => {
      const maxCacheSize = 100 * 1024 * 1024; // 100MB
      const currentSize = this.size();
      
      if (currentSize > maxCacheSize) {
        this.clear();
        console.log(`Cache cleared: was ${(currentSize / 1024 / 1024).toFixed(2)}MB`);
      }
    },
  };
};

// Performance profiling
const createPerformanceProfiler = () => {
  const profiles = new Map();
  
  return {
    start: (name) => {
      profiles.set(name, {
        startTime: performance.now(),
        startMemory: process.memoryUsage(),
      });
    },
    
    end: (name) => {
      const profile = profiles.get(name);
      if (!profile) return null;
      
      const endTime = performance.now();
      const endMemory = process.memoryUsage();
      
      const result = {
        name,
        duration: endTime - profile.startTime,
        memoryDelta: endMemory.heapUsed - profile.startMemory.heapUsed,
      };
      
      profiles.delete(name);
      return result;
    },
    
    getAll: () => Array.from(profiles.entries()),
    
    clear: () => profiles.clear(),
  };
};

// CI-specific optimizations
const getCIOptimizations = () => {
  if (!isCI) return {};
  
  return {
    // Reduce test output verbosity
    verbose: false,
    silent: true,
    
    // Optimize for CI environment
    setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
    globalSetup: '<rootDir>/tests/utils/globalSetup.js',
    globalTeardown: '<rootDir>/tests/utils/globalTeardown.js',
    
    // Error handling
    bail: 1, // Stop after first test suite failure
    errorOnDeprecated: false,
    
    // Resource limits
    maxConcurrency: 5,
    
    // Retry configuration for flaky tests
    retry: process.env.TEST_RETRY ? parseInt(process.env.TEST_RETRY, 10) : 0,
  };
};

// Test sharding for parallel execution
const createTestShards = (testFiles, shardCount) => {
  const shards = Array.from({ length: shardCount }, () => []);
  
  testFiles.forEach((file, index) => {
    const shardIndex = index % shardCount;
    shards[shardIndex].push(file);
  });
  
  return shards;
};

// Export configuration functions
module.exports = {
  getOptimizedJestConfig,
  getExecutionStrategy,
  getOptimalWorkerCount,
  getTestTimeout,
  shouldRunInBand,
  monitorResources,
  aggregateTestResults,
  manageCacheOptimization,
  createPerformanceProfiler,
  getCIOptimizations,
  createTestShards,
  testCategories,
  
  // Environment flags
  isCI,
  isGitHubActions,
  isLocal,
  
  // Utility functions
  formatDuration: (ms) => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  },
  
  formatMemory: (bytes) => {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(1)}GB`;
  },
};