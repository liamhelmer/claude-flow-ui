const nextJest = require('next/jest');

const createJestConfig = nextJest({
  dir: './',
});

// Optimized Jest configuration for Claude Flow UI - Performance Enhanced
const optimizedJestConfig = {
  // Setup files - streamlined for performance
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  setupFiles: ['<rootDir>/tests/jest.setup.simplified.js'],
  
  // Test environment
  testEnvironment: 'jsdom',
  
  // Optimized test file patterns
  testMatch: [
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],
  
  // Prioritize newer tests and faster patterns
  testPathIgnorePatterns: [
    '<rootDir>/.next/',
    '<rootDir>/node_modules/',
    '<rootDir>/src/**/*.comprehensive.enhanced.test.*', // Skip slow comprehensive tests in CI
  ],
  
  // Module name mapping for path aliases
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@components/(.*)$': '<rootDir>/src/components/$1',
    '^@lib/(.*)$': '<rootDir>/src/lib/$1',
    '^@hooks/(.*)$': '<rootDir>/src/hooks/$1',
    // Handle CSS and asset imports
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$': 'jest-transform-stub',
  },
  
  // Optimized transform patterns
  transformIgnorePatterns: [
    'node_modules/(?!(socket.io-client|@xterm/xterm|@xterm/addon-fit|uuid)/)',
  ],
  
  // Enhanced coverage configuration
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/app/layout.tsx',
    '!src/app/page.tsx',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/*.config.{js,jsx,ts,tsx}',
    '!src/**/*.test.{js,jsx,ts,tsx}',
    '!src/**/__tests__/**/*',
  ],
  
  // Coverage reporting
  coverageReporters: ['text', 'lcov', 'html-spa', 'json-summary'],
  coverageDirectory: 'coverage',
  
  // Improved coverage thresholds
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80, 
      lines: 85,
      statements: 85,
    },
    // Component-specific thresholds
    './src/components/': {
      branches: 75,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    './src/hooks/': {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/lib/': {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
  
  // Global setup and teardown
  globalSetup: '<rootDir>/tests/utils/globalSetup.js',
  globalTeardown: '<rootDir>/tests/utils/globalTeardown.js',
  
  // Performance optimizations
  testTimeout: 10000, // Increased timeout for comprehensive tests
  maxWorkers: process.env.CI ? 1 : '50%', // Use half available workers locally
  
  // Enhanced caching
  cacheDirectory: '<rootDir>/.jest-cache',
  
  // Mock and cleanup configuration
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  
  // Error handling improvements
  errorOnDeprecated: false,
  bail: false,
  detectOpenHandles: true,
  forceExit: true,
  
  // Optimized for different environments
  ...(process.env.CI === 'true' && { 
    runInBand: true,
    maxWorkers: 1,
    testTimeout: 15000, // Longer timeout in CI
  }),
  
  // Development optimizations
  ...(process.env.NODE_ENV === 'development' && {
    watchman: true,
    watchPathIgnorePatterns: [
      '<rootDir>/node_modules/',
      '<rootDir>/.next/',
      '<rootDir>/coverage/',
      '<rootDir>/.swarm/',
      '<rootDir>/.jest-cache/',
    ],
  }),
  
  // Enhanced logging
  verbose: process.env.NODE_ENV === 'test' && process.env.DEBUG_TESTS === 'true',
  
  // Better error reporting
  reporters: [
    'default',
    ['jest-junit', { 
      outputDirectory: 'test-results', 
      outputName: 'results.xml',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}',
      ancestorSeparator: ' › ',
    }],
    // Add performance reporter for monitoring test speed
    ...(process.env.PERFORMANCE_TESTS ? [['<rootDir>/tests/utils/performance-reporter.js']] : []),
  ],
  
  // Test categorization
  projects: [
    // Fast unit tests
    {
      displayName: 'unit',
      testMatch: [
        '<rootDir>/src/**/__tests__/**/*.test.{js,jsx,ts,tsx}',
        '!<rootDir>/src/**/__tests__/**/*.integration.test.{js,jsx,ts,tsx}',
        '!<rootDir>/src/**/__tests__/**/*.comprehensive.test.{js,jsx,ts,tsx}',
        '!<rootDir>/src/**/__tests__/**/*.performance.test.{js,jsx,ts,tsx}',
      ],
      testTimeout: 5000,
    },
    // Integration tests  
    {
      displayName: 'integration',
      testMatch: [
        '<rootDir>/src/**/__tests__/**/*.integration.test.{js,jsx,ts,tsx}',
        '<rootDir>/src/__tests__/integration/**/*.test.{js,jsx,ts,tsx}',
      ],
      testTimeout: 10000,
    },
    // Performance tests
    {
      displayName: 'performance',
      testMatch: [
        '<rootDir>/src/**/__tests__/**/*.performance.test.{js,jsx,ts,tsx}',
        '<rootDir>/src/__tests__/performance/**/*.test.{js,jsx,ts,tsx}',
      ],
      testTimeout: 30000,
      maxWorkers: 1, // Run performance tests serially
    },
    // Comprehensive tests (optional)
    ...(process.env.RUN_COMPREHENSIVE_TESTS ? [{
      displayName: 'comprehensive',
      testMatch: [
        '<rootDir>/src/**/__tests__/**/*.comprehensive.test.{js,jsx,ts,tsx}',
        '<rootDir>/src/**/__tests__/**/*.enhanced.test.{js,jsx,ts,tsx}',
      ],
      testTimeout: 20000,
    }] : []),
  ],
  
  // Memory and resource management
  logHeapUsage: process.env.CI === 'true',
  
  // Test result processors
  testResultsProcessor: '<rootDir>/tests/utils/test-results-processor.js',
  
  // Snapshot configuration
  snapshotSerializers: [
    'jest-serializer-html',
  ],
  
  // Module directories for faster resolution
  moduleDirectories: ['node_modules', '<rootDir>/src'],
  
  // Extensions in order of preference
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  
  // Collect test timing information
  ...(process.env.COLLECT_TEST_TIMING && {
    collectCoverage: false, // Disable coverage for timing runs
    reporters: [['<rootDir>/tests/utils/timing-reporter.js']],
  }),
};

module.exports = createJestConfig(optimizedJestConfig);