/**
 * Enhanced Jest Configuration for Reliability and Performance
 * Optimized for Claude Flow UI testing requirements
 */

const nextJest = require('next/jest');

const createJestConfig = nextJest({
  dir: './',
});

// Reliability-focused Jest configuration
const reliabilityJestConfig = {
  // ============================================================================
  // PERFORMANCE OPTIMIZATION
  // ============================================================================

  // Optimize worker usage based on environment
  maxWorkers: process.env.CI ? 1 : '50%',

  // Run tests in band for CI to prevent resource conflicts
  runInBand: process.env.CI === 'true',

  // Enable caching for faster subsequent runs
  cache: true,
  cacheDirectory: '<rootDir>/.jest-cache',

  // Optimize test execution order
  testSequencer: '<rootDir>/tests/config/testSequencer.js',

  // ============================================================================
  // TIMEOUT CONFIGURATION
  // ============================================================================

  // Reasonable timeouts for different test types
  testTimeout: process.env.CI ? 60000 : 30000, // 60s for CI, 30s for local

  // Setup files with reliable initialization
  setupFilesAfterEnv: [
    '<rootDir>/tests/config/setup.reliable.js'
  ],

  setupFiles: [
    '<rootDir>/tests/config/setup.globals.js'
  ],

  // ============================================================================
  // TEST ENVIRONMENT
  // ============================================================================

  testEnvironment: 'jsdom',

  // Enhanced test environment options
  testEnvironmentOptions: {
    url: 'http://localhost:3000',
    userAgent: 'Claude-Flow-UI-Test-Agent',
    pretendToBeVisual: true,
    resources: 'usable',
    runScripts: 'dangerously',
  },

  // ============================================================================
  // TEST DISCOVERY
  // ============================================================================

  // Optimized test patterns
  testMatch: [
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],

  // Ignore patterns for better performance
  testPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/.next/',
    '<rootDir>/coverage/',
    '<rootDir>/.swarm/',
    '<rootDir>/tests/archives/',
    '<rootDir>/tests/temp/',
  ],

  // ============================================================================
  // MODULE RESOLUTION
  // ============================================================================

  // Enhanced module name mapping
  moduleNameMapper: {
    // Path aliases
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@components/(.*)$': '<rootDir>/src/components/$1',
    '^@lib/(.*)$': '<rootDir>/src/lib/$1',
    '^@hooks/(.*)$': '<rootDir>/src/hooks/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',

    // Asset mocking
    '\\\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '\\\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$': '<rootDir>/tests/mocks/fileMock.js',

    // WebSocket mocking
    '^ws$': '<rootDir>/tests/mocks/wsMock.js',
    '^socket\\.io-client$': '<rootDir>/tests/mocks/socketMock.js',
  },

  // Module directories for resolution
  moduleDirectories: [
    'node_modules',
    '<rootDir>/src',
    '<rootDir>/tests',
  ],

  // ============================================================================
  // TRANSFORM CONFIGURATION
  // ============================================================================

  // Transform ignore patterns for better compatibility
  transformIgnorePatterns: [
    'node_modules/(?!(socket\\.io-client|@xterm/xterm|@xterm/addon-.*|uuid|es6-promise|p-map|p-limit|nanoid)/)'
  ],

  // Custom transforms
  transform: {
    '^.+\\\\.(js|jsx|ts|tsx)$': ['next/jest'],
    '^.+\\\\.svg$': '<rootDir>/tests/transforms/svgTransform.js',
  },

  // ============================================================================
  // COVERAGE CONFIGURATION
  // ============================================================================

  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/*.config.{js,jsx,ts,tsx}',
    '!src/**/index.{js,jsx,ts,tsx}',
    '!src/app/layout.tsx',
    '!src/app/page.tsx',
  ],

  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json-summary',
    'clover'
  ],

  coverageDirectory: 'coverage',

  // Adjusted coverage thresholds for reliability
  coverageThreshold: {
    global: {
      branches: 65,
      functions: 65,
      lines: 65,
      statements: 65,
    },
    // Specific thresholds for critical components
    'src/components/terminal/': {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70,
    },
    'src/hooks/': {
      branches: 75,
      functions: 75,
      lines: 75,
      statements: 75,
    },
  },

  // ============================================================================
  // RELIABILITY FEATURES
  // ============================================================================

  // Mock and cleanup configuration
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  // Error handling
  errorOnDeprecated: false,
  bail: false, // Continue running tests even if some fail

  // Handle detection and cleanup
  detectOpenHandles: false, // Disable to prevent timeout issues
  forceExit: true, // Force exit after tests complete

  // Retry configuration for flaky tests
  retry: process.env.CI ? 2 : 0,
  retryImmediately: true,

  // ============================================================================
  // GLOBAL SETUP AND TEARDOWN
  // ============================================================================

  globalSetup: '<rootDir>/tests/config/globalSetup.reliable.js',
  globalTeardown: '<rootDir>/tests/config/globalTeardown.reliable.js',

  // ============================================================================
  // REPORTING
  // ============================================================================

  // Enhanced reporters for CI and local development
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: './test-results',
      filename: 'jest-report.html',
      expand: true,
      hideIcon: false,
      pageTitle: 'Claude Flow UI Test Results'
    }],
    ...(process.env.CI ? [
      ['jest-junit', {
        outputDirectory: 'test-results',
        outputName: 'junit.xml',
        titleTemplate: '{classname} - {title}',
        ancestorSeparator: ' › ',
        usePathForSuiteName: true
      }]
    ] : [])
  ],

  // Verbose output for debugging
  verbose: process.env.DEBUG_TESTS === 'true',

  // ============================================================================
  // WATCH MODE CONFIGURATION
  // ============================================================================

  watchPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/.next/',
    '<rootDir>/coverage/',
    '<rootDir>/.swarm/',
    '<rootDir>/test-results/',
    '<rootDir>/.jest-cache/',
  ],

  // Watch plugins for better development experience
  watchPlugins: [
    'jest-watch-typeahead/filename',
    'jest-watch-typeahead/testname',
  ],

  // ============================================================================
  // CUSTOM CONFIGURATION
  // ============================================================================

  // Custom globals for test utilities
  globals: {
    __TEST_ENV__: 'jest',
    __PERFORMANCE_BUDGET__: {
      render: 100,
      interaction: 50,
      async: 1000,
    },
    __MEMORY_BUDGET__: {
      baseline: 50 * 1024 * 1024, // 50MB
      leak_threshold: 10 * 1024 * 1024, // 10MB
    },
  },

  // ============================================================================
  // EXPERIMENTAL FEATURES
  // ============================================================================

  // Enable experimental features for better performance
  extensionsToTreatAsEsm: ['.ts', '.tsx'],

  // ============================================================================
  // DEBUGGING CONFIGURATION
  // ============================================================================

  // Enhanced debugging options
  ...(process.env.DEBUG_JEST === 'true' && {
    verbose: true,
    detectOpenHandles: true,
    forceExit: false,
    logHeapUsage: true,
  }),
};

// Export the enhanced configuration
module.exports = createJestConfig(reliabilityJestConfig);