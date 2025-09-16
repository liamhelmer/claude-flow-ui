/**
 * Enhanced Jest Configuration for Maximum Code Coverage
 * Targets 90%+ coverage across all metrics
 */

const baseConfig = require('../jest.config.js');

module.exports = {
  ...baseConfig,

  // Coverage collection
  collectCoverage: true,
  collectCoverageFrom: [
    // Main server files
    'unified-server.js',
    'websocket-server.js',

    // Source code
    'src/**/*.{js,jsx,ts,tsx}',

    // Library files
    'src/lib/**/*.{js,ts}',
    'src/components/**/*.{jsx,tsx}',
    'src/hooks/**/*.{js,ts,tsx}',
    'src/services/**/*.{js,ts}',

    // Exclude files from coverage
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/*.config.{js,jsx,ts,tsx}',
    '!src/**/index.{js,jsx,ts,tsx}',
    '!src/**/__tests__/**',
    '!src/**/__mocks__/**',
    '!**/node_modules/**',
    '!**/*.test.{js,jsx,ts,tsx}',
    '!**/*.spec.{js,jsx,ts,tsx}',
    '!coverage/**',
    '!.next/**',
    '!out/**',
    '!public/**',
    '!docs/**',
    '!scripts/**'
  ],

  // Coverage reporting
  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json',
    'json-summary',
    'clover',
    'cobertura'
  ],

  // Coverage output directory
  coverageDirectory: 'coverage',

  // Enhanced coverage thresholds for 90%+ coverage
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90
    },
    // Specific thresholds for critical components
    'src/lib/tmux-stream-manager.js': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95
    },
    'unified-server.js': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85
    },
    'src/components/**/*.{jsx,tsx}': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85
    },
    'src/hooks/**/*.{js,ts,tsx}': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90
    }
  },

  // Test patterns for comprehensive coverage
  testMatch: [
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/**/*.{test,spec}.{js,jsx,ts,tsx}'
  ],

  // Coverage path ignore patterns
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/.next/',
    '/out/',
    '/coverage/',
    '/docs/',
    '/scripts/',
    '/public/',
    '\\.stories\\.',
    '\\.config\\.',
    '\\.d\\.ts$',
    '__tests__',
    '__mocks__',
    'test-utils',
    'setupTests'
  ],

  // Additional Jest options for better coverage
  verbose: true,
  bail: false,

  // Force exit to ensure clean coverage reports
  forceExit: true,

  // Detect handles to identify potential leaks
  detectOpenHandles: true,

  // Clear mocks between tests for accurate coverage
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  // Custom reporters for enhanced output
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: './coverage/html-report',
      filename: 'jest-report.html',
      expand: true,
      hideIcon: false,
      pageTitle: 'Claude Flow UI Test Coverage Report'
    }],
    ['jest-junit', {
      outputDirectory: './coverage',
      outputName: 'junit.xml',
      ancestorSeparator: ' › ',
      uniqueOutputName: false,
      suiteNameTemplate: '{filepath}',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}'
    }]
  ],

  // Setup for coverage-specific configuration
  setupFilesAfterEnv: [
    '<rootDir>/tests/setup-enhanced.ts',
    '<rootDir>/tests/coverage-setup.js'
  ],

  // Transform ignore patterns for coverage
  transformIgnorePatterns: [
    'node_modules/(?!(socket.io-client|@xterm/.*|uuid|es6-promise)/)'
  ]
};