const nextJest = require('next/jest');
const path = require('path');

const createJestConfig = nextJest({
  dir: './',
});

/**
 * Enhanced Jest Configuration for Comprehensive Coverage Collection
 * Optimized for claude-flow-ui with advanced coverage reporting
 */
const coverageJestConfig = {
  // Use the optimized setup from main config
  extends: '<rootDir>/jest.config.js',

  // Enhanced setup files for coverage collection
  setupFilesAfterEnv: [
    '<rootDir>/tests/setup-comprehensive.ts',
    '<rootDir>/tests/coverage/setup-coverage.ts'
  ],

  setupFiles: ['<rootDir>/tests/jest.setup.reliable.js'],

  testEnvironment: 'jsdom',

  // Comprehensive test matching for coverage
  testMatch: [
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/*.{test,spec}.{js,jsx,ts,tsx}',
    // Include integration tests
    '<rootDir>/tests/integration/**/*.{test,spec}.{js,jsx,ts,tsx}',
    // Include API tests
    '<rootDir>/tests/api/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],

  // Path aliases for consistent imports
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@components/(.*)$': '<rootDir>/src/components/$1',
    '^@lib/(.*)$': '<rootDir>/src/lib/$1',
    '^@hooks/(.*)$': '<rootDir>/src/hooks/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    // Handle static assets and CSS
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$': 'jest-transform-stub',
    // Mock WebSocket for tests
    '^socket.io-client$': '<rootDir>/tests/mocks/socket.io-client.js',
  },

  // Ignore patterns for node_modules
  transformIgnorePatterns: [
    'node_modules/(?!(socket.io-client|@xterm/xterm|@xterm/addon-.*|uuid|es6-promise|p-map|p-limit|unique-filename)/)'
  ],

  // Comprehensive coverage collection
  collectCoverage: true,

  collectCoverageFrom: [
    // Source files
    'src/**/*.{js,jsx,ts,tsx}',
    // Server files
    'unified-server.js',
    'websocket-server.js',

    // Exclude files that don't need coverage
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/*.config.{js,jsx,ts,tsx}',
    '!src/**/*.test.{js,jsx,ts,tsx}',
    '!src/**/*.spec.{js,jsx,ts,tsx}',
    '!src/**/__tests__/**',

    // Exclude Next.js specific files
    '!src/app/layout.tsx',
    '!src/app/page.tsx',
    '!src/app/globals.css',

    // Exclude generated files
    '!src/**/*.generated.{js,jsx,ts,tsx}',
    '!**/node_modules/**',
    '!**/.next/**',
    '!**/coverage/**',
    '!**/build/**',
    '!**/dist/**',
  ],

  // Enhanced coverage reporting
  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json',
    'json-summary',
    'cobertura',
    'clover'
  ],

  coverageDirectory: 'coverage/jest',

  // Realistic coverage thresholds for gradual improvement
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    // Higher thresholds for critical components
    './src/hooks/**/*.{js,jsx,ts,tsx}': {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/lib/**/*.{js,jsx,ts,tsx}': {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/services/**/*.{js,jsx,ts,tsx}': {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85,
    },
    // Slightly lower for UI components (harder to test)
    './src/components/**/*.{js,jsx,ts,tsx}': {
      branches: 70,
      functions: 75,
      lines: 75,
      statements: 75,
    },
  },

  // Enhanced reporting for CI/CD
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'coverage/jest',
      outputName: 'junit.xml',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}',
      ancestorSeparator: ' › ',
      usePathForSuiteName: true
    }],
    ...(process.env.CI ? [
      ['jest-sonar-reporter', {
        outputDirectory: 'coverage/jest',
        outputName: 'sonar-report.xml'
      }]
    ] : [])
  ],

  // Performance settings for coverage
  testTimeout: 45000,
  maxWorkers: process.env.CI ? 2 : '50%',

  // Coverage-specific settings
  collectCoverageOnlyFrom: {
    'src/**/*.{js,jsx,ts,tsx}': true,
    'unified-server.js': true,
    'websocket-server.js': true,
  },

  // Additional coverage options
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/tests/',
    '/coverage/',
    '/.next/',
    '/build/',
    '/dist/',
    '\\.stories\\.',
    '\\.test\\.',
    '\\.spec\\.',
    '__tests__',
    '__mocks__',
  ],

  // Mock and cleanup configuration
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  // Error handling
  errorOnDeprecated: false,
  bail: false,
  detectOpenHandles: false,
  forceExit: true,

  // CI-specific settings
  ...(process.env.CI === 'true' && {
    runInBand: true,
    ci: true,
    updateSnapshot: false,
  }),

  // Watch mode configuration
  watchPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/.next/',
    '<rootDir>/coverage/',
    '<rootDir>/.swarm/',
    '<rootDir>/rest-api/',
  ],

  // Global test setup/teardown
  globalSetup: '<rootDir>/tests/utils/globalSetup.js',
  globalTeardown: '<rootDir>/tests/utils/globalTeardown.js',

  // Verbose output for debugging coverage issues
  verbose: process.env.COVERAGE_DEBUG === 'true',

  // Custom test environment options
  testEnvironmentOptions: {
    url: 'http://localhost:11235',
    runScripts: 'dangerously',
    resources: 'usable',
  },
};

module.exports = createJestConfig(coverageJestConfig);