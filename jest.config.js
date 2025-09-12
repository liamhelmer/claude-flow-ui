const nextJest = require('next/jest');

const createJestConfig = nextJest({
  dir: './',
});

// Optimized Jest configuration for Claude Flow UI
const customJestConfig = {
  // Setup files - enhanced setup with performance and reliability fixes
  setupFilesAfterEnv: ['<rootDir>/tests/setup-enhanced.ts'],
  
  // CRITICAL FIX: Use reliable setup for setupFiles (before Jest globals)
  setupFiles: ['<rootDir>/tests/jest.setup.reliable.js'],
  
  // Test environment
  testEnvironment: 'jsdom',
  
  // Test file patterns - optimized for better discovery
  testMatch: [
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{test,spec}.{js,jsx,ts,tsx}',
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
  
  // Transform ignore patterns for node_modules
  transformIgnorePatterns: [
    'node_modules/(?!(socket.io-client|@xterm/xterm|@xterm/addon-fit|uuid|es6-promise|p-map|p-limit)/)'
  ],
  
  // Coverage configuration
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/app/layout.tsx',
    '!src/app/page.tsx',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/*.config.{js,jsx,ts,tsx}',
  ],
  
  // Coverage reporting
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  coverageDirectory: 'coverage',
  
  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70, 
      lines: 70,
      statements: 70,
    },
  },
  
  // Global setup and teardown
  globalSetup: '<rootDir>/tests/utils/globalSetup.js',
  globalTeardown: '<rootDir>/tests/utils/globalTeardown.js',
  
  // Performance optimizations
  testTimeout: 30000, // 30 seconds - reasonable for reliable execution
  maxWorkers: "50%", // Use half available workers for better performance
  
  // Mock and cleanup configuration
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  
  // Error handling improvements
  errorOnDeprecated: false, // Don't fail on deprecation warnings
  bail: false, // Continue running tests even if some fail
  detectOpenHandles: false, // Disable to prevent timeout issues
  forceExit: true, // Force exit after tests complete
  
  // Better test isolation - run tests serially in CI
  ...(process.env.CI === 'true' && { runInBand: true }),
  
  // Verbose output for debugging
  verbose: process.env.NODE_ENV === 'test' && process.env.DEBUG_TESTS === 'true',
  
  // Better error reporting
  reporters: [
    'default',
    ...(process.env.CI ? [['jest-junit', { outputDirectory: 'test-results', outputName: 'results.xml' }]] : [])
  ],
  
  // Watch mode configuration
  watchPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/.next/',
    '<rootDir>/coverage/',
    '<rootDir>/.swarm/',
  ],
};

module.exports = createJestConfig(customJestConfig);