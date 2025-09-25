/**
 * Jest Security Testing Configuration
 *
 * Specialized Jest configuration for security tests with:
 * - Extended timeouts for security scanning
 * - Custom test environment for security isolation
 * - Security-specific coverage requirements
 * - Mock configurations for external security tools
 */

const baseConfig = require('../../jest.config.js');

module.exports = {
  ...baseConfig,
  
  // Test environment
  testEnvironment: 'node',
  
  // Test match patterns specifically for security tests
  testMatch: [
    '<rootDir>/tests/security/**/*.test.ts',
    '<rootDir>/tests/security/**/*.test.js'
  ],
  
  // Extended timeouts for security scanning operations
  testTimeout: 120000, // 2 minutes
  
  // Setup files for security testing
  setupFilesAfterEnv: [
    '<rootDir>/tests/security/setup/security-test-setup.js'
  ],
  
  // Module name mapping for security testing
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@security/(.*)$': '<rootDir>/tests/security/$1'
  },
  
  // Coverage configuration for security tests
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    'unified-server.js',
    'tests/security/utils/*.ts',
    '!src/**/*.d.ts',
    '!src/**/__tests__/**',
    '!**/*.test.{js,jsx,ts,tsx}',
    '!**/node_modules/**'
  ],
  
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    },
    './tests/security/utils/': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90
    }
  },
  
  // Custom reporters for security test results
  reporters: [
    'default',
    [
      'jest-html-reporters',
      {
        publicDir: './tests/security/reports',
        filename: 'security-test-report.html',
        openReport: false,
        pageTitle: 'Security Test Report'
      }
    ],
    [
      'jest-junit',
      {
        outputDirectory: './tests/security/reports',
        outputName: 'security-test-results.xml',
        suiteName: 'Security Tests'
      }
    ]
  ],
  
  // Transform configuration
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
    '^.+\\.(js|jsx)$': 'babel-jest'
  },
  
  // Module file extensions
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  
  // Global setup and teardown for security tests
  globalSetup: '<rootDir>/tests/security/setup/global-setup.js',
  globalTeardown: '<rootDir>/tests/security/setup/global-teardown.js',
  
  // Security-specific test environment variables
  testEnvironmentOptions: {
    // Isolate tests to prevent cross-contamination
    NODE_ENV: 'test',
    SECURITY_TEST_MODE: 'true',
    DISABLE_EXTERNAL_REQUESTS: 'true'
  },
  
  // Cache configuration
  cache: true,
  cacheDirectory: '<rootDir>/node_modules/.cache/jest-security',
  
  // Verbose output for security test debugging
  verbose: true,
  
  // Fail fast on first test failure for critical security issues
  bail: false,
  
  // Force exit after tests complete
  forceExit: true,
  
  // Clear mocks between tests
  clearMocks: true,
  
  // Mock specific modules for security testing
  modulePathIgnorePatterns: [
    '<rootDir>/node_modules/(?!(supertest|ws|validator|isomorphic-dompurify)/)',
  ],
  
  // Custom mock configurations
  __mocks__: {
    // Mock external security tools
    'child_process': '<rootDir>/tests/security/mocks/child_process.js',
    'fs/promises': '<rootDir>/tests/security/mocks/fs-promises.js'
  }
};
