/**
 * Jest Configuration for Production Terminal Testing
 *
 * This configuration ensures tests run in a production-like environment
 * to reproduce terminal input/switching issues that only occur in production.
 */

module.exports = {
  displayName: 'Production Terminal Regression Tests',
  testMatch: [
    '**/tests/regression/production-*.test.js'
  ],
  setupFilesAfterEnv: [
    '<rootDir>/tests/regression/production-environment-setup.js'
  ],
  testEnvironment: 'jsdom',
  testEnvironmentOptions: {
    url: 'http://localhost:3000'
  },

  // Force production environment
  globals: {
    'process.env': {
      NODE_ENV: 'production',
      FAST_REFRESH: 'false',
      REACT_STRICT_MODE: 'false'
    }
  },

  // Production-specific module handling
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@components/(.*)$': '<rootDir>/src/components/$1',
    '^@hooks/(.*)$': '<rootDir>/src/hooks/$1',
    '^@lib/(.*)$': '<rootDir>/src/lib/$1'
  },

  // Transform settings for production testing
  transform: {
    '^.+\\.(js|jsx|ts|tsx)$': ['babel-jest', {
      presets: [
        ['@babel/preset-env', { targets: 'defaults' }],
        ['@babel/preset-react', { runtime: 'automatic' }]
      ],
      plugins: [
        // Disable development-specific transforms
        process.env.NODE_ENV === 'production' && [
          'transform-remove-console',
          { exclude: ['error', 'warn'] }
        ]
      ].filter(Boolean)
    }]
  },

  // Coverage for production-specific code paths
  collectCoverageFrom: [
    'src/components/terminal/**/*.{js,jsx,ts,tsx}',
    'src/hooks/useTerminal.{js,ts}',
    'src/hooks/useWebSocket.{js,ts}',
    'src/lib/websocket/**/*.{js,jsx,ts,tsx}',
    '!**/*.d.ts',
    '!**/node_modules/**'
  ],

  // Timeouts adjusted for production behavior simulation
  testTimeout: 10000,

  // Verbose output for debugging production issues
  verbose: true,

  // Additional setup for production environment
  setupFiles: [
    '<rootDir>/tests/regression/production-polyfills.js'
  ]
};