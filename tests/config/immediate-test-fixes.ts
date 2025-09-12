/**
 * Immediate Test Environment Fixes
 * Quick wins to get basic test suite operational
 */

export const TEST_FIXES = {
  // Fix test environment issues
  environment: {
    jsdom_fixes: [
      'Add @testing-library/jest-dom to setupFilesAfterEnv',
      'Mock window/document for Node.js tests', 
      'Configure proper test environment per file type'
    ],
    
    mock_fixes: [
      'Fix variable initialization order in mocks',
      'Use proper jest.mock hoisting patterns',
      'Implement consistent mock patterns across tests'
    ]
  },

  // Priority test coverage targets
  priority_coverage: [
    {
      module: 'lib/tmux-manager.js',
      current_coverage: 73.76,
      target: 90,
      status: 'working'
    },
    {
      module: 'components/sidebar/Sidebar.tsx', 
      current_coverage: 100,
      target: 100,
      status: 'complete'
    },
    {
      module: 'lib/utils.ts',
      current_coverage: 13.79,
      target: 80,
      status: 'needs_tests'
    }
  ],

  // Missing modules that need implementation
  missing_modules: [
    'src/lib/file-system-utils.ts',
    'src/lib/memory-leak-detector.ts', 
    'src/hooks/useWebSocketConnection.tsx',
    'src/components/ErrorBoundary.tsx',
    'src/lib/tmux/session-manager.ts'
  ],

  // Immediate actionable fixes
  quick_wins: [
    'Remove tests for non-existent modules',
    'Fix Jest environment configuration',
    'Implement basic mock patterns',
    'Add comprehensive tests for working modules'
  ]
};

/**
 * Test Environment Configuration Fix
 */
export const createTestEnvironmentFix = () => {
  return {
    // Global setup that works
    setupFilesAfterEnv: [
      '<rootDir>/tests/setup-enhanced.ts'
    ],
    
    // Environment per test type
    projects: [
      {
        displayName: 'jsdom',
        testEnvironment: 'jsdom',
        testMatch: [
          '<rootDir>/src/components/**/*.test.{ts,tsx}',
          '<rootDir>/src/hooks/**/*.test.{ts,tsx}',
          '<rootDir>/tests/integration/**/*.test.{ts,tsx}'
        ]
      },
      {
        displayName: 'node',
        testEnvironment: 'node', 
        testMatch: [
          '<rootDir>/src/lib/**/*.test.{ts,js}',
          '<rootDir>/tests/performance/**/*.test.{ts,js}',
          '<rootDir>/tests/security/**/*.test.{ts,js}'
        ]
      }
    ]
  };
};

/**
 * Mock Pattern Templates
 */
export const MOCK_PATTERNS = {
  websocket: `
// Proper WebSocket mock pattern
const mockSocket = {
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  off: jest.fn()
};

jest.mock('socket.io-client', () => ({
  io: jest.fn(() => mockSocket)
}));
  `,

  terminal: `
// Proper Terminal mock pattern  
const mockTerminal = {
  open: jest.fn(),
  write: jest.fn(),
  writeln: jest.fn(),
  resize: jest.fn(),
  dispose: jest.fn()
};

jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => mockTerminal)
}));
  `,

  filesystem: `
// Proper filesystem mock pattern
jest.mock('fs', () => ({
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
  existsSync: jest.fn(),
  mkdirSync: jest.fn()
}));
  `
};

export default TEST_FIXES;