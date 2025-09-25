/**
 * Security Test Setup
 *
 * Global setup configuration for security tests including:
 * - Mock external security services
 * - Configure test isolation
 * - Set up security test utilities
 * - Initialize test data
 */

// Mock external HTTP requests to prevent actual network calls during testing
global.fetch = jest.fn();

// Mock WebSocket to prevent actual connections
jest.mock('ws', () => {
  const EventEmitter = require('events');
  
  class MockWebSocket extends EventEmitter {
    constructor(url, options = {}) {
      super();
      this.url = url;
      this.options = options;
      this.readyState = 1; // OPEN
      this.CONNECTING = 0;
      this.OPEN = 1;
      this.CLOSING = 2;
      this.CLOSED = 3;
    }
    
    send(data) {
      // Mock send - emit message event for testing
      setTimeout(() => this.emit('message', data), 10);
    }
    
    close(code, reason) {
      this.readyState = this.CLOSED;
      this.emit('close', code, reason);
    }
  }
  
  MockWebSocket.CONNECTING = 0;
  MockWebSocket.OPEN = 1;
  MockWebSocket.CLOSING = 2;
  MockWebSocket.CLOSED = 3;
  
  return MockWebSocket;
});

// Mock child_process for security tool execution
jest.mock('child_process', () => ({
  spawn: jest.fn().mockReturnValue({
    stdout: {
      on: jest.fn(),
      pipe: jest.fn()
    },
    stderr: {
      on: jest.fn()
    },
    on: jest.fn(),
    kill: jest.fn()
  }),
  exec: jest.fn((command, callback) => {
    // Mock different security tool responses
    const mockResponses = {
      'npm audit': JSON.stringify({
        vulnerabilities: { info: 0, low: 2, moderate: 1, high: 0, critical: 0 },
        metadata: { totalDependencies: 150 }
      }),
      'zap-baseline.py': JSON.stringify({
        site: [{
          alerts: [
            {
              name: 'Missing X-Content-Type-Options Header',
              riskdesc: 'Medium (Medium)',
              instances: [{ uri: 'http://localhost:3000' }]
            }
          ]
        }]
      })
    };
    
    const response = mockResponses[command] || '{"status": "completed"}';
    setTimeout(() => callback(null, response, ''), 100);
  })
}));

// Mock fs/promises for file system operations
jest.mock('fs/promises', () => ({
  readFile: jest.fn().mockResolvedValue('mock file content'),
  writeFile: jest.fn().mockResolvedValue(),
  readdir: jest.fn().mockResolvedValue(['file1.js', 'file2.ts']),
  stat: jest.fn().mockResolvedValue({
    isFile: () => true,
    isDirectory: () => false,
    mode: 0o644
  }),
  access: jest.fn().mockResolvedValue()
}));

// Security test utilities
global.SecurityTestHelpers = {
  // Generate test JWT token
  generateTestJWT: (payload = {}, secret = 'test-secret') => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const testPayload = Buffer.from(JSON.stringify({
      sub: 'test-user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...payload
    })).toString('base64');
    const signature = 'mock-signature';
    
    return `${header}.${testPayload}.${signature}`;
  },
  
  // Create mock HTTP server for testing
  createMockServer: () => ({
    listen: jest.fn().mockReturnValue({ close: jest.fn() }),
    use: jest.fn(),
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn()
  }),
  
  // Security assertion helpers
  assertSecureResponse: (response) => {
    expect(response.headers).toHaveProperty('x-content-type-options');
    expect(response.headers).toHaveProperty('x-frame-options');
    expect(response.headers).toHaveProperty('x-xss-protection');
  },
  
  // Mock vulnerability scanner results
  mockVulnerabilityResults: {
    clean: {
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      findings: []
    },
    withIssues: {
      vulnerabilities: { critical: 1, high: 2, medium: 5, low: 10 },
      findings: [
        {
          id: 'test-vuln-1',
          severity: 'critical',
          title: 'SQL Injection Vulnerability',
          description: 'Potential SQL injection in search endpoint'
        },
        {
          id: 'test-vuln-2',
          severity: 'high',
          title: 'XSS Vulnerability',
          description: 'Stored XSS in comment system'
        }
      ]
    }
  }
};

// Configure test environment
process.env.NODE_ENV = 'test';
process.env.SECURITY_TEST_MODE = 'true';

// Increase timeout for security tests
jest.setTimeout(120000);

// Console logging control for security tests
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

beforeAll(() => {
  // Suppress expected security test warnings/errors
  console.error = jest.fn((message) => {
    if (!message.includes('SecurityTest') && !message.includes('Expected')) {
      originalConsoleError(message);
    }
  });
  
  console.warn = jest.fn((message) => {
    if (!message.includes('SecurityTest') && !message.includes('Expected')) {
      originalConsoleWarn(message);
    }
  });
});

afterAll(() => {
  // Restore original console methods
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
  
  // Clear any global test state
  if (global.__testState) {
    global.__testState = {};
  }
});

// Custom matchers for security testing
expect.extend({
  toBeSecureResponse(received) {
    const requiredHeaders = [
      'x-content-type-options',
      'x-frame-options', 
      'x-xss-protection'
    ];
    
    const missingHeaders = requiredHeaders.filter(
      header => !received.headers || !received.headers[header]
    );
    
    const pass = missingHeaders.length === 0;
    
    return {
      pass,
      message: () => 
        pass 
          ? `Expected response to not have security headers`
          : `Expected response to have security headers. Missing: ${missingHeaders.join(', ')}`
    };
  },
  
  toContainSecurityVulnerability(received, vulnerabilityType) {
    const hasVulnerability = received.findings && 
      received.findings.some(finding => 
        finding.title.toLowerCase().includes(vulnerabilityType.toLowerCase()) ||
        finding.description.toLowerCase().includes(vulnerabilityType.toLowerCase())
      );
    
    return {
      pass: hasVulnerability,
      message: () => 
        hasVulnerability
          ? `Expected not to find ${vulnerabilityType} vulnerability`
          : `Expected to find ${vulnerabilityType} vulnerability in findings`
    };
  },
  
  toPassSecurityGate(received, thresholds) {
    const { critical = 0, high = 0, medium = 10, low = 20 } = thresholds;
    const vulns = received.vulnerabilities || {};
    
    const passes = 
      (vulns.critical || 0) <= critical &&
      (vulns.high || 0) <= high &&
      (vulns.medium || 0) <= medium &&
      (vulns.low || 0) <= low;
    
    return {
      pass: passes,
      message: () => 
        passes
          ? `Expected security gate to fail`
          : `Expected security gate to pass. Vulnerabilities: ${JSON.stringify(vulns)}, Thresholds: ${JSON.stringify(thresholds)}`
    };
  }
});

// Export for use in tests
module.exports = {
  SecurityTestHelpers: global.SecurityTestHelpers
};
