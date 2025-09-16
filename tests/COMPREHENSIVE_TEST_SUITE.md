# Comprehensive Testing Suite

This directory contains a complete testing framework for the Node.js hello world application with 90%+ code coverage.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual functions
├── integration/             # Integration tests for API endpoints
├── e2e/                     # End-to-end tests with Playwright
├── load/                    # Load testing with Artillery
├── security/                # Security vulnerability tests
├── performance/             # Performance benchmarks
├── mocks/                   # Mock implementations
├── fixtures/                # Test data and fixtures
└── ci/                      # CI/CD scripts and configurations
```

## Running Tests

### Prerequisites

Install dependencies:
```bash
npm install
```

### Individual Test Suites

```bash
# Unit tests
npm run test:unit

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e

# Security tests
npm run test:security

# Load tests
npm run test:load

# Performance benchmarks
npm run test:performance

# All tests with coverage
npm run test:coverage
```

### CI/CD Pipeline

Run the complete test suite:
```bash
# Use the comprehensive test runner
chmod +x tests/ci/test-runner.sh
./tests/ci/test-runner.sh

# Or run individual phases
npm run test:ci
```

## Test Coverage

The testing suite achieves 90%+ code coverage across:

- **Statements**: 90%+
- **Branches**: 90%+
- **Functions**: 90%+
- **Lines**: 90%+

### Coverage Reports

Coverage reports are generated in multiple formats:
- HTML: `coverage/lcov-report/index.html`
- LCOV: `coverage/lcov.info`
- JSON: `coverage/coverage-final.json`

## Test Types

### 1. Unit Tests (`/tests/unit/`)

Tests individual functions and modules in isolation:

- **unified-server.test.js**: Main server functionality
- **tmux-manager.test.js**: Terminal session management
- **utils.test.js**: Utility functions
- **api-client.test.js**: API client methods

**Key Features:**
- Complete mocking of external dependencies
- Edge case testing
- Error handling validation
- Memory leak detection

### 2. Integration Tests (`/tests/integration/`)

Tests API endpoints and component interactions:

- **api-endpoints.test.js**: HTTP API testing
- **websocket-integration.test.js**: WebSocket communication
- **database-integration.test.js**: Data persistence
- **external-services.test.js**: Third-party integrations

**Key Features:**
- Real server instances
- Database transactions
- WebSocket connections
- Cross-component workflows

### 3. End-to-End Tests (`/tests/e2e/`)

Browser-based testing with Playwright:

- **terminal-workflow.spec.js**: Complete user workflows
- **responsive-design.spec.js**: Mobile/tablet testing
- **accessibility.spec.js**: A11y compliance
- **performance.spec.js**: Frontend performance

**Browsers Tested:**
- Chromium
- Firefox
- WebKit
- Mobile Safari
- Mobile Chrome

### 4. Load Tests (`/tests/load/`)

Performance and scalability testing:

- **Artillery configuration**: `artillery-config.yml`
- **Custom load testing**: `load-test.js`
- **Stress testing**: Concurrent users, high throughput
- **Performance metrics**: Response times, error rates

**Load Test Scenarios:**
- HTTP endpoint stress testing
- WebSocket connection floods
- Mixed protocol testing
- Memory usage under load

### 5. Security Tests (`/tests/security/`)

Vulnerability and security testing:

- **SQL Injection**: Parameter validation
- **XSS Prevention**: Output sanitization
- **Command Injection**: Input validation
- **Path Traversal**: File access controls
- **Rate Limiting**: DoS protection
- **Authentication**: Session security

### 6. Performance Benchmarks (`/tests/performance/`)

Comprehensive performance analysis:

- **CPU Operations**: Computational benchmarks
- **Memory Usage**: Leak detection and optimization
- **I/O Operations**: File system performance
- **Network Simulation**: Request/response handling
- **Terminal Operations**: ANSI processing, session management

## Mock Implementations

### TmuxStreamManager Mock (`/tests/mocks/`)

Complete mock implementation for testing:
- Session creation/destruction
- Client attachment/detachment
- Command execution simulation
- Error scenario testing

### Test Fixtures (`/tests/fixtures/`)

Comprehensive test data:
- Terminal configurations
- WebSocket events
- API requests/responses
- Security payloads
- Performance test cases

## CI/CD Integration

### GitHub Actions (`/tests/ci/github-actions.yml`)

Automated testing pipeline:
- Multi-node version testing (18, 20, 22)
- Cross-browser E2E testing
- Security scanning with Snyk
- Coverage reporting to Codecov
- Automated deployments

### Test Runner Script (`/tests/ci/test-runner.sh`)

Comprehensive CI script featuring:
- Dependency checking
- Parallel test execution
- Coverage validation
- Artifact collection
- Failure reporting

## Configuration Files

### Jest Configuration

- **jest.config.js**: Base configuration
- **jest.config.coverage.js**: Enhanced coverage settings
- **coverage-setup.js**: Coverage-specific setup

### Playwright Configuration

- **playwright.config.js**: E2E test configuration
- **global-setup.js**: Test environment preparation
- **global-teardown.js**: Cleanup procedures

## Best Practices

### Test Organization

1. **Arrange-Act-Assert**: Clear test structure
2. **Descriptive Names**: Self-documenting test cases
3. **Single Responsibility**: One behavior per test
4. **Independent Tests**: No test dependencies
5. **Comprehensive Coverage**: Edge cases and error paths

### Performance Considerations

1. **Parallel Execution**: Tests run concurrently
2. **Timeouts**: Reasonable test timeouts
3. **Resource Cleanup**: Proper teardown procedures
4. **Mock Optimization**: Efficient mock implementations
5. **Memory Management**: Leak detection and prevention

### Security Testing

1. **Input Validation**: All user inputs tested
2. **Output Sanitization**: XSS prevention
3. **Authentication**: Session security
4. **Authorization**: Access control validation
5. **Error Handling**: Information disclosure prevention

## Debugging Tests

### Environment Variables

```bash
# Enable debug output
DEBUG=true npm test

# Debug specific components
DEBUG_TMUX=true npm test

# Verbose test output
npm test -- --verbose

# Watch mode for development
npm run test:watch
```

### Test Utilities (`/tests/utils/`)

Helper functions for testing:
- Mock factories
- Test data generators
- Assertion helpers
- Setup/teardown utilities

## Continuous Improvement

### Monitoring

- Coverage trends tracking
- Performance regression detection
- Security vulnerability scanning
- Test stability monitoring

### Metrics

- Test execution time
- Coverage percentages
- Failure rates
- Performance benchmarks

## Contributing

When adding new tests:

1. Follow existing naming conventions
2. Include both positive and negative test cases
3. Add appropriate mocks and fixtures
4. Update coverage thresholds if needed
5. Document complex test scenarios

## Support

For test-related issues:

1. Check test logs in `test-reports/`
2. Review coverage reports in `coverage/`
3. Examine CI/CD pipeline outputs
4. Consult individual test README files

---

This testing suite ensures the reliability, security, and performance of the Node.js application through comprehensive automated testing.