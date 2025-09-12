# Claude UI Tmux Integration Test Suite

This comprehensive test suite validates the transition from buffer-based terminal output to tmux-based session management for the Claude Flow UI.

## 🧪 Test Architecture

The test suite follows a pyramid structure with comprehensive coverage across multiple layers:

### Test Layers

```
    E2E Tests (Browser/Playwright)
    ├── Full workflow testing
    ├── User interaction scenarios
    └── Claude Flow integration validation

  Integration Tests (WebSocket + Tmux)
  ├── WebSocket to tmux communication
  ├── Multi-user session sharing
  ├── Session persistence testing
  └── Real-time data streaming

Unit Tests (Session Management)
├── Tmux session lifecycle
├── Socket file management
├── Command execution
└── Error handling
```

## 📁 Test Organization

```
tests/
├── setup.ts                    # Global test configuration & mocks
├── unit/
│   └── tmux-session-manager.test.ts   # Core session management
├── integration/
│   └── tmux-websocket.test.ts         # WebSocket integration
├── e2e/
│   └── tmux-claude-flow.test.ts       # End-to-end scenarios
├── performance/
│   └── tmux-performance.test.ts       # Performance benchmarks
├── security/
│   └── tmux-security.test.ts          # Security validation
├── regression/
│   └── tmux-regression.test.ts        # Backward compatibility
├── fixtures/
│   └── tmux-fixtures.ts               # Test data & scenarios
└── README.md                          # This documentation
```

## 🚀 Running Tests

### Prerequisites

```bash
# Install dependencies
npm install

# Ensure tmux is available (for integration tests)
# Ubuntu/Debian: apt-get install tmux
# macOS: brew install tmux
# Windows: Use WSL with tmux installed
```

### Test Commands

```bash
# Run all tests
npm test

# Run specific test categories
npm test -- --testNamePattern="Unit Tests"
npm test -- --testNamePattern="Integration"
npm test -- --testNamePattern="E2E"
npm test -- --testNamePattern="Performance"
npm test -- --testNamePattern="Security"

# Run with coverage
npm run test:coverage

# Watch mode for development
npm run test:watch

# CI mode (no watch, coverage)
npm run test:ci
```

### Test-Specific Commands

```bash
# Run only tmux-related tests
npm test -- tests/unit/tmux-session-manager.test.ts
npm test -- tests/integration/tmux-websocket.test.ts

# Run performance tests with extended timeout
npm test -- tests/performance/tmux-performance.test.ts --testTimeout=60000

# Run E2E tests with Playwright
npx playwright test tests/e2e/
```

## 📊 Test Coverage Requirements

### Coverage Targets
- **Statements**: >80%
- **Branches**: >75%
- **Functions**: >80%
- **Lines**: >80%

### Critical Components
- TmuxSessionManager: >90% coverage
- WebSocket integration: >85% coverage
- Session persistence: >90% coverage
- Error handling: >95% coverage

## 🔧 Mock Infrastructure

### Tmux Mocking
The test suite includes comprehensive tmux mocking to enable testing without requiring a real tmux server:

```typescript
// Access global tmux mock
global.mockTmux.sessions        // Mock session storage
global.mockTmux.commands        // Command execution log
global.mockTmux.sockets         // Socket file simulation

// Utility functions
global.tmuxTestUtils.createMockSession()
global.tmuxTestUtils.simulateSessionOutput()
global.tmuxTestUtils.clearMockTmux()
```

### WebSocket Mocking
Socket.IO and WebSocket connections are mocked for isolated testing:

```typescript
// Mock WebSocket client
const mockSocket = {
  on: jest.fn(),
  emit: jest.fn(),
  connected: true
};
```

### File System Mocking
File operations for socket files and configurations are mocked:

```typescript
// Mock fs operations
jest.mock('fs');
(fs.existsSync as jest.Mock).mockReturnValue(true);
```

## 🎯 Test Scenarios

### Unit Tests - TmuxSessionManager

#### Session Lifecycle
- ✅ Create new tmux session with proper configuration
- ✅ Connect to existing session
- ✅ Kill session and cleanup socket files
- ✅ List active sessions with metadata
- ✅ Validate session existence

#### Socket Management
- ✅ Generate secure socket paths
- ✅ Validate socket file permissions (600)
- ✅ Cleanup orphaned socket files
- ✅ Handle socket path traversal attacks

#### Command Execution
- ✅ Send keys to tmux session
- ✅ Capture pane content
- ✅ Resize session dimensions
- ✅ Handle command timeouts

#### Error Handling
- ✅ Tmux not installed scenarios
- ✅ Permission denied errors
- ✅ Invalid session IDs
- ✅ Network/socket errors

### Integration Tests - WebSocket Communication

#### Session Management via WebSocket
- ✅ Create session through WebSocket messages
- ✅ Attach to existing sessions
- ✅ List all available sessions
- ✅ Handle session creation errors

#### Data Streaming
- ✅ Real-time input streaming to tmux
- ✅ Output streaming from tmux to clients
- ✅ Binary data handling (ANSI codes)
- ✅ High-frequency data without memory leaks

#### Multi-User Support
- ✅ Multiple clients on same session
- ✅ Broadcast input to all connected clients
- ✅ Concurrent resize requests
- ✅ Session isolation between users

#### Persistence & Reconnection
- ✅ Session survives client disconnections
- ✅ Reconnect with full history replay
- ✅ Handle dead session reconnection attempts
- ✅ Socket file validation on reconnect

### E2E Tests - Full User Workflow

#### UI Integration
- ✅ Load Claude UI with tmux terminal
- ✅ WebSocket connection establishment
- ✅ Terminal rendering and interaction
- ✅ Session creation through UI

#### Claude Flow Integration
- ✅ Execute claude-flow commands via tmux
- ✅ Support for swarm operations
- ✅ Long-running TDD processes
- ✅ Process interruption (Ctrl+C)

#### Session Management
- ✅ Session persistence across page refreshes
- ✅ Multiple windows/panes in tmux
- ✅ Terminal resizing
- ✅ History and scrollback

#### Error Scenarios
- ✅ Network interruption handling
- ✅ Session cleanup on page close
- ✅ Graceful degradation

### Performance Tests

#### Benchmarks
- ✅ Session creation time (<2s per session)
- ✅ Concurrent session handling (50+ sessions)
- ✅ High-frequency data throughput (>1000 msgs/sec)
- ✅ Memory usage stability (<100MB increase)

#### Comparative Analysis
- ✅ Tmux vs buffer output capture performance
- ✅ Session persistence overhead comparison
- ✅ WebSocket connection scaling

#### Stress Testing
- ✅ Extreme session counts (100+ sessions)
- ✅ Large output buffer handling (10K+ lines)
- ✅ Extended runtime stability

### Security Tests

#### Socket Security
- ✅ Socket file permissions (600 only)
- ✅ Owner validation
- ✅ Path traversal prevention
- ✅ Unauthorized access prevention

#### Command Injection Prevention
- ✅ Session ID sanitization
- ✅ Command parameter escaping
- ✅ Shell metacharacter filtering
- ✅ Input validation

#### WebSocket Security
- ✅ Message format validation
- ✅ Rate limiting implementation
- ✅ Session hijacking prevention
- ✅ Resource access control

#### Data Privacy
- ✅ Session data isolation
- ✅ Sensitive data cleanup
- ✅ Error message sanitization
- ✅ Audit logging without secrets

### Regression Tests

#### Backward Compatibility
- ✅ Existing API compatibility
- ✅ Message format consistency
- ✅ Configuration file compatibility
- ✅ Environment variable handling

#### Output Consistency
- ✅ Buffer vs tmux output formatting
- ✅ ANSI color code preservation
- ✅ Unicode character handling
- ✅ Special character escaping

#### Performance Regression
- ✅ Session creation time maintenance
- ✅ Memory usage stability
- ✅ Error handling consistency

## 🔍 Test Data & Fixtures

### Fixture Categories
- **Simple Sessions**: Basic single-pane sessions
- **Complex Sessions**: Multi-window, multi-pane scenarios
- **Long Output**: Sessions with extensive scrollback
- **Concurrent Sessions**: Multiple simultaneous sessions
- **Crashed Sessions**: Error and recovery scenarios

### Generated Test Data
- Command history files
- Sample tmux configurations
- Session state snapshots
- Performance benchmarks
- Security test vectors

## 🚨 Test Failures & Debugging

### Common Issues
1. **Mock Environment**: Many tests run in mock mode - failures may indicate test logic issues rather than implementation problems
2. **Timing Issues**: Use appropriate timeouts for async operations
3. **Cleanup**: Ensure test cleanup to prevent state leakage
4. **Platform Differences**: Some tests may behave differently on Windows/macOS/Linux

### Debugging Tips
```bash
# Run with verbose output
npm test -- --verbose

# Debug specific test
npm test -- --testNamePattern="specific test name" --verbose

# Enable console logging in tests
DEBUG=* npm test

# Check mock state during test failures
console.log('Mock state:', global.mockTmux.commands);
```

### CI/CD Considerations
- Tests are designed to run in headless environments
- No real tmux server required (mocked)
- WebSocket tests use ephemeral ports
- E2E tests include browser automation setup

## 📈 Metrics & Reporting

### Test Metrics Tracked
- Execution time per test suite
- Memory usage during test runs
- Coverage percentages by component
- Performance benchmark results
- Security test compliance scores

### Reports Generated
- Jest coverage reports (HTML, LCOV)
- Performance benchmark results
- Security scan summaries
- Regression test comparisons

## 🔄 Continuous Integration

### GitHub Actions Integration
```yaml
- name: Run Tmux Tests
  run: |
    npm ci
    npm run test:ci
    npm run test:coverage
    
- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage/lcov.info
```

### Pre-commit Hooks
- Run unit tests before commits
- Validate test coverage thresholds
- Security test execution
- Performance regression checks

## 📚 Additional Resources

- [Tmux Documentation](https://github.com/tmux/tmux/wiki)
- [Socket.IO Testing Guide](https://socket.io/docs/v4/testing/)
- [Jest Testing Framework](https://jestjs.io/docs/getting-started)
- [Playwright E2E Testing](https://playwright.dev/)
- [Claude Flow Documentation](https://github.com/ruvnet/claude-flow)

---

## 🤝 Contributing to Tests

When adding new tmux integration features, ensure you:

1. **Add unit tests** for core functionality
2. **Include integration tests** for WebSocket communication
3. **Update E2E tests** for user-facing changes
4. **Add performance tests** for new operations
5. **Include security tests** for new endpoints
6. **Update regression tests** for API changes

### Test Writing Guidelines

1. **Descriptive Names**: Use clear test descriptions
2. **Arrange-Act-Assert**: Follow AAA pattern
3. **Isolated Tests**: No dependencies between tests
4. **Mock Appropriately**: Use fixtures and mocks consistently
5. **Edge Cases**: Test error conditions and boundary cases
6. **Performance**: Include timing assertions where relevant
7. **Security**: Test for common vulnerabilities

The test suite is designed to be comprehensive, maintainable, and reliable. When in doubt, err on the side of more testing rather than less.