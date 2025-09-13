# Comprehensive Test Plan for Claude Flow UI Service

## Overview

This test plan covers comprehensive testing of the Claude Flow UI service, including service launch with claude-flow arguments, tmux session management, fallback modes, and full command validation. The tests are designed to ensure robust operation across different scenarios and environments.

## Test Categories

### 1. Service Launch Tests

#### 1.1 Basic Service Launch
```bash
# Test basic service startup
npx @liamhelmer/claude-flow-ui
# Expected: Service starts on default port 8080, creates tmux session if available
```

#### 1.2 Service Launch with Custom Port
```bash
# Test custom port specification
npx @liamhelmer/claude-flow-ui -- --port 9090
# Expected: Service starts on port 9090
```

#### 1.3 Service Launch with Terminal Size
```bash
# Test terminal size configuration
npx @liamhelmer/claude-flow-ui -- --terminal-size 120x40
# Expected: Terminal created with 120 columns, 40 rows
```

#### 1.4 Service Launch with Claude Flow Arguments
```bash
# Test with basic claude-flow command
npx @liamhelmer/claude-flow-ui -- --port 8888 --terminal-size 120x40 swarm 'await further instructions' --claude

# Test with different claude-flow modes
npx @liamhelmer/claude-flow-ui -- --port 8889 sparc modes
npx @liamhelmer/claude-flow-ui -- --port 8890 swarm init --topology mesh
npx @liamhelmer/claude-flow-ui -- --port 8891 tdd "create a simple function"
```

### 2. Tmux Session Creation and Management Tests

#### 2.1 Tmux Session Verification
```javascript
// Test tmux session creation with npx claude-flow
describe('Tmux Session Creation', () => {
  test('should create tmux session with claude-flow arguments', async () => {
    const server = await startServer(['--port', '8888', 'swarm', 'await further instructions', '--claude']);
    
    // Wait for session creation
    await waitForCondition(() => server.hasActiveSession(), 10000);
    
    // Verify session exists
    const sessionId = server.getGlobalSessionId();
    expect(sessionId).toBeTruthy();
    expect(sessionId).toMatch(/^claude-flow-ui-\d+$/);
    
    // Verify tmux session exists
    const tmuxSessionExists = await checkTmuxSession(sessionId);
    expect(tmuxSessionExists).toBe(true);
  });
});
```

#### 2.2 Tmux Session Command Execution
```javascript
test('should execute claude-flow commands in tmux session', async () => {
  const server = await startServer(['--port', '8888', 'sparc', 'modes']);
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Wait for initial output
  const output = await waitForTerminalOutput(client, 5000);
  
  // Verify claude-flow command executed
  expect(output).toContain('sparc');
  expect(output).toMatch(/Available modes|modes/i);
});
```

#### 2.3 Tmux Session Persistence
```javascript
test('should maintain tmux session across reconnections', async () => {
  const server = await startServer(['--port', '8888']);
  let client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Send command to create persistent state
  const marker = `test-marker-${Date.now()}`;
  await sendTerminalInput(client, `echo "${marker}"\n`);
  
  // Verify marker appears
  let output = await waitForTerminalOutput(client, 2000);
  expect(output).toContain(marker);
  
  // Disconnect and reconnect
  client.close();
  await wait(1000);
  client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Verify session content is restored
  output = await waitForTerminalOutput(client, 3000);
  expect(output).toContain(marker);
});
```

### 3. Fallback Mode Tests (Without Tmux)

#### 3.1 Fallback Mode Detection
```javascript
describe('Fallback Mode Tests', () => {
  beforeAll(() => {
    // Mock tmux as unavailable
    jest.mock('child_process', () => ({
      ...jest.requireActual('child_process'),
      spawn: jest.fn((command, args) => {
        if (command === 'tmux') {
          const mockProcess = {
            on: jest.fn((event, callback) => {
              if (event === 'error') {
                callback(new Error('Command not found'));
              }
            })
          };
          return mockProcess;
        }
        return jest.requireActual('child_process').spawn(command, args);
      })
    }));
  });

  test('should start in fallback mode when tmux unavailable', async () => {
    const server = await startServer(['--port', '8888']);
    
    // Verify fallback mode
    expect(server.useTmux).toBe(false);
    expect(server.globalTerminalProcess).toBeTruthy();
    expect(server.globalTerminalProcess.pid).toBeTruthy();
  });
});
```

#### 3.2 Fallback Mode Terminal Operations
```javascript
test('should handle terminal operations in fallback mode', async () => {
  const server = await startServerWithoutTmux(['--port', '8888']);
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Test input/output
  await sendTerminalInput(client, 'echo "fallback test"\n');
  const output = await waitForTerminalOutput(client, 2000);
  
  expect(output).toContain('fallback test');
});
```

#### 3.3 Fallback Mode with Claude Flow Arguments
```javascript
test('should execute claude-flow in fallback mode', async () => {
  const server = await startServerWithoutTmux(['--port', '8888', 'sparc', 'modes']);
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Verify claude-flow executed directly
  const output = await waitForTerminalOutput(client, 5000);
  expect(output).toContain('sparc');
});
```

### 4. Full Command Validation Tests

#### 4.1 Complete Command Syntax Validation
```javascript
describe('Full Command Validation', () => {
  test('should validate complete npx command syntax', async () => {
    const fullCommand = 'npx @liamhelmer/claude-flow-ui -- --port 8888 --terminal-size 120x40 swarm \'await further instructions\' --claude';
    
    const { port, cols, rows, claudeArgs } = parseCommandLine(fullCommand);
    
    expect(port).toBe(8888);
    expect(cols).toBe(120);
    expect(rows).toBe(40);
    expect(claudeArgs).toEqual(['swarm', 'await further instructions', '--claude']);
  });
});
```

#### 4.2 Command Argument Processing
```javascript
test('should process all command line arguments correctly', async () => {
  const testCases = [
    {
      args: ['--port', '8888', '--terminal-size', '120x40', 'swarm', 'await further instructions', '--claude'],
      expected: { port: 8888, cols: 120, rows: 40, claudeArgs: ['swarm', 'await further instructions', '--claude'] }
    },
    {
      args: ['--port', '9090', 'sparc', 'modes'],
      expected: { port: 9090, cols: 120, rows: 40, claudeArgs: ['sparc', 'modes'] }
    },
    {
      args: ['--terminal-size', '80x24', 'tdd', '"create a function"'],
      expected: { port: 8080, cols: 80, rows: 24, claudeArgs: ['tdd', '"create a function"'] }
    }
  ];

  for (const testCase of testCases) {
    const result = parseArgs(testCase.args);
    expect(result).toEqual(testCase.expected);
  }
});
```

### 5. Integration Tests

#### 5.1 End-to-End Service Workflow
```javascript
test('should complete full service workflow', async () => {
  // Start service with claude-flow
  const server = await startServer([
    '--port', '8888', 
    '--terminal-size', '120x40', 
    'swarm', 'await further instructions', '--claude'
  ]);
  
  // Connect client
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Verify configuration
  const config = await getTerminalConfig(client);
  expect(config.cols).toBe(120);
  expect(config.rows).toBe(40);
  
  // Verify claude-flow execution
  const output = await waitForTerminalOutput(client, 10000);
  expect(output).toMatch(/swarm|claude|instructions/i);
  
  // Test interaction
  await sendTerminalInput(client, 'help\n');
  const helpOutput = await waitForTerminalOutput(client, 3000);
  expect(helpOutput).toBeTruthy();
  
  await server.stop();
});
```

#### 5.2 Multi-Client Session Sharing
```javascript
test('should share session between multiple clients', async () => {
  const server = await startServer(['--port', '8888']);
  
  // Connect first client
  const client1 = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Send command from first client
  const marker = `multi-client-${Date.now()}`;
  await sendTerminalInput(client1, `echo "${marker}"\n`);
  
  // Connect second client
  const client2 = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Verify second client sees first client's output
  const output = await waitForTerminalOutput(client2, 3000);
  expect(output).toContain(marker);
});
```

### 6. Error Handling and Resilience Tests

#### 6.1 Service Recovery Tests
```javascript
test('should recover from tmux session failures', async () => {
  const server = await startServer(['--port', '8888']);
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Simulate tmux session failure
  await killTmuxSession(server.getGlobalSessionId());
  
  // Verify service continues (fallback to direct process)
  await sendTerminalInput(client, 'echo "recovery test"\n');
  const output = await waitForTerminalOutput(client, 5000);
  
  expect(output).toContain('recovery test');
});
```

#### 6.2 Network Disconnection Handling
```javascript
test('should handle client disconnections gracefully', async () => {
  const server = await startServer(['--port', '8888']);
  let client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Send command
  await sendTerminalInput(client, 'echo "before disconnect"\n');
  
  // Disconnect client
  client.close();
  await wait(2000);
  
  // Reconnect
  client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Verify session state preserved
  const output = await waitForTerminalOutput(client, 3000);
  expect(output).toContain('before disconnect');
});
```

### 7. Performance and Stress Tests

#### 7.1 High-Load Terminal Operations
```javascript
test('should handle high-frequency terminal operations', async () => {
  const server = await startServer(['--port', '8888']);
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  // Send rapid commands
  const commands = Array.from({length: 50}, (_, i) => `echo "command ${i}"`);
  
  for (const command of commands) {
    await sendTerminalInput(client, command + '\n');
    await wait(10); // Small delay
  }
  
  // Verify all commands processed
  const output = await waitForTerminalOutput(client, 10000);
  expect(output).toContain('command 0');
  expect(output).toContain('command 49');
});
```

#### 7.2 Memory Leak Detection
```javascript
test('should not leak memory during extended operation', async () => {
  const server = await startServer(['--port', '8888']);
  const client = await connectWebSocketClient(`ws://localhost:8888/api/ws`);
  
  const initialMemory = process.memoryUsage().heapUsed;
  
  // Perform many operations
  for (let i = 0; i < 1000; i++) {
    await sendTerminalInput(client, `echo "test ${i}"\n`);
    if (i % 100 === 0) {
      await wait(100); // Periodic pause
    }
  }
  
  // Force garbage collection and check memory
  global.gc && global.gc();
  const finalMemory = process.memoryUsage().heapUsed;
  const memoryIncrease = finalMemory - initialMemory;
  
  // Memory increase should be reasonable (less than 50MB)
  expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
});
```

## Test Utilities and Helpers

### Server Management Utilities
```javascript
// Test helper functions
async function startServer(args = []) {
  const port = extractPort(args) || (8000 + Math.floor(Math.random() * 1000));
  const serverProcess = spawn('node', ['unified-server.js', ...args], {
    env: { ...process.env, PORT: port },
    stdio: 'pipe'
  });
  
  await waitForServerReady(port);
  return new ServerWrapper(serverProcess, port);
}

async function startServerWithoutTmux(args = []) {
  // Mock environment without tmux
  const port = extractPort(args) || (8000 + Math.floor(Math.random() * 1000));
  const serverProcess = spawn('node', ['unified-server.js', ...args], {
    env: { 
      ...process.env, 
      PORT: port,
      PATH: process.env.PATH.replace(/tmux/g, '') // Remove tmux from PATH
    },
    stdio: 'pipe'
  });
  
  await waitForServerReady(port);
  return new ServerWrapper(serverProcess, port);
}

class ServerWrapper {
  constructor(process, port) {
    this.process = process;
    this.port = port;
  }
  
  async stop() {
    this.process.kill('SIGTERM');
    await new Promise(resolve => {
      this.process.on('exit', resolve);
      setTimeout(() => {
        this.process.kill('SIGKILL');
        resolve();
      }, 5000);
    });
  }
  
  getGlobalSessionId() {
    // Implementation to extract session ID from server state
  }
  
  hasActiveSession() {
    // Implementation to check if server has active session
  }
}
```

### WebSocket Client Utilities
```javascript
async function connectWebSocketClient(url) {
  const WebSocket = require('ws');
  const client = new WebSocket(url);
  
  await new Promise((resolve, reject) => {
    client.on('open', resolve);
    client.on('error', reject);
  });
  
  return new WebSocketClientWrapper(client);
}

class WebSocketClientWrapper {
  constructor(ws) {
    this.ws = ws;
    this.messages = [];
    this.ws.on('message', (data) => {
      const message = JSON.parse(data);
      this.messages.push(message);
    });
  }
  
  async sendTerminalInput(data) {
    this.ws.send(JSON.stringify({
      type: 'data',
      sessionId: 'test-session',
      data: data
    }));
  }
  
  async waitForTerminalOutput(timeout = 5000) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      const terminalData = this.messages
        .filter(msg => msg.type === 'terminal-data')
        .map(msg => msg.data)
        .join('');
      
      if (terminalData) {
        return terminalData;
      }
      
      await wait(100);
    }
    throw new Error('Timeout waiting for terminal output');
  }
  
  close() {
    this.ws.close();
  }
}
```

### Command Line Parsing Utilities
```javascript
function parseArgs(args) {
  let customPort = null;
  let terminalCols = 120;
  let terminalRows = 40;
  let claudeFlowArgs = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && i + 1 < args.length) {
      customPort = parseInt(args[i + 1]);
      i++; // Skip next arg
    } else if (args[i] === '--terminal-size' && i + 1 < args.length) {
      const size = args[i + 1].split('x');
      if (size.length === 2) {
        terminalCols = parseInt(size[0]) || 120;
        terminalRows = parseInt(size[1]) || 40;
      }
      i++; // Skip next arg
    } else {
      // Pass remaining args to claude-flow
      claudeFlowArgs.push(args[i]);
    }
  }

  return {
    port: customPort || 8080,
    cols: terminalCols,
    rows: terminalRows,
    claudeArgs: claudeFlowArgs
  };
}
```

## Test Execution Commands

### Running Individual Test Suites
```bash
# Run service launch tests
npm test -- --testNamePattern="Service Launch"

# Run tmux integration tests  
npm test -- --testNamePattern="Tmux"

# Run fallback mode tests
npm test -- --testNamePattern="Fallback"

# Run full command validation tests
npm test -- --testNamePattern="Command Validation"

# Run integration tests
npm test -- --testNamePattern="Integration"

# Run performance tests
npm test -- --testNamePattern="Performance"
```

### Running All Service Tests
```bash
# Run complete service test suite
npm test tests/service/

# Run with coverage
npm run test:coverage -- tests/service/

# Run in CI mode
npm run test:ci -- tests/service/
```

### Debug Mode Testing
```bash
# Run tests with debug output
DEBUG_TMUX=true npm test

# Run tests with verbose logging
NODE_ENV=test DEBUG_TESTS=true npm test -- --verbose
```

## Expected Behaviors

### Service Launch Expected Behaviors

1. **Basic Launch**: Service starts on default port 8080, creates tmux session if available
2. **Custom Port**: Service starts on specified port
3. **Terminal Size**: Terminal created with specified dimensions
4. **Claude Flow Args**: Arguments passed correctly to claude-flow command in tmux session

### Tmux Session Expected Behaviors

1. **Session Creation**: Unique tmux session created with proper socket path
2. **Command Execution**: Claude-flow commands execute within tmux session
3. **Session Persistence**: Session maintains state across client disconnections
4. **Multi-client Support**: Multiple clients can connect to same session

### Fallback Mode Expected Behaviors

1. **Automatic Detection**: Service detects tmux unavailability and switches to fallback
2. **Direct Process**: Uses node-pty for direct terminal process management
3. **Feature Parity**: All terminal operations work in fallback mode
4. **Claude Flow Support**: Claude-flow commands execute directly without tmux

### Error Handling Expected Behaviors

1. **Graceful Degradation**: Service continues operating when tmux fails
2. **Connection Recovery**: Clients can reconnect and resume sessions
3. **Resource Cleanup**: Proper cleanup of processes and socket files
4. **Error Reporting**: Clear error messages and appropriate status codes

## Test Data and Fixtures

### Test Commands
```javascript
const TEST_COMMANDS = {
  basic: ['echo "test"', 'pwd', 'ls -la'],
  claudeFlow: [
    'sparc modes',
    'swarm init --topology mesh',
    'tdd "create a simple function"',
    'swarm "await further instructions" --claude'
  ],
  interactive: ['vi test.txt', 'top', 'htop'],
  longRunning: ['sleep 5', 'find / -name "*.txt" 2>/dev/null']
};
```

### Test Configurations
```javascript
const TEST_CONFIGS = {
  ports: [8080, 8888, 9090, 3000],
  terminalSizes: [
    { cols: 80, rows: 24 },
    { cols: 120, rows: 40 },
    { cols: 132, rows: 50 }
  ],
  environments: ['development', 'production', 'test']
};
```

This comprehensive test plan ensures robust validation of the Claude Flow UI service across all operational scenarios and provides clear documentation of expected behaviors and test commands.