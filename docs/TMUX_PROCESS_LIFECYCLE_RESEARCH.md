# Tmux Process Lifecycle and Exit Code Capture Research

## Executive Summary

This technical report analyzes tmux process lifecycle management, termination signal handling, and exit code capture mechanisms within the claude-flow-ui codebase. The current implementation has robust termination detection but could benefit from enhanced exit code capture using tmux format strings.

## Current Implementation Analysis

### Socket-Based Lifecycle Management

The current implementation uses a multi-layered approach for process lifecycle detection:

1. **Socket File Monitoring**: Polls for socket file existence every 100ms
2. **Pane Death Detection**: Uses `tmux list-panes -F '#{pane_dead}'` format string
3. **Session Existence Validation**: Regular `tmux has-session` checks

```javascript
// Current implementation in tmux-manager.js (lines 231-246)
const isPaneDead = await this.isPaneDead(sessionName, socketPath);
if (isPaneDead && !commandCompletedDetected) {
  commandCompletedDetected = true;
  console.log(`🔌 [DEBUG] Command completed in session ${sessionName} - pane is dead`);
  // Triggers shutdown with exit code 0
  exitCallbacks.forEach(callback => callback({ exitCode: 0, signal: 'COMMAND_COMPLETED' }));
}
```

### Exit Code Capture Limitations

**Current Issues:**
- Exit code is hardcoded to `0` when pane dies
- No actual capture of the command's exit status
- Missing signal information for process termination

## Tmux Format String Capabilities

### Available Format Variables for Exit Code Capture

Based on research and tmux manual analysis:

```bash
#{pane_dead}          # 1 if pane is dead, 0 if alive
#{pane_dead_status}   # Exit status of process in dead pane
#{pane_dead_signal}   # Exit signal of process in dead pane
#{pane_dead_time}     # Exit time of process in dead pane
```

### Critical Requirement: remain-on-exit

The `pane_dead_status` format variable **only works** when `remain-on-exit` is enabled:

```bash
# Enable remain-on-exit for a session
tmux set-window-option -t session_name remain-on-exit on

# After process exits, pane remains with status information
tmux list-panes -F '#{pane_dead} #{pane_dead_status} #{pane_dead_signal}'
```

## Signal Propagation in Tmux Sessions

### Signal Handling Hierarchy

1. **Host Process Signals** → Tmux Server
2. **Tmux Server** → Session Management
3. **Session** → Window Management
4. **Window** → Pane Process

### Socket Lifecycle Events

```javascript
// Socket termination triggers in current implementation (lines 205-214)
if (!fs.existsSync(socketPath)) {
  console.log(`🔌 [CRITICAL] Socket file deleted for session ${sessionName}`);
  isActive = false;
  this.activeSessions.delete(sessionName);
  exitCallbacks.forEach(callback => callback({
    exitCode: 0,
    signal: 'SOCKET_TERMINATED'
  }));
  process.exit(0);
}
```

## Recommended Implementation Improvements

### 1. Enhanced Exit Code Capture

**Implementation Strategy:**

```javascript
async function captureExitCode(sessionName, socketPath) {
  return new Promise((resolve) => {
    // First check if pane is dead
    const tmux = spawn('tmux', [
      '-S', socketPath,
      'list-panes',
      '-t', sessionName,
      '-F', '#{pane_dead}:#{pane_dead_status}:#{pane_dead_signal}'
    ], { stdio: 'pipe' });

    let output = '';
    tmux.stdout.on('data', (data) => {
      output += data.toString();
    });

    tmux.on('exit', (code) => {
      if (code === 0 && output.trim()) {
        const [isDead, exitStatus, exitSignal] = output.trim().split(':');
        resolve({
          isDead: isDead === '1',
          exitCode: exitStatus ? parseInt(exitStatus, 10) : null,
          signal: exitSignal || null
        });
      } else {
        resolve({ isDead: false, exitCode: null, signal: null });
      }
    });

    tmux.on('error', () => {
      resolve({ isDead: false, exitCode: null, signal: null });
    });
  });
}
```

### 2. Conditional remain-on-exit Management

**Strategy**: Enable `remain-on-exit` temporarily when exit code capture is needed:

```javascript
async function enableExitCapture(sessionName, socketPath) {
  // Enable remain-on-exit for this session
  await execAsync(`tmux -S "${socketPath}" set-window-option -t "${sessionName}" remain-on-exit on`);
}

async function disableExitCapture(sessionName, socketPath) {
  // Disable remain-on-exit and kill the dead pane
  await execAsync(`tmux -S "${socketPath}" set-window-option -t "${sessionName}" remain-on-exit off`);
  await execAsync(`tmux -S "${socketPath}" respawn-pane -t "${sessionName}" -k`);
}
```

### 3. Improved Termination Detection

**Enhanced Implementation:**

```javascript
async function detectTermination(sessionName, socketPath) {
  // 1. Check socket existence (fastest)
  if (!fs.existsSync(socketPath)) {
    return {
      reason: 'SOCKET_TERMINATED',
      exitCode: null,
      signal: 'SOCKET_DELETED'
    };
  }

  // 2. Check session existence
  const sessionExists = await this.sessionExists(sessionName, socketPath);
  if (!sessionExists) {
    return {
      reason: 'SESSION_TERMINATED',
      exitCode: 0,
      signal: null
    };
  }

  // 3. Check pane status with exit code capture
  const paneStatus = await this.captureExitCode(sessionName, socketPath);
  if (paneStatus.isDead) {
    return {
      reason: 'COMMAND_COMPLETED',
      exitCode: paneStatus.exitCode,
      signal: paneStatus.signal
    };
  }

  return { reason: 'ACTIVE', exitCode: null, signal: null };
}
```

## Implementation Considerations

### 1. Performance Impact

- **Current**: 100ms polling interval
- **Recommended**: Keep same interval, enhance data capture
- **Socket checks**: Fastest (~1ms)
- **Format string queries**: Medium (~10-50ms)

### 2. Compatibility Issues

**remain-on-exit Considerations:**
- Must be enabled before command execution completes
- Creates "dead pane" display that shows exit status
- Requires manual cleanup of dead panes

### 3. Error Handling

```javascript
// Robust error handling for format string queries
try {
  const exitInfo = await this.captureExitCode(sessionName, socketPath);
  if (exitInfo.isDead) {
    // Process actual exit code
    this.handleCommandExit(exitInfo.exitCode, exitInfo.signal);
  }
} catch (error) {
  // Fallback to current behavior
  console.warn('Exit code capture failed, using fallback detection');
  const isPaneDead = await this.isPaneDead(sessionName, socketPath);
  if (isPaneDead) {
    this.handleCommandExit(0, 'UNKNOWN');
  }
}
```

## Socket Lifecycle Best Practices

### 1. Socket Path Management

**Current Implementation Strengths:**
- Secure temporary directory usage
- Path length validation (104-108 char Unix socket limit)
- Collision detection and auto-increment

### 2. Cleanup Strategies

**Current Cleanup Process:**
1. Stop polling intervals
2. Notify WebSocket clients
3. Kill tmux sessions
4. Remove socket files
5. Exit application

**Recommended Enhancement:**
```javascript
async function enhancedCleanup(sessionName, exitCode, signal) {
  // 1. Capture final output if needed
  const finalOutput = await this.capturePane(sessionName, socketPath)
    .catch(() => ''); // Ignore errors during cleanup

  // 2. Clean up remain-on-exit if enabled
  await this.disableExitCapture(sessionName, socketPath)
    .catch(() => {}); // Ignore errors

  // 3. Standard cleanup process
  await this.killSession(sessionName);
  this.cleanupSocket(socketPath);

  // 4. Notify with actual exit information
  exitCallbacks.forEach(callback => callback({
    exitCode,
    signal,
    finalOutput
  }));
}
```

## Testing Strategies

### 1. Exit Code Validation Tests

```javascript
// Test different exit codes
describe('Exit Code Capture', () => {
  test('captures successful command exit (code 0)', async () => {
    const session = await tmux.createSession('test', 'echo "success"');
    const result = await waitForExit(session);
    expect(result.exitCode).toBe(0);
  });

  test('captures failed command exit (code 1)', async () => {
    const session = await tmux.createSession('test', 'exit 1');
    const result = await waitForExit(session);
    expect(result.exitCode).toBe(1);
  });

  test('captures signal termination', async () => {
    const session = await tmux.createSession('test', 'sleep 10');
    await sendSignal(session, 'SIGTERM');
    const result = await waitForExit(session);
    expect(result.signal).toBe('SIGTERM');
  });
});
```

### 2. Socket Lifecycle Tests

```javascript
describe('Socket Lifecycle', () => {
  test('detects socket deletion', async () => {
    const session = await tmux.createSession('test', 'sleep 30');
    const socketPath = session.socketPath;

    // Manually delete socket
    fs.unlinkSync(socketPath);

    const result = await waitForTermination(session);
    expect(result.reason).toBe('SOCKET_TERMINATED');
  });
});
```

## Conclusion

The current tmux lifecycle management in claude-flow-ui is robust but can be enhanced with proper exit code capture using tmux format strings. The key improvements would be:

1. **Enable remain-on-exit temporarily** for exit code capture
2. **Use pane_dead_status format strings** to get actual exit codes
3. **Enhance termination detection** with proper exit information
4. **Maintain backward compatibility** with fallback mechanisms

These improvements would provide accurate exit code reporting to the frontend while maintaining the reliable termination detection already in place.

## Files Analyzed

- `/src/lib/tmux-manager.js` - Core tmux session management
- `/src/lib/tmux-stream-manager.js` - Streaming interface
- `/docs/TMUX_TERMINATION_DETECTION.md` - Current documentation
- `/docs/TMUX_SESSION_VALIDATION_FIX.md` - Session management fixes

## Technical References

- Tmux Manual: Format strings and pane lifecycle variables
- Unix socket limitations: 104-108 character path limits
- Signal propagation: SIGTERM, SIGINT, SIGHUP handling
- Process lifecycle: spawn → run → exit → cleanup