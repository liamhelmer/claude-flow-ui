# Tmux Termination Test Plan

## Overview
This document outlines comprehensive test scenarios for validating tmux session termination handling, exit code capture, and graceful shutdown behavior in the Claude Flow UI application.

## Test Categories

### 1. Normal Command Completion (Exit Code 0)

#### Test Scenario: Successful Command Execution
**Description**: Test that commands completing successfully return exit code 0

**Setup Steps**:
1. Start tmux session with session ID `test-success`
2. Execute simple command: `echo "Hello World"`
3. Wait for command completion
4. Monitor session termination

**Expected Behavior**:
- Command executes successfully
- Exit code 0 is captured and logged
- Session terminates gracefully
- Socket file is cleaned up automatically

**Verification Steps**:
1. Check server console for exit code log: `Session test-success exited with code: 0`
2. Verify socket file removal: `ls /tmp/tmux-*/test-success`
3. Confirm session is not listed in `tmux ls`

**Cleanup Verification**:
- No orphaned tmux sessions remain
- No socket files persist in `/tmp/tmux-*`
- Server logs show proper cleanup

---

### 2. Command Failure (Non-Zero Exit Codes)

#### Test Scenario 2.1: Command Not Found (Exit Code 127)
**Description**: Test handling of commands that don't exist

**Setup Steps**:
1. Start tmux session with session ID `test-not-found`
2. Execute non-existent command: `nonexistent-command`
3. Monitor session behavior

**Expected Behavior**:
- Command fails immediately
- Exit code 127 is captured and logged
- Error message is displayed in output
- Session terminates with proper cleanup

**Verification Steps**:
1. Check console log: `Session test-not-found exited with code: 127`
2. Verify error output contains "command not found"
3. Confirm session cleanup

#### Test Scenario 2.2: Script Failure (Exit Code 1)
**Description**: Test handling of scripts that exit with failure codes

**Setup Steps**:
1. Start tmux session with session ID `test-failure`
2. Execute failing command: `exit 1`
3. Monitor termination

**Expected Behavior**:
- Command exits with code 1
- Exit code is properly captured
- Session terminates cleanly

**Verification Steps**:
1. Check console log: `Session test-failure exited with code: 1`
2. Verify session cleanup

#### Test Scenario 2.3: Interrupted Command (Exit Code 130)
**Description**: Test handling of commands interrupted by SIGINT

**Setup Steps**:
1. Start tmux session with session ID `test-interrupt`
2. Execute long-running command: `sleep 60`
3. Send SIGINT to the process

**Expected Behavior**:
- Command is interrupted
- Exit code 130 (128 + SIGINT) is captured
- Session terminates properly

**Verification Steps**:
1. Check console log: `Session test-interrupt exited with code: 130`
2. Verify proper cleanup

---

### 3. Socket File Deletion

#### Test Scenario 3.1: Manual Socket Deletion
**Description**: Test behavior when socket file is manually deleted

**Setup Steps**:
1. Start tmux session with session ID `test-socket-delete`
2. Execute long-running command: `sleep 30`
3. Manually delete socket file: `rm /tmp/tmux-*/test-socket-delete`
4. Wait for detection

**Expected Behavior**:
- Session becomes unreachable
- Manager detects socket deletion
- Session is marked as terminated
- Cleanup procedures are executed

**Verification Steps**:
1. Check console for socket deletion detection
2. Verify session is removed from active sessions list
3. Confirm no orphaned processes remain

#### Test Scenario 3.2: Socket Directory Removal
**Description**: Test handling when entire tmux socket directory is removed

**Setup Steps**:
1. Start multiple sessions: `test-multi-1`, `test-multi-2`
2. Remove entire socket directory: `rm -rf /tmp/tmux-*`
3. Monitor all session handling

**Expected Behavior**:
- All sessions become unreachable
- Manager detects directory removal
- All sessions are properly cleaned up
- Server continues operating normally

**Verification Steps**:
1. Check console logs for all session terminations
2. Verify session list is empty
3. Confirm server stability

---

### 4. Manual Tmux Session Kill

#### Test Scenario 4.1: Kill Session Command
**Description**: Test handling of `tmux kill-session` command

**Setup Steps**:
1. Start tmux session with session ID `test-manual-kill`
2. Execute long-running command: `sleep 60`
3. Execute: `tmux kill-session -t test-manual-kill`
4. Monitor termination handling

**Expected Behavior**:
- Session is immediately terminated
- Exit code is captured (may be non-zero due to forced termination)
- Manager detects session termination
- Proper cleanup is performed

**Verification Steps**:
1. Check console for termination log
2. Verify exit code capture
3. Confirm session removal from active list

#### Test Scenario 4.2: Kill Server Command
**Description**: Test handling of `tmux kill-server` command

**Setup Steps**:
1. Start multiple sessions: `test-server-1`, `test-server-2`, `test-server-3`
2. Execute: `tmux kill-server`
3. Monitor all session handling

**Expected Behavior**:
- All sessions are terminated simultaneously
- Manager detects server shutdown
- All sessions are cleaned up
- Manager handles mass termination gracefully

**Verification Steps**:
1. Check console for multiple termination logs
2. Verify all sessions are removed
3. Confirm manager stability

---

### 5. Server SIGTERM/SIGINT Handling

#### Test Scenario 5.1: SIGTERM to Application Server
**Description**: Test graceful shutdown when server receives SIGTERM

**Setup Steps**:
1. Start application server
2. Create multiple active tmux sessions
3. Send SIGTERM to server process: `kill -TERM <server-pid>`
4. Monitor shutdown sequence

**Expected Behavior**:
- Server initiates graceful shutdown
- All active tmux sessions are terminated
- Exit codes are captured for all sessions
- Server shuts down cleanly

**Verification Steps**:
1. Check shutdown logs for all session terminations
2. Verify all exit codes are captured
3. Confirm no orphaned sessions remain
4. Verify clean server exit

#### Test Scenario 5.2: SIGINT to Application Server
**Description**: Test interrupt handling when server receives SIGINT

**Setup Steps**:
1. Start application server
2. Create active tmux sessions
3. Send SIGINT to server process (Ctrl+C)
4. Monitor interrupt handling

**Expected Behavior**:
- Server handles interrupt gracefully
- Sessions are terminated cleanly
- Proper cleanup is performed
- Server exits with appropriate code

**Verification Steps**:
1. Check interrupt handling logs
2. Verify session cleanup
3. Confirm proper server termination

---

### 6. Concurrent Session Termination

#### Test Scenario 6.1: Multiple Simultaneous Terminations
**Description**: Test handling when multiple sessions terminate simultaneously

**Setup Steps**:
1. Start 5 sessions with IDs: `concurrent-1` through `concurrent-5`
2. Execute commands that will exit at the same time: `sleep 5 && exit 0`
3. Monitor concurrent termination handling

**Expected Behavior**:
- All sessions terminate within same time window
- All exit codes are captured correctly
- No race conditions in cleanup
- Manager handles concurrent terminations gracefully

**Verification Steps**:
1. Check console for 5 termination logs
2. Verify all exit codes are 0
3. Confirm no sessions remain active
4. Check for any race condition errors

#### Test Scenario 6.2: Mixed Success/Failure Terminations
**Description**: Test concurrent terminations with different exit codes

**Setup Steps**:
1. Start 4 sessions: `mixed-1` through `mixed-4`
2. Configure different exit codes:
   - `mixed-1`: `sleep 3 && exit 0`
   - `mixed-2`: `sleep 3 && exit 1`
   - `mixed-3`: `sleep 3 && exit 2`
   - `mixed-4`: `sleep 3 && nonexistent-command`
3. Monitor concurrent termination

**Expected Behavior**:
- All sessions terminate around same time
- Different exit codes are captured correctly
- Manager handles mixed results properly
- No data corruption or loss

**Verification Steps**:
1. Check console for 4 different exit codes: 0, 1, 2, 127
2. Verify proper cleanup for all sessions
3. Confirm manager stability

---

## Test Environment Setup

### Prerequisites
- Node.js environment with tmux installed
- Access to `/tmp` directory for socket files
- Ability to send signals to processes
- Console logging enabled for exit code capture

### Common Setup Commands
```bash
# Verify tmux installation
tmux -V

# Clean any existing sessions
tmux kill-server 2>/dev/null || true

# Start fresh test environment
npm start
```

### Test Data Cleanup
```bash
# Remove any orphaned tmux sessions
tmux kill-server 2>/dev/null || true

# Clean socket files
rm -rf /tmp/tmux-* 2>/dev/null || true

# Reset test environment
pkill -f "node.*server" 2>/dev/null || true
```

## Success Criteria

### Primary Criteria
1. **Exit Code Capture**: All session terminations must log exit codes to console
2. **Clean Termination**: No orphaned tmux sessions or socket files
3. **Error Handling**: Graceful handling of all failure scenarios
4. **Concurrent Safety**: No race conditions during simultaneous terminations

### Performance Criteria
1. **Response Time**: Termination detection within 1 second
2. **Resource Cleanup**: Complete cleanup within 5 seconds
3. **Memory Management**: No memory leaks during mass terminations
4. **Stability**: Server remains stable through all test scenarios

### Reliability Criteria
1. **Consistency**: 100% success rate across multiple test runs
2. **Determinism**: Consistent behavior across different environments
3. **Recovery**: Proper recovery from any failure scenario
4. **Logging**: Complete audit trail of all operations

## Test Execution Notes

1. **Sequential Execution**: Run tests in order to avoid interference
2. **Environment Reset**: Clean environment between test categories
3. **Timing Considerations**: Allow sufficient time for async operations
4. **Log Monitoring**: Continuously monitor console output during tests
5. **Resource Monitoring**: Watch for memory leaks and resource exhaustion

## Expected Console Output Format

```
Session <session-id> exited with code: <exit-code>
Session <session-id> cleaned up successfully
Tmux socket removed: /tmp/tmux-<id>/<session-id>
```

This test plan ensures comprehensive validation of tmux termination handling with proper exit code capture and cleanup verification.