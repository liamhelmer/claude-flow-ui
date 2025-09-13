# Tmux Termination Detection and Cleanup

## Overview

The Claude Flow UI now includes comprehensive termination detection that monitors tmux sessions and automatically shuts down the application when:

1. **The tmux socket file is deleted** - Indicates the tmux server has terminated
2. **The command running in tmux completes** - Detected when the tmux pane becomes "dead"
3. **The tmux session is killed** - Normal session termination

## Important Note

When commands complete very quickly (like `echo`), the entire tmux session may terminate before the pane death can be detected. This is expected behavior - the session termination itself triggers the shutdown, which is the desired outcome.

## Implementation Details

### Socket Monitoring

The application continuously monitors the tmux socket file for existence:

- **Location**: Socket files are stored in a secure temporary directory
- **Monitoring Frequency**: Every 100ms during active polling
- **Detection**: Uses `fs.existsSync()` to check socket file presence
- **Action**: Immediate application shutdown when socket disappears

### Command Completion Detection

The application detects when commands complete inside tmux sessions:

- **Method**: Checks tmux pane status using `tmux list-panes -F '#{pane_dead}'`
- **Frequency**: Checked during each polling cycle (100ms)
- **Detection**: Pane status of '1' indicates the command has completed
- **Action**: Triggers graceful shutdown with proper cleanup

### Cleanup Process

When termination is detected, the application performs a comprehensive cleanup:

1. **Stop all polling intervals** - Prevents further tmux operations
2. **Notify connected clients** - Sends termination message to all WebSocket clients
3. **Clean up tmux sessions** - Kills any remaining tmux sessions
4. **Remove socket files** - Deletes socket files from the filesystem
5. **Close log streams** - Ensures logs are properly flushed
6. **Exit the process** - Terminates with appropriate exit code

## Exit Scenarios

### 1. Socket Termination
```
🔌 [CRITICAL] Socket file deleted for session <name> - initiating shutdown
🛑 Socket terminated - shutting down application...
```

### 2. Command Completion
```
🔌 [DEBUG] Command completed in session <name> - pane is dead
✅ Command completed - shutting down application...
```

### 3. Session Termination
```
🔌 [DEBUG] Session <name> no longer exists - terminating
🛑 Tmux session terminated - shutting down application...
```

## Signal Handling

The application handles multiple termination signals:

- **SIGTERM**: Graceful termination request
- **SIGINT**: Interrupt signal (Ctrl+C)
- **SIGHUP**: Hangup signal

All signals trigger the same comprehensive cleanup process.

## Error Recovery

The implementation includes robust error handling:

- **Retry Logic**: Failed capture operations are retried up to 3 times
- **Fallback Strategies**: Multiple capture methods for different scenarios
- **Timeout Protection**: Operations have timeouts to prevent hanging
- **Resource Cleanup**: Resources are cleaned up even if errors occur

## Testing

To test termination detection:

1. **Test Socket Deletion**:
   ```bash
   # Start the UI with a command
   npm start -- --claude-flow-args echo "test"
   
   # In another terminal, find and delete the socket
   rm /path/to/socket/file
   ```

2. **Test Command Completion**:
   ```bash
   # Start the UI with a short-lived command
   npm start -- --claude-flow-args "sleep 5 && echo done"
   
   # Wait for command to complete
   # Application should shut down automatically
   ```

3. **Test Session Kill**:
   ```bash
   # Start the UI
   npm start
   
   # Find the tmux session
   tmux ls
   
   # Kill the session
   tmux kill-session -t <session-name>
   ```

## Configuration

The termination detection behavior can be influenced by environment variables:

- **DEBUG_TMUX**: Set to enable detailed debug logging
- **NODE_ENV**: Set to 'test' for test-specific behavior

## Architecture

The termination detection is implemented across multiple components:

1. **tmux-manager.js**: Core tmux session management and monitoring
2. **tmux-stream-manager.js**: Streaming interface with termination detection
3. **websocket-server.js**: WebSocket server with cleanup coordination
4. **server.js**: Main server with cascading shutdown logic

## Benefits

- **Automatic Cleanup**: No orphaned processes or tmux sessions
- **Resource Management**: Proper cleanup of sockets, files, and connections
- **User Experience**: Clean shutdown without manual intervention
- **Reliability**: Robust detection of various termination scenarios

## Troubleshooting

If the application doesn't shut down properly:

1. Check for remaining tmux sessions: `tmux ls`
2. Verify socket files are cleaned up: `ls /tmp/claude-flow-*`
3. Check process list: `ps aux | grep claude-flow`
4. Review logs in `.claude-flow` directory

## Future Improvements

Potential enhancements for termination detection:

1. **Configurable shutdown delay**: Allow grace period before shutdown
2. **Reconnection support**: Option to reconnect instead of shutdown
3. **Custom exit handlers**: User-defined cleanup scripts
4. **Persistence options**: Save session state before shutdown