# Tmux Session Validation Fix

## Problem
When starting claude-flow-ui via npx, the following error occurred:
```
[TmuxStream] Session validation failed for terminal-1757719235006: Session terminal-1757719235006 does not exist or is not accessible
Capture error for session terminal-1757719235006: [Error: Session validation failed: Session terminal-1757719235006 does not exist or is not accessible]
```

## Root Cause
The issue was caused by the `pipe-pane` command being used during session creation. The pipe-pane command can interfere with tmux session stability, especially when:
1. The session is created with a specific socket path
2. The pipe-pane tries to write to a file that may not be accessible
3. The validation check happens immediately after creation

## Solution
Removed the problematic `pipe-pane` command from the session creation process and switched to a pure capture-based streaming approach.

### Changes Made in `src/lib/tmux-stream-manager.js`:

1. **Removed pipe-pane command**:
   - Deleted the `tmux pipe-pane` command that was causing session instability
   - Removed references to `streamProcess` and pipe file handling

2. **Switched to capture-based streaming**:
   - Use `tmux capture-pane` for all terminal output capture
   - Rely on `captureInterval` for periodic updates
   - More stable and reliable approach

3. **Simplified session management**:
   - Sessions are created without any additional piping
   - Validation works correctly immediately after creation
   - No file system dependencies for streaming

## Implementation Details

### Before (problematic):
```javascript
// Create tmux session with pipe-pane
await execAsync(`tmux -S "${socketPath}" new-session -d -s "${sessionName}" ${command}`);
await execAsync(`tmux -S "${socketPath}" pipe-pane -t "${sessionName}" -o 'cat >> /tmp/tmux-output'`);
```

### After (fixed):
```javascript
// Create tmux session without pipe-pane
await execAsync(`tmux -S "${socketPath}" new-session -d -s "${sessionName}" ${command}`);
// Use capture-based streaming instead
this.startCaptureStreaming(sessionName);
```

## Benefits of the Fix

1. **Stability**: Sessions are created reliably without interference
2. **Simplicity**: Fewer moving parts and dependencies
3. **Compatibility**: Works consistently across different environments
4. **Performance**: No file I/O overhead from pipe-pane

## Testing Confirmation

Tested with npx installation:
```bash
cd /tmp/test-npx-3
npm install @liamhelmer/claude-flow-ui
npx claude-flow-ui
```

Result: Service starts cleanly without any session validation errors.

## Version
Fixed in version 1.0.5 of @liamhelmer/claude-flow-ui