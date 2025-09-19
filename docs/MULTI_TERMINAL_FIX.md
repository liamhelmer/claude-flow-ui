# Multi-Terminal Functionality Fix

## Issues Fixed

### 1. WebSocket Disconnection on Terminal Switch
**Problem**: When clicking on a new terminal or spawning one, the entire page showed "Disconnected - Unable to connect to terminal server"

**Root Cause**:
- The Terminal component was remounting when `activeSessionId` changed
- The WebSocket handler didn't properly handle session switching
- Spawned terminals weren't emitting proper `session-created` events

**Solution**:
- Updated WebSocket handler to emit `session-created` for all terminals on connection
- Fixed session switching logic to use correct tmux session names
- Added proper `currentSessionId` tracking in socket.data

### 2. Terminal Spawning Issues
**Problem**: Newly spawned terminals couldn't be connected to

**Root Cause**:
- Spawned terminals weren't emitting `session-created` events
- The tmux session names weren't being properly mapped

**Solution**:
- Added `session-created` emission when spawning terminals
- Fixed tmux session name resolution using `terminal.tmuxSession?.name`

### 3. Session Data Routing
**Problem**: Terminal data wasn't routing correctly to different sessions

**Root Cause**:
- Initial WebSocket connection didn't set `currentSessionId`
- Session switching didn't update terminal configuration

**Solution**:
- Set `currentSessionId` in initial connection
- Send terminal config when switching sessions

## Code Changes

### unified-server.js

1. **Terminal Spawn Endpoint** (line 214-219):
```javascript
// Notify connected clients - emit session-created so Terminal component knows it's ready
io.emit('session-created', {
  sessionId: sessionId
});
```

2. **WebSocket Connection Handler** (line 679-690):
```javascript
// Send initial configuration for all terminals
terminals.forEach((terminal, sessionId) => {
  socket.emit('terminal-config', {
    cols: TERMINAL_CONFIG.cols,
    rows: TERMINAL_CONFIG.rows,
    sessionId: sessionId,
    timestamp: Date.now()
  });

  // Send session created event for each terminal
  socket.emit('session-created', { sessionId: sessionId });
});
```

3. **Session Switching Logic** (line 764-787):
```javascript
// Connect to new session
const terminal = terminals.get(targetSessionId);
if (terminal && useTmux) {
  // Use the actual tmux session name from the terminal object
  const tmuxSessionName = terminal.tmuxSession?.name || targetSessionId;

  const connection = tmuxManager.connectClient(socket.id, tmuxSessionName, (data) => {
    socket.emit('terminal-data', { sessionId: targetSessionId, data });
  });

  socket.data = {
    ...socket.data,
    streamConnection: connection,
    currentSessionId: targetSessionId
  };

  // Send session configuration and created event for the new terminal
  socket.emit('terminal-config', {
    cols: TERMINAL_CONFIG.cols,
    rows: TERMINAL_CONFIG.rows,
    sessionId: targetSessionId,
    timestamp: Date.now()
  });
}
```

4. **Initial Connection Setup** (line 709-713):
```javascript
// Store connection info for cleanup and operations
socket.data = {
  streamConnection,
  sessionName: currentTmuxSession.name,
  currentSessionId: globalSessionId
};
```

## Testing

### API Verification
```bash
# List terminals
curl http://localhost:8080/api/terminals

# Spawn new terminal
curl -X POST -H "Content-Type: application/json" \
  -d '{"name":"Test Terminal","command":"/bin/bash"}' \
  http://localhost:8080/api/terminals/spawn

# Close terminal
curl -X DELETE http://localhost:8080/api/terminals/{id}
```

### Expected Behavior
1. ✅ Initial load shows main "Claude Flow" terminal
2. ✅ Clicking "New Terminal" spawns a bash shell
3. ✅ Terminal list shows all active terminals
4. ✅ Clicking on terminals switches between them
5. ✅ Closing terminals (except main) removes them from list
6. ✅ WebSocket connection remains stable during switches

## Current Status

✅ **FIXED**: Multi-terminal functionality is now fully operational
- Terminal spawning works correctly
- Session switching maintains WebSocket connection
- Data routing works for all terminal sessions
- UI properly reflects terminal state changes
- Terminal data isolation prevents output mixing

## Final Terminal Data Mixing Fix (Latest)

### Problem
Terminal data from multiple sessions was getting mixed - when switching between terminals, output from all terminals would appear in the active terminal.

### Root Cause
1. The `useTerminal` hook was accepting data from any sessionId (line 569 had comment "Accept data from any sessionId since we only have one terminal")
2. When switching sessions, the old tmux stream connection wasn't immediately disconnected, causing the old callback to continue receiving and emitting data

### Solution

#### 1. Fixed Terminal Data Filtering (useTerminal.ts)
```javascript
// Only accept data for the current sessionId to prevent mixing terminal outputs
if (terminalRef.current && data.sessionId === sessionId) {
  // Process data only for matching sessionId
} else if (data.sessionId !== sessionId) {
  // Log rejected data from other sessions
  console.debug(`[Terminal] 🚫 Rejected data for session ${data.sessionId} (expected: ${sessionId})`);
}
```

#### 2. Immediate Disconnect on Session Switch (tmux-stream-manager.js)
```javascript
disconnectClient(clientId, immediate = false) {
  if (immediate) {
    // Immediate disconnect without grace period (for session switching)
    this.finalDisconnect(clientId);
  } else {
    // Normal disconnect with grace period
  }
}
```

#### 3. Updated Server Session Switching (unified-server.js)
```javascript
// Disconnect from current session immediately (no grace period for session switches)
if (socket.data?.streamConnection) {
  socket.data.streamConnection.disconnect(true); // true = immediate disconnect
}
```

### Testing Verification
- ✅ Initial terminal loads correctly
- ✅ Spawning new terminals works
- ✅ Switching between terminals maintains connection
- ✅ Each terminal shows only its own output
- ✅ Input is correctly routed to the active terminal only