# Terminal Input Routing Fix

## Issues Fixed

### Issue 1: Input Not Routing to Correct Terminal
When switching between multiple terminals, keyboard input was not being routed to the correct backend terminal. The onData handler in useTerminal.ts was capturing the sessionId as a closure variable when created, and this wasn't updating when switching terminals.

### Issue 2: Terminals Unresponsive After Switching
After switching from one terminal to another, existing terminals became unresponsive. The backend didn't have a proper 'switch-session' handler, and session switching wasn't properly reconnecting to the tmux sessions.

### Issue 3: Terminal Display Not Updating in Real-Time
Terminal output wasn't appearing until switching away and back. The tmux callback was using a dynamically read sessionId that could change during execution.

### Issue 4: Server Crash on Session Switch
Server crashed with "Session not found" error when switching between terminals. The switch-session handler wasn't validating session existence before attempting to connect.

## Root Causes

1. **Frontend**: The `onData` handler registered with xterm.js captured `sessionId` from its closure when created. Since the terminal instance persisted across session changes, the handler continued using the old sessionId value.

2. **Backend**: No dedicated 'switch-session' event handler existed. The server was trying to auto-switch sessions when receiving input with a different sessionId, which created inconsistent state.

3. **Callback Scope**: The tmux streaming callback was reading sessionId from socket.data, which could change during execution, causing data to be sent with wrong sessionIds.

4. **Missing Validation**: The switch-session handler didn't validate whether terminals existed in the terminals map or whether tmux sessions were available before attempting to connect.

## Solution

### 1. Added sessionIdRef to track current sessionId (useTerminal.ts)
```typescript
const sessionIdRef = useRef<string>(sessionId);

// Keep sessionIdRef in sync with sessionId prop
useEffect(() => {
  sessionIdRef.current = sessionId;
}, [sessionId]);
```

### 2. Updated onData handler to use ref value (useTerminal.ts:389)
```typescript
const onDataDisposable = terminal.onData((data: string) => {
  // Send raw keypress data immediately to the PTY backend
  // Use ref to always get current sessionId
  sendData(sessionIdRef.current, data);
  onData?.(data);
});
```

### 3. Added switchSession method to WebSocket hook (useWebSocket.ts)
```typescript
const switchSession = useCallback((sessionId: string) => {
  if (wsClient.connected) {
    console.debug(`[useWebSocket] Switching to session: ${sessionId}`);
    wsClient.send('switch-session', { targetSessionId: sessionId });
  } else {
    console.warn('WebSocket not connected, cannot switch session');
  }
}, []);
```

### 4. Call switchSession when selecting terminal (page.tsx)
```typescript
const handleSessionSelect = (sessionId: string) => {
  // Notify backend about session switch
  switchSession(sessionId);
  // Update local state
  setActiveSession(sessionId);
};
```

### 5. Added enhanced switch-session handler with validation (unified-server.js)
```javascript
socket.on('switch-session', (message) => {
  const targetSessionId = message?.targetSessionId;

  // Disconnect from current session
  if (socket.data?.streamConnection) {
    socket.data.streamConnection.disconnect(true);
  }

  // Validate terminal exists
  const terminal = terminals.get(targetSessionId);
  if (!terminal) {
    console.error(`Terminal ${targetSessionId} not found`);
    socket.emit('session-switched', { success: false, error: 'Terminal not found' });
    return;
  }

  // Validate tmux session exists
  const tmuxSessionName = terminal.tmuxSession?.name;
  if (!tmuxSessionName || !tmuxManager.sessions.has(tmuxSessionName)) {
    console.error(`Tmux session ${tmuxSessionName} not found`);
    socket.emit('session-switched', { success: false, error: 'Tmux session not found' });
    return;
  }

  // Connect to new session with error handling
  try {
    const connection = tmuxManager.connectClient(socket.id, tmuxSessionName, (data) => {
      socket.emit('terminal-data', { sessionId: targetSessionId, data });
    });

    socket.data = {
      ...socket.data,
      streamConnection: connection,
      currentSessionId: targetSessionId
    };

    // Send config and refresh
    socket.emit('terminal-config', { ... });
    if (connection?.refresh) {
      setTimeout(() => connection.refresh(), 100);
    }
  } catch (error) {
    socket.emit('session-switched', { success: false, error: error.message });
  }
});
```

### 6. Removed unnecessary createSession call (page.tsx)
Removed the frontend's attempt to call `createSession()` when connected, as the main terminal is created by the server on startup and automatically sends `session-created` event.

## Files Modified
- `/src/hooks/useTerminal.ts` - Added sessionIdRef to track current sessionId
- `/src/hooks/useWebSocket.ts` - Added switchSession method
- `/src/app/page.tsx` - Call switchSession when selecting terminal, removed unnecessary createSession call
- `/unified-server.js` - Enhanced switch-session handler with comprehensive validation and error handling

## Testing
1. Start the application with `npm run claude-flow-ui`
2. Open the terminal sidebar
3. Click "New Terminal" to spawn a bash terminal
4. Type in the bash terminal to verify input works
5. Switch back to Claude Flow terminal
6. Verify input goes to Claude Flow
7. Switch back to bash terminal
8. Verify input goes to bash terminal

## Result
✅ Terminal input now correctly routes to the active terminal session
✅ No more input mixing between terminals
✅ Terminals remain responsive after switching
✅ Session switching properly reconnects to tmux sessions
✅ Real-time terminal output updates work correctly
✅ Server no longer crashes when switching sessions
✅ Proper error handling and validation for all edge cases
✅ Build passes without errors

## Key Improvements
1. **Proper session tracking**: Using a ref ensures the current sessionId is always used
2. **Explicit session switching**: Dedicated switch-session event prevents ambiguous state
3. **Clean reconnection**: Immediate disconnect and proper tmux reconnection ensures clean state
4. **Comprehensive validation**: Server validates terminal and tmux session existence before connection
5. **Better error handling**: Detailed error messages help diagnose issues
6. **Auto-switch on spawn**: New terminals automatically become active with proper backend notification
7. **Session state sync**: Frontend properly notifies backend when sessions are created or spawned
8. **Robust error recovery**: Try-catch blocks prevent crashes and provide graceful error handling
9. **Simplified initialization**: Removed unnecessary createSession call that was causing confusion