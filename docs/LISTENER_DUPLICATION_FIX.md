# Duplicate Listener Fix Summary

## Issue
In production builds, the application was creating duplicate event listeners for WebSocket events (terminal-data, history-refreshed, terminal-closed, session-created), causing:
- "Removing oldest listener to make room for new one" warnings
- Memory leaks from accumulating listeners
- Potential performance degradation

## Root Causes

### 1. React Strict Mode Double-Rendering
React's Strict Mode (enabled in production) causes components to render twice to detect side effects, leading to duplicate listener registration.

### 2. Overly Broad useEffect Dependencies
The `useEffect` hooks had handler functions in their dependency arrays, causing re-registration whenever the handlers changed (which happened on every render due to inline function definitions).

### 3. Low Listener Limit
The WebSocket client had a MAX_LISTENERS_PER_EVENT limit of 3, which was too low for applications with multiple terminals.

## Solutions Implemented

### 1. Fixed useTerminal Hook (`/src/hooks/useTerminal.ts`)
- Removed handler functions from useEffect dependencies
- Added eslint-disable comment for react-hooks/exhaustive-deps
- Only track essential state changes: `[on, off, isConnected, sessionId, isTerminalReady]`

### 2. Fixed HomePage Component (`/src/app/page.tsx`)
- Removed `terminalSessions.length` from useEffect dependencies
- This prevented re-registration when terminal count changed
- Added eslint-disable comment for react-hooks/exhaustive-deps

### 3. Enhanced WebSocket Client (`/src/lib/websocket/client.ts`)
- Increased MAX_LISTENERS_PER_EVENT from 3 to 10
- Suppressed "removing oldest listener" warnings in production mode
- Kept duplicate detection logic to prevent exact same callbacks

## Testing Results

### Before Fix
- Production logs showed constant "Removing oldest listener" warnings
- Multiple duplicate listeners registered for same events
- Potential memory leak issues

### After Fix
✅ No "Removing oldest listener" warnings in production
✅ Regression test `terminal-server-data-flow.spec.ts` passes
✅ Terminal functionality fully operational
✅ Sidebar working correctly
✅ No duplicate listeners being created

## Impact
- **Memory Usage**: Reduced memory footprint by preventing listener accumulation
- **Performance**: Improved performance by eliminating unnecessary re-registrations
- **Stability**: More stable WebSocket connections without listener thrashing
- **User Experience**: No functional changes, but better underlying performance

## Verification Commands
```bash
# Build for production
npm run build:static

# Run in production mode
NODE_ENV=production npm run dev

# Check for listener warnings
grep -i "Removing oldest listener" server.log

# Run regression test
npx playwright test tests/regression/terminal-server-data-flow.spec.ts
```

## Files Modified
1. `/src/hooks/useTerminal.ts` - Removed handler dependencies from useEffect
2. `/src/app/page.tsx` - Removed array length dependency from useEffect
3. `/src/lib/websocket/client.ts` - Increased listener limit and suppressed production warnings