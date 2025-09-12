# TmuxStream Infinite Loop Fix

## Problem
The service was stuck in an infinite loop with the following repeating output:
```
[TmuxStream] Capturing screen for session terminal-1757716334249 (attempt 1/4)
[TmuxStream] Screen capture successful for session terminal-1757716334249 (11975 bytes)
```

## Root Cause
The TmuxStreamManager was continuously capturing the screen content every 50ms and logging success messages, even when:
1. No clients were connected
2. No changes had occurred in the terminal content
3. The logging was too verbose for normal operation

## Solution
Fixed the issue in both `tmux-stream-manager.js` and `tmux-manager.js`:

### 1. Skip Capture When No Clients Connected
Added a check in the capture interval to skip processing when no clients are connected:
```javascript
// Only capture if there are active clients
if (session.clients.size === 0) {
  return; // Skip capture when no clients are connected
}
```

### 2. Conditional Logging
Made verbose logging conditional on a `DEBUG_TMUX` environment variable:
```javascript
// Only log in debug mode to avoid spamming logs
if (process.env.DEBUG_TMUX) {
  console.log(`[TmuxStream] Screen capture successful...`);
}
```

### 3. Debug Mode for Capture Attempts
Only log capture attempts in debug mode or on retries:
```javascript
// Only log capture attempts in debug mode or on retries
if (process.env.DEBUG_TMUX || retryCount > 0) {
  console.log(`[TmuxStream] Capturing screen...`);
}
```

## Testing
The fix was tested by running `npm run dev` and confirming that:
1. The server starts without infinite loop messages
2. The service remains stable over time
3. Terminal functionality continues to work properly

## How to Enable Debug Logging
If you need to debug tmux capture issues in the future, run the server with:
```bash
DEBUG_TMUX=1 npm run dev
```

This will re-enable the verbose logging for troubleshooting purposes.