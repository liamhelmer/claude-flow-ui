# Tmux Capture Error Fix for NPM Installations

## Problem Description
When the package was installed via `npm install @liamhelmer/claude-flow-ui` and run from a different directory, the tmux capture-pane command would fail with exit code 1, causing the error:
```
Capture error for session terminal-XXXXXX: [Error: Failed to capture screen: 1]
```

## Root Causes
1. **Socket Directory**: The tmux socket directory wasn't being created with proper permissions
2. **Verbose Logging**: Excessive logging was causing performance issues and log spam
3. **Error Handling**: Insufficient error details made debugging difficult

## Solutions Implemented

### 1. Socket Directory Management
**File**: `src/lib/tmux-stream-manager.js`

- Changed socket directory to use a consistent path under temp directory
- Ensure directory is created with proper permissions (755) before creating sessions
- Added validation to check if socket exists before attempting operations

```javascript
// Ensure socket directory exists
const socketDir = path.join(os.tmpdir(), '.claude-flow-tmux');
if (!fs.existsSync(socketDir)) {
  fs.mkdirSync(socketDir, { recursive: true, mode: 0o755 });
}
```

### 2. Conditional Logging
**Files**: `src/lib/tmux-stream-manager.js`, `src/lib/tmux-manager.js`

- Made verbose logging conditional on `DEBUG_TMUX` environment variable
- Only log capture attempts on retries or in debug mode
- Skip capture entirely when no clients are connected

```javascript
// Only log in debug mode to avoid spamming logs
if (process.env.DEBUG_TMUX) {
  console.log(`[TmuxStream] Screen capture successful...`);
}
```

### 3. Enhanced Error Diagnostics
**Files**: `src/lib/tmux-stream-manager.js`, `scripts/diagnose-tmux.js`

- Added detailed error logging including socket path and error output
- Created diagnostic script to check tmux installation and permissions
- Added session validation before capture attempts
- Implemented fallback capture strategies

### 4. Package Distribution
**File**: `package.json`

- Added all necessary tmux-related files to the npm package
- Included diagnostic script for troubleshooting
- Added `npm run diagnose` command for easy debugging

## Testing the Fix

1. **Build and pack the package**:
```bash
npm run build:static
npm pack
```

2. **Install in a test directory**:
```bash
cd /tmp
mkdir test-app && cd test-app
npm init -y
npm install /path/to/liamhelmer-claude-flow-ui-1.0.2.tgz
```

3. **Run the service**:
```bash
npx @liamhelmer/claude-flow-ui --port 8080
```

4. **Run diagnostics if issues occur**:
```bash
npx @liamhelmer/claude-flow-ui diagnose
```

## Diagnostic Tool
A comprehensive diagnostic tool is now included that checks:
- Tmux installation and version
- Socket directory permissions
- Active tmux sessions
- Test session creation and capture
- Environment variables
- Platform compatibility

Run with: `npm run diagnose` or `npx @liamhelmer/claude-flow-ui diagnose`

## Environment Variables

- `DEBUG_TMUX=1`: Enable verbose tmux logging for debugging
- `PORT`: Override default port (8080)

## Verification
The fix has been tested and verified to:
1. Start without infinite loop errors
2. Create tmux sessions successfully from any directory
3. Capture terminal output correctly
4. Handle multiple client connections
5. Clean up resources properly on exit