# Secure Temporary Directory Implementation

## Overview
Implemented a comprehensive secure temporary directory management system for Claude Flow UI that ensures all temporary files and Unix domain sockets are created with proper security permissions and collision detection.

## Security Features

### 1. Secure Directory Creation
- All directories created with **mode 0o700** (owner-only access)
- Ownership verification on Unix systems
- Permission validation and automatic correction
- Protection against world-writable directories

### 2. Collision Detection
- Automatic collision detection for directory and socket names
- Retry mechanism with numbered suffixes
- Stale socket detection and cleanup
- Unique session IDs using timestamp + random bytes

### 3. Platform-Specific Handling
- **$TMPDIR** environment variable (primary)
- **XDG_RUNTIME_DIR** on Linux (secure for sockets)
- **TEMP/TMP** on Windows
- Fallback to `/tmp`, `/var/tmp`, and user home directory
- Socket path length limitation handling (Unix 108-char limit)

### 4. Directory Structure
```
$TMPDIR/.claude-flow/
├── sessions/
│   └── cf-{timestamp}-{random}/
│       ├── sockets/    # Unix domain sockets (mode 700)
│       ├── logs/       # Application logs (mode 700)
│       └── cache/      # Temporary files (mode 700)
```

For long paths, sockets are created in `/tmp/.cf-sock/` with hashed names.

## Implementation Details

### SecureTempDir Class
Located in `src/lib/secure-temp-dir.js`, provides:

- **Singleton pattern** for consistent directory usage
- **Automatic cleanup** on process exit (SIGINT, SIGTERM)
- **Old session cleanup** (removes sessions older than 24 hours)
- **Platform detection** with OS-specific optimizations

### Key Methods

```javascript
// Get singleton instance
const secureTempDir = getInstance();

// Get secure directories
const socketDir = secureTempDir.getSocketDir();    // For Unix sockets
const logDir = secureTempDir.getLogDir();          // For log files
const cacheDir = secureTempDir.getCacheDir();      // For temp files

// Get socket path with collision detection
const socketPath = secureTempDir.getSocketPath('tmux-session');

// Create unique temp file
const tempFile = secureTempDir.createTempFile('data', '.json');
```

### Integration with Tmux

Both `tmux-stream-manager.js` and `tmux-manager.js` now use SecureTempDir:

```javascript
const { getInstance: getSecureTempDir } = require('./secure-temp-dir');

// In createSession()
const secureTempDir = getSecureTempDir();
const socketPath = secureTempDir.getSocketPath(sessionName);
```

## Security Benefits

1. **Permission Isolation**: All temp files are only accessible by the owner
2. **No World-Writable Files**: Prevents tampering by other users
3. **Automatic Cleanup**: Reduces attack surface by removing old files
4. **Collision Prevention**: Prevents symlink attacks and race conditions
5. **Path Validation**: Checks ownership and permissions before use

## Testing & Verification

### Check Directory Permissions
```bash
ls -la /tmp/.claude-flow/
# Should show: drwx------ (700)

ls -la /tmp/.cf-sock/
# Should show: drwx------ (700) and srw------- for sockets
```

### Run Diagnostic
```bash
npm run diagnose
# Verifies tmux, permissions, and socket creation
```

### Test Socket Creation
```bash
node -e "
const { getInstance } = require('./src/lib/secure-temp-dir');
const st = getInstance();
console.log(st.getInfo());
"
```

## Environment Variables

- `TMPDIR`: Override default temp directory location
- `XDG_RUNTIME_DIR`: Used on Linux for runtime files
- `DEBUG_TMUX`: Enable verbose logging for debugging

## Platform Compatibility

Tested and verified on:
- ✅ macOS (Darwin)
- ✅ Linux (Ubuntu, Debian, RHEL)
- ✅ Windows (with WSL)

## Migration Notes

When updating from v1.0.2 to v1.0.3+:
1. Old socket files in `/tmp/.claude-flow-sockets/` are abandoned
2. New sockets created in secure session directories
3. Automatic cleanup removes old sessions after 24 hours
4. No manual intervention required

## Troubleshooting

### Socket Path Too Long
- Automatically handled by using `/tmp/.cf-sock/` with hashed names
- Original paths over 100 characters are shortened
- Hash ensures uniqueness while maintaining security

### Permission Denied
- Ensure user has write access to `$TMPDIR`
- Check that parent directories aren't restrictive
- Run diagnostic: `npm run diagnose`

### Cleanup Issues
- Sessions auto-cleanup after 24 hours
- Manual cleanup: `rm -rf $TMPDIR/.claude-flow/`
- Process exit handlers ensure cleanup on termination

## Security Considerations

1. **Never run as root** unless absolutely necessary
2. **Check file ownership** before trusting socket files
3. **Monitor temp directory** for unexpected files
4. **Regular cleanup** reduces exposure window
5. **Audit logs** stored in secure session directories

## Future Enhancements

- [ ] Configurable retention period for old sessions
- [ ] Encrypted temp file option for sensitive data
- [ ] Audit logging for security events
- [ ] Integration with systemd's PrivateTmp on Linux
- [ ] Windows named pipe support as alternative to Unix sockets