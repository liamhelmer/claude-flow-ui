# Unified Server Integration Guide

## Integrating Backstage Authentication into unified-server.js

This guide provides step-by-step instructions for integrating the Backstage JWT authentication system into the existing unified-server.js file.

## Integration Points

### 1. Add Require Statements (Top of File)

After the existing require statements (around line 15), add:

```javascript
// Backstage Authentication (optional)
let backstageAuth = null;
try {
  const {
    parseBackstageAuthOptions,
    initializeBackstageAuth,
    applyExpressMiddleware,
    applyWebSocketMiddleware,
    getAuthenticatedUser,
    getSocketAuthenticatedUser,
    canAccessTerminal,
  } = require('./src/services/backstage-auth-integration');

  // Parse authentication configuration from CLI and env vars
  const authConfig = parseBackstageAuthOptions(args);

  // Initialize authentication system if configured
  if (authConfig.backstageUrl) {
    backstageAuth = initializeBackstageAuth(authConfig);
  }
} catch (error) {
  console.log('[Backstage Auth] Not available:', error.message);
}
```

### 2. Apply Express Middleware (After app.use(express.json()))

After line 238 where `app.use(express.json());` is called, add:

```javascript
// Apply Backstage authentication middleware (if enabled)
if (backstageAuth) {
  const { applyExpressMiddleware } = require('./src/services/backstage-auth-integration');
  applyExpressMiddleware(app, backstageAuth);
}
```

### 3. Apply WebSocket Middleware (After Socket.IO Server Creation)

After the Socket.IO server is created (around line 234), before the `io.on('connection')` handler, add:

```javascript
// Apply Backstage authentication middleware for WebSocket (if enabled)
if (backstageAuth) {
  const { applyWebSocketMiddleware } = require('./src/services/backstage-auth-integration');
  applyWebSocketMiddleware(io, backstageAuth);
}
```

### 4. Update Terminal Spawn Endpoint (Add User Context)

In the `/api/terminals/spawn` endpoint (around line 330), add user context:

```javascript
app.post('/api/terminals/spawn', async (req, res) => {
  if (!useTmux || !tmuxManager) {
    return res.status(400).json({ error: 'Tmux not available' });
  }

  try {
    terminalCounter++;
    const sessionId = `terminal-${Date.now()}-${terminalCounter}`;
    const command = req.body.command || '/bin/bash --login';
    const name = req.body.name || `Terminal ${terminalCounter}`;

    // Get authenticated user (if authentication is enabled)
    let owner = null;
    if (backstageAuth && req.user) {
      const { stringifyEntityRef } = require('./src/services/identity-resolver');
      owner = stringifyEntityRef(req.user.userRef);
    }

    // Create tmux session
    const tmuxSession = await tmuxManager.createSession(sessionId, command);

    // Store terminal info with owner
    terminals.set(sessionId, {
      name,
      command,
      createdAt: new Date(),
      tmuxSession,
      owner, // Store owner for access control
    });

    console.log(`✅ Spawned new terminal: ${sessionId} (${name}) [owner: ${owner || 'none'}]`);

    // Notify connected clients
    io.emit('session-created', {
      sessionId: sessionId
    });

    io.emit('terminal-spawned', {
      id: sessionId,
      name,
      command,
      createdAt: new Date(),
      owner,
    });

    res.json({
      id: sessionId,
      name,
      command,
      createdAt: new Date(),
      owner,
    });
  } catch (error) {
    console.error('Failed to spawn terminal:', error);
    res.status(500).json({ error: 'Failed to spawn terminal' });
  }
});
```

### 5. Add Terminal Access Control (Optional)

In the WebSocket connection handler (around line 849), add access control:

```javascript
io.on('connection', async (socket) => {
  // Existing connection logging...

  // Get authenticated user from socket
  let authenticatedUser = null;
  if (backstageAuth) {
    const { getSocketAuthenticatedUser } = require('./src/services/backstage-auth-integration');
    authenticatedUser = getSocketAuthenticatedUser(socket);

    if (authenticatedUser) {
      const { stringifyEntityRef } = require('./src/services/identity-resolver');
      console.log(`[WS] Authenticated user: ${stringifyEntityRef(authenticatedUser.userRef)}`);
    }
  }

  // Store user in socket for later access
  socket.user = authenticatedUser;

  // Rest of connection handler...
});
```

### 6. Add Help Command Support (Optional)

Add help output for authentication options. In the argument parsing section (around line 162), add:

```javascript
// Check for help flag
if (args.includes('--help') || args.includes('-h')) {
  console.log('Claude Flow UI Server');
  console.log('\nUsage: claude-flow-ui [options] [-- claude-flow-args]');
  console.log('\nServer Options:');
  console.log('  --port <port>              Server port (default: 11235)');
  console.log('  --terminal-size <cols>x<rows>  Terminal size (default: 120x40)');

  // Print Backstage auth help if available
  if (backstageAuth !== null) {
    try {
      const { printBackstageAuthHelp } = require('./src/services/backstage-auth-integration');
      printBackstageAuthHelp();
    } catch (e) {
      // Ignore if not available
    }
  }

  console.log('\nClaude Flow Options:');
  console.log('  All arguments after -- are passed to claude-flow');
  console.log('  Use environment variables like CLAUDE_FLOW_MODE, CLAUDE_FLOW_PROMPT, etc.');

  process.exit(0);
}
```

## Complete Integration Example

Here's a complete example showing all integration points in context:

```javascript
#!/usr/bin/env node

const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const pty = require('node-pty');
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const next = require('next');
const TmuxStreamManager = require('./src/lib/tmux-stream-manager');
const { existsSync } = require('fs');
const { getClaudeFlowCommand, buildClaudeFlowCommand, getInitCommands, logClaudeFlowVersion } = require('./src/lib/claude-flow-utils');

// Parse command line arguments
const args = process.argv.slice(2);

// Initialize Backstage Authentication (optional)
let backstageAuth = null;
try {
  const {
    parseBackstageAuthOptions,
    initializeBackstageAuth,
  } = require('./src/services/backstage-auth-integration');

  const authConfig = parseBackstageAuthOptions(args);

  if (authConfig.backstageUrl) {
    backstageAuth = initializeBackstageAuth(authConfig);
  }
} catch (error) {
  console.log('[Backstage Auth] Not available:', error.message);
}

// ... rest of argument parsing ...

// Create Express app
const app = express();
const httpServer = createServer(app);

// Configure Socket.IO
const io = new Server(httpServer, {
  path: '/api/ws',
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling']
});

// Middleware
app.use(cors());
app.use(express.json());

// Apply Backstage authentication middleware (if enabled)
if (backstageAuth) {
  const { applyExpressMiddleware } = require('./src/services/backstage-auth-integration');
  applyExpressMiddleware(app, backstageAuth);
}

// ... API endpoints ...

// Apply WebSocket authentication middleware (if enabled)
if (backstageAuth) {
  const { applyWebSocketMiddleware } = require('./src/services/backstage-auth-integration');
  applyWebSocketMiddleware(io, backstageAuth);
}

// WebSocket connection handler
io.on('connection', async (socket) => {
  // Get authenticated user
  let authenticatedUser = null;
  if (backstageAuth) {
    const { getSocketAuthenticatedUser } = require('./src/services/backstage-auth-integration');
    authenticatedUser = getSocketAuthenticatedUser(socket);

    if (authenticatedUser) {
      const { stringifyEntityRef } = require('./src/services/identity-resolver');
      console.log(`[WS] Authenticated user: ${stringifyEntityRef(authenticatedUser.userRef)}`);
    }
  }

  socket.user = authenticatedUser;

  // ... rest of WebSocket handler ...
});

// ... rest of server code ...
```

## Testing Integration

### 1. Test Without Authentication

```bash
# Start server without authentication
npm run dev

# Should work without auth headers
curl http://localhost:11235/api/health
```

### 2. Test With Authentication Enabled (Not Required)

```bash
# Start server with auth enabled but not required
npm run dev -- --backstage-url https://backstage.example.com

# Should work without auth headers
curl http://localhost:11235/api/health

# Should also work with valid token
curl -H "Authorization: Bearer <token>" http://localhost:11235/api/terminals
```

### 3. Test With Required Authentication

```bash
# Start server with required auth
npm run dev -- \
  --backstage-url https://backstage.example.com \
  --backstage-require-auth true

# Should fail without auth
curl http://localhost:11235/api/terminals
# Response: {"error":"Authentication required","type":"MISSING_TOKEN"}

# Should work with valid token
curl -H "Authorization: Bearer <token>" http://localhost:11235/api/terminals
```

### 4. Test Authorization

```bash
# Start server with user restrictions
npm run dev -- \
  --backstage-url https://backstage.example.com \
  --backstage-require-auth true \
  --backstage-allowed-users "user:default/admin"

# Valid token but unauthorized user should fail
curl -H "Authorization: Bearer <unauthorized-token>" http://localhost:11235/api/terminals
# Response: {"error":"Access denied","type":"AUTHORIZATION_FAILED"}

# Authorized user should work
curl -H "Authorization: Bearer <admin-token>" http://localhost:11235/api/terminals
```

## Rollback Plan

If you need to disable authentication:

1. **Quick Disable**: Set `BACKSTAGE_URL` to empty or remove the flag
2. **Remove Integration**: Comment out the authentication initialization and middleware application
3. **Revert Changes**: Use git to revert to previous version

## Performance Impact

The authentication system has minimal performance impact:

- **JWKS Caching**: Keys are cached for 1 hour, reducing latency
- **In-Memory Rate Limiting**: No database queries
- **Minimal Overhead**: ~1-2ms per request for token validation

## Monitoring

Monitor authentication in production:

```javascript
// Add endpoint to check auth status
app.get('/api/auth/status', (req, res) => {
  if (!backstageAuth) {
    return res.json({ enabled: false });
  }

  const { authManager } = backstageAuth;
  const stats = authManager.jwksManager.getCacheStats();

  res.json({
    enabled: true,
    requireAuth: backstageAuth.config.requireAuth,
    jwksCache: stats,
    user: req.user ? {
      subject: req.user.subject,
      expiresAt: new Date(req.user.expiresAt * 1000).toISOString(),
    } : null,
  });
});
```

## Troubleshooting

### Authentication Not Working

1. Check that authentication modules are compiled:
   ```bash
   ls src/services/*.js src/middleware/*.js src/types/*.js
   ```

2. Verify configuration:
   ```bash
   npm run dev -- --backstage-url https://backstage.example.com
   ```

3. Check console output for initialization messages:
   ```
   [Backstage Auth] Initializing with configuration:
     URL: https://backstage.example.com
     ...
   ```

### Module Not Found Errors

If you see "Cannot find module" errors:

1. Ensure TypeScript files are compiled:
   ```bash
   npx tsc src/types/backstage-auth.ts src/services/*.ts src/middleware/*.ts \
     --module commonjs --target ES2020 --esModuleInterop --skipLibCheck
   ```

2. Verify JavaScript files exist:
   ```bash
   find src -name "*.js" | grep -E "(auth|jwks|token|identity)"
   ```

## Next Steps

After integration:

1. Test all authentication flows
2. Configure production environment variables
3. Set up monitoring and alerting
4. Document authentication requirements for users
5. Create integration tests
6. Update CI/CD pipelines

## Support

For issues:
- Review the [BACKSTAGE_AUTH_IMPLEMENTATION.md](./BACKSTAGE_AUTH_IMPLEMENTATION.md) documentation
- Check audit logs for detailed error information
- File an issue with logs and configuration details
