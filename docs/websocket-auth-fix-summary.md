# WebSocket Authentication Fix Summary

## Problem
WebSocket connections were failing authentication despite a valid JWT token being available in sessionStorage. The error message was "no token provided" even though the client was attempting to send the token.

## Root Cause
1. **Improper Authentication Architecture**: Server was using manual authentication checks in the connection handler instead of Socket.IO middleware
2. **Token Not Being Transmitted**: The client's auth callback might not have been working as expected
3. **Missing Fallback**: No query parameter fallback for token transmission

## Solutions Implemented

### 1. Client-Side Changes (`src/lib/websocket/client.ts`)

**Enhanced Token Transmission**:
- Added **both** auth callback AND query parameter approaches
- Socket.IO v4 supports both methods, providing maximum compatibility
- Added detailed debug logging to trace token flow

```typescript
auth: (cb) => {
  const freshToken = sessionStorage.getItem('backstage_jwt_token');
  console.debug('[WebSocket] 🔐 Auth callback executed, token present:', !!freshToken);
  if (freshToken) {
    console.debug('[WebSocket] 📤 Sending token via auth callback');
    cb({ token: freshToken });
  } else {
    cb({});
  }
},
query: authToken ? { token: authToken } : undefined,
```

**Benefits**:
- Fresh token retrieved on each connection attempt (via callback)
- Query parameter provides fallback if callback fails
- Enhanced logging for debugging

### 2. Server-Side Changes (`unified-server.js`)

**Socket.IO Middleware Approach** (lines 347-385):
- Implemented proper Socket.IO middleware using `io.use()`
- Middleware executes **before** connection handlers
- This is the recommended approach for Socket.IO v4

```javascript
io.use(async (socket, next) => {
  try {
    // Extract token from handshake auth or query
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;

    if (!token) {
      const err = new Error('Authentication required');
      err.data = { type: 'auth-error', message: 'Please provide a valid JWT token' };
      return next(err);
    }

    // Validate token
    const authResult = await websocketAuthHandler(token);

    if (!authResult.authenticated) {
      const err = new Error(authResult.message || 'Authentication failed');
      err.data = { type: 'auth-error', error: authResult.error };
      return next(err);
    }

    // Store user info
    socket.data.user = authResult.user;
    next();
  } catch (error) {
    const err = new Error('Authentication failed');
    err.data = { type: 'auth-error' };
    next(err);
  }
});
```

**Removed Duplicate Auth Logic** (lines 1023-1033):
- Removed manual authentication check from connection handler
- Authentication now handled by middleware only
- Connection handler can safely assume socket is authenticated

**Benefits**:
- Cleaner separation of concerns
- Authentication happens before connection established
- Better error handling with Socket.IO error protocol
- Prevents unauthenticated connections from reaching handlers

### 3. Algorithm Support (`src/services/token-validator.ts`)

**Earlier Fix**:
- Added ES256/384/512 (Elliptic Curve) algorithm support
- Previously only supported RS256/384/512 (RSA)

```typescript
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
  issuer: this.config.issuer,
  audience: this.config.audience,
  clockTolerance: 30,
}) as BackstageJWTPayload;
```

## Testing

### Manual Test Script
Created `docs/test-websocket-auth.js` to verify the complete flow:

```bash
node docs/test-websocket-auth.js
```

Expected output:
```
✅ Connected successfully!
   Socket ID: xxxxx
🎉 WebSocket authentication is working correctly!
```

### Start Server with Authentication
```bash
NODE_ENV=production \
CLAUDE_FLOW_MODE=hive-mind \
TERMINAL_SIZE=120x40 \
PORT=9011 \
BACKSTAGE_REQUIRE_AUTH=true \
BACKSTAGE_ALLOWED_GROUPS=group:default/badal-everyone \
BACKSTAGE_URL=http://localhost:7007 \
npm exec claude-flow-ui
```

## Architecture Improvements

### Before:
```
Client → Socket.IO Connection → Server checks auth manually
                                 ↓
                          Manual disconnect if invalid
```

### After:
```
Client → Socket.IO Middleware → Validates auth
                                 ↓
                          Authenticated socket → Connection handler
```

## Debug Logging

Enhanced logging helps diagnose issues:

**Client logs**:
- `[WebSocket] 🔐 Auth callback executed`
- `[WebSocket] 📤 Sending token via auth callback`

**Server logs**:
- `[WS Middleware] Checking authentication for socket`
- `[WS Middleware] Token from auth: true/false`
- `[WS Middleware] Token from query: true/false`
- `[WS Middleware] ✅ Socket authenticated - user: xxx`

## Related Files

### Modified:
- `src/lib/websocket/client.ts` - Client WebSocket auth
- `unified-server.js` - Server Socket.IO middleware
- `src/services/token-validator.ts` - ES256 algorithm support
- `src/services/token-validator.js` - Manual ES256 support update

### Created:
- `docs/test-websocket-auth.js` - Test script
- `docs/websocket-auth-fix-summary.md` - This document

## Key Takeaways

1. **Use Socket.IO Middleware**: Always use `io.use()` for authentication in Socket.IO v4+
2. **Multiple Token Paths**: Support both `auth` callback and `query` parameters for compatibility
3. **Debug Logging**: Comprehensive logging is essential for debugging auth issues
4. **Algorithm Support**: Ensure JWT validator supports all algorithms your IDP uses (RS*, ES*)
5. **TypeScript Compilation**: Remember to recompile TypeScript or manually update JavaScript in production

## Next Steps

1. Start the server with authentication enabled
2. Run the test script to verify WebSocket auth works
3. Open the UI and log in with a Backstage token
4. Verify WebSocket connection succeeds in browser console
5. Monitor server logs for successful authentication messages
