# Backstage JWT Authentication - Quick Start Guide

## 🚀 Quick Start

### Basic Setup (5 minutes)

**Using CLI arguments (recommended):**
```bash
# 1. Start server with Backstage authentication
npx claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-allowed-groups "group:default/platform-team"

# 2. Use with authentication token
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/terminals
```

**Using environment variables:**
```bash
# 1. Set environment variables
export BACKSTAGE_URL="https://backstage.example.com"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team"

# 2. Start server
npx claude-flow-ui

# 3. Use with authentication token
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/terminals
```

### Production Setup (10 minutes)

```bash
# 1. Create environment file
cat > .env.production <<EOF
BACKSTAGE_URL=https://backstage.example.com
BACKSTAGE_REQUIRE_AUTH=true
BACKSTAGE_ISSUER=backstage
BACKSTAGE_AUDIENCE=claude-flow-ui
BACKSTAGE_ALLOWED_GROUPS=group:default/devops,group:default/admins
BACKSTAGE_RATE_LIMIT_MAX=100
BACKSTAGE_RATE_LIMIT_WINDOW=900000
EOF

# 2. Start server
source .env.production
claude-flow-ui

# 3. Test authentication
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:11235/api/terminals
```

## 📋 Configuration Cheat Sheet

### Required Options

```bash
--backstage-url <url>              # Backstage base URL
```

### Recommended Options

```bash
--backstage-require-auth true      # Require auth for all requests
--backstage-allowed-groups <refs>  # Restrict to specific groups
```

### All Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--backstage-url` | `BACKSTAGE_URL` | - | Backstage base URL (required) |
| `--backstage-require-auth` | `BACKSTAGE_REQUIRE_AUTH` | `false` | Require authentication |
| `--backstage-issuer` | `BACKSTAGE_ISSUER` | - | Expected JWT issuer |
| `--backstage-audience` | `BACKSTAGE_AUDIENCE` | - | Expected JWT audience |
| `--backstage-allowed-users` | `BACKSTAGE_ALLOWED_USERS` | - | Comma-separated user refs |
| `--backstage-allowed-groups` | `BACKSTAGE_ALLOWED_GROUPS` | - | Comma-separated group refs |
| `--backstage-jwks-path` | `BACKSTAGE_JWKS_PATH` | `/api/auth/.well-known/jwks.json` | JWKS endpoint |
| `--backstage-rate-limit-max` | `BACKSTAGE_RATE_LIMIT_MAX` | `100` | Max requests per window |
| `--backstage-rate-limit-window` | `BACKSTAGE_RATE_LIMIT_WINDOW` | `900000` | Window duration (ms) |

## 🔐 Usage Examples

### 1. Development (No Auth Required)

```bash
# Auth enabled but not required - best for development
npx claude-flow-ui --backstage-url https://backstage.example.com
```

**Use Cases**:
- Local development
- Testing without tokens
- Gradual rollout

### 2. Combining Backstage Auth with Claude Flow Arguments

```bash
# Backstage args come BEFORE any Claude Flow commands
npx claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-allowed-groups "group:default/platform-team" \
  hive start --objective "Build authentication system"

# The arguments are parsed as:
# - Backstage: --backstage-url, --backstage-allowed-groups
# - Claude Flow: hive start --objective "Build authentication system"
```

**Important**: Backstage arguments (all starting with `--backstage-`) are extracted FIRST, then remaining arguments are passed to claude-flow.

### 3. Production (Auth Required)

```bash
# Auth required for all requests
claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-require-auth true \
  --backstage-allowed-groups "group:default/devops"
```

**Use Cases**:
- Production environments
- Sensitive data access
- Compliance requirements

### 3. User-Based Access Control

```bash
# Allow specific users only
claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-require-auth true \
  --backstage-allowed-users "user:default/admin,user:default/john.doe"
```

**Use Cases**:
- Admin-only access
- Specific user testing
- Granular control

### 4. Group-Based Access Control

```bash
# Allow specific groups only
claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-require-auth true \
  --backstage-allowed-groups "group:default/devops,group:default/admins"
```

**Use Cases**:
- Team-based access
- Department restrictions
- Role-based access

### 5. Full Security Configuration

```bash
# Maximum security settings
claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-require-auth true \
  --backstage-issuer backstage \
  --backstage-audience claude-flow-ui \
  --backstage-allowed-groups "group:default/admins" \
  --backstage-rate-limit-max 50 \
  --backstage-rate-limit-window 900000
```

**Use Cases**:
- High-security environments
- Production deployments
- Compliance requirements

## 🌐 Client Integration

### HTTP API

```javascript
// JavaScript/TypeScript
const response = await fetch('http://localhost:11235/api/terminals', {
  headers: {
    'Authorization': `Bearer ${jwtToken}`
  }
});
```

```python
# Python
import requests

response = requests.get(
    'http://localhost:11235/api/terminals',
    headers={'Authorization': f'Bearer {jwt_token}'}
)
```

```bash
# curl
curl -H "Authorization: Bearer ${JWT_TOKEN}" \
  http://localhost:11235/api/terminals
```

### WebSocket

```javascript
// Socket.IO Client
import { io } from 'socket.io-client';

// Method 1: Auth object (recommended)
const socket = io('http://localhost:11235', {
  path: '/api/ws',
  auth: {
    token: jwtToken
  }
});

// Method 2: Query parameter
const socket = io('http://localhost:11235', {
  path: '/api/ws',
  query: {
    token: jwtToken
  }
});
```

## 🔍 Testing

### 1. Test Without Authentication

```bash
# Should work (health check is always public)
curl http://localhost:11235/api/health

# Expected: {"status":"ok",...}
```

### 2. Test With Invalid Token

```bash
# Should fail with 401
curl -H "Authorization: Bearer invalid-token" \
  http://localhost:11235/api/terminals

# Expected: {"error":"Invalid token signature","type":"INVALID_SIGNATURE"}
```

### 3. Test With Valid Token

```bash
# Get a valid token from Backstage
export TOKEN=$(backstage-cli auth --get-token)

# Should work
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:11235/api/terminals

# Expected: [{"id":"...","name":"..."}]
```

### 4. Test Authorization

```bash
# With unauthorized user (should fail with 403)
curl -H "Authorization: Bearer $UNAUTHORIZED_TOKEN" \
  http://localhost:11235/api/terminals

# Expected: {"error":"Access denied","type":"AUTHORIZATION_FAILED"}

# With authorized user (should work)
curl -H "Authorization: Bearer $AUTHORIZED_TOKEN" \
  http://localhost:11235/api/terminals

# Expected: [{"id":"...","name":"..."}]
```

## 🚨 Troubleshooting

### Issue: "Authentication required"

**Cause**: No token provided and `--backstage-require-auth true` is set

**Solution**:
```bash
# Provide token in Authorization header
curl -H "Authorization: Bearer YOUR_TOKEN" ...
```

### Issue: "Invalid token signature"

**Cause**: Token not signed by Backstage or JWKS fetch failed

**Solutions**:
1. Verify `--backstage-url` is correct
2. Check network connectivity to Backstage
3. Verify JWKS endpoint is accessible
4. Check server logs for JWKS fetch errors

### Issue: "Access denied"

**Cause**: User not in allowed users or groups

**Solutions**:
1. Check user entity reference: `user:default/username`
2. Verify group memberships in Backstage
3. Update `--backstage-allowed-users` or `--backstage-allowed-groups`
4. Check server logs for authorization details

### Issue: "Too many requests"

**Cause**: Rate limit exceeded

**Solutions**:
1. Wait for rate limit window to reset (default: 15 minutes)
2. Increase `--backstage-rate-limit-max`
3. Adjust `--backstage-rate-limit-window`
4. Check for client retry loops

## 📊 Monitoring

### Check Authentication Status

```bash
# Add this endpoint to unified-server.js for monitoring
curl http://localhost:11235/api/auth/status

# Response:
# {
#   "enabled": true,
#   "requireAuth": true,
#   "jwksCache": {
#     "cached": true,
#     "keysCount": 2,
#     "expiresAt": "2025-10-02T15:00:00Z"
#   },
#   "user": {
#     "subject": "user:default/john.doe",
#     "expiresAt": "2025-10-02T14:00:00Z"
#   }
# }
```

### View Audit Logs

Audit logs are stored in memory. Access them programmatically:

```javascript
// In unified-server.js
const { authManager } = backstageAuth;
const logs = authManager.getAuditLogs(100);
console.log(logs);
```

## 🎯 Common Patterns

### Pattern 1: Development to Production

```bash
# Development: Optional auth
export BACKSTAGE_URL=https://backstage-dev.example.com
claude-flow-ui

# Staging: Required auth, specific groups
export BACKSTAGE_URL=https://backstage-staging.example.com
export BACKSTAGE_REQUIRE_AUTH=true
export BACKSTAGE_ALLOWED_GROUPS=group:default/qa
claude-flow-ui

# Production: Required auth, strict limits
export BACKSTAGE_URL=https://backstage.example.com
export BACKSTAGE_REQUIRE_AUTH=true
export BACKSTAGE_ALLOWED_GROUPS=group:default/admins
export BACKSTAGE_RATE_LIMIT_MAX=50
claude-flow-ui
```

### Pattern 2: Multi-Environment Configuration

```bash
# .env.development
BACKSTAGE_URL=https://backstage-dev.example.com
BACKSTAGE_REQUIRE_AUTH=false

# .env.staging
BACKSTAGE_URL=https://backstage-staging.example.com
BACKSTAGE_REQUIRE_AUTH=true
BACKSTAGE_ALLOWED_GROUPS=group:default/qa,group:default/devops

# .env.production
BACKSTAGE_URL=https://backstage.example.com
BACKSTAGE_REQUIRE_AUTH=true
BACKSTAGE_ISSUER=backstage
BACKSTAGE_AUDIENCE=claude-flow-ui
BACKSTAGE_ALLOWED_GROUPS=group:default/admins
BACKSTAGE_RATE_LIMIT_MAX=50
```

### Pattern 3: Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY . .
RUN npm install

# Set authentication environment variables
ENV BACKSTAGE_URL=https://backstage.example.com
ENV BACKSTAGE_REQUIRE_AUTH=true
ENV BACKSTAGE_ALLOWED_GROUPS=group:default/devops

EXPOSE 11235
CMD ["node", "unified-server.js"]
```

## 📚 Additional Resources

- [Full Implementation Guide](./BACKSTAGE_AUTH_IMPLEMENTATION.md)
- [Integration Instructions](./UNIFIED_SERVER_INTEGRATION.md)
- [Implementation Summary](./IMPLEMENTATION_SUMMARY.md)
- [Backstage Authentication Docs](https://backstage.io/docs/auth/)

## 🆘 Getting Help

1. **Check Documentation**: Review the full implementation guide
2. **Check Logs**: Look at server logs for detailed errors
3. **Check Audit Logs**: Review audit logs for authentication events
4. **File Issue**: Create GitHub issue with logs and configuration

---

**Quick Tip**: Start with `--backstage-require-auth false` for testing, then enable required auth once everything works.
