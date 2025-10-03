# Backstage Authentication Configuration

This document provides a quick reference for configuring Backstage JWT authentication in claude-flow-ui.

## Configuration Methods

You can configure Backstage authentication using either **environment variables** or **CLI arguments**. CLI arguments take precedence over environment variables.

---

## 🔧 Configuration Options

### Core Settings

| CLI Argument | Environment Variable | Default | Description |
|-------------|---------------------|---------|-------------|
| `--backstage-url <url>` | `BACKSTAGE_URL` | `null` | Backstage base URL (e.g., `https://backstage.company.com`) |
| `--backstage-jwks-path <path>` | `BACKSTAGE_JWKS_PATH` | `/api/auth/.well-known/jwks.json` | Path to JWKS endpoint |
| `--backstage-require-auth <boolean>` | `BACKSTAGE_REQUIRE_AUTH` | `false` | Require authentication for all requests |

### Access Control

| CLI Argument | Environment Variable | Default | Description |
|-------------|---------------------|---------|-------------|
| `--backstage-allowed-users <refs>` | `BACKSTAGE_ALLOWED_USERS` | `[]` | Comma-separated list of allowed user entity refs |
| `--backstage-allowed-groups <refs>` | `BACKSTAGE_ALLOWED_GROUPS` | `[]` | Comma-separated list of allowed group entity refs |

### JWT Validation

| CLI Argument | Environment Variable | Default | Description |
|-------------|---------------------|---------|-------------|
| `--backstage-issuer <string>` | `BACKSTAGE_ISSUER` | `null` | Expected JWT issuer (e.g., `backstage`) |
| `--backstage-audience <string>` | `BACKSTAGE_AUDIENCE` | `null` | Expected JWT audience |

### Performance & Security

| CLI Argument | Environment Variable | Default | Description |
|-------------|---------------------|---------|-------------|
| `--backstage-jwks-cache-ttl <ms>` | `BACKSTAGE_JWKS_CACHE_TTL` | `3600000` | JWKS cache TTL in milliseconds (1 hour) |
| `--backstage-rate-limit-max <number>` | `BACKSTAGE_RATE_LIMIT_MAX` | `100` | Maximum requests per window |
| `--backstage-rate-limit-window <ms>` | `BACKSTAGE_RATE_LIMIT_WINDOW` | `900000` | Rate limit window in milliseconds (15 min) |
| `--backstage-clock-tolerance <seconds>` | `BACKSTAGE_CLOCK_TOLERANCE` | `30` | Clock skew tolerance in seconds |
| `--backstage-audit-log-max <number>` | `BACKSTAGE_AUDIT_LOG_MAX` | `1000` | Maximum audit log entries to retain |

---

## 📝 Usage Examples

### Example 1: Basic Setup with Environment Variables

```bash
# Set environment variables
export BACKSTAGE_URL="https://backstage.company.com"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team,group:default/developers"

# Start the server
npx claude-flow-ui
```

### Example 2: CLI Arguments (Recommended)

```bash
npx claude-flow-ui \
  --backstage-url https://backstage.company.com \
  --backstage-allowed-groups "group:default/platform-team,group:default/developers"
```

### Example 3: Specific Users and Groups

```bash
npx claude-flow-ui \
  --backstage-url https://backstage.company.com \
  --backstage-allowed-users "user:default/jane.doe,user:default/john.smith" \
  --backstage-allowed-groups "group:default/admins"
```

### Example 4: Required Authentication with Custom Settings

```bash
npx claude-flow-ui \
  --backstage-url https://backstage.company.com \
  --backstage-require-auth true \
  --backstage-issuer "backstage" \
  --backstage-audience "claude-flow-ui" \
  --backstage-allowed-groups "group:default/platform-team"
```

### Example 5: Environment Variables for Production

```bash
# .env file
BACKSTAGE_URL=https://backstage.company.com
BACKSTAGE_REQUIRE_AUTH=true
BACKSTAGE_ISSUER=backstage
BACKSTAGE_AUDIENCE=claude-flow-ui
BACKSTAGE_ALLOWED_GROUPS=group:default/platform-team,group:default/sre
BACKSTAGE_RATE_LIMIT_MAX=200
BACKSTAGE_RATE_LIMIT_WINDOW=600000
```

Then start with:
```bash
source .env
npx claude-flow-ui
```

### Example 6: Passing Claude Flow Arguments

Use `--` to separate claude-flow-ui arguments from claude-flow arguments:

```bash
npx claude-flow-ui \
  --backstage-url https://backstage.company.com \
  --backstage-allowed-groups "group:default/devs" \
  -- hive start --objective "Build authentication system"
```

---

## 🔍 Entity Reference Format

Backstage uses entity references in the format: `kind:namespace/name`

### Common Entity Kinds

- **User**: `user:default/jane.doe`
- **Group**: `group:default/platform-team`
- **Component**: `component:default/my-service`

### Examples

**Allow specific users:**
```bash
--backstage-allowed-users "user:default/jane.doe,user:default/john.smith"
```

**Allow specific groups:**
```bash
--backstage-allowed-groups "group:default/platform-team,group:default/sre"
```

**Mixed access control:**
```bash
--backstage-allowed-users "user:default/admin" \
--backstage-allowed-groups "group:default/developers"
```

---

## 🔐 Authentication Flow

1. **Client sends request** with `Authorization: Bearer <jwt-token>` header
2. **Server extracts token** from Authorization header
3. **Server fetches JWKS** from Backstage (cached for 1 hour by default)
4. **Server verifies JWT signature** using public key from JWKS
5. **Server validates claims** (exp, nbf, iss, aud)
6. **Server checks authorization** (user/group allowlists)
7. **Server enforces rate limits** (100 req/15min per user by default)
8. **Request proceeds** or returns 401/403 error

---

## ⚠️ Important Notes

1. **HTTPS Required in Production**: Always use HTTPS for Backstage URL in production
2. **Case Sensitivity**: Entity references are case-insensitive
3. **Multiple Groups**: Users inherit permissions from all their groups
4. **Default Deny**: If allowlists are configured, only listed users/groups are allowed
5. **Environment Variables**: Perfect for containerized deployments
6. **CLI Arguments**: Better for local development and testing

---

## 🧪 Testing Configuration

Test your configuration with curl:

```bash
# Get a token from Backstage
TOKEN="your-jwt-token-here"

# Test authenticated request
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/terminals/spawn

# Should return 200 if authorized, 401/403 if not
```

---

## 📊 Monitoring

The server logs authentication events:

```
🔐 Backstage Authentication Configuration:
   URL: https://backstage.company.com
   JWKS Path: /api/auth/.well-known/jwks.json
   Allowed Groups: group:default/platform-team
   Authentication Required: false
   Rate Limit: 100 requests per 15 minutes
```

Authentication failures are logged with audit trail:
```
[Audit] authentication_failure: user:default/jane.doe (IP: 192.168.1.100)
[Audit] rate_limit_exceeded: user:default/john.smith (IP: 192.168.1.101)
```

---

## 🚀 Quick Start

**For development:**
```bash
npx claude-flow-ui \
  --backstage-url https://backstage.company.com \
  --backstage-allowed-groups "group:default/developers"
```

**For production:**
```bash
export BACKSTAGE_URL="https://backstage.company.com"
export BACKSTAGE_REQUIRE_AUTH="true"
export BACKSTAGE_ISSUER="backstage"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team"
npx claude-flow-ui
```

---

## 📚 Additional Resources

- [Backstage Identity Resolver Documentation](https://backstage.io/docs/auth/identity-resolver)
- [Full Implementation Guide](./BACKSTAGE_AUTH_IMPLEMENTATION.md)
- [Architecture Documentation](./backstage-jwt-architecture.md)
- [Quick Start Guide](./BACKSTAGE_AUTH_QUICK_START.md)
