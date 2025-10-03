# Backstage Argument Parsing Fix

## Problem

When running `npx claude-flow-ui --backstage-url XXX --backstage-allowed-groups XXX`, the Backstage-specific arguments were being incorrectly passed to claude-flow instead of being consumed by claude-flow-ui.

## Solution

Updated `unified-server.js` to properly parse Backstage arguments before passing remaining arguments to claude-flow.

## Changes Made

### 1. Added Backstage Configuration Object

```javascript
// Backstage authentication configuration
let backstageConfig = {
  url: process.env.BACKSTAGE_URL || null,
  jwksPath: process.env.BACKSTAGE_JWKS_PATH || '/api/auth/.well-known/jwks.json',
  allowedUsers: process.env.BACKSTAGE_ALLOWED_USERS ? process.env.BACKSTAGE_ALLOWED_USERS.split(',') : [],
  allowedGroups: process.env.BACKSTAGE_ALLOWED_GROUPS ? process.env.BACKSTAGE_ALLOWED_GROUPS.split(',') : [],
  requireAuth: process.env.BACKSTAGE_REQUIRE_AUTH === 'true' || process.env.BACKSTAGE_REQUIRE_AUTH === '1',
  issuer: process.env.BACKSTAGE_ISSUER || null,
  audience: process.env.BACKSTAGE_AUDIENCE || null,
  // ... additional config options
};
```

### 2. Updated Argument Parser

The argument parser now extracts all `--backstage-*` arguments before passing remaining args to claude-flow:

```javascript
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--backstage-url' && i + 1 < args.length) {
    backstageConfig.url = args[i + 1];
    i++; // Skip next arg
  } else if (args[i] === '--backstage-allowed-groups' && i + 1 < args.length) {
    backstageConfig.allowedGroups = args[i + 1].split(',').map(g => g.trim());
    i++; // Skip next arg
  }
  // ... other backstage arguments
  else {
    // Non-backstage args go to claude-flow
    claudeFlowArgs.push(args[i]);
  }
}
```

### 3. Added Configuration Logging

```javascript
if (backstageConfig.url || backstageConfig.requireAuth) {
  console.log('🔐 Backstage Authentication Configuration:');
  console.log(`   URL: ${backstageConfig.url}`);
  console.log(`   Allowed Groups: ${backstageConfig.allowedGroups.join(', ')}`);
  // ... other config logging
}
```

## Supported CLI Arguments

All arguments support both CLI flags and environment variables:

| CLI Argument | Environment Variable |
|-------------|---------------------|
| `--backstage-url` | `BACKSTAGE_URL` |
| `--backstage-jwks-path` | `BACKSTAGE_JWKS_PATH` |
| `--backstage-allowed-users` | `BACKSTAGE_ALLOWED_USERS` |
| `--backstage-allowed-groups` | `BACKSTAGE_ALLOWED_GROUPS` |
| `--backstage-require-auth` | `BACKSTAGE_REQUIRE_AUTH` |
| `--backstage-issuer` | `BACKSTAGE_ISSUER` |
| `--backstage-audience` | `BACKSTAGE_AUDIENCE` |
| `--backstage-jwks-cache-ttl` | `BACKSTAGE_JWKS_CACHE_TTL` |
| `--backstage-rate-limit-max` | `BACKSTAGE_RATE_LIMIT_MAX` |
| `--backstage-rate-limit-window` | `BACKSTAGE_RATE_LIMIT_WINDOW` |
| `--backstage-clock-tolerance` | `BACKSTAGE_CLOCK_TOLERANCE` |
| `--backstage-audit-log-max` | `BACKSTAGE_AUDIT_LOG_MAX` |

## Usage Examples

### ✅ Correct Usage (After Fix)

**CLI arguments:**
```bash
npx claude-flow-ui \
  --backstage-url https://backstage.company.com \
  --backstage-allowed-groups "group:default/platform-team" \
  hive start --objective "Build auth system"
```

**Environment variables:**
```bash
export BACKSTAGE_URL="https://backstage.company.com"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team"
npx claude-flow-ui hive start --objective "Build auth system"
```

**Mixed (CLI overrides env vars):**
```bash
export BACKSTAGE_URL="https://dev.backstage.com"
npx claude-flow-ui \
  --backstage-url https://prod.backstage.com \
  --backstage-allowed-groups "group:default/admins"
```

### ❌ Previous Behavior (Before Fix)

```bash
npx claude-flow-ui --backstage-url https://backstage.company.com
# ❌ Backstage args were passed to claude-flow, causing errors
```

## Testing

### Test 1: Argument Parsing

```bash
npx claude-flow-ui \
  --backstage-url https://backstage.test.com \
  --backstage-allowed-groups "group:default/devs"
```

**Expected Output:**
```
🔐 Backstage Authentication Configuration:
   URL: https://backstage.test.com
   JWKS Path: /api/auth/.well-known/jwks.json
   Allowed Groups: group:default/devs
   Authentication Required: false
   Rate Limit: 100 requests per 15 minutes
```

### Test 2: Environment Variables

```bash
export BACKSTAGE_URL="https://backstage.test.com"
export BACKSTAGE_ALLOWED_USERS="user:default/jane.doe"
npx claude-flow-ui
```

**Expected Output:**
```
🔐 Backstage Authentication Configuration:
   URL: https://backstage.test.com
   JWKS Path: /api/auth/.well-known/jwks.json
   Allowed Users: user:default/jane.doe
   Authentication Required: false
   Rate Limit: 100 requests per 15 minutes
```

### Test 3: Combined with Claude Flow Arguments

```bash
npx claude-flow-ui \
  --backstage-url https://backstage.test.com \
  hive start --objective "Test"
```

**Expected:**
- Backstage config parsed: ✅
- Claude Flow receives: `["hive", "start", "--objective", "Test"]` ✅

## Benefits

1. **Clear Separation**: Backstage arguments are clearly separated from claude-flow arguments
2. **Flexibility**: Support for both CLI arguments and environment variables
3. **Production-Ready**: Environment variables perfect for containerized deployments
4. **Developer-Friendly**: CLI arguments better for local development and testing
5. **Visibility**: Configuration logging shows exactly what's configured

## Documentation

Created comprehensive documentation:

1. **`BACKSTAGE_AUTH_CONFIG.md`** - Complete configuration reference with all options
2. **`BACKSTAGE_AUTH_QUICK_START.md`** - Updated with correct usage examples
3. **`BACKSTAGE_ARG_PARSING_FIX.md`** - This document

## Files Modified

- `unified-server.js` - Lines 16-261 (added Backstage config parsing and logging)

## Backward Compatibility

✅ **Fully backward compatible** - existing deployments without Backstage authentication continue to work normally.

## Next Steps

To use Backstage authentication:

1. **Set environment variables** (recommended for production):
   ```bash
   export BACKSTAGE_URL="https://backstage.company.com"
   export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team"
   ```

2. **Or use CLI arguments** (recommended for development):
   ```bash
   npx claude-flow-ui \
     --backstage-url https://backstage.company.com \
     --backstage-allowed-groups "group:default/platform-team"
   ```

3. **Integrate authentication middleware** (see `BACKSTAGE_AUTH_IMPLEMENTATION.md`)

## References

- Full configuration guide: `docs/BACKSTAGE_AUTH_CONFIG.md`
- Quick start guide: `docs/BACKSTAGE_AUTH_QUICK_START.md`
- Implementation guide: `docs/BACKSTAGE_AUTH_IMPLEMENTATION.md`
- Architecture documentation: `docs/backstage-jwt-architecture.md`
