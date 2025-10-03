# Production Build Fix - NPM Package Configuration

## Problem
When running the package from npx, it failed with:
```
❌ Failed to load authentication middleware: Cannot find module './src/middleware/authentication'
```

This occurred because the middleware and service files weren't included in the published npm package.

## Root Cause
The `files` array in `package.json` was incomplete:
- Only included `src/services/*.ts` (TypeScript only, not JavaScript)
- Didn't include `src/middleware/` directory at all
- Missing some subdirectories in `src/lib/` and `src/types/`

## Solution

### Updated `package.json` files array (lines 41-64):

**Before:**
```json
"files": [
  "unified-server.js",
  "websocket-server.js",
  ".next/**/*",
  "public/**/*",
  "src/app/**/*",
  "src/lib/*.js",
  "src/services/*.ts",
  ...
]
```

**After:**
```json
"files": [
  "unified-server.js",
  "websocket-server.js",
  ".next/**/*",
  "public/**/*",
  "src/app/**/*",
  "src/lib/**/*.js",
  "src/lib/**/*.ts",
  "src/services/**/*.ts",
  "src/services/**/*.js",
  "src/middleware/**/*.ts",
  "src/middleware/**/*.js",
  "src/types/**/*.ts",
  ...
]
```

### Key Changes:
1. **Added middleware**: `src/middleware/**/*.ts` and `src/middleware/**/*.js`
2. **Added service JS**: `src/services/**/*.js` (previously only had TS)
3. **Added lib subdirs**: Changed `src/lib/*.js` to `src/lib/**/*.js` and added `src/lib/**/*.ts`
4. **Added types**: `src/types/**/*.ts` for TypeScript type definitions

## Verification

### Package Contents
The package now includes all required authentication files:

```bash
$ tar -tzf liamhelmer-claude-flow-ui-1.4.1.tgz | grep -E "(middleware|services).*\.(js|ts)$"

# Middleware files:
package/src/middleware/authentication.js
package/src/middleware/authentication.ts
package/src/middleware/authorization.js
package/src/middleware/authorization.ts
package/src/middleware/errorHandler.js
package/src/middleware/index.js

# Service files:
package/src/services/identity-resolver.js
package/src/services/identity-resolver.ts
package/src/services/jwks-manager.js
package/src/services/jwks-manager.ts
package/src/services/token-validator.js
package/src/services/token-validator.ts

# Type definitions:
package/src/types/backstage-auth.d.ts
package/src/types/backstage-auth.ts
```

### Package Size
- **Unpacked size**: 232.1 MB
- **Package size**: 98.7 MB
- **Total files**: 255

## Testing

### Local Test
```bash
# Create package
npm pack

# Verify files
tar -tzf liamhelmer-claude-flow-ui-1.4.1.tgz | grep middleware

# Install locally
npm install -g ./liamhelmer-claude-flow-ui-1.4.1.tgz

# Test
npx @liamhelmer/claude-flow-ui
```

### Expected Result
Server should start successfully with authentication middleware loaded:
```
🔒 Initializing Backstage authentication middleware...
✅ Backstage authentication middleware enabled (Express + Socket.IO)
```

## Build Scripts

### Pre-publish Hooks
The package.json includes hooks that ensure the build is always up to date:

```json
"prepublishOnly": "npm run lint && npm run build:static",
"prepack": "npm run build:static"
```

These run automatically before:
- `npm publish` (prepublishOnly)
- `npm pack` (prepack)

### Manual Build
```bash
# Development build
npm run build

# Production build (for publishing)
npm run build:static
```

## Publishing

```bash
# Dry run to verify
npm publish --dry-run

# Publish to npm
npm publish
```

## Files Included in Package

### Core Server Files
- `unified-server.js` - Main server
- `websocket-server.js` - WebSocket server
- `.next/**/*` - Next.js build output

### Source Files (for TypeScript/runtime)
- `src/app/**/*` - Next.js app pages
- `src/lib/**/*.{js,ts}` - Utility libraries
- `src/middleware/**/*.{js,ts}` - Authentication middleware
- `src/services/**/*.{js,ts}` - Service layer
- `src/types/**/*.ts` - TypeScript definitions

### Configuration Files
- `next.config.js`
- `postcss.config.js`
- `tailwind.config.ts`
- `tsconfig.json`

### Documentation
- `README.md`
- `USAGE.md`

## Excluded from Package

The `files` array excludes:
- `**/__tests__/**` - Test files
- `**/*.test.*` - Test files
- `**/*.spec.*` - Spec files

This keeps the package size smaller while including all runtime-necessary files.

## Related Issues Fixed

This also resolves:
1. WebSocket authentication not working in production
2. JWKS manager not found errors
3. Token validator import errors
4. Identity resolver module not found errors

All authentication-related modules are now properly bundled and accessible in the production package.
