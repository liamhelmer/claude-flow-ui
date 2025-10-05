# URL-Based Authentication

Claude Flow UI supports automatic authentication via URL parameters, enabling seamless integration with Backstage and other platforms that can generate authenticated links.

## Overview

Users can be automatically logged in by including a JWT token in the URL as a query parameter. This is particularly useful for:

- **Backstage Integration**: Generate links from Backstage that automatically authenticate users
- **Deep Linking**: Create shareable links that include authentication
- **SSO Flows**: Redirect users from SSO providers with tokens
- **API Integration**: Programmatically generate authenticated links

## Usage

### Basic Usage

To authenticate a user, append the `backstage_token` parameter to any URL:

```
https://your-app.com/?backstage_token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
```

The application will:
1. Extract the token from the URL
2. Store it in `sessionStorage`
3. Remove the token from the URL (security best practice)
4. Use the token for all subsequent API calls

### Backstage Integration

In your Backstage catalog configuration, you can create links that automatically authenticate users:

```yaml
# catalog-info.yaml
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: my-component
  annotations:
    # Link to Claude Flow UI with auto-auth
    claude-flow-ui/url: https://claude-flow-ui.example.com/?backstage_token=${BACKSTAGE_TOKEN}
```

Or in a Backstage plugin:

```typescript
import { useApi, backstageAuthApiRef } from '@backstage/core-plugin-api';

function MyComponent() {
  const authApi = useApi(backstageAuthApiRef);

  const openClaudeFlowUI = async () => {
    const token = await authApi.getBackstageIdentity().then(id => id.token);
    const url = `https://claude-flow-ui.example.com/?backstage_token=${token}`;
    window.open(url, '_blank');
  };

  return <Button onClick={openClaudeFlowUI}>Open Claude Flow UI</Button>;
}
```

## Security Considerations

### URL Cleanup

The token is **automatically removed from the URL** after being extracted to prevent:
- Token exposure in browser history
- Token leakage in server logs
- Accidental sharing of authenticated URLs

The URL is cleaned using `window.history.replaceState()`:

```
Before:  https://your-app.com/?backstage_token=eyJhbG...
After:   https://your-app.com/
```

### Token Storage

Tokens are stored in `sessionStorage` (not `localStorage`):
- **Session-scoped**: Tokens are cleared when the browser tab is closed
- **Tab-isolated**: Each browser tab has its own token
- **No persistence**: Tokens don't survive browser restarts

### HTTPS Requirement

**Always use HTTPS in production** to prevent token interception during transmission.

## Configuration

### Custom Parameter Name

By default, the parameter name is `backstage_token`, but you can customize it in the authentication utilities:

```typescript
import { handleUrlAuthentication } from '@/lib/auth';

// Use a custom parameter name
const tokenFound = handleUrlAuthentication('custom_token');
```

### Token Validation

The server validates all tokens using:
- JWT signature verification (ES256, RS256, etc.)
- Expiration checks
- Issuer validation
- Audience validation (if configured)
- Group membership checks (if configured)

Invalid or expired tokens result in a 401 Unauthorized response.

## API Reference

### `handleUrlAuthentication(paramName?: string): boolean`

Handles automatic authentication from URL parameters.

**Parameters:**
- `paramName` (optional): Query parameter name (default: `'backstage_token'`)

**Returns:**
- `true` if token was found and stored
- `false` if no token was found

**Example:**
```typescript
import { handleUrlAuthentication } from '@/lib/auth';

useEffect(() => {
  const authenticated = handleUrlAuthentication();
  if (authenticated) {
    console.log('User authenticated from URL');
  }
}, []);
```

### `extractTokenFromUrl(paramName?: string): string | null`

Extracts token from URL without storing it.

**Parameters:**
- `paramName` (optional): Query parameter name (default: `'backstage_token'`)

**Returns:**
- Token string if found, `null` otherwise

### `removeTokenFromUrl(paramName?: string): void`

Removes token parameter from URL.

**Parameters:**
- `paramName` (optional): Query parameter name (default: `'backstage_token'`)

## Examples

### React Component

```typescript
'use client';

import { useEffect } from 'react';
import { handleUrlAuthentication, isAuthenticated } from '@/lib/auth';

export default function MyPage() {
  useEffect(() => {
    // Handle URL-based authentication
    handleUrlAuthentication();
  }, []);

  if (!isAuthenticated()) {
    return <div>Please log in</div>;
  }

  return <div>Welcome!</div>;
}
```

### Generating Authenticated Links

```typescript
function generateAuthenticatedLink(token: string, path: string = '/'): string {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:8080';
  const url = new URL(path, baseUrl);
  url.searchParams.set('backstage_token', token);
  return url.toString();
}

// Usage
const link = generateAuthenticatedLink(userToken, '/');
// Result: http://localhost:8080/?backstage_token=eyJhbG...
```

### Testing Locally

1. Get a valid JWT token from Backstage:
```bash
# In Backstage, extract your token
curl http://localhost:7007/api/auth/backstage/refresh \
  -H "Cookie: backstage-auth=..." \
  | jq -r '.backstageIdentity.token'
```

2. Use it in the URL:
```
http://localhost:8080/?backstage_token=YOUR_TOKEN_HERE
```

3. The application will log:
```
[HomePage] 🔐 Authenticated from URL parameter
[Auth] Token stored, URL cleaned
```

## Troubleshooting

### Token Not Working

**Check token validity:**
```typescript
import { parseJwtPayload, isTokenExpired } from '@/lib/auth';

const payload = parseJwtPayload(token);
console.log('Token payload:', payload);
console.log('Token expired:', isTokenExpired(token));
```

**Common issues:**
- Token expired (check `exp` claim)
- Invalid signature (wrong JWKS keys)
- Missing required claims (`sub`, `iss`, etc.)
- Group membership not in `BACKSTAGE_ALLOWED_GROUPS`

### Token Not Being Extracted

**Check browser console:**
- Look for `[Auth] Found token in URL` message
- Verify query parameter name matches (`backstage_token`)
- Ensure JavaScript is enabled

### Authentication Required Errors

**Verify server configuration:**
```bash
# Check environment variables
echo $BACKSTAGE_REQUIRE_AUTH  # Should be 'true'
echo $BACKSTAGE_URL          # Should point to Backstage
echo $BACKSTAGE_ALLOWED_GROUPS  # Optional group filter
```

## Related Documentation

- [Authentication Middleware](./authentication-middleware.md)
- [Backstage JWT Integration](./backstage-jwt.md)
- [Security Best Practices](./security.md)

## References

- [Backstage Authentication](https://backstage.io/docs/auth/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [sessionStorage API](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage)
