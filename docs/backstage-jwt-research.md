# Backstage JWT Authentication & JWKS Validation Research

**Research Date:** October 2, 2025
**Researcher:** Hive Mind Swarm - Research Agent
**Session ID:** swarm-1759436777684-0ofm1ral3

---

## Executive Summary

This document provides comprehensive research findings on Backstage JWT authentication, JWKS validation, identity resolver patterns, Node.js/TypeScript implementation best practices, and security considerations for implementing JWT-based authentication in Backstage applications.

---

## 1. Backstage JWT Authentication Overview

### 1.1 Authentication Methods

Backstage supports **four primary authentication methods** for service-to-service communication:

1. **Standard Plugin-to-Plugin Authentication**
   - Automatically generates self-signed tokens between backend plugins
   - Secure by default without additional configuration
   - Uses `auth` and `httpAuth` service APIs
   - Token generation: `auth.getPluginRequestToken({onBehalfOf: credentials, targetPluginId: '<plugin-id>'})`

2. **Static Tokens**
   - Configured external access tokens in app-config
   - Useful for command-line scripts and webhooks
   - Tokens should be "sufficiently long" to prevent brute force attacks

3. **JWKS Token Authentication** (Focus of this research)
   - Authenticate external callers using JSON Web Key Sets
   - Ideal for third-party integrations (Auth0, Okta, etc.)
   - Requires JWKS URL, issuer, algorithm, and audience configuration

4. **Legacy Tokens**
   - Uses shared static secrets for signing/verification
   - Primarily for older backend systems (not recommended for new implementations)

### 1.2 User Identity Tokens

Backstage user identity tokens are **JWTs** with the following characteristics:

- **User entity reference** stored in the `sub` (subject) claim
- **Ownership references** available through user info API endpoint on auth backend
- Tokens passed in **`Authorization: Bearer <token>`** header
- Can include custom claims for user groups, roles, and permissions

### 1.3 Token Structure

```typescript
interface BackstageJWTPayload {
  sub: string;           // User entity reference (e.g., "user:default/john.doe")
  ent: string[];         // Ownership entity references
  iss: string;           // Issuer
  aud: string | string[]; // Audience
  iat: number;           // Issued at timestamp
  exp: number;           // Expiration timestamp
}
```

---

## 2. JWKS Endpoint Structure & Validation

### 2.1 JWKS Endpoint Location

Backstage exposes the JWKS endpoint at:
```
/api/auth/.well-known/jwks.json
```

This follows the **RFC 8615** well-known URI standard for consistent metadata discovery.

### 2.2 JWKS Response Structure

```json
{
  "keys": [
    {
      "crv": "P-256",        // Elliptic curve (P-256 for ES256)
      "x": "...",            // X coordinate (base64url)
      "y": "...",            // Y coordinate (base64url)
      "kty": "EC",           // Key type (EC for Elliptic Curve)
      "kid": "947202e4-...", // Key ID (unique identifier)
      "alg": "ES256",        // Algorithm (ES256, RS256, etc.)
      "use": "sig"           // Public key use (signature verification)
    }
  ]
}
```

### 2.3 JWKS Validation Process

**Step-by-step validation:**

1. **Extract `kid` from JWT header**
   ```typescript
   const header = jwt.decode(token, { complete: true })?.header;
   const kid = header?.kid;
   ```

2. **Fetch JWKS from endpoint**
   ```typescript
   const jwksResponse = await fetch('https://backstage.example.com/api/auth/.well-known/jwks.json');
   const jwks = await jwksResponse.json();
   ```

3. **Find matching public key**
   ```typescript
   const key = jwks.keys.find(k => k.kid === kid);
   ```

4. **Verify JWT signature with public key**
   ```typescript
   const verified = jwt.verify(token, publicKey, {
     algorithms: ['ES256'],
     issuer: 'https://backstage.example.com',
     audience: 'backstage-api'
   });
   ```

5. **Validate required claims**
   - `sub`: Subject (user entity reference)
   - `iss`: Issuer (must match expected issuer)
   - `aud`: Audience (must match expected audience)
   - `exp`: Expiration (token must not be expired)
   - `jti`: JWT ID (optional, for token revocation tracking)

### 2.4 JWKS Security Best Practices

#### **Endpoint Protection**
- ✅ Always use **HTTPS** to encrypt data in transit
- ✅ Implement **authentication** if necessary
- ✅ **Monitor access logs** for suspicious activities
- ✅ Use **rate limiting** to prevent abuse

#### **Key Rotation**
```typescript
// Key Rotation Process
1. Generate new key pair
2. Add public JWK to JWKS with new kid
3. Update issuer to sign tokens with new private key
4. Keep old public JWK in JWKS for grace period (e.g., 24 hours)
5. Remove old JWK once tokens signed with it are expired
```

#### **Caching Considerations**
- Implement appropriate **cache-control headers** on JWKS endpoint
- Handle **cache-control** and **expires** headers properly
- Clients may cache JWKS responses causing them to use outdated keys
- Set reasonable cache TTL (e.g., 1 hour) to balance performance and security

#### **Access Control**
- Restrict access to JWKS endpoint to only authorized clients
- Store cryptographic keys securely using **HSM** (Hardware Security Modules) or **KMS** (Key Management Services)

---

## 3. Backstage Identity Resolver Patterns

### 3.1 Overview

**Identity resolvers** map external authentication provider identities to Backstage user identities. This mapping is organization-specific and must be explicitly configured.

### 3.2 Built-In Resolver Patterns

Backstage provides several built-in sign-in resolvers:

| Resolver Pattern | Description |
|-----------------|-------------|
| `emailLocalPartMatchingUserEntityName` | Matches the local part of email addresses (before @) to user entity names |
| `emailMatchingUserEntityAnnotation` | Matches email to user entity annotations |
| `emailMatchingUserEntityProfileEmail` | Matches email to user entity profile email field |
| `usernameMatchingUserEntityName` | Matches username (e.g., GitHub username) with `metadata.name` value of User in Catalog |

### 3.3 Custom Resolver Implementation

Custom resolvers allow complex identity mapping logic:

```typescript
async signInResolver({ profile }, ctx) {
  // Validate email presence
  if (!profile.email) {
    throw new Error('Login failed, no email provided');
  }

  // Extract local part and domain
  const [localPart, domain] = profile.email.split('@');

  // Domain validation (security critical)
  if (domain !== 'acme.org') {
    throw new Error('Invalid domain - only acme.org users allowed');
  }

  // Create user entity reference
  const userEntity = stringifyEntityRef({
    kind: 'User',
    name: localPart,
    namespace: DEFAULT_NAMESPACE,
  });

  // Issue token with claims
  return ctx.issueToken({
    claims: {
      sub: userEntity,              // User entity reference
      ent: [userEntity],            // Ownership references
    },
  });
}
```

### 3.4 Identity Resolver Security

#### **Critical Security Rules:**

1. **Single Sign-In Resolver**
   - ⚠️ **Always configure only ONE sign-in resolver** for an auth provider
   - Multiple resolvers increase the risk of **account hijacking**
   - Only use multiple resolvers if you need to allow users to sign in multiple ways (not recommended)

2. **Domain Validation**
   - ✅ Always validate email domains in custom resolvers
   - ✅ Implement allowlists for authorized domains
   - ✅ Reject unauthorized domains explicitly

3. **Catalog User Requirement**
   - Most built-in resolvers require user entities to be present in the catalog
   - ⚠️ **Avoid `dangerouslyAllowSignInWithoutUserInCatalog` in production**
   - This option poses security risks and may grant access to unexpected users

4. **Token Claim Validation**
   - Validate all required claims (`sub`, `ent`, `iss`, `aud`, `exp`)
   - Implement additional custom claim validation as needed

---

## 4. Node.js/TypeScript Implementation Best Practices

### 4.1 JWT Validation with `jsonwebtoken` Package

#### **Installation**
```bash
npm install jsonwebtoken @types/jsonwebtoken
npm install jwks-rsa @types/jwks-rsa
```

#### **TypeScript Type Definitions**

```typescript
interface JWTPayload {
  sub: string;           // User ID or entity reference
  email?: string;        // User email
  role?: UserRole;       // User role (admin, user, etc.)
  groups?: string[];     // User groups/teams
  iat: number;           // Issued at timestamp
  exp: number;           // Expiration timestamp
  iss: string;           // Issuer
  aud: string | string[]; // Audience
}

enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  VIEWER = 'viewer'
}
```

#### **JWT Verification Middleware**

```typescript
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: JWTPayload;
    }
  }
}

const jwtMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET!, {
      algorithms: ['ES256', 'RS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    }) as JWTPayload;

    // Attach to request object
    req.user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: 'Token expired' });
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    return res.status(500).json({ error: 'Authentication failed' });
  }
};

export default jwtMiddleware;
```

### 4.2 JWKS Validation with `jwks-rsa`

```typescript
import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';

const client = jwksClient({
  jwksUri: 'https://backstage.example.com/api/auth/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 3600000, // 1 hour
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

const getKey = (header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key?.getPublicKey();
    callback(null, signingKey);
  });
};

const verifyToken = (token: string): Promise<JWTPayload> => {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getKey,
      {
        algorithms: ['ES256', 'RS256'],
        issuer: 'https://backstage.example.com',
        audience: 'backstage-api',
      },
      (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded as JWTPayload);
      }
    );
  });
};
```

### 4.3 Extracting User/Group Claims

```typescript
interface UserClaims {
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  permissions: string[];
}

const extractUserClaims = (token: JWTPayload): UserClaims => {
  return {
    userId: token.sub,
    email: token.email || '',
    groups: token.groups || [],
    roles: token.role ? [token.role] : [],
    permissions: token.permissions || [],
  };
};

// Usage in route handler
app.get('/api/protected', jwtMiddleware, (req, res) => {
  const userClaims = extractUserClaims(req.user!);

  // Check permissions
  if (!userClaims.groups.includes('admin')) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }

  res.json({ message: 'Access granted', user: userClaims });
});
```

---

## 5. Security Considerations

### 5.1 Critical Security Principles

1. **JWTs are Signed, NOT Encrypted**
   - ⚠️ Anyone can decode a JWT and read its contents
   - ⚠️ **NEVER include sensitive information** in JWT claims (passwords, SSNs, credit cards, etc.)
   - Use JWT for authentication, not for storing sensitive data

2. **Token Storage**
   - ❌ **Avoid `localStorage`** - susceptible to XSS attacks, tokens hard to revoke
   - ✅ **Prefer `httpOnly` cookies** - inaccessible to JavaScript, more secure
   - ✅ Consider **sessionStorage** for single-tab sessions

3. **Token Expiration Strategy**
   - ✅ **Short-lived access tokens**: 15 minutes
   - ✅ **Long-lived refresh tokens**: 2 weeks
   - ✅ Implement token refresh flow to balance security and user experience

4. **Always Validate Claims**
   ```typescript
   // Required claim validation
   const validateClaims = (token: JWTPayload): boolean => {
     const now = Math.floor(Date.now() / 1000);

     // Check expiration
     if (token.exp < now) {
       throw new Error('Token expired');
     }

     // Check issuer
     if (token.iss !== process.env.JWT_ISSUER) {
       throw new Error('Invalid issuer');
     }

     // Check audience
     const validAudiences = process.env.JWT_AUDIENCE?.split(',') || [];
     if (!validAudiences.includes(token.aud as string)) {
       throw new Error('Invalid audience');
     }

     // Check subject
     if (!token.sub || token.sub.length === 0) {
       throw new Error('Missing subject');
     }

     return true;
   };
   ```

5. **Key Management**
   - ✅ Use **Hardware Security Modules (HSM)** or **Key Management Services (KMS)**
   - ✅ **Rotate keys regularly** (e.g., every 90 days)
   - ✅ Store private keys securely, never commit to version control
   - ✅ Use environment variables for secrets

6. **JWKS Endpoint Security**
   - ✅ Protect with **HTTPS** (TLS 1.2+)
   - ✅ Implement **access control** if necessary
   - ✅ **Monitor access logs** for suspicious activities
   - ✅ Set appropriate **cache-control headers**
   - ✅ Implement **rate limiting** to prevent abuse

7. **Domain Validation**
   - ✅ Restrict authentication to authorized domains
   - ✅ Implement email domain allowlists
   - ✅ Reject unauthorized domains explicitly

8. **Single Sign-In Resolver**
   - ⚠️ Configure **only ONE sign-in resolver** per auth provider
   - Multiple resolvers increase the risk of account hijacking

### 5.2 Security Checklist

- [ ] JWT secret keys stored in environment variables (never hardcoded)
- [ ] HTTPS enabled in production
- [ ] Token expiration configured (short-lived access tokens)
- [ ] Refresh token flow implemented
- [ ] All required claims validated (`sub`, `iss`, `aud`, `exp`)
- [ ] Domain validation implemented in custom resolvers
- [ ] JWKS endpoint protected with HTTPS
- [ ] Key rotation schedule established (90 days)
- [ ] Access logs monitored for suspicious activities
- [ ] Rate limiting implemented on authentication endpoints
- [ ] httpOnly cookies used for token storage (if applicable)
- [ ] Sensitive data never stored in JWT claims
- [ ] Single sign-in resolver configured per auth provider

---

## 6. Backstage Configuration

### 6.1 JWKS Configuration in app-config.yaml

```yaml
backend:
  auth:
    externalAccess:
      # JWKS-based authentication for external callers
      - type: jwks
        options:
          # Required: JWKS endpoint URL
          url: https://auth.example.com/.well-known/jwks.json

          # Required: Accepted JWT issuers (must match 'iss' claim)
          issuer: https://auth.example.com

          # Required: Signature algorithm
          algorithm: ES256  # or RS256, HS256, etc.

          # Required: Expected audience (aud claim validation)
          audience: backstage-api

          # Optional: Prefix to prepend to sub claim
          subjectPrefix: 'external:'

          # Optional: Access restrictions
          accessRestrictions:
            # Restrict to specific plugins
            - plugin: catalog
              permission: catalog.entity.read

            # Restrict to specific permissions
            - permission: catalog.entity.create
              attributes:
                action: create
```

### 6.2 Token Generation Example

```typescript
import { AuthService, HttpAuthService } from '@backstage/backend-plugin-api';

class MyBackendPlugin {
  constructor(
    private auth: AuthService,
    private httpAuth: HttpAuthService
  ) {}

  async callExternalService(credentials: BackstageCredentials) {
    // Generate plugin-to-plugin token
    const { token } = await this.auth.getPluginRequestToken({
      onBehalfOf: credentials,
      targetPluginId: 'external-service',
    });

    // Make authenticated request
    const response = await fetch('https://external-service/api/data', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    return response.json();
  }
}
```

### 6.3 Token Optimization

```yaml
backend:
  auth:
    # Omit ownership claims from identity tokens to reduce token size
    omitIdentityTokenOwnershipClaim: true
```

**Note:** When enabling this optimization, you'll need to fetch user info separately via the user info API endpoint.

---

## 7. Implementation Recommendations

### 7.1 For New Implementations

1. **Start with JWKS-based authentication**
   - More secure than static tokens
   - Easier key rotation
   - Better integration with third-party auth providers

2. **Use TypeScript for type safety**
   - Define clear interfaces for JWT payloads
   - Leverage TypeScript's type checking

3. **Implement proper error handling**
   - Distinguish between expired tokens, invalid tokens, and missing tokens
   - Provide clear error messages

4. **Set up monitoring and logging**
   - Log authentication attempts
   - Monitor for suspicious activities
   - Set up alerts for failed authentication patterns

### 7.2 For Existing Implementations

1. **Migrate from static tokens to JWKS**
   - Plan migration strategy
   - Support both methods during transition
   - Set sunset date for static tokens

2. **Implement key rotation**
   - Establish 90-day rotation schedule
   - Document key rotation process
   - Test rotation in staging environment

3. **Review and update token expiration**
   - Shorten access token expiration (15 minutes)
   - Implement refresh token flow
   - Update client applications

### 7.3 Testing Strategy

```typescript
// Unit test example
describe('JWT Validation', () => {
  it('should validate valid token', async () => {
    const token = generateTestToken({
      sub: 'user:default/test-user',
      iss: 'https://backstage.test',
      aud: 'backstage-api',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const result = await verifyToken(token);
    expect(result.sub).toBe('user:default/test-user');
  });

  it('should reject expired token', async () => {
    const token = generateTestToken({
      sub: 'user:default/test-user',
      iss: 'https://backstage.test',
      aud: 'backstage-api',
      exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
    });

    await expect(verifyToken(token)).rejects.toThrow('Token expired');
  });

  it('should reject token with invalid issuer', async () => {
    const token = generateTestToken({
      sub: 'user:default/test-user',
      iss: 'https://malicious.com',
      aud: 'backstage-api',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    await expect(verifyToken(token)).rejects.toThrow('Invalid issuer');
  });
});
```

---

## 8. Key Findings Summary

### 8.1 Backstage JWT Authentication
- ✅ Supports 4 authentication methods (plugin-to-plugin, static, JWKS, legacy)
- ✅ User identity tokens are JWTs with `sub` and `ent` claims
- ✅ JWKS endpoint at `/api/auth/.well-known/jwks.json`
- ✅ Uses ES256 algorithm with P-256 elliptic curve keys

### 8.2 JWKS Validation
- ✅ Extract `kid` from JWT header, find matching public key in JWKS
- ✅ Verify signature with public key
- ✅ Validate all required claims (`sub`, `iss`, `aud`, `exp`, `jti`)
- ✅ Implement key rotation with grace period

### 8.3 Identity Resolvers
- ✅ Map external auth provider identities to Backstage user identities
- ✅ Built-in patterns for common use cases (email, username matching)
- ✅ Custom resolvers allow complex mapping logic
- ⚠️ **Configure only ONE sign-in resolver per auth provider**

### 8.4 Node.js/TypeScript Best Practices
- ✅ Use `jsonwebtoken` and `jwks-rsa` packages
- ✅ Define TypeScript interfaces for JWT payloads
- ✅ Implement middleware for token extraction and validation
- ✅ Short-lived access tokens (15 min) with refresh tokens (2 weeks)

### 8.5 Security Considerations
- ⚠️ JWTs are signed, NOT encrypted - never include sensitive data
- ✅ Use httpOnly cookies for token storage (avoid localStorage)
- ✅ Always validate all required claims
- ✅ Implement key rotation (90-day schedule)
- ✅ Protect JWKS endpoint with HTTPS, access control, and rate limiting
- ✅ Domain validation in custom resolvers
- ⚠️ Single sign-in resolver to prevent account hijacking

---

## 9. References

### Official Documentation
- [Backstage Authentication](https://backstage.io/docs/auth/)
- [Backstage Identity Resolver](https://backstage.io/docs/auth/identity-resolver)
- [Backstage Service-to-Service Auth](https://backstage.io/docs/auth/service-to-service-auth/)

### Libraries & Tools
- [jsonwebtoken (npm)](https://www.npmjs.com/package/jsonwebtoken)
- [jwks-rsa (npm)](https://www.npmjs.com/package/jwks-rsa)
- [JWT.io - JWT Debugger](https://jwt.io/)

### Standards
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 8615 - Well-Known URIs](https://datatracker.ietf.org/doc/html/rfc8615)

### Security Best Practices
- [JWT Security Best Practices | Curity](https://curity.io/resources/learn/jwt-best-practices/)
- [Understanding JWKS | Stytch](https://stytch.com/blog/understanding-jwks/)

---

## 10. Next Steps for Implementation

1. **Review current authentication implementation** in the codebase
2. **Identify integration points** where JWT authentication will be used
3. **Design JWT payload structure** with required claims
4. **Implement JWKS validation** using `jwks-rsa` library
5. **Create custom identity resolver** if needed (with domain validation)
6. **Set up proper error handling** and logging
7. **Write comprehensive tests** for JWT validation and identity resolution
8. **Configure app-config.yaml** with JWKS settings
9. **Establish key rotation schedule** and document process
10. **Set up monitoring and alerting** for authentication events

---

**Research Completed:** October 2, 2025
**Status:** ✅ Complete - All findings stored in collective memory
**Memory Keys:**
- `hive/research/backstage-jwt`
- `hive/research/jwks-validation`
- `hive/research/identity-resolver`
- `hive/research/jwt-node-typescript`
- `hive/research/jwt-security`
- `hive/research/backstage-config`
