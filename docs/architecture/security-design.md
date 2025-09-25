# Security-First REST API Design - OWASP Compliance

## Security Architecture Overview

### Defense in Depth Strategy
```
┌─────────────────────────────────────────────────────────────────┐
│                        Security Layers                         │
├─────────────────────────────────────────────────────────────────┤
│  1. Network Security (Firewall, VPN, WAF)                     │
│  2. API Gateway (Rate limiting, Auth, Input validation)        │
│  3. Application Security (HTTPS, CSP, HSTS)                   │
│  4. Authentication & Authorization (JWT, RBAC)                 │
│  5. Data Security (Encryption, Hashing, Sanitization)         │
│  6. Database Security (RLS, Encryption at rest)               │
│  7. Monitoring & Logging (SIEM, Audit trails)                 │
└─────────────────────────────────────────────────────────────────┘
```

## OWASP Top 10 2021 Mitigation

### A01 - Broken Access Control
**Mitigations:**
```javascript
// 1. Implement proper authorization checks
const checkPermission = (requiredPermission) => {
  return (req, res, next) => {
    const userPermissions = req.user.permissions;
    const tenantId = req.params.tenantId || req.user.tenantId;

    // Verify tenant access
    if (req.user.tenantId !== tenantId) {
      return res.status(403).json({ error: 'Access denied: Invalid tenant' });
    }

    // Check specific permission
    if (!userPermissions.includes(requiredPermission) && !userPermissions.includes('*:*')) {
      return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
    }

    next();
  };
};

// 2. Resource-level access control
const checkResourceOwnership = async (req, res, next) => {
  const { tenantId, resourceId } = req.params;
  const userId = req.user.id;

  const resource = await db.query(`
    SELECT owner_id, organization_id
    FROM ${tenantId}.resources
    WHERE id = $1
  `, [resourceId]);

  if (!resource || (resource.owner_id !== userId && !await checkOrganizationMembership(userId, resource.organization_id))) {
    return res.status(404).json({ error: 'Resource not found' });
  }

  req.resource = resource;
  next();
};
```

### A02 - Cryptographic Failures
**Mitigations:**
```javascript
// 1. Strong password hashing
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

class PasswordManager {
  static async hash(password) {
    // Validate password strength first
    if (!this.validatePasswordStrength(password)) {
      throw new Error('Password does not meet security requirements');
    }
    return bcrypt.hash(password, SALT_ROUNDS);
  }

  static async verify(password, hash) {
    return bcrypt.compare(password, hash);
  }

  static validatePasswordStrength(password) {
    const minLength = 12;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasNonalphas = /\W/.test(password);

    return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasNonalphas;
  }
}

// 2. Encryption for sensitive data
const crypto = require('crypto');

class DataEncryption {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 16;
  }

  encrypt(text, key) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipher(this.algorithm, key, { iv });

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  decrypt(encryptedData, key) {
    const { encrypted, iv, authTag } = encryptedData;
    const decipher = crypto.createDecipher(this.algorithm, key, { iv: Buffer.from(iv, 'hex') });

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
```

### A03 - Injection Attacks
**Mitigations:**
```javascript
// 1. Parameterized queries (SQL injection prevention)
class SecureDatabase {
  async getUser(tenantId, userId) {
    // NEVER do this: `SELECT * FROM ${tenantId}.users WHERE id = '${userId}'`
    // Always use parameterized queries:
    return this.db.query(`
      SELECT id, email, first_name, last_name, created_at
      FROM ${this.escapeIdentifier(tenantId)}.users
      WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);
  }

  escapeIdentifier(identifier) {
    // Validate tenant schema name against whitelist
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(identifier)) {
      throw new Error('Invalid schema identifier');
    }
    return identifier;
  }
}

// 2. Input validation and sanitization
const validator = require('validator');
const xss = require('xss');

class InputValidator {
  static validateEmail(email) {
    return validator.isEmail(email) && email.length <= 254;
  }

  static sanitizeString(input, maxLength = 255) {
    if (typeof input !== 'string') return '';
    return xss(validator.escape(input.trim().substring(0, maxLength)));
  }

  static validateUUID(uuid) {
    return validator.isUUID(uuid, 4);
  }

  static validateJSON(jsonString, maxSize = 10240) {
    try {
      if (jsonString.length > maxSize) return false;
      const parsed = JSON.parse(jsonString);
      return typeof parsed === 'object' && parsed !== null;
    } catch {
      return false;
    }
  }
}

// 3. NoSQL injection prevention
class MongoSecure {
  static sanitizeQuery(query) {
    // Remove any keys starting with $ to prevent operator injection
    const sanitized = {};
    for (const [key, value] of Object.entries(query)) {
      if (!key.startsWith('$') && typeof key === 'string') {
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          sanitized[key] = this.sanitizeQuery(value);
        } else {
          sanitized[key] = value;
        }
      }
    }
    return sanitized;
  }
}
```

### A04 - Insecure Design
**Mitigations:**
```javascript
// 1. Secure session management
class SessionManager {
  constructor(redis) {
    this.redis = redis;
    this.sessionTTL = 24 * 60 * 60; // 24 hours
    this.maxSessions = 5; // Max concurrent sessions per user
  }

  async createSession(user) {
    const sessionId = crypto.randomUUID();
    const refreshToken = crypto.randomBytes(32).toString('hex');

    const sessionData = {
      userId: user.id,
      tenantId: user.tenantId,
      permissions: user.permissions,
      deviceInfo: this.getDeviceFingerprint(req),
      ipAddress: req.ip,
      createdAt: new Date().toISOString(),
      lastAccessAt: new Date().toISOString()
    };

    // Store session
    await this.redis.setex(`session:${sessionId}`, this.sessionTTL, JSON.stringify(sessionData));

    // Store refresh token (longer TTL)
    await this.redis.setex(`refresh:${refreshToken}`, this.sessionTTL * 7, sessionId);

    // Manage concurrent sessions
    await this.manageConcurrentSessions(user.id, sessionId);

    return { sessionId, refreshToken };
  }

  async manageConcurrentSessions(userId, newSessionId) {
    const sessionsKey = `user_sessions:${userId}`;

    // Add new session
    await this.redis.lpush(sessionsKey, newSessionId);

    // Trim to max sessions (invalidate old ones)
    const sessions = await this.redis.lrange(sessionsKey, 0, -1);
    if (sessions.length > this.maxSessions) {
      const oldSessions = sessions.slice(this.maxSessions);
      for (const oldSession of oldSessions) {
        await this.redis.del(`session:${oldSession}`);
      }
      await this.redis.ltrim(sessionsKey, 0, this.maxSessions - 1);
    }
  }
}

// 2. Rate limiting with progressive delays
class RateLimiter {
  constructor(redis) {
    this.redis = redis;
    this.limits = {
      login: { requests: 5, window: 900, lockout: 3600 }, // 5 attempts per 15min, 1h lockout
      api: { requests: 1000, window: 3600, lockout: 300 }, // 1000 requests per hour, 5min cooldown
      password_reset: { requests: 3, window: 3600, lockout: 3600 } // 3 attempts per hour, 1h lockout
    };
  }

  async checkLimit(identifier, type = 'api') {
    const limit = this.limits[type];
    const key = `rate_limit:${type}:${identifier}`;
    const lockKey = `rate_lock:${type}:${identifier}`;

    // Check if locked out
    const locked = await this.redis.get(lockKey);
    if (locked) {
      return { allowed: false, remaining: 0, reset: parseInt(locked) };
    }

    const current = await this.redis.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= limit.requests) {
      // Lock out user
      await this.redis.setex(lockKey, limit.lockout, Date.now() + (limit.lockout * 1000));
      return { allowed: false, remaining: 0, reset: Date.now() + (limit.lockout * 1000) };
    }

    // Increment counter
    await this.redis.multi()
      .incr(key)
      .expire(key, limit.window)
      .exec();

    return {
      allowed: true,
      remaining: limit.requests - count - 1,
      reset: Date.now() + (limit.window * 1000)
    };
  }
}
```

### A05 - Security Misconfiguration
**Mitigations:**
```javascript
// 1. Secure HTTP headers
const helmet = require('helmet');

const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: false,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true,
});

// 2. Environment-based configuration
class SecurityConfig {
  constructor() {
    this.config = {
      jwtSecret: this.getRequiredEnvVar('JWT_SECRET'),
      jwtExpiry: process.env.JWT_EXPIRY || '24h',
      bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
      rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000,
        max: parseInt(process.env.RATE_LIMIT_MAX) || 100
      },
      cors: {
        origin: this.parseOrigins(process.env.CORS_ORIGINS),
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true
      }
    };
  }

  getRequiredEnvVar(name) {
    const value = process.env[name];
    if (!value) {
      throw new Error(`Required environment variable ${name} is not set`);
    }
    return value;
  }

  parseOrigins(originsString) {
    if (!originsString) return false;
    return originsString.split(',').map(origin => origin.trim());
  }
}
```

### A06 - Vulnerable and Outdated Components
**Mitigations:**
```json
// 1. Package.json with security-focused dependencies
{
  "scripts": {
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "security-check": "npm run audit && snyk test",
    "update-deps": "npm-check-updates -u"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "helmet": "^6.1.0",
    "express-rate-limit": "^6.7.0",
    "express-validator": "^6.15.0",
    "jsonwebtoken": "^9.0.0"
  },
  "devDependencies": {
    "snyk": "^1.1158.0",
    "npm-check-updates": "^16.10.0"
  }
}
```

### A07 - Identification and Authentication Failures
**Mitigations:**
```javascript
// 1. Multi-factor authentication
class MFAManager {
  constructor() {
    this.speakeasy = require('speakeasy');
  }

  generateSecret(user) {
    return this.speakeasy.generateSecret({
      name: `${user.email} (${user.tenantId})`,
      issuer: 'YourApp'
    });
  }

  verifyToken(secret, token, window = 1) {
    return this.speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window // Allow for clock drift
    });
  }

  async enforceMFA(req, res, next) {
    const user = req.user;

    if (user.mfaEnabled && !req.session.mfaVerified) {
      return res.status(403).json({
        error: 'MFA_REQUIRED',
        message: 'Multi-factor authentication required'
      });
    }

    next();
  }
}

// 2. Account lockout protection
class AccountSecurity {
  constructor(redis) {
    this.redis = redis;
    this.maxAttempts = 5;
    this.lockoutDuration = 30 * 60; // 30 minutes
    this.attemptWindow = 15 * 60; // 15 minutes
  }

  async checkAccountLockout(email) {
    const lockKey = `lockout:${email}`;
    const attemptKey = `attempts:${email}`;

    const locked = await this.redis.get(lockKey);
    if (locked) {
      return {
        locked: true,
        remainingTime: await this.redis.ttl(lockKey)
      };
    }

    const attempts = await this.redis.get(attemptKey) || 0;
    return {
      locked: false,
      attempts: parseInt(attempts),
      remaining: this.maxAttempts - parseInt(attempts)
    };
  }

  async recordFailedAttempt(email) {
    const attemptKey = `attempts:${email}`;
    const lockKey = `lockout:${email}`;

    const attempts = await this.redis.incr(attemptKey);
    await this.redis.expire(attemptKey, this.attemptWindow);

    if (attempts >= this.maxAttempts) {
      await this.redis.setex(lockKey, this.lockoutDuration, 'locked');
      await this.redis.del(attemptKey);

      // Log security event
      console.warn(`Account locked: ${email} - too many failed attempts`);
    }

    return attempts;
  }

  async clearAttempts(email) {
    await this.redis.del(`attempts:${email}`);
  }
}
```

### A08 - Software and Data Integrity Failures
**Mitigations:**
```javascript
// 1. API request/response integrity
class IntegrityValidator {
  static generateSignature(data, secret) {
    return crypto.createHmac('sha256', secret).update(JSON.stringify(data)).digest('hex');
  }

  static verifySignature(data, signature, secret) {
    const expectedSignature = this.generateSignature(data, secret);
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }

  static middleware(secret) {
    return (req, res, next) => {
      const signature = req.headers['x-signature'];
      if (!signature || !this.verifySignature(req.body, signature, secret)) {
        return res.status(401).json({ error: 'Invalid signature' });
      }
      next();
    };
  }
}

// 2. File upload security
const multer = require('multer');
const path = require('path');

class SecureFileUpload {
  static configure() {
    const allowedMimeTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'text/plain'
    ];

    const storage = multer.diskStorage({
      destination: (req, file, cb) => {
        cb(null, '/secure/uploads/');
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
      }
    });

    return multer({
      storage,
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 5
      },
      fileFilter: (req, file, cb) => {
        if (allowedMimeTypes.includes(file.mimetype)) {
          cb(null, true);
        } else {
          cb(new Error('File type not allowed'), false);
        }
      }
    });
  }

  static async scanFile(filePath) {
    // Integrate with antivirus scanning
    // This would typically call an external service like ClamAV
    return { safe: true, threats: [] };
  }
}
```

### A09 - Security Logging and Monitoring Failures
**Mitigations:**
```javascript
// 1. Comprehensive security logging
class SecurityLogger {
  constructor() {
    this.winston = require('winston');
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ filename: 'security.log' }),
        new winston.transports.Console()
      ]
    });
  }

  logAuthEvent(type, user, req, success = true, details = {}) {
    this.logger.info({
      type: 'AUTHENTICATION',
      event: type,
      success,
      user: user ? { id: user.id, email: user.email, tenantId: user.tenantId } : null,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      details
    });
  }

  logAccessEvent(resource, user, req, granted = true) {
    this.logger.info({
      type: 'AUTHORIZATION',
      resource,
      user: { id: user.id, email: user.email, tenantId: user.tenantId },
      granted,
      ip: req.ip,
      method: req.method,
      url: req.url,
      timestamp: new Date().toISOString()
    });
  }

  logSecurityIncident(type, severity, details, req = null) {
    this.logger.error({
      type: 'SECURITY_INCIDENT',
      incident: type,
      severity,
      ip: req ? req.ip : null,
      userAgent: req ? req.get('User-Agent') : null,
      details,
      timestamp: new Date().toISOString()
    });
  }
}

// 2. Real-time monitoring and alerting
class SecurityMonitor {
  constructor(redis, alertSystem) {
    this.redis = redis;
    this.alerts = alertSystem;
    this.thresholds = {
      failedLogins: { count: 10, window: 300 }, // 10 failed logins in 5 minutes
      suspiciousActivity: { count: 50, window: 600 }, // 50 suspicious events in 10 minutes
      dataExfiltration: { size: 100 * 1024 * 1024, window: 3600 } // 100MB in 1 hour
    };
  }

  async checkAnomalies(event) {
    const key = `security_events:${event.type}:${event.ip}`;
    const count = await this.redis.incr(key);
    await this.redis.expire(key, this.thresholds[event.type]?.window || 300);

    const threshold = this.thresholds[event.type];
    if (threshold && count >= threshold.count) {
      await this.triggerAlert('SECURITY_THRESHOLD_EXCEEDED', {
        type: event.type,
        ip: event.ip,
        count,
        threshold: threshold.count,
        window: threshold.window
      });
    }
  }

  async triggerAlert(type, details) {
    await this.alerts.send({
      type,
      severity: 'HIGH',
      message: `Security alert: ${type}`,
      details,
      timestamp: new Date().toISOString()
    });
  }
}
```

### A10 - Server-Side Request Forgery (SSRF)
**Mitigations:**
```javascript
// 1. URL validation and allowlisting
class SSRFProtection {
  constructor() {
    this.allowedHosts = process.env.ALLOWED_HOSTS?.split(',') || [];
    this.blockedIPs = [
      '127.0.0.1', '::1', // Localhost
      '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', // Private networks
      '169.254.0.0/16', // Link-local
      '224.0.0.0/4' // Multicast
    ];
  }

  isAllowedURL(url) {
    try {
      const parsed = new URL(url);

      // Check protocol
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return false;
      }

      // Check against allowlist
      if (this.allowedHosts.length > 0) {
        return this.allowedHosts.includes(parsed.hostname);
      }

      // Check against blocked IPs
      return !this.isBlockedIP(parsed.hostname);
    } catch {
      return false;
    }
  }

  isBlockedIP(hostname) {
    // This would include proper CIDR matching logic
    return this.blockedIPs.some(blocked => hostname.includes(blocked.split('/')[0]));
  }

  async safeRequest(url, options = {}) {
    if (!this.isAllowedURL(url)) {
      throw new Error('URL not allowed');
    }

    const timeoutOptions = {
      ...options,
      timeout: options.timeout || 5000,
      maxRedirects: 0 // Prevent redirect-based attacks
    };

    return fetch(url, timeoutOptions);
  }
}
```

## Additional Security Measures

### 1. API Security Best Practices
```javascript
// Content-Type validation
const validateContentType = (req, res, next) => {
  const contentType = req.get('Content-Type');

  if (req.method === 'POST' || req.method === 'PUT') {
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(400).json({ error: 'Content-Type must be application/json' });
    }
  }

  next();
};

// Request size limits
const requestLimits = {
  json: { limit: '1mb' },
  urlencoded: { limit: '1mb', extended: false },
  raw: { limit: '10mb' }
};
```

### 2. Database Security
```sql
-- Row Level Security (RLS) policies
CREATE POLICY tenant_isolation ON users
  USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Audit trigger for sensitive tables
CREATE OR REPLACE FUNCTION audit_sensitive_changes()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_log (table_name, operation, old_values, new_values, user_id, timestamp)
  VALUES (TG_TABLE_NAME, TG_OP,
    CASE WHEN TG_OP = 'DELETE' THEN row_to_json(OLD) ELSE NULL END,
    CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN row_to_json(NEW) ELSE NULL END,
    current_setting('app.current_user_id', true)::UUID,
    NOW()
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
```

### 3. Incident Response Plan
```javascript
class IncidentResponse {
  async handleSecurityIncident(type, severity, details) {
    // 1. Log incident
    securityLogger.logSecurityIncident(type, severity, details);

    // 2. Alert security team
    await this.alertSecurityTeam(type, severity, details);

    // 3. Auto-remediation for known threats
    if (this.autoRemediationEnabled(type)) {
      await this.executeRemediation(type, details);
    }

    // 4. Create incident ticket
    await this.createIncidentTicket(type, severity, details);
  }

  async executeRemediation(type, details) {
    switch (type) {
      case 'BRUTE_FORCE_ATTACK':
        await this.blockIPAddress(details.ip, '1 hour');
        break;
      case 'SQL_INJECTION_ATTEMPT':
        await this.quarantineUser(details.userId);
        break;
      case 'SUSPICIOUS_FILE_UPLOAD':
        await this.quarantineFile(details.filePath);
        break;
    }
  }
}
```

This comprehensive security design ensures OWASP compliance and implements defense-in-depth strategies across all layers of the REST API architecture.