# Middleware Stack Architecture

## Overview

This document defines the comprehensive middleware architecture for our REST API system, providing a layered approach to request processing with security, performance, and observability at its core.

## Middleware Stack Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Incoming Request                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  1. Security Headers Middleware                             │
│     • Content Security Policy                              │
│     • HSTS, X-Frame-Options                                │
│     • XSS Protection                                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  2. Request Logging & Correlation ID                       │
│     • Generate correlation ID                              │
│     • Log request details                                  │
│     • Setup tracing context                                │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  3. CORS & Preflight Handling                              │
│     • Cross-origin resource sharing                        │
│     • OPTIONS method handling                              │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  4. Rate Limiting                                           │
│     • IP-based rate limiting                               │
│     • User-based rate limiting                             │
│     • Endpoint-specific limits                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  5. Content Processing                                      │
│     • Body parsing (JSON, URL-encoded)                     │
│     • Content-Type validation                              │
│     • Request size limits                                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  6. Input Validation & Sanitization                        │
│     • Schema validation                                    │
│     • XSS prevention                                       │
│     • SQL injection prevention                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  7. Authentication                                          │
│     • JWT token validation                                 │
│     • Session verification                                 │
│     • User context setup                                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  8. Authorization & Permissions                             │
│     • Role-based access control                            │
│     • Resource-level permissions                           │
│     • Tenant isolation                                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  9. Caching Layer                                           │
│     • Response caching check                               │
│     • Cache invalidation                                   │
│     • ETag handling                                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  10. Business Logic (Controllers)                          │
│      • Route handlers                                      │
│      • Service layer calls                                 │
│      • Response preparation                                │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  11. Response Processing                                    │
│      • Response formatting                                 │
│      • Performance metrics                                 │
│      • Response logging                                    │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│  12. Error Handling                                         │
│      • Centralized error processing                        │
│      • Error logging                                       │
│      • Client-safe error responses                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                     Response                                │
└─────────────────────────────────────────────────────────────┘
```

## 1. Security Headers Middleware

```javascript
// security-headers-middleware.js
const helmet = require('helmet');

class SecurityHeadersMiddleware {
  static configure() {
    return helmet({
      // Content Security Policy
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            "'strict-dynamic'",
            "'nonce-${nonce}'"
          ],
          styleSrc: [
            "'self'",
            "'unsafe-inline'" // Only for backwards compatibility
          ],
          imgSrc: [
            "'self'",
            "data:",
            "https:"
          ],
          connectSrc: [
            "'self'",
            "wss:",
            "https:"
          ],
          fontSrc: [
            "'self'",
            "data:"
          ],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
          childSrc: ["'none'"],
          workerSrc: ["'none'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: [],
        },
        reportOnly: false
      },

      // HTTP Strict Transport Security
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      },

      // X-Frame-Options
      frameguard: {
        action: 'deny'
      },

      // X-Content-Type-Options
      noSniff: true,

      // X-XSS-Protection
      xssFilter: true,

      // Referrer Policy
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
      },

      // Cross-Origin Embedder Policy
      crossOriginEmbedderPolicy: true,

      // Cross-Origin Opener Policy
      crossOriginOpenerPolicy: { policy: 'same-origin' },

      // Cross-Origin Resource Policy
      crossOriginResourcePolicy: { policy: 'same-site' },

      // DNS Prefetch Control
      dnsPrefetchControl: { allow: false },

      // Expect-CT
      expectCt: {
        maxAge: 86400,
        enforce: true
      },

      // Feature Policy / Permissions Policy
      permissionsPolicy: {
        camera: [],
        microphone: [],
        geolocation: [],
        interest: []
      }
    });
  }

  static customHeaders() {
    return (req, res, next) => {
      // Remove server information
      res.removeHeader('X-Powered-By');
      res.setHeader('Server', 'API/1.0');

      // Add custom security headers
      res.setHeader('X-API-Version', process.env.API_VERSION || '1.0');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Download-Options', 'noopen');
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

      next();
    };
  }
}

module.exports = SecurityHeadersMiddleware;
```

## 2. Request Logging & Correlation Middleware

```javascript
// request-logging-middleware.js
const { v4: uuidv4 } = require('uuid');
const { AsyncLocalStorage } = require('async_hooks');

class RequestLoggingMiddleware {
  constructor(logger) {
    this.logger = logger;
    this.asyncLocalStorage = new AsyncLocalStorage();
  }

  middleware() {
    return (req, res, next) => {
      const startTime = process.hrtime.bigint();

      // Generate correlation ID
      const correlationId = uuidv4();
      req.correlationId = correlationId;
      res.setHeader('X-Correlation-ID', correlationId);

      // Extract or generate request ID
      const requestId = req.get('X-Request-ID') || uuidv4();
      req.requestId = requestId;
      res.setHeader('X-Request-ID', requestId);

      // Setup request context
      const requestContext = {
        correlationId,
        requestId,
        startTime,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: null, // Will be set by auth middleware
        tenantId: null // Will be set by auth middleware
      };

      // Store context in async local storage
      this.asyncLocalStorage.run(requestContext, () => {
        // Log incoming request
        this.logger.info('Request received', {
          correlationId,
          requestId,
          method: req.method,
          url: req.url,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          contentLength: req.get('Content-Length'),
          contentType: req.get('Content-Type')
        });

        // Setup response logging
        res.on('finish', () => {
          const endTime = process.hrtime.bigint();
          const duration = Number(endTime - startTime) / 1e6; // Convert to milliseconds

          const logData = {
            correlationId,
            requestId,
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration,
            responseSize: res.get('Content-Length'),
            ip: req.ip,
            userId: requestContext.userId,
            tenantId: requestContext.tenantId
          };

          // Log based on status code
          if (res.statusCode >= 500) {
            this.logger.error('Request failed', logData);
          } else if (res.statusCode >= 400) {
            this.logger.warn('Request error', logData);
          } else {
            this.logger.info('Request completed', logData);
          }
        });

        next();
      });
    };
  }

  // Helper method to get current request context
  getContext() {
    return this.asyncLocalStorage.getStore() || {};
  }

  // Helper method to update context (useful for auth middleware)
  updateContext(updates) {
    const context = this.getContext();
    Object.assign(context, updates);
  }
}

module.exports = RequestLoggingMiddleware;
```

## 3. CORS Middleware

```javascript
// cors-middleware.js
const cors = require('cors');

class CORSMiddleware {
  static configure() {
    const allowedOrigins = process.env.CORS_ORIGINS
      ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim())
      : ['http://localhost:3000'];

    return cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
          callback(null, true);
        } else {
          const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
          callback(new Error(msg), false);
        }
      },
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-API-Key',
        'X-Request-ID',
        'X-Correlation-ID'
      ],
      exposedHeaders: [
        'X-Request-ID',
        'X-Correlation-ID',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset'
      ],
      credentials: true,
      maxAge: 86400, // 24 hours
      optionsSuccessStatus: 204
    });
  }

  static preflightHandler() {
    return (req, res, next) => {
      if (req.method === 'OPTIONS') {
        res.status(204).end();
      } else {
        next();
      }
    };
  }
}

module.exports = CORSMiddleware;
```

## 4. Rate Limiting Middleware

```javascript
// rate-limiting-middleware.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

class RateLimitingMiddleware {
  constructor(redisClient, logger) {
    this.redis = redisClient;
    this.logger = logger;
  }

  // General API rate limiter
  apiLimiter() {
    return rateLimit({
      store: new RedisStore({
        sendCommand: (...args) => this.redis.call(...args),
        prefix: 'rl:api:'
      }),
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: (req) => {
        // Higher limits for authenticated users
        if (req.user) {
          return req.user.isPremium ? 2000 : 1000;
        }
        return 100; // Anonymous users
      },
      keyGenerator: (req) => {
        // Use user ID if authenticated, otherwise IP
        return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
      },
      message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: 900
      },
      standardHeaders: true,
      legacyHeaders: false,
      onLimitReached: (req, res, options) => {
        this.logger.warn('Rate limit exceeded', {
          ip: req.ip,
          userId: req.user?.id,
          endpoint: req.path,
          method: req.method
        });
      }
    });
  }

  // Auth endpoints rate limiter (more restrictive)
  authLimiter() {
    return rateLimit({
      store: new RedisStore({
        sendCommand: (...args) => this.redis.call(...args),
        prefix: 'rl:auth:'
      }),
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // Only 5 attempts per IP
      keyGenerator: (req) => `ip:${req.ip}`,
      message: {
        error: 'Too many authentication attempts',
        message: 'Too many login attempts. Please try again in 15 minutes.',
        retryAfter: 900
      },
      skipSuccessfulRequests: true,
      onLimitReached: (req, res, options) => {
        this.logger.warn('Authentication rate limit exceeded', {
          ip: req.ip,
          email: req.body?.email,
          endpoint: req.path
        });
      }
    });
  }

  // File upload rate limiter
  uploadLimiter() {
    return rateLimit({
      store: new RedisStore({
        sendCommand: (...args) => this.redis.call(...args),
        prefix: 'rl:upload:'
      }),
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10, // 10 uploads per hour
      keyGenerator: (req) => req.user ? `user:${req.user.id}` : `ip:${req.ip}`,
      message: {
        error: 'Upload limit exceeded',
        message: 'Too many file uploads. Please try again in an hour.',
        retryAfter: 3600
      }
    });
  }

  // Progressive rate limiting based on consecutive failures
  progressiveLimiter() {
    return async (req, res, next) => {
      const key = `progressive:${req.ip}`;
      const failures = await this.redis.get(key) || 0;

      let maxRequests = 100;
      let windowMs = 15 * 60 * 1000; // 15 minutes

      // Reduce limits based on failure count
      if (failures > 20) {
        maxRequests = 10;
        windowMs = 60 * 60 * 1000; // 1 hour
      } else if (failures > 10) {
        maxRequests = 25;
        windowMs = 30 * 60 * 1000; // 30 minutes
      } else if (failures > 5) {
        maxRequests = 50;
      }

      // Apply dynamic rate limit
      const limiter = rateLimit({
        store: new RedisStore({
          sendCommand: (...args) => this.redis.call(...args),
          prefix: 'rl:progressive:'
        }),
        windowMs,
        max: maxRequests,
        keyGenerator: () => `${req.ip}:${failures}`,
        message: {
          error: 'Progressive rate limit',
          message: `Rate limited due to previous failures. ${maxRequests} requests per ${windowMs/60000} minutes.`,
          retryAfter: windowMs / 1000
        }
      });

      limiter(req, res, next);
    };
  }
}

module.exports = RateLimitingMiddleware;
```

## 5. Content Processing Middleware

```javascript
// content-processing-middleware.js
const express = require('express');

class ContentProcessingMiddleware {
  static configure() {
    return {
      // JSON body parser with strict type checking
      json: express.json({
        limit: '10mb',
        strict: true,
        type: (req) => {
          const contentType = req.get('content-type');
          return contentType && contentType.includes('application/json');
        },
        verify: (req, res, buf) => {
          // Store raw body for signature verification if needed
          req.rawBody = buf;
        }
      }),

      // URL-encoded body parser
      urlencoded: express.urlencoded({
        limit: '10mb',
        extended: false,
        parameterLimit: 1000
      }),

      // Raw body parser for webhooks
      raw: express.raw({
        limit: '10mb',
        type: 'application/octet-stream'
      }),

      // Text body parser
      text: express.text({
        limit: '1mb',
        type: 'text/plain'
      })
    };
  }

  static contentTypeValidator() {
    return (req, res, next) => {
      // Skip validation for GET, HEAD, and OPTIONS requests
      if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
      }

      const contentType = req.get('content-type');

      // Require Content-Type header for requests with body
      if (!contentType && req.get('content-length') !== '0') {
        return res.status(400).json({
          error: 'Content-Type header is required'
        });
      }

      // Validate specific content types
      const allowedTypes = [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'application/octet-stream',
        'text/plain'
      ];

      if (contentType && !allowedTypes.some(type => contentType.includes(type))) {
        return res.status(415).json({
          error: 'Unsupported Media Type',
          supportedTypes: allowedTypes
        });
      }

      next();
    };
  }

  static requestSizeValidator(maxSize = '10mb') {
    return (req, res, next) => {
      const contentLength = parseInt(req.get('content-length') || '0');
      const maxBytes = this.parseSize(maxSize);

      if (contentLength > maxBytes) {
        return res.status(413).json({
          error: 'Request entity too large',
          maxSize: maxSize,
          receivedSize: this.formatSize(contentLength)
        });
      }

      next();
    };
  }

  static parseSize(size) {
    if (typeof size === 'number') return size;

    const units = { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3 };
    const match = size.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*([a-z]+)?$/);

    if (!match) throw new Error('Invalid size format');

    const [, value, unit = 'b'] = match;
    return Math.round(parseFloat(value) * (units[unit] || 1));
  }

  static formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(1)} ${units[unitIndex]}`;
  }
}

module.exports = ContentProcessingMiddleware;
```

## 6. Input Validation & Sanitization Middleware

```javascript
// validation-middleware.js
const { validationResult, body, param, query } = require('express-validator');
const DOMPurify = require('isomorphic-dompurify');
const { JSDOM } = require('jsdom');

class ValidationMiddleware {
  constructor() {
    const window = new JSDOM('').window;
    this.domPurify = DOMPurify(window);
  }

  // Validation chain factory
  static createValidationChain() {
    return {
      email: () => body('email')
        .isEmail()
        .normalizeEmail()
        .isLength({ max: 254 })
        .withMessage('Invalid email address'),

      password: () => body('password')
        .isLength({ min: 8, max: 128 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain uppercase, lowercase, number and special character'),

      id: (fieldName = 'id') => param(fieldName)
        .isUUID(4)
        .withMessage('Invalid ID format'),

      string: (fieldName, { min = 1, max = 255 } = {}) => body(fieldName)
        .isString()
        .trim()
        .isLength({ min, max })
        .withMessage(`${fieldName} must be between ${min} and ${max} characters`),

      integer: (fieldName, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) => body(fieldName)
        .isInt({ min, max })
        .toInt()
        .withMessage(`${fieldName} must be an integer between ${min} and ${max}`),

      boolean: (fieldName) => body(fieldName)
        .isBoolean()
        .toBoolean()
        .withMessage(`${fieldName} must be a boolean`),

      array: (fieldName, { minItems = 0, maxItems = 100 } = {}) => body(fieldName)
        .isArray({ min: minItems, max: maxItems })
        .withMessage(`${fieldName} must be an array with ${minItems}-${maxItems} items`),

      enum: (fieldName, values) => body(fieldName)
        .isIn(values)
        .withMessage(`${fieldName} must be one of: ${values.join(', ')}`),

      json: (fieldName) => body(fieldName)
        .custom((value) => {
          try {
            JSON.parse(typeof value === 'string' ? value : JSON.stringify(value));
            return true;
          } catch {
            throw new Error('Invalid JSON format');
          }
        })
    };
  }

  // Handle validation results
  static handleValidationErrors() {
    return (req, res, next) => {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Input validation failed',
            details: errors.array().map(error => ({
              field: error.path || error.param,
              message: error.msg,
              value: error.value,
              location: error.location
            }))
          },
          timestamp: new Date().toISOString(),
          requestId: req.requestId
        });
      }

      next();
    };
  }

  // Sanitization middleware
  sanitize() {
    return (req, res, next) => {
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = this.sanitizeObject(req.body);
      }

      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = this.sanitizeObject(req.query);
      }

      // Sanitize URL parameters
      if (req.params && typeof req.params === 'object') {
        req.params = this.sanitizeObject(req.params);
      }

      next();
    };
  }

  sanitizeObject(obj, maxDepth = 10, currentDepth = 0) {
    if (currentDepth >= maxDepth) {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item, maxDepth, currentDepth + 1));
    }

    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        const sanitizedKey = this.sanitizeString(key);
        sanitized[sanitizedKey] = this.sanitizeObject(value, maxDepth, currentDepth + 1);
      }
      return sanitized;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    return obj;
  }

  sanitizeString(str) {
    if (typeof str !== 'string') return str;

    // Remove null bytes
    str = str.replace(/\0/g, '');

    // Trim whitespace
    str = str.trim();

    // Sanitize HTML/XSS
    str = this.domPurify.sanitize(str, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });

    // Encode HTML entities
    str = str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');

    return str;
  }

  // SQL injection prevention
  static preventSQLInjection() {
    const sqlInjectionPatterns = [
      /(\b(select|insert|update|delete|drop|create|alter|exec|execute|union|script)\b)/i,
      /(\b(or|and)\s+\d+\s*=\s*\d+)/i,
      /("|')\s*(or|and)\s*\1\s*=\s*\1/i,
      /\b(exec|execute)\s*\(/i
    ];

    return (req, res, next) => {
      const checkForSQLInjection = (obj, path = '') => {
        if (typeof obj === 'string') {
          for (const pattern of sqlInjectionPatterns) {
            if (pattern.test(obj)) {
              throw new Error(`Potential SQL injection detected in ${path || 'request'}`);
            }
          }
        } else if (Array.isArray(obj)) {
          obj.forEach((item, index) => checkForSQLInjection(item, `${path}[${index}]`));
        } else if (obj && typeof obj === 'object') {
          for (const [key, value] of Object.entries(obj)) {
            checkForSQLInjection(value, path ? `${path}.${key}` : key);
          }
        }
      };

      try {
        checkForSQLInjection(req.body, 'body');
        checkForSQLInjection(req.query, 'query');
        checkForSQLInjection(req.params, 'params');
        next();
      } catch (error) {
        res.status(400).json({
          success: false,
          error: {
            code: 'SECURITY_VIOLATION',
            message: 'Request blocked for security reasons'
          },
          timestamp: new Date().toISOString(),
          requestId: req.requestId
        });
      }
    };
  }
}

module.exports = ValidationMiddleware;
```

## 7. Authentication Middleware

```javascript
// auth-middleware.js
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

class AuthenticationMiddleware {
  constructor(redisClient, userService, logger) {
    this.redis = redisClient;
    this.userService = userService;
    this.logger = logger;
    this.jwtVerify = promisify(jwt.verify);
  }

  // Main authentication middleware
  authenticate(options = {}) {
    const { optional = false, skipPaths = [] } = options;

    return async (req, res, next) => {
      try {
        // Skip authentication for certain paths
        if (skipPaths.some(path => req.path.startsWith(path))) {
          return next();
        }

        const token = this.extractToken(req);

        if (!token && optional) {
          return next();
        }

        if (!token) {
          return this.sendAuthError(res, 'Authentication required', 401);
        }

        // Verify JWT token
        const decoded = await this.verifyToken(token);

        // Check if session is still valid
        const sessionValid = await this.validateSession(decoded.sessionId);
        if (!sessionValid) {
          return this.sendAuthError(res, 'Session expired', 401);
        }

        // Load full user data
        const user = await this.loadUser(decoded.userId);
        if (!user || user.status !== 'active') {
          return this.sendAuthError(res, 'User not found or inactive', 401);
        }

        // Set user context
        req.user = {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles || [],
          permissions: user.permissions || [],
          tenantId: user.tenantId,
          sessionId: decoded.sessionId,
          tokenExp: decoded.exp
        };

        // Update session activity
        await this.updateSessionActivity(decoded.sessionId);

        // Update request context
        if (req.correlationId) {
          const context = req.context || {};
          context.userId = user.id;
          context.tenantId = user.tenantId;
          req.context = context;
        }

        this.logger.info('User authenticated', {
          userId: user.id,
          sessionId: decoded.sessionId,
          correlationId: req.correlationId
        });

        next();
      } catch (error) {
        this.logger.warn('Authentication failed', {
          error: error.message,
          ip: req.ip,
          correlationId: req.correlationId
        });

        if (optional) {
          return next();
        }

        this.sendAuthError(res, 'Authentication failed', 401);
      }
    };
  }

  extractToken(req) {
    const authHeader = req.get('Authorization');

    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Also check for token in cookies (for web apps)
    if (req.cookies && req.cookies.access_token) {
      return req.cookies.access_token;
    }

    return null;
  }

  async verifyToken(token) {
    try {
      return await this.jwtVerify(token, process.env.JWT_ACCESS_SECRET, {
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE
      });
    } catch (error) {
      throw new Error(`Invalid token: ${error.message}`);
    }
  }

  async validateSession(sessionId) {
    if (!sessionId) return false;

    const sessionKey = `session:${sessionId}`;
    const session = await this.redis.get(sessionKey);

    return !!session;
  }

  async loadUser(userId) {
    // Check cache first
    const cacheKey = `user:${userId}`;
    let user = await this.redis.get(cacheKey);

    if (user) {
      return JSON.parse(user);
    }

    // Load from database
    user = await this.userService.findById(userId);
    if (user) {
      // Cache for 1 hour
      await this.redis.setex(cacheKey, 3600, JSON.stringify(user));
    }

    return user;
  }

  async updateSessionActivity(sessionId) {
    const sessionKey = `session:${sessionId}`;
    const session = await this.redis.get(sessionKey);

    if (session) {
      const sessionData = JSON.parse(session);
      sessionData.lastActivity = new Date().toISOString();

      // Extend session TTL by 24 hours
      await this.redis.setex(sessionKey, 86400, JSON.stringify(sessionData));
    }
  }

  sendAuthError(res, message, statusCode) {
    res.status(statusCode).json({
      success: false,
      error: {
        code: statusCode === 401 ? 'AUTHENTICATION_REQUIRED' : 'AUTHENTICATION_FAILED',
        message
      },
      timestamp: new Date().toISOString()
    });
  }

  // Middleware to require authentication
  requireAuth() {
    return this.authenticate({ optional: false });
  }

  // Middleware for optional authentication
  optionalAuth() {
    return this.authenticate({ optional: true });
  }
}

module.exports = AuthenticationMiddleware;
```

## 8. Authorization & Permissions Middleware

```javascript
// authorization-middleware.js
class AuthorizationMiddleware {
  constructor(rbacService, logger) {
    this.rbac = rbacService;
    this.logger = logger;
  }

  // Role-based authorization
  requireRole(roles) {
    if (typeof roles === 'string') {
      roles = [roles];
    }

    return async (req, res, next) => {
      if (!req.user) {
        return this.sendAuthzError(res, 'Authentication required', 401);
      }

      const userRoles = req.user.roles || [];
      const hasRole = roles.some(role => userRoles.includes(role));

      if (!hasRole) {
        this.logger.warn('Authorization failed - insufficient role', {
          userId: req.user.id,
          requiredRoles: roles,
          userRoles,
          correlationId: req.correlationId
        });

        return this.sendAuthzError(res, 'Insufficient permissions', 403);
      }

      next();
    };
  }

  // Permission-based authorization
  requirePermission(permission) {
    return async (req, res, next) => {
      if (!req.user) {
        return this.sendAuthzError(res, 'Authentication required', 401);
      }

      try {
        const hasPermission = await this.rbac.hasPermission(
          req.user.id,
          permission,
          this.extractResourceContext(req)
        );

        if (!hasPermission) {
          this.logger.warn('Authorization failed - insufficient permission', {
            userId: req.user.id,
            requiredPermission: permission,
            userPermissions: req.user.permissions,
            correlationId: req.correlationId
          });

          return this.sendAuthzError(res, 'Insufficient permissions', 403);
        }

        next();
      } catch (error) {
        this.logger.error('Authorization check failed', {
          error: error.message,
          userId: req.user.id,
          permission,
          correlationId: req.correlationId
        });

        return this.sendAuthzError(res, 'Authorization check failed', 500);
      }
    };
  }

  // Resource ownership authorization
  requireOwnership(resourceIdParam = 'id', resourceType = 'resource') {
    return async (req, res, next) => {
      if (!req.user) {
        return this.sendAuthzError(res, 'Authentication required', 401);
      }

      try {
        const resourceId = req.params[resourceIdParam];
        const isOwner = await this.rbac.isResourceOwner(
          req.user.id,
          resourceType,
          resourceId,
          req.user.tenantId
        );

        if (!isOwner) {
          this.logger.warn('Authorization failed - not owner', {
            userId: req.user.id,
            resourceType,
            resourceId,
            correlationId: req.correlationId
          });

          return this.sendAuthzError(res, 'Resource not found', 404); // Hide existence
        }

        next();
      } catch (error) {
        this.logger.error('Ownership check failed', {
          error: error.message,
          userId: req.user.id,
          resourceType,
          correlationId: req.correlationId
        });

        return this.sendAuthzError(res, 'Authorization check failed', 500);
      }
    };
  }

  // Tenant isolation middleware
  enforceTenantIsolation() {
    return (req, res, next) => {
      if (!req.user || !req.user.tenantId) {
        return this.sendAuthzError(res, 'Tenant context required', 403);
      }

      // Add tenant context to all database queries
      req.tenantContext = {
        tenantId: req.user.tenantId,
        enforceIsolation: true
      };

      // Validate tenant ID in URL params if present
      if (req.params.tenantId && req.params.tenantId !== req.user.tenantId) {
        this.logger.warn('Tenant isolation violation attempt', {
          userId: req.user.id,
          userTenantId: req.user.tenantId,
          requestedTenantId: req.params.tenantId,
          correlationId: req.correlationId
        });

        return this.sendAuthzError(res, 'Access denied', 403);
      }

      next();
    };
  }

  // Dynamic permission checking based on request context
  dynamicPermissionCheck() {
    return async (req, res, next) => {
      if (!req.user) {
        return next();
      }

      const context = this.extractResourceContext(req);
      const requiredPermission = this.inferPermissionFromRequest(req);

      if (requiredPermission) {
        try {
          const hasPermission = await this.rbac.hasContextualPermission(
            req.user.id,
            requiredPermission,
            context
          );

          if (!hasPermission) {
            return this.sendAuthzError(res, 'Insufficient permissions', 403);
          }
        } catch (error) {
          this.logger.error('Dynamic permission check failed', {
            error: error.message,
            userId: req.user.id,
            requiredPermission,
            correlationId: req.correlationId
          });

          return this.sendAuthzError(res, 'Authorization check failed', 500);
        }
      }

      next();
    };
  }

  // Rate limiting based on user permissions
  permissionBasedRateLimit() {
    return async (req, res, next) => {
      if (!req.user) {
        return next();
      }

      const userPermissions = req.user.permissions || [];
      let multiplier = 1;

      // Adjust rate limits based on user permissions
      if (userPermissions.includes('admin:*')) {
        multiplier = 10;
      } else if (userPermissions.includes('premium:*')) {
        multiplier = 5;
      } else if (userPermissions.includes('user:verified')) {
        multiplier = 2;
      }

      // Store multiplier for rate limiting middleware
      req.rateLimitMultiplier = multiplier;
      next();
    };
  }

  extractResourceContext(req) {
    return {
      resourceId: req.params.id || req.params.resourceId,
      resourceType: this.inferResourceType(req.path),
      tenantId: req.user?.tenantId,
      method: req.method,
      ip: req.ip
    };
  }

  inferPermissionFromRequest(req) {
    const path = req.path;
    const method = req.method;

    // Basic CRUD mapping
    const permissionMap = {
      'GET': 'read',
      'POST': 'create',
      'PUT': 'update',
      'PATCH': 'update',
      'DELETE': 'delete'
    };

    const action = permissionMap[method];
    const resourceType = this.inferResourceType(path);

    return action && resourceType ? `${resourceType}:${action}` : null;
  }

  inferResourceType(path) {
    // Extract resource type from path
    const match = path.match(/\/api\/v\d+\/([^\/]+)/);
    return match ? match[1] : 'unknown';
  }

  sendAuthzError(res, message, statusCode) {
    res.status(statusCode).json({
      success: false,
      error: {
        code: statusCode === 401 ? 'AUTHENTICATION_REQUIRED' : 'AUTHORIZATION_FAILED',
        message
      },
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = AuthorizationMiddleware;
```

## 9. Caching Middleware

```javascript
// caching-middleware.js
class CachingMiddleware {
  constructor(redisClient, logger) {
    this.redis = redisClient;
    this.logger = logger;
  }

  // Response caching middleware
  responseCache(options = {}) {
    const {
      ttl = 300,  // 5 minutes default
      keyGenerator = this.defaultKeyGenerator,
      skipCache = () => false,
      vary = ['Accept', 'Accept-Encoding', 'Authorization']
    } = options;

    return async (req, res, next) => {
      // Skip caching for non-GET requests
      if (req.method !== 'GET' || skipCache(req)) {
        return next();
      }

      const cacheKey = keyGenerator(req);

      try {
        // Check cache
        const cached = await this.redis.get(cacheKey);
        if (cached) {
          const { body, headers, statusCode, etag } = JSON.parse(cached);

          // Handle ETag
          if (etag && req.get('If-None-Match') === etag) {
            return res.status(304).end();
          }

          // Set headers
          Object.entries(headers).forEach(([key, value]) => {
            res.set(key, value);
          });

          res.set('X-Cache', 'HIT');
          res.set('X-Cache-Key', this.maskCacheKey(cacheKey));

          return res.status(statusCode).json(body);
        }

        // Cache miss - intercept response
        const originalSend = res.json;
        const originalStatus = res.status;
        let statusCode = 200;

        res.status = function(code) {
          statusCode = code;
          return originalStatus.call(this, code);
        };

        res.json = async function(body) {
          // Only cache successful responses
          if (statusCode === 200) {
            const etag = this.get('ETag');
            const headers = {};

            // Capture response headers to cache
            vary.forEach(header => {
              const value = this.get(header);
              if (value) headers[header] = value;
            });

            const cacheData = {
              body,
              headers,
              statusCode,
              etag,
              cachedAt: new Date().toISOString()
            };

            // Cache response
            await redis.setex(cacheKey, ttl, JSON.stringify(cacheData));
          }

          this.set('X-Cache', 'MISS');
          this.set('X-Cache-Key', maskCacheKey(cacheKey));

          return originalSend.call(this, body);
        };

        next();
      } catch (error) {
        this.logger.warn('Cache middleware error', {
          error: error.message,
          cacheKey,
          correlationId: req.correlationId
        });
        next();
      }
    };
  }

  // Cache invalidation middleware
  invalidateCache(patterns) {
    if (typeof patterns === 'string') {
      patterns = [patterns];
    }

    return async (req, res, next) => {
      const originalSend = res.json;
      const originalStatus = res.status;
      let statusCode = 200;

      res.status = function(code) {
        statusCode = code;
        return originalStatus.call(this, code);
      };

      res.json = async function(body) {
        // Invalidate cache on successful modifications
        if (statusCode >= 200 && statusCode < 300) {
          try {
            for (const pattern of patterns) {
              const resolvedPattern = this.resolvePattern(pattern, req);
              await this.invalidatePattern(resolvedPattern);
            }
          } catch (error) {
            logger.warn('Cache invalidation failed', {
              error: error.message,
              patterns,
              correlationId: req.correlationId
            });
          }
        }

        return originalSend.call(this, body);
      };

      next();
    };
  }

  // ETag middleware for conditional requests
  etag() {
    return (req, res, next) => {
      const originalSend = res.json;

      res.json = function(body) {
        // Generate ETag based on content
        const etag = this.generateETag(body);
        this.set('ETag', etag);

        // Check If-None-Match header
        const clientETag = req.get('If-None-Match');
        if (clientETag === etag) {
          return this.status(304).end();
        }

        return originalSend.call(this, body);
      };

      next();
    };
  }

  defaultKeyGenerator(req) {
    const { method, path, query, user } = req;
    const userId = user ? user.id : 'anonymous';
    const tenantId = user ? user.tenantId : 'public';
    const queryString = new URLSearchParams(query).toString();

    return `cache:${tenantId}:${userId}:${method}:${path}:${queryString}`;
  }

  resolvePattern(pattern, req) {
    return pattern
      .replace('{tenantId}', req.user?.tenantId || 'public')
      .replace('{userId}', req.user?.id || 'anonymous')
      .replace('{resourceId}', req.params.id || '*');
  }

  async invalidatePattern(pattern) {
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
      this.logger.info('Cache invalidated', { pattern, count: keys.length });
    }
  }

  maskCacheKey(key) {
    // Mask sensitive parts of cache key for logging
    return key.replace(/([a-f0-9]{8})[a-f0-9-]+/g, '$1...');
  }

  generateETag(body) {
    const crypto = require('crypto');
    const content = typeof body === 'string' ? body : JSON.stringify(body);
    return `"${crypto.createHash('md5').update(content).digest('hex')}"`;
  }
}

module.exports = CachingMiddleware;
```

## Middleware Registration & Configuration

```javascript
// middleware-setup.js
class MiddlewareSetup {
  constructor(app, dependencies) {
    this.app = app;
    this.redis = dependencies.redis;
    this.logger = dependencies.logger;
    this.userService = dependencies.userService;
    this.rbacService = dependencies.rbacService;
  }

  configure() {
    // 1. Security headers (first)
    this.app.use(SecurityHeadersMiddleware.configure());
    this.app.use(SecurityHeadersMiddleware.customHeaders());

    // 2. Request logging & correlation
    const requestLogger = new RequestLoggingMiddleware(this.logger);
    this.app.use(requestLogger.middleware());

    // 3. CORS
    this.app.use(CORSMiddleware.configure());

    // 4. Rate limiting
    const rateLimiter = new RateLimitingMiddleware(this.redis, this.logger);
    this.app.use('/api/v1/auth', rateLimiter.authLimiter());
    this.app.use('/api/v1/upload', rateLimiter.uploadLimiter());
    this.app.use('/api/v1', rateLimiter.apiLimiter());

    // 5. Content processing
    const contentProcessors = ContentProcessingMiddleware.configure();
    this.app.use(contentProcessors.json);
    this.app.use(contentProcessors.urlencoded);
    this.app.use(contentProcessors.raw);
    this.app.use(ContentProcessingMiddleware.contentTypeValidator());

    // 6. Input validation & sanitization
    const validator = new ValidationMiddleware();
    this.app.use(validator.sanitize());
    this.app.use(ValidationMiddleware.preventSQLInjection());

    // 7. Authentication (for protected routes)
    const auth = new AuthenticationMiddleware(
      this.redis,
      this.userService,
      this.logger
    );

    // Optional auth for public endpoints
    this.app.use('/api/v1/public', auth.optionalAuth());

    // Required auth for protected endpoints
    this.app.use('/api/v1/auth/logout', auth.requireAuth());
    this.app.use('/api/v1/users', auth.requireAuth());
    this.app.use('/api/v1/projects', auth.requireAuth());
    this.app.use('/api/v1/admin', auth.requireAuth());

    // 8. Authorization
    const authz = new AuthorizationMiddleware(this.rbacService, this.logger);
    this.app.use('/api/v1/users', authz.enforceTenantIsolation());
    this.app.use('/api/v1/projects', authz.enforceTenantIsolation());
    this.app.use('/api/v1/admin', authz.requireRole(['admin', 'super-admin']));

    // 9. Caching
    const caching = new CachingMiddleware(this.redis, this.logger);
    this.app.use('/api/v1', caching.responseCache({
      ttl: 300,
      skipCache: (req) => req.method !== 'GET' || req.path.includes('/admin/')
    }));

    // 10. Routes (business logic)
    this.setupRoutes();

    // 11. Error handling (last)
    this.app.use(this.globalErrorHandler());
  }

  setupRoutes() {
    // Route registration
    this.app.use('/api/v1/auth', require('../routes/auth-routes'));
    this.app.use('/api/v1/users', require('../routes/user-routes'));
    this.app.use('/api/v1/projects', require('../routes/project-routes'));
    this.app.use('/api/v1/admin', require('../routes/admin-routes'));

    // Health check routes
    this.app.use('/health', require('../routes/health-routes'));
    this.app.use('/metrics', require('../routes/metrics-routes'));
  }

  globalErrorHandler() {
    return (error, req, res, next) => {
      this.logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        correlationId: req.correlationId,
        userId: req.user?.id,
        url: req.url,
        method: req.method
      });

      // Don't expose internal errors in production
      const message = process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : error.message;

      res.status(error.statusCode || 500).json({
        success: false,
        error: {
          code: error.code || 'INTERNAL_ERROR',
          message
        },
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      });
    };
  }
}

module.exports = MiddlewareSetup;
```

This comprehensive middleware stack provides robust security, performance, and observability features for the REST API system, with clear separation of concerns and modular design for easy maintenance and extension.