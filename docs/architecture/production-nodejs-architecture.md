# Production-Ready Node.js Hello World Application Architecture

## System Overview

This document defines the architecture for a production-ready Node.js hello world application that demonstrates enterprise-grade patterns, scalability, and operational excellence.

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer/Reverse Proxy             │
│                    (NGINX/ALB/CloudFlare)                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Application Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   App 1     │  │   App 2     │  │   App N     │         │
│  │  Port 3001  │  │  Port 3002  │  │  Port 300N  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Monitoring & Observability                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Metrics   │  │    Logs     │  │   Traces    │         │
│  │ (Prometheus)│  │ (Winston)   │  │ (OpenTel)   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## 2. Modular Folder Structure

```
production-nodejs-app/
├── src/                          # Source code
│   ├── app/                      # Application layer
│   │   ├── controllers/          # Request handlers
│   │   ├── middleware/           # Express middleware
│   │   ├── routes/               # Route definitions
│   │   └── validators/           # Input validation
│   ├── core/                     # Core business logic
│   │   ├── services/             # Business services
│   │   ├── models/               # Domain models
│   │   └── interfaces/           # Type definitions
│   ├── infrastructure/           # External concerns
│   │   ├── database/             # Database layer
│   │   ├── cache/                # Caching layer
│   │   ├── messaging/            # Message queues
│   │   └── external/             # External APIs
│   ├── config/                   # Configuration management
│   │   ├── database.js           # Database configuration
│   │   ├── redis.js              # Cache configuration
│   │   ├── logging.js            # Logging configuration
│   │   └── index.js              # Main config aggregator
│   ├── utils/                    # Utility functions
│   │   ├── logger.js             # Logging utilities
│   │   ├── errors.js             # Error classes
│   │   ├── validation.js         # Validation helpers
│   │   └── security.js           # Security utilities
│   └── server.js                 # Server entry point
├── tests/                        # Test files
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   ├── e2e/                      # End-to-end tests
│   ├── performance/              # Performance tests
│   ├── fixtures/                 # Test data
│   └── utils/                    # Test utilities
├── docs/                         # Documentation
│   ├── api/                      # API documentation
│   ├── architecture/             # Architecture docs
│   └── deployment/               # Deployment guides
├── scripts/                      # Build and deployment scripts
│   ├── build.sh                  # Build script
│   ├── deploy.sh                 # Deployment script
│   └── health-check.sh           # Health check script
├── docker/                       # Docker configurations
│   ├── Dockerfile                # Production dockerfile
│   ├── Dockerfile.dev            # Development dockerfile
│   └── docker-compose.yml        # Local development
├── k8s/                          # Kubernetes manifests
│   ├── deployment.yaml           # K8s deployment
│   ├── service.yaml              # K8s service
│   └── configmap.yaml            # Configuration
├── .github/                      # GitHub workflows
│   └── workflows/                # CI/CD pipelines
├── config/                       # Environment configs
│   ├── production.json           # Production config
│   ├── staging.json              # Staging config
│   └── development.json          # Development config
├── package.json                  # Dependencies
├── Dockerfile                    # Production container
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
├── .eslintrc.js                  # Linting rules
├── .prettierrc                   # Code formatting
├── jest.config.js                # Testing configuration
└── README.md                     # Project documentation
```

## 3. Separation of Concerns

### 3.1 Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Presentation Layer                          │
│  Controllers, Routes, Middleware, Validators               │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Business Layer                             │
│     Services, Domain Models, Business Logic                │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Infrastructure Layer                         │
│  Database, Cache, External APIs, File System               │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Dependency Flow

- **Presentation → Business**: Controllers call services
- **Business → Infrastructure**: Services call repositories
- **Infrastructure ↔ External**: Repositories interact with databases/APIs

## 4. Configuration Management Architecture

### 4.1 Configuration Hierarchy

```
Environment Variables (Highest Priority)
    ↓
Config Files (env-specific)
    ↓
Default Configuration (Lowest Priority)
```

### 4.2 Configuration Structure

```javascript
// config/index.js
const config = {
  app: {
    name: process.env.APP_NAME || 'production-nodejs-app',
    version: process.env.APP_VERSION || '1.0.0',
    port: parseInt(process.env.PORT) || 3000,
    host: process.env.HOST || '0.0.0.0',
    nodeEnv: process.env.NODE_ENV || 'development'
  },
  server: {
    timeout: parseInt(process.env.SERVER_TIMEOUT) || 30000,
    keepAliveTimeout: parseInt(process.env.KEEP_ALIVE_TIMEOUT) || 5000,
    headersTimeout: parseInt(process.env.HEADERS_TIMEOUT) || 6000
  },
  security: {
    cors: {
      origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    },
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
      standardHeaders: true,
      legacyHeaders: false
    }
  },
  monitoring: {
    health: {
      endpoint: '/health',
      timeout: parseInt(process.env.HEALTH_TIMEOUT) || 5000
    },
    metrics: {
      endpoint: '/metrics',
      collectDefaultMetrics: true
    }
  }
};
```

## 5. Health Check Endpoints Architecture

### 5.1 Health Check Levels

```
┌─────────────────────────────────────────────────────────────┐
│                   Liveness Probe                            │
│  /health/live - Basic application availability             │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Readiness Probe                            │
│  /health/ready - Application ready to serve traffic        │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                   Deep Health Check                         │
│  /health - Comprehensive system health                     │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Health Check Components

```javascript
// src/app/controllers/healthController.js
class HealthController {
  async liveness(req, res) {
    // Basic application liveness
    return res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  }

  async readiness(req, res) {
    // Check if app is ready to serve traffic
    const checks = await Promise.allSettled([
      this.checkDatabase(),
      this.checkCache(),
      this.checkExternalServices()
    ]);

    const isReady = checks.every(check => check.status === 'fulfilled');

    return res.status(isReady ? 200 : 503).json({
      status: isReady ? 'ready' : 'not_ready',
      checks: this.formatChecks(checks),
      timestamp: new Date().toISOString()
    });
  }

  async comprehensive(req, res) {
    // Detailed health information
    const health = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: process.env.APP_VERSION,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      dependencies: await this.checkAllDependencies()
    };

    return res.json(health);
  }
}
```

## 6. Graceful Shutdown Handling

### 6.1 Shutdown Sequence

```
SIGTERM/SIGINT → Stop accepting new connections →
Close existing connections → Cleanup resources →
Exit process
```

### 6.2 Graceful Shutdown Implementation

```javascript
// src/utils/gracefulShutdown.js
class GracefulShutdown {
  constructor(server, logger) {
    this.server = server;
    this.logger = logger;
    this.isShuttingDown = false;
    this.connections = new Set();
    this.setupHandlers();
  }

  setupHandlers() {
    process.on('SIGTERM', () => this.shutdown('SIGTERM'));
    process.on('SIGINT', () => this.shutdown('SIGINT'));
    process.on('uncaughtException', (error) => this.handleUncaughtException(error));
    process.on('unhandledRejection', (reason) => this.handleUnhandledRejection(reason));
  }

  async shutdown(signal) {
    if (this.isShuttingDown) return;

    this.isShuttingDown = true;
    this.logger.info(`Received ${signal}, starting graceful shutdown`);

    // Stop accepting new connections
    this.server.close(() => {
      this.logger.info('HTTP server closed');
    });

    // Close existing connections gracefully
    await this.closeConnections();

    // Cleanup resources
    await this.cleanup();

    this.logger.info('Graceful shutdown completed');
    process.exit(0);
  }

  async closeConnections() {
    const timeout = parseInt(process.env.SHUTDOWN_TIMEOUT) || 10000;

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.logger.warn('Force closing remaining connections');
        this.connections.forEach(conn => conn.destroy());
        resolve();
      }, timeout);

      this.server.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  async cleanup() {
    // Close database connections
    // Close cache connections
    // Stop background jobs
    // Flush logs
  }
}
```

## 7. Middleware Pipeline Architecture

### 7.1 Middleware Stack Order

```
Request → Security → Logging → Parsing → Validation →
Business Logic → Response → Error Handling
```

### 7.2 Middleware Implementation

```javascript
// src/app/middleware/index.js
const middlewareStack = [
  // 1. Security middleware (first)
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"]
      }
    }
  }),

  // 2. CORS
  cors(config.security.cors),

  // 3. Rate limiting
  rateLimit(config.security.rateLimit),

  // 4. Request logging
  requestLogger,

  // 5. Body parsing
  express.json({ limit: '10mb' }),
  express.urlencoded({ extended: true, limit: '10mb' }),

  // 6. Request validation
  requestValidator,

  // 7. Authentication (if required)
  authentication,

  // 8. Authorization (if required)
  authorization
];
```

## 8. Environment Variable Management

### 8.1 Environment Variable Categories

```javascript
// config/env.js
const envSchema = {
  // Application
  APP_NAME: { required: false, default: 'production-nodejs-app' },
  APP_VERSION: { required: false, default: '1.0.0' },
  NODE_ENV: { required: true, enum: ['development', 'staging', 'production'] },
  PORT: { required: false, type: 'number', default: 3000 },

  // Security
  JWT_SECRET: { required: true, sensitive: true },
  CORS_ORIGIN: { required: false, default: 'http://localhost:3000' },

  // Database
  DATABASE_URL: { required: true, sensitive: true },
  DATABASE_POOL_SIZE: { required: false, type: 'number', default: 10 },

  // Cache
  REDIS_URL: { required: false, sensitive: true },
  CACHE_TTL: { required: false, type: 'number', default: 3600 },

  // Monitoring
  LOG_LEVEL: { required: false, enum: ['error', 'warn', 'info', 'debug'], default: 'info' },
  METRICS_ENABLED: { required: false, type: 'boolean', default: true }
};
```

### 8.2 Environment Validation

```javascript
// src/utils/envValidator.js
class EnvironmentValidator {
  static validate() {
    const errors = [];

    Object.entries(envSchema).forEach(([key, schema]) => {
      const value = process.env[key];

      if (schema.required && !value) {
        errors.push(`Required environment variable ${key} is missing`);
      }

      if (value && schema.enum && !schema.enum.includes(value)) {
        errors.push(`Environment variable ${key} must be one of: ${schema.enum.join(', ')}`);
      }

      if (value && schema.type === 'number' && isNaN(Number(value))) {
        errors.push(`Environment variable ${key} must be a number`);
      }
    });

    if (errors.length > 0) {
      throw new Error(`Environment validation failed:\n${errors.join('\n')}`);
    }
  }
}
```

## 9. Logging Architecture

### 9.1 Structured Logging Levels

```
ERROR: System errors, exceptions
WARN:  Warnings, deprecated usage
INFO:  General information, requests
DEBUG: Detailed debugging information
```

### 9.2 Logging Implementation

```javascript
// src/utils/logger.js
const winston = require('winston');

class Logger {
  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: {
        service: process.env.APP_NAME || 'production-nodejs-app',
        version: process.env.APP_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development'
      },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({
          filename: 'logs/error.log',
          level: 'error'
        }),
        new winston.transports.File({
          filename: 'logs/combined.log'
        })
      ]
    });
  }

  error(message, meta = {}) {
    this.logger.error(message, meta);
  }

  warn(message, meta = {}) {
    this.logger.warn(message, meta);
  }

  info(message, meta = {}) {
    this.logger.info(message, meta);
  }

  debug(message, meta = {}) {
    this.logger.debug(message, meta);
  }
}
```

## 10. Error Handling Flow

### 10.1 Error Hierarchy

```
ApplicationError (Base)
├── ValidationError
├── AuthenticationError
├── AuthorizationError
├── NotFoundError
├── ConflictError
└── InternalServerError
```

### 10.2 Error Handling Implementation

```javascript
// src/utils/errors.js
class ApplicationError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

// Global error handler middleware
const errorHandler = (error, req, res, next) => {
  const logger = req.logger || console;

  // Log error
  logger.error('Request error', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Handle known errors
  if (error instanceof ApplicationError) {
    return res.status(error.statusCode).json({
      error: {
        message: error.message,
        code: error.code,
        timestamp: error.timestamp
      }
    });
  }

  // Handle unknown errors
  res.status(500).json({
    error: {
      message: 'Internal server error',
      code: 'INTERNAL_ERROR',
      timestamp: new Date().toISOString()
    }
  });
};
```

## 11. Testing Structure

### 11.1 Testing Pyramid

```
    Unit Tests (70%)
   ┌─────────────────┐
   │  Components     │
   │  Services       │
   │  Utilities      │
   └─────────────────┘

  Integration Tests (20%)
 ┌─────────────────────┐
 │  API Endpoints      │
 │  Database           │
 │  External Services  │
 └─────────────────────┘

E2E Tests (10%)
┌─────────────────────────┐
│  Complete User Flows    │
│  Critical Paths         │
└─────────────────────────┘
```

### 11.2 Test Configuration

```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'node',
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/**/*.test.js',
    '!src/server.js'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  testMatch: [
    '**/tests/unit/**/*.test.js',
    '**/tests/integration/**/*.test.js'
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js']
};
```

## 12. Deployment Architecture

### 12.1 Container Strategy

```dockerfile
# Multi-stage Dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine AS runtime
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .
USER nodejs
EXPOSE 3000
CMD ["node", "src/server.js"]
```

### 12.2 Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: production-nodejs-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: production-nodejs-app
  template:
    metadata:
      labels:
        app: production-nodejs-app
    spec:
      containers:
      - name: app
        image: production-nodejs-app:latest
        ports:
        - containerPort: 3000
        livenessProbe:
          httpGet:
            path: /health/live
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
```

## 13. Monitoring and Observability

### 13.1 Metrics Collection

```javascript
// src/utils/metrics.js
const prometheus = require('prom-client');

const metrics = {
  httpRequestDuration: new prometheus.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status_code']
  }),

  httpRequestTotal: new prometheus.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code']
  }),

  activeConnections: new prometheus.Gauge({
    name: 'active_connections',
    help: 'Number of active connections'
  })
};

// Collect default metrics
prometheus.collectDefaultMetrics();
```

## 14. Security Considerations

### 14.1 Security Headers
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security

### 14.2 Input Validation
- Request body validation
- Parameter sanitization
- SQL injection prevention
- XSS protection

### 14.3 Authentication & Authorization
- JWT token validation
- Role-based access control
- Rate limiting
- CORS configuration

## 15. Performance Optimization

### 15.1 Caching Strategy
- Redis for session storage
- HTTP response caching
- Database query caching
- Static asset caching

### 15.2 Connection Pooling
- Database connection pools
- HTTP keep-alive connections
- WebSocket connection management

## 16. Development Workflow

### 16.1 Local Development
```bash
# Development setup
npm install
npm run dev
npm run test:watch
```

### 16.2 CI/CD Pipeline
1. Code quality checks (ESLint, Prettier)
2. Unit and integration tests
3. Security scanning
4. Build and package
5. Deploy to staging
6. E2E tests
7. Deploy to production

This architecture provides a robust foundation for a production-ready Node.js application with enterprise-grade patterns, scalability, and operational excellence.