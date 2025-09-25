# Monitoring and Observability Architecture

## Overview
Comprehensive monitoring and observability strategy for production REST API with multi-tenant architecture.

## Three Pillars of Observability

### 1. Metrics (Prometheus + Grafana)
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │───►│   Prometheus    │───►│    Grafana      │
│    Metrics      │    │    (TSDB)       │    │  (Visualization)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 2. Logs (ELK Stack)
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │───►│   Logstash      │───►│  Elasticsearch  │───►│     Kibana      │
│     Logs        │    │ (Log Processing)│    │   (Storage)     │    │ (Log Analysis)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 3. Traces (Jaeger/Zipkin)
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │───►│     Jaeger      │───►│   Jaeger UI     │
│    Traces       │    │  (Collection)   │    │  (Visualization)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Application Metrics Implementation

### 1. Business Metrics
```javascript
const promClient = require('prom-client');

class BusinessMetrics {
  constructor() {
    // User engagement metrics
    this.userRegistrations = new promClient.Counter({
      name: 'user_registrations_total',
      help: 'Total number of user registrations',
      labelNames: ['tenant_id', 'source']
    });

    this.userLogins = new promClient.Counter({
      name: 'user_logins_total',
      help: 'Total number of user logins',
      labelNames: ['tenant_id', 'success']
    });

    // API usage metrics
    this.apiRequests = new promClient.Counter({
      name: 'api_requests_total',
      help: 'Total number of API requests',
      labelNames: ['tenant_id', 'method', 'endpoint', 'status']
    });

    this.apiDuration = new promClient.Histogram({
      name: 'api_request_duration_seconds',
      help: 'API request duration in seconds',
      labelNames: ['tenant_id', 'method', 'endpoint'],
      buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
    });

    // Resource usage metrics
    this.activeUsers = new promClient.Gauge({
      name: 'active_users_current',
      help: 'Currently active users',
      labelNames: ['tenant_id']
    });

    this.resourceCount = new promClient.Gauge({
      name: 'tenant_resources_count',
      help: 'Number of resources per tenant',
      labelNames: ['tenant_id', 'resource_type']
    });

    // Revenue/subscription metrics
    this.subscriptionEvents = new promClient.Counter({
      name: 'subscription_events_total',
      help: 'Subscription lifecycle events',
      labelNames: ['tenant_id', 'event_type', 'plan']
    });
  }

  recordUserRegistration(tenantId, source = 'web') {
    this.userRegistrations.inc({ tenant_id: tenantId, source });
  }

  recordLogin(tenantId, success = true) {
    this.userLogins.inc({ tenant_id: tenantId, success: success.toString() });
  }

  recordApiRequest(tenantId, method, endpoint, status, duration) {
    this.apiRequests.inc({ tenant_id: tenantId, method, endpoint, status: status.toString() });
    this.apiDuration.observe({ tenant_id: tenantId, method, endpoint }, duration);
  }

  setActiveUsers(tenantId, count) {
    this.activeUsers.set({ tenant_id: tenantId }, count);
  }

  setResourceCount(tenantId, resourceType, count) {
    this.resourceCount.set({ tenant_id: tenantId, resource_type: resourceType }, count);
  }
}

// Middleware for automatic API metrics
const metricsMiddleware = (metrics) => {
  return (req, res, next) => {
    const start = Date.now();
    const tenantId = req.user?.tenantId || 'unknown';

    res.on('finish', () => {
      const duration = (Date.now() - start) / 1000;
      const endpoint = req.route?.path || req.path;

      metrics.recordApiRequest(
        tenantId,
        req.method,
        endpoint,
        res.statusCode,
        duration
      );
    });

    next();
  };
};
```

### 2. Technical Metrics
```javascript
class TechnicalMetrics {
  constructor() {
    // Database metrics
    this.dbConnections = new promClient.Gauge({
      name: 'database_connections_active',
      help: 'Active database connections',
      labelNames: ['database', 'state']
    });

    this.dbQueryDuration = new promClient.Histogram({
      name: 'database_query_duration_seconds',
      help: 'Database query duration',
      labelNames: ['database', 'operation', 'table'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
    });

    // Cache metrics
    this.cacheOperations = new promClient.Counter({
      name: 'cache_operations_total',
      help: 'Cache operations',
      labelNames: ['operation', 'result']
    });

    this.cacheHitRatio = new promClient.Gauge({
      name: 'cache_hit_ratio',
      help: 'Cache hit ratio',
      labelNames: ['cache_type']
    });

    // Queue metrics
    this.queueSize = new promClient.Gauge({
      name: 'queue_size_current',
      help: 'Current queue size',
      labelNames: ['queue_name']
    });

    this.queueProcessingTime = new promClient.Histogram({
      name: 'queue_processing_duration_seconds',
      help: 'Queue job processing time',
      labelNames: ['queue_name', 'job_type'],
      buckets: [0.1, 0.5, 1, 5, 10, 30, 60]
    });

    // Error metrics
    this.errorRate = new promClient.Counter({
      name: 'errors_total',
      help: 'Total errors',
      labelNames: ['service', 'error_type', 'tenant_id']
    });

    // Security metrics
    this.securityEvents = new promClient.Counter({
      name: 'security_events_total',
      help: 'Security events',
      labelNames: ['event_type', 'severity', 'source_ip']
    });
  }
}

// Database monitoring wrapper
class MonitoredDatabase {
  constructor(db, metrics) {
    this.db = db;
    this.metrics = metrics;
  }

  async query(sql, params, options = {}) {
    const start = Date.now();
    const operation = sql.trim().split(' ')[0].toUpperCase();
    const table = this.extractTableName(sql);

    try {
      this.metrics.dbConnections.inc({ database: 'postgresql', state: 'active' });

      const result = await this.db.query(sql, params);

      const duration = (Date.now() - start) / 1000;
      this.metrics.dbQueryDuration.observe(
        { database: 'postgresql', operation, table },
        duration
      );

      return result;
    } catch (error) {
      this.metrics.errorRate.inc({
        service: 'database',
        error_type: error.constructor.name,
        tenant_id: options.tenantId || 'unknown'
      });
      throw error;
    } finally {
      this.metrics.dbConnections.dec({ database: 'postgresql', state: 'active' });
    }
  }

  extractTableName(sql) {
    const match = sql.match(/(?:FROM|INTO|UPDATE|JOIN)\s+(\w+)/i);
    return match ? match[1] : 'unknown';
  }
}
```

## Structured Logging Implementation

### 1. Logger Configuration
```javascript
const winston = require('winston');
const { ElasticsearchTransport } = require('winston-elasticsearch');

class ApplicationLogger {
  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        this.addCorrelationId(),
        this.addTenantContext()
      ),
      defaultMeta: {
        service: process.env.SERVICE_NAME || 'api',
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
          level: 'error',
          maxsize: 100 * 1024 * 1024, // 100MB
          maxFiles: 10
        }),
        new winston.transports.File({
          filename: 'logs/combined.log',
          maxsize: 100 * 1024 * 1024,
          maxFiles: 10
        })
      ]
    });

    // Add Elasticsearch transport for production
    if (process.env.NODE_ENV === 'production') {
      this.logger.add(new ElasticsearchTransport({
        level: 'info',
        clientOpts: {
          node: process.env.ELASTICSEARCH_URL
        },
        index: `logs-${process.env.SERVICE_NAME}-${new Date().toISOString().slice(0, 7)}`
      }));
    }
  }

  addCorrelationId() {
    return winston.format((info, opts) => {
      const correlationId = this.getCorrelationId();
      if (correlationId) {
        info.correlationId = correlationId;
      }
      return info;
    });
  }

  addTenantContext() {
    return winston.format((info, opts) => {
      const tenantContext = this.getTenantContext();
      if (tenantContext) {
        info.tenant = tenantContext;
      }
      return info;
    });
  }

  getCorrelationId() {
    // Use AsyncLocalStorage or similar for request correlation
    return global.correlationId || null;
  }

  getTenantContext() {
    return global.tenantContext || null;
  }

  // Business event logging
  logBusinessEvent(event, data, user) {
    this.logger.info({
      type: 'BUSINESS_EVENT',
      event,
      data,
      user: user ? {
        id: user.id,
        email: user.email,
        tenantId: user.tenantId
      } : null,
      timestamp: new Date().toISOString()
    });
  }

  // Security event logging
  logSecurityEvent(event, severity, details, req) {
    this.logger.warn({
      type: 'SECURITY_EVENT',
      event,
      severity,
      details,
      ip: req?.ip,
      userAgent: req?.get('User-Agent'),
      user: req?.user ? {
        id: req.user.id,
        email: req.user.email,
        tenantId: req.user.tenantId
      } : null,
      timestamp: new Date().toISOString()
    });
  }

  // Performance logging
  logPerformanceEvent(operation, duration, metadata) {
    this.logger.info({
      type: 'PERFORMANCE',
      operation,
      duration,
      metadata,
      timestamp: new Date().toISOString()
    });
  }

  // Error logging with context
  logError(error, context = {}) {
    this.logger.error({
      type: 'ERROR',
      message: error.message,
      stack: error.stack,
      context,
      timestamp: new Date().toISOString()
    });
  }
}

// Request logging middleware
const requestLoggingMiddleware = (logger) => {
  return (req, res, next) => {
    const start = Date.now();

    // Generate correlation ID
    const correlationId = require('crypto').randomUUID();
    req.correlationId = correlationId;
    res.set('X-Correlation-ID', correlationId);

    // Set global context (use AsyncLocalStorage in production)
    global.correlationId = correlationId;
    global.tenantContext = req.user?.tenantId;

    res.on('finish', () => {
      const duration = Date.now() - start;
      const logLevel = res.statusCode >= 400 ? 'error' : 'info';

      logger.logger[logLevel]({
        type: 'HTTP_REQUEST',
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        user: req.user ? {
          id: req.user.id,
          email: req.user.email,
          tenantId: req.user.tenantId
        } : null,
        correlationId
      });
    });

    next();
  };
};
```

### 2. Distributed Tracing
```javascript
const opentelemetry = require('@opentelemetry/api');
const { NodeSDK } = require('@opentelemetry/auto-instrumentations-node');
const { JaegerExporter } = require('@opentelemetry/exporter-jaeger');
const { Resource } = require('@opentelemetry/resources');
const { SemanticResourceAttributes } = require('@opentelemetry/semantic-conventions');

class TracingService {
  constructor() {
    this.tracer = opentelemetry.trace.getTracer('rest-api-service');
    this.initializeTracing();
  }

  initializeTracing() {
    const sdk = new NodeSDK({
      resource: new Resource({
        [SemanticResourceAttributes.SERVICE_NAME]: process.env.SERVICE_NAME || 'api',
        [SemanticResourceAttributes.SERVICE_VERSION]: process.env.APP_VERSION || '1.0.0',
        [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: process.env.NODE_ENV || 'development'
      }),
      traceExporter: new JaegerExporter({
        endpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces'
      }),
      instrumentations: [] // Auto-instrumentations
    });

    sdk.start();
  }

  // Create custom spans for business operations
  async traceBusinessOperation(operationName, tenantId, userId, operation) {
    const span = this.tracer.startSpan(operationName, {
      attributes: {
        'tenant.id': tenantId,
        'user.id': userId,
        'operation.type': 'business'
      }
    });

    try {
      const result = await operation();
      span.setStatus({ code: opentelemetry.SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.setStatus({
        code: opentelemetry.SpanStatusCode.ERROR,
        message: error.message
      });
      span.recordException(error);
      throw error;
    } finally {
      span.end();
    }
  }

  // Database operation tracing
  async traceDatabaseOperation(operation, query, params) {
    const span = this.tracer.startSpan('database.query', {
      attributes: {
        'db.system': 'postgresql',
        'db.operation': operation,
        'db.statement': query
      }
    });

    try {
      const result = await this.db.query(query, params);
      span.setAttributes({
        'db.rows_affected': result.rowCount
      });
      return result;
    } catch (error) {
      span.recordException(error);
      throw error;
    } finally {
      span.end();
    }
  }

  // Cache operation tracing
  async traceCacheOperation(operation, key, ttl) {
    const span = this.tracer.startSpan('cache.operation', {
      attributes: {
        'cache.system': 'redis',
        'cache.operation': operation,
        'cache.key': key,
        'cache.ttl': ttl
      }
    });

    try {
      const result = await this.cache[operation](key);
      span.setAttributes({
        'cache.hit': result !== null
      });
      return result;
    } catch (error) {
      span.recordException(error);
      throw error;
    } finally {
      span.end();
    }
  }
}
```

## Health Checks and Service Discovery

### 1. Health Check Implementation
```javascript
class HealthCheckService {
  constructor(dependencies) {
    this.dependencies = dependencies;
    this.checks = new Map();
    this.setupHealthChecks();
  }

  setupHealthChecks() {
    // Database health check
    this.checks.set('database', async () => {
      try {
        await this.dependencies.db.query('SELECT 1');
        return { status: 'healthy', responseTime: Date.now() };
      } catch (error) {
        return { status: 'unhealthy', error: error.message };
      }
    });

    // Redis health check
    this.checks.set('redis', async () => {
      try {
        const start = Date.now();
        await this.dependencies.redis.ping();
        return { status: 'healthy', responseTime: Date.now() - start };
      } catch (error) {
        return { status: 'unhealthy', error: error.message };
      }
    });

    // External API health check
    this.checks.set('external_api', async () => {
      try {
        const response = await fetch(`${process.env.EXTERNAL_API_URL}/health`, {
          timeout: 5000
        });
        return {
          status: response.ok ? 'healthy' : 'unhealthy',
          statusCode: response.status
        };
      } catch (error) {
        return { status: 'unhealthy', error: error.message };
      }
    });
  }

  async performHealthCheck() {
    const results = {};
    const start = Date.now();

    for (const [name, check] of this.checks) {
      try {
        results[name] = await Promise.race([
          check(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), 5000)
          )
        ]);
      } catch (error) {
        results[name] = { status: 'unhealthy', error: error.message };
      }
    }

    const overallStatus = Object.values(results).every(r => r.status === 'healthy')
      ? 'healthy' : 'unhealthy';

    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      duration: Date.now() - start,
      checks: results,
      version: process.env.APP_VERSION,
      environment: process.env.NODE_ENV
    };
  }

  // Express middleware for health endpoints
  healthEndpoint() {
    return async (req, res) => {
      const health = await this.performHealthCheck();
      const statusCode = health.status === 'healthy' ? 200 : 503;
      res.status(statusCode).json(health);
    };
  }

  // Readiness check (for Kubernetes)
  readinessEndpoint() {
    return async (req, res) => {
      // Check if service is ready to accept traffic
      const critical = ['database', 'redis'];
      const health = await this.performHealthCheck();

      const isReady = critical.every(service =>
        health.checks[service]?.status === 'healthy'
      );

      res.status(isReady ? 200 : 503).json({
        ready: isReady,
        timestamp: new Date().toISOString()
      });
    };
  }

  // Liveness check (for Kubernetes)
  livenessEndpoint() {
    return (req, res) => {
      // Simple check - if the process is running, it's alive
      res.status(200).json({
        alive: true,
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    };
  }
}
```

## Alerting and Incident Response

### 1. Alert Manager Configuration
```javascript
class AlertManager {
  constructor(channels) {
    this.channels = channels; // Slack, PagerDuty, Email, etc.
    this.alertRules = new Map();
    this.setupAlertRules();
  }

  setupAlertRules() {
    // High error rate alert
    this.alertRules.set('high_error_rate', {
      condition: 'error_rate > 0.05', // 5% error rate
      duration: '5m',
      severity: 'warning',
      message: 'High error rate detected: {{ $value }}%'
    });

    // Database connection issues
    this.alertRules.set('database_connections', {
      condition: 'database_connections_active / database_connections_max > 0.8',
      duration: '2m',
      severity: 'critical',
      message: 'Database connection pool nearly exhausted'
    });

    // High response time
    this.alertRules.set('high_response_time', {
      condition: 'api_request_duration_seconds_p95 > 2',
      duration: '5m',
      severity: 'warning',
      message: '95th percentile response time is {{ $value }}s'
    });

    // Security incidents
    this.alertRules.set('security_incident', {
      condition: 'security_events_total > 10',
      duration: '1m',
      severity: 'critical',
      message: 'Multiple security events detected'
    });

    // Disk space
    this.alertRules.set('low_disk_space', {
      condition: 'disk_usage_percent > 0.85',
      duration: '5m',
      severity: 'warning',
      message: 'Disk usage is {{ $value }}%'
    });
  }

  async processAlert(alertName, value, labels) {
    const rule = this.alertRules.get(alertName);
    if (!rule) return;

    const alert = {
      alertName,
      severity: rule.severity,
      message: rule.message.replace('{{ $value }}', value),
      labels,
      timestamp: new Date().toISOString(),
      runbook: this.getRunbookUrl(alertName)
    };

    // Send to appropriate channels based on severity
    const channels = this.getChannelsForSeverity(rule.severity);
    await Promise.all(channels.map(channel => this.sendAlert(channel, alert)));

    // Log alert
    console.log('Alert triggered:', alert);
  }

  getChannelsForSeverity(severity) {
    const channelMap = {
      'info': ['email'],
      'warning': ['slack', 'email'],
      'critical': ['slack', 'pagerduty', 'email'],
      'emergency': ['slack', 'pagerduty', 'email', 'sms']
    };
    return channelMap[severity] || ['email'];
  }

  async sendAlert(channel, alert) {
    const sender = this.channels[channel];
    if (sender) {
      await sender.send(alert);
    }
  }

  getRunbookUrl(alertName) {
    return `https://docs.company.com/runbooks/${alertName}`;
  }
}

// Slack notification channel
class SlackAlertChannel {
  constructor(webhookUrl) {
    this.webhookUrl = webhookUrl;
  }

  async send(alert) {
    const color = this.getColorForSeverity(alert.severity);
    const payload = {
      attachments: [{
        color,
        title: `🚨 ${alert.severity.toUpperCase()}: ${alert.alertName}`,
        text: alert.message,
        fields: [
          { title: 'Severity', value: alert.severity, short: true },
          { title: 'Timestamp', value: alert.timestamp, short: true },
          { title: 'Runbook', value: `<${alert.runbook}|View Runbook>`, short: true }
        ],
        footer: 'Monitoring System',
        ts: Math.floor(Date.now() / 1000)
      }]
    };

    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  }

  getColorForSeverity(severity) {
    const colors = {
      'info': '#36a64f',
      'warning': '#ff9900',
      'critical': '#ff0000',
      'emergency': '#8b0000'
    };
    return colors[severity] || '#36a64f';
  }
}
```

## Monitoring Dashboard Configuration

### 1. Grafana Dashboard JSON
```json
{
  "dashboard": {
    "id": null,
    "title": "REST API Monitoring Dashboard",
    "tags": ["api", "monitoring", "production"],
    "timezone": "browser",
    "panels": [
      {
        "title": "API Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(api_requests_total[5m])) by (tenant_id)",
            "legendFormat": "{{ tenant_id }}"
          }
        ]
      },
      {
        "title": "Response Time P95",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, sum(rate(api_request_duration_seconds_bucket[5m])) by (le, tenant_id))",
            "legendFormat": "{{ tenant_id }} - 95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(api_requests_total{status=~\"4..|5..\"}[5m])) by (tenant_id) / sum(rate(api_requests_total[5m])) by (tenant_id)",
            "legendFormat": "{{ tenant_id }}"
          }
        ]
      },
      {
        "title": "Active Users",
        "type": "singlestat",
        "targets": [
          {
            "expr": "sum(active_users_current)",
            "legendFormat": "Total Active Users"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "cache_hit_ratio",
            "legendFormat": "{{ cache_type }}"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "database_connections_active",
            "legendFormat": "Active Connections"
          }
        ]
      }
    ]
  }
}
```

This comprehensive monitoring and observability architecture provides full visibility into system performance, user behavior, and operational health across all layers of the REST API.