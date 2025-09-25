# Caching Strategy for Production REST API

## Overview
Multi-layer caching architecture designed for high performance, scalability, and tenant isolation.

## Caching Architecture

### Layer 1: CDN/Edge Caching
```
┌─────────────────┐
│   CloudFlare    │ ← Static assets, API responses (public)
│   /Amazon CF    │   TTL: 1h - 24h
└─────────────────┘
```

### Layer 2: API Gateway Caching
```
┌─────────────────┐
│   Kong/Envoy    │ ← Rate limit counters, routing cache
│   Gateway       │   TTL: 5-60 minutes
└─────────────────┘
```

### Layer 3: Application Cache (Redis)
```
┌─────────────────┐
│  Redis Cluster  │ ← Session data, frequently accessed data
│  (Distributed)  │   TTL: Variable (1m - 24h)
└─────────────────┘
```

### Layer 4: Database Query Cache
```
┌─────────────────┐
│   PostgreSQL    │ ← Query result cache, prepared statements
│  Shared Buffers │   Managed by PostgreSQL
└─────────────────┘
```

## Redis Cluster Configuration

### Cluster Setup
```yaml
# Redis Cluster Configuration
cluster:
  nodes: 6  # 3 masters, 3 replicas
  replicas: 1
  failover: automatic

memory:
  maxmemory: 4gb
  policy: allkeys-lru

persistence:
  enabled: true
  save: "900 1 300 10 60 10000"
  appendonly: yes
  appendfsync: everysec

security:
  requirepass: "${REDIS_PASSWORD}"
  tls_enabled: true
  acl_enabled: true
```

### Connection Pooling
```javascript
// Redis connection configuration
const redis = require('ioredis');

const cluster = new redis.Cluster([
  { host: 'redis-node-1', port: 6379 },
  { host: 'redis-node-2', port: 6379 },
  { host: 'redis-node-3', port: 6379 }
], {
  redisOptions: {
    password: process.env.REDIS_PASSWORD,
    tls: process.env.NODE_ENV === 'production' ? {} : null
  },
  maxRetriesPerRequest: 3,
  retryDelayOnFailover: 100,
  enableOfflineQueue: false,
  lazyConnect: true
});
```

## Caching Strategies by Data Type

### 1. User Sessions
```
Key Pattern: session:{tenant_id}:{user_id}:{session_id}
TTL: 24 hours (configurable)
Strategy: Write-through with refresh on access
Invalidation: Manual on logout/password change

Example:
session:acme:user123:sess456 → {
  userId: "user123",
  tenantId: "acme",
  roles: ["admin"],
  permissions: ["user:read", "user:write"],
  lastAccess: "2025-01-15T10:30:00Z"
}
```

### 2. User Profile Data
```
Key Pattern: user:{tenant_id}:{user_id}
TTL: 1 hour
Strategy: Cache-aside with lazy loading
Invalidation: TTL + manual on profile update

Example:
user:acme:user123 → {
  id: "user123",
  email: "john@acme.com",
  firstName: "John",
  lastName: "Doe",
  roles: ["admin"],
  lastLogin: "2025-01-15T09:00:00Z"
}
```

### 3. Frequently Accessed Resources
```
Key Pattern: resource:{tenant_id}:{resource_type}:{resource_id}
TTL: 30 minutes
Strategy: Write-through with background refresh
Invalidation: TTL + event-driven

Example:
resource:acme:project:proj123 → {
  id: "proj123",
  name: "Website Redesign",
  status: "active",
  memberCount: 5,
  lastModified: "2025-01-15T08:30:00Z"
}
```

### 4. API Response Cache
```
Key Pattern: api:{version}:{tenant_id}:{endpoint_hash}:{query_hash}
TTL: 5-15 minutes (based on data volatility)
Strategy: Cache-aside with ETag support
Invalidation: TTL + content-based

Example:
api:v1:acme:users:list:abc123 → {
  data: [...],
  etag: "W/\"1234567890\"",
  totalCount: 150,
  cached_at: "2025-01-15T10:25:00Z"
}
```

### 5. Configuration Data
```
Key Pattern: config:{tenant_id}:{config_type}
TTL: 6 hours
Strategy: Write-through with immediate update
Invalidation: Manual on configuration change

Example:
config:acme:app_settings → {
  theme: "dark",
  timezone: "America/New_York",
  features: ["advanced_reporting", "api_access"],
  limits: { api_calls_per_hour: 1000 }
}
```

## Cache Invalidation Strategies

### 1. Time-Based Expiration (TTL)
```javascript
// Set with TTL
await redis.setex(`user:${tenantId}:${userId}`, 3600, JSON.stringify(userData));

// Extend TTL on access
await redis.expire(`session:${tenantId}:${userId}:${sessionId}`, 86400);
```

### 2. Event-Driven Invalidation
```javascript
// Pub/Sub pattern for cache invalidation
class CacheInvalidator {
  constructor(redis) {
    this.redis = redis;
    this.subscriber = redis.duplicate();
    this.setupSubscriptions();
  }

  setupSubscriptions() {
    this.subscriber.subscribe('cache:invalidate');
    this.subscriber.on('message', (channel, message) => {
      const { pattern, tenantId } = JSON.parse(message);
      this.invalidateByPattern(pattern, tenantId);
    });
  }

  async invalidateUser(tenantId, userId) {
    const patterns = [
      `user:${tenantId}:${userId}`,
      `session:${tenantId}:${userId}:*`,
      `api:*:${tenantId}:users:*`
    ];

    await Promise.all(patterns.map(pattern =>
      this.redis.eval(`
        local keys = redis.call('KEYS', ARGV[1])
        for i=1,#keys do
          redis.call('DEL', keys[i])
        end
        return #keys
      `, 0, pattern)
    ));
  }
}
```

### 3. Cache Tags and Dependencies
```javascript
// Tag-based cache invalidation
class TaggedCache {
  async set(key, value, ttl, tags = []) {
    const multi = this.redis.multi();

    // Set the main key
    multi.setex(key, ttl, JSON.stringify(value));

    // Add to tag sets
    tags.forEach(tag => {
      multi.sadd(`tag:${tag}`, key);
      multi.expire(`tag:${tag}`, ttl + 300); // Tag TTL slightly longer
    });

    await multi.exec();
  }

  async invalidateTag(tag) {
    const keys = await this.redis.smembers(`tag:${tag}`);
    if (keys.length > 0) {
      await this.redis.del(...keys);
      await this.redis.del(`tag:${tag}`);
    }
  }
}
```

## Performance Optimization

### 1. Connection Pooling
```javascript
// Optimized connection pool
const connectionPool = {
  min: 5,
  max: 20,
  acquireTimeoutMillis: 30000,
  createTimeoutMillis: 30000,
  destroyTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  reapIntervalMillis: 1000,
  createRetryIntervalMillis: 100
};
```

### 2. Batch Operations
```javascript
// Batch cache operations for efficiency
class BatchCache {
  constructor(redis) {
    this.redis = redis;
    this.batchSize = 100;
  }

  async mgetUsers(tenantId, userIds) {
    const keys = userIds.map(id => `user:${tenantId}:${id}`);
    const values = await this.redis.mget(...keys);

    return keys.reduce((result, key, index) => {
      if (values[index]) {
        result[key] = JSON.parse(values[index]);
      }
      return result;
    }, {});
  }

  async msetUsers(tenantId, userData, ttl = 3600) {
    const multi = this.redis.multi();

    Object.entries(userData).forEach(([userId, data]) => {
      const key = `user:${tenantId}:${userId}`;
      multi.setex(key, ttl, JSON.stringify(data));
    });

    await multi.exec();
  }
}
```

### 3. Pipeline Operations
```javascript
// Use pipelines for multiple operations
async function warmupUserCache(tenantId, userId, userData) {
  const pipeline = redis.pipeline();

  // Cache user data
  pipeline.setex(`user:${tenantId}:${userId}`, 3600, JSON.stringify(userData.profile));

  // Cache permissions
  pipeline.setex(`permissions:${tenantId}:${userId}`, 1800, JSON.stringify(userData.permissions));

  // Cache recent activity
  pipeline.setex(`activity:${tenantId}:${userId}`, 900, JSON.stringify(userData.recentActivity));

  // Add to online users set
  pipeline.sadd(`online:${tenantId}`, userId);
  pipeline.expire(`online:${tenantId}`, 86400);

  await pipeline.exec();
}
```

## Monitoring and Metrics

### 1. Cache Performance Metrics
```javascript
// Cache metrics collection
class CacheMetrics {
  constructor(redis, metricsCollector) {
    this.redis = redis;
    this.metrics = metricsCollector;
  }

  async recordCacheOperation(operation, key, hit = null) {
    const labels = {
      operation,
      tenant: this.extractTenantFromKey(key),
      cache_type: this.extractCacheType(key)
    };

    this.metrics.increment('cache_operations_total', labels);

    if (hit !== null) {
      this.metrics.increment('cache_hits_total', { ...labels, hit: hit.toString() });
      this.metrics.observe('cache_hit_ratio', hit ? 1 : 0, labels);
    }
  }

  async getClusterHealth() {
    const info = await this.redis.cluster('info');
    const nodes = await this.redis.cluster('nodes');

    return {
      clusterState: info.includes('cluster_state:ok'),
      nodeCount: nodes.split('\n').filter(line => line.trim()).length,
      masterNodes: nodes.split('\n').filter(line => line.includes('master')).length
    };
  }
}
```

### 2. Cache Hit Ratios by Type
```javascript
// Track cache effectiveness
const cacheTypes = {
  'user': { target_hit_ratio: 0.85, ttl: 3600 },
  'session': { target_hit_ratio: 0.95, ttl: 86400 },
  'api': { target_hit_ratio: 0.70, ttl: 900 },
  'config': { target_hit_ratio: 0.90, ttl: 21600 }
};
```

## Error Handling and Fallbacks

### 1. Redis Failover Handling
```javascript
class ResilientCache {
  constructor(redis) {
    this.redis = redis;
    this.fallbackEnabled = true;
    this.circuitBreaker = new CircuitBreaker(this.redis, {
      timeout: 1000,
      errorThresholdPercentage: 50,
      resetTimeout: 30000
    });
  }

  async get(key) {
    try {
      return await this.circuitBreaker.fire(key);
    } catch (error) {
      console.warn(`Cache miss for key ${key}:`, error.message);
      if (this.fallbackEnabled) {
        return this.getFallback(key);
      }
      return null;
    }
  }

  async getFallback(key) {
    // Implement fallback to database or secondary cache
    // This is where you'd query the primary data source
    return null;
  }
}
```

### 2. Graceful Degradation
```javascript
// Application should work without cache
class CacheWrapper {
  constructor(redis, fallbackDataSource) {
    this.redis = redis;
    this.fallback = fallbackDataSource;
    this.cacheAvailable = true;
  }

  async getWithFallback(key, fallbackFn, ttl = 3600) {
    if (!this.cacheAvailable) {
      return await fallbackFn();
    }

    try {
      const cached = await this.redis.get(key);
      if (cached) {
        return JSON.parse(cached);
      }

      const data = await fallbackFn();
      if (data) {
        await this.redis.setex(key, ttl, JSON.stringify(data));
      }
      return data;
    } catch (error) {
      console.warn('Cache operation failed, using fallback:', error.message);
      this.cacheAvailable = false;
      setTimeout(() => { this.cacheAvailable = true; }, 60000); // Retry in 1 minute
      return await fallbackFn();
    }
  }
}
```

## Best Practices

### 1. Cache Key Naming Convention
- Use consistent patterns: `{type}:{tenant}:{resource}:{id}`
- Include version info when needed: `api:v1:{endpoint}:{params_hash}`
- Use readable separators and avoid special characters
- Keep keys under 250 characters

### 2. TTL Management
- Short TTL for frequently changing data (1-15 minutes)
- Medium TTL for semi-static data (1-6 hours)
- Long TTL for configuration data (6-24 hours)
- Consider business hours for cache warming

### 3. Memory Management
- Monitor memory usage and set appropriate maxmemory limits
- Use LRU eviction policy for general purpose caching
- Implement cache warming strategies for critical data
- Regular cleanup of expired keys and unused patterns

### 4. Security Considerations
- Encrypt sensitive data before caching
- Use Redis AUTH and ACLs for access control
- Enable TLS for Redis connections in production
- Audit cache access patterns and implement rate limiting