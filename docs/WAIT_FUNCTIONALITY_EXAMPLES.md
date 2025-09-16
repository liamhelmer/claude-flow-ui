# Wait Functionality Integration Examples

This document provides practical examples of how to use the enhanced wait functionality in the claude-flow-ui project.

## Table of Contents

1. [Basic Wait Operations](#basic-wait-operations)
2. [Tmux Session Management](#tmux-session-management)
3. [Service Health Monitoring](#service-health-monitoring)
4. [File System Operations](#file-system-operations)
5. [Network Operations](#network-operations)
6. [Complex Orchestration](#complex-orchestration)
7. [Error Recovery Patterns](#error-recovery-patterns)

## Basic Wait Operations

### Simple Delays and Timeouts

```javascript
const { wait, waitWithTimeout, waitUntil } = require('./src/utils/wait');

// Basic delay
await wait(1000); // Wait 1 second

// Wait with timeout for any promise
const result = await waitWithTimeout(
  fetchData(),
  5000,
  'Data fetch timed out'
);

// Wait for a condition
await waitUntil(
  () => server.isReady(),
  {
    timeout: 30000,
    interval: 1000,
    message: 'Server did not become ready'
  }
);
```

### Cancellation Support

```javascript
const { waitWithCancel, waitUntil } = require('./src/utils/wait');

// Create cancellation controller
const controller = new AbortController();

// Cancel after 5 seconds
setTimeout(() => controller.abort(), 5000);

try {
  await waitUntil(
    () => longRunningCondition(),
    {
      timeout: 60000,
      signal: controller.signal
    }
  );
} catch (error) {
  if (error.message === 'Wait cancelled') {
    console.log('Operation was cancelled');
  }
}
```

## Tmux Session Management

### Enhanced Session Creation with Waiting

```javascript
const { waitForTmuxSession, waitForSocket } = require('./src/utils/waitHelpers');
const TmuxManager = require('./src/lib/tmux-manager');

async function createTmuxSessionSafely(sessionName, command) {
  const tmuxManager = new TmuxManager();

  try {
    // Create session
    const sessionInfo = await tmuxManager.createSession(sessionName, command);

    // Wait for socket to be available
    await waitForSocket(sessionInfo.socketPath, { timeout: 5000 });

    // Wait for session to be responsive
    await waitForTmuxSession(sessionName, sessionInfo.socketPath, {
      timeout: 10000,
      interval: 500
    });

    console.log(`✅ Tmux session ${sessionName} is ready`);
    return sessionInfo;

  } catch (error) {
    console.error(`❌ Failed to create tmux session: ${error.message}`);
    throw error;
  }
}
```

### Waiting for Command Completion

```javascript
const { waitForPaneDeath } = require('./src/utils/waitHelpers');

async function runCommandAndWait(sessionName, socketPath, command) {
  const tmuxManager = new TmuxManager();

  // Send command
  await tmuxManager.sendCommand(sessionName, command);

  // Wait for command to complete
  const result = await waitForPaneDeath(sessionName, socketPath, {
    timeout: 300000, // 5 minutes
    interval: 2000
  });

  console.log(`Command completed with exit code: ${result.exitCode}`);
  return result;
}
```

## Service Health Monitoring

### Wait for Multiple Services

```javascript
const { waitForService, waitForPort } = require('./src/utils/wait');

async function waitForApplicationStack() {
  const services = [
    {
      name: 'database',
      check: () => waitForPort(5432, 'localhost'),
      timeout: 30000
    },
    {
      name: 'redis',
      check: () => waitForPort(6379, 'localhost'),
      timeout: 15000
    },
    {
      name: 'api',
      check: async () => {
        const response = await fetch('http://localhost:3000/health');
        return response.ok;
      },
      timeout: 60000
    }
  ];

  console.log('🔄 Waiting for application stack...');

  for (const service of services) {
    console.log(`⏳ Waiting for ${service.name}...`);

    await waitForService(service.check, {
      timeout: service.timeout,
      interval: 2000,
      serviceName: service.name
    });

    console.log(`✅ ${service.name} is ready`);
  }

  console.log('🚀 All services are ready!');
}
```

### Health Check with Circuit Breaker

```javascript
const WaitManager = require('./src/lib/enhanced-wait-manager');

async function monitorServiceHealth() {
  const waitManager = new WaitManager();

  // Create circuit breaker for the service
  waitManager.createCircuitBreaker('api-service', {
    failureThreshold: 3,
    resetTimeout: 60000
  });

  // Monitor health with automatic circuit breaking
  await waitManager.waitForHealthCheck(
    'api-service',
    async () => {
      const response = await fetch('http://localhost:3000/health');
      return response.ok;
    },
    {
      timeout: 30000,
      interval: 5000
    }
  );
}
```

## File System Operations

### Wait for File Operations

```javascript
const { waitForFile } = require('./src/utils/wait');
const { retry } = require('./src/utils/wait');

async function processFileWhenReady(filePath) {
  // Wait for file to exist
  await waitForFile(filePath, {
    operation: 'exists',
    timeout: 30000,
    interval: 1000
  });

  // Wait for file to be readable
  await waitForFile(filePath, {
    operation: 'readable',
    timeout: 5000,
    interval: 500
  });

  // Process file with retry on failure
  const content = await retry(
    async () => {
      const fs = require('fs').promises;
      return await fs.readFile(filePath, 'utf8');
    },
    {
      maxRetries: 3,
      baseDelay: 1000,
      shouldRetry: (error) => error.code === 'EBUSY' || error.code === 'EAGAIN'
    }
  );

  return content;
}
```

## Network Operations

### Robust Network Requests

```javascript
const { retry, retryConfig } = require('./src/utils/wait');

async function fetchWithRetry(url) {
  return await retry(
    async () => {
      const response = await fetch(url);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    },
    {
      ...retryConfig.network,
      onRetry: (error, attempt) => {
        console.log(`🔄 Retry attempt ${attempt + 1} for ${url}: ${error.message}`);
      }
    }
  );
}
```

### Multiple Endpoint Coordination

```javascript
const { waitForAll, waitForAny } = require('./src/utils/wait');

async function coordinateMultipleAPIs() {
  const apiCalls = [
    fetch('https://api1.example.com/data'),
    fetch('https://api2.example.com/data'),
    fetch('https://api3.example.com/data')
  ];

  // Wait for all APIs (fail on any timeout)
  try {
    const results = await waitForAll(apiCalls, 5000, true);
    console.log('All APIs responded:', results);
  } catch (error) {
    console.error('One or more APIs failed:', error.message);
  }

  // Or wait for any API to respond
  try {
    const firstResult = await waitForAny(apiCalls, 3000);
    console.log('First API response:', firstResult);
  } catch (error) {
    console.error('No API responded in time:', error.message);
  }
}
```

## Complex Orchestration

### Multi-Stage Deployment

```javascript
const WaitManager = require('./src/lib/enhanced-wait-manager');

async function deployApplication() {
  const waitManager = new WaitManager();

  // Define deployment stages
  const deploymentStages = [
    {
      name: 'database_migration',
      operation: async () => {
        console.log('🔄 Running database migrations...');
        await runDatabaseMigrations();
      },
      options: { timeout: 120000 }
    },
    {
      name: 'backend_deployment',
      operation: async () => {
        console.log('🔄 Deploying backend services...');
        await deployBackendServices();
      },
      options: {
        timeout: 180000,
        dependencies: ['database_migration']
      }
    },
    {
      name: 'frontend_deployment',
      operation: async () => {
        console.log('🔄 Deploying frontend...');
        await deployFrontend();
      },
      options: {
        timeout: 120000,
        dependencies: ['backend_deployment']
      }
    }
  ];

  // Execute deployment with proper orchestration
  await waitManager.waitForGroup('deployment', deploymentStages, {
    sequential: true,
    stopOnFirstFailure: true,
    timeout: 600000
  });

  console.log('🚀 Deployment completed successfully!');

  // Get deployment metrics
  const metrics = waitManager.getMetrics();
  console.log('📊 Deployment metrics:', metrics);
}
```

### Parallel Processing with Circuit Breakers

```javascript
const WaitManager = require('./src/lib/enhanced-wait-manager');

async function processItemsInParallel(items) {
  const waitManager = new WaitManager();

  // Create circuit breaker for processing operations
  waitManager.createCircuitBreaker('item-processor', {
    failureThreshold: 5,
    resetTimeout: 30000
  });

  // Process items with automatic circuit breaking
  const operations = items.map((item, index) => ({
    name: `process_item_${index}`,
    operation: async () => {
      if (waitManager.isCircuitOpen('item-processor')) {
        throw new Error('Circuit breaker is open - too many failures');
      }

      return await processItem(item);
    },
    options: {
      timeout: 30000,
      retries: 2
    }
  }));

  const results = await waitManager.waitForAll(operations, {
    failFast: false,
    timeout: 300000
  });

  return results;
}
```

## Error Recovery Patterns

### Graceful Degradation

```javascript
const { retry, waitForService } = require('./src/utils/wait');

async function getDataWithFallback() {
  // Try primary data source
  try {
    return await retry(
      () => fetchFromPrimaryDB(),
      { maxRetries: 2, baseDelay: 1000 }
    );
  } catch (primaryError) {
    console.warn('Primary DB failed, trying cache:', primaryError.message);

    // Fall back to cache
    try {
      return await retry(
        () => fetchFromCache(),
        { maxRetries: 1, baseDelay: 500 }
      );
    } catch (cacheError) {
      console.warn('Cache failed, trying backup DB:', cacheError.message);

      // Last resort: backup database
      return await retry(
        () => fetchFromBackupDB(),
        { maxRetries: 3, baseDelay: 2000 }
      );
    }
  }
}
```

### Self-Healing Services

```javascript
const { waitUntil, retry } = require('./src/utils/wait');

class SelfHealingService {
  constructor() {
    this.isHealthy = false;
    this.healingInProgress = false;
  }

  async ensureHealthy() {
    if (this.isHealthy) return;

    if (this.healingInProgress) {
      // Wait for ongoing healing to complete
      await waitUntil(() => this.isHealthy, {
        timeout: 60000,
        interval: 1000,
        message: 'Service healing timed out'
      });
      return;
    }

    this.healingInProgress = true;

    try {
      await retry(
        async () => {
          await this.performHealthCheck();
          if (!this.isHealthy) {
            await this.heal();
          }
        },
        {
          maxRetries: 3,
          baseDelay: 5000,
          onRetry: (error, attempt) => {
            console.log(`🔧 Healing attempt ${attempt + 1}: ${error.message}`);
          }
        }
      );
    } finally {
      this.healingInProgress = false;
    }
  }

  async performHealthCheck() {
    // Implementation specific health check
    const response = await fetch('http://localhost:3000/health');
    this.isHealthy = response.ok;
  }

  async heal() {
    console.log('🔧 Attempting to heal service...');
    // Implementation specific healing logic
    await this.restart();
    await wait(5000); // Wait for restart
    await this.performHealthCheck();
  }
}
```

## Integration with Existing Code

### Enhancing Tmux Managers

```javascript
// In your tmux manager, replace basic timeouts with enhanced wait utilities
const { waitWithTimeout, retry } = require('./src/utils/wait');
const { waitForTmuxSession, retryTmuxOperation } = require('./src/utils/waitHelpers');

class EnhancedTmuxManager extends TmuxManager {
  async createSessionSafely(sessionName, command, args, cols, rows) {
    return await retryTmuxOperation(
      async () => {
        const sessionInfo = await super.createSession(sessionName, command, args, cols, rows);

        // Wait for session to be fully ready
        await waitForTmuxSession(sessionName, sessionInfo.socketPath);

        return sessionInfo;
      },
      {
        maxRetries: 3,
        baseDelay: 2000,
        onRetry: (error, attempt) => {
          console.log(`🔄 Retrying tmux session creation (attempt ${attempt + 1}): ${error.message}`);
        }
      }
    );
  }

  async captureWithTimeout(sessionName, socketPath, timeout = 5000) {
    return await waitWithTimeout(
      super.captureFullScreen(sessionName, socketPath),
      timeout,
      `Tmux capture timed out for session ${sessionName}`
    );
  }
}
```

This enhanced wait functionality provides robust, production-ready async operations with proper error handling, timeouts, retries, and monitoring capabilities for the claude-flow-ui project.