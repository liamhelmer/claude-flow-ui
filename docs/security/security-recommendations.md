# Security Recommendations - Implementation Guide

## 🛡️ Critical Security Fixes

### 1. Command Injection Prevention (CRITICAL)

**Current Issue**: `tmux-manager.js` lines 96-106
```javascript
// ❌ VULNERABLE: Shell injection possible
const escapedArgs = args.map(arg => `'${arg.replace(/'/g, "'\\''")}' `).join('');
fullCommand = `${command} ${escapedArgs}2> >(tee '${outputFile}' >&2)`;
```

**Secure Implementation**:
```javascript
// ✅ SECURE: Use spawn with array arguments
const createSecureSession = async (sessionName, command, args) => {
  const outputFile = path.join(this.socketDir, `${sessionName}.output`);

  // Validate command against whitelist
  const allowedCommands = [
    'bash', 'sh', 'zsh', 'fish',
    'node', 'npm', 'yarn', 'git',
    'python', 'python3', 'pip'
  ];

  if (!allowedCommands.includes(path.basename(command))) {
    throw new Error(`Command not allowed: ${command}`);
  }

  // Use spawn with array to prevent injection
  const tmux = spawn('tmux', [
    '-S', socketPath,
    'new-session',
    '-d',
    '-s', sessionName,
    '-c', this.workingDir,
    command,
    ...args // Safely pass arguments as array
  ], {
    stdio: ['pipe', 'pipe', fs.createWriteStream(outputFile)],
    env: { ...process.env, TERM: 'xterm-256color' }
  });

  return tmux;
};
```

### 2. Timer Management System

**Create**: `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/src/lib/timer-manager.ts`
```typescript
export class TimerManager {
  private timers = new Set<NodeJS.Timeout>();
  private intervals = new Set<NodeJS.Timeout>();

  setTimeout(callback: () => void, delay: number): NodeJS.Timeout {
    const id = setTimeout(() => {
      this.timers.delete(id);
      callback();
    }, delay);

    this.timers.add(id);
    return id;
  }

  setInterval(callback: () => void, delay: number): NodeJS.Timeout {
    const id = setInterval(callback, delay);
    this.intervals.add(id);
    return id;
  }

  clearTimeout(id: NodeJS.Timeout): void {
    clearTimeout(id);
    this.timers.delete(id);
  }

  clearInterval(id: NodeJS.Timeout): void {
    clearInterval(id);
    this.intervals.delete(id);
  }

  cleanup(): void {
    this.timers.forEach(id => clearTimeout(id));
    this.intervals.forEach(id => clearInterval(id));
    this.timers.clear();
    this.intervals.clear();
  }

  getActiveCount(): { timers: number; intervals: number } {
    return {
      timers: this.timers.size,
      intervals: this.intervals.size
    };
  }
}

export const globalTimerManager = new TimerManager();

// Cleanup on process exit
process.on('exit', () => globalTimerManager.cleanup());
process.on('SIGINT', () => {
  globalTimerManager.cleanup();
  process.exit(0);
});
```

### 3. Environment Variable Security

**Create**: `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/src/lib/secure-env.ts`
```typescript
const SENSITIVE_PATTERNS = [
  /password/i,
  /secret/i,
  /key/i,
  /token/i,
  /auth/i,
  /credential/i
];

export const sanitizeEnvForLogging = (env: NodeJS.ProcessEnv): Record<string, string> => {
  return Object.fromEntries(
    Object.entries(env).filter(([key, value]) => {
      // Skip sensitive keys
      if (SENSITIVE_PATTERNS.some(pattern => pattern.test(key))) {
        return false;
      }

      // Skip if value looks like a secret (long alphanumeric string)
      if (value && /^[a-zA-Z0-9+/=]{32,}$/.test(value)) {
        return false;
      }

      return true;
    }).map(([key, value]) => [key, value || ''])
  );
};

export const validateRequiredEnvVars = (required: string[]): void => {
  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
};
```

## 🔒 Input Validation Framework

### WebSocket Message Validation

**Create**: `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/src/lib/websocket-validator.ts`
```typescript
import { z } from 'zod';

const BaseMessageSchema = z.object({
  type: z.string().min(1).max(50),
  timestamp: z.number().optional(),
  sessionId: z.string().uuid().optional()
});

const DataMessageSchema = BaseMessageSchema.extend({
  type: z.literal('data'),
  sessionId: z.string().uuid(),
  data: z.string().max(4096) // Limit message size
});

const ResizeMessageSchema = BaseMessageSchema.extend({
  type: z.literal('resize'),
  sessionId: z.string().uuid(),
  cols: z.number().int().min(10).max(300),
  rows: z.number().int().min(5).max(100)
});

const CommandMessageSchema = BaseMessageSchema.extend({
  type: z.literal('command'),
  command: z.enum(['create', 'destroy', 'list']),
  sessionId: z.string().uuid().optional()
});

export const MessageSchemas = {
  data: DataMessageSchema,
  resize: ResizeMessageSchema,
  command: CommandMessageSchema
};

export const validateWebSocketMessage = (message: unknown): { valid: boolean; error?: string; data?: any } => {
  try {
    // First validate base structure
    const baseResult = BaseMessageSchema.safeParse(message);
    if (!baseResult.success) {
      return { valid: false, error: 'Invalid message structure' };
    }

    const { type } = baseResult.data;
    const schema = MessageSchemas[type as keyof typeof MessageSchemas];

    if (!schema) {
      return { valid: false, error: `Unknown message type: ${type}` };
    }

    const result = schema.safeParse(message);
    if (!result.success) {
      return {
        valid: false,
        error: `Validation failed: ${result.error.errors.map(e => e.message).join(', ')}`
      };
    }

    return { valid: true, data: result.data };
  } catch (error) {
    return { valid: false, error: 'Validation error' };
  }
};
```

## 🛡️ File System Security

### Secure File Operations

**Create**: `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/src/lib/secure-fs.ts`
```typescript
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

export class SecureFileSystem {
  private allowedPaths: Set<string>;
  private maxFileSize: number;

  constructor(allowedPaths: string[], maxFileSize = 10 * 1024 * 1024) { // 10MB default
    this.allowedPaths = new Set(allowedPaths.map(p => path.resolve(p)));
    this.maxFileSize = maxFileSize;
  }

  private validatePath(filePath: string): void {
    const resolvedPath = path.resolve(filePath);

    // Check if path is within allowed directories
    const isAllowed = Array.from(this.allowedPaths).some(allowedPath =>
      resolvedPath.startsWith(allowedPath)
    );

    if (!isAllowed) {
      throw new Error(`Access denied: Path not in allowed directories: ${filePath}`);
    }

    // Check for directory traversal
    if (filePath.includes('..') || filePath.includes('~')) {
      throw new Error(`Invalid path: Directory traversal detected: ${filePath}`);
    }
  }

  async writeFile(filePath: string, content: string, options: { mode?: number } = {}): Promise<void> {
    this.validatePath(filePath);

    if (content.length > this.maxFileSize) {
      throw new Error(`File too large: ${content.length} bytes (max: ${this.maxFileSize})`);
    }

    // Set secure permissions by default
    const mode = options.mode || 0o600;

    await fs.writeFile(filePath, content, { mode });
  }

  async readFile(filePath: string): Promise<string> {
    this.validatePath(filePath);

    const stats = await fs.stat(filePath);
    if (stats.size > this.maxFileSize) {
      throw new Error(`File too large: ${stats.size} bytes (max: ${this.maxFileSize})`);
    }

    return fs.readFile(filePath, 'utf-8');
  }

  async createSecureTemp(prefix: string, content: string): Promise<string> {
    const tempDir = path.join(process.cwd(), 'temp');

    // Ensure temp directory exists and has secure permissions
    await fs.mkdir(tempDir, { recursive: true, mode: 0o700 });

    const filename = `${prefix}-${crypto.randomBytes(8).toString('hex')}.tmp`;
    const filePath = path.join(tempDir, filename);

    await this.writeFile(filePath, content, { mode: 0o600 });
    return filePath;
  }
}
```

## 🔐 Memory Leak Detection

### Production Memory Monitoring

**Create**: `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/src/lib/memory-monitor.ts`
```typescript
export interface MemoryMetrics {
  heapUsed: number;
  heapTotal: number;
  external: number;
  rss: number;
  timestamp: number;
}

export class MemoryMonitor {
  private metrics: MemoryMetrics[] = [];
  private readonly maxMetrics = 100;
  private interval?: NodeJS.Timeout;
  private thresholds = {
    heapUsedMB: 200,
    heapGrowthMB: 50,
    rssMB: 300
  };

  start(intervalMs = 10000): void {
    this.interval = setInterval(() => {
      this.collectMetrics();
      this.checkThresholds();
    }, intervalMs);
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = undefined;
    }
  }

  private collectMetrics(): void {
    const usage = process.memoryUsage();
    const metric: MemoryMetrics = {
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      external: usage.external,
      rss: usage.rss,
      timestamp: Date.now()
    };

    this.metrics.push(metric);

    // Keep only recent metrics
    if (this.metrics.length > this.maxMetrics) {
      this.metrics.splice(0, this.metrics.length - this.maxMetrics);
    }
  }

  private checkThresholds(): void {
    if (this.metrics.length < 2) return;

    const latest = this.metrics[this.metrics.length - 1];
    const previous = this.metrics[this.metrics.length - 2];

    const heapUsedMB = latest.heapUsed / 1024 / 1024;
    const heapGrowthMB = (latest.heapUsed - previous.heapUsed) / 1024 / 1024;
    const rssMB = latest.rss / 1024 / 1024;

    if (heapUsedMB > this.thresholds.heapUsedMB) {
      console.warn(`⚠️ High heap usage: ${heapUsedMB.toFixed(1)}MB`);
    }

    if (heapGrowthMB > this.thresholds.heapGrowthMB) {
      console.warn(`⚠️ Rapid heap growth: +${heapGrowthMB.toFixed(1)}MB`);
    }

    if (rssMB > this.thresholds.rssMB) {
      console.warn(`⚠️ High RSS usage: ${rssMB.toFixed(1)}MB`);
    }
  }

  getMetrics(): MemoryMetrics[] {
    return [...this.metrics];
  }

  getCurrentMetrics(): MemoryMetrics {
    const usage = process.memoryUsage();
    return {
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      external: usage.external,
      rss: usage.rss,
      timestamp: Date.now()
    };
  }

  detectLeaks(): { suspicious: boolean; details: string[] } {
    if (this.metrics.length < 10) {
      return { suspicious: false, details: ['Not enough data'] };
    }

    const details: string[] = [];
    let suspicious = false;

    // Check for consistent growth trend
    const recentMetrics = this.metrics.slice(-10);
    const growthTrend = recentMetrics.reduce((acc, metric, index) => {
      if (index === 0) return acc;
      return acc + (metric.heapUsed - recentMetrics[index - 1].heapUsed);
    }, 0);

    if (growthTrend > 50 * 1024 * 1024) { // 50MB total growth
      suspicious = true;
      details.push(`Consistent heap growth: +${(growthTrend / 1024 / 1024).toFixed(1)}MB`);
    }

    // Check for external memory growth
    const firstExternal = recentMetrics[0].external;
    const lastExternal = recentMetrics[recentMetrics.length - 1].external;
    const externalGrowth = lastExternal - firstExternal;

    if (externalGrowth > 20 * 1024 * 1024) { // 20MB external growth
      suspicious = true;
      details.push(`External memory growth: +${(externalGrowth / 1024 / 1024).toFixed(1)}MB`);
    }

    return { suspicious, details };
  }
}

// Global instance for production monitoring
export const globalMemoryMonitor = new MemoryMonitor();

// Auto-start in production
if (process.env.NODE_ENV === 'production') {
  globalMemoryMonitor.start();

  process.on('exit', () => {
    const leakCheck = globalMemoryMonitor.detectLeaks();
    if (leakCheck.suspicious) {
      console.warn('🚨 Potential memory leaks detected:', leakCheck.details.join(', '));
    }
    globalMemoryMonitor.stop();
  });
}
```

## 🔧 Integration Instructions

### 1. Update tmux-manager.js
Replace command execution with secure implementation above.

### 2. Update WebSocket handlers
Add validation using the WebSocket validator.

### 3. Replace setTimeout/setInterval usage
Use TimerManager throughout the codebase.

### 4. Add to unified-server.js
```javascript
const { globalMemoryMonitor } = require('./src/lib/memory-monitor');
const { globalTimerManager } = require('./src/lib/timer-manager');

// Start monitoring in production
if (process.env.NODE_ENV === 'production') {
  globalMemoryMonitor.start();

  // Graceful shutdown
  process.on('SIGTERM', () => {
    globalTimerManager.cleanup();
    globalMemoryMonitor.stop();
    process.exit(0);
  });
}
```

### 5. Environment Configuration
Update logging to use `sanitizeEnvForLogging` before outputting environment variables.

## 📊 Monitoring & Alerts

Set up production monitoring for:
- Memory usage trends
- Active timer counts
- WebSocket validation failures
- Command execution attempts
- File system access patterns

These implementations will significantly improve the security posture and reliability of the Claude Flow UI application.