# Claude Flow UI - Performance Guide

## Table of Contents

1. [Overview](#overview)
2. [Performance Metrics](#performance-metrics)
3. [Server Optimization](#server-optimization)
4. [Client-Side Optimization](#client-side-optimization)
5. [WebSocket Performance](#websocket-performance)
6. [Terminal Performance](#terminal-performance)
7. [Memory Management](#memory-management)
8. [Network Optimization](#network-optimization)
9. [Monitoring and Profiling](#monitoring-and-profiling)
10. [Benchmarks](#benchmarks)
11. [Troubleshooting](#troubleshooting)

## Overview

Claude Flow UI is designed for high performance in web-based terminal environments. This guide covers optimization techniques, monitoring strategies, and performance benchmarks to help you achieve optimal performance.

### Performance Goals

- **Low Latency**: < 50ms response time for terminal input
- **High Throughput**: Support 100+ concurrent sessions
- **Memory Efficiency**: < 100MB per terminal session
- **CPU Optimization**: < 5% CPU usage per session at idle
- **Network Efficiency**: Minimal bandwidth usage through compression

## Performance Metrics

### Key Performance Indicators

#### Response Times
- **Terminal Input Latency**: Time from key press to screen update
- **Session Creation**: Time to create new terminal session
- **WebSocket Handshake**: Connection establishment time
- **API Response**: HTTP API endpoint response times

#### Throughput Metrics
- **Concurrent Sessions**: Number of active terminal sessions
- **Messages Per Second**: WebSocket message processing rate
- **Data Transfer Rate**: Bytes per second through WebSocket
- **Request Rate**: HTTP requests per second

#### Resource Utilization
- **Memory Usage**: RAM consumption per session and total
- **CPU Usage**: Processor utilization per session
- **Network Bandwidth**: Upload/download speeds
- **Disk I/O**: File system read/write operations

### Monitoring Commands

```bash
# Real-time performance metrics
curl http://localhost:3000/api/metrics

# System resource usage
top -p $(pgrep -f claude-flow-ui)

# Memory usage breakdown
node --expose-gc --max-old-space-size=4096 unified-server.js

# Network statistics
netstat -i 1
```

## Server Optimization

### Node.js Performance

#### Memory Configuration

```bash
# Optimize memory for high-load scenarios
node --max-old-space-size=4096 \
     --max-semi-space-size=64 \
     --optimize-for-size \
     unified-server.js
```

#### V8 Engine Optimization

```bash
# Enable V8 optimizations
node --optimize-for-size \
     --gc-interval=100 \
     --harmony \
     --use-largepages \
     unified-server.js
```

#### Event Loop Optimization

```bash
# Monitor event loop lag
const { performance, PerformanceObserver } = require('perf_hooks');

const obs = new PerformanceObserver((list) => {
  list.getEntries().forEach((entry) => {
    console.log(`${entry.name}: ${entry.duration}ms`);
  });
});
obs.observe({ entryTypes: ['measure'] });
```

### Environment Variables for Performance

```bash
# High-performance server configuration
NODE_ENV=production
CLUSTER_MODE=true
WORKERS=0                      # Auto-detect CPU cores
MAX_SESSIONS=50               # Maximum concurrent sessions
SESSION_TIMEOUT=300000        # 5-minute session timeout

# Memory optimization
MAX_MEMORY_USAGE=2048         # Maximum memory in MB
GC_INTERVAL=60000            # Garbage collection interval
BUFFER_POOL_SIZE=1000        # Buffer pool size

# Performance monitoring
ENABLE_METRICS=true
METRICS_INTERVAL=10000       # Metrics collection interval
```

### Clustering Configuration

```javascript
// cluster.js - Enable multi-process scaling
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
  console.log(`Master ${process.pid} is running`);

  // Fork workers
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    cluster.fork(); // Replace dead worker
  });
} else {
  // Start Claude Flow UI server
  require('./unified-server.js');
  console.log(`Worker ${process.pid} started`);
}
```

### Load Balancing

```nginx
# nginx.conf - Load balancer configuration
upstream claude_flow_ui {
    least_conn;
    server 127.0.0.1:3000 weight=1 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3001 weight=1 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3002 weight=1 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3003 weight=1 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name claude-flow-ui.local;

    location / {
        proxy_pass http://claude_flow_ui;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
    }
}
```

## Client-Side Optimization

### Browser Performance

#### Memory Management

```javascript
// Optimize client-side memory usage
const terminalConfig = {
  scrollback: 1000,        // Limit scrollback buffer
  convertEol: false,       // Disable line ending conversion
  allowTransparency: false, // Disable transparency
  disableStdin: false,     // Keep input enabled
  screenReaderMode: false, // Disable unless needed
  fastScrollModifier: 'alt'
};
```

#### Rendering Optimization

```javascript
// Terminal rendering performance
const terminal = new Terminal({
  ...terminalConfig,
  rendererType: 'canvas',    // Use Canvas renderer for performance
  allowTransparency: false,   // Disable transparency
  cursorBlink: false,        // Disable cursor blink if not needed
  theme: {
    background: '#1a1a1a',   // Solid background color
    foreground: '#ffffff'    // High contrast text
  }
});

// Optimize addon loading
import { FitAddon } from '@xterm/addon-fit';
import { SearchAddon } from '@xterm/addon-search';
// Only load necessary addons

const fitAddon = new FitAddon();
terminal.loadAddon(fitAddon);
```

#### Network Request Optimization

```javascript
// Batch WebSocket messages for better performance
class MessageBatcher {
  constructor(websocket, batchSize = 10, flushInterval = 16) {
    this.ws = websocket;
    this.batch = [];
    this.batchSize = batchSize;
    this.flushInterval = flushInterval;
    this.flushTimer = null;
  }

  send(message) {
    this.batch.push(message);

    if (this.batch.length >= this.batchSize) {
      this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.flushInterval);
    }
  }

  flush() {
    if (this.batch.length > 0) {
      this.ws.send(JSON.stringify({
        type: 'batch',
        messages: this.batch
      }));
      this.batch = [];
    }

    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }
}
```

### React Performance Optimization

```javascript
// Terminal component optimization
import React, { memo, useCallback, useMemo } from 'react';

const Terminal = memo(({ sessionId, className }) => {
  // Memoize WebSocket connection
  const ws = useMemo(() => {
    return new WebSocket(`ws://localhost:3000/ws`);
  }, []);

  // Optimize event handlers
  const handleResize = useCallback((cols, rows) => {
    ws.send(JSON.stringify({
      type: 'resize',
      sessionId,
      cols,
      rows
    }));
  }, [ws, sessionId]);

  const handleData = useCallback((data) => {
    ws.send(JSON.stringify({
      type: 'data',
      sessionId,
      data
    }));
  }, [ws, sessionId]);

  return (
    <div className={className}>
      {/* Terminal implementation */}
    </div>
  );
});

// Session list optimization
const SessionList = memo(({ sessions, onSelect }) => {
  const sortedSessions = useMemo(() => {
    return sessions.sort((a, b) =>
      new Date(b.lastActivity) - new Date(a.lastActivity)
    );
  }, [sessions]);

  return (
    <ul>
      {sortedSessions.map(session => (
        <SessionItem
          key={session.id}
          session={session}
          onSelect={onSelect}
        />
      ))}
    </ul>
  );
});
```

## WebSocket Performance

### Connection Optimization

```javascript
// High-performance WebSocket server configuration
const io = new Server(httpServer, {
  // Connection settings
  pingTimeout: 60000,        // 60 seconds
  pingInterval: 25000,       // 25 seconds
  upgradeTimeout: 10000,     // 10 seconds
  maxHttpBufferSize: 1e6,    // 1MB

  // Performance settings
  compression: true,         // Enable compression
  allowEIO3: false,         // Disable legacy protocol
  transports: ['websocket'], // WebSocket only

  // CORS settings
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
    credentials: false
  }
});
```

### Message Processing Optimization

```javascript
// Efficient message handling
class OptimizedWebSocketHandler {
  constructor() {
    this.messageQueue = [];
    this.processing = false;
    this.batchSize = 50;
  }

  async handleMessage(socket, message) {
    this.messageQueue.push({ socket, message });

    if (!this.processing) {
      this.processing = true;
      await this.processQueue();
      this.processing = false;
    }
  }

  async processQueue() {
    while (this.messageQueue.length > 0) {
      const batch = this.messageQueue.splice(0, this.batchSize);

      // Process batch in parallel
      await Promise.all(
        batch.map(({ socket, message }) =>
          this.processMessage(socket, message)
        )
      );
    }
  }

  async processMessage(socket, message) {
    try {
      const parsed = JSON.parse(message);

      switch (parsed.type) {
        case 'data':
          return this.handleTerminalData(socket, parsed);
        case 'resize':
          return this.handleResize(socket, parsed);
        default:
          console.warn('Unknown message type:', parsed.type);
      }
    } catch (error) {
      console.error('Message processing error:', error);
    }
  }
}
```

### Compression Configuration

```javascript
// WebSocket compression settings
const compressionOptions = {
  threshold: 1024,           // Compress messages > 1KB
  level: 6,                  // Compression level (1-9)
  windowBits: 15,           // Compression window size
  memLevel: 8,              // Memory usage level
  strategy: require('zlib').constants.Z_DEFAULT_STRATEGY
};

io.engine.compression(compressionOptions);
```

## Terminal Performance

### Buffer Management

```javascript
// Efficient terminal buffer management
class TerminalBufferManager {
  constructor(maxLines = 1000) {
    this.buffer = [];
    this.maxLines = maxLines;
    this.cleanupThreshold = Math.floor(maxLines * 0.8);
  }

  addLine(line) {
    this.buffer.push({
      content: line,
      timestamp: Date.now()
    });

    // Periodic cleanup
    if (this.buffer.length > this.cleanupThreshold) {
      this.cleanup();
    }
  }

  cleanup() {
    // Keep only the most recent lines
    if (this.buffer.length > this.maxLines) {
      this.buffer = this.buffer.slice(-this.maxLines);
    }
  }

  getLines(start = 0, end = this.buffer.length) {
    return this.buffer.slice(start, end).map(item => item.content);
  }
}
```

### Terminal Rendering Optimization

```javascript
// Optimized terminal configuration
const performantTerminalConfig = {
  // Core settings
  cols: 80,
  rows: 24,
  scrollback: 1000,

  // Performance settings
  convertEol: false,         // Skip line ending conversion
  allowTransparency: false,  // Solid background
  disableStdin: false,       // Keep interactive
  screenReaderMode: false,   // Disable unless needed

  // Rendering optimization
  rendererType: 'canvas',    // Use Canvas for performance
  cursorBlink: false,        // Disable if not needed
  cursorStyle: 'block',      // Simple cursor style

  // Font settings
  fontFamily: 'Monaco, Consolas, monospace',
  fontSize: 14,
  lineHeight: 1.0,

  // Theme optimization
  theme: {
    background: '#1a1a1a',
    foreground: '#ffffff',
    cursor: '#ffffff',
    selection: '#ffffff40'
  }
};
```

### Tmux Performance

```bash
# Tmux performance optimization
# ~/.tmux.conf

# Display settings
set -g default-terminal "screen-256color"
set -g terminal-overrides ',xterm-256color:Tc'

# Performance settings
set -g escape-time 0          # Remove escape key delay
set -g repeat-time 600        # Key repeat timeout
set -g display-time 4000      # Message display time

# Buffer settings
set -g history-limit 10000    # Scrollback buffer size
set -g buffer-limit 20        # Number of buffers

# Mouse settings (disable for performance)
set -g mouse off

# Status bar optimization
set -g status-interval 60     # Update every 60 seconds
set -g status-left-length 50
set -g status-right-length 50

# Window and pane settings
setw -g aggressive-resize on  # Aggressive resize
setw -g monitor-activity off  # Disable activity monitoring
```

## Memory Management

### Server-Side Memory Optimization

```javascript
// Memory-efficient session management
class MemoryOptimizedSessionManager {
  constructor() {
    this.sessions = new Map();
    this.cleanupInterval = 60000;  // 1 minute
    this.maxInactiveTime = 300000; // 5 minutes

    this.startCleanup();
  }

  createSession(sessionId, options = {}) {
    const session = {
      id: sessionId,
      created: Date.now(),
      lastActivity: Date.now(),
      buffer: new CircularBuffer(1000), // Fixed-size buffer
      metadata: { ...options }
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  updateActivity(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastActivity = Date.now();
    }
  }

  startCleanup() {
    setInterval(() => {
      this.cleanupInactiveSessions();
      this.forceGarbageCollection();
    }, this.cleanupInterval);
  }

  cleanupInactiveSessions() {
    const now = Date.now();
    for (const [sessionId, session] of this.sessions) {
      if (now - session.lastActivity > this.maxInactiveTime) {
        this.destroySession(sessionId);
      }
    }
  }

  forceGarbageCollection() {
    if (global.gc) {
      global.gc();
    }
  }
}

// Circular buffer implementation for fixed memory usage
class CircularBuffer {
  constructor(size) {
    this.buffer = new Array(size);
    this.size = size;
    this.head = 0;
    this.tail = 0;
    this.count = 0;
  }

  push(item) {
    this.buffer[this.tail] = item;
    this.tail = (this.tail + 1) % this.size;

    if (this.count < this.size) {
      this.count++;
    } else {
      this.head = (this.head + 1) % this.size;
    }
  }

  toArray() {
    if (this.count === 0) return [];

    const result = new Array(this.count);
    for (let i = 0; i < this.count; i++) {
      result[i] = this.buffer[(this.head + i) % this.size];
    }
    return result;
  }
}
```

### Client-Side Memory Management

```javascript
// Client memory optimization
class ClientMemoryManager {
  constructor() {
    this.terminals = new WeakMap();
    this.memoryThreshold = 100 * 1024 * 1024; // 100MB
    this.checkInterval = 30000; // 30 seconds

    this.startMonitoring();
  }

  startMonitoring() {
    if ('memory' in performance) {
      setInterval(() => {
        this.checkMemoryUsage();
      }, this.checkInterval);
    }
  }

  checkMemoryUsage() {
    const memInfo = performance.memory;

    if (memInfo.usedJSHeapSize > this.memoryThreshold) {
      console.warn('High memory usage detected:', {
        used: Math.round(memInfo.usedJSHeapSize / 1024 / 1024) + 'MB',
        total: Math.round(memInfo.totalJSHeapSize / 1024 / 1024) + 'MB',
        limit: Math.round(memInfo.jsHeapSizeLimit / 1024 / 1024) + 'MB'
      });

      this.cleanupMemory();
    }
  }

  cleanupMemory() {
    // Force garbage collection if available
    if (window.gc) {
      window.gc();
    }

    // Clear unused caches
    this.clearUnusedCaches();

    // Notify user to close inactive tabs
    console.info('Consider closing inactive terminal sessions');
  }

  clearUnusedCaches() {
    // Implementation depends on your caching strategy
    if ('caches' in window) {
      caches.keys().then(names => {
        names.forEach(name => {
          if (name.includes('old-') || name.includes('temp-')) {
            caches.delete(name);
          }
        });
      });
    }
  }
}
```

## Network Optimization

### Bandwidth Optimization

```javascript
// Intelligent data compression
class DataCompressor {
  constructor() {
    this.compressionThreshold = 1024; // 1KB
    this.compressionLevel = 6;
  }

  async compress(data) {
    if (data.length < this.compressionThreshold) {
      return { compressed: false, data };
    }

    try {
      const compressed = await this.gzipCompress(data);

      // Only use compression if it saves space
      if (compressed.length < data.length * 0.9) {
        return { compressed: true, data: compressed };
      }
    } catch (error) {
      console.warn('Compression failed:', error);
    }

    return { compressed: false, data };
  }

  async gzipCompress(data) {
    const stream = new CompressionStream('gzip');
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    writer.write(new TextEncoder().encode(data));
    writer.close();

    const chunks = [];
    let done = false;

    while (!done) {
      const { value, done: readerDone } = await reader.read();
      done = readerDone;
      if (value) chunks.push(value);
    }

    return new Uint8Array(chunks.reduce((acc, chunk) => [...acc, ...chunk], []));
  }
}
```

### Connection Pooling

```javascript
// WebSocket connection pool for multiple sessions
class WebSocketPool {
  constructor(maxConnections = 5) {
    this.connections = [];
    this.maxConnections = maxConnections;
    this.currentIndex = 0;
  }

  getConnection() {
    if (this.connections.length < this.maxConnections) {
      const ws = new WebSocket('ws://localhost:3000/ws');
      this.connections.push({
        websocket: ws,
        sessions: new Set(),
        lastUsed: Date.now()
      });
      return ws;
    }

    // Round-robin selection
    const connection = this.connections[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.connections.length;
    connection.lastUsed = Date.now();

    return connection.websocket;
  }

  assignSession(sessionId, websocket) {
    const connection = this.connections.find(conn => conn.websocket === websocket);
    if (connection) {
      connection.sessions.add(sessionId);
    }
  }

  removeSession(sessionId) {
    this.connections.forEach(connection => {
      connection.sessions.delete(sessionId);
    });
  }
}
```

## Monitoring and Profiling

### Performance Monitoring

```javascript
// Built-in performance monitoring
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      responseTime: [],
      memoryUsage: [],
      cpuUsage: [],
      activeConnections: 0,
      messagesPerSecond: 0
    };

    this.startTime = Date.now();
    this.messageCount = 0;

    this.startMonitoring();
  }

  startMonitoring() {
    // Collect metrics every 10 seconds
    setInterval(() => {
      this.collectMetrics();
    }, 10000);

    // Reset message counter every second
    setInterval(() => {
      this.metrics.messagesPerSecond = this.messageCount;
      this.messageCount = 0;
    }, 1000);
  }

  collectMetrics() {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    this.metrics.memoryUsage.push({
      timestamp: Date.now(),
      rss: memUsage.rss,
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      external: memUsage.external
    });

    // Keep only last 100 measurements
    if (this.metrics.memoryUsage.length > 100) {
      this.metrics.memoryUsage.shift();
    }
  }

  recordResponseTime(duration) {
    this.metrics.responseTime.push({
      timestamp: Date.now(),
      duration
    });

    // Keep only last 1000 measurements
    if (this.metrics.responseTime.length > 1000) {
      this.metrics.responseTime.shift();
    }
  }

  incrementMessageCount() {
    this.messageCount++;
  }

  getMetrics() {
    const now = Date.now();
    const uptime = now - this.startTime;

    return {
      uptime,
      ...this.metrics,
      averageResponseTime: this.calculateAverage(this.metrics.responseTime, 'duration'),
      currentMemoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
    };
  }

  calculateAverage(array, property) {
    if (array.length === 0) return 0;
    const sum = array.reduce((acc, item) => acc + item[property], 0);
    return sum / array.length;
  }
}
```

### Profiling Tools

```bash
# Node.js profiling
# CPU profiling
node --prof unified-server.js

# Memory profiling
node --inspect --inspect-brk unified-server.js

# V8 profiling
node --prof-process isolate-0x*.log > processed.txt

# Chrome DevTools profiling
node --inspect=0.0.0.0:9229 unified-server.js
# Open chrome://inspect in Chrome
```

### Health Check Endpoints

```javascript
// Health check with performance metrics
app.get('/api/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    connections: io.engine.clientsCount,
    version: process.version,
    platform: process.platform,
    arch: process.arch
  };

  // Check critical thresholds
  const memoryUsageMB = health.memory.heapUsed / 1024 / 1024;
  if (memoryUsageMB > 1000) { // 1GB threshold
    health.status = 'degraded';
    health.warnings = ['High memory usage'];
  }

  if (health.connections > 100) { // Connection threshold
    health.status = 'degraded';
    health.warnings = [...(health.warnings || []), 'High connection count'];
  }

  res.json(health);
});

// Detailed metrics endpoint
app.get('/api/metrics', (req, res) => {
  const performanceMonitor = req.app.get('performanceMonitor');
  res.json(performanceMonitor.getMetrics());
});
```

## Benchmarks

### Terminal Performance Benchmarks

```javascript
// Terminal input latency benchmark
class LatencyBenchmark {
  constructor(websocket) {
    this.ws = websocket;
    this.results = [];
  }

  async runBenchmark(iterations = 100) {
    console.log(`Running latency benchmark with ${iterations} iterations...`);

    for (let i = 0; i < iterations; i++) {
      const latency = await this.measureInputLatency();
      this.results.push(latency);

      // Wait between tests
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    return this.analyzeResults();
  }

  async measureInputLatency() {
    return new Promise((resolve) => {
      const startTime = performance.now();

      this.ws.send(JSON.stringify({
        type: 'benchmark',
        timestamp: startTime
      }));

      const handler = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === 'benchmark_response') {
          const latency = performance.now() - startTime;
          this.ws.removeEventListener('message', handler);
          resolve(latency);
        }
      };

      this.ws.addEventListener('message', handler);
    });
  }

  analyzeResults() {
    const sorted = this.results.sort((a, b) => a - b);
    const avg = this.results.reduce((sum, val) => sum + val, 0) / this.results.length;

    return {
      average: Math.round(avg * 100) / 100,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p90: sorted[Math.floor(sorted.length * 0.9)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
  }
}
```

### Load Testing

```bash
# Load testing with Artillery
npm install -g artillery

# Create artillery config
cat > load-test.yml << EOF
config:
  target: 'http://localhost:3000'
  phases:
    - duration: 60
      arrivalRate: 10
  websocket:
    url: 'ws://localhost:3000/ws'

scenarios:
  - name: "Terminal session workflow"
    weight: 100
    engine: ws
    flow:
      - send:
          payload:
            type: 'create'
            name: 'load-test-{{ \$randomNumber() }}'
      - think: 1
      - send:
          payload:
            type: 'data'
            data: 'echo "Hello World"\n'
      - think: 2
      - send:
          payload:
            type: 'destroy'
EOF

# Run load test
artillery run load-test.yml
```

### Memory Stress Test

```javascript
// Memory stress test
class MemoryStressTest {
  constructor() {
    this.sessions = [];
    this.monitoring = false;
  }

  async runTest(maxSessions = 50, duration = 60000) {
    console.log(`Starting memory stress test: ${maxSessions} sessions, ${duration}ms`);

    this.startMemoryMonitoring();

    // Create sessions gradually
    for (let i = 0; i < maxSessions; i++) {
      await this.createSession(`stress-test-${i}`);
      await this.sleep(100); // 100ms between session creations
    }

    console.log(`Created ${maxSessions} sessions`);

    // Let it run for specified duration
    await this.sleep(duration);

    // Cleanup
    await this.cleanup();
    this.stopMemoryMonitoring();

    console.log('Stress test completed');
  }

  async createSession(sessionId) {
    const session = {
      id: sessionId,
      ws: new WebSocket('ws://localhost:3000/ws'),
      buffer: []
    };

    session.ws.onopen = () => {
      session.ws.send(JSON.stringify({
        type: 'create',
        name: sessionId
      }));
    };

    session.ws.onmessage = (event) => {
      session.buffer.push(event.data);

      // Simulate terminal activity
      if (Math.random() < 0.1) {
        session.ws.send(JSON.stringify({
          type: 'data',
          data: `echo "${Date.now()}"\n`
        }));
      }
    };

    this.sessions.push(session);
  }

  startMemoryMonitoring() {
    this.monitoring = true;

    const monitor = () => {
      if (!this.monitoring) return;

      if ('memory' in performance) {
        const memInfo = performance.memory;
        console.log(`Memory: ${Math.round(memInfo.usedJSHeapSize / 1024 / 1024)}MB used, ${Math.round(memInfo.totalJSHeapSize / 1024 / 1024)}MB total`);
      }

      setTimeout(monitor, 5000);
    };

    monitor();
  }

  stopMemoryMonitoring() {
    this.monitoring = false;
  }

  async cleanup() {
    for (const session of this.sessions) {
      if (session.ws.readyState === WebSocket.OPEN) {
        session.ws.close();
      }
    }

    this.sessions = [];

    if (window.gc) {
      window.gc();
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

## Troubleshooting

### Performance Issues

#### High Memory Usage

**Symptoms**:
- Server running out of memory
- Slow response times
- Browser tab crashes

**Solutions**:
```bash
# Reduce scrollback buffer
SCROLLBACK_LINES=500 claude-flow-ui

# Limit concurrent sessions
MAX_SESSIONS=10 claude-flow-ui

# Enable aggressive garbage collection
node --expose-gc --gc-interval=30000 unified-server.js

# Monitor memory usage
watch -n 5 'ps aux | grep claude-flow-ui | head -5'
```

#### High CPU Usage

**Symptoms**:
- Server consuming high CPU
- UI becoming unresponsive
- Fans spinning up

**Solutions**:
```bash
# Reduce WebSocket heartbeat frequency
WS_HEARTBEAT_INTERVAL=60000 claude-flow-ui

# Disable terminal features
TERMINAL_CURSOR_BLINK=false \
TERMINAL_ALLOW_TRANSPARENCY=false \
claude-flow-ui

# Use clustering to distribute load
CLUSTER_MODE=true WORKERS=4 claude-flow-ui
```

#### Network Latency

**Symptoms**:
- Delayed terminal input
- Slow page loads
- WebSocket disconnections

**Solutions**:
```bash
# Enable compression
WS_COMPRESSION=true claude-flow-ui

# Optimize buffer sizes
WS_BUFFER_SIZE=8192 \
WS_MAX_MESSAGE_SIZE=1048576 \
claude-flow-ui

# Use CDN for static assets
STATIC_CDN_URL=https://cdn.example.com claude-flow-ui
```

### Debugging Performance Issues

```bash
# Enable performance debugging
DEBUG=performance,websocket,terminal claude-flow-ui

# Profile with clinic.js
npm install -g clinic
clinic doctor -- node unified-server.js

# Monitor system resources
htop
iotop
nethogs
```

### Performance Testing Scripts

```bash
#!/bin/bash
# performance-test.sh

echo "Starting Claude Flow UI performance tests..."

# Start server in background
node unified-server.js &
SERVER_PID=$!

sleep 5

echo "Running load tests..."
artillery run load-test.yml

echo "Running memory stress test..."
node memory-stress-test.js

echo "Running latency benchmark..."
node latency-benchmark.js

# Cleanup
kill $SERVER_PID

echo "Performance tests completed"
```

This comprehensive performance guide provides the tools and techniques needed to optimize Claude Flow UI for various deployment scenarios and usage patterns.