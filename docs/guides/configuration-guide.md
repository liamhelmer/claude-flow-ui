# Claude Flow UI - Configuration Guide

## Table of Contents

1. [Overview](#overview)
2. [Environment Variables](#environment-variables)
3. [Command Line Options](#command-line-options)
4. [Configuration Files](#configuration-files)
5. [Server Configuration](#server-configuration)
6. [Terminal Configuration](#terminal-configuration)
7. [WebSocket Configuration](#websocket-configuration)
8. [Security Configuration](#security-configuration)
9. [Performance Configuration](#performance-configuration)
10. [Claude Flow Integration](#claude-flow-integration)
11. [Advanced Configuration](#advanced-configuration)

## Overview

Claude Flow UI can be configured through multiple methods:

1. **Environment Variables** - System-wide configuration
2. **Command Line Options** - Runtime configuration
3. **Configuration Files** - Persistent configuration
4. **Runtime API** - Dynamic configuration

Configuration precedence (highest to lowest):
1. Command line options
2. Environment variables
3. Configuration files
4. Default values

## Environment Variables

### Basic Server Configuration

```bash
# Server port (default: 3000)
PORT=3000

# WebSocket server port (default: PORT + 1)
WS_PORT=3001

# Development mode (default: false)
NODE_ENV=development

# Maximum concurrent sessions (default: 10)
MAX_SESSIONS=10

# Session timeout in milliseconds (default: 300000)
SESSION_TIMEOUT=300000
```

### Terminal Configuration

```bash
# Default terminal size (default: 80x24)
TERMINAL_SIZE=120x40

# Terminal scrollback lines (default: 1000)
SCROLLBACK_LINES=2000

# Terminal theme (default: dark)
TERMINAL_THEME=dark

# Terminal font family
TERMINAL_FONT_FAMILY="Monaco, Consolas, monospace"

# Terminal font size (default: 14)
TERMINAL_FONT_SIZE=16
```

### WebSocket Configuration

```bash
# WebSocket heartbeat interval in ms (default: 30000)
WS_HEARTBEAT_INTERVAL=30000

# WebSocket connection timeout in ms (default: 5000)
WS_CONNECTION_TIMEOUT=5000

# Maximum WebSocket message size in bytes (default: 1048576)
WS_MAX_MESSAGE_SIZE=1048576

# WebSocket compression (default: true)
WS_COMPRESSION=true
```

### Security Configuration

```bash
# API key for authentication (optional)
API_KEY=your_secure_api_key

# Allowed origins for CORS (comma-separated)
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Enable/disable HTTPS (default: false)
ENABLE_HTTPS=false

# SSL certificate path (required if ENABLE_HTTPS=true)
SSL_CERT_PATH=/path/to/cert.pem

# SSL key path (required if ENABLE_HTTPS=true)
SSL_KEY_PATH=/path/to/key.pem
```

### Claude Flow Integration

```bash
# Claude API key
CLAUDE_API_KEY=sk-ant-api03-...

# Initial Claude Flow command
CLAUDE_FLOW_INIT=swarm --objective "development tasks"

# Additional Claude Flow arguments
CLAUDE_FLOW_ARGS=--verbose --log-level debug

# Claude Flow workspace directory
CLAUDE_FLOW_WORKSPACE=/path/to/workspace

# Enable Claude Flow auto-start (default: false)
CLAUDE_FLOW_AUTOSTART=true
```

### Logging Configuration

```bash
# Log level (error, warn, info, debug)
LOG_LEVEL=info

# Log file path
LOG_FILE=/var/log/claude-flow-ui.log

# Enable request logging (default: false)
ENABLE_REQUEST_LOGGING=true

# Log format (json, text)
LOG_FORMAT=json

# Maximum log file size in MB
LOG_MAX_SIZE=100

# Number of log files to retain
LOG_MAX_FILES=5
```

## Command Line Options

### Basic Options

```bash
claude-flow-ui [options] [claude-flow-args]

# Server configuration
--port, -p <port>           Server port (default: 3000)
--ws-port <port>           WebSocket port (default: PORT + 1)
--host <host>              Server host (default: localhost)

# Terminal configuration
--terminal-size <size>     Terminal size as "COLSxROWS" (default: 80x24)
--max-sessions <count>     Maximum concurrent sessions (default: 10)
--session-timeout <ms>     Session timeout in milliseconds

# Logging options
--log-level <level>        Log level: error, warn, info, debug
--log-file <path>          Log file path
--quiet, -q               Suppress non-error output
--verbose, -v             Enable verbose logging

# General options
--help, -h                Show help information
--version                 Show version information
--config <path>           Configuration file path
```

### Advanced Options

```bash
# Performance options
--scrollback-lines <count>  Terminal scrollback buffer size
--ws-heartbeat <ms>        WebSocket heartbeat interval
--compression             Enable WebSocket compression

# Security options
--api-key <key>           API key for authentication
--ssl-cert <path>         SSL certificate path
--ssl-key <path>          SSL private key path
--allowed-origins <urls>  Comma-separated allowed origins

# Development options
--dev                     Development mode
--hot-reload              Enable hot reload
--debug                   Enable debug mode
--inspect                 Enable Node.js inspector
```

### Usage Examples

```bash
# Basic usage with custom port
claude-flow-ui --port 8080

# Development setup with debugging
claude-flow-ui --dev --debug --log-level debug

# Production setup with SSL
claude-flow-ui \
  --port 443 \
  --ssl-cert /etc/ssl/certs/server.crt \
  --ssl-key /etc/ssl/private/server.key \
  --log-level warn

# High-performance configuration
claude-flow-ui \
  --max-sessions 50 \
  --scrollback-lines 5000 \
  --ws-heartbeat 60000 \
  --compression

# With Claude Flow integration
claude-flow-ui --port 3000 swarm --objective "API development"
```

## Configuration Files

### Default Configuration File

Create `~/.claude-flow-ui/config.json`:

```json
{
  "server": {
    "port": 3000,
    "host": "localhost",
    "wsPort": 3001,
    "maxSessions": 10,
    "sessionTimeout": 300000
  },
  "terminal": {
    "size": "80x24",
    "scrollbackLines": 1000,
    "theme": "dark",
    "fontFamily": "Monaco, Consolas, monospace",
    "fontSize": 14,
    "cursorBlink": true
  },
  "websocket": {
    "heartbeatInterval": 30000,
    "connectionTimeout": 5000,
    "maxMessageSize": 1048576,
    "compression": true
  },
  "security": {
    "apiKey": null,
    "allowedOrigins": ["http://localhost:3000"],
    "enableHttps": false,
    "sslCertPath": null,
    "sslKeyPath": null
  },
  "logging": {
    "level": "info",
    "file": null,
    "format": "text",
    "enableRequestLogging": false,
    "maxSize": "100MB",
    "maxFiles": 5
  },
  "claudeFlow": {
    "apiKey": null,
    "initCommand": null,
    "args": [],
    "workspace": null,
    "autostart": false
  }
}
```

### Project Configuration File

Create `claude-flow-ui.config.js` in your project root:

```javascript
module.exports = {
  server: {
    port: process.env.PORT || 3000,
    host: process.env.HOST || 'localhost',
    maxSessions: 20
  },

  terminal: {
    size: process.env.TERMINAL_SIZE || '120x40',
    scrollbackLines: 2000,
    theme: 'dark'
  },

  websocket: {
    heartbeatInterval: 30000,
    compression: true
  },

  security: {
    allowedOrigins: [
      'http://localhost:3000',
      'https://yourdomain.com'
    ]
  },

  claudeFlow: {
    apiKey: process.env.CLAUDE_API_KEY,
    initCommand: 'swarm --objective "development"',
    workspace: './workspace'
  },

  // Environment-specific overrides
  development: {
    server: { port: 3000 },
    logging: { level: 'debug' }
  },

  production: {
    server: { port: 80 },
    logging: { level: 'warn', file: '/var/log/claude-flow-ui.log' },
    security: { enableHttps: true }
  }
};
```

### TypeScript Configuration

Create `claude-flow-ui.config.ts`:

```typescript
import type { ClaudeFlowUIConfig } from '@liamhelmer/claude-flow-ui';

const config: ClaudeFlowUIConfig = {
  server: {
    port: 3000,
    maxSessions: 15
  },

  terminal: {
    size: '100x30',
    scrollbackLines: 1500,
    theme: 'dark' as const
  },

  websocket: {
    heartbeatInterval: 25000,
    compression: true
  }
};

export default config;
```

### Loading Configuration Files

```bash
# Specify custom config file
claude-flow-ui --config /path/to/config.json

# Use project config file
claude-flow-ui --config ./claude-flow-ui.config.js

# Environment-specific config
NODE_ENV=production claude-flow-ui --config config.json
```

## Server Configuration

### Basic Server Settings

```bash
# Server binding
HOST=0.0.0.0          # Bind to all interfaces
PORT=3000             # HTTP server port

# Worker processes (for clustering)
WORKERS=4             # Number of worker processes
CLUSTER_MODE=true     # Enable cluster mode

# Request handling
REQUEST_TIMEOUT=30000 # Request timeout in ms
BODY_LIMIT=1mb        # Request body size limit
```

### Performance Settings

```bash
# Connection limits
MAX_CONNECTIONS=1000     # Maximum concurrent connections
KEEP_ALIVE_TIMEOUT=5000  # Keep-alive timeout
HEADERS_TIMEOUT=60000    # Headers timeout

# Memory management
MAX_MEMORY_USAGE=512     # Maximum memory usage in MB
MEMORY_CHECK_INTERVAL=60 # Memory check interval in seconds

# Garbage collection
GC_INTERVAL=300000      # Garbage collection interval in ms
GC_THRESHOLD=80         # GC threshold as percentage
```

### Production Settings

```bash
# Process management
NODE_ENV=production
CLUSTER_MODE=true
WORKERS=0              # Auto-detect CPU count

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_PATH=/health

# Error handling
CRASH_ON_UNHANDLED_REJECTION=false
GRACEFUL_SHUTDOWN_TIMEOUT=10000
```

## Terminal Configuration

### Display Settings

```bash
# Terminal appearance
TERMINAL_THEME=dark              # dark, light, or custom theme name
TERMINAL_FONT_FAMILY="Fira Code" # Font family
TERMINAL_FONT_SIZE=14           # Font size in pixels
TERMINAL_LINE_HEIGHT=1.2        # Line height multiplier

# Cursor settings
CURSOR_BLINK=true               # Enable cursor blinking
CURSOR_STYLE=block              # block, underline, bar
CURSOR_WIDTH=1                  # Cursor width in pixels

# Text settings
ALLOW_TRANSPARENCY=false        # Allow transparent background
DRAW_BOLD_TEXT_IN_BRIGHT_COLORS=true
FAST_SCROLL_MODIFIER=alt        # Modifier for fast scroll
```

### Buffer Settings

```bash
# Scrollback configuration
SCROLLBACK_LINES=1000           # Number of scrollback lines
SCROLL_SENSITIVITY=1            # Scroll sensitivity multiplier
FAST_SCROLL_SENSITIVITY=5       # Fast scroll sensitivity

# Selection settings
WORD_SEPARATOR=" ()[]{},'\"`"   # Word separator characters
RIGHT_CLICK_SELECTS_WORD=true   # Right-click word selection
TRIPLE_CLICK_SELECTS_LINE=true  # Triple-click line selection
```

### Behavior Settings

```bash
# Terminal behavior
BELL_SOUND=false               # Enable bell sound
BELL_STYLE=none                # none, sound, visual, both
CONVERT_EOL=false              # Convert line endings
DISABLE_STDIN=false            # Disable terminal input
MAC_OPTION_IS_META=false       # macOS Option key behavior

# Copy/paste settings
COPY_ON_SELECT=false           # Auto-copy on selection
RIGHT_CLICK_MOVES_CURSOR=false # Right-click cursor positioning
```

## WebSocket Configuration

### Connection Settings

```bash
# Connection behavior
WS_HEARTBEAT_INTERVAL=30000    # Heartbeat interval in ms
WS_CONNECTION_TIMEOUT=5000     # Connection timeout in ms
WS_RECONNECTION_DELAY=1000     # Reconnection delay in ms
WS_MAX_RECONNECTION_ATTEMPTS=5 # Maximum reconnection attempts

# Message handling
WS_MAX_MESSAGE_SIZE=1048576    # Maximum message size in bytes
WS_MESSAGE_QUEUE_SIZE=100      # Message queue size
WS_BUFFER_HIGH_WATER_MARK=16384 # Buffer high water mark
```

### Performance Settings

```bash
# Compression and optimization
WS_COMPRESSION=true            # Enable compression
WS_COMPRESSION_THRESHOLD=1024  # Compression threshold in bytes
WS_COMPRESSION_LEVEL=6         # Compression level (1-9)

# Batching and buffering
WS_MESSAGE_BATCHING=true       # Enable message batching
WS_BATCH_INTERVAL=16           # Batch interval in ms
WS_BATCH_SIZE=100             # Maximum messages per batch
```

### Advanced WebSocket Settings

```bash
# Protocol settings
WS_PROTOCOL_VERSION=13         # WebSocket protocol version
WS_EXTENSIONS="permessage-deflate" # Enabled extensions
WS_SUBPROTOCOLS=""            # Supported subprotocols

# Security settings
WS_ORIGIN_CHECK=true          # Enable origin checking
WS_MAX_FRAME_SIZE=1048576     # Maximum frame size
WS_MAX_MESSAGE_QUEUE=1000     # Maximum message queue length
```

## Security Configuration

### Authentication

```bash
# API key authentication
API_KEY=your_secure_key_here   # API key for protected endpoints
API_KEY_HEADER=X-API-Key       # Header name for API key

# Session-based authentication
ENABLE_SESSIONS=false          # Enable session authentication
SESSION_SECRET=your_secret     # Session encryption secret
SESSION_TIMEOUT=3600000        # Session timeout in ms
```

### CORS Settings

```bash
# Cross-Origin Resource Sharing
CORS_ENABLED=true                    # Enable CORS
ALLOWED_ORIGINS=http://localhost:3000 # Comma-separated origins
ALLOWED_METHODS=GET,POST,PUT,DELETE  # Allowed HTTP methods
ALLOWED_HEADERS=Content-Type,Authorization # Allowed headers
ALLOW_CREDENTIALS=false              # Allow credentials
```

### SSL/TLS Configuration

```bash
# HTTPS settings
ENABLE_HTTPS=false             # Enable HTTPS
SSL_CERT_PATH=/path/to/cert.pem # SSL certificate path
SSL_KEY_PATH=/path/to/key.pem  # SSL private key path
SSL_CA_PATH=/path/to/ca.pem    # Certificate authority path

# TLS settings
TLS_MIN_VERSION=1.2           # Minimum TLS version
TLS_CIPHERS=HIGH:!aNULL       # Allowed cipher suites
HSTS_MAX_AGE=31536000         # HSTS max age in seconds
```

### Content Security Policy

```bash
# CSP settings
CSP_ENABLED=true              # Enable CSP
CSP_POLICY="default-src 'self'; script-src 'self' 'unsafe-inline'"
CSP_REPORT_URI=/api/csp-report # CSP report endpoint
CSP_REPORT_ONLY=false         # CSP report-only mode
```

## Performance Configuration

### Memory Management

```bash
# Memory limits
MAX_MEMORY_USAGE=512          # Maximum memory in MB
MEMORY_CHECK_INTERVAL=60000   # Memory check interval in ms
GC_INTERVAL=300000           # Garbage collection interval

# Buffer management
BUFFER_POOL_SIZE=1000        # Buffer pool size
BUFFER_CLEANUP_INTERVAL=60000 # Buffer cleanup interval
MAX_BUFFER_SIZE=1048576      # Maximum buffer size
```

### CPU Optimization

```bash
# Process management
CLUSTER_MODE=true            # Enable cluster mode
WORKERS=0                    # Worker count (0 = auto-detect)
WORKER_RESTART_DELAY=1000    # Worker restart delay in ms

# Event loop optimization
EVENT_LOOP_DELAY_THRESHOLD=100 # Event loop delay threshold
UV_THREADPOOL_SIZE=16          # UV thread pool size
```

### Caching Configuration

```bash
# Response caching
ENABLE_CACHE=true            # Enable response caching
CACHE_MAX_SIZE=100           # Cache size in MB
CACHE_TTL=3600000           # Cache TTL in ms
CACHE_COMPRESSION=true       # Enable cache compression

# Static file caching
STATIC_CACHE_MAX_AGE=86400   # Static file cache max age
STATIC_CACHE_CONTROL=public  # Static file cache control
```

## Claude Flow Integration

### Basic Integration

```bash
# Claude API configuration
CLAUDE_API_KEY=sk-ant-api03-... # Claude API key (required)
CLAUDE_MODEL=claude-3-opus-20240229 # Claude model to use
CLAUDE_MAX_TOKENS=4096          # Maximum tokens per request

# Claude Flow initialization
CLAUDE_FLOW_INIT=swarm          # Initial command
CLAUDE_FLOW_ARGS="--objective 'development'" # Additional arguments
CLAUDE_FLOW_WORKSPACE=./workspace # Workspace directory
```

### Advanced Integration

```bash
# Automatic startup
CLAUDE_FLOW_AUTOSTART=true      # Auto-start on server launch
CLAUDE_FLOW_RESTART_ON_FAIL=true # Restart on failure
CLAUDE_FLOW_MAX_RESTARTS=3      # Maximum restart attempts

# Communication settings
CLAUDE_FLOW_TIMEOUT=30000       # Request timeout in ms
CLAUDE_FLOW_RETRY_COUNT=3       # Retry count for failed requests
CLAUDE_FLOW_RETRY_DELAY=1000    # Retry delay in ms

# Logging and monitoring
CLAUDE_FLOW_LOG_LEVEL=info      # Claude Flow log level
CLAUDE_FLOW_LOG_FILE=./claude-flow.log # Log file path
CLAUDE_FLOW_METRICS_ENABLED=true # Enable metrics collection
```

### Environment-Specific Settings

```bash
# Development environment
CLAUDE_FLOW_DEV_MODE=true       # Enable development mode
CLAUDE_FLOW_MOCK_RESPONSES=false # Use mock responses
CLAUDE_FLOW_DEBUG_REQUESTS=true  # Debug API requests

# Production environment
CLAUDE_FLOW_RATE_LIMIT=100      # Requests per minute
CLAUDE_FLOW_CIRCUIT_BREAKER=true # Enable circuit breaker
CLAUDE_FLOW_HEALTH_CHECK=true   # Enable health checks
```

## Advanced Configuration

### Custom Configuration Sources

```javascript
// Load configuration from external source
const config = await loadConfigFromDatabase();
const app = new ClaudeFlowUI(config);

// Dynamic configuration updates
app.updateConfig({
  server: { maxSessions: 20 }
});

// Configuration validation
const { valid, errors } = validateConfig(config);
if (!valid) {
  console.error('Configuration errors:', errors);
}
```

### Configuration Profiles

```bash
# Create profiles for different environments
cp config.json config.development.json
cp config.json config.production.json
cp config.json config.testing.json

# Use profile-specific configuration
NODE_ENV=development claude-flow-ui
NODE_ENV=production claude-flow-ui
```

### Runtime Configuration Changes

```javascript
// Via WebSocket
ws.send(JSON.stringify({
  type: 'configure',
  target: 'terminal',
  config: {
    theme: 'light',
    fontSize: 16
  }
}));

// Via HTTP API
fetch('/api/config', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    terminal: { scrollbackLines: 2000 }
  })
});
```

### Configuration Monitoring

```bash
# Enable configuration change monitoring
CONFIG_WATCH=true              # Watch config files for changes
CONFIG_RELOAD_GRACE_PERIOD=5000 # Grace period before reload

# Configuration backup
CONFIG_BACKUP_ENABLED=true     # Enable config backups
CONFIG_BACKUP_INTERVAL=3600000 # Backup interval in ms
CONFIG_BACKUP_RETENTION=7      # Number of backups to retain
```

This comprehensive configuration guide covers all aspects of configuring Claude Flow UI for various use cases and environments.