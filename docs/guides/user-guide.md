# Claude Flow UI - User Guide

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Basic Usage](#basic-usage)
5. [Terminal Management](#terminal-management)
6. [Configuration](#configuration)
7. [Data Transformations](#data-transformations)
8. [Advanced Features](#advanced-features)
9. [Troubleshooting](#troubleshooting)

## Overview

Claude Flow UI is a modern web-based terminal and monitoring interface for Claude Flow with real-time system monitoring and tmux integration. It provides a powerful web interface for managing terminal sessions, executing commands, and processing data transformations.

### Key Features

- **Web-based Terminal**: Full-featured terminal accessible through your browser
- **Multi-session Management**: Create and manage multiple terminal sessions
- **Real-time Communication**: WebSocket-based real-time terminal interaction
- **Data Transformations**: Built-in data processing and transformation pipeline
- **Tmux Integration**: Seamless integration with tmux for session persistence
- **Responsive Design**: Works on desktop and mobile devices
- **Performance Monitoring**: Real-time system monitoring and metrics

## Quick Start

### 1. Installation

```bash
# Install globally
npm install -g @liamhelmer/claude-flow-ui

# Or run directly with npx
npx @liamhelmer/claude-flow-ui
```

### 2. Start the Server

```bash
# Start with default settings
claude-flow-ui

# Start with custom port
claude-flow-ui --port 8080

# Start with custom terminal size
TERMINAL_SIZE=100x30 claude-flow-ui
```

### 3. Open in Browser

Navigate to `http://localhost:3000` (or your custom port) to access the web interface.

## Installation

### Requirements

- **Node.js**: >= 18.0.0
- **npm**: >= 8.0.0
- **Operating System**: Linux, macOS, or Windows with WSL

### Installation Methods

#### Global Installation

```bash
npm install -g @liamhelmer/claude-flow-ui
```

#### Local Installation

```bash
npm install @liamhelmer/claude-flow-ui
```

#### Using npx (No Installation)

```bash
npx @liamhelmer/claude-flow-ui
```

### Environment Setup

Create a `.env` file for configuration:

```bash
# Server Configuration
PORT=3000
TERMINAL_SIZE=80x24

# Claude Flow Configuration
CLAUDE_FLOW_INIT=swarm --objective "development tasks"
CLAUDE_API_KEY=your_api_key_here

# Advanced Configuration
WS_HEARTBEAT_INTERVAL=30000
SESSION_TIMEOUT=300000
```

## Basic Usage

### Starting the Application

1. **Default Start**:
   ```bash
   claude-flow-ui
   ```

2. **With Custom Port**:
   ```bash
   claude-flow-ui --port 8080
   ```

3. **With Terminal Size**:
   ```bash
   claude-flow-ui --terminal-size 100x40
   ```

4. **With Claude Flow Arguments**:
   ```bash
   claude-flow-ui swarm --objective "build API"
   ```

### Web Interface

The web interface consists of:

- **Sidebar**: Session management and controls
- **Terminal Area**: Main terminal display
- **Tab Bar**: Multiple session tabs
- **Control Panel**: Terminal controls and settings

### Basic Operations

1. **Create New Session**: Click "New Terminal" in sidebar
2. **Switch Sessions**: Click on session tabs or sidebar items
3. **Resize Terminal**: Drag resize handles or use controls
4. **Close Session**: Click X on tab or use sidebar controls

## Terminal Management

### Creating Sessions

#### Via Web Interface

1. Click "New Terminal" button in sidebar
2. Optionally specify session name and initial command
3. Session will appear in new tab

#### Via WebSocket API

```javascript
const ws = new WebSocket('ws://localhost:3000/ws');

ws.send(JSON.stringify({
  type: 'create',
  name: 'my-session',
  command: 'bash'
}));
```

#### Via HTTP API

```bash
curl -X POST http://localhost:3000/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"name": "my-session", "command": "bash"}'
```

### Session Management

#### List Active Sessions

```bash
curl http://localhost:3000/api/sessions
```

#### Get Session Details

```bash
curl http://localhost:3000/api/sessions/{sessionId}
```

#### Delete Session

```bash
curl -X DELETE http://localhost:3000/api/sessions/{sessionId}
```

### Terminal Controls

- **Refresh**: Reload terminal content
- **Scroll to Top**: Jump to beginning of scrollback
- **Scroll to Bottom**: Jump to latest output
- **Clear**: Clear terminal display
- **Resize**: Adjust terminal dimensions

### Keyboard Shortcuts

- `Ctrl+Shift+T`: New terminal session
- `Ctrl+Shift+W`: Close current session
- `Ctrl+Shift+N`: Next session
- `Ctrl+Shift+P`: Previous session
- `Ctrl+Shift+R`: Refresh current session

## Configuration

### Server Configuration

Configure via environment variables or `.env` file:

```bash
# Basic Configuration
PORT=3000                    # Server port
TERMINAL_SIZE=80x24         # Default terminal size

# WebSocket Configuration
WS_PORT=3001                # WebSocket server port
WS_HEARTBEAT_INTERVAL=30000 # Heartbeat interval (ms)

# Session Configuration
SESSION_TIMEOUT=300000      # Session timeout (ms)
MAX_SESSIONS=10             # Maximum concurrent sessions
SCROLLBACK_LINES=1000       # Terminal scrollback buffer

# Claude Flow Integration
CLAUDE_API_KEY=sk-...       # Claude API key
CLAUDE_FLOW_INIT=swarm      # Initial claude-flow command
CLAUDE_FLOW_ARGS=--help     # Additional arguments
```

### Terminal Configuration

```javascript
// Via WebSocket message
{
  "type": "configure",
  "sessionId": "session-123",
  "config": {
    "theme": "dark",
    "fontSize": 14,
    "fontFamily": "Monaco, Consolas, monospace",
    "cursorBlink": true,
    "scrollback": 1000
  }
}
```

### Command Line Options

```bash
claude-flow-ui [options] [claude-flow-args]

Options:
  --port, -p <port>           Server port (default: 3000)
  --ws-port <port>           WebSocket port (default: PORT + 1)
  --terminal-size <size>     Terminal size as "COLSxROWS"
  --max-sessions <count>     Maximum concurrent sessions
  --session-timeout <ms>     Session timeout in milliseconds
  --help, -h                 Show help information
  --version, -v              Show version information
```

## Data Transformations

### Overview

Claude Flow UI includes a powerful data transformation system for processing and manipulating data through configurable pipelines.

### Available Transformations

List available transformations:

```bash
curl http://localhost:3000/api/transformations
```

### Basic Transformation

```bash
curl -X POST http://localhost:3000/api/transformations \
  -H "Content-Type: application/json" \
  -d '{
    "transformationName": "text-processor",
    "data": {"text": "hello world"},
    "config": {
      "batchSize": 100,
      "parallel": true
    }
  }'
```

### Transformation Configuration

```javascript
{
  "transformationName": "data-cleaner",
  "data": { /* your data */ },
  "config": {
    "batchSize": 1000,        // Items per batch
    "parallel": false,        // Parallel processing
    "maxRetries": 3,         // Retry attempts
    "timeout": 30000,        // Timeout in ms
    "preserveOriginal": true  // Keep original data
  }
}
```

### Creating Custom Transformations

1. **Extend BaseTransformation**:

```typescript
import { AbstractTransformation } from './BaseTransformation';

export class MyTransformation extends AbstractTransformation {
  readonly name = 'my-transformation';
  readonly version = '1.0.0';
  readonly description = 'Custom transformation';

  async transform(data: any, context: TransformationContext) {
    // Your transformation logic here
    return this.createSuccessResult(processedData, 1, 0, 0);
  }

  async validate(data: any) {
    // Validation logic
    return [];
  }
}
```

2. **Register Transformation**:

```javascript
// In your startup code
const transformationManager = new TransformationManager();
transformationManager.register(new MyTransformation());
```

### Chaining Transformations

```javascript
// Create transformation chain
const chain = new TransformationChain([
  new DataCleanerTransformation(),
  new DataValidatorTransformation(),
  new DataFormatterTransformation()
]);

// Execute chain
const result = await chain.transform(data, context);
```

## Advanced Features

### WebSocket Communication

#### Connection

```javascript
const ws = new WebSocket('ws://localhost:3000/ws');

ws.onopen = () => {
  console.log('Connected to Claude Flow UI');
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

#### Message Types

1. **Data Messages**:
```javascript
// Send terminal input
ws.send(JSON.stringify({
  type: 'data',
  sessionId: 'session-123',
  data: 'ls -la\n'
}));
```

2. **Control Messages**:
```javascript
// Resize terminal
ws.send(JSON.stringify({
  type: 'resize',
  sessionId: 'session-123',
  cols: 120,
  rows: 40
}));
```

3. **Session Messages**:
```javascript
// Create new session
ws.send(JSON.stringify({
  type: 'create',
  name: 'development',
  command: 'zsh'
}));
```

### Tmux Integration

#### Automatic Session Management

Claude Flow UI automatically manages tmux sessions:

- Creates isolated tmux sessions for each terminal
- Handles session cleanup on disconnect
- Provides session persistence across page reloads
- Supports tmux window and pane operations

#### Manual Tmux Commands

```bash
# List tmux sessions
tmux list-sessions

# Attach to session
tmux attach-session -t session-name

# Kill session
tmux kill-session -t session-name
```

### Performance Monitoring

#### System Metrics

Access system metrics via API:

```bash
curl http://localhost:3000/api/metrics
```

Response includes:
- CPU usage
- Memory usage
- Active sessions count
- WebSocket connections
- System uptime

#### Performance Tuning

1. **Adjust Buffer Sizes**:
```bash
SCROLLBACK_LINES=5000 claude-flow-ui
```

2. **Limit Concurrent Sessions**:
```bash
MAX_SESSIONS=5 claude-flow-ui
```

3. **WebSocket Optimization**:
```bash
WS_HEARTBEAT_INTERVAL=60000 claude-flow-ui
```

### Health Monitoring

#### Health Check Endpoint

```bash
curl http://localhost:3000/api/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-09-24T12:00:00.000Z",
  "uptime": 3600,
  "services": {
    "websocket": "active",
    "tmux": "available"
  }
}
```

#### Monitoring Integration

Integrate with monitoring systems:

```bash
# Prometheus metrics endpoint
curl http://localhost:3000/metrics

# Health check for load balancer
curl -f http://localhost:3000/api/health || exit 1
```

## Troubleshooting

### Common Issues

#### 1. Port Already in Use

**Problem**: Server fails to start with "EADDRINUSE" error

**Solution**:
```bash
# Use different port
claude-flow-ui --port 8080

# Or kill process using port
lsof -ti:3000 | xargs kill -9
```

#### 2. WebSocket Connection Failed

**Problem**: Browser shows WebSocket connection errors

**Solutions**:
- Check firewall settings
- Verify WebSocket port is accessible
- Try different port: `--ws-port 3002`
- Check browser console for detailed errors

#### 3. Terminal Not Responding

**Problem**: Terminal appears frozen or unresponsive

**Solutions**:
- Refresh the page
- Check server logs for errors
- Restart terminal session
- Verify tmux session status

#### 4. Session Creation Failed

**Problem**: Cannot create new terminal sessions

**Solutions**:
```bash
# Check tmux availability
which tmux

# Install tmux if missing
# Ubuntu/Debian:
sudo apt-get install tmux

# macOS:
brew install tmux

# Check session limits
curl http://localhost:3000/api/sessions
```

#### 5. High Memory Usage

**Problem**: Application consuming excessive memory

**Solutions**:
- Reduce scrollback buffer: `SCROLLBACK_LINES=500`
- Limit concurrent sessions: `MAX_SESSIONS=3`
- Close unused sessions
- Restart application periodically

### Debugging

#### Enable Debug Logging

```bash
DEBUG=claude-flow-ui:* claude-flow-ui
```

#### Log File Locations

- **Server logs**: `~/.claude-flow-ui/logs/server.log`
- **Session logs**: `~/.claude-flow-ui/logs/session-*.log`
- **Error logs**: `~/.claude-flow-ui/logs/error.log`

#### Browser Debugging

1. Open browser Developer Tools (F12)
2. Check Console tab for JavaScript errors
3. Check Network tab for failed requests
4. Monitor WebSocket connection in Network tab

### Getting Help

1. **Documentation**: Check `/docs` folder for detailed documentation
2. **Issues**: Report bugs at [GitHub Issues](https://github.com/liamhelmer/claude-flow-ui/issues)
3. **Discussions**: Join discussions for questions and feature requests
4. **Logs**: Always include relevant logs when reporting issues

### Performance Optimization

#### Client-Side

- Use modern browsers with WebSocket support
- Close unused browser tabs
- Disable unnecessary browser extensions
- Clear browser cache periodically

#### Server-Side

```bash
# Optimize for high-performance scenarios
NODE_ENV=production \
MAX_SESSIONS=20 \
SCROLLBACK_LINES=2000 \
WS_HEARTBEAT_INTERVAL=60000 \
claude-flow-ui
```

This comprehensive user guide covers all aspects of using Claude Flow UI effectively. For additional technical details, refer to the API documentation and plugin development guides.