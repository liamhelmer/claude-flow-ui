# Claude Flow UI - Troubleshooting Guide

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Installation Issues](#installation-issues)
3. [Server Startup Problems](#server-startup-problems)
4. [WebSocket Connection Issues](#websocket-connection-issues)
5. [Terminal Session Problems](#terminal-session-problems)
6. [Performance Issues](#performance-issues)
7. [Configuration Problems](#configuration-problems)
8. [Browser Compatibility](#browser-compatibility)
9. [Network and Firewall Issues](#network-and-firewall-issues)
10. [Error Messages and Solutions](#error-messages-and-solutions)
11. [Debugging Tools](#debugging-tools)
12. [Getting Help](#getting-help)

## Quick Diagnostics

### Health Check Command

```bash
# Check if server is running and healthy
curl -f http://localhost:3000/api/health || echo "Server not responding"

# Check WebSocket connectivity
wscat -c ws://localhost:3000/ws || echo "WebSocket connection failed"

# Check system resources
ps aux | grep claude-flow-ui
netstat -tlnp | grep :3000
```

### Common Status Checks

```bash
# Verify installation
claude-flow-ui --version

# Check Node.js version
node --version  # Should be >= 18.0.0

# Check npm version
npm --version   # Should be >= 8.0.0

# Test tmux availability
tmux -V        # Should show tmux version

# Check port availability
lsof -i :3000  # Should be empty if port is free
```

## Installation Issues

### Package Installation Failures

#### Issue: npm install fails with permission errors

**Error Messages**:
```
EACCES: permission denied, mkdir '/usr/local/lib/node_modules'
Error: EACCES: permission denied, access '/usr/local/lib'
```

**Solutions**:
```bash
# Option 1: Use npm prefix to install globally without sudo
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
npm install -g @liamhelmer/claude-flow-ui

# Option 2: Use npx instead of global installation
npx @liamhelmer/claude-flow-ui

# Option 3: Fix npm permissions (not recommended)
sudo chown -R $(whoami) $(npm config get prefix)/{lib/node_modules,bin,share}
```

#### Issue: Node.js version incompatibility

**Error Messages**:
```
engine "node": ">=18.0.0"
Found incompatible module
```

**Solutions**:
```bash
# Install Node.js 18+ using Node Version Manager
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 18
nvm use 18

# Or update Node.js directly
# Ubuntu/Debian:
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS:
brew install node@18
```

#### Issue: Native module compilation fails

**Error Messages**:
```
gyp ERR! build error
node-gyp rebuild failed
Error compiling native addon
```

**Solutions**:
```bash
# Install build tools
# Ubuntu/Debian:
sudo apt-get install build-essential python3

# CentOS/RHEL:
sudo yum groupinstall "Development Tools"
sudo yum install python3

# macOS:
xcode-select --install

# Windows:
npm install -g windows-build-tools

# Clear npm cache and reinstall
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

## Server Startup Problems

### Port Already in Use

**Error Messages**:
```
Error: listen EADDRINUSE :::3000
Port 3000 is already in use
```

**Solutions**:
```bash
# Find what's using the port
lsof -ti:3000
sudo lsof -i :3000

# Kill process using the port
sudo kill -9 $(lsof -ti:3000)

# Use a different port
claude-flow-ui --port 8080
PORT=8080 claude-flow-ui

# Check for conflicting services
sudo systemctl status apache2   # Apache
sudo systemctl status nginx     # Nginx
sudo systemctl status httpd     # HTTP daemon
```

### Server Crashes on Startup

**Error Messages**:
```
Segmentation fault (core dumped)
Process exited with code 139
Cannot read property of undefined
```

**Solutions**:
```bash
# Enable debug mode for more information
DEBUG=* claude-flow-ui

# Check for conflicting environment variables
env | grep -i claude
env | grep -i port

# Run with minimal configuration
claude-flow-ui --port 3000 --terminal-size 80x24

# Check system resources
free -h        # Memory
df -h          # Disk space
ulimit -a      # System limits
```

### Missing Dependencies

**Error Messages**:
```
Cannot find module 'tmux'
Command 'tmux' not found
```

**Solutions**:
```bash
# Install tmux
# Ubuntu/Debian:
sudo apt-get install tmux

# CentOS/RHEL:
sudo yum install tmux

# macOS:
brew install tmux

# Verify installation
which tmux
tmux -V

# Check PATH
echo $PATH
```

## WebSocket Connection Issues

### Connection Refused

**Error Messages**:
```
WebSocket connection failed
Error: connect ECONNREFUSED
ERR_CONNECTION_REFUSED
```

**Solutions**:
```bash
# Verify server is running
curl http://localhost:3000/api/health

# Check WebSocket port (usually server port + 1)
netstat -tlnp | grep :3001

# Test WebSocket connection
wscat -c ws://localhost:3000/ws

# Check firewall settings
sudo ufw status
sudo iptables -L

# Restart server with WebSocket debugging
DEBUG=websocket,socket.io claude-flow-ui
```

### WebSocket Disconnections

**Symptoms**:
- Frequent disconnections
- Terminal becomes unresponsive
- Connection drops after idle time

**Solutions**:
```bash
# Increase heartbeat interval
WS_HEARTBEAT_INTERVAL=60000 claude-flow-ui

# Disable proxy timeout (if using nginx/apache)
# nginx.conf:
proxy_read_timeout 86400;
proxy_send_timeout 86400;

# Check network stability
ping -c 10 localhost
traceroute localhost

# Monitor WebSocket messages
DEBUG=websocket:* claude-flow-ui
```

### CORS Errors

**Error Messages**:
```
Access to XMLHttpRequest blocked by CORS policy
WebSocket connection failed: Error during WebSocket handshake
```

**Solutions**:
```bash
# Set allowed origins
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com claude-flow-ui

# Disable CORS for development (not recommended for production)
CORS_ENABLED=false claude-flow-ui

# Check browser console for specific CORS errors
# Open F12 -> Console tab
```

## Terminal Session Problems

### Session Creation Fails

**Error Messages**:
```
Failed to create terminal session
spawn ENOENT
tmux: command not found
```

**Solutions**:
```bash
# Verify tmux installation
which tmux
tmux list-sessions 2>/dev/null || echo "tmux not available"

# Check session limits
curl http://localhost:3000/api/sessions | jq length

# Increase session limit
MAX_SESSIONS=20 claude-flow-ui

# Clear zombie sessions
tmux list-sessions | grep -v attached | cut -d: -f1 | xargs -I {} tmux kill-session -t {}

# Check disk space for socket files
df -h ~/.claude-flow-ui/
```

### Terminal Not Responding

**Symptoms**:
- Terminal appears frozen
- No response to keyboard input
- Cursor not blinking

**Solutions**:
```bash
# Check if tmux session exists
tmux list-sessions

# Restart terminal session via API
curl -X DELETE http://localhost:3000/api/sessions/{sessionId}
curl -X POST http://localhost:3000/api/sessions -d '{"name":"new-session"}'

# Clear browser cache and refresh
# Chrome: Ctrl+Shift+R
# Firefox: Ctrl+F5

# Check browser console for errors
# F12 -> Console tab

# Verify WebSocket connection
# F12 -> Network tab -> WS
```

### Character Encoding Issues

**Symptoms**:
- Special characters appear as boxes
- Non-ASCII text corrupted
- Terminal colors not working

**Solutions**:
```bash
# Set correct locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Configure tmux for UTF-8
echo "set -g utf8 on" >> ~/.tmux.conf
echo "set-window-option -g utf8 on" >> ~/.tmux.conf

# Check terminal capabilities
echo $TERM
tput colors

# Test Unicode support
echo "Unicode test: 你好 🌟 ñ"
```

### Scrollback Issues

**Symptoms**:
- Cannot scroll up to see command history
- Scrollback buffer appears empty
- Lost terminal output

**Solutions**:
```bash
# Increase scrollback buffer
SCROLLBACK_LINES=5000 claude-flow-ui

# Check tmux scrollback
tmux show-options -g history-limit

# Refresh terminal history
# Send refresh-history message via WebSocket

# Clear and reset terminal
curl -X POST http://localhost:3000/api/sessions/{sessionId}/refresh

# Check browser memory usage
# Task Manager -> Memory tab
```

## Performance Issues

### High Memory Usage

**Symptoms**:
- Server using excessive RAM
- Browser tabs crashing
- System becomes unresponsive

**Solutions**:
```bash
# Monitor memory usage
watch -n 5 'ps aux | grep claude-flow-ui | head -5'

# Reduce memory usage
SCROLLBACK_LINES=1000 \
MAX_SESSIONS=10 \
claude-flow-ui

# Enable garbage collection
node --expose-gc --max-old-space-size=2048 unified-server.js

# Check for memory leaks
DEBUG=memory claude-flow-ui

# Close unused terminal sessions
# Via web interface or API
```

### High CPU Usage

**Symptoms**:
- CPU usage consistently high
- Fan noise from laptop/server
- UI becomes laggy

**Solutions**:
```bash
# Monitor CPU usage
top -p $(pgrep -f claude-flow-ui)

# Optimize settings
TERMINAL_CURSOR_BLINK=false \
WS_HEARTBEAT_INTERVAL=60000 \
claude-flow-ui

# Use clustering
CLUSTER_MODE=true WORKERS=2 claude-flow-ui

# Profile CPU usage
node --prof unified-server.js
node --prof-process isolate-*.log > profile.txt
```

### Slow Response Times

**Symptoms**:
- Delayed terminal input
- Slow page loading
- API requests timing out

**Solutions**:
```bash
# Enable compression
WS_COMPRESSION=true claude-flow-ui

# Optimize buffer sizes
WS_BUFFER_SIZE=8192 claude-flow-ui

# Use a reverse proxy
# nginx configuration for caching static assets

# Check network latency
ping localhost
curl -w "@curl-format.txt" http://localhost:3000/api/health

# Monitor event loop lag
DEBUG=performance claude-flow-ui
```

## Configuration Problems

### Environment Variables Not Working

**Symptoms**:
- Configuration changes ignored
- Default values used instead of custom ones
- Inconsistent behavior

**Solutions**:
```bash
# Verify environment variables are set
env | grep -i claude
env | grep PORT

# Check precedence (command line > env vars > config file)
claude-flow-ui --port 8080  # This overrides PORT env var

# Use dotenv file
echo "PORT=3000" > .env
echo "TERMINAL_SIZE=120x40" >> .env

# Debug configuration loading
DEBUG=config claude-flow-ui

# Verify configuration file location
ls -la ~/.claude-flow-ui/config.json
```

### Invalid Configuration Values

**Error Messages**:
```
Invalid port number
Terminal size must be in format COLSxROWS
Configuration validation failed
```

**Solutions**:
```bash
# Validate configuration
claude-flow-ui --config ./config.json --validate

# Check configuration format
# Valid: PORT=3000
# Invalid: PORT=abc

# Valid: TERMINAL_SIZE=80x24
# Invalid: TERMINAL_SIZE=80

# Reset to defaults
rm ~/.claude-flow-ui/config.json
```

### SSL/TLS Configuration Issues

**Error Messages**:
```
Error: ENOENT: no such file or directory, open 'cert.pem'
SSL handshake failed
Certificate verification failed
```

**Solutions**:
```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Set correct file permissions
chmod 600 key.pem cert.pem

# Verify certificate
openssl x509 -in cert.pem -text -noout

# Test SSL connection
curl -k https://localhost:3000/api/health

# Configure SSL properly
SSL_CERT_PATH=/path/to/cert.pem \
SSL_KEY_PATH=/path/to/key.pem \
ENABLE_HTTPS=true \
claude-flow-ui
```

## Browser Compatibility

### WebSocket Not Supported

**Error Messages**:
```
WebSocket is not defined
This browser doesn't support WebSocket
```

**Solutions**:
- Update to a modern browser (Chrome 76+, Firefox 72+, Safari 13+)
- Enable WebSocket support in browser settings
- Use a WebSocket polyfill for older browsers
- Check corporate firewall/proxy settings

### JavaScript Errors

**Error Messages**:
```
Unexpected token '?'
Promise is not defined
async/await not supported
```

**Solutions**:
```bash
# Check browser version compatibility
# Required: ES2020 support, WebSocket, Promise, async/await

# Clear browser cache
# Chrome: Settings -> Privacy -> Clear browsing data
# Firefox: Settings -> Privacy -> Clear Data

# Disable browser extensions temporarily
# Chrome: Settings -> Extensions -> Disable all
```

### Display Issues

**Symptoms**:
- Terminal text overlapping
- Incorrect colors
- Font rendering problems
- Layout broken on mobile

**Solutions**:
```css
/* Custom CSS overrides in browser console */
.terminal-container {
  font-family: 'Monaco', 'Consolas', monospace !important;
  line-height: 1.2 !important;
}

/* Check for conflicting CSS */
/* F12 -> Elements tab -> Check computed styles */
```

## Network and Firewall Issues

### Firewall Blocking Connections

**Symptoms**:
- Connection refused errors
- Timeouts when accessing from remote machines
- WebSocket connection failures

**Solutions**:
```bash
# Linux (ufw)
sudo ufw allow 3000
sudo ufw allow 3001  # WebSocket port
sudo ufw reload

# Linux (iptables)
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3001 -j ACCEPT

# macOS
# System Preferences -> Security & Privacy -> Firewall -> Options
# Add claude-flow-ui to allowed apps

# Windows
# Windows Defender Firewall -> Allow an app
# Add node.js to exceptions
```

### Proxy Configuration

**Symptoms**:
- Cannot access from behind corporate proxy
- WebSocket upgrades fail
- SSL certificate errors

**Solutions**:
```bash
# Configure npm proxy
npm config set proxy http://proxy.company.com:8080
npm config set https-proxy https://proxy.company.com:8080

# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=https://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Bypass proxy for WebSocket
# Add WebSocket upgrade headers in proxy config
```

## Error Messages and Solutions

### Common Error Codes

#### EADDRINUSE
```bash
# Port already in use
lsof -ti:3000 | xargs kill -9
# or use different port
claude-flow-ui --port 8080
```

#### ENOENT
```bash
# File or command not found
which tmux  # Check if tmux is installed
ls -la ~/.claude-flow-ui/  # Check if directory exists
```

#### EACCES
```bash
# Permission denied
sudo chown -R $(whoami) ~/.claude-flow-ui/
chmod 755 ~/.claude-flow-ui/
```

#### ECONNREFUSED
```bash
# Connection refused
# Check if server is running
ps aux | grep claude-flow-ui
# Check firewall
sudo ufw status
```

#### ETIMEDOUT
```bash
# Connection timeout
# Check network connectivity
ping localhost
# Increase timeout
WS_CONNECTION_TIMEOUT=10000 claude-flow-ui
```

### Application-Specific Errors

#### "Failed to initialize tmux"
```bash
# Check tmux installation
which tmux && tmux -V

# Check permissions on tmux socket directory
ls -la /tmp/tmux-*/

# Clear old tmux sessions
tmux list-sessions | xargs -I {} tmux kill-session -t {}
```

#### "WebSocket handshake failed"
```bash
# Check WebSocket upgrade headers
curl -i -N -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: test" \
     http://localhost:3000/ws
```

#### "Terminal session limit exceeded"
```bash
# Increase session limit
MAX_SESSIONS=50 claude-flow-ui

# Clean up old sessions
curl http://localhost:3000/api/sessions | \
  jq -r '.[] | select(.isActive == false) | .id' | \
  xargs -I {} curl -X DELETE http://localhost:3000/api/sessions/{}
```

## Debugging Tools

### Server-Side Debugging

```bash
# Enable debug logging
DEBUG=* claude-flow-ui

# Specific debug categories
DEBUG=websocket,terminal,session claude-flow-ui

# Node.js inspector
node --inspect unified-server.js
# Open chrome://inspect in Chrome

# Memory profiling
node --inspect --expose-gc unified-server.js

# CPU profiling
node --prof unified-server.js
```

### Client-Side Debugging

```javascript
// Browser console debugging
// F12 -> Console

// Check WebSocket connection
const ws = new WebSocket('ws://localhost:3000/ws');
ws.onopen = () => console.log('Connected');
ws.onerror = (e) => console.error('WebSocket error:', e);
ws.onmessage = (e) => console.log('Message:', e.data);

// Monitor performance
console.time('page-load');
// ... after page loads
console.timeEnd('page-load');

// Memory usage (Chrome only)
if (performance.memory) {
  console.log('Memory usage:', {
    used: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024) + 'MB',
    total: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024) + 'MB'
  });
}
```

### Network Debugging

```bash
# Monitor network traffic
sudo tcpdump -i lo port 3000

# Test WebSocket with wscat
npm install -g wscat
wscat -c ws://localhost:3000/ws

# HTTP debugging with curl
curl -v http://localhost:3000/api/health
curl -v -H "Upgrade: websocket" http://localhost:3000/ws

# Network latency testing
ping -c 10 localhost
traceroute localhost
```

### Log Analysis

```bash
# View server logs
tail -f ~/.claude-flow-ui/logs/server.log

# Search for specific errors
grep -i error ~/.claude-flow-ui/logs/*.log
grep -i "websocket" ~/.claude-flow-ui/logs/*.log

# Log rotation and cleanup
find ~/.claude-flow-ui/logs/ -name "*.log" -mtime +7 -delete

# Real-time log monitoring
tail -f ~/.claude-flow-ui/logs/server.log | grep -E "(ERROR|WARN|Failed)"
```

## Getting Help

### Information to Collect

Before reporting issues, collect this information:

```bash
#!/bin/bash
# diagnostic-info.sh

echo "=== System Information ==="
uname -a
node --version
npm --version
tmux -V

echo "=== Claude Flow UI Status ==="
claude-flow-ui --version
ps aux | grep claude-flow-ui

echo "=== Network Status ==="
netstat -tlnp | grep :3000
lsof -i :3000

echo "=== Configuration ==="
env | grep -E "(PORT|TERMINAL|CLAUDE|WS_)" | sort

echo "=== Recent Logs ==="
tail -20 ~/.claude-flow-ui/logs/server.log 2>/dev/null || echo "No logs found"

echo "=== Resource Usage ==="
free -h
df -h
```

### Support Channels

1. **GitHub Issues**: [Report bugs and request features](https://github.com/liamhelmer/claude-flow-ui/issues)
2. **Documentation**: Check the `/docs` folder for detailed guides
3. **Community Discussions**: Join GitHub Discussions for questions
4. **Stack Overflow**: Tag questions with `claude-flow-ui`

### Creating Bug Reports

Include in your bug report:
- System information (OS, Node.js version, browser)
- Steps to reproduce the issue
- Expected vs actual behavior
- Error messages and logs
- Configuration (environment variables, config files)
- Screenshots (if applicable)

### Emergency Recovery

If the system is completely broken:

```bash
# Kill all processes
pkill -f claude-flow-ui

# Clean up temporary files
rm -rf ~/.claude-flow-ui/temp/
rm -rf ~/.claude-flow-ui/sockets/

# Reset configuration
mv ~/.claude-flow-ui/config.json ~/.claude-flow-ui/config.json.backup

# Reinstall package
npm uninstall -g @liamhelmer/claude-flow-ui
npm install -g @liamhelmer/claude-flow-ui

# Start with minimal configuration
claude-flow-ui --port 3000 --terminal-size 80x24
```

This troubleshooting guide covers the most common issues and their solutions. For complex problems or issues not covered here, please consult the support channels listed above.