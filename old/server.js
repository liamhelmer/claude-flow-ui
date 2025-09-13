#!/usr/bin/env node

const { spawn } = require('child_process');
const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const net = require('net');
const path = require('path');

const DEFAULT_PORT = 11235;
const DEFAULT_WS_PORT = 11236; // WebSocket port is UI port + 1

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  let port = DEFAULT_PORT;
  let terminalSize = null;
  let claudeFlowArgs = [];
  
  console.log('Raw arguments:', args);
  
  // Parse server arguments before --claude-flow-args
  let serverArgs = args;
  const claudeFlowIndex = args.indexOf('--claude-flow-args');
  if (claudeFlowIndex !== -1) {
    serverArgs = args.slice(0, claudeFlowIndex);
    claudeFlowArgs = args.slice(claudeFlowIndex + 1);
  }
  
  // Parse server-specific arguments
  for (let i = 0; i < serverArgs.length; i++) {
    const arg = serverArgs[i];
    
    if (arg === '--port' && i + 1 < serverArgs.length) {
      const portValue = parseInt(serverArgs[i + 1], 10);
      if (isNaN(portValue)) {
        console.error('Error: --port requires a number');
        process.exit(1);
      }
      port = portValue;
      i++; // Skip next argument since we used it
    } else if (arg === '--terminal-size' && i + 1 < serverArgs.length) {
      terminalSize = serverArgs[i + 1];
      i++; // Skip next argument since we used it
    }
  }
  
  // If no explicit --claude-flow-args and no server args parsed, treat remaining as claude-flow args
  if (claudeFlowIndex === -1 && serverArgs.length === args.length) {
    // Check if any server args were found
    let serverArgsFound = false;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--port' || args[i] === '--terminal-size') {
        serverArgsFound = true;
        break;
      }
    }
    
    // If no server args found, treat all as claude-flow args (backward compatibility)
    if (!serverArgsFound) {
      claudeFlowArgs = args;
    }
  }
  
  console.log('Parsed - UI Port:', port, 'Terminal Size:', terminalSize, 'Claude-flow args:', claudeFlowArgs);
  
  return { port, terminalSize, claudeFlowArgs };
}

// Check if a port is available
function checkPort(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        resolve(false);
      } else {
        resolve(false);
      }
    });
    
    server.once('listening', () => {
      server.close();
      resolve(true);
    });
    
    server.listen(port);
  });
}

// Find next available port
async function findAvailablePort(startPort) {
  let port = startPort;
  let attempts = 0;
  const maxAttempts = 100; // Prevent infinite loop
  
  while (attempts < maxAttempts) {
    if (await checkPort(port)) {
      return port;
    }
    console.log(`Port ${port} is in use, trying ${port + 1}...`);
    port++;
    attempts++;
  }
  
  throw new Error(`Could not find an available port after ${maxAttempts} attempts`);
}

// Start WebSocket server
function startWebSocketServer(port, claudeFlowArgs = [], workingDir, terminalSize = null) {
  console.log(`🔌 Starting WebSocket server on port ${port}...`);
  console.log(`📂 Working directory: ${workingDir}`);
  if (terminalSize) {
    console.log(`🖥️  Terminal size: ${terminalSize}`);
  }
  
  const wsArgs = [
    path.join(__dirname, 'websocket-server.js'), 
    '--port', port.toString(),
    '--cwd', workingDir  // Pass working directory explicitly
  ];
  
  // Add terminal size if specified
  if (terminalSize) {
    wsArgs.push('--terminal-size', terminalSize);
  }
  
  // Add claude-flow arguments last
  if (claudeFlowArgs && claudeFlowArgs.length > 0) {
    wsArgs.push('--claude-flow-args', ...claudeFlowArgs);
  }
  
  const wsServer = spawn('node', wsArgs, {
    stdio: 'pipe',
    shell: false,
    cwd: __dirname,  // Run from script directory
    env: process.env  // Pass environment variables
  });
  
  wsServer.stdout.on('data', (data) => {
    const output = data.toString().trim();
    if (output && !output.includes('═══')) {
      console.log(`[WS] ${output}`);
    }
  });
  
  wsServer.stderr.on('data', (data) => {
    console.error(`[WS Error] ${data.toString().trim()}`);
  });
  
  wsServer.on('error', (err) => {
    console.error('❌ Failed to start WebSocket server:', err.message);
  });
  
  wsServer.on('exit', (code, signal) => {
    console.log(`💀 WebSocket server exited (code: ${code}, signal: ${signal})`);
    
    // Determine exit reason
    let exitReason = 'unknown';
    if (signal === 'SIGTERM' || signal === 'SIGINT') {
      exitReason = 'WebSocket server was terminated by signal';
    } else if (code === 0) {
      exitReason = 'WebSocket server exited cleanly (tmux terminated or command completed)';
    } else {
      exitReason = 'WebSocket server terminated unexpectedly';
    }
    
    console.log(`🛑 ${exitReason}. Shutting down entire application...`);
    
    // Shutdown the web server first
    if (globalServer) {
      console.log('🌐 Closing web server...');
      globalServer.close(() => {
        console.log('✅ Web server closed');
        process.exit(code || 0);
      });
      
      // Force exit after 3 seconds if server doesn't close
      setTimeout(() => {
        console.error('⚠️  Forced shutdown after timeout');
        process.exit(code || 1);
      }, 3000);
    } else {
      // No server to close, just exit
      process.exit(code || 0);
    }
  });
  
  return wsServer;
}

// Note: claude-flow is now started by the WebSocket server as a PTY process
// This provides better integration with the terminal UI

// Global references for cleanup
let globalServer = null;
let globalWsServer = null;

// Main function
async function main() {
  const { port: requestedPort, terminalSize, claudeFlowArgs } = parseArgs();
  
  // Capture the actual working directory before npm changes it
  const workingDir = process.env.INIT_CWD || process.cwd();
  
  // Find available port
  let port = requestedPort;
  if (await checkPort(requestedPort)) {
    console.log(`✅ Port ${requestedPort} is available`);
  } else {
    console.log(`⚠️  Port ${requestedPort} is in use`);
    port = await findAvailablePort(requestedPort);
    console.log(`✅ Using port ${port} instead`);
  }
  
  // Set WebSocket port to UI port + 1
  const wsPort = port === DEFAULT_PORT ? DEFAULT_WS_PORT : port + 1;
  process.env.NEXT_PUBLIC_WS_PORT = wsPort.toString();
  process.env.NEXT_PUBLIC_WS_URL = `ws://localhost:${wsPort}`;
  console.log(`🔌 WebSocket will use port ${wsPort}`);
  
  // Start WebSocket server with claude-flow args, working directory, and terminal size
  const wsServer = startWebSocketServer(wsPort, claudeFlowArgs, workingDir, terminalSize);
  globalWsServer = wsServer; // Store reference for cleanup
  
  // Wait a moment for WebSocket server to start
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Don't start claude-flow separately - the WebSocket server will handle it
  // const claudeFlowProcess = startClaudeFlow(claudeFlowArgs);
  
  // Start Next.js server
  const dev = process.env.NODE_ENV !== 'production';
  const hostname = 'localhost';
  const app = next({ dev, hostname, port });
  const handle = app.getRequestHandler();
  
  await app.prepare();
  
  const server = createServer(async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true);
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('Error occurred handling', req.url, err);
      res.statusCode = 500;
      res.end('internal server error');
    }
  });
  
  server.once('error', (err) => {
    console.error('❌ Server error:', err);
    process.exit(1);
  });
  
  globalServer = server; // Store reference for cleanup
  
  server.listen(port, () => {
    console.log('');
    console.log('🐝 Claude Flow UI Server Started');
    console.log('═══════════════════════════════════════════');
    console.log(`📍 UI:        http://localhost:${port}`);
    console.log(`🔌 WebSocket: ws://localhost:${wsPort}`);
    console.log(`📍 Network:   http://${getNetworkAddress()}:${port}`);
    console.log('═══════════════════════════════════════════');
    console.log('');
    
    if (claudeFlowArgs.length > 0) {
      console.log('Claude Flow Arguments:', claudeFlowArgs.join(' '));
    } else {
      console.log('Running UI in standalone mode (no claude-flow process)');
    }
    
    console.log('');
    console.log('Press Ctrl+C to stop');
  });
  
  // Handle graceful shutdown
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  
  function shutdown() {
    console.log('\n🛑 Shutting down all servers...');
    
    // Kill WebSocket server first (this will trigger its exit handler)
    if (globalWsServer && !globalWsServer.killed) {
      console.log('🔌 Stopping WebSocket server...');
      globalWsServer.kill('SIGTERM');
      globalWsServer = null;
    }
    
    // Close web server
    if (globalServer) {
      console.log('🌐 Closing web server...');
      globalServer.close(() => {
        console.log('✅ Web server closed');
        process.exit(0);
      });
      globalServer = null;
    }
    
    // Force exit after 5 seconds
    setTimeout(() => {
      console.error('⚠️  Forced shutdown after timeout');
      process.exit(1);
    }, 5000);
  }
}

// Get network address
function getNetworkAddress() {
  const { networkInterfaces } = require('os');
  const nets = networkInterfaces();
  
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      // Skip internal and non-IPv4 addresses
      if (!net.internal && net.family === 'IPv4') {
        return net.address;
      }
    }
  }
  return 'localhost';
}

// Run the server
main().catch((err) => {
  console.error('❌ Fatal error:', err);
  process.exit(1);
});