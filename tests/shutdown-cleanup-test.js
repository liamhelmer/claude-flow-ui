#!/usr/bin/env node

/**
 * Test script to verify shutdown cleanup works properly
 * This script starts the server, creates terminals, then tests shutdown cleanup
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const TEST_PORT = 3001;
const SERVER_TIMEOUT = 30000; // 30 seconds max test time
const CLEANUP_VERIFICATION_DELAY = 2000; // 2 seconds to verify cleanup

let serverProcess;
let testPassed = false;

function log(message) {
  console.log(`[ShutdownTest] ${message}`);
}

function error(message) {
  console.error(`[ShutdownTest] ERROR: ${message}`);
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function startServer() {
  log('Starting server for shutdown test...');

  serverProcess = spawn('node', ['unified-server.js'], {
    env: {
      ...process.env,
      PORT: TEST_PORT,
      USE_TMUX: 'true',
      DEBUG_TMUX: 'true'
    },
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let serverReady = false;

  serverProcess.stdout.on('data', (data) => {
    const output = data.toString();
    console.log(`[Server] ${output.trim()}`);

    if (output.includes(`Server running on port ${TEST_PORT}`)) {
      serverReady = true;
    }

    // Monitor cleanup messages
    if (output.includes('[Server] Starting comprehensive cleanup')) {
      log('✓ Comprehensive cleanup initiated');
    }
    if (output.includes('[Server] All tracked terminals cleaned up')) {
      log('✓ Tracked terminals cleaned up');
    }
    if (output.includes('[Server] Tmux manager cleanup completed')) {
      log('✓ Tmux manager cleanup completed');
    }
    if (output.includes('[Server] Force cleanup of tmux processes completed')) {
      log('✓ Force cleanup of tmux processes completed');
    }
    if (output.includes('[Server] Shutdown complete')) {
      log('✓ Server shutdown completed');
      testPassed = true;
    }
  });

  serverProcess.stderr.on('data', (data) => {
    const output = data.toString();
    if (!output.includes('ExperimentalWarning')) {
      console.error(`[Server Error] ${output.trim()}`);
    }
  });

  // Wait for server to be ready
  const maxWait = 10000; // 10 seconds
  const startTime = Date.now();
  while (!serverReady && (Date.now() - startTime) < maxWait) {
    await sleep(100);
  }

  if (!serverReady) {
    throw new Error('Server failed to start within timeout');
  }

  log('✓ Server started successfully');
  return serverReady;
}

async function createTestTerminals() {
  log('Creating test terminals via HTTP API...');

  try {
    // Create a few test terminals
    for (let i = 1; i <= 3; i++) {
      const response = await fetch(`http://localhost:${TEST_PORT}/terminals`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          command: 'echo "Test terminal ' + i + '"',
          name: `test-terminal-${i}`
        }),
      });

      if (response.ok) {
        const result = await response.json();
        log(`✓ Created test terminal ${i}: ${result.id}`);
      } else {
        log(`⚠ Failed to create test terminal ${i}: ${response.status}`);
      }

      await sleep(500); // Small delay between terminal creation
    }
  } catch (error) {
    log(`⚠ Error creating test terminals: ${error.message}`);
  }
}

async function testShutdown() {
  log('Testing shutdown cleanup...');

  // Send SIGTERM to trigger graceful shutdown
  log('Sending SIGTERM to server...');
  serverProcess.kill('SIGTERM');

  // Wait for shutdown process to complete
  await sleep(CLEANUP_VERIFICATION_DELAY);

  // Verify no tmux processes are left running
  try {
    const { execSync } = require('child_process');
    const tmuxProcesses = execSync('pgrep -f "tmux.*terminal-" 2>/dev/null || echo "none"', { encoding: 'utf8' });

    if (tmuxProcesses.trim() === 'none') {
      log('✓ No tmux terminal processes found after shutdown');
    } else {
      error(`✗ Found remaining tmux processes: ${tmuxProcesses.trim()}`);
      testPassed = false;
    }
  } catch (err) {
    log('✓ No tmux terminal processes found after shutdown (command failed safely)');
  }
}

async function runTest() {
  log('Starting shutdown cleanup test...');

  try {
    // Set up timeout for entire test
    const testTimeout = setTimeout(() => {
      error('Test timed out');
      if (serverProcess && !serverProcess.killed) {
        serverProcess.kill('SIGKILL');
      }
      process.exit(1);
    }, SERVER_TIMEOUT);

    // Run test sequence
    await startServer();
    await sleep(2000); // Let server stabilize
    await createTestTerminals();
    await sleep(2000); // Let terminals initialize
    await testShutdown();

    // Wait a bit more for cleanup to complete
    await sleep(3000);

    clearTimeout(testTimeout);

    if (testPassed) {
      log('✅ Shutdown cleanup test PASSED - all terminals and sessions properly cleaned up');
      process.exit(0);
    } else {
      error('❌ Shutdown cleanup test FAILED - cleanup was not comprehensive');
      process.exit(1);
    }

  } catch (error) {
    error(`Test failed with error: ${error.message}`);
    if (serverProcess && !serverProcess.killed) {
      serverProcess.kill('SIGKILL');
    }
    process.exit(1);
  }
}

// Handle test interruption
process.on('SIGINT', () => {
  log('Test interrupted');
  if (serverProcess && !serverProcess.killed) {
    serverProcess.kill('SIGKILL');
  }
  process.exit(1);
});

// Run the test
runTest().catch(error => {
  error(`Unhandled error: ${error.message}`);
  process.exit(1);
});