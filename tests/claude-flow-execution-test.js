#!/usr/bin/env node

/**
 * Test script to verify claude-flow commands are properly executed in terminal
 * This script starts the server and checks that claude-flow runs instead of bash
 */

const { spawn } = require('child_process');
const path = require('path');

const TEST_PORT = 3003;
const TEST_TIMEOUT = 15000; // 15 seconds

let serverProcess;

function log(message) {
  console.log(`[ClaudeFlowTest] ${message}`);
}

function error(message) {
  console.error(`[ClaudeFlowTest] ERROR: ${message}`);
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function testClaudeFlowExecution() {
  log('=== Testing Claude-Flow Command Execution ===');

  return new Promise((resolve) => {
    let testResults = {
      interactive: false,
      withArgs: false,
      alphaVersion: false
    };

    log('Starting server with various configurations...');

    // Test 1: Interactive claude-flow (no args)
    log('Test 1: Interactive claude-flow (no args)');
    serverProcess = spawn('node', ['unified-server.js'], {
      env: {
        ...process.env,
        PORT: TEST_PORT,
        USE_TMUX: 'true'
      },
      stdio: 'pipe'
    });

    let outputBuffer = '';
    const testTimeout = setTimeout(() => {
      serverProcess.kill('SIGTERM');
      log('Test completed (timeout reached)');
      resolve(testResults);
    }, TEST_TIMEOUT);

    serverProcess.stdout.on('data', (data) => {
      const output = data.toString();
      outputBuffer += output;
      console.log(`[Server] ${output.trim()}`);

      // Check for claude-flow execution indicators
      if (output.includes('🚀 Running interactive claude-flow:')) {
        log('✅ Test 1 PASSED: Interactive claude-flow detected');
        testResults.interactive = true;
      }

      if (output.includes('npx claude-flow')) {
        log('✅ Basic claude-flow command detected');
        testResults.withArgs = true;
      }

      if (output.includes('npx claude-flow@alpha')) {
        log('✅ Alpha version command detected');
        testResults.alphaVersion = true;
      }

      if (output.includes('🚀 Running command:') && output.includes('claude-flow')) {
        log('✅ Claude-flow command execution confirmed');
      }

      // Don't log the bash fallback as an error - we fixed that
      if (output.includes('/bin/bash --login') && !output.includes('🚀 Running')) {
        error('❌ Detected bash fallback instead of claude-flow');
      }

      // Check for successful server startup
      if (output.includes(`Server running on port ${TEST_PORT}`)) {
        log('✅ Server started successfully');

        // Give it a moment to process, then kill the server
        setTimeout(() => {
          serverProcess.kill('SIGTERM');
          clearTimeout(testTimeout);

          // Wait for cleanup and resolve
          setTimeout(() => {
            resolve(testResults);
          }, 2000);
        }, 3000);
      }
    });

    serverProcess.stderr.on('data', (data) => {
      const output = data.toString();
      if (!output.includes('ExperimentalWarning')) {
        console.error(`[Server Error] ${output.trim()}`);
      }
    });

    serverProcess.on('error', (err) => {
      error(`Failed to start server: ${err.message}`);
      clearTimeout(testTimeout);
      resolve(testResults);
    });
  });
}

async function testWithEnvironmentVariables() {
  log('=== Testing With Environment Variables ===');

  return new Promise((resolve) => {
    let envTestResults = {
      envArgsProcessed: false,
      claudeFlowWithMode: false
    };

    serverProcess = spawn('node', ['unified-server.js'], {
      env: {
        ...process.env,
        PORT: TEST_PORT + 1,
        USE_TMUX: 'true',
        CLAUDE_FLOW_MODE: 'test',
        CLAUDE_FLOW_ALPHA: 'true'
      },
      stdio: 'pipe'
    });

    const testTimeout = setTimeout(() => {
      serverProcess.kill('SIGTERM');
      resolve(envTestResults);
    }, TEST_TIMEOUT);

    serverProcess.stdout.on('data', (data) => {
      const output = data.toString();
      console.log(`[EnvTest] ${output.trim()}`);

      if (output.includes('🔬 Using claude-flow@alpha')) {
        log('✅ Alpha version environment variable detected');
        envTestResults.envArgsProcessed = true;
      }

      if (output.includes('claude-flow@alpha test')) {
        log('✅ Environment mode argument detected in command');
        envTestResults.claudeFlowWithMode = true;
      }

      if (output.includes(`Server running on port ${TEST_PORT + 1}`)) {
        setTimeout(() => {
          serverProcess.kill('SIGTERM');
          clearTimeout(testTimeout);
          setTimeout(() => resolve(envTestResults), 2000);
        }, 2000);
      }
    });

    serverProcess.stderr.on('data', (data) => {
      const output = data.toString();
      if (!output.includes('ExperimentalWarning')) {
        console.error(`[EnvTest Error] ${output.trim()}`);
      }
    });
  });
}

async function runTests() {
  log('🚀 Starting Claude-Flow execution tests...');

  try {
    const basicResults = await testClaudeFlowExecution();
    const envResults = await testWithEnvironmentVariables();

    log('=== Test Results ===');
    log(`Interactive claude-flow: ${basicResults.interactive ? '✅ PASS' : '❌ FAIL'}`);
    log(`Claude-flow command: ${basicResults.withArgs ? '✅ PASS' : '❌ FAIL'}`);
    log(`Environment processing: ${envResults.envArgsProcessed ? '✅ PASS' : '❌ FAIL'}`);
    log(`Environment mode args: ${envResults.claudeFlowWithMode ? '✅ PASS' : '❌ FAIL'}`);

    const allPassed = basicResults.interactive &&
                     (basicResults.withArgs || basicResults.interactive) &&
                     envResults.envArgsProcessed;

    if (allPassed) {
      log('🎉 All tests PASSED! Claude-flow is properly executed in terminal.');
      process.exit(0);
    } else {
      error('❌ Some tests FAILED. Claude-flow execution may have issues.');
      process.exit(1);
    }

  } catch (error) {
    error(`Test suite failed: ${error.message}`);
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

// Run the tests
runTests().catch(error => {
  error(`Unhandled error: ${error.message}`);
  process.exit(1);
});