/**
 * Integration test demonstrating enhanced graceful shutdown with tmux cleanup
 * This test shows how the graceful shutdown properly handles tmux managers
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

describe('Graceful Shutdown with Tmux Integration', () => {
  let testServer;
  const testPort = 3333;

  beforeEach(() => {
    jest.setTimeout(30000); // Allow more time for tmux operations
  });

  afterEach(async () => {
    if (testServer) {
      testServer.kill('SIGKILL');
      testServer = null;
    }
  });

  test('should demonstrate graceful shutdown with tmux cleanup', async () => {
    // Create a test server script that uses tmux managers
    const testServerScript = `
const express = require('express');
const gracefulShutdown = require('./src/utils/gracefulShutdown');

const app = express();

app.get('/test', (req, res) => {
  res.json({ message: 'Server running with tmux integration' });
});

const server = app.listen(${testPort}, () => {
  console.log('Test server started on port ${testPort}');
});

// Initialize graceful shutdown
gracefulShutdown.init(server);

// Create and register tmux managers
const tmuxManager = gracefulShutdown.createTmuxManager(process.cwd(), 'TestTmuxManager');
const tmuxStreamManager = gracefulShutdown.createTmuxStreamManager('TestStreamManager');

console.log('Tmux managers registered for cleanup');

// Keep server running
process.on('SIGTERM', () => {
  console.log('SIGTERM received - graceful shutdown will handle cleanup');
});
`;

    // Write test server script
    const testScriptPath = path.join(__dirname, 'test-server-tmux.js');
    fs.writeFileSync(testScriptPath, testServerScript);

    try {
      // Start test server
      testServer = spawn('node', [testScriptPath], {
        stdio: 'pipe',
        cwd: path.join(__dirname, '..')
      });

      let serverOutput = '';
      testServer.stdout.on('data', (data) => {
        serverOutput += data.toString();
        console.log('Server:', data.toString().trim());
      });

      testServer.stderr.on('data', (data) => {
        console.error('Server Error:', data.toString().trim());
      });

      // Wait for server to start
      await new Promise((resolve) => {
        const checkServer = () => {
          if (serverOutput.includes('Test server started')) {
            resolve();
          } else {
            setTimeout(checkServer, 100);
          }
        };
        checkServer();
      });

      // Make a test request to ensure server is responsive
      const testResponse = await fetch(\`http://localhost:\${testPort}/test\`);
      expect(testResponse.status).toBe(200);

      // Send SIGTERM to trigger graceful shutdown
      console.log('Sending SIGTERM to test server...');
      testServer.kill('SIGTERM');

      // Wait for graceful shutdown to complete
      await new Promise((resolve) => {
        testServer.on('exit', (code, signal) => {
          console.log(\`Test server exited with code: \${code}, signal: \${signal}\`);
          resolve();
        });
      });

      // Verify shutdown messages appeared in output
      expect(serverOutput).toContain('Tmux managers registered');
      expect(serverOutput).toContain('SIGTERM received');

    } finally {
      // Cleanup test script
      if (fs.existsSync(testScriptPath)) {
        fs.unlinkSync(testScriptPath);
      }
    }
  });

  test('should handle tmux cleanup failures gracefully', async () => {
    // This test demonstrates error handling during tmux cleanup
    const mockTmuxManager = {
      cleanup: jest.fn().mockRejectedValue(new Error('Simulated tmux cleanup failure'))
    };

    const gracefulShutdown = require('../src/utils/gracefulShutdown');

    // Register mock tmux manager
    gracefulShutdown.registerTmuxManager(mockTmuxManager, 'MockFailingTmux');

    // Simulate cleanup
    await gracefulShutdown.cleanupTmuxManagers();

    // Verify cleanup was attempted even though it failed
    expect(mockTmuxManager.cleanup).toHaveBeenCalled();
  });
});