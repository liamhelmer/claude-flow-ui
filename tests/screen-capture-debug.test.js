#!/usr/bin/env node

/**
 * Screen Capture Debug Test Suite
 * 
 * This test suite is specifically designed to debug and fix the 
 * "Failed to capture screen: 1" error occurring in tmux capture operations.
 * 
 * The error originates from tmux capture-pane commands in:
 * - src/lib/tmux-stream-manager.js (line 333)
 * - src/lib/tmux-manager.js (line 337, 370)
 * 
 * Root Cause Analysis:
 * 1. tmux capture-pane returns exit code 1 when:
 *    - Session doesn't exist
 *    - Invalid session name or target
 *    - Permission issues with socket
 *    - Pane has no content or is empty
 *    - Socket path is too long or inaccessible
 */

const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const assert = require('assert');

class ScreenCaptureDebugger {
  constructor() {
    this.testResults = [];
    this.sessionName = `test-debug-${Date.now()}`;
    this.socketPath = path.join(os.tmpdir(), `${this.sessionName}.sock`);
  }

  /**
   * Log test results
   */
  log(message, success = true) {
    const result = { message, success, timestamp: new Date().toISOString() };
    this.testResults.push(result);
    console.log(`${success ? '✅' : '❌'} ${message}`);
    return result;
  }

  /**
   * Test 1: Basic tmux availability and version
   */
  async testTmuxAvailability() {
    console.log('\n🔍 Test 1: Basic tmux availability and version');
    
    return new Promise((resolve) => {
      exec('tmux -V', (error, stdout, stderr) => {
        if (error) {
          this.log(`tmux not available: ${error.message}`, false);
          resolve(false);
        } else {
          this.log(`tmux available: ${stdout.trim()}`);
          resolve(true);
        }
      });
    });
  }

  /**
   * Test 2: Create a test tmux session
   */
  async testSessionCreation() {
    console.log('\n🔍 Test 2: Create a test tmux session');
    
    return new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'new-session',
        '-d',
        '-s', this.sessionName,
        '-x', '80',
        '-y', '24'
      ]);

      tmux.on('exit', (code) => {
        if (code === 0) {
          this.log(`Session created successfully: ${this.sessionName}`);
          resolve(true);
        } else {
          this.log(`Failed to create session (code: ${code})`, false);
          resolve(false);
        }
      });

      tmux.on('error', (err) => {
        this.log(`Session creation error: ${err.message}`, false);
        reject(err);
      });
    });
  }

  /**
   * Test 3: Test basic capture-pane command
   */
  async testBasicCapture() {
    console.log('\n🔍 Test 3: Test basic capture-pane command');
    
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'capture-pane',
        '-t', this.sessionName,
        '-p'
      ], { stdio: 'pipe' });

      let output = '';
      let error = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        error += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          this.log(`Basic capture successful, output length: ${output.length}`);
          this.log(`Output preview: ${JSON.stringify(output.slice(0, 100))}`);
          resolve(true);
        } else {
          this.log(`Basic capture failed (code: ${code}): ${error}`, false);
          resolve(false);
        }
      });

      tmux.on('error', (err) => {
        this.log(`Basic capture error: ${err.message}`, false);
        resolve(false);
      });
    });
  }

  /**
   * Test 4: Test capture with escape sequences (-e flag)
   */
  async testCaptureWithEscapes() {
    console.log('\n🔍 Test 4: Test capture with escape sequences (-e flag)');
    
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'capture-pane',
        '-t', this.sessionName,
        '-e',  // Include escape sequences
        '-p'
      ], { stdio: 'pipe' });

      let output = '';
      let error = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        error += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          this.log(`Capture with escapes successful, output length: ${output.length}`);
          resolve(true);
        } else {
          this.log(`Capture with escapes failed (code: ${code}): ${error}`, false);
          resolve(false);
        }
      });

      tmux.on('error', (err) => {
        this.log(`Capture with escapes error: ${err.message}`, false);
        resolve(false);
      });
    });
  }

  /**
   * Test 5: Test full history capture (-S - -E -)
   */
  async testFullHistoryCapture() {
    console.log('\n🔍 Test 5: Test full history capture (-S - -E -)');
    
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'capture-pane',
        '-t', this.sessionName,
        '-S', '-',    // Start from beginning of history
        '-E', '-',    // End at end of history
        '-e',         // Include escape sequences
        '-p'          // Print to stdout
      ], { stdio: 'pipe' });

      let output = '';
      let error = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        error += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          this.log(`Full history capture successful, output length: ${output.length}`);
          resolve(true);
        } else {
          this.log(`Full history capture failed (code: ${code}): ${error}`, false);
          resolve(false);
        }
      });

      tmux.on('error', (err) => {
        this.log(`Full history capture error: ${err.message}`, false);
        resolve(false);
      });
    });
  }

  /**
   * Test 6: Test session existence check
   */
  async testSessionExists() {
    console.log('\n🔍 Test 6: Test session existence check');
    
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'has-session',
        '-t', this.sessionName
      ]);

      tmux.on('exit', (code) => {
        if (code === 0) {
          this.log(`Session exists check passed`);
          resolve(true);
        } else {
          this.log(`Session exists check failed (code: ${code})`, false);
          resolve(false);
        }
      });

      tmux.on('error', (err) => {
        this.log(`Session exists error: ${err.message}`, false);
        resolve(false);
      });
    });
  }

  /**
   * Test 7: Add content to session and test capture
   */
  async testCaptureWithContent() {
    console.log('\n🔍 Test 7: Add content to session and test capture');
    
    // Send some content to the session
    await new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'send-keys',
        '-t', this.sessionName,
        'echo "Test content for capture"',
        'Enter'
      ]);

      tmux.on('exit', () => {
        resolve();
      });
    });

    // Wait a moment for the command to execute
    await new Promise(resolve => setTimeout(resolve, 500));

    // Now try to capture
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'capture-pane',
        '-t', this.sessionName,
        '-e',
        '-p'
      ], { stdio: 'pipe' });

      let output = '';
      let error = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        error += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          this.log(`Capture with content successful, found test string: ${output.includes('Test content for capture')}`);
          this.log(`Full output preview: ${JSON.stringify(output.slice(0, 200))}`);
          resolve(true);
        } else {
          this.log(`Capture with content failed (code: ${code}): ${error}`, false);
          resolve(false);
        }
      });

      tmux.on('error', (err) => {
        this.log(`Capture with content error: ${err.message}`, false);
        resolve(false);
      });
    });
  }

  /**
   * Test 8: Test socket permissions and accessibility
   */
  async testSocketPermissions() {
    console.log('\n🔍 Test 8: Test socket permissions and accessibility');
    
    try {
      const stats = fs.statSync(this.socketPath);
      this.log(`Socket exists with permissions: ${stats.mode.toString(8)}`);
      
      // Check if socket is accessible
      fs.accessSync(this.socketPath, fs.constants.R_OK | fs.constants.W_OK);
      this.log(`Socket is readable and writable`);
      
      return true;
    } catch (err) {
      this.log(`Socket access error: ${err.message}`, false);
      return false;
    }
  }

  /**
   * Test 9: Test path length issues
   */
  async testPathLength() {
    console.log('\n🔍 Test 9: Test path length issues');
    
    const pathLength = this.socketPath.length;
    this.log(`Socket path length: ${pathLength} characters`);
    
    // Unix domain socket path limit is typically around 108 characters
    if (pathLength > 100) {
      this.log(`Warning: Socket path may be too long (${pathLength} > 100)`, false);
      return false;
    } else {
      this.log(`Socket path length is acceptable`);
      return true;
    }
  }

  /**
   * Test 10: Test alternative capture methods
   */
  async testAlternativeCaptures() {
    console.log('\n🔍 Test 10: Test alternative capture methods');
    
    const methods = [
      {
        name: 'capture-pane only',
        args: ['-S', this.socketPath, 'capture-pane', '-t', this.sessionName, '-p']
      },
      {
        name: 'capture-pane with -S 0',
        args: ['-S', this.socketPath, 'capture-pane', '-t', this.sessionName, '-S', '0', '-p']
      },
      {
        name: 'capture-pane with -E -1',
        args: ['-S', this.socketPath, 'capture-pane', '-t', this.sessionName, '-E', '-1', '-p']
      }
    ];

    let successCount = 0;
    
    for (const method of methods) {
      const success = await new Promise((resolve) => {
        const tmux = spawn('tmux', method.args, { stdio: 'pipe' });
        
        let output = '';
        let error = '';
        
        tmux.stdout.on('data', (data) => {
          output += data.toString();
        });
        
        tmux.stderr.on('data', (data) => {
          error += data.toString();
        });
        
        tmux.on('exit', (code) => {
          if (code === 0) {
            this.log(`${method.name}: SUCCESS (${output.length} bytes)`);
            resolve(true);
          } else {
            this.log(`${method.name}: FAILED (code: ${code}) - ${error}`, false);
            resolve(false);
          }
        });
        
        tmux.on('error', (err) => {
          this.log(`${method.name}: ERROR - ${err.message}`, false);
          resolve(false);
        });
      });
      
      if (success) successCount++;
    }
    
    return successCount > 0;
  }

  /**
   * Clean up test session
   */
  async cleanup() {
    console.log('\n🧹 Cleaning up test session');
    
    return new Promise((resolve) => {
      const tmux = spawn('tmux', [
        '-S', this.socketPath,
        'kill-session',
        '-t', this.sessionName
      ]);

      tmux.on('exit', (code) => {
        this.log(`Session cleanup completed (code: ${code})`);
        
        // Remove socket file
        try {
          if (fs.existsSync(this.socketPath)) {
            fs.unlinkSync(this.socketPath);
            this.log(`Socket file removed: ${this.socketPath}`);
          }
        } catch (err) {
          this.log(`Failed to remove socket: ${err.message}`, false);
        }
        
        resolve();
      });

      tmux.on('error', () => {
        resolve(); // Don't fail cleanup
      });
    });
  }

  /**
   * Run all tests
   */
  async runAllTests() {
    console.log('🚀 Starting Screen Capture Debug Test Suite\n');
    console.log(`Session: ${this.sessionName}`);
    console.log(`Socket: ${this.socketPath}`);
    console.log(`Platform: ${process.platform}`);
    console.log(`Node: ${process.version}`);
    
    const tests = [
      () => this.testTmuxAvailability(),
      () => this.testSessionCreation(),
      () => this.testSessionExists(),
      () => this.testSocketPermissions(),
      () => this.testPathLength(),
      () => this.testBasicCapture(),
      () => this.testCaptureWithEscapes(),
      () => this.testCaptureWithContent(),
      () => this.testFullHistoryCapture(),
      () => this.testAlternativeCaptures()
    ];

    let passedTests = 0;
    let totalTests = tests.length;

    try {
      for (let i = 0; i < tests.length; i++) {
        try {
          const result = await tests[i]();
          if (result) passedTests++;
        } catch (err) {
          this.log(`Test ${i + 1} threw error: ${err.message}`, false);
        }
      }
    } finally {
      await this.cleanup();
    }

    // Print summary
    console.log(`\n📊 Test Results Summary:`);
    console.log(`✅ Passed: ${passedTests}/${totalTests}`);
    console.log(`❌ Failed: ${totalTests - passedTests}/${totalTests}`);
    
    if (passedTests === totalTests) {
      console.log('\n🎉 All tests passed! Screen capture should be working.');
    } else {
      console.log('\n⚠️  Some tests failed. Check the detailed results above.');
    }

    return this.testResults;
  }

  /**
   * Generate fix recommendations based on test results
   */
  generateFixRecommendations() {
    console.log('\n🔧 Fix Recommendations:');
    
    const failedTests = this.testResults.filter(r => !r.success);
    
    if (failedTests.length === 0) {
      console.log('✅ No issues found. The screen capture functionality appears to be working correctly.');
      return;
    }

    console.log('\n📋 Based on failed tests, here are the recommended fixes:\n');
    
    failedTests.forEach((test, index) => {
      console.log(`${index + 1}. ${test.message}`);
      
      // Provide specific recommendations
      if (test.message.includes('tmux not available')) {
        console.log('   → Install tmux: brew install tmux (macOS) or apt-get install tmux (Ubuntu)');
      }
      
      if (test.message.includes('Session') && test.message.includes('failed')) {
        console.log('   → Check tmux permissions and ensure no conflicting sessions');
      }
      
      if (test.message.includes('capture') && test.message.includes('failed')) {
        console.log('   → Implement fallback capture methods and better error handling');
      }
      
      if (test.message.includes('Socket') && test.message.includes('error')) {
        console.log('   → Use shorter socket paths or different socket directory');
      }
      
      if (test.message.includes('path') && test.message.includes('too long')) {
        console.log('   → Move socket directory to /tmp or use shorter session names');
      }
    });

    console.log('\n🛠️  Recommended Code Changes:');
    console.log('1. Add retry logic for failed capture operations');
    console.log('2. Implement fallback capture methods');
    console.log('3. Add better error handling and logging');
    console.log('4. Use shorter socket paths');
    console.log('5. Add session validation before capture attempts');
  }
}

// Export for use in other tests
module.exports = ScreenCaptureDebugger;

// Run directly if called as script
if (require.main === module) {
  const screenDebugger = new ScreenCaptureDebugger();
  
  screenDebugger.runAllTests()
    .then(() => {
      screenDebugger.generateFixRecommendations();
      process.exit(0);
    })
    .catch((err) => {
      console.error('❌ Test suite failed:', err);
      process.exit(1);
    });
}