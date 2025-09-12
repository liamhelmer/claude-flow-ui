#!/usr/bin/env node

/**
 * Production Screen Capture Test Suite
 * 
 * This test replicates the exact production scenario that causes
 * "Failed to capture screen: 1" errors by using the actual
 * TmuxStreamManager and TmuxManager classes.
 */

const path = require('path');
const fs = require('fs');

// Import the actual production classes
const TmuxStreamManager = require('../src/lib/tmux-stream-manager');
const TmuxManager = require('../src/lib/tmux-manager');

class ProductionScreenCaptureTest {
  constructor() {
    this.testResults = [];
    this.tmuxStreamManager = new TmuxStreamManager();
    this.tmuxManager = new TmuxManager();
  }

  log(message, success = true) {
    const result = { message, success, timestamp: new Date().toISOString() };
    this.testResults.push(result);
    console.log(`${success ? '✅' : '❌'} ${message}`);
    return result;
  }

  /**
   * Test 1: TmuxStreamManager session creation and capture
   */
  async testTmuxStreamManagerCapture() {
    console.log('\n🔍 Test 1: TmuxStreamManager session creation and capture');
    
    try {
      // Create session using TmuxStreamManager
      const session = await this.tmuxStreamManager.createSession();
      this.log(`TmuxStreamManager session created: ${session.name}`);

      // Wait a moment for session to be ready
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Test direct capture using the class method
      try {
        const output = await this.tmuxStreamManager.captureFullScreen(session.name, session.socketPath);
        this.log(`TmuxStreamManager capture successful: ${output.length} bytes`);
        
        // Clean up
        await this.tmuxStreamManager.killSession(session.name);
        return true;
      } catch (captureError) {
        this.log(`TmuxStreamManager capture failed: ${captureError.message}`, false);
        // Clean up even on failure
        await this.tmuxStreamManager.killSession(session.name);
        return false;
      }
    } catch (sessionError) {
      this.log(`TmuxStreamManager session creation failed: ${sessionError.message}`, false);
      return false;
    }
  }

  /**
   * Test 2: TmuxManager session creation and capture
   */
  async testTmuxManagerCapture() {
    console.log('\n🔍 Test 2: TmuxManager session creation and capture');
    
    try {
      // Create session using TmuxManager
      const sessionInfo = await this.tmuxManager.createSession();
      this.log(`TmuxManager session created: ${sessionInfo.name}`);

      // Wait a moment for session to be ready
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Test both capture methods
      try {
        // Test capturePane
        const paneOutput = await this.tmuxManager.capturePane(sessionInfo.name, sessionInfo.socketPath);
        this.log(`TmuxManager capturePane successful: ${paneOutput.length} bytes`);

        // Test captureFullScreen
        const fullOutput = await this.tmuxManager.captureFullScreen(sessionInfo.name, sessionInfo.socketPath);
        this.log(`TmuxManager captureFullScreen successful: ${fullOutput.length} bytes`);

        // Clean up
        await this.tmuxManager.killSession(sessionInfo.name);
        return true;
      } catch (captureError) {
        this.log(`TmuxManager capture failed: ${captureError.message}`, false);
        // Clean up even on failure
        await this.tmuxManager.killSession(sessionInfo.name);
        return false;
      }
    } catch (sessionError) {
      this.log(`TmuxManager session creation failed: ${sessionError.message}`, false);
      return false;
    }
  }

  /**
   * Test 3: Test rapid capture operations (stress test)
   */
  async testRapidCaptures() {
    console.log('\n🔍 Test 3: Test rapid capture operations (stress test)');
    
    try {
      const session = await this.tmuxStreamManager.createSession();
      this.log(`Created session for stress test: ${session.name}`);

      // Wait for session to be ready
      await new Promise(resolve => setTimeout(resolve, 1000));

      let successCount = 0;
      let failureCount = 0;
      const numTests = 10;

      // Perform rapid captures
      for (let i = 0; i < numTests; i++) {
        try {
          const output = await this.tmuxStreamManager.captureFullScreen(session.name, session.socketPath);
          successCount++;
          console.log(`  Capture ${i + 1}: SUCCESS (${output.length} bytes)`);
        } catch (err) {
          failureCount++;
          console.log(`  Capture ${i + 1}: FAILED - ${err.message}`);
        }
        
        // Small delay between captures
        await new Promise(resolve => setTimeout(resolve, 50));
      }

      this.log(`Stress test completed: ${successCount}/${numTests} succeeded, ${failureCount}/${numTests} failed`);
      
      // Clean up
      await this.tmuxStreamManager.killSession(session.name);
      
      return successCount > failureCount;
    } catch (err) {
      this.log(`Stress test setup failed: ${err.message}`, false);
      return false;
    }
  }

  /**
   * Test 4: Test capture on non-existent session
   */
  async testCaptureNonExistentSession() {
    console.log('\n🔍 Test 4: Test capture on non-existent session');
    
    const fakeSessionName = 'non-existent-session-12345';
    const fakeSocketPath = '/tmp/fake.sock';
    
    try {
      const output = await this.tmuxStreamManager.captureFullScreen(fakeSessionName, fakeSocketPath);
      this.log(`Non-existent session capture unexpectedly succeeded`, false);
      return false;
    } catch (err) {
      if (err.message.includes('Failed to capture screen: 1')) {
        this.log(`Non-existent session correctly produced "Failed to capture screen: 1" error`);
        return true;
      } else {
        this.log(`Non-existent session produced unexpected error: ${err.message}`, false);
        return false;
      }
    }
  }

  /**
   * Test 5: Test capture with dead session
   */
  async testCaptureDeadSession() {
    console.log('\n🔍 Test 5: Test capture with dead session (this reproduces the production error)');
    
    try {
      // Create session
      const session = await this.tmuxStreamManager.createSession();
      this.log(`Created session: ${session.name}`);

      // Kill the session manually (but keep the object reference)
      await this.tmuxStreamManager.killSession(session.name);
      this.log(`Killed session: ${session.name}`);

      // Wait a moment
      await new Promise(resolve => setTimeout(resolve, 500));

      // Now try to capture from the dead session
      try {
        const output = await this.tmuxStreamManager.captureFullScreen(session.name, session.socketPath);
        this.log(`Dead session capture unexpectedly succeeded`, false);
        return false;
      } catch (err) {
        if (err.message.includes('Failed to capture screen: 1')) {
          this.log(`Dead session correctly produced "Failed to capture screen: 1" error - THIS IS THE PRODUCTION ISSUE!`);
          return true;
        } else {
          this.log(`Dead session produced unexpected error: ${err.message}`, false);
          return false;
        }
      }
    } catch (err) {
      this.log(`Dead session test setup failed: ${err.message}`, false);
      return false;
    }
  }

  /**
   * Test 6: Test socket permission issues
   */
  async testSocketPermissions() {
    console.log('\n🔍 Test 6: Test socket permission issues');
    
    try {
      const session = await this.tmuxStreamManager.createSession();
      this.log(`Created session: ${session.name}`);

      // Change socket permissions to read-only
      try {
        fs.chmodSync(session.socketPath, 0o444); // Read-only
        this.log(`Changed socket to read-only: ${session.socketPath}`);

        // Try to capture
        try {
          const output = await this.tmuxStreamManager.captureFullScreen(session.name, session.socketPath);
          this.log(`Read-only socket capture unexpectedly succeeded`);
          
          // Restore permissions and clean up
          fs.chmodSync(session.socketPath, 0o600);
          await this.tmuxStreamManager.killSession(session.name);
          return true;
        } catch (err) {
          this.log(`Read-only socket capture failed as expected: ${err.message}`);
          
          // Restore permissions and clean up
          fs.chmodSync(session.socketPath, 0o600);
          await this.tmuxStreamManager.killSession(session.name);
          return true;
        }
      } catch (permErr) {
        this.log(`Could not change socket permissions: ${permErr.message}`, false);
        await this.tmuxStreamManager.killSession(session.name);
        return false;
      }
    } catch (err) {
      this.log(`Permission test setup failed: ${err.message}`, false);
      return false;
    }
  }

  /**
   * Test 7: Test concurrent captures from multiple clients
   */
  async testConcurrentCaptures() {
    console.log('\n🔍 Test 7: Test concurrent captures from multiple clients');
    
    try {
      const session = await this.tmuxStreamManager.createSession();
      this.log(`Created session for concurrent test: ${session.name}`);

      // Wait for session to be ready
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Start multiple concurrent captures
      const capturePromises = [];
      for (let i = 0; i < 5; i++) {
        capturePromises.push(
          this.tmuxStreamManager.captureFullScreen(session.name, session.socketPath)
            .then(output => ({ success: true, length: output.length, index: i }))
            .catch(err => ({ success: false, error: err.message, index: i }))
        );
      }

      const results = await Promise.all(capturePromises);
      const successes = results.filter(r => r.success).length;
      const failures = results.filter(r => !r.success).length;

      this.log(`Concurrent captures: ${successes} succeeded, ${failures} failed`);
      
      // Log details of failures
      results.forEach(result => {
        if (!result.success) {
          console.log(`  Capture ${result.index}: FAILED - ${result.error}`);
        } else {
          console.log(`  Capture ${result.index}: SUCCESS (${result.length} bytes)`);
        }
      });

      // Clean up
      await this.tmuxStreamManager.killSession(session.name);
      
      return successes > 0;
    } catch (err) {
      this.log(`Concurrent test setup failed: ${err.message}`, false);
      return false;
    }
  }

  /**
   * Test 8: Test the streaming behavior that might cause issues
   */
  async testStreamingBehavior() {
    console.log('\n🔍 Test 8: Test streaming behavior that might cause issues');
    
    try {
      const session = await this.tmuxStreamManager.createSession();
      this.log(`Created streaming session: ${session.name}`);

      // Simulate a client connecting (this starts the streaming)
      let dataReceived = '';
      const clientId = 'test-client-' + Date.now();
      
      const connection = this.tmuxStreamManager.connectClient(clientId, session.name, (data) => {
        dataReceived += data;
      });

      // Wait for some streaming data
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Now try manual capture while streaming is active
      try {
        const captureOutput = await this.tmuxStreamManager.captureFullScreen(session.name, session.socketPath);
        this.log(`Manual capture during streaming succeeded: ${captureOutput.length} bytes`);
        this.log(`Streaming received: ${dataReceived.length} bytes`);

        // Disconnect and cleanup
        this.tmuxStreamManager.disconnectClient(clientId);
        await this.tmuxStreamManager.killSession(session.name);
        return true;
      } catch (err) {
        this.log(`Manual capture during streaming failed: ${err.message}`, false);
        this.tmuxStreamManager.disconnectClient(clientId);
        await this.tmuxStreamManager.killSession(session.name);
        return false;
      }
    } catch (err) {
      this.log(`Streaming test setup failed: ${err.message}`, false);
      return false;
    }
  }

  /**
   * Run all production tests
   */
  async runAllTests() {
    console.log('🚀 Starting Production Screen Capture Test Suite\n');
    console.log(`Platform: ${process.platform}`);
    console.log(`Node: ${process.version}`);
    console.log(`Testing actual production classes...\n`);
    
    const tests = [
      () => this.testTmuxStreamManagerCapture(),
      () => this.testTmuxManagerCapture(),
      () => this.testRapidCaptures(),
      () => this.testCaptureNonExistentSession(),
      () => this.testCaptureDeadSession(),
      () => this.testSocketPermissions(),
      () => this.testConcurrentCaptures(),
      () => this.testStreamingBehavior()
    ];

    let passedTests = 0;
    let totalTests = tests.length;

    for (let i = 0; i < tests.length; i++) {
      try {
        const result = await tests[i]();
        if (result) passedTests++;
      } catch (err) {
        this.log(`Test ${i + 1} threw unexpected error: ${err.message}`, false);
      }
      
      // Small delay between tests
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    // Final cleanup
    try {
      await this.tmuxStreamManager.cleanup();
      await this.tmuxManager.cleanup();
    } catch (err) {
      console.log('Cleanup error (non-critical):', err.message);
    }

    // Print summary
    console.log(`\n📊 Production Test Results Summary:`);
    console.log(`✅ Passed: ${passedTests}/${totalTests}`);
    console.log(`❌ Failed: ${totalTests - passedTests}/${totalTests}`);
    
    return this.testResults;
  }

  /**
   * Generate production fix recommendations
   */
  generateProductionFixes() {
    console.log('\n🔧 Production Fix Recommendations:\n');
    
    const failedTests = this.testResults.filter(r => !r.success);
    const hasDeadSessionError = failedTests.some(t => t.message.includes('Failed to capture screen: 1'));
    
    if (hasDeadSessionError) {
      console.log('🎯 FOUND THE PRODUCTION ISSUE: "Failed to capture screen: 1"');
      console.log('   This occurs when trying to capture from dead/non-existent sessions.\n');
    }

    console.log('📋 Recommended fixes for production code:\n');
    console.log('1. Add session validation before capture attempts');
    console.log('2. Implement retry logic with exponential backoff');
    console.log('3. Add graceful fallback when capture fails');
    console.log('4. Improve error messages for debugging');
    console.log('5. Add session health monitoring');
    console.log('6. Implement session recovery mechanisms');

    return {
      hasIssues: failedTests.length > 0,
      hasDeadSessionError,
      totalFailures: failedTests.length,
      failedTests
    };
  }
}

// Export for use in other tests
module.exports = ProductionScreenCaptureTest;

// Run directly if called as script
if (require.main === module) {
  const tester = new ProductionScreenCaptureTest();
  
  tester.runAllTests()
    .then(() => {
      const results = tester.generateProductionFixes();
      process.exit(results.hasIssues ? 1 : 0);
    })
    .catch((err) => {
      console.error('❌ Production test suite failed:', err);
      process.exit(1);
    });
}