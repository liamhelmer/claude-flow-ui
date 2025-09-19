/**
 * Test to reproduce the terminal container detection issue
 *
 * This test simulates the browser behavior when running:
 * npm run claude-flow-ui -- --port 11236 --terminal-size 120x40 hive-mind spawn 'wait for instructions' --claude
 *
 * Expected issue: Container not found after 10 attempts
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');
const path = require('path');

async function runContainerDetectionTest() {
  let serverProcess = null;
  let browser = null;
  let page = null;

  try {
    console.log('🚀 Starting claude-flow-ui server with test command...');

    // Start the server with the problematic command
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11236',
      '--terminal-size', '120x40',
      'hive-mind', 'spawn', 'wait for instructions',
      '--claude'
    ], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    console.log('⏳ Waiting for server to start...');
    await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => {
        reject(new Error('Server startup timeout'));
      }, 30000);

      serverProcess.stdout.on('data', (data) => {
        output += data.toString();
        console.log('📊 Server output:', data.toString().trim());

        // Look for server ready indicators
        if (output.includes('Running on:') || output.includes('localhost:11236')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.log('⚠️ Server stderr:', data.toString().trim());
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    console.log('🌐 Launching browser...');
    browser = await chromium.launch({
      headless: false,  // Set to true for CI, false for debugging
      devtools: true
    });

    const context = await browser.newContext();
    page = await context.newPage();

    // Collect console logs to capture the container detection issue
    const consoleLogs = [];
    page.on('console', (msg) => {
      const text = msg.text();
      consoleLogs.push(text);
      console.log(`🖥️ Browser console: ${text}`);
    });

    // Collect network errors
    page.on('requestfailed', (request) => {
      console.log(`❌ Network failed: ${request.url()} - ${request.failure().errorText}`);
    });

    console.log('📱 Navigating to http://localhost:11236...');

    // Navigate to the page
    const response = await page.goto('http://localhost:11236', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Page response status: ${response.status()}`);

    // Wait for potential container detection attempts
    console.log('⏳ Waiting for container detection attempts...');
    await page.waitForTimeout(15000); // Wait 15 seconds to catch all 10 attempts

    // Analyze the console logs for container detection issues
    const containerLogs = consoleLogs.filter(log =>
      log.includes('Container not ready yet') ||
      log.includes('Container not found after') ||
      log.includes('Container element detected') ||
      log.includes('Terminal Component') ||
      log.includes('Ref callback called')
    );

    console.log('\n📋 CONTAINER DETECTION ANALYSIS:');
    console.log('='.repeat(50));

    if (containerLogs.length === 0) {
      console.log('✅ No container detection issues found');
    } else {
      console.log(`⚠️ Found ${containerLogs.length} container-related log entries:`);
      containerLogs.forEach((log, index) => {
        console.log(`${index + 1}. ${log}`);
      });
    }

    // Check for the specific error pattern
    const containerNotFoundLogs = consoleLogs.filter(log =>
      log.includes('Container not found after 10 attempts')
    );

    const containerAttemptLogs = consoleLogs.filter(log =>
      log.includes('Container not ready yet, attempt')
    );

    console.log('\n🔍 ISSUE REPRODUCTION:');
    console.log('='.repeat(50));

    if (containerNotFoundLogs.length > 0) {
      console.log('❌ ISSUE REPRODUCED: Container not found after 10 attempts');
      console.log(`   Found ${containerAttemptLogs.length} retry attempts`);
      return {
        success: false,
        issue: 'Container detection failed',
        attempts: containerAttemptLogs.length,
        logs: containerLogs
      };
    } else if (containerAttemptLogs.length > 0) {
      console.log('⚠️ PARTIAL ISSUE: Container detection retries found but no final failure');
      console.log(`   Found ${containerAttemptLogs.length} retry attempts`);
      return {
        success: false,
        issue: 'Container detection retrying',
        attempts: containerAttemptLogs.length,
        logs: containerLogs
      };
    } else {
      console.log('✅ NO ISSUE: Container detection appears to be working');
      return {
        success: true,
        issue: null,
        attempts: 0,
        logs: containerLogs
      };
    }

  } catch (error) {
    console.error('💥 Test failed:', error.message);
    return {
      success: false,
      issue: 'Test execution failed',
      error: error.message,
      logs: []
    };
  } finally {
    // Cleanup
    if (page) {
      console.log('🧹 Closing browser page...');
      await page.close();
    }
    if (browser) {
      console.log('🧹 Closing browser...');
      await browser.close();
    }
    if (serverProcess) {
      console.log('🧹 Stopping server...');
      serverProcess.kill('SIGTERM');

      // Force kill after 5 seconds if needed
      setTimeout(() => {
        if (!serverProcess.killed) {
          serverProcess.kill('SIGKILL');
        }
      }, 5000);
    }
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  runContainerDetectionTest()
    .then((result) => {
      console.log('\n📊 FINAL RESULT:');
      console.log('='.repeat(50));
      console.log(JSON.stringify(result, null, 2));

      // Exit with appropriate code
      process.exit(result.success ? 0 : 1);
    })
    .catch((error) => {
      console.error('💥 Test runner failed:', error);
      process.exit(1);
    });
}

module.exports = { runContainerDetectionTest };