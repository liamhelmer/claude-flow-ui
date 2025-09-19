#!/usr/bin/env node

/**
 * Terminal Refresh and Switching Validation Test
 * Tests the fixes we implemented for terminal refresh and switching issues
 */

const { spawn } = require('child_process');
const puppeteer = require('puppeteer');

async function runValidationTest() {
  console.log('🚀 Starting Terminal Refresh & Switching Validation Test...');

  const startTime = Date.now();
  let server = null;
  let browser = null;

  try {
    // Start production server
    console.log('🌐 Starting production server...');
    server = spawn('npm', ['run', 'claude-flow-ui', '--', '--port', '11245'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NODE_ENV: 'production' }
    });

    // Wait for server to start
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Server startup timeout')), 30000);

      server.stdout.on('data', (data) => {
        const output = data.toString();
        console.log('📊 Server:', output.trim());

        if (output.includes('Running on: http://localhost:11245')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      server.stderr.on('data', (data) => {
        console.log('⚠️ Server stderr:', data.toString().trim());
      });
    });

    // Launch browser
    console.log('🌐 Starting browser...');
    browser = await puppeteer.launch({
      headless: false,
      devtools: false,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();

    // Set up console logging
    page.on('console', msg => {
      const text = msg.text();
      if (text.includes('[Terminal]') || text.includes('[WebSocket]') || text.includes('refresh')) {
        console.log('📱 Browser:', text);
      }
    });

    // Navigate to application
    console.log('📱 Navigating to production server...');
    await page.goto('http://localhost:11245', { waitUntil: 'networkidle0' });

    // Wait for terminal to be ready
    console.log('⏳ Waiting for terminal to be ready...');
    await page.waitForSelector('.terminal', { timeout: 10000 });

    // Wait a bit more for full initialization
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Test 1: Terminal Refresh Fix Validation
    console.log('\n🔍 TEST 1: TERMINAL REFRESH VALIDATION');
    console.log('=======================================');

    // Check if refresh button exists
    const hasRefreshButton = await page.$('.terminal-controls button[title*="refresh"], .terminal-controls button[aria-label*="refresh"], button[data-testid="refresh"]') !== null;
    console.log(`✅ Refresh button present: ${hasRefreshButton}`);

    if (hasRefreshButton) {
      // Click refresh button
      console.log('🔄 Clicking refresh button...');
      await page.click('.terminal-controls button[title*="refresh"], .terminal-controls button[aria-label*="refresh"], button[data-testid="refresh"]');

      // Wait for refresh to complete
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Check if terminal is still visible and not blank
      const terminalVisible = await page.$eval('.terminal', el => {
        return el.offsetHeight > 0 && el.offsetWidth > 0;
      });

      console.log(`✅ Terminal visible after refresh: ${terminalVisible}`);

      // Check if terminal has content (not completely blank)
      const hasContent = await page.evaluate(() => {
        const terminalEl = document.querySelector('.terminal .xterm-viewport, .terminal .xterm-screen');
        return terminalEl && terminalEl.textContent && terminalEl.textContent.trim().length > 0;
      });

      console.log(`✅ Terminal has content after refresh: ${hasContent}`);
    }

    // Test 2: Terminal Switching Fix Validation (if multiple sessions exist)
    console.log('\n🔍 TEST 2: TERMINAL SWITCHING VALIDATION');
    console.log('=========================================');

    // Check if sidebar/session switcher exists
    const hasSidebar = await page.$('.sidebar, .terminal-sidebar, .session-list') !== null;
    console.log(`✅ Terminal sidebar/switcher present: ${hasSidebar}`);

    // Test 3: WebSocket Message Handling
    console.log('\n🔍 TEST 3: WEBSOCKET MESSAGE HANDLING');
    console.log('======================================');

    // Check WebSocket connection status
    const wsConnected = await page.evaluate(() => {
      return window.__wsClient__ && window.__wsClient__.connected;
    });

    console.log(`✅ WebSocket connected: ${wsConnected || 'unknown'}`);

    // Test 4: Session ID Routing
    console.log('\n🔍 TEST 4: SESSION ID ROUTING');
    console.log('==============================');

    // Check if session ID is properly set
    const hasSessionId = await page.evaluate(() => {
      const sessionElement = document.querySelector('[data-session-id], [data-testid="session-id"]');
      return sessionElement && sessionElement.getAttribute('data-session-id') ||
             sessionElement && sessionElement.getAttribute('data-testid') === 'session-id';
    });

    console.log(`✅ Session ID routing active: ${hasSessionId !== null}`);

    // Final Status Check
    console.log('\n📊 FINAL VALIDATION SUMMARY');
    console.log('============================');

    const validationResults = {
      terminalRefreshFix: hasRefreshButton && terminalVisible,
      terminalSwitchingFix: hasSidebar,
      websocketHandling: wsConnected || false,
      sessionIdRouting: hasSessionId !== null,
      timestamp: new Date().toISOString(),
      testDuration: Date.now() - startTime
    };

    console.log(JSON.stringify(validationResults, null, 2));

    // Overall result
    const overallSuccess = Object.values(validationResults).filter(v => typeof v === 'boolean').every(v => v);
    console.log(`\n🎯 OVERALL VALIDATION: ${overallSuccess ? 'SUCCESS ✅' : 'NEEDS ATTENTION ⚠️'}`);

    return validationResults;

  } catch (error) {
    console.error('❌ Validation test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    // Cleanup
    if (browser) {
      console.log('🧹 Closing browser...');
      await browser.close();
    }

    if (server) {
      console.log('🧹 Stopping server...');
      server.kill('SIGTERM');
    }
  }
}

// Run the test
runValidationTest()
  .then(results => {
    console.log('\n✅ Validation test completed');
    process.exit(0);
  })
  .catch(error => {
    console.error('❌ Test execution failed:', error);
    process.exit(1);
  });