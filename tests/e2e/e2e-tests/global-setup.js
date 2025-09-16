/**
 * Global Setup for E2E Tests
 * Sets up test environment before running tests
 */

const { chromium } = require('@playwright/test');

async function globalSetup(config) {
  console.log('🚀 Starting E2E test global setup...');

  try {
    // Launch browser to check if the server is running
    const browser = await chromium.launch();
    const page = await browser.newPage();

    // Wait for the server to be available
    const maxRetries = 30;
    let retries = 0;

    while (retries < maxRetries) {
      try {
        await page.goto('http://localhost:3000/health');
        const response = await page.waitForResponse('**/health', { timeout: 5000 });

        if (response.ok()) {
          console.log('✅ Server is running and healthy');
          break;
        }
      } catch (error) {
        retries++;
        console.log(`⏳ Waiting for server... (${retries}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    if (retries >= maxRetries) {
      throw new Error('❌ Server failed to start within timeout period');
    }

    // Set up test data if needed
    await setupTestData(page);

    // Clean up any existing test sessions
    await cleanupTestSessions(page);

    await browser.close();

    console.log('✅ E2E test global setup completed');

  } catch (error) {
    console.error('❌ Global setup failed:', error);
    throw error;
  }
}

async function setupTestData(page) {
  console.log('📋 Setting up test data...');

  try {
    // Create test terminal sessions if needed
    await page.evaluate(() => {
      // Clear any existing test data in localStorage
      Object.keys(localStorage).forEach(key => {
        if (key.startsWith('test-') || key.startsWith('e2e-')) {
          localStorage.removeItem(key);
        }
      });

      // Set up test configuration
      localStorage.setItem('e2e-test-mode', 'true');
      localStorage.setItem('e2e-test-timestamp', Date.now().toString());
    });

    console.log('✅ Test data setup completed');
  } catch (error) {
    console.error('❌ Test data setup failed:', error);
    // Don't throw here, as this is not critical
  }
}

async function cleanupTestSessions(page) {
  console.log('🧹 Cleaning up existing test sessions...');

  try {
    // Make API call to clean up any existing test sessions
    const response = await page.request.get('http://localhost:3000/api/terminals');

    if (response.ok()) {
      const terminals = await response.json();

      // Clean up test sessions
      for (const terminal of terminals) {
        if (terminal.sessionName && terminal.sessionName.includes('test')) {
          try {
            await page.request.delete(`http://localhost:3000/api/terminals/${terminal.id}`);
          } catch (error) {
            console.warn(`⚠️ Failed to cleanup session ${terminal.id}:`, error.message);
          }
        }
      }
    }

    console.log('✅ Test session cleanup completed');
  } catch (error) {
    console.warn('⚠️ Test session cleanup failed:', error.message);
    // Don't throw here, as this is not critical
  }
}

module.exports = globalSetup;