/**
 * Global Teardown for E2E Tests
 * Cleans up test environment after running tests
 */

const { chromium } = require('@playwright/test');

async function globalTeardown(config) {
  console.log('🧹 Starting E2E test global teardown...');

  try {
    // Launch browser for cleanup
    const browser = await chromium.launch();
    const page = await browser.newPage();

    // Clean up test data
    await cleanupTestData(page);

    // Clean up test sessions
    await cleanupTestSessions(page);

    // Generate test summary report
    await generateTestSummary();

    await browser.close();

    console.log('✅ E2E test global teardown completed');

  } catch (error) {
    console.error('❌ Global teardown failed:', error);
    // Don't throw here to avoid masking test failures
  }
}

async function cleanupTestData(page) {
  console.log('🗑️ Cleaning up test data...');

  try {
    await page.goto('http://localhost:3000');

    // Clear test data from localStorage
    await page.evaluate(() => {
      Object.keys(localStorage).forEach(key => {
        if (key.startsWith('test-') || key.startsWith('e2e-')) {
          localStorage.removeItem(key);
        }
      });

      // Clear any test cookies
      Object.keys(sessionStorage).forEach(key => {
        if (key.startsWith('test-') || key.startsWith('e2e-')) {
          sessionStorage.removeItem(key);
        }
      });
    });

    console.log('✅ Test data cleanup completed');
  } catch (error) {
    console.warn('⚠️ Test data cleanup failed:', error.message);
  }
}

async function cleanupTestSessions(page) {
  console.log('🔌 Cleaning up test terminal sessions...');

  try {
    // Get list of active terminals
    const response = await page.request.get('http://localhost:3000/api/terminals');

    if (response.ok()) {
      const terminals = await response.json();

      // Clean up test sessions
      for (const terminal of terminals) {
        if (terminal.sessionName && (
          terminal.sessionName.includes('test') ||
          terminal.sessionName.includes('e2e') ||
          terminal.sessionName.includes('playwright')
        )) {
          try {
            await page.request.delete(`http://localhost:3000/api/terminals/${terminal.id}`);
            console.log(`🗑️ Cleaned up test session: ${terminal.sessionName}`);
          } catch (error) {
            console.warn(`⚠️ Failed to cleanup session ${terminal.id}:`, error.message);
          }
        }
      }
    }

    console.log('✅ Test session cleanup completed');
  } catch (error) {
    console.warn('⚠️ Test session cleanup failed:', error.message);
  }
}

async function generateTestSummary() {
  console.log('📊 Generating test summary...');

  try {
    const fs = require('fs').promises;
    const path = require('path');

    // Check if test results exist
    const resultsPath = path.join(process.cwd(), 'test-results', 'results.json');

    try {
      const resultsData = await fs.readFile(resultsPath, 'utf8');
      const results = JSON.parse(resultsData);

      const summary = {
        timestamp: new Date().toISOString(),
        total: results.stats?.total || 0,
        passed: results.stats?.passed || 0,
        failed: results.stats?.failed || 0,
        skipped: results.stats?.skipped || 0,
        duration: results.stats?.duration || 0,
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch
        }
      };

      // Save summary
      const summaryPath = path.join(process.cwd(), 'test-results', 'summary.json');
      await fs.writeFile(summaryPath, JSON.stringify(summary, null, 2));

      // Log summary
      console.log('\n📈 Test Summary:');
      console.log(`   Total: ${summary.total}`);
      console.log(`   Passed: ${summary.passed}`);
      console.log(`   Failed: ${summary.failed}`);
      console.log(`   Skipped: ${summary.skipped}`);
      console.log(`   Duration: ${(summary.duration / 1000).toFixed(2)}s`);

      if (summary.failed > 0) {
        console.log('\n❌ Some tests failed. Check test-results/ for details.');
      } else {
        console.log('\n✅ All tests passed!');
      }

    } catch (error) {
      console.warn('⚠️ Could not read test results:', error.message);
    }

    console.log('✅ Test summary generation completed');
  } catch (error) {
    console.warn('⚠️ Test summary generation failed:', error.message);
  }
}

module.exports = globalTeardown;