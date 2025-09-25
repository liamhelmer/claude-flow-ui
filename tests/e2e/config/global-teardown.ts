import { FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

/**
 * Global teardown for E2E tests
 * Handles cleanup, report generation, and test environment cleanup
 */
async function globalTeardown(config: FullConfig) {
  console.log('🧹 Starting global E2E test teardown...');

  try {
    // Generate test summary
    await generateTestSummary();

    // Cleanup temporary files if needed
    await cleanupTempFiles();

    // Archive old test results if in CI
    if (process.env.CI) {
      await archiveTestResults();
    }

    console.log('✅ Global teardown completed successfully');

  } catch (error) {
    console.error('❌ Global teardown failed:', error);
    // Don't throw to avoid masking test failures
  }
}

/**
 * Generate a summary of test results
 */
async function generateTestSummary() {
  try {
    const resultsPath = 'tests/e2e/reports/test-results.json';

    if (fs.existsSync(resultsPath)) {
      const results = JSON.parse(fs.readFileSync(resultsPath, 'utf-8'));

      const summary = {
        timestamp: new Date().toISOString(),
        total: results.stats?.total || 0,
        passed: results.stats?.passed || 0,
        failed: results.stats?.failed || 0,
        skipped: results.stats?.skipped || 0,
        flaky: results.stats?.flaky || 0,
        duration: results.stats?.duration || 0,
      };

      // Write summary
      fs.writeFileSync(
        'tests/e2e/reports/summary.json',
        JSON.stringify(summary, null, 2)
      );

      console.log(`📊 Test Summary:`);
      console.log(`   Total: ${summary.total}`);
      console.log(`   Passed: ${summary.passed}`);
      console.log(`   Failed: ${summary.failed}`);
      console.log(`   Skipped: ${summary.skipped}`);
      console.log(`   Duration: ${(summary.duration / 1000).toFixed(2)}s`);
    }
  } catch (error) {
    console.warn('⚠️ Could not generate test summary:', error);
  }
}

/**
 * Clean up temporary files created during testing
 */
async function cleanupTempFiles() {
  try {
    const tempDirs = [
      'tests/e2e/temp',
      '.tmp',
    ];

    for (const dir of tempDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        console.log(`🗑️ Cleaned up ${dir}`);
      }
    }
  } catch (error) {
    console.warn('⚠️ Cleanup of temp files failed:', error);
  }
}

/**
 * Archive old test results in CI environment
 */
async function archiveTestResults() {
  try {
    const archiveDir = `tests/e2e/archives/${new Date().toISOString().split('T')[0]}`;

    if (!fs.existsSync(archiveDir)) {
      fs.mkdirSync(archiveDir, { recursive: true });
    }

    // Archive reports
    if (fs.existsSync('tests/e2e/reports')) {
      const archivePath = path.join(archiveDir, 'reports');
      fs.cpSync('tests/e2e/reports', archivePath, { recursive: true });
      console.log(`📦 Archived reports to ${archivePath}`);
    }

    // Keep only last 7 days of archives
    const archivesDir = 'tests/e2e/archives';
    if (fs.existsSync(archivesDir)) {
      const archives = fs.readdirSync(archivesDir)
        .filter(name => /^\d{4}-\d{2}-\d{2}$/.test(name))
        .sort()
        .reverse();

      // Remove archives older than 7 days
      archives.slice(7).forEach(archive => {
        const archivePath = path.join(archivesDir, archive);
        fs.rmSync(archivePath, { recursive: true, force: true });
        console.log(`🗑️ Removed old archive ${archive}`);
      });
    }

  } catch (error) {
    console.warn('⚠️ Archive operation failed:', error);
  }
}

export default globalTeardown;