import { chromium, FullConfig } from '@playwright/test';
import path from 'path';
import fs from 'fs/promises';

/**
 * Global setup for Playwright E2E coverage collection
 * Prepares the environment and starts coverage instrumentation
 */
async function globalSetup(config: FullConfig) {
  console.log('🎭 Setting up Playwright E2E coverage collection...');

  // Create coverage directories
  const coverageDir = path.resolve('./coverage/playwright');
  const tempDir = path.join(coverageDir, 'temp');

  await fs.mkdir(coverageDir, { recursive: true });
  await fs.mkdir(tempDir, { recursive: true });

  // Initialize coverage tracking files
  const coverageState = {
    startTime: new Date().toISOString(),
    testFiles: [],
    browserContexts: [],
    setupComplete: false
  };

  await fs.writeFile(
    path.join(coverageDir, 'coverage-state.json'),
    JSON.stringify(coverageState, null, 2)
  );

  console.log('📊 Coverage directories created');

  // Setup browser context for coverage collection
  try {
    const browser = await chromium.launch({
      headless: true,
      args: [
        '--enable-precise-memory-info',
        '--js-flags="--expose-gc"',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor',
      ]
    });

    const context = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      // Enable JavaScript coverage
      recordVideo: {
        dir: path.join(coverageDir, 'videos'),
        size: { width: 1280, height: 720 }
      }
    });

    // Start JavaScript coverage collection
    const page = await context.newPage();

    // Enable coverage collection
    await page.coverage.startJSCoverage({
      resetOnNavigation: false,
      reportAnonymousScripts: true,
    });

    await page.coverage.startCSSCoverage({
      resetOnNavigation: false,
    });

    // Navigate to the application to start coverage
    const baseURL = process.env.BASE_URL || 'http://localhost:11235';

    try {
      await page.goto(baseURL, { waitUntil: 'networkidle' });
      console.log('✅ Application loaded for coverage collection');

      // Wait for the application to be ready
      await page.waitForSelector('[data-testid="terminal-container"], .terminal-container', {
        timeout: 30000
      });

      console.log('✅ Terminal interface ready for testing');

    } catch (error) {
      console.warn('⚠️  Could not fully load application for coverage:', error.message);
      // Continue anyway, coverage will be collected from what loads
    }

    // Store initial coverage data
    const jsCoverage = await page.coverage.stopJSCoverage();
    const cssCoverage = await page.coverage.stopCSSCoverage();

    const initialCoverage = {
      timestamp: new Date().toISOString(),
      type: 'initial',
      js: jsCoverage,
      css: cssCoverage
    };

    await fs.writeFile(
      path.join(coverageDir, 'initial-coverage.json'),
      JSON.stringify(initialCoverage, null, 2)
    );

    // Update coverage state
    coverageState.setupComplete = true;
    coverageState.browserContexts.push({
      id: 'initial',
      timestamp: new Date().toISOString(),
      url: baseURL
    });

    await fs.writeFile(
      path.join(coverageDir, 'coverage-state.json'),
      JSON.stringify(coverageState, null, 2)
    );

    await context.close();
    await browser.close();

    console.log('✅ Playwright E2E coverage setup completed');

  } catch (error) {
    console.error('❌ Coverage setup failed:', error.message);
    console.error('Continuing with tests, but coverage may be incomplete');

    // Write error state
    const errorState = {
      ...coverageState,
      setupError: error.message,
      setupComplete: false
    };

    await fs.writeFile(
      path.join(coverageDir, 'coverage-state.json'),
      JSON.stringify(errorState, null, 2)
    );
  }
}

export default globalSetup;