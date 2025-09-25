import { chromium, FullConfig } from '@playwright/test';
import path from 'path';
import fs from 'fs';

/**
 * Global setup for E2E tests
 * Handles authentication, initial state setup, and test environment preparation
 */
async function globalSetup(config: FullConfig) {
  console.log('🚀 Starting global E2E test setup...');

  // Ensure test directories exist
  const dirs = [
    'tests/e2e/test-results',
    'tests/e2e/reports',
    'tests/e2e/reports/html',
    'tests/e2e/visual-snapshots',
    'tests/e2e/screenshots',
    'tests/e2e/videos',
    'tests/e2e/traces',
  ];

  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  const { baseURL } = config.projects[0].use;
  console.log(`📍 Base URL: ${baseURL}`);

  // Wait for application to be ready
  console.log('⏳ Waiting for application to start...');

  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Wait for app to be accessible
    let retries = 30;
    while (retries > 0) {
      try {
        await page.goto(baseURL!, { waitUntil: 'networkidle', timeout: 5000 });
        const title = await page.title();
        if (title) {
          console.log(`✅ Application ready: ${title}`);
          break;
        }
      } catch (error) {
        retries--;
        if (retries === 0) {
          throw new Error(`Application not ready after 30 attempts: ${error}`);
        }
        console.log(`🔄 Waiting for application... (${30 - retries}/30)`);
        await page.waitForTimeout(2000);
      }
    }

    // Setup test authentication state if needed
    await setupAuthentication(page);

    // Pre-warm critical resources
    await prewarmApplication(page);

    console.log('✅ Global setup completed successfully');

  } catch (error) {
    console.error('❌ Global setup failed:', error);
    throw error;
  } finally {
    await browser.close();
  }
}

/**
 * Setup authentication for tests that require it
 */
async function setupAuthentication(page: any) {
  try {
    // For Backstage integration tests, setup mock authentication
    await page.addInitScript(() => {
      // Mock auth state for testing
      window.localStorage.setItem('test-auth-token', 'mock-token');
      window.localStorage.setItem('test-user-id', 'test-user');
    });

    console.log('🔐 Authentication setup completed');
  } catch (error) {
    console.warn('⚠️ Authentication setup failed (may not be required):', error);
  }
}

/**
 * Pre-warm application by loading critical resources
 */
async function prewarmApplication(page: any) {
  try {
    // Load main components to warm up
    await page.waitForSelector('body', { timeout: 10000 });

    // Check for terminal initialization
    const hasTerminal = await page.locator('.xterm-wrapper, [data-testid="terminal"]').count() > 0;
    if (hasTerminal) {
      console.log('🖥️ Terminal components detected and warmed');
    }

    // Check for WebSocket connection
    const hasWebSocket = await page.evaluate(() => {
      return 'WebSocket' in window;
    });
    if (hasWebSocket) {
      console.log('🌐 WebSocket support confirmed');
    }

    console.log('🔥 Application prewarming completed');
  } catch (error) {
    console.warn('⚠️ Application prewarming failed (non-critical):', error);
  }
}

export default globalSetup;