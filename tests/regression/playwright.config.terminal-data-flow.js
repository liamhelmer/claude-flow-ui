import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright Configuration for Terminal Data Flow Regression Tests
 *
 * This configuration is optimized for testing terminal interactions
 * and WebSocket data flow validation.
 */

export default defineConfig({
  testDir: './tests/regression',
  testMatch: '**/terminal-data-flow.spec.ts',

  // Test execution settings
  timeout: 30000,
  fullyParallel: false, // Run tests sequentially for stability
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: 1, // Single worker for consistent terminal state

  // Reporting
  reporter: [
    ['line'],
    ['html', {
      outputFolder: 'tests/regression/reports',
      open: 'never'
    }],
    ['json', {
      outputFile: 'tests/regression/reports/terminal-data-flow-results.json'
    }]
  ],

  // Global test settings
  use: {
    // Base URL
    baseURL: 'http://localhost:3000',

    // Browser settings optimized for terminal testing
    headless: false, // Show browser for debugging
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,

    // Timeouts
    actionTimeout: 10000,
    navigationTimeout: 15000,

    // Screenshots and videos for debugging
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',

    // Context options
    contextOptions: {
      // Enable console API for debugging
      permissions: ['clipboard-read', 'clipboard-write'],
    }
  },

  // Projects for different browsers
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Enable additional debugging features
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=TranslateUI',
            '--disable-extensions',
            '--no-first-run',
            '--enable-logging',
            '--v=1'
          ]
        }
      },
    },

    // Uncomment for cross-browser testing
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },

    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] },
    // },
  ],

  // Web server configuration
  webServer: process.env.CI ? undefined : {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: true,
    timeout: 120000,
    stdout: 'pipe',
    stderr: 'pipe'
  },

  // Output directories
  outputDir: 'tests/regression/test-results',

  // Global setup and teardown
  globalSetup: './tests/regression/global-setup.js',
  globalTeardown: './tests/regression/global-teardown.js',

  // Test metadata
  metadata: {
    'test-suite': 'Terminal Data Flow Regression',
    'test-type': 'regression',
    'component': 'terminal',
    'focus': 'data-flow-validation'
  }
});