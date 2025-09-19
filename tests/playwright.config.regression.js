/**
 * Playwright Configuration for Terminal Input Regression Tests
 */

module.exports = {
  testDir: './tests',
  testMatch: '**/terminal-input-regression.test.ts',
  timeout: 120000, // 2 minutes per test
  fullyParallel: false, // Run tests sequentially to avoid port conflicts
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: 1, // Single worker to avoid server conflicts
  reporter: [
    ['list'],
    ['html', { outputFolder: 'tests/results/regression-html' }],
    ['json', { outputFile: 'tests/results/regression-results.json' }]
  ],
  outputDir: 'tests/results/artifacts',
  use: {
    // Global test settings
    actionTimeout: 30000,
    navigationTimeout: 30000,
    baseURL: 'http://localhost:11242',

    // Browser settings optimized for terminal testing
    headless: false, // Keep visible to see input behavior
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,

    // Recording settings for debugging
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',

    // Terminal-specific settings
    launchOptions: {
      slowMo: 100, // Slow down for better visibility
      args: [
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor'
      ]
    }
  },

  projects: [
    {
      name: 'chromium-desktop',
      use: {
        ...require('@playwright/test').devices['Desktop Chrome'],
        contextOptions: {
          // Enable clipboard access for paste tests
          permissions: ['clipboard-read', 'clipboard-write']
        }
      },
    },

    // Optionally test in different browsers
    // {
    //   name: 'firefox',
    //   use: { ...require('@playwright/test').devices['Desktop Firefox'] },
    // },
  ],

  // Global setup/teardown
  globalSetup: require.resolve('./tests/global-setup.js'),
  globalTeardown: require.resolve('./tests/global-teardown.js'),

  // Configure test environment
  webServer: {
    // We'll start our own server in tests, so disable built-in server
    command: 'echo "Server will be started by tests"',
    port: 11242,
    reuseExistingServer: false,
  },

  expect: {
    // Longer timeouts for terminal operations
    timeout: 10000,

    // Softer assertions for terminal content (content may load gradually)
    toMatchSnapshot: {
      threshold: 0.3,
      mode: 'percent'
    }
  }
};