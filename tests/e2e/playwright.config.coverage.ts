import { defineConfig, devices } from '@playwright/test';
import path from 'path';

/**
 * Playwright Configuration for E2E Coverage Collection
 * Enhanced configuration to collect JavaScript coverage during E2E tests
 */
export default defineConfig({
  // Test directory structure
  testDir: './tests/e2e',
  testMatch: ['**/*.spec.ts', '**/*.e2e.ts'],

  // Global test configuration
  fullyParallel: false, // Sequential for consistent coverage
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: process.env.CI ? 1 : 2, // Reduce workers for coverage stability

  // Test timeouts (increased for coverage collection)
  timeout: 90000,
  expect: {
    timeout: 20000,
  },

  // Reporter configuration with coverage support
  reporter: [
    ['html', { outputFolder: 'tests/e2e/reports/coverage-html' }],
    ['json', { outputFile: 'tests/e2e/reports/coverage-results.json' }],
    ['junit', { outputFile: 'tests/e2e/reports/coverage-junit.xml' }],
    ['line'],
    process.env.CI ? ['github'] : ['list'],
  ],

  // Global test options with coverage
  use: {
    // Base URL for the application
    baseURL: process.env.BASE_URL || 'http://localhost:11235',

    // Browser configuration
    headless: process.env.CI ? true : false,
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,

    // Screenshots and videos
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'on-all-tests', // Always collect traces for coverage

    // Extended timeouts for coverage collection
    actionTimeout: 20000,
    navigationTimeout: 45000,

    // Coverage-specific settings
    contextOptions: {
      permissions: ['clipboard-read', 'clipboard-write', 'notifications'],
      // Record coverage data
      recordVideo: {
        mode: 'retain-on-failure',
        size: { width: 1280, height: 720 }
      },
    },
  },

  // Output directories
  outputDir: 'tests/e2e/test-results-coverage/',
  snapshotDir: 'tests/e2e/visual-snapshots-coverage/',

  // Global setup and teardown for coverage
  globalSetup: './tests/e2e/config/coverage-global-setup.ts',
  globalTeardown: './tests/e2e/config/coverage-global-teardown.ts',

  // Test projects optimized for coverage collection
  projects: [
    // Setup project for coverage environment
    {
      name: 'coverage-setup',
      testMatch: /.*\.coverage-setup\.ts/,
      teardown: 'coverage-cleanup',
    },

    // Cleanup project
    {
      name: 'coverage-cleanup',
      testMatch: /.*\.coverage-cleanup\.ts/,
    },

    // Primary coverage collection (Chrome only for consistency)
    {
      name: 'coverage-chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: [
            '--enable-features=VaapiVideoDecoder',
            '--disable-web-security',
            '--allow-running-insecure-content',
            '--disable-features=VizDisplayCompositor',
            // Coverage-specific flags
            '--enable-precise-memory-info',
            '--js-flags="--expose-gc --allow-natives-syntax"',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
          ],
        },
        // Enable JavaScript coverage collection
        contextOptions: {
          recordVideo: { mode: 'retain-on-failure' },
          recordHar: { mode: 'retain-on-failure' },
        }
      },
      dependencies: ['coverage-setup'],
      // Only run core E2E tests for coverage to avoid duplication
      testMatch: [
        '**/terminal/*.spec.ts',
        '**/websocket/*.spec.ts',
        '**/api/*.spec.ts',
        '**/core/*.spec.ts'
      ],
    },

    // API and integration tests (no browser coverage needed)
    {
      name: 'coverage-api',
      use: {
        headless: true,
      },
      testMatch: [
        '**/api/*.spec.ts',
        '**/websocket/*.spec.ts',
        '**/integration/*.spec.ts'
      ],
      dependencies: ['coverage-setup'],
    },
  ],

  // Web server configuration with coverage instrumentation
  webServer: [
    {
      command: 'npm run claude-flow-ui -- --port 11235',
      url: 'http://localhost:11235',
      reuseExistingServer: !process.env.CI,
      timeout: 180 * 1000, // 3 minutes for coverage setup
      env: {
        PORT: '11235',
        NODE_ENV: 'test',
        TERMINAL_SIZE: '120x40',

        // Coverage-specific environment variables
        COVERAGE_ENABLED: 'true',
        NYC_OUTPUT_DIR: path.resolve('./coverage/playwright'),
        COVERAGE_REPORT: 'true',

        // Disable features that might interfere with coverage
        CLAUDE_FLOW_NEURAL: 'false',
        CLAUDE_SPAWN: 'false',

        // Enable debugging for coverage issues
        DEBUG: process.env.COVERAGE_DEBUG ? 'coverage:*' : '',
      },
    },
  ],

  // Metadata for coverage reporting
  metadata: {
    'test-environment': 'coverage',
    'coverage-enabled': 'true',
    'base-url': process.env.BASE_URL || 'http://localhost:11235',
    'ci': !!process.env.CI,
    'node-version': process.version,
  },
});