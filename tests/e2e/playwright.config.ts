import { defineConfig, devices } from '@playwright/test';
import path from 'path';

/**
 * Comprehensive Playwright E2E Testing Configuration
 * Supports multi-browser testing, visual regression, performance monitoring,
 * and accessibility validation for claude-flow-ui
 */
export default defineConfig({
  // Test directory structure
  testDir: './tests/e2e',
  testMatch: ['**/*.spec.ts', '**/*.e2e.ts'],

  // Global test configuration
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 3 : 1,
  workers: process.env.CI ? 2 : undefined,

  // Test timeouts
  timeout: 60000,
  expect: {
    timeout: 15000,
  },

  // Reporter configuration
  reporter: [
    ['html', { outputFolder: 'tests/e2e/reports/html' }],
    ['json', { outputFile: 'tests/e2e/reports/test-results.json' }],
    ['junit', { outputFile: 'tests/e2e/reports/junit.xml' }],
    ['line'],
    process.env.CI ? ['github'] : ['list'],
  ],

  // Global test options
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
    trace: 'retain-on-failure',

    // Additional options
    actionTimeout: 15000,
    navigationTimeout: 30000,

    // Custom properties for our tests
    contextOptions: {
      // Grant permissions needed for clipboard, notifications, etc.
      permissions: ['clipboard-read', 'clipboard-write', 'notifications'],
    },
  },

  // Output directories
  outputDir: 'tests/e2e/test-results/',
  snapshotDir: 'tests/e2e/visual-snapshots/',

  // Global setup and teardown
  globalSetup: './tests/e2e/config/global-setup.ts',
  globalTeardown: './tests/e2e/config/global-teardown.ts',

  // Test projects for different browsers and scenarios
  projects: [
    // Setup project for authentication and initial state
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
      teardown: 'cleanup',
    },

    // Cleanup project
    {
      name: 'cleanup',
      testMatch: /.*\.cleanup\.ts/,
    },

    // Desktop Chrome (Primary)
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Enable additional Chrome features for terminal testing
        launchOptions: {
          args: [
            '--enable-features=VaapiVideoDecoder',
            '--disable-web-security',
            '--allow-running-insecure-content',
            '--disable-features=VizDisplayCompositor',
          ],
        },
      },
      dependencies: ['setup'],
    },

    // Desktop Firefox
    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        // Firefox-specific configuration for terminal compatibility
        launchOptions: {
          firefoxUserPrefs: {
            'dom.webnotifications.enabled': true,
            'media.navigator.streams.fake': true,
          },
        },
      },
      dependencies: ['setup'],
    },

    // Desktop Safari
    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
        // Safari-specific configuration
      },
      dependencies: ['setup'],
    },

    // Mobile Chrome (Responsive testing)
    {
      name: 'mobile-chrome',
      use: {
        ...devices['Pixel 5'],
      },
      dependencies: ['setup'],
      testMatch: ['**/mobile/*.spec.ts', '**/responsive/*.spec.ts'],
    },

    // Mobile Safari (iOS testing)
    {
      name: 'mobile-safari',
      use: {
        ...devices['iPhone 12'],
      },
      dependencies: ['setup'],
      testMatch: ['**/mobile/*.spec.ts', '**/responsive/*.spec.ts'],
    },

    // Tablet testing
    {
      name: 'tablet',
      use: {
        ...devices['iPad Pro'],
      },
      dependencies: ['setup'],
      testMatch: ['**/tablet/*.spec.ts', '**/responsive/*.spec.ts'],
    },

    // High DPI testing
    {
      name: 'high-dpi',
      use: {
        ...devices['Desktop Chrome HiDPI'],
      },
      dependencies: ['setup'],
      testMatch: ['**/visual/*.spec.ts'],
    },

    // Performance testing (Chrome only for consistent metrics)
    {
      name: 'performance',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: ['--enable-precise-memory-info'],
        },
      },
      dependencies: ['setup'],
      testMatch: ['**/performance/*.spec.ts'],
    },

    // Accessibility testing
    {
      name: 'accessibility',
      use: {
        ...devices['Desktop Chrome'],
      },
      dependencies: ['setup'],
      testMatch: ['**/accessibility/*.spec.ts'],
    },

    // Visual regression testing
    {
      name: 'visual',
      use: {
        ...devices['Desktop Chrome'],
        // Consistent rendering for visual tests
        viewport: { width: 1280, height: 720 },
        deviceScaleFactor: 1,
      },
      dependencies: ['setup'],
      testMatch: ['**/visual/*.spec.ts'],
    },

    // API and WebSocket testing (no UI)
    {
      name: 'api',
      use: {
        // No browser needed for API tests
        headless: true,
      },
      testMatch: ['**/api/*.spec.ts', '**/websocket/*.spec.ts'],
    },
  ],

  // Web server configuration
  webServer: [
    {
      command: 'npm run claude-flow-ui -- --port 11235',
      url: 'http://localhost:11235',
      reuseExistingServer: !process.env.CI,
      timeout: 120 * 1000, // 2 minutes
      env: {
        PORT: '11235',
        NODE_ENV: 'test',
        TERMINAL_SIZE: '120x40',
        // Disable some features for testing stability
        CLAUDE_FLOW_NEURAL: 'false',
        CLAUDE_SPAWN: 'false',
      },
    },
  ],

  // Metadata for test reporting
  metadata: {
    'test-environment': process.env.NODE_ENV || 'test',
    'base-url': process.env.BASE_URL || 'http://localhost:11235',
    'ci': !!process.env.CI,
  },
});