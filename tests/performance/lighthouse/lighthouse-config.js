/**
 * Lighthouse CI Configuration for Automated Performance Checks
 *
 * This configuration sets up automated performance testing with Lighthouse CI
 * for the Claude Flow UI project, focusing on key performance metrics.
 */

module.exports = {
  ci: {
    collect: {
      // URLs to test
      url: [
        'http://localhost:3000',
        'http://localhost:8080', // Backend server
      ],

      // Collection settings
      numberOfRuns: 3, // Run each URL 3 times for consistency
      settings: {
        // Use desktop configuration for consistent results
        preset: 'desktop',

        // Disable network throttling for local testing
        throttling: {
          rttMs: 0,
          throughputKbps: 0,
          requestLatencyMs: 0,
          downloadThroughputKbps: 0,
          uploadThroughputKbps: 0,
          cpuSlowdownMultiplier: 1,
        },

        // Specific audits for web terminal performance
        onlyAudits: [
          // Core Web Vitals
          'first-contentful-paint',
          'largest-contentful-paint',
          'cumulative-layout-shift',
          'first-input-delay',
          'speed-index',

          // Performance metrics
          'interactive',
          'total-blocking-time',
          'max-potential-fid',

          // Resource optimization
          'unused-javascript',
          'unused-css-rules',
          'render-blocking-resources',
          'unminified-javascript',
          'unminified-css',
          'efficient-animated-content',
          'uses-text-compression',
          'uses-responsive-images',
          'uses-optimized-images',
          'uses-webp-images',
          'uses-rel-preload',
          'uses-rel-preconnect',

          // Terminal-specific performance
          'dom-size',
          'bootup-time',
          'mainthread-work-breakdown',
          'diagnostics',
          'network-rtt',
          'network-server-latency',

          // Best practices
          'uses-https',
          'uses-http2',
          'no-document-write',
          'external-anchors-use-rel-noopener',
          'geolocation-on-start',
          'notification-on-start',
          'no-vulnerable-libraries',

          // Accessibility (important for terminal UI)
          'color-contrast',
          'focus-traps',
          'focusable-controls',
          'interactive-element-affordance',
          'logical-tab-order',
          'managed-focus',
          'offscreen-content-hidden',
          'use-landmarks',
          'valid-lang',
        ],

        // Skip PWA audits as this is not a PWA
        skipAudits: [
          'is-on-https',
          'service-worker',
          'works-offline',
          'viewport',
          'without-javascript',
          'first-meaningful-paint',
          'load-fast-enough-for-pwa',
          'redirects-http',
          'splash-screen',
          'themed-omnibox',
          'maskable-icon',
          'content-width',
        ],

        // Chrome flags for better terminal rendering testing
        chromeFlags: [
          '--headless',
          '--no-sandbox',
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--disable-web-security',
          '--allow-running-insecure-content',
          '--enable-features=VaapiVideoDecoder',
          '--disable-background-timer-throttling',
          '--disable-renderer-backgrounding',
          '--disable-backgrounding-occluded-windows',
          '--disable-ipc-flooding-protection',
        ],
      },

      // Start local server for testing
      startServerCommand: 'npm run dev',
      startServerReadyPattern: 'ready on',
      startServerReadyTimeout: 30000,
    },

    assert: {
      // Performance budget assertions
      assertions: {
        // Core Web Vitals thresholds
        'first-contentful-paint': ['error', { maxNumericValue: 2000 }], // 2s
        'largest-contentful-paint': ['error', { maxNumericValue: 3000 }], // 3s
        'cumulative-layout-shift': ['error', { maxNumericValue: 0.1 }], // 0.1
        'speed-index': ['error', { maxNumericValue: 4000 }], // 4s
        'interactive': ['error', { maxNumericValue: 5000 }], // 5s
        'total-blocking-time': ['warn', { maxNumericValue: 300 }], // 300ms

        // Resource optimization thresholds
        'unused-javascript': ['warn', { maxNumericValue: 20 }], // 20% unused JS
        'unused-css-rules': ['warn', { maxNumericValue: 20 }], // 20% unused CSS
        'render-blocking-resources': ['warn', { maxNumericValue: 1000 }], // 1s blocking

        // Terminal-specific thresholds
        'dom-size': ['warn', { maxNumericValue: 1500 }], // 1500 DOM nodes
        'bootup-time': ['error', { maxNumericValue: 3000 }], // 3s script evaluation
        'mainthread-work-breakdown': ['warn', { maxNumericValue: 4000 }], // 4s main thread work

        // Overall performance score
        'categories:performance': ['error', { minScore: 0.8 }], // 80% performance score
        'categories:accessibility': ['warn', { minScore: 0.9 }], // 90% accessibility score
        'categories:best-practices': ['warn', { minScore: 0.9 }], // 90% best practices score
      },
    },

    upload: {
      // Store results locally for now
      target: 'filesystem',
      outputDir: './tests/performance/lighthouse/reports',

      // GitHub integration (uncomment when ready)
      // target: 'github',
      // githubToken: process.env.LHCI_GITHUB_APP_TOKEN,
      // githubAppToken: process.env.LHCI_GITHUB_APP_TOKEN,
      // repo: 'liamhelmer/claude-flow-ui',
    },

    server: {
      // Optional: use LHCI server for result storage
      // baseURL: 'https://your-lhci-server.com',
      // basicAuth: {
      //   username: process.env.LHCI_BASIC_AUTH_USERNAME,
      //   password: process.env.LHCI_BASIC_AUTH_PASSWORD,
      // },
    },
  },

  // Custom performance categories for terminal applications
  extends: 'lighthouse:default',

  settings: {
    // Additional settings for terminal performance testing
    emulatedFormFactor: 'desktop',
    throttling: {
      rttMs: 0,
      throughputKbps: 0,
      cpuSlowdownMultiplier: 1,
    },

    // Longer timeout for terminal initialization
    maxWaitForLoad: 45000,

    // Custom audit categories
    categories: {
      performance: {
        title: 'Terminal Performance',
        description: 'Performance metrics for web terminal applications',
        auditRefs: [
          { id: 'first-contentful-paint', weight: 10 },
          { id: 'largest-contentful-paint', weight: 25 },
          { id: 'speed-index', weight: 10 },
          { id: 'interactive', weight: 10 },
          { id: 'total-blocking-time', weight: 30 },
          { id: 'cumulative-layout-shift', weight: 5 },
          { id: 'bootup-time', weight: 5 },
          { id: 'mainthread-work-breakdown', weight: 5 },
        ],
      },

      'terminal-optimization': {
        title: 'Terminal Optimization',
        description: 'Specific optimizations for terminal rendering',
        auditRefs: [
          { id: 'dom-size', weight: 20 },
          { id: 'unused-javascript', weight: 20 },
          { id: 'render-blocking-resources', weight: 20 },
          { id: 'efficient-animated-content', weight: 15 },
          { id: 'uses-text-compression', weight: 10 },
          { id: 'unminified-javascript', weight: 10 },
          { id: 'uses-rel-preload', weight: 5 },
        ],
      },
    },
  },
};

// Export additional configuration for programmatic use
module.exports.performanceThresholds = {
  // Critical thresholds that will fail CI
  critical: {
    'first-contentful-paint': 2000,
    'largest-contentful-paint': 3000,
    'cumulative-layout-shift': 0.1,
    'interactive': 5000,
    'categories:performance': 0.8,
  },

  // Warning thresholds
  warning: {
    'speed-index': 4000,
    'total-blocking-time': 300,
    'unused-javascript': 20,
    'dom-size': 1500,
    'categories:accessibility': 0.9,
    'categories:best-practices': 0.9,
  },
};

// Terminal-specific performance recommendations
module.exports.terminalOptimizations = {
  xterm: {
    recommendations: [
      'Use WebGL renderer for better performance',
      'Enable canvas fallback for compatibility',
      'Implement virtual scrolling for large buffers',
      'Use requestAnimationFrame for smooth rendering',
      'Batch DOM updates to minimize reflows',
    ],
  },

  websocket: {
    recommendations: [
      'Implement message batching to reduce overhead',
      'Use binary frames for large data transfers',
      'Implement compression for text data',
      'Add connection pooling for multiple terminals',
      'Use ping/pong frames for connection health',
    ],
  },

  react: {
    recommendations: [
      'Use React.memo for terminal components',
      'Implement virtual scrolling for terminal history',
      'Use useCallback for event handlers',
      'Implement proper cleanup in useEffect',
      'Use React DevTools Profiler for optimization',
    ],
  },
};