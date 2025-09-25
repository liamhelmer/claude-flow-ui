/**
 * K6 Performance Testing Configuration
 *
 * Centralized configuration for all performance tests including:
 * - Test scenarios and thresholds
 * - Environment-specific settings
 * - Performance SLA definitions
 * - Custom metrics configuration
 */

// Environment configuration
export const environments = {
  development: {
    baseUrl: 'http://localhost:8080',
    wsUrl: 'ws://localhost:8080/api/ws',
    thresholds: {
      // More lenient thresholds for development
      http_req_duration: ['p(95)<1000', 'p(99)<2000'],
      http_req_failed: ['rate<0.1'],
      ws_connection_time: ['p(95)<3000'],
      ws_message_latency: ['p(95)<200'],
      terminal_io_latency: ['p(95)<800'],
      memory_usage_mb: ['value<1024'],
      cpu_usage_percent: ['avg<90'],
    },
  },

  staging: {
    baseUrl: 'http://staging.claude-flow-ui.com',
    wsUrl: 'ws://staging.claude-flow-ui.com/api/ws',
    thresholds: {
      // Production-like thresholds for staging
      http_req_duration: ['p(95)<500', 'p(99)<1000'],
      http_req_failed: ['rate<0.05'],
      ws_connection_time: ['p(95)<2000'],
      ws_message_latency: ['p(95)<100'],
      terminal_io_latency: ['p(95)<500'],
      memory_usage_mb: ['value<512'],
      cpu_usage_percent: ['avg<80'],
    },
  },

  production: {
    baseUrl: 'https://claude-flow-ui.com',
    wsUrl: 'wss://claude-flow-ui.com/api/ws',
    thresholds: {
      // Strict production thresholds
      http_req_duration: ['p(95)<200', 'p(99)<500'],
      http_req_failed: ['rate<0.02'],
      ws_connection_time: ['p(95)<1000'],
      ws_message_latency: ['p(95)<50'],
      terminal_io_latency: ['p(95)<200'],
      memory_usage_mb: ['value<256'],
      cpu_usage_percent: ['avg<70'],
    },
  },
};

// Test scenario configurations
export const scenarioConfigs = {
  // Load Testing Scenarios
  load: {
    api_load_light: {
      executor: 'constant-vus',
      vus: 5,
      duration: '2m',
      gracefulRampDown: '15s',
    },

    api_load_normal: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '1m', target: 10 },
        { duration: '3m', target: 10 },
        { duration: '1m', target: 0 },
      ],
    },

    websocket_load_normal: {
      executor: 'constant-vus',
      vus: 20,
      duration: '3m',
      gracefulRampDown: '30s',
    },
  },

  // Stress Testing Scenarios
  stress: {
    api_stress_high: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '2m', target: 50 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 150 },
        { duration: '1m', target: 0 },
      ],
    },

    websocket_stress_extreme: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '1m', target: 50 },
        { duration: '3m', target: 200 },
        { duration: '1m', target: 500 },
        { duration: '1m', target: 0 },
      ],
    },

    terminal_io_stress: {
      executor: 'constant-vus',
      vus: 30,
      duration: '5m',
      gracefulRampDown: '30s',
    },
  },

  // Spike Testing Scenarios
  spike: {
    api_spike_sudden: {
      executor: 'ramping-vus',
      startVUs: 5,
      stages: [
        { duration: '1m', target: 5 },
        { duration: '10s', target: 100 },
        { duration: '1m', target: 100 },
        { duration: '10s', target: 5 },
        { duration: '1m', target: 5 },
      ],
    },

    websocket_spike_burst: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      stages: [
        { duration: '30s', target: 50 },
        { duration: '10s', target: 500 },
        { duration: '30s', target: 500 },
        { duration: '10s', target: 50 },
      ],
      preAllocatedVUs: 100,
      maxVUs: 600,
    },
  },

  // Soak Testing Scenarios
  soak: {
    long_duration_stability: {
      executor: 'constant-vus',
      vus: 15,
      duration: '30m',
      gracefulRampDown: '2m',
    },

    memory_leak_detection: {
      executor: 'constant-vus',
      vus: 10,
      duration: '1h',
      gracefulRampDown: '5m',
    },
  },
};

// Performance SLA definitions
export const performanceSLAs = {
  // API Performance SLAs
  api: {
    health_check: {
      availability: 99.9, // 99.9% uptime
      response_time_95th: 50, // 95th percentile under 50ms
      response_time_99th: 100, // 99th percentile under 100ms
    },

    terminal_config: {
      availability: 99.5,
      response_time_95th: 200,
      response_time_99th: 500,
    },

    terminal_operations: {
      availability: 99.0,
      response_time_95th: 300,
      response_time_99th: 1000,
    },
  },

  // WebSocket Performance SLAs
  websocket: {
    connection_establishment: {
      success_rate: 95.0, // 95% connection success rate
      connection_time_95th: 2000, // 95th percentile under 2s
      connection_time_99th: 5000, // 99th percentile under 5s
    },

    message_delivery: {
      success_rate: 98.0, // 98% message delivery rate
      latency_95th: 100, // 95th percentile under 100ms
      latency_99th: 500, // 99th percentile under 500ms
    },

    terminal_data_streaming: {
      throughput_min: 1000, // Minimum 1000 messages/second
      latency_95th: 50, // 95th percentile under 50ms
      data_loss_rate: 0.5, // Less than 0.5% data loss
    },
  },

  // Terminal I/O Performance SLAs
  terminal: {
    command_execution: {
      latency_95th: 200, // 95th percentile under 200ms
      throughput_min: 10, // Minimum 10 commands/second per session
      error_rate: 2.0, // Less than 2% command failures
    },

    large_output_handling: {
      latency_95th: 2000, // Large outputs under 2s
      throughput_min_mb: 1, // Minimum 1MB/s throughput
      buffer_overflow_rate: 5.0, // Less than 5% buffer overflows
    },

    session_switching: {
      latency_95th: 1000, // Session switch under 1s
      success_rate: 98.0, // 98% successful switches
    },
  },

  // Resource Consumption SLAs
  resources: {
    memory_usage: {
      baseline_mb: 100, // Baseline memory usage
      peak_mb: 512, // Peak memory under 512MB
      growth_rate_mb_per_hour: 50, // Less than 50MB/hour growth
      leak_detection_threshold: 10.0, // Less than 10% leak detection
    },

    cpu_usage: {
      average_percent: 70, // Average CPU under 70%
      peak_percent: 90, // Peak CPU under 90%
      sustained_high_duration: 300, // Max 5 minutes of high CPU
    },

    connection_pooling: {
      efficiency_rate: 80.0, // 80%+ connection pool efficiency
      reuse_rate: 60.0, // 60%+ connection reuse
      allocation_latency_95th: 100, // Resource allocation under 100ms
    },
  },
};

// Custom metrics configuration
export const customMetrics = {
  api: [
    'health_check_latency',
    'terminal_config_latency',
    'terminal_ops_latency',
    'api_calls_total',
  ],

  websocket: [
    'ws_connection_time',
    'ws_message_latency',
    'ws_connection_success_rate',
    'ws_message_success_rate',
    'ws_active_connections',
    'terminal_data_latency',
    'session_switch_latency',
  ],

  terminal: [
    'terminal_io_latency',
    'terminal_command_latency',
    'terminal_throughput_bytes',
    'terminal_large_output_latency',
    'terminal_scrollback_latency',
    'terminal_resize_latency',
    'terminal_buffer_overflow_rate',
  ],

  resources: [
    'memory_usage_mb',
    'memory_growth_rate',
    'cpu_usage_percent',
    'gc_pressure_ms',
    'resource_allocation_latency',
    'connection_pool_efficiency',
    'active_resources_count',
  ],
};

// Test execution matrix
export const testMatrix = {
  // Quick smoke test (5 minutes)
  smoke: [
    { test: 'api-load-test.js', scenario: 'load.api_load_light' },
    { test: 'websocket-stress-test.js', scenario: 'load.websocket_load_normal' },
  ],

  // Standard performance test (15 minutes)
  standard: [
    { test: 'api-load-test.js', scenario: 'load.api_load_normal' },
    { test: 'websocket-stress-test.js', scenario: 'load.websocket_load_normal' },
    { test: 'terminal-io-performance.js', scenario: 'load.api_load_normal' },
    { test: 'memory-consumption-test.js', scenario: 'load.api_load_light' },
  ],

  // Comprehensive stress test (45 minutes)
  stress: [
    { test: 'api-load-test.js', scenario: 'stress.api_stress_high' },
    { test: 'websocket-stress-test.js', scenario: 'stress.websocket_stress_extreme' },
    { test: 'terminal-io-performance.js', scenario: 'stress.terminal_io_stress' },
    { test: 'memory-consumption-test.js', scenario: 'stress.api_stress_high' },
  ],

  // Spike resilience test (20 minutes)
  spike: [
    { test: 'api-load-test.js', scenario: 'spike.api_spike_sudden' },
    { test: 'websocket-stress-test.js', scenario: 'spike.websocket_spike_burst' },
  ],

  // Long-duration soak test (1-2 hours)
  soak: [
    { test: 'memory-consumption-test.js', scenario: 'soak.memory_leak_detection' },
    { test: 'websocket-stress-test.js', scenario: 'soak.long_duration_stability' },
    { test: 'terminal-io-performance.js', scenario: 'soak.long_duration_stability' },
  ],
};

// Report configuration
export const reportConfig = {
  formats: ['html', 'json', 'junit'],

  output_paths: {
    html: '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/',
    json: '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/',
    junit: '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/',
  },

  include_details: {
    request_metrics: true,
    custom_metrics: true,
    check_failures: true,
    threshold_violations: true,
    system_resources: true,
  },

  dashboard: {
    enabled: true,
    update_interval: 5, // seconds
    retention_days: 30,
  },
};

// Helper functions
export function getEnvironmentConfig(env = 'development') {
  return environments[env] || environments.development;
}

export function getScenarioConfig(category, scenario) {
  return scenarioConfigs[category]?.[scenario] || null;
}

export function getSLAConfig(category, component) {
  return performanceSLAs[category]?.[component] || null;
}

export function getTestMatrix(testSuite = 'standard') {
  return testMatrix[testSuite] || testMatrix.standard;
}

export function validateSLA(metric, value, category, component) {
  const sla = getSLAConfig(category, component);
  if (!sla) return { valid: true, message: 'No SLA defined' };

  // Example validation logic (extend as needed)
  for (const [slaKey, slaValue] of Object.entries(sla)) {
    if (slaKey.includes('95th') && metric.includes('p95')) {
      if (value > slaValue) {
        return {
          valid: false,
          message: `SLA violation: ${metric} (${value}) exceeds ${slaKey} threshold (${slaValue})`,
        };
      }
    }
  }

  return { valid: true, message: 'SLA met' };
}

// Export configuration object
export default {
  environments,
  scenarioConfigs,
  performanceSLAs,
  customMetrics,
  testMatrix,
  reportConfig,
  getEnvironmentConfig,
  getScenarioConfig,
  getSLAConfig,
  getTestMatrix,
  validateSLA,
};