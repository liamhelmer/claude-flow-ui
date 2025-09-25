/**
 * K6 REST API Load Testing Suite
 *
 * Tests all REST API endpoints with various load patterns:
 * - Load Testing (normal expected traffic)
 * - Stress Testing (beyond normal capacity)
 * - Spike Testing (sudden traffic bursts)
 * - Soak Testing (sustained load over time)
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

// Custom metrics
const errorRate = new Rate('error_rate');
const responseTimeTrend = new Trend('response_time');
const apiCallsCounter = new Counter('api_calls_total');
const terminalConfigLatency = new Trend('terminal_config_latency');
const healthCheckLatency = new Trend('health_check_latency');
const terminalOpsLatency = new Trend('terminal_ops_latency');

// Test data
const testData = new SharedArray('test-data', function () {
  return [
    { sessionId: 'session-001', name: 'Terminal 1' },
    { sessionId: 'session-002', name: 'Terminal 2' },
    { sessionId: 'session-003', name: 'Terminal 3' },
    { sessionId: 'session-004', name: 'Terminal 4' },
    { sessionId: 'session-005', name: 'Terminal 5' },
  ];
});

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TEST_MODE = __ENV.TEST_MODE || 'load';

// Test scenarios configuration
export const options = {
  scenarios: {
    // Load Testing - Normal expected traffic
    load_test: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '1m', target: 10 },  // Ramp up to 10 VUs
        { duration: '3m', target: 10 },  // Stay at 10 VUs
        { duration: '1m', target: 0 },   // Ramp down
      ],
      gracefulRampDown: '30s',
      tags: { test_type: 'load' },
    },

    // Stress Testing - Beyond normal capacity
    stress_test: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '2m', target: 50 },   // Ramp up to 50 VUs
        { duration: '5m', target: 50 },   // Stay at 50 VUs
        { duration: '2m', target: 100 },  // Increase to 100 VUs
        { duration: '5m', target: 100 },  // Stay at 100 VUs
        { duration: '2m', target: 0 },    // Ramp down
      ],
      gracefulRampDown: '30s',
      tags: { test_type: 'stress' },
    },

    // Spike Testing - Sudden traffic bursts
    spike_test: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 5 },    // Baseline
        { duration: '10s', target: 200 },  // Sudden spike
        { duration: '1m', target: 200 },   // Sustain spike
        { duration: '10s', target: 5 },    // Return to baseline
        { duration: '30s', target: 5 },    // Maintain baseline
        { duration: '10s', target: 0 },    // Ramp down
      ],
      gracefulRampDown: '30s',
      tags: { test_type: 'spike' },
    },

    // Soak Testing - Extended duration at normal load
    soak_test: {
      executor: 'constant-vus',
      vus: 20,
      duration: '10m',
      gracefulRampDown: '30s',
      tags: { test_type: 'soak' },
    },
  },

  thresholds: {
    // Overall performance thresholds
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% under 500ms, 99% under 1s
    http_req_failed: ['rate<0.05'], // Error rate under 5%
    error_rate: ['rate<0.05'],

    // API-specific thresholds
    'http_req_duration{endpoint:health}': ['p(95)<100'], // Health check under 100ms
    'http_req_duration{endpoint:terminal_config}': ['p(95)<200'], // Terminal config under 200ms
    'http_req_duration{endpoint:terminals}': ['p(95)<300'], // Terminal operations under 300ms

    // Custom metric thresholds
    terminal_config_latency: ['p(95)<200'],
    health_check_latency: ['p(95)<50'],
    terminal_ops_latency: ['p(95)<300'],
  },

  // Report generation
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  summaryTimeUnit: 'ms',
};

/**
 * Setup function - runs once before all VUs
 */
export function setup() {
  console.log(`🚀 Starting API Load Test - Mode: ${TEST_MODE}`);
  console.log(`📊 Base URL: ${BASE_URL}`);

  // Verify server is accessible
  const response = http.get(`${BASE_URL}/api/health`);
  if (response.status !== 200) {
    throw new Error(`Server not accessible. Status: ${response.status}`);
  }

  console.log('✅ Server accessibility verified');

  return {
    baseUrl: BASE_URL,
    startTime: new Date().toISOString(),
  };
}

/**
 * Main test function - runs for each VU iteration
 */
export default function (data) {
  const testSession = testData[Math.floor(Math.random() * testData.length)];

  // Test health endpoint (most critical)
  testHealthEndpoint();

  // Test terminal configuration endpoints
  testTerminalConfigEndpoints(testSession.sessionId);

  // Test terminal management endpoints
  testTerminalManagementEndpoints(testSession);

  // Test WebSocket endpoint info
  testWebSocketEndpoint();

  // Random sleep between 0.5-2 seconds to simulate real user behavior
  sleep(Math.random() * 1.5 + 0.5);
}

/**
 * Test health check endpoint
 */
function testHealthEndpoint() {
  const response = http.get(`${BASE_URL}/api/health`, {
    tags: { endpoint: 'health' },
  });

  const success = check(response, {
    'health check status is 200': (r) => r.status === 200,
    'health check response time < 100ms': (r) => r.timings.duration < 100,
    'health check has correct structure': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.status === 'ok' &&
               body.timestamp &&
               body.services &&
               body.services.api === 'running';
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  healthCheckLatency.add(response.timings.duration);
  apiCallsCounter.add(1);
}

/**
 * Test terminal configuration endpoints
 */
function testTerminalConfigEndpoints(sessionId) {
  // Test default terminal config
  let response = http.get(`${BASE_URL}/api/terminal-config`, {
    tags: { endpoint: 'terminal_config' },
  });

  let success = check(response, {
    'terminal config status is 200': (r) => r.status === 200,
    'terminal config response time < 200ms': (r) => r.timings.duration < 200,
    'terminal config has required fields': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.cols && body.rows && body.theme && body.scrollback;
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  terminalConfigLatency.add(response.timings.duration);
  apiCallsCounter.add(1);

  // Test session-specific terminal config
  response = http.get(`${BASE_URL}/api/terminal-config/${sessionId}`, {
    tags: { endpoint: 'terminal_config' },
  });

  success = check(response, {
    'session terminal config status is 200': (r) => r.status === 200,
    'session terminal config has sessionId': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.sessionId === sessionId;
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  terminalConfigLatency.add(response.timings.duration);
  apiCallsCounter.add(1);
}

/**
 * Test terminal management endpoints
 */
function testTerminalManagementEndpoints(testSession) {
  // Test list terminals
  let response = http.get(`${BASE_URL}/api/terminals`, {
    tags: { endpoint: 'terminals' },
  });

  let success = check(response, {
    'terminals list status is 200': (r) => r.status === 200,
    'terminals list response time < 300ms': (r) => r.timings.duration < 300,
    'terminals list returns array': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body);
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  terminalOpsLatency.add(response.timings.duration);
  apiCallsCounter.add(1);

  // Test spawn terminal (POST)
  const spawnPayload = {
    command: '/bin/bash',
    name: testSession.name,
  };

  response = http.post(
    `${BASE_URL}/api/terminals/spawn`,
    JSON.stringify(spawnPayload),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { endpoint: 'terminals' },
    }
  );

  let spawnedTerminalId = null;
  success = check(response, {
    'terminal spawn status is 201': (r) => r.status === 201,
    'terminal spawn response time < 500ms': (r) => r.timings.duration < 500,
    'terminal spawn returns terminal info': (r) => {
      try {
        const body = JSON.parse(r.body);
        if (body.id && body.name && body.command) {
          spawnedTerminalId = body.id;
          return true;
        }
        return false;
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  terminalOpsLatency.add(response.timings.duration);
  apiCallsCounter.add(1);

  // Clean up: delete the spawned terminal (if it was created successfully)
  if (spawnedTerminalId) {
    // Wait a bit before deletion
    sleep(0.1);

    response = http.del(`${BASE_URL}/api/terminals/${spawnedTerminalId}`, {
      tags: { endpoint: 'terminals' },
    });

    success = check(response, {
      'terminal delete status is 200 or 404': (r) => r.status === 200 || r.status === 404,
    });

    errorRate.add(!success);
    terminalOpsLatency.add(response.timings.duration);
    apiCallsCounter.add(1);
  }
}

/**
 * Test WebSocket endpoint info
 */
function testWebSocketEndpoint() {
  const response = http.get(`${BASE_URL}/api/ws`, {
    tags: { endpoint: 'websocket' },
  });

  const success = check(response, {
    'websocket endpoint info status is 200': (r) => r.status === 200,
    'websocket endpoint has correct info': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.message === 'WebSocket endpoint' &&
               body.path === '/api/ws' &&
               body.protocol === 'socket.io';
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  apiCallsCounter.add(1);
}

/**
 * Teardown function - runs once after all VUs complete
 */
export function teardown(data) {
  console.log('🏁 API Load Test completed');
  console.log(`📊 Test started: ${data.startTime}`);
  console.log(`📊 Test ended: ${new Date().toISOString()}`);
}

/**
 * Generate HTML report
 */
export function handleSummary(data) {
  const testMode = __ENV.TEST_MODE || 'load';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/api-${testMode}-test-${timestamp}.html`]: htmlReport(data),
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/api-${testMode}-test-${timestamp}.json`]: JSON.stringify(data, null, 2),
  };
}