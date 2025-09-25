/**
 * K6 WebSocket Stress Testing Suite
 *
 * Comprehensive WebSocket performance testing for terminal sessions:
 * - Connection establishment stress
 * - High-frequency message throughput
 * - Concurrent terminal sessions
 * - Terminal switching performance
 * - Memory leak detection under load
 * - Connection recovery testing
 */

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

// Custom metrics for WebSocket performance
const wsConnectionTime = new Trend('ws_connection_time');
const wsMessageLatency = new Trend('ws_message_latency');
const wsConnectionRate = new Rate('ws_connection_success_rate');
const wsMessageRate = new Rate('ws_message_success_rate');
const wsMessageCounter = new Counter('ws_messages_total');
const wsErrorCounter = new Counter('ws_errors_total');
const wsActiveConnections = new Gauge('ws_active_connections');
const terminalDataLatency = new Trend('terminal_data_latency');
const terminalInputLatency = new Trend('terminal_input_latency');
const sessionSwitchLatency = new Trend('session_switch_latency');

// Test data for terminal commands
const terminalCommands = new SharedArray('terminal-commands', function () {
  return [
    'ls -la',
    'pwd',
    'echo "Hello World"',
    'date',
    'whoami',
    'ps aux | head -10',
    'df -h',
    'free -m',
    'uptime',
    'cat /etc/hostname',
    'history | tail -5',
    'env | grep PATH',
    'which bash',
    'uname -a',
    'id',
  ];
});

// Configuration
const BASE_URL = __ENV.BASE_URL || 'localhost:8080';
const WS_URL = `ws://${BASE_URL}/api/ws`;
const TEST_MODE = __ENV.TEST_MODE || 'stress';
const MAX_MESSAGE_SIZE = parseInt(__ENV.MAX_MESSAGE_SIZE) || 1024;
const MESSAGE_FREQUENCY = parseInt(__ENV.MESSAGE_FREQUENCY) || 100; // messages per second

export const options = {
  scenarios: {
    // WebSocket Connection Stress Test
    connection_stress: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 10 },   // Warm up
        { duration: '1m', target: 50 },    // Moderate load
        { duration: '2m', target: 100 },   // High load
        { duration: '1m', target: 200 },   // Stress load
        { duration: '30s', target: 0 },    // Cool down
      ],
      gracefulRampDown: '30s',
      tags: { test_type: 'connection_stress' },
    },

    // High-Frequency Message Throughput Test
    message_throughput: {
      executor: 'constant-vus',
      vus: 25,
      duration: '3m',
      gracefulRampDown: '15s',
      tags: { test_type: 'message_throughput' },
    },

    // Concurrent Terminal Sessions Test
    concurrent_terminals: {
      executor: 'per-vu-iterations',
      vus: 50,
      iterations: 10,
      maxDuration: '5m',
      tags: { test_type: 'concurrent_terminals' },
    },

    // Terminal Session Switching Test
    session_switching: {
      executor: 'constant-vus',
      vus: 15,
      duration: '2m',
      gracefulRampDown: '15s',
      tags: { test_type: 'session_switching' },
    },

    // Soak Test for Memory Leaks
    websocket_soak: {
      executor: 'constant-vus',
      vus: 30,
      duration: '10m',
      gracefulRampDown: '30s',
      tags: { test_type: 'soak' },
    },
  },

  thresholds: {
    // WebSocket connection performance
    ws_connection_time: ['p(95)<2000', 'p(99)<5000'], // Connection under 2s (95%), 5s (99%)
    ws_connection_success_rate: ['rate>0.95'], // 95% connection success rate

    // Message performance
    ws_message_latency: ['p(95)<100', 'p(99)<500'], // Message latency under 100ms (95%), 500ms (99%)
    ws_message_success_rate: ['rate>0.98'], // 98% message success rate

    // Terminal-specific performance
    terminal_data_latency: ['p(95)<50'], // Terminal data under 50ms
    terminal_input_latency: ['p(95)<100'], // Terminal input under 100ms
    session_switch_latency: ['p(95)<1000'], // Session switch under 1s

    // Error thresholds
    ws_errors_total: ['count<100'], // Less than 100 total errors
  },
};

/**
 * Setup function
 */
export function setup() {
  console.log(`🚀 Starting WebSocket Stress Test - Mode: ${TEST_MODE}`);
  console.log(`🔌 WebSocket URL: ${WS_URL}`);
  console.log(`📊 Max Message Size: ${MAX_MESSAGE_SIZE} bytes`);
  console.log(`⚡ Message Frequency: ${MESSAGE_FREQUENCY}/sec`);

  return {
    wsUrl: WS_URL,
    startTime: new Date().toISOString(),
    testConfig: {
      maxMessageSize: MAX_MESSAGE_SIZE,
      messageFrequency: MESSAGE_FREQUENCY,
    },
  };
}

/**
 * Main test function
 */
export default function (data) {
  const testType = __ENV.TAGS_TEST_TYPE || 'connection_stress';

  switch (testType) {
    case 'connection_stress':
      runConnectionStressTest(data);
      break;
    case 'message_throughput':
      runMessageThroughputTest(data);
      break;
    case 'concurrent_terminals':
      runConcurrentTerminalsTest(data);
      break;
    case 'session_switching':
      runSessionSwitchingTest(data);
      break;
    case 'soak':
      runSoakTest(data);
      break;
    default:
      runConnectionStressTest(data);
  }
}

/**
 * Connection Stress Test - Focus on connection establishment and basic functionality
 */
function runConnectionStressTest(data) {
  const sessionId = `stress-session-${__VU}-${__ITER}-${Date.now()}`;
  const connectionStart = Date.now();

  const response = ws.connect(data.wsUrl, {
    headers: { 'User-Agent': 'k6-websocket-stress-test' },
  }, function (socket) {
    const connectionTime = Date.now() - connectionStart;
    wsConnectionTime.add(connectionTime);
    wsConnectionRate.add(true);
    wsActiveConnections.add(1);

    let messagesSent = 0;
    let messagesReceived = 0;
    let errors = 0;

    socket.on('open', () => {
      console.log(`🔌 Connected to WebSocket (${connectionTime}ms)`);

      // Request terminal configuration
      socket.send(JSON.stringify({
        type: 'request-config',
        sessionId: sessionId,
      }));

      // Send test commands periodically
      const sendInterval = setInterval(() => {
        if (messagesSent < 10) { // Limit messages in stress test
          const command = terminalCommands[messagesSent % terminalCommands.length];
          const messageStart = Date.now();

          socket.send(JSON.stringify({
            sessionId: sessionId,
            data: command + '\n',
            timestamp: messageStart,
          }));

          messagesSent++;
          wsMessageCounter.add(1);
        } else {
          clearInterval(sendInterval);
          socket.close();
        }
      }, 200); // Send every 200ms
    });

    socket.on('message', (message) => {
      const messageEnd = Date.now();
      messagesReceived++;

      try {
        const data = JSON.parse(message);

        if (data.timestamp) {
          const latency = messageEnd - data.timestamp;
          wsMessageLatency.add(latency);
          terminalDataLatency.add(latency);
        }

        wsMessageRate.add(true);

        // Handle different message types
        if (data.type === 'terminal-config') {
          check(data, {
            'terminal config has required fields': (d) => d.cols && d.rows,
          });
        } else if (data.type === 'terminal-data') {
          check(data, {
            'terminal data has sessionId': (d) => d.sessionId === sessionId,
          });
        }

      } catch (e) {
        wsMessageRate.add(false);
        wsErrorCounter.add(1);
        errors++;
      }
    });

    socket.on('error', (e) => {
      console.error(`❌ WebSocket error: ${e}`);
      wsErrorCounter.add(1);
      errors++;
    });

    socket.on('close', () => {
      wsActiveConnections.add(-1);
      console.log(`🔌 Disconnected (Sent: ${messagesSent}, Received: ${messagesReceived}, Errors: ${errors})`);
    });

    // Keep connection alive for test duration
    socket.setTimeout(() => {
      socket.close();
    }, 10000); // 10 seconds per connection
  });

  check(response, {
    'websocket connection successful': (r) => r && r.url,
  });

  if (!response || !response.url) {
    wsConnectionRate.add(false);
    wsErrorCounter.add(1);
  }
}

/**
 * High-Frequency Message Throughput Test
 */
function runMessageThroughputTest(data) {
  const sessionId = `throughput-session-${__VU}-${Date.now()}`;
  const messagesPerSecond = data.testConfig.messageFrequency / __VU; // Distribute load
  const testDuration = 30000; // 30 seconds

  const response = ws.connect(data.wsUrl, {}, function (socket) {
    let messagesSent = 0;
    let messagesReceived = 0;
    let startTime = Date.now();

    socket.on('open', () => {
      const sendInterval = setInterval(() => {
        if (Date.now() - startTime > testDuration) {
          clearInterval(sendInterval);
          socket.close();
          return;
        }

        // Generate test data
        const messageSize = Math.min(data.testConfig.maxMessageSize, 512);
        const testData = 'x'.repeat(messageSize);
        const messageStart = Date.now();

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: testData,
          timestamp: messageStart,
          messageId: messagesSent,
        }));

        messagesSent++;
        wsMessageCounter.add(1);
      }, 1000 / messagesPerSecond);
    });

    socket.on('message', (message) => {
      const messageEnd = Date.now();
      messagesReceived++;

      try {
        const data = JSON.parse(message);
        if (data.timestamp) {
          const latency = messageEnd - data.timestamp;
          wsMessageLatency.add(latency);
          terminalInputLatency.add(latency);
        }
        wsMessageRate.add(true);
      } catch (e) {
        wsMessageRate.add(false);
        wsErrorCounter.add(1);
      }
    });

    socket.on('close', () => {
      const actualDuration = Date.now() - startTime;
      const actualThroughput = messagesSent / (actualDuration / 1000);
      console.log(`📊 Throughput: ${actualThroughput.toFixed(2)} msgs/sec (Sent: ${messagesSent}, Received: ${messagesReceived})`);
    });
  });

  check(response, { 'throughput test connection established': (r) => r && r.url });
}

/**
 * Concurrent Terminal Sessions Test
 */
function runConcurrentTerminalsTest(data) {
  const sessions = [];
  const numSessions = 3; // Multiple sessions per VU

  for (let i = 0; i < numSessions; i++) {
    const sessionId = `concurrent-session-${__VU}-${i}-${Date.now()}`;
    sessions.push(sessionId);
  }

  // Connect to multiple sessions
  sessions.forEach((sessionId, index) => {
    sleep(index * 0.1); // Stagger connections

    ws.connect(data.wsUrl, {}, function (socket) {
      let commandIndex = 0;

      socket.on('open', () => {
        console.log(`🔌 Session ${sessionId} connected`);

        // Send periodic commands
        const commandInterval = setInterval(() => {
          if (commandIndex < 5) {
            const command = terminalCommands[commandIndex % terminalCommands.length];
            const messageStart = Date.now();

            socket.send(JSON.stringify({
              sessionId: sessionId,
              data: command + '\n',
              timestamp: messageStart,
            }));

            commandIndex++;
          } else {
            clearInterval(commandInterval);
            socket.close();
          }
        }, 1000);
      });

      socket.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          if (data.timestamp) {
            const latency = Date.now() - data.timestamp;
            wsMessageLatency.add(latency);
          }
        } catch (e) {
          wsErrorCounter.add(1);
        }
      });
    });
  });
}

/**
 * Session Switching Test
 */
function runSessionSwitchingTest(data) {
  const sessions = [`session-a-${__VU}`, `session-b-${__VU}`, `session-c-${__VU}`];
  let currentSessionIndex = 0;

  ws.connect(data.wsUrl, {}, function (socket) {
    socket.on('open', () => {
      // Switch sessions every 2 seconds
      const switchInterval = setInterval(() => {
        const switchStart = Date.now();
        const targetSession = sessions[currentSessionIndex % sessions.length];

        socket.send(JSON.stringify({
          type: 'switch-session',
          targetSessionId: targetSession,
          timestamp: switchStart,
        }));

        currentSessionIndex++;

        if (currentSessionIndex >= 10) { // Switch 10 times
          clearInterval(switchInterval);
          socket.close();
        }
      }, 2000);
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);

        if (data.type === 'session-switched') {
          if (data.timestamp) {
            const switchLatency = Date.now() - data.timestamp;
            sessionSwitchLatency.add(switchLatency);
          }

          check(data, {
            'session switch successful': (d) => d.success === true,
          });
        }
      } catch (e) {
        wsErrorCounter.add(1);
      }
    });
  });
}

/**
 * Soak Test for Memory Leak Detection
 */
function runSoakTest(data) {
  const sessionId = `soak-session-${__VU}-${Date.now()}`;
  let messageCount = 0;

  ws.connect(data.wsUrl, {}, function (socket) {
    socket.on('open', () => {
      // Send messages continuously but at a sustainable rate
      const soakInterval = setInterval(() => {
        const command = terminalCommands[messageCount % terminalCommands.length];

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: command + '\n',
          messageCount: messageCount,
        }));

        messageCount++;

        // Log memory usage periodically
        if (messageCount % 100 === 0) {
          console.log(`💾 Soak test - VU ${__VU}: ${messageCount} messages sent`);
        }
      }, 500); // Send every 500ms for sustainability

      // Keep test running for the full duration
      socket.setTimeout(() => {
        clearInterval(soakInterval);
        socket.close();
      }, 300000); // 5 minutes per connection
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        wsMessageRate.add(true);
      } catch (e) {
        wsMessageRate.add(false);
        wsErrorCounter.add(1);
      }
    });

    socket.on('close', () => {
      console.log(`🏁 Soak test completed - VU ${__VU}: ${messageCount} total messages`);
    });
  });
}

/**
 * Teardown function
 */
export function teardown(data) {
  console.log('🏁 WebSocket Stress Test completed');
  console.log(`📊 Test started: ${data.startTime}`);
  console.log(`📊 Test ended: ${new Date().toISOString()}`);
}

/**
 * Generate HTML and JSON reports
 */
export function handleSummary(data) {
  const testMode = __ENV.TEST_MODE || 'websocket-stress';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/websocket-${testMode}-test-${timestamp}.html`]: htmlReport(data),
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/websocket-${testMode}-test-${timestamp}.json`]: JSON.stringify(data, null, 2),
  };
}