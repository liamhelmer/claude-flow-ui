/**
 * K6 Terminal I/O Performance Testing Suite
 *
 * High-frequency terminal I/O operations testing:
 * - Large file output streaming
 * - Rapid command execution
 * - Terminal scrollback performance
 * - Buffer overflow handling
 * - Terminal resizing under load
 * - High-throughput data processing
 */

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

// Custom metrics for terminal I/O performance
const terminalIOLatency = new Trend('terminal_io_latency');
const terminalThroughput = new Counter('terminal_throughput_bytes');
const terminalCommandLatency = new Trend('terminal_command_latency');
const terminalScrollbackLatency = new Trend('terminal_scrollback_latency');
const terminalResizeLatency = new Trend('terminal_resize_latency');
const terminalBufferOverflowRate = new Rate('terminal_buffer_overflow_rate');
const terminalIOErrorRate = new Rate('terminal_io_error_rate');
const terminalActiveStreams = new Gauge('terminal_active_streams');
const terminalDataProcessingRate = new Rate('terminal_data_processing_rate');
const terminalLargeOutputLatency = new Trend('terminal_large_output_latency');

// Test data for high I/O operations
const highIOCommands = new SharedArray('high-io-commands', function () {
  return [
    // Large output commands
    'find /usr -name "*.so" 2>/dev/null | head -1000',
    'ps aux | grep -v grep | head -500',
    'ls -laR /var/log 2>/dev/null | head -2000',
    'cat /var/log/system.log 2>/dev/null | head -1000',
    'dmesg 2>/dev/null | head -500',

    // Continuous output commands
    'yes "test line with some data" | head -100',
    'seq 1 1000',
    'for i in $(seq 1 100); do echo "Line $i: $(date)"; done',

    // Memory and CPU intensive
    'dd if=/dev/zero bs=1024 count=1000 2>/dev/null | base64',
    'cat /dev/urandom | base64 | head -500',

    // Network-like streaming
    'ping -c 50 localhost 2>/dev/null',
    'curl -s https://httpbin.org/stream/100 2>/dev/null',

    // Log streaming simulation
    'tail -f /var/log/system.log | head -100 2>/dev/null',
    'while [ $i -lt 200 ]; do echo "Log entry $i: $(date)"; i=$((i+1)); sleep 0.01; done',

    // Large file processing
    'head -2000 /usr/share/dict/words 2>/dev/null',
  ];
});

// Terminal resize test configurations
const resizeConfigs = new SharedArray('resize-configs', function () {
  return [
    { cols: 80, rows: 24 },   // Standard
    { cols: 120, rows: 30 },  // Large
    { cols: 200, rows: 50 },  // Extra large
    { cols: 40, rows: 12 },   // Small
    { cols: 160, rows: 40 },  // Wide
    { cols: 300, rows: 100 }, // Huge
  ];
});

// Configuration
const BASE_URL = __ENV.BASE_URL || 'localhost:8080';
const WS_URL = `ws://${BASE_URL}/api/ws`;
const TEST_DURATION = parseInt(__ENV.TEST_DURATION) || 120; // seconds
const IO_INTENSITY = __ENV.IO_INTENSITY || 'high'; // low, medium, high, extreme

export const options = {
  scenarios: {
    // High-frequency I/O operations test
    high_frequency_io: {
      executor: 'constant-vus',
      vus: 10,
      duration: `${TEST_DURATION}s`,
      gracefulRampDown: '10s',
      tags: { test_type: 'high_frequency_io' },
    },

    // Large output streaming test
    large_output_streaming: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 5 },
        { duration: '1m', target: 15 },
        { duration: '1m', target: 15 },
        { duration: '30s', target: 0 },
      ],
      tags: { test_type: 'large_output_streaming' },
    },

    // Terminal scrollback performance test
    scrollback_performance: {
      executor: 'constant-vus',
      vus: 8,
      duration: '2m',
      gracefulRampDown: '15s',
      tags: { test_type: 'scrollback_performance' },
    },

    // Buffer overflow and resilience test
    buffer_overflow_test: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '15s', target: 3 },
        { duration: '30s', target: 10 },
        { duration: '30s', target: 20 },
        { duration: '15s', target: 0 },
      ],
      tags: { test_type: 'buffer_overflow' },
    },

    // Terminal resizing under load
    resize_under_load: {
      executor: 'constant-vus',
      vus: 5,
      duration: '90s',
      gracefulRampDown: '10s',
      tags: { test_type: 'resize_under_load' },
    },
  },

  thresholds: {
    // Terminal I/O performance thresholds
    terminal_io_latency: ['p(95)<500', 'p(99)<1000'], // I/O latency under 500ms (95%), 1s (99%)
    terminal_command_latency: ['p(95)<200'], // Command execution under 200ms
    terminal_scrollback_latency: ['p(95)<100'], // Scrollback operations under 100ms
    terminal_resize_latency: ['p(95)<1000'], // Terminal resize under 1s

    // Error and overflow rates
    terminal_io_error_rate: ['rate<0.05'], // Less than 5% I/O errors
    terminal_buffer_overflow_rate: ['rate<0.1'], // Less than 10% buffer overflows
    terminal_data_processing_rate: ['rate>0.95'], // 95% data processing success rate

    // Throughput thresholds
    terminal_throughput_bytes: ['count>1000000'], // At least 1MB of terminal data processed
    terminal_large_output_latency: ['p(95)<2000'], // Large outputs under 2s
  },
};

/**
 * Setup function
 */
export function setup() {
  console.log(`🚀 Starting Terminal I/O Performance Test`);
  console.log(`🔌 WebSocket URL: ${WS_URL}`);
  console.log(`⚡ I/O Intensity: ${IO_INTENSITY}`);
  console.log(`⏱️  Test Duration: ${TEST_DURATION}s`);

  return {
    wsUrl: WS_URL,
    startTime: new Date().toISOString(),
    testConfig: {
      duration: TEST_DURATION,
      intensity: IO_INTENSITY,
    },
  };
}

/**
 * Main test function
 */
export default function (data) {
  const testType = __ENV.TAGS_TEST_TYPE || 'high_frequency_io';

  switch (testType) {
    case 'high_frequency_io':
      runHighFrequencyIOTest(data);
      break;
    case 'large_output_streaming':
      runLargeOutputStreamingTest(data);
      break;
    case 'scrollback_performance':
      runScrollbackPerformanceTest(data);
      break;
    case 'buffer_overflow':
      runBufferOverflowTest(data);
      break;
    case 'resize_under_load':
      runResizeUnderLoadTest(data);
      break;
    default:
      runHighFrequencyIOTest(data);
  }
}

/**
 * High-frequency I/O operations test
 */
function runHighFrequencyIOTest(data) {
  const sessionId = `high-io-${__VU}-${Date.now()}`;
  const testDuration = 60000; // 60 seconds

  ws.connect(data.wsUrl, {}, function (socket) {
    let commandsSent = 0;
    let bytesReceived = 0;
    let startTime = Date.now();

    terminalActiveStreams.add(1);

    socket.on('open', () => {
      console.log(`🔌 High I/O session ${sessionId} connected`);

      // Send rapid-fire commands
      const commandInterval = setInterval(() => {
        if (Date.now() - startTime > testDuration) {
          clearInterval(commandInterval);
          socket.close();
          return;
        }

        const command = highIOCommands[commandsSent % highIOCommands.length];
        const commandStart = Date.now();

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: command + '\n',
          timestamp: commandStart,
          commandIndex: commandsSent,
        }));

        commandsSent++;
      }, 100); // Send command every 100ms
    });

    socket.on('message', (message) => {
      const receiveTime = Date.now();

      try {
        const data = JSON.parse(message);
        const messageSize = JSON.stringify(data).length;
        bytesReceived += messageSize;
        terminalThroughput.add(messageSize);

        // Measure I/O latency
        if (data.timestamp) {
          const ioLatency = receiveTime - data.timestamp;
          terminalIOLatency.add(ioLatency);
          terminalCommandLatency.add(ioLatency);
        }

        // Track data processing success
        terminalDataProcessingRate.add(true);

        // Check for large outputs
        if (messageSize > 5000) { // 5KB+ messages
          terminalLargeOutputLatency.add(receiveTime - (data.timestamp || receiveTime));
        }

        terminalIOErrorRate.add(false);

      } catch (e) {
        terminalIOErrorRate.add(true);
        terminalDataProcessingRate.add(false);
      }
    });

    socket.on('error', (e) => {
      console.error(`❌ High I/O error: ${e}`);
      terminalIOErrorRate.add(true);
    });

    socket.on('close', () => {
      terminalActiveStreams.add(-1);
      const duration = Date.now() - startTime;
      const throughput = bytesReceived / (duration / 1000);
      console.log(`🏁 High I/O test completed: ${commandsSent} commands, ${bytesReceived} bytes, ${throughput.toFixed(2)} B/s`);
    });
  });
}

/**
 * Large output streaming test
 */
function runLargeOutputStreamingTest(data) {
  const sessionId = `large-output-${__VU}-${Date.now()}`;
  const largeOutputCommands = [
    'find /usr -type f 2>/dev/null | head -5000',
    'ps -eo pid,ppid,cmd,etime,rss,vsz | head -2000',
    'ls -laR /Applications 2>/dev/null | head -3000',
    'cat /usr/share/dict/words 2>/dev/null',
    'dmesg 2>/dev/null',
  ];

  ws.connect(data.wsUrl, {}, function (socket) {
    let outputsProcessed = 0;
    let totalBytes = 0;

    socket.on('open', () => {
      console.log(`🔌 Large output session ${sessionId} connected`);

      // Send large output commands with delays
      const processNextCommand = () => {
        if (outputsProcessed >= largeOutputCommands.length) {
          socket.close();
          return;
        }

        const command = largeOutputCommands[outputsProcessed];
        const commandStart = Date.now();

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: command + '\n',
          timestamp: commandStart,
          expectLargeOutput: true,
        }));

        outputsProcessed++;
      };

      // Start first command immediately
      processNextCommand();

      // Process subsequent commands every 10 seconds
      const commandInterval = setInterval(() => {
        if (outputsProcessed >= largeOutputCommands.length) {
          clearInterval(commandInterval);
        } else {
          processNextCommand();
        }
      }, 10000);
    });

    socket.on('message', (message) => {
      const receiveTime = Date.now();

      try {
        const data = JSON.parse(message);
        const messageSize = JSON.stringify(data).length;
        totalBytes += messageSize;
        terminalThroughput.add(messageSize);

        // Measure large output processing latency
        if (data.expectLargeOutput && data.timestamp) {
          const outputLatency = receiveTime - data.timestamp;
          terminalLargeOutputLatency.add(outputLatency);
          terminalIOLatency.add(outputLatency);
        }

        // Check for buffer overflow conditions
        if (messageSize > 50000) { // 50KB+ messages might cause buffer issues
          terminalBufferOverflowRate.add(false); // Successfully handled large message
        }

        terminalDataProcessingRate.add(true);

      } catch (e) {
        terminalBufferOverflowRate.add(true);
        terminalDataProcessingRate.add(false);
      }
    });

    socket.on('close', () => {
      const throughputMB = (totalBytes / (1024 * 1024)).toFixed(2);
      console.log(`🏁 Large output test completed: ${outputsProcessed} outputs, ${throughputMB} MB processed`);
    });
  });
}

/**
 * Scrollback performance test
 */
function runScrollbackPerformanceTest(data) {
  const sessionId = `scrollback-${__VU}-${Date.now()}`;

  ws.connect(data.wsUrl, {}, function (socket) {
    let linesGenerated = 0;
    const targetLines = 10000; // Generate 10K lines for scrollback testing

    socket.on('open', () => {
      console.log(`🔌 Scrollback session ${sessionId} connected`);

      // Generate many lines for scrollback testing
      const lineInterval = setInterval(() => {
        if (linesGenerated >= targetLines) {
          clearInterval(lineInterval);

          // Test scrollback operations
          setTimeout(() => {
            testScrollbackOperations(socket, sessionId);
          }, 1000);

          return;
        }

        const scrollbackStart = Date.now();

        // Generate line with timestamp for tracking
        const line = `echo "Scrollback line ${linesGenerated}: $(date)"`;

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: line + '\n',
          timestamp: scrollbackStart,
          isScrollbackTest: true,
        }));

        linesGenerated++;
      }, 10); // Generate line every 10ms
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);

        if (data.isScrollbackTest && data.timestamp) {
          const scrollbackLatency = Date.now() - data.timestamp;
          terminalScrollbackLatency.add(scrollbackLatency);
          terminalIOLatency.add(scrollbackLatency);
        }

        terminalDataProcessingRate.add(true);

      } catch (e) {
        terminalDataProcessingRate.add(false);
      }
    });
  });
}

/**
 * Test scrollback operations like searching and navigation
 */
function testScrollbackOperations(socket, sessionId) {
  console.log(`📜 Testing scrollback operations for ${sessionId}`);

  const scrollbackOps = [
    // Simulate scrollback search
    { operation: 'search', query: 'line 1000' },
    { operation: 'search', query: 'date' },
    { operation: 'scroll_to_top' },
    { operation: 'scroll_to_bottom' },
    { operation: 'search', query: 'Scrollback line 500' },
  ];

  scrollbackOps.forEach((op, index) => {
    setTimeout(() => {
      const opStart = Date.now();

      socket.send(JSON.stringify({
        sessionId: sessionId,
        operation: op.operation,
        query: op.query,
        timestamp: opStart,
        isScrollbackOperation: true,
      }));
    }, index * 2000); // Space operations 2 seconds apart
  });

  // Close connection after all operations
  setTimeout(() => {
    socket.close();
  }, scrollbackOps.length * 2000 + 5000);
}

/**
 * Buffer overflow and resilience test
 */
function runBufferOverflowTest(data) {
  const sessionId = `buffer-overflow-${__VU}-${Date.now()}`;

  // Commands designed to generate massive output
  const overflowCommands = [
    'yes "Buffer overflow test line with significant data content" | head -10000',
    'seq 1 50000',
    'cat /dev/zero | base64 | head -5000 2>/dev/null',
    'find / -name "*" 2>/dev/null | head -20000',
  ];

  ws.connect(data.wsUrl, {}, function (socket) {
    let overflowTestsRun = 0;

    socket.on('open', () => {
      console.log(`🔌 Buffer overflow session ${sessionId} connected`);

      const runOverflowTest = () => {
        if (overflowTestsRun >= overflowCommands.length) {
          socket.close();
          return;
        }

        const command = overflowCommands[overflowTestsRun];
        const testStart = Date.now();

        console.log(`💥 Running buffer overflow test ${overflowTestsRun + 1}: ${command}`);

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: command + '\n',
          timestamp: testStart,
          isBufferOverflowTest: true,
          expectedLargeOutput: true,
        }));

        overflowTestsRun++;
      };

      // Start first test
      runOverflowTest();

      // Run subsequent tests every 15 seconds
      const testInterval = setInterval(() => {
        if (overflowTestsRun >= overflowCommands.length) {
          clearInterval(testInterval);
        } else {
          runOverflowTest();
        }
      }, 15000);
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        const messageSize = JSON.stringify(data).length;
        terminalThroughput.add(messageSize);

        // Check if we successfully handled large output without overflow
        if (data.isBufferOverflowTest) {
          if (messageSize > 100000) { // 100KB+ messages
            terminalBufferOverflowRate.add(false); // Successfully handled
          }

          if (data.timestamp) {
            terminalIOLatency.add(Date.now() - data.timestamp);
          }
        }

        terminalDataProcessingRate.add(true);

      } catch (e) {
        console.error(`Buffer overflow handling error: ${e}`);
        terminalBufferOverflowRate.add(true);
        terminalDataProcessingRate.add(false);
      }
    });

    socket.on('error', (e) => {
      console.error(`❌ Buffer overflow test error: ${e}`);
      terminalBufferOverflowRate.add(true);
    });

    socket.on('close', () => {
      console.log(`🏁 Buffer overflow test completed: ${overflowTestsRun} tests run`);
    });
  });
}

/**
 * Terminal resizing under load test
 */
function runResizeUnderLoadTest(data) {
  const sessionId = `resize-load-${__VU}-${Date.now()}`;

  ws.connect(data.wsUrl, {}, function (socket) {
    let resizeCount = 0;
    let backgroundLoad = true;

    socket.on('open', () => {
      console.log(`🔌 Resize under load session ${sessionId} connected`);

      // Start background I/O load
      const backgroundInterval = setInterval(() => {
        if (!backgroundLoad) {
          clearInterval(backgroundInterval);
          return;
        }

        const command = highIOCommands[Math.floor(Math.random() * highIOCommands.length)];

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: command + '\n',
          isBackgroundLoad: true,
        }));
      }, 500);

      // Perform terminal resizes under load
      const resizeInterval = setInterval(() => {
        if (resizeCount >= resizeConfigs.length) {
          backgroundLoad = false;
          clearInterval(resizeInterval);
          socket.close();
          return;
        }

        const config = resizeConfigs[resizeCount];
        const resizeStart = Date.now();

        console.log(`📏 Resizing terminal to ${config.cols}x${config.rows} under load`);

        socket.send(JSON.stringify({
          type: 'resize',
          cols: config.cols,
          rows: config.rows,
          sessionId: sessionId,
          timestamp: resizeStart,
          isResizeTest: true,
        }));

        resizeCount++;
      }, 5000); // Resize every 5 seconds
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);

        // Track resize performance
        if (data.isResizeTest && data.timestamp) {
          const resizeLatency = Date.now() - data.timestamp;
          terminalResizeLatency.add(resizeLatency);
          console.log(`📏 Resize completed in ${resizeLatency}ms`);
        }

        // Track background I/O performance during resizing
        if (data.isBackgroundLoad) {
          terminalIOLatency.add(Date.now() - (data.timestamp || Date.now()));
        }

        terminalDataProcessingRate.add(true);

      } catch (e) {
        terminalDataProcessingRate.add(false);
      }
    });

    socket.on('close', () => {
      console.log(`🏁 Resize under load test completed: ${resizeCount} resizes performed`);
    });
  });
}

/**
 * Teardown function
 */
export function teardown(data) {
  console.log('🏁 Terminal I/O Performance Test completed');
  console.log(`📊 Test started: ${data.startTime}`);
  console.log(`📊 Test ended: ${new Date().toISOString()}`);
}

/**
 * Generate comprehensive performance report
 */
export function handleSummary(data) {
  const testMode = IO_INTENSITY;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/terminal-io-${testMode}-${timestamp}.html`]: htmlReport(data),
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/terminal-io-${testMode}-${timestamp}.json`]: JSON.stringify(data, null, 2),
  };
}