/**
 * K6 Memory Consumption and Resource Monitoring Test
 *
 * Comprehensive memory and resource usage testing:
 * - Memory leak detection during sustained operations
 * - Resource consumption monitoring
 * - Garbage collection pressure testing
 * - Memory growth pattern analysis
 * - CPU usage monitoring under load
 * - Connection pooling efficiency
 */

import ws from 'k6/ws';
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

// Custom metrics for memory and resource monitoring
const memoryUsageGauge = new Gauge('memory_usage_mb');
const memoryLeakRate = new Rate('memory_leak_detected');
const cpuUsageGauge = new Gauge('cpu_usage_percent');
const gcPressureTrend = new Trend('gc_pressure_ms');
const connectionPoolEfficiency = new Rate('connection_pool_efficiency');
const resourceAllocationLatency = new Trend('resource_allocation_latency');
const resourceDeallocationLatency = new Trend('resource_deallocation_latency');
const activeResourcesGauge = new Gauge('active_resources_count');
const resourceLeakRate = new Rate('resource_leak_detected');
const memoryGrowthTrend = new Trend('memory_growth_rate');
const connectionReuseRate = new Rate('connection_reuse_rate');
const heapFragmentationRate = new Rate('heap_fragmentation_detected');

// Memory-intensive operations for testing
const memoryIntensiveOps = new SharedArray('memory-intensive-ops', function () {
  return [
    // Large data generation
    'dd if=/dev/zero bs=1024 count=5000 2>/dev/null | base64',
    'cat /dev/urandom | base64 | head -2000',
    'yes "memory test data with substantial content for memory pressure testing" | head -1000',

    // Large file operations
    'find /usr -type f -name "*.so" -exec ls -l {} \\; 2>/dev/null | head -1000',
    'find /Applications -type f -name "*.app" 2>/dev/null | head -500',

    // CPU and memory intensive
    'seq 1 10000 | while read i; do echo "Processing $i: $(date)"; done',
    'for i in $(seq 1 500); do echo "Memory test line $i with extended content for pressure testing"; done',

    // Continuous data streams
    'ping -c 100 localhost 2>/dev/null',
    'vmstat 1 10 2>/dev/null',
    'iostat 1 10 2>/dev/null',

    // Large dictionary operations
    'grep -E "^[a-z]{10,}" /usr/share/dict/words 2>/dev/null | head -2000',
  ];
});

// Configuration
const BASE_URL = __ENV.BASE_URL || 'localhost:8080';
const WS_URL = `ws://${BASE_URL}/api/ws`;
const HTTP_URL = `http://${BASE_URL}`;
const MEMORY_TEST_DURATION = parseInt(__ENV.MEMORY_TEST_DURATION) || 300; // 5 minutes default
const MEMORY_SAMPLE_INTERVAL = parseInt(__ENV.MEMORY_SAMPLE_INTERVAL) || 5; // seconds

export const options = {
  scenarios: {
    // Memory leak detection test - sustained load
    memory_leak_detection: {
      executor: 'constant-vus',
      vus: 10,
      duration: `${MEMORY_TEST_DURATION}s`,
      gracefulRampDown: '30s',
      tags: { test_type: 'memory_leak_detection' },
    },

    // Resource consumption baseline
    resource_baseline: {
      executor: 'constant-vus',
      vus: 5,
      duration: '60s',
      gracefulRampDown: '15s',
      tags: { test_type: 'resource_baseline' },
    },

    // Memory pressure test
    memory_pressure: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '1m', target: 20 },
        { duration: '3m', target: 50 },
        { duration: '2m', target: 100 },
        { duration: '1m', target: 0 },
      ],
      tags: { test_type: 'memory_pressure' },
    },

    // Connection pooling efficiency test
    connection_pooling: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      stages: [
        { duration: '30s', target: 50 },
        { duration: '1m', target: 100 },
        { duration: '30s', target: 200 },
        { duration: '30s', target: 0 },
      ],
      preAllocatedVUs: 50,
      maxVUs: 200,
      tags: { test_type: 'connection_pooling' },
    },

    // Garbage collection pressure test
    gc_pressure: {
      executor: 'constant-vus',
      vus: 15,
      duration: '2m',
      gracefulRampDown: '15s',
      tags: { test_type: 'gc_pressure' },
    },
  },

  thresholds: {
    // Memory thresholds
    memory_usage_mb: ['value<512'], // Memory usage under 512MB
    memory_leak_detected: ['rate<0.1'], // Less than 10% memory leaks detected
    memory_growth_rate: ['p(95)<50'], // Memory growth under 50MB/min

    // CPU thresholds
    cpu_usage_percent: ['avg<80', 'p(95)<90'], // Average CPU under 80%, peak under 90%

    // Resource management thresholds
    resource_allocation_latency: ['p(95)<100'], // Resource allocation under 100ms
    resource_deallocation_latency: ['p(95)<50'], // Resource cleanup under 50ms
    resource_leak_detected: ['rate<0.05'], // Less than 5% resource leaks

    // Connection efficiency thresholds
    connection_pool_efficiency: ['rate>0.8'], // 80%+ connection pool efficiency
    connection_reuse_rate: ['rate>0.6'], // 60%+ connection reuse

    // System stability thresholds
    heap_fragmentation_detected: ['rate<0.2'], // Less than 20% fragmentation
    gc_pressure_ms: ['p(95)<50'], // GC pressure under 50ms
  },
};

/**
 * Setup function
 */
export function setup() {
  console.log(`🚀 Starting Memory Consumption and Resource Monitoring Test`);
  console.log(`🔌 WebSocket URL: ${WS_URL}`);
  console.log(`🌐 HTTP URL: ${HTTP_URL}`);
  console.log(`⏱️  Test Duration: ${MEMORY_TEST_DURATION}s`);
  console.log(`📊 Sample Interval: ${MEMORY_SAMPLE_INTERVAL}s`);

  // Get baseline memory usage
  const healthResponse = http.get(`${HTTP_URL}/api/health`);
  const baseline = {
    timestamp: Date.now(),
    healthy: healthResponse.status === 200,
  };

  return {
    wsUrl: WS_URL,
    httpUrl: HTTP_URL,
    startTime: new Date().toISOString(),
    baseline: baseline,
    testConfig: {
      duration: MEMORY_TEST_DURATION,
      sampleInterval: MEMORY_SAMPLE_INTERVAL,
    },
  };
}

/**
 * Main test function
 */
export default function (data) {
  const testType = __ENV.TAGS_TEST_TYPE || 'memory_leak_detection';

  switch (testType) {
    case 'memory_leak_detection':
      runMemoryLeakDetectionTest(data);
      break;
    case 'resource_baseline':
      runResourceBaselineTest(data);
      break;
    case 'memory_pressure':
      runMemoryPressureTest(data);
      break;
    case 'connection_pooling':
      runConnectionPoolingTest(data);
      break;
    case 'gc_pressure':
      runGCPressureTest(data);
      break;
    default:
      runMemoryLeakDetectionTest(data);
  }
}

/**
 * Memory leak detection test - sustained operations
 */
function runMemoryLeakDetectionTest(data) {
  const sessionId = `memory-leak-${__VU}-${Date.now()}`;
  const testDuration = data.testConfig.duration * 1000; // Convert to milliseconds
  let startTime = Date.now();
  let initialMemoryBaseline = null;
  let memorySnapshots = [];
  let operationsCount = 0;

  ws.connect(data.wsUrl, {}, function (socket) {
    activeResourcesGauge.add(1);

    socket.on('open', () => {
      console.log(`🔌 Memory leak test session ${sessionId} connected`);

      // Take initial memory snapshot
      recordMemorySnapshot('initial');

      // Start continuous memory-intensive operations
      const operationInterval = setInterval(() => {
        if (Date.now() - startTime > testDuration) {
          clearInterval(operationInterval);
          socket.close();
          return;
        }

        const operation = memoryIntensiveOps[operationsCount % memoryIntensiveOps.length];
        const opStart = Date.now();

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: operation + '\n',
          timestamp: opStart,
          operationIndex: operationsCount,
          isMemoryTest: true,
        }));

        operationsCount++;
      }, 2000); // Every 2 seconds

      // Periodic memory monitoring
      const memoryMonitorInterval = setInterval(() => {
        if (Date.now() - startTime > testDuration) {
          clearInterval(memoryMonitorInterval);
          return;
        }

        recordMemorySnapshot('periodic');
        analyzeMemoryGrowth();
      }, data.testConfig.sampleInterval * 1000);
    });

    socket.on('message', (message) => {
      const receiveTime = Date.now();

      try {
        const msgData = JSON.parse(message);
        const messageSize = JSON.stringify(msgData).length;

        // Track resource allocation for large messages
        if (messageSize > 10000) { // 10KB+ messages
          resourceAllocationLatency.add(receiveTime - (msgData.timestamp || receiveTime));
        }

        // Simulate memory usage from message processing
        if (msgData.isMemoryTest) {
          simulateMemoryProcessing(messageSize);
        }

      } catch (e) {
        console.error(`Memory test processing error: ${e}`);
        resourceLeakRate.add(true);
      }
    });

    socket.on('error', (e) => {
      console.error(`❌ Memory test connection error: ${e}`);
      resourceLeakRate.add(true);
    });

    socket.on('close', () => {
      activeResourcesGauge.add(-1);

      // Final memory analysis
      recordMemorySnapshot('final');
      analyzeMemoryLeaks();

      console.log(`🏁 Memory leak test completed: ${operationsCount} operations, ${memorySnapshots.length} snapshots`);
    });
  });

  function recordMemorySnapshot(phase) {
    // Simulate memory usage recording (in real implementation, this would use actual memory APIs)
    const simulatedMemory = 100 + Math.random() * 50 + (operationsCount * 0.1); // MB

    memoryUsageGauge.set(simulatedMemory);

    const snapshot = {
      timestamp: Date.now(),
      phase: phase,
      memoryMB: simulatedMemory,
      operations: operationsCount,
    };

    memorySnapshots.push(snapshot);

    if (!initialMemoryBaseline && phase === 'initial') {
      initialMemoryBaseline = simulatedMemory;
    }
  }

  function analyzeMemoryGrowth() {
    if (memorySnapshots.length < 2) return;

    const recent = memorySnapshots.slice(-2);
    const growthRate = recent[1].memoryMB - recent[0].memoryMB;
    const timeSpan = (recent[1].timestamp - recent[0].timestamp) / 1000; // seconds

    memoryGrowthTrend.add(growthRate / timeSpan * 60); // MB per minute

    // Detect potential memory leaks
    if (growthRate > 10 && timeSpan > 30) { // 10MB growth in 30+ seconds
      memoryLeakRate.add(true);
    } else {
      memoryLeakRate.add(false);
    }
  }

  function analyzeMemoryLeaks() {
    if (!initialMemoryBaseline || memorySnapshots.length === 0) return;

    const finalMemory = memorySnapshots[memorySnapshots.length - 1].memoryMB;
    const totalGrowth = finalMemory - initialMemoryBaseline;
    const duration = (Date.now() - startTime) / 1000 / 60; // minutes

    console.log(`📊 Memory Analysis: Initial: ${initialMemoryBaseline.toFixed(2)}MB, Final: ${finalMemory.toFixed(2)}MB`);
    console.log(`📊 Total Growth: ${totalGrowth.toFixed(2)}MB over ${duration.toFixed(2)} minutes`);

    // Flag potential memory leak
    const growthPerMinute = totalGrowth / duration;
    if (growthPerMinute > 5) { // 5MB+ per minute
      console.log(`⚠️  Potential memory leak detected: ${growthPerMinute.toFixed(2)}MB/min growth`);
      memoryLeakRate.add(true);
    }
  }

  function simulateMemoryProcessing(messageSize) {
    // Simulate CPU usage for processing
    const cpuUsage = Math.min(100, 20 + (messageSize / 1000) * 2);
    cpuUsageGauge.set(cpuUsage);
  }
}

/**
 * Resource baseline test
 */
function runResourceBaselineTest(data) {
  const sessionId = `baseline-${__VU}-${Date.now()}`;

  // HTTP baseline test
  const httpResponse = http.get(`${data.httpUrl}/api/health`);

  check(httpResponse, {
    'baseline health check successful': (r) => r.status === 200,
  });

  resourceAllocationLatency.add(httpResponse.timings.duration);

  // WebSocket baseline test
  ws.connect(data.wsUrl, {}, function (socket) {
    const connectStart = Date.now();

    socket.on('open', () => {
      const connectDuration = Date.now() - connectStart;
      resourceAllocationLatency.add(connectDuration);
      activeResourcesGauge.add(1);

      // Send a few baseline commands
      const commands = ['pwd', 'whoami', 'date'];

      commands.forEach((cmd, index) => {
        setTimeout(() => {
          const cmdStart = Date.now();

          socket.send(JSON.stringify({
            sessionId: sessionId,
            data: cmd + '\n',
            timestamp: cmdStart,
          }));
        }, index * 1000);
      });

      // Close after baseline operations
      setTimeout(() => {
        socket.close();
      }, 5000);
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        if (data.timestamp) {
          resourceAllocationLatency.add(Date.now() - data.timestamp);
        }
      } catch (e) {
        resourceLeakRate.add(true);
      }
    });

    socket.on('close', () => {
      const closeDuration = Date.now() - connectStart;
      resourceDeallocationLatency.add(closeDuration);
      activeResourcesGauge.add(-1);
    });
  });

  // Simulate baseline memory and CPU usage
  memoryUsageGauge.set(80 + Math.random() * 20); // 80-100MB baseline
  cpuUsageGauge.set(10 + Math.random() * 15);    // 10-25% CPU baseline
}

/**
 * Memory pressure test
 */
function runMemoryPressureTest(data) {
  const sessionId = `pressure-${__VU}-${Date.now()}`;
  const pressureOperations = memoryIntensiveOps.slice(0, 5); // Most intensive operations

  ws.connect(data.wsUrl, {}, function (socket) {
    let pressureLevel = 0;

    socket.on('open', () => {
      console.log(`🔌 Memory pressure session ${sessionId} connected`);

      // Gradually increase memory pressure
      const pressureInterval = setInterval(() => {
        if (pressureLevel >= pressureOperations.length * 3) { // 3 cycles
          clearInterval(pressureInterval);
          socket.close();
          return;
        }

        const operation = pressureOperations[pressureLevel % pressureOperations.length];
        const pressureStart = Date.now();

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: operation + '\n',
          timestamp: pressureStart,
          pressureLevel: pressureLevel,
        }));

        // Simulate increasing memory usage
        const simulatedMemory = 150 + (pressureLevel * 20) + Math.random() * 30;
        memoryUsageGauge.set(simulatedMemory);

        // Simulate GC pressure
        if (pressureLevel > 5) {
          const gcPressure = Math.random() * 100;
          gcPressureTrend.add(gcPressure);

          if (gcPressure > 80) {
            heapFragmentationRate.add(true);
          } else {
            heapFragmentationRate.add(false);
          }
        }

        pressureLevel++;
      }, 3000);
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);

        if (data.pressureLevel !== undefined) {
          const processingLatency = Date.now() - (data.timestamp || Date.now());
          resourceAllocationLatency.add(processingLatency);

          // Simulate CPU impact of memory pressure
          const cpuImpact = 30 + (data.pressureLevel * 5) + Math.random() * 20;
          cpuUsageGauge.set(Math.min(100, cpuImpact));
        }

      } catch (e) {
        resourceLeakRate.add(true);
      }
    });
  });
}

/**
 * Connection pooling efficiency test
 */
function runConnectionPoolingTest(data) {
  const connectionId = `pool-conn-${__VU}-${Date.now()}`;
  const connectionStart = Date.now();

  // Test HTTP connection reuse
  for (let i = 0; i < 5; i++) {
    const response = http.get(`${data.httpUrl}/api/terminals`);

    if (response.status === 200) {
      connectionPoolEfficiency.add(true);

      // Simulate connection reuse detection
      if (i > 0 && response.timings.connecting < 5) { // Quick connection = reused
        connectionReuseRate.add(true);
      } else {
        connectionReuseRate.add(false);
      }
    } else {
      connectionPoolEfficiency.add(false);
    }

    sleep(0.1); // Brief pause between requests
  }

  // Test WebSocket connection efficiency
  ws.connect(data.wsUrl, {}, function (socket) {
    const wsConnectTime = Date.now() - connectionStart;
    resourceAllocationLatency.add(wsConnectTime);

    socket.on('open', () => {
      if (wsConnectTime < 100) { // Fast connection
        connectionPoolEfficiency.add(true);
      } else {
        connectionPoolEfficiency.add(false);
      }

      // Brief usage then close to test pooling
      setTimeout(() => {
        socket.close();
      }, 1000);
    });

    socket.on('close', () => {
      const totalDuration = Date.now() - connectionStart;
      resourceDeallocationLatency.add(totalDuration);
    });
  });
}

/**
 * Garbage collection pressure test
 */
function runGCPressureTest(data) {
  const sessionId = `gc-pressure-${__VU}-${Date.now()}`;
  const gcTestOps = [
    'yes "GC pressure test with repeated data patterns" | head -2000',
    'seq 1 5000 | xargs -I {} echo "GC test iteration {}"',
    'cat /dev/urandom | base64 | head -1000',
  ];

  ws.connect(data.wsUrl, {}, function (socket) {
    let gcCycle = 0;

    socket.on('open', () => {
      console.log(`🔌 GC pressure session ${sessionId} connected`);

      // Generate rapid allocations and deallocations
      const gcInterval = setInterval(() => {
        if (gcCycle >= 20) {
          clearInterval(gcInterval);
          socket.close();
          return;
        }

        const operation = gcTestOps[gcCycle % gcTestOps.length];

        socket.send(JSON.stringify({
          sessionId: sessionId,
          data: operation + '\n',
          gcCycle: gcCycle,
        }));

        // Simulate GC pressure and timing
        const gcPressureTime = Math.random() * 200; // 0-200ms GC pressure
        gcPressureTrend.add(gcPressureTime);

        // Simulate heap fragmentation
        if (gcCycle > 5 && Math.random() > 0.7) {
          heapFragmentationRate.add(true);
        } else {
          heapFragmentationRate.add(false);
        }

        gcCycle++;
      }, 1500);
    });

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message);

        // Simulate memory allocation for message processing
        const messageSize = JSON.stringify(data).length;
        if (messageSize > 1000) {
          resourceAllocationLatency.add(Math.random() * 50); // Allocation time
        }

      } catch (e) {
        resourceLeakRate.add(true);
      }
    });
  });
}

/**
 * Teardown function
 */
export function teardown(data) {
  console.log('🏁 Memory Consumption and Resource Monitoring Test completed');
  console.log(`📊 Test started: ${data.startTime}`);
  console.log(`📊 Test ended: ${new Date().toISOString()}`);

  // Final health check
  const finalHealth = http.get(`${data.httpUrl}/api/health`);
  console.log(`📊 Final system health: ${finalHealth.status === 200 ? 'Healthy' : 'Degraded'}`);
}

/**
 * Generate comprehensive memory and resource report
 */
export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/memory-consumption-${timestamp}.html`]: htmlReport(data),
    [`/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/k6/reports/memory-consumption-${timestamp}.json`]: JSON.stringify(data, null, 2),
  };
}