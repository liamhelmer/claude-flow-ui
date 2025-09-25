/**
 * Comprehensive Stress Testing Suite
 *
 * Tests the claude-flow-ui under various stress conditions including:
 * - Multiple concurrent WebSocket connections
 * - High-frequency message throughput
 * - Memory pressure scenarios
 * - CPU intensive operations
 * - Network latency simulation
 */

import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';
import io from 'socket.io-client';

interface StressTestConfig {
  maxConnections: number;
  messagesPerConnection: number;
  messageSize: number;
  testDuration: number; // milliseconds
  rampUpTime: number; // milliseconds
  rampDownTime: number; // milliseconds
  enableNetworkSimulation: boolean;
  networkLatencyRange: [number, number]; // min, max latency in ms
  networkLossRate: number; // 0-1, packet loss percentage
  enableMemoryPressure: boolean;
  memoryPressureSize: number; // bytes
  enableCPUStress: boolean;
  cpuStressLevel: number; // 0-1, CPU utilization level
}

interface StressTestResult {
  testName: string;
  config: StressTestConfig;
  duration: number;
  success: boolean;
  connections: {
    attempted: number;
    successful: number;
    failed: number;
    averageConnectionTime: number;
    maxConnectionTime: number;
    connectionFailures: Array<{ time: number; error: string }>;
  };
  messages: {
    sent: number;
    received: number;
    lost: number;
    averageLatency: number;
    p95Latency: number;
    p99Latency: number;
    maxLatency: number;
    throughput: number; // messages per second
    byteThroughput: number; // bytes per second
  };
  memory: {
    initial: NodeJS.MemoryUsage;
    peak: NodeJS.MemoryUsage;
    final: NodeJS.MemoryUsage;
    leaked: number;
    gcCount: number;
    gcTime: number;
  };
  cpu: {
    averageUsage: number;
    peakUsage: number;
    samples: number[];
  };
  errors: Array<{
    timestamp: number;
    type: string;
    message: string;
    context?: any;
  }>;
  performance: {
    score: number;
    bottlenecks: string[];
    recommendations: string[];
  };
}

interface MockConnection {
  id: string;
  socket?: any;
  connected: boolean;
  connectionTime: number;
  messagesSent: number;
  messagesReceived: number;
  lastActivity: number;
  latencies: number[];
  errors: string[];
}

export class StressTestSuite extends EventEmitter {
  private isRunning: boolean = false;
  private activeConnections: Map<string, MockConnection> = new Map();
  private messageLatencies: number[] = [];
  private connectionTimes: number[] = [];
  private errors: Array<{ timestamp: number; type: string; message: string; context?: any }> = [];
  private memorySnapshots: NodeJS.MemoryUsage[] = [];
  private cpuSamples: number[] = [];
  private gcCount: number = 0;
  private gcTime: number = 0;

  constructor() {
    super();
  }

  /**
   * Run comprehensive stress test with specified configuration
   */
  async runStressTest(config: Partial<StressTestConfig> = {}): Promise<StressTestResult> {
    const fullConfig: StressTestConfig = {
      maxConnections: 1000,
      messagesPerConnection: 100,
      messageSize: 1024,
      testDuration: 60000, // 1 minute
      rampUpTime: 10000, // 10 seconds
      rampDownTime: 5000, // 5 seconds
      enableNetworkSimulation: true,
      networkLatencyRange: [10, 100],
      networkLossRate: 0.01, // 1%
      enableMemoryPressure: true,
      memoryPressureSize: 100 * 1024 * 1024, // 100MB
      enableCPUStress: true,
      cpuStressLevel: 0.5, // 50% CPU usage
      ...config
    };

    console.log(`🧪 Starting stress test with ${fullConfig.maxConnections} connections...`);

    this.isRunning = true;
    this.reset();

    const startTime = performance.now();
    const initialMemory = process.memoryUsage();

    try {
      // Phase 1: Setup and initialization
      await this.setupStressEnvironment(fullConfig);

      // Phase 2: Ramp up connections
      await this.rampUpConnections(fullConfig);

      // Phase 3: Sustain load
      await this.sustainLoad(fullConfig);

      // Phase 4: Ramp down and cleanup
      await this.rampDownConnections(fullConfig);

      const endTime = performance.now();
      const finalMemory = process.memoryUsage();
      const duration = endTime - startTime;

      console.log(`✅ Stress test completed in ${duration.toFixed(2)}ms`);

      return this.compileResults(fullConfig, duration, initialMemory, finalMemory, true);

    } catch (error) {
      const endTime = performance.now();
      const finalMemory = process.memoryUsage();
      const duration = endTime - startTime;

      this.recordError('stress-test-failure', error instanceof Error ? error.message : String(error));
      console.error(`❌ Stress test failed after ${duration.toFixed(2)}ms:`, error);

      return this.compileResults(fullConfig, duration, initialMemory, finalMemory, false);

    } finally {
      this.isRunning = false;
      await this.cleanup();
    }
  }

  private reset(): void {
    this.activeConnections.clear();
    this.messageLatencies = [];
    this.connectionTimes = [];
    this.errors = [];
    this.memorySnapshots = [];
    this.cpuSamples = [];
    this.gcCount = 0;
    this.gcTime = 0;
  }

  private async setupStressEnvironment(config: StressTestConfig): Promise<void> {
    console.log('🔧 Setting up stress test environment...');

    // Start memory monitoring
    this.startMemoryMonitoring();

    // Start CPU monitoring
    this.startCPUMonitoring();

    // Setup GC monitoring
    if (global.gc) {
      this.setupGCMonitoring();
    }

    // Apply memory pressure if enabled
    if (config.enableMemoryPressure) {
      await this.applyMemoryPressure(config.memoryPressureSize);
    }

    // Start CPU stress if enabled
    if (config.enableCPUStress) {
      this.startCPUStress(config.cpuStressLevel);
    }
  }

  private async rampUpConnections(config: StressTestConfig): Promise<void> {
    console.log(`📈 Ramping up ${config.maxConnections} connections over ${config.rampUpTime}ms...`);

    const connectionsPerStep = Math.max(1, Math.floor(config.maxConnections / 10));
    const stepInterval = config.rampUpTime / 10;

    for (let step = 0; step < 10 && this.isRunning; step++) {
      const connectionsToCreate = Math.min(connectionsPerStep, config.maxConnections - this.activeConnections.size);

      const promises = [];
      for (let i = 0; i < connectionsToCreate; i++) {
        promises.push(this.createConnection(config));
      }

      await Promise.allSettled(promises);

      console.log(`  📊 Connections: ${this.activeConnections.size}/${config.maxConnections}`);

      if (step < 9) {
        await this.sleep(stepInterval);
      }
    }

    console.log(`✅ Ramp up complete: ${this.activeConnections.size} active connections`);
  }

  private async sustainLoad(config: StressTestConfig): Promise<void> {
    const sustainDuration = config.testDuration - config.rampUpTime - config.rampDownTime;
    console.log(`⚡ Sustaining load for ${sustainDuration}ms...`);

    const startTime = performance.now();
    const messagePromises: Promise<void>[] = [];

    // Start message pumping for all connections
    for (const [connectionId, connection] of this.activeConnections) {
      if (connection.connected) {
        messagePromises.push(this.pumpMessages(connection, config));
      }
    }

    // Monitor performance during sustained load
    const monitoringInterval = setInterval(() => {
      this.capturePerformanceSnapshot();
    }, 1000);

    try {
      // Wait for either all messages to complete or timeout
      await Promise.race([
        Promise.allSettled(messagePromises),
        this.sleep(sustainDuration)
      ]);
    } finally {
      clearInterval(monitoringInterval);
    }

    const actualDuration = performance.now() - startTime;
    console.log(`✅ Load sustained for ${actualDuration.toFixed(2)}ms`);
  }

  private async rampDownConnections(config: StressTestConfig): Promise<void> {
    console.log(`📉 Ramping down connections over ${config.rampDownTime}ms...`);

    const connectionsToClose = Array.from(this.activeConnections.values());
    const connectionsPerStep = Math.max(1, Math.floor(connectionsToClose.length / 5));
    const stepInterval = config.rampDownTime / 5;

    for (let step = 0; step < 5 && connectionsToClose.length > 0; step++) {
      const batch = connectionsToClose.splice(0, connectionsPerStep);

      const promises = batch.map(conn => this.closeConnection(conn));
      await Promise.allSettled(promises);

      console.log(`  📊 Connections remaining: ${this.activeConnections.size}`);

      if (step < 4 && this.activeConnections.size > 0) {
        await this.sleep(stepInterval);
      }
    }

    console.log(`✅ Ramp down complete: ${this.activeConnections.size} connections remaining`);
  }

  private async createConnection(config: StressTestConfig): Promise<void> {
    const connectionId = `conn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const startTime = performance.now();

    try {
      // Create mock connection (in real scenario, this would be socket.io)
      const connection: MockConnection = {
        id: connectionId,
        connected: false,
        connectionTime: 0,
        messagesSent: 0,
        messagesReceived: 0,
        lastActivity: Date.now(),
        latencies: [],
        errors: []
      };

      // Simulate connection establishment
      const networkLatency = config.enableNetworkSimulation
        ? this.simulateNetworkLatency(config.networkLatencyRange)
        : 0;

      await this.sleep(networkLatency);

      // Simulate occasional connection failures
      if (Math.random() < 0.05) { // 5% failure rate
        throw new Error('Connection failed');
      }

      const connectionTime = performance.now() - startTime;
      connection.connected = true;
      connection.connectionTime = connectionTime;

      this.activeConnections.set(connectionId, connection);
      this.connectionTimes.push(connectionTime);

      this.emit('connection-established', connection);

    } catch (error) {
      const connectionTime = performance.now() - startTime;
      this.connectionTimes.push(connectionTime);
      this.recordError('connection-failed', error instanceof Error ? error.message : String(error), {
        connectionId,
        connectionTime
      });
    }
  }

  private async pumpMessages(connection: MockConnection, config: StressTestConfig): Promise<void> {
    const messagePayload = 'x'.repeat(config.messageSize);

    for (let i = 0; i < config.messagesPerConnection && this.isRunning && connection.connected; i++) {
      try {
        const messageStart = performance.now();

        // Simulate network conditions
        if (config.enableNetworkSimulation) {
          // Packet loss simulation
          if (Math.random() < config.networkLossRate) {
            this.recordError('message-lost', 'Simulated packet loss', {
              connectionId: connection.id,
              messageIndex: i
            });
            continue;
          }

          // Network latency simulation
          const latency = this.simulateNetworkLatency(config.networkLatencyRange);
          await this.sleep(latency);
        }

        // Simulate message processing
        await this.sleep(Math.random() * 2); // 0-2ms processing time

        const messageEnd = performance.now();
        const messageLatency = messageEnd - messageStart;

        connection.messagesSent++;
        connection.messagesReceived++;
        connection.lastActivity = Date.now();
        connection.latencies.push(messageLatency);
        this.messageLatencies.push(messageLatency);

        // Rate limiting to prevent overwhelming
        if (i % 10 === 0) {
          await this.sleep(1);
        }

      } catch (error) {
        connection.errors.push(error instanceof Error ? error.message : String(error));
        this.recordError('message-failed', error instanceof Error ? error.message : String(error), {
          connectionId: connection.id,
          messageIndex: i
        });
      }
    }
  }

  private async closeConnection(connection: MockConnection): Promise<void> {
    try {
      if (connection.socket && connection.socket.disconnect) {
        connection.socket.disconnect();
      }

      connection.connected = false;
      this.activeConnections.delete(connection.id);

      this.emit('connection-closed', connection);

    } catch (error) {
      this.recordError('connection-close-failed', error instanceof Error ? error.message : String(error), {
        connectionId: connection.id
      });
    }
  }

  private startMemoryMonitoring(): void {
    const interval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(interval);
        return;
      }

      this.memorySnapshots.push(process.memoryUsage());
    }, 1000);
  }

  private startCPUMonitoring(): void {
    const interval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(interval);
        return;
      }

      // Simple CPU usage estimation (not perfectly accurate)
      const startUsage = process.cpuUsage();
      setTimeout(() => {
        const endUsage = process.cpuUsage(startUsage);
        const cpuPercent = (endUsage.user + endUsage.system) / 10000; // Rough approximation
        this.cpuSamples.push(Math.min(100, cpuPercent));
      }, 100);
    }, 1000);
  }

  private setupGCMonitoring(): void {
    if (!global.gc) return;

    const originalGC = global.gc;
    global.gc = (...args: any[]) => {
      const start = performance.now();
      const result = originalGC.apply(this, args);
      const end = performance.now();

      this.gcCount++;
      this.gcTime += (end - start);

      return result;
    };
  }

  private async applyMemoryPressure(size: number): Promise<void> {
    console.log(`💾 Applying memory pressure: ${(size / 1024 / 1024).toFixed(2)}MB`);

    // Create large objects to simulate memory pressure
    const buffers: Buffer[] = [];
    const chunkSize = 1024 * 1024; // 1MB chunks
    const chunks = Math.floor(size / chunkSize);

    for (let i = 0; i < chunks; i++) {
      buffers.push(Buffer.alloc(chunkSize, `chunk_${i}`));

      // Yield control occasionally
      if (i % 10 === 0) {
        await this.sleep(1);
      }
    }

    // Keep reference to prevent GC
    (this as any)._memoryPressureBuffers = buffers;
  }

  private startCPUStress(level: number): void {
    const targetCPU = level * 100; // Convert to percentage
    console.log(`🔥 Starting CPU stress at ${targetCPU}% utilization`);

    // CPU stress using busy loops
    const stressWorker = () => {
      if (!this.isRunning) return;

      const start = performance.now();
      const workDuration = 50; // 50ms of work
      const idleDuration = (workDuration / level) - workDuration;

      // Busy loop for work duration
      while (performance.now() - start < workDuration) {
        Math.sqrt(Math.random() * 1000000);
      }

      // Idle for calculated duration
      setTimeout(stressWorker, idleDuration);
    };

    // Start multiple workers for multi-core stress
    const workers = Math.max(1, Math.floor(require('os').cpus().length * level));
    for (let i = 0; i < workers; i++) {
      setTimeout(stressWorker, i * 10);
    }
  }

  private capturePerformanceSnapshot(): void {
    const snapshot = {
      timestamp: Date.now(),
      memory: process.memoryUsage(),
      connections: this.activeConnections.size,
      messageLatencies: this.messageLatencies.length,
      errors: this.errors.length
    };

    this.emit('performance-snapshot', snapshot);
  }

  private simulateNetworkLatency(range: [number, number]): number {
    return Math.random() * (range[1] - range[0]) + range[0];
  }

  private recordError(type: string, message: string, context?: any): void {
    this.errors.push({
      timestamp: Date.now(),
      type,
      message,
      context
    });

    this.emit('error-recorded', { type, message, context });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async cleanup(): Promise<void> {
    console.log('🧹 Cleaning up stress test environment...');

    // Close remaining connections
    for (const connection of this.activeConnections.values()) {
      await this.closeConnection(connection);
    }

    // Clean up memory pressure
    if ((this as any)._memoryPressureBuffers) {
      delete (this as any)._memoryPressureBuffers;
    }

    // Force garbage collection
    if (global.gc) {
      global.gc();
    }
  }

  private compileResults(
    config: StressTestConfig,
    duration: number,
    initialMemory: NodeJS.MemoryUsage,
    finalMemory: NodeJS.MemoryUsage,
    success: boolean
  ): StressTestResult {
    const connectionFailures = this.errors.filter(e => e.type === 'connection-failed');
    const messagesSent = Array.from(this.activeConnections.values()).reduce((sum, conn) => sum + conn.messagesSent, 0);
    const messagesReceived = Array.from(this.activeConnections.values()).reduce((sum, conn) => sum + conn.messagesReceived, 0);
    const messagesLost = this.errors.filter(e => e.type === 'message-lost').length;

    // Calculate latency statistics
    const sortedLatencies = this.messageLatencies.sort((a, b) => a - b);
    const avgLatency = sortedLatencies.reduce((sum, lat) => sum + lat, 0) / sortedLatencies.length || 0;
    const p95Latency = sortedLatencies[Math.floor(sortedLatencies.length * 0.95)] || 0;
    const p99Latency = sortedLatencies[Math.floor(sortedLatencies.length * 0.99)] || 0;
    const maxLatency = Math.max(...sortedLatencies, 0);

    // Calculate throughput
    const throughput = messagesSent / (duration / 1000);
    const byteThroughput = throughput * config.messageSize;

    // Memory analysis
    const peakMemory = this.memorySnapshots.reduce((peak, snapshot) => ({
      rss: Math.max(peak.rss, snapshot.rss),
      heapUsed: Math.max(peak.heapUsed, snapshot.heapUsed),
      heapTotal: Math.max(peak.heapTotal, snapshot.heapTotal),
      external: Math.max(peak.external, snapshot.external),
      arrayBuffers: Math.max(peak.arrayBuffers, snapshot.arrayBuffers),
    }), initialMemory);

    const memoryLeaked = finalMemory.heapUsed - initialMemory.heapUsed;

    // CPU analysis
    const avgCPU = this.cpuSamples.reduce((sum, sample) => sum + sample, 0) / this.cpuSamples.length || 0;
    const peakCPU = Math.max(...this.cpuSamples, 0);

    // Performance scoring
    const performanceScore = this.calculatePerformanceScore({
      connectionSuccessRate: (this.activeConnections.size / config.maxConnections),
      messageDeliveryRate: messagesReceived / Math.max(messagesSent, 1),
      averageLatency: avgLatency,
      memoryEfficiency: 1 - (memoryLeaked / initialMemory.heapUsed),
      errorRate: this.errors.length / Math.max(messagesSent, 1),
    });

    const bottlenecks = this.identifyBottlenecks(avgLatency, avgCPU, memoryLeaked, this.errors.length);
    const recommendations = this.generateRecommendations(bottlenecks);

    return {
      testName: 'comprehensive-stress-test',
      config,
      duration,
      success,
      connections: {
        attempted: config.maxConnections,
        successful: this.activeConnections.size,
        failed: connectionFailures.length,
        averageConnectionTime: this.connectionTimes.reduce((sum, time) => sum + time, 0) / this.connectionTimes.length || 0,
        maxConnectionTime: Math.max(...this.connectionTimes, 0),
        connectionFailures: connectionFailures.map(e => ({
          time: e.timestamp,
          error: e.message
        }))
      },
      messages: {
        sent: messagesSent,
        received: messagesReceived,
        lost: messagesLost,
        averageLatency: avgLatency,
        p95Latency,
        p99Latency,
        maxLatency,
        throughput,
        byteThroughput
      },
      memory: {
        initial: initialMemory,
        peak: peakMemory,
        final: finalMemory,
        leaked: memoryLeaked,
        gcCount: this.gcCount,
        gcTime: this.gcTime
      },
      cpu: {
        averageUsage: avgCPU,
        peakUsage: peakCPU,
        samples: this.cpuSamples
      },
      errors: this.errors,
      performance: {
        score: performanceScore,
        bottlenecks,
        recommendations
      }
    };
  }

  private calculatePerformanceScore(metrics: {
    connectionSuccessRate: number;
    messageDeliveryRate: number;
    averageLatency: number;
    memoryEfficiency: number;
    errorRate: number;
  }): number {
    let score = 100;

    // Connection success rate (25% weight)
    score -= (1 - metrics.connectionSuccessRate) * 25;

    // Message delivery rate (25% weight)
    score -= (1 - metrics.messageDeliveryRate) * 25;

    // Latency penalty (20% weight)
    const latencyPenalty = Math.min(20, (metrics.averageLatency / 100) * 20);
    score -= latencyPenalty;

    // Memory efficiency (15% weight)
    score -= (1 - Math.max(0, metrics.memoryEfficiency)) * 15;

    // Error rate penalty (15% weight)
    const errorPenalty = Math.min(15, metrics.errorRate * 100 * 15);
    score -= errorPenalty;

    return Math.max(0, Math.min(100, score));
  }

  private identifyBottlenecks(avgLatency: number, avgCPU: number, memoryLeaked: number, errorCount: number): string[] {
    const bottlenecks: string[] = [];

    if (avgLatency > 100) {
      bottlenecks.push('high-latency');
    }

    if (avgCPU > 80) {
      bottlenecks.push('cpu-bound');
    }

    if (memoryLeaked > 50 * 1024 * 1024) { // 50MB
      bottlenecks.push('memory-leak');
    }

    if (errorCount > 100) {
      bottlenecks.push('high-error-rate');
    }

    if (this.gcCount > 50) {
      bottlenecks.push('gc-pressure');
    }

    return bottlenecks;
  }

  private generateRecommendations(bottlenecks: string[]): string[] {
    const recommendations: string[] = [];

    if (bottlenecks.includes('high-latency')) {
      recommendations.push('Optimize message processing pipeline');
      recommendations.push('Consider implementing message batching');
      recommendations.push('Review network configuration and routing');
    }

    if (bottlenecks.includes('cpu-bound')) {
      recommendations.push('Profile CPU-intensive operations');
      recommendations.push('Consider using worker threads for heavy computations');
      recommendations.push('Implement CPU usage throttling');
    }

    if (bottlenecks.includes('memory-leak')) {
      recommendations.push('Review object lifecycle management');
      recommendations.push('Check for circular references');
      recommendations.push('Implement proper cleanup in connection handlers');
    }

    if (bottlenecks.includes('high-error-rate')) {
      recommendations.push('Improve error handling and recovery');
      recommendations.push('Add retry mechanisms for transient failures');
      recommendations.push('Implement circuit breaker pattern');
    }

    if (bottlenecks.includes('gc-pressure')) {
      recommendations.push('Optimize object allocation patterns');
      recommendations.push('Consider object pooling for frequently created objects');
      recommendations.push('Review data structure choices for efficiency');
    }

    return recommendations;
  }

  /**
   * Run a quick stress test with default settings
   */
  async runQuickStressTest(): Promise<StressTestResult> {
    return this.runStressTest({
      maxConnections: 100,
      messagesPerConnection: 50,
      testDuration: 30000, // 30 seconds
      rampUpTime: 5000, // 5 seconds
      rampDownTime: 2000, // 2 seconds
    });
  }

  /**
   * Run an extreme stress test to find breaking points
   */
  async runExtremeStressTest(): Promise<StressTestResult> {
    return this.runStressTest({
      maxConnections: 5000,
      messagesPerConnection: 500,
      messageSize: 4096, // 4KB messages
      testDuration: 300000, // 5 minutes
      rampUpTime: 30000, // 30 seconds
      rampDownTime: 15000, // 15 seconds
      networkLatencyRange: [50, 200],
      networkLossRate: 0.05, // 5% loss
      memoryPressureSize: 500 * 1024 * 1024, // 500MB
      cpuStressLevel: 0.8, // 80% CPU
    });
  }
}