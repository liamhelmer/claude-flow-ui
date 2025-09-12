/**
 * Performance Benchmarks and Testing Strategies
 * 
 * Comprehensive performance testing framework for Claude UI Terminal Application
 */

import { performance } from 'perf_hooks';

// ============================================================================
// Performance Measurement Utilities
// ============================================================================

export interface PerformanceMetrics {
  duration: number;
  memoryUsage: number;
  operations: number;
  operationsPerSecond: number;
  gcCount?: number;
  gcDuration?: number;
}

class TestPerformanceMeter {
  private startTime: number = 0;
  private endTime: number = 0;
  private startMemory: number = 0;
  private endMemory: number = 0;
  private operationCount: number = 0;

  start(): void {
    // Force garbage collection if available for accurate memory measurement
    if (global.gc) {
      global.gc();
    }
    
    this.startTime = performance.now();
    this.startMemory = this.getMemoryUsage();
    this.operationCount = 0;
  }

  end(): PerformanceMetrics {
    this.endTime = performance.now();
    this.endMemory = this.getMemoryUsage();
    
    const duration = this.endTime - this.startTime;
    const memoryUsage = this.endMemory - this.startMemory;
    const operationsPerSecond = this.operationCount / (duration / 1000);

    return {
      duration,
      memoryUsage,
      operations: this.operationCount,
      operationsPerSecond
    };
  }

  recordOperation(): void {
    this.operationCount++;
  }

  recordOperations(count: number): void {
    this.operationCount += count;
  }

  private getMemoryUsage(): number {
    if (typeof performance !== 'undefined' && (performance as any).memory) {
      return (performance as any).memory.usedJSHeapSize;
    }
    if (process && process.memoryUsage) {
      return process.memoryUsage().heapUsed;
    }
    return 0;
  }
}

// ============================================================================
// WebSocket Performance Benchmarks
// ============================================================================

class WebSocketPerformanceBenchmarks {
  
  /**
   * Benchmark WebSocket connection establishment
   */
  static async benchmarkConnectionSpeed(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    meter.start();

    // Simulate multiple rapid connections
    const connections = [];
    for (let i = 0; i < 100; i++) {
      const startConnect = performance.now();
      const ws = new WebSocket(`ws://localhost:8080/test-${i}`);
      
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);
        
        ws.onopen = () => {
          clearTimeout(timeout);
          meter.recordOperation();
          resolve(ws);
        };
        
        ws.onerror = () => {
          clearTimeout(timeout);
          reject(new Error('Connection failed'));
        };
      });
      
      connections.push(ws);
    }

    // Cleanup
    connections.forEach(ws => ws.close());
    
    return meter.end();
  }

  /**
   * Benchmark message throughput
   */
  static async benchmarkMessageThroughput(): Promise<{
    send: PerformanceMetrics;
    receive: PerformanceMetrics;
  }> {
    const sendMeter = new TestPerformanceMeter();
    const receiveMeter = new TestPerformanceMeter();
    
    const ws = new WebSocket('ws://localhost:8080');
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = reject;
      setTimeout(reject, 5000);
    });

    // Benchmark sending messages
    sendMeter.start();
    const messageCount = 10000;
    const testMessage = JSON.stringify({ type: 'test', data: 'x'.repeat(1024) }); // 1KB message

    for (let i = 0; i < messageCount; i++) {
      ws.send(testMessage);
      sendMeter.recordOperation();
    }
    const sendResults = sendMeter.end();

    // Benchmark receiving messages
    receiveMeter.start();
    let receivedCount = 0;
    
    await new Promise(resolve => {
      ws.onmessage = () => {
        receivedCount++;
        receiveMeter.recordOperation();
        if (receivedCount >= messageCount) {
          resolve(undefined);
        }
      };
    });
    
    const receiveResults = receiveMeter.end();
    ws.close();

    return {
      send: sendResults,
      receive: receiveResults
    };
  }

  /**
   * Benchmark large message handling
   */
  static async benchmarkLargeMessages(): Promise<PerformanceMetrics[]> {
    const results: PerformanceMetrics[] = [];
    const messageSizes = [1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB

    for (const size of messageSizes) {
      const meter = new TestPerformanceMeter();
      const ws = new WebSocket('ws://localhost:8080');
      
      await new Promise((resolve, reject) => {
        ws.onopen = resolve;
        ws.onerror = reject;
        setTimeout(reject, 5000);
      });

      meter.start();
      const largeMessage = JSON.stringify({ data: 'x'.repeat(size) });
      
      for (let i = 0; i < 100; i++) {
        ws.send(largeMessage);
        meter.recordOperation();
      }

      const result = meter.end();
      results.push({ ...result, messageSize: size } as any);
      
      ws.close();
    }

    return results;
  }
}

// ============================================================================
// Terminal Performance Benchmarks
// ============================================================================

class TerminalPerformanceBenchmarks {
  
  /**
   * Benchmark terminal rendering performance
   */
  static async benchmarkTerminalRendering(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    // Mock terminal setup
    const terminal = {
      write: jest.fn(),
      clear: jest.fn(),
      resize: jest.fn()
    };

    meter.start();

    // Simulate high-frequency terminal writes
    const iterations = 10000;
    const testData = 'Terminal output line with some color codes \x1b[31mRed\x1b[0m\n';

    for (let i = 0; i < iterations; i++) {
      terminal.write(testData);
      meter.recordOperation();
    }

    return meter.end();
  }

  /**
   * Benchmark scrollback buffer management
   */
  static async benchmarkScrollbackBuffer(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    class MockScrollbackBuffer {
      private lines: string[] = [];
      private maxLines: number = 10000;

      addLine(line: string): void {
        this.lines.push(line);
        if (this.lines.length > this.maxLines) {
          this.lines.shift();
        }
      }

      getLines(): string[] {
        return this.lines;
      }

      clear(): void {
        this.lines = [];
      }
    }

    const buffer = new MockScrollbackBuffer();
    meter.start();

    // Add many lines to test buffer management
    for (let i = 0; i < 50000; i++) {
      buffer.addLine(`Line ${i}: Some terminal output with varying length content...`);
      meter.recordOperation();
    }

    return meter.end();
  }

  /**
   * Benchmark terminal resizing operations
   */
  static async benchmarkTerminalResize(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    const terminal = {
      cols: 80,
      rows: 24,
      resize: (cols: number, rows: number) => {
        terminal.cols = cols;
        terminal.rows = rows;
      }
    };

    meter.start();

    // Simulate rapid resize operations
    for (let i = 0; i < 1000; i++) {
      const cols = 80 + (i % 100);
      const rows = 24 + (i % 50);
      terminal.resize(cols, rows);
      meter.recordOperation();
    }

    return meter.end();
  }

  /**
   * Benchmark ANSI escape sequence processing
   */
  static async benchmarkAnsiProcessing(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    const ansiSequences = [
      '\x1b[31mRed text\x1b[0m',
      '\x1b[1mBold\x1b[0m',
      '\x1b[4mUnderline\x1b[0m',
      '\x1b[7mReverse\x1b[0m',
      '\x1b[2JClear screen\x1b[H',
      '\x1b[10;20HPosition cursor',
      '\x1b[KClear line',
      '\x1b[38;5;196mColor 256\x1b[0m'
    ];

    class MockAnsiProcessor {
      process(text: string): string {
        // Simulate ANSI processing
        return text.replace(/\x1b\[[0-9;]*m/g, '');
      }
    }

    const processor = new MockAnsiProcessor();
    meter.start();

    for (let i = 0; i < 10000; i++) {
      const sequence = ansiSequences[i % ansiSequences.length];
      processor.process(sequence);
      meter.recordOperation();
    }

    return meter.end();
  }
}

// ============================================================================
// State Management Performance Benchmarks
// ============================================================================

class StatePerformanceBenchmarks {
  
  /**
   * Benchmark store operations
   */
  static async benchmarkStoreOperations(): Promise<{
    add: PerformanceMetrics;
    update: PerformanceMetrics;
    remove: PerformanceMetrics;
  }> {
    const mockStore = {
      sessions: new Map(),
      addSession: (session: any) => {
        mockStore.sessions.set(session.id, session);
      },
      updateSession: (id: string, updates: any) => {
        const session = mockStore.sessions.get(id);
        if (session) {
          mockStore.sessions.set(id, { ...session, ...updates });
        }
      },
      removeSession: (id: string) => {
        mockStore.sessions.delete(id);
      }
    };

    // Benchmark adding sessions
    const addMeter = new TestPerformanceMeter();
    addMeter.start();
    
    for (let i = 0; i < 10000; i++) {
      mockStore.addSession({
        id: `session-${i}`,
        name: `Terminal ${i}`,
        isActive: i === 0,
        lastActivity: new Date()
      });
      addMeter.recordOperation();
    }
    
    const addResults = addMeter.end();

    // Benchmark updating sessions
    const updateMeter = new TestPerformanceMeter();
    updateMeter.start();
    
    for (let i = 0; i < 10000; i++) {
      mockStore.updateSession(`session-${i}`, { 
        name: `Updated Terminal ${i}`,
        lastActivity: new Date()
      });
      updateMeter.recordOperation();
    }
    
    const updateResults = updateMeter.end();

    // Benchmark removing sessions
    const removeMeter = new TestPerformanceMeter();
    removeMeter.start();
    
    for (let i = 0; i < 10000; i++) {
      mockStore.removeSession(`session-${i}`);
      removeMeter.recordOperation();
    }
    
    const removeResults = removeMeter.end();

    return {
      add: addResults,
      update: updateResults,
      remove: removeResults
    };
  }

  /**
   * Benchmark state serialization/deserialization
   */
  static async benchmarkStateSerialization(): Promise<{
    serialize: PerformanceMetrics;
    deserialize: PerformanceMetrics;
  }> {
    // Create large state object
    const largeState = {
      sessions: Array.from({ length: 1000 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i}`,
        isActive: i === 0,
        lastActivity: new Date(),
        history: Array.from({ length: 100 }, (_, j) => `Command ${j}: ${'x'.repeat(100)}`)
      })),
      activeSessionId: 'session-0',
      sidebarOpen: true,
      settings: {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'Monaco',
        cursorStyle: 'block'
      }
    };

    // Benchmark serialization
    const serializeMeter = new TestPerformanceMeter();
    serializeMeter.start();
    
    for (let i = 0; i < 100; i++) {
      JSON.stringify(largeState);
      serializeMeter.recordOperation();
    }
    
    const serializeResults = serializeMeter.end();

    // Benchmark deserialization
    const serializedState = JSON.stringify(largeState);
    const deserializeMeter = new TestPerformanceMeter();
    deserializeMeter.start();
    
    for (let i = 0; i < 100; i++) {
      JSON.parse(serializedState);
      deserializeMeter.recordOperation();
    }
    
    const deserializeResults = deserializeMeter.end();

    return {
      serialize: serializeResults,
      deserialize: deserializeResults
    };
  }
}

// ============================================================================
// Component Rendering Performance Benchmarks
// ============================================================================

class ComponentPerformanceBenchmarks {
  
  /**
   * Benchmark component rendering performance
   */
  static async benchmarkComponentRendering(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    // Mock React rendering
    const mockRender = (component: any, props: any) => {
      // Simulate component rendering overhead
      const start = performance.now();
      
      // Simulate virtual DOM operations
      const vdom = {
        type: component,
        props,
        children: []
      };
      
      // Simulate reconciliation
      const reconciled = { ...vdom, reconciled: true };
      
      // Simulate DOM updates
      const domTime = performance.now() - start;
      return { vdom: reconciled, renderTime: domTime };
    };

    meter.start();

    // Simulate rendering many components
    for (let i = 0; i < 1000; i++) {
      mockRender('Terminal', {
        sessionId: `session-${i}`,
        className: 'terminal-component',
        onData: () => {},
        onResize: () => {}
      });
      meter.recordOperation();
    }

    return meter.end();
  }

  /**
   * Benchmark list rendering performance
   */
  static async benchmarkListRendering(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    const mockRenderList = (items: any[]) => {
      return items.map((item, index) => ({
        key: item.id || index,
        type: 'ListItem',
        props: item
      }));
    };

    meter.start();

    // Create large lists and render them
    for (let listSize = 100; listSize <= 10000; listSize += 100) {
      const items = Array.from({ length: listSize }, (_, i) => ({
        id: `item-${i}`,
        name: `Terminal ${i}`,
        isActive: i === 0
      }));
      
      mockRenderList(items);
      meter.recordOperation();
    }

    return meter.end();
  }
}

// ============================================================================
// Memory Performance Benchmarks
// ============================================================================

class MemoryPerformanceBenchmarks {
  
  /**
   * Benchmark memory usage patterns
   */
  static async benchmarkMemoryUsage(): Promise<{
    baseline: number;
    peak: number;
    afterGC: number;
    leaks: any[];
  }> {
    const measurements = {
      baseline: 0,
      peak: 0,
      afterGC: 0,
      leaks: [] as any[]
    };

    // Get baseline memory
    if (global.gc) global.gc();
    measurements.baseline = this.getMemoryUsage();

    // Create memory pressure
    const largeObjects = [];
    for (let i = 0; i < 1000; i++) {
      largeObjects.push({
        id: i,
        data: new Array(10000).fill(`data-${i}`),
        timestamp: new Date(),
        meta: {
          sessions: new Array(100).fill(null).map((_, j) => ({
            id: `session-${i}-${j}`,
            content: 'x'.repeat(1000)
          }))
        }
      });
    }

    measurements.peak = this.getMemoryUsage();

    // Clear references and force GC
    largeObjects.length = 0;
    if (global.gc) global.gc();
    
    measurements.afterGC = this.getMemoryUsage();

    // Check for potential leaks
    const memoryDelta = measurements.afterGC - measurements.baseline;
    if (memoryDelta > 1024 * 1024) { // More than 1MB difference
      measurements.leaks.push({
        type: 'potential_leak',
        delta: memoryDelta,
        description: 'Memory not fully released after GC'
      });
    }

    return measurements;
  }

  /**
   * Benchmark garbage collection impact
   */
  static async benchmarkGarbageCollection(): Promise<PerformanceMetrics> {
    const meter = new TestPerformanceMeter();
    
    if (!global.gc) {
      throw new Error('Garbage collection not available - run with --expose-gc');
    }

    meter.start();

    // Create and destroy objects to trigger GC
    for (let i = 0; i < 100; i++) {
      const objects = [];
      
      // Create many objects
      for (let j = 0; j < 10000; j++) {
        objects.push({
          id: j,
          data: new Array(100).fill(`item-${j}`)
        });
      }
      
      // Force GC
      const gcStart = performance.now();
      global.gc();
      const gcDuration = performance.now() - gcStart;
      
      meter.recordOperation();
      
      // Clear objects
      objects.length = 0;
    }

    return meter.end();
  }

  private static getMemoryUsage(): number {
    if (typeof performance !== 'undefined' && (performance as any).memory) {
      return (performance as any).memory.usedJSHeapSize;
    }
    if (process && process.memoryUsage) {
      return process.memoryUsage().heapUsed;
    }
    return 0;
  }
}

// ============================================================================
// Network Performance Benchmarks
// ============================================================================

class NetworkPerformanceBenchmarks {
  
  /**
   * Benchmark network latency simulation
   */
  static async benchmarkNetworkLatency(): Promise<PerformanceMetrics[]> {
    const latencies = [0, 50, 100, 250, 500, 1000]; // ms
    const results: PerformanceMetrics[] = [];

    for (const latency of latencies) {
      const meter = new TestPerformanceMeter();
      meter.start();

      // Simulate operations with network latency
      const operations = 100;
      const promises = [];

      for (let i = 0; i < operations; i++) {
        const promise = new Promise(resolve => {
          setTimeout(() => {
            meter.recordOperation();
            resolve(undefined);
          }, latency);
        });
        promises.push(promise);
      }

      await Promise.all(promises);
      const result = meter.end();
      results.push({ ...result, latency } as any);
    }

    return results;
  }

  /**
   * Benchmark bandwidth simulation
   */
  static async benchmarkBandwidth(): Promise<PerformanceMetrics[]> {
    const bandwidths = [
      { name: '56k Modem', bytesPerSecond: 7000 },
      { name: 'DSL', bytesPerSecond: 125000 },
      { name: 'Cable', bytesPerSecond: 1250000 },
      { name: 'Fiber', bytesPerSecond: 12500000 }
    ];

    const results: PerformanceMetrics[] = [];

    for (const bandwidth of bandwidths) {
      const meter = new TestPerformanceMeter();
      const messageSize = 1024; // 1KB message
      const transmissionTime = (messageSize / bandwidth.bytesPerSecond) * 1000; // ms

      meter.start();

      // Simulate sending 100 messages with bandwidth limitation
      for (let i = 0; i < 100; i++) {
        await new Promise(resolve => setTimeout(resolve, transmissionTime));
        meter.recordOperation();
      }

      const result = meter.end();
      results.push({ ...result, bandwidth: bandwidth.name } as any);
    }

    return results;
  }
}

// ============================================================================
// Performance Test Runner
// ============================================================================

class PerformanceTestRunner {
  
  static async runAllBenchmarks(): Promise<{
    websocket: any;
    terminal: any;
    state: any;
    component: any;
    memory: any;
    network: any;
  }> {
    console.log('Starting comprehensive performance benchmarks...');

    const results = {
      websocket: {} as any,
      terminal: {} as any,
      state: {} as any,
      component: {} as any,
      memory: {} as any,
      network: {} as any
    };

    try {
      // WebSocket benchmarks
      console.log('Running WebSocket benchmarks...');
      results.websocket.connectionSpeed = await WebSocketPerformanceBenchmarks.benchmarkConnectionSpeed();
      results.websocket.messageThroughput = await WebSocketPerformanceBenchmarks.benchmarkMessageThroughput();
      results.websocket.largeMessages = await WebSocketPerformanceBenchmarks.benchmarkLargeMessages();

      // Terminal benchmarks
      console.log('Running Terminal benchmarks...');
      results.terminal.rendering = await TerminalPerformanceBenchmarks.benchmarkTerminalRendering();
      results.terminal.scrollback = await TerminalPerformanceBenchmarks.benchmarkScrollbackBuffer();
      results.terminal.resize = await TerminalPerformanceBenchmarks.benchmarkTerminalResize();
      results.terminal.ansi = await TerminalPerformanceBenchmarks.benchmarkAnsiProcessing();

      // State benchmarks
      console.log('Running State benchmarks...');
      results.state.operations = await StatePerformanceBenchmarks.benchmarkStoreOperations();
      results.state.serialization = await StatePerformanceBenchmarks.benchmarkStateSerialization();

      // Component benchmarks
      console.log('Running Component benchmarks...');
      results.component.rendering = await ComponentPerformanceBenchmarks.benchmarkComponentRendering();
      results.component.listRendering = await ComponentPerformanceBenchmarks.benchmarkListRendering();

      // Memory benchmarks
      console.log('Running Memory benchmarks...');
      results.memory.usage = await MemoryPerformanceBenchmarks.benchmarkMemoryUsage();
      
      if (global.gc) {
        results.memory.garbageCollection = await MemoryPerformanceBenchmarks.benchmarkGarbageCollection();
      }

      // Network benchmarks
      console.log('Running Network benchmarks...');
      results.network.latency = await NetworkPerformanceBenchmarks.benchmarkNetworkLatency();
      results.network.bandwidth = await NetworkPerformanceBenchmarks.benchmarkBandwidth();

      console.log('All performance benchmarks completed successfully');
      
    } catch (error) {
      console.error('Performance benchmark failed:', error);
      throw error;
    }

    return results;
  }

  static generatePerformanceReport(results: any): string {
    let report = '# Performance Benchmark Report\n\n';
    report += `Generated: ${new Date().toISOString()}\n\n`;

    // WebSocket Performance
    report += '## WebSocket Performance\n\n';
    if (results.websocket.connectionSpeed) {
      report += `- **Connection Speed**: ${results.websocket.connectionSpeed.operationsPerSecond.toFixed(2)} connections/sec\n`;
    }
    if (results.websocket.messageThroughput) {
      report += `- **Message Send Rate**: ${results.websocket.messageThroughput.send.operationsPerSecond.toFixed(2)} messages/sec\n`;
      report += `- **Message Receive Rate**: ${results.websocket.messageThroughput.receive.operationsPerSecond.toFixed(2)} messages/sec\n`;
    }

    // Terminal Performance
    report += '\n## Terminal Performance\n\n';
    if (results.terminal.rendering) {
      report += `- **Rendering Speed**: ${results.terminal.rendering.operationsPerSecond.toFixed(2)} writes/sec\n`;
    }
    if (results.terminal.scrollback) {
      report += `- **Scrollback Buffer**: ${results.terminal.scrollback.operationsPerSecond.toFixed(2)} lines/sec\n`;
    }

    // State Performance
    report += '\n## State Management Performance\n\n';
    if (results.state.operations) {
      report += `- **Add Operations**: ${results.state.operations.add.operationsPerSecond.toFixed(2)} ops/sec\n`;
      report += `- **Update Operations**: ${results.state.operations.update.operationsPerSecond.toFixed(2)} ops/sec\n`;
      report += `- **Remove Operations**: ${results.state.operations.remove.operationsPerSecond.toFixed(2)} ops/sec\n`;
    }

    // Memory Usage
    report += '\n## Memory Performance\n\n';
    if (results.memory.usage) {
      const usage = results.memory.usage;
      report += `- **Baseline Memory**: ${(usage.baseline / 1024 / 1024).toFixed(2)} MB\n`;
      report += `- **Peak Memory**: ${(usage.peak / 1024 / 1024).toFixed(2)} MB\n`;
      report += `- **After GC**: ${(usage.afterGC / 1024 / 1024).toFixed(2)} MB\n`;
      
      if (usage.leaks.length > 0) {
        report += `- **Memory Leaks Detected**: ${usage.leaks.length}\n`;
      }
    }

    report += '\n## Recommendations\n\n';
    
    // Add performance recommendations based on results
    if (results.websocket.messageThroughput && 
        results.websocket.messageThroughput.send.operationsPerSecond < 1000) {
      report += '- Consider implementing message batching for WebSocket communications\n';
    }
    
    if (results.terminal.rendering && 
        results.terminal.rendering.operationsPerSecond < 10000) {
      report += '- Terminal rendering performance may benefit from virtualization\n';
    }
    
    if (results.memory.usage && results.memory.usage.leaks.length > 0) {
      report += '- Memory leaks detected - review component cleanup and event listener removal\n';
    }

    return report;
  }
}

export {
  TestPerformanceMeter,
  WebSocketPerformanceBenchmarks,
  TerminalPerformanceBenchmarks,
  StatePerformanceBenchmarks,
  ComponentPerformanceBenchmarks,
  MemoryPerformanceBenchmarks,
  NetworkPerformanceBenchmarks,
  PerformanceTestRunner
};