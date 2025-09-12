/**
 * Memory Leak Detector Test Suite
 * Tests for detecting and preventing memory leaks in React components and services
 */

const { 
  MemoryLeakDetector,
  trackComponentMounts,
  detectEventListenerLeaks,
  monitorMemoryUsage,
  analyzeHeapSnapshots,
  detectClosureLeaks,
  trackResourceCleanup,
  generateLeakReport
} = require('../memory-leak-detector');

// Mock performance and memory APIs
global.performance = {
  now: jest.fn(() => Date.now()),
  mark: jest.fn(),
  measure: jest.fn(),
  getEntriesByType: jest.fn(() => []),
  memory: {
    usedJSHeapSize: 50000000,
    totalJSHeapSize: 100000000,
    jsHeapSizeLimit: 2000000000
  }
};

// Mock garbage collection
global.gc = jest.fn();

// Mock WeakRef and FinalizationRegistry for modern environments
global.WeakRef = class WeakRef {
  constructor(target) {
    this.target = target;
  }
  deref() {
    return this.target;
  }
};

global.FinalizationRegistry = class FinalizationRegistry {
  constructor(callback) {
    this.callback = callback;
  }
  register(target, heldValue) {
    // Simulate cleanup callback after a delay
    setTimeout(() => this.callback(heldValue), 0);
  }
  unregister() {}
};

describe('MemoryLeakDetector', () => {
  let detector;
  let consoleSpy;

  beforeEach(() => {
    detector = new MemoryLeakDetector({
      threshold: 50 * 1024 * 1024, // 50MB
      checkInterval: 1000,
      maxSamples: 100
    });
    
    consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
    jest.clearAllMocks();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    detector.stop();
  });

  describe('Initialization', () => {
    it('should initialize with default options', () => {
      const defaultDetector = new MemoryLeakDetector();
      
      expect(defaultDetector.options.threshold).toBe(100 * 1024 * 1024);
      expect(defaultDetector.options.checkInterval).toBe(5000);
      expect(defaultDetector.isRunning).toBe(false);
    });

    it('should initialize with custom options', () => {
      const customDetector = new MemoryLeakDetector({
        threshold: 200 * 1024 * 1024,
        checkInterval: 2000,
        enableHeapSnapshots: true
      });

      expect(customDetector.options.threshold).toBe(200 * 1024 * 1024);
      expect(customDetector.options.checkInterval).toBe(2000);
      expect(customDetector.options.enableHeapSnapshots).toBe(true);
    });
  });

  describe('Memory Monitoring', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should start monitoring memory usage', () => {
      detector.start();
      
      expect(detector.isRunning).toBe(true);
      expect(detector.interval).toBeDefined();
    });

    it('should collect memory samples periodically', () => {
      detector.start();
      
      // Simulate memory usage changes
      global.performance.memory.usedJSHeapSize = 60000000;
      
      jest.advanceTimersByTime(1000);
      
      expect(detector.samples.length).toBe(1);
      expect(detector.samples[0].usedJSHeapSize).toBe(60000000);
    });

    it('should detect memory growth over time', () => {
      const onLeakDetected = jest.fn();
      detector.on('leak-detected', onLeakDetected);
      
      detector.start();
      
      // Simulate gradual memory increase
      const memoryIncreases = [55, 65, 75, 85, 95]; // MB
      
      memoryIncreases.forEach((mb, index) => {
        global.performance.memory.usedJSHeapSize = mb * 1024 * 1024;
        jest.advanceTimersByTime(1000);
      });

      expect(onLeakDetected).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'memory-growth',
          growthRate: expect.any(Number),
          currentUsage: expect.any(Number)
        })
      );
    });

    it('should respect memory threshold limits', () => {
      const onThresholdExceeded = jest.fn();
      detector.on('threshold-exceeded', onThresholdExceeded);
      
      detector.start();
      
      // Exceed threshold
      global.performance.memory.usedJSHeapSize = 60 * 1024 * 1024;
      
      jest.advanceTimersByTime(1000);
      
      expect(onThresholdExceeded).toHaveBeenCalledWith({
        currentUsage: 60 * 1024 * 1024,
        threshold: 50 * 1024 * 1024
      });
    });

    it('should limit sample collection', () => {
      detector.start();
      
      // Generate more samples than the limit
      for (let i = 0; i < 150; i++) {
        global.performance.memory.usedJSHeapSize = (50 + i) * 1024 * 1024;
        jest.advanceTimersByTime(1000);
      }
      
      expect(detector.samples.length).toBe(100); // maxSamples limit
    });
  });

  describe('Component Tracking', () => {
    it('should track component mount/unmount cycles', () => {
      const componentTracker = trackComponentMounts();
      
      const ComponentA = () => 'Component A';
      const ComponentB = () => 'Component B';
      
      // Simulate component mounting
      componentTracker.onMount('ComponentA', ComponentA);
      componentTracker.onMount('ComponentB', ComponentB);
      
      expect(componentTracker.getActiveComponents()).toEqual({
        ComponentA: { instances: 1, component: ComponentA },
        ComponentB: { instances: 1, component: ComponentB }
      });
      
      // Simulate component unmounting
      componentTracker.onUnmount('ComponentA');
      
      expect(componentTracker.getActiveComponents().ComponentA.instances).toBe(0);
    });

    it('should detect orphaned component instances', () => {
      const componentTracker = trackComponentMounts({
        orphanThreshold: 1000 // 1 second
      });
      
      jest.useFakeTimers();
      
      const Component = () => 'Test Component';
      
      componentTracker.onMount('TestComponent', Component);
      
      // Don't call unmount, simulate component being orphaned
      jest.advanceTimersByTime(2000);
      
      const orphans = componentTracker.detectOrphans();
      
      expect(orphans).toContain('TestComponent');
      
      jest.useRealTimers();
    });

    it('should warn about potential memory leaks in components', () => {
      const componentTracker = trackComponentMounts();
      
      const Component = () => 'Leaky Component';
      
      // Mount same component multiple times without unmounting
      for (let i = 0; i < 10; i++) {
        componentTracker.onMount('LeakyComponent', Component);
      }
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Potential memory leak'),
        expect.stringContaining('LeakyComponent')
      );
    });
  });

  describe('Event Listener Leak Detection', () => {
    it('should track event listener additions and removals', () => {
      const listenerTracker = detectEventListenerLeaks();
      
      const mockElement = {
        addEventListener: jest.fn(),
        removeEventListener: jest.fn()
      };
      
      const handler = () => {};
      
      // Track listener addition
      listenerTracker.trackAddListener(mockElement, 'click', handler);
      
      expect(listenerTracker.getActiveListeners()).toHaveLength(1);
      
      // Track listener removal
      listenerTracker.trackRemoveListener(mockElement, 'click', handler);
      
      expect(listenerTracker.getActiveListeners()).toHaveLength(0);
    });

    it('should detect unremoved event listeners', () => {
      const listenerTracker = detectEventListenerLeaks();
      
      const mockElements = Array.from({ length: 5 }, () => ({
        addEventListener: jest.fn(),
        removeEventListener: jest.fn()
      }));
      
      // Add listeners without removing them
      mockElements.forEach((element, index) => {
        listenerTracker.trackAddListener(element, 'click', () => {});
      });
      
      const leaks = listenerTracker.detectLeaks();
      
      expect(leaks).toHaveLength(5);
      expect(leaks[0]).toMatchObject({
        event: 'click',
        element: expect.any(Object)
      });
    });

    it('should group listeners by event type', () => {
      const listenerTracker = detectEventListenerLeaks();
      
      const element = { addEventListener: jest.fn(), removeEventListener: jest.fn() };
      
      listenerTracker.trackAddListener(element, 'click', () => {});
      listenerTracker.trackAddListener(element, 'click', () => {});
      listenerTracker.trackAddListener(element, 'scroll', () => {});
      
      const summary = listenerTracker.getSummary();
      
      expect(summary.click).toBe(2);
      expect(summary.scroll).toBe(1);
    });
  });

  describe('Heap Snapshot Analysis', () => {
    it('should analyze heap snapshots when available', () => {
      // Mock Chrome DevTools heap snapshot API
      global.chrome = {
        devtools: {
          inspectedWindow: {
            eval: jest.fn((code, callback) => {
              callback(JSON.stringify({
                nodes: [
                  { name: 'Object', size: 1000, retainedSize: 1000 },
                  { name: 'Array', size: 500, retainedSize: 500 }
                ]
              }));
            })
          }
        }
      };

      const analyzer = analyzeHeapSnapshots();
      const snapshot = analyzer.takeSnapshot();

      expect(snapshot).toMatchObject({
        totalSize: expect.any(Number),
        nodeCount: expect.any(Number),
        types: expect.any(Object)
      });
    });

    it('should compare heap snapshots to detect growth', () => {
      const analyzer = analyzeHeapSnapshots();
      
      // Mock two snapshots with different sizes
      const snapshot1 = { totalSize: 1000000, nodeCount: 100 };
      const snapshot2 = { totalSize: 1500000, nodeCount: 150 };
      
      const comparison = analyzer.compareSnapshots(snapshot1, snapshot2);
      
      expect(comparison.sizeGrowth).toBe(500000);
      expect(comparison.nodeGrowth).toBe(50);
      expect(comparison.growthPercentage).toBe(50);
    });
  });

  describe('Closure Leak Detection', () => {
    it('should detect potential closure leaks', () => {
      const closureDetector = detectClosureLeaks();
      
      // Simulate closure that captures large objects
      const largeObject = { data: 'x'.repeat(1000000) };
      
      const createClosure = () => {
        return function leakyFunction() {
          return largeObject.data; // Captures largeObject
        };
      };
      
      const closure = createClosure();
      closureDetector.analyzeClosure(closure, 'leakyFunction');
      
      const leaks = closureDetector.getDetectedLeaks();
      
      expect(leaks).toContainEqual(
        expect.objectContaining({
          name: 'leakyFunction',
          suspiciousCaptures: expect.any(Array)
        })
      );
    });

    it('should track function scope sizes', () => {
      const closureDetector = detectClosureLeaks();
      
      const createHeavyClosure = () => {
        const heavyData = new Array(10000).fill('data');
        const moreData = new Array(5000).fill('more');
        
        return function() {
          return heavyData.length + moreData.length;
        };
      };
      
      const closure = createHeavyClosure();
      const scopeSize = closureDetector.estimateScopeSize(closure);
      
      expect(scopeSize).toBeGreaterThan(100000); // Rough estimate
    });
  });

  describe('Resource Cleanup Tracking', () => {
    it('should track resource allocation and cleanup', () => {
      const resourceTracker = trackResourceCleanup();
      
      const mockResource = {
        id: 'resource-1',
        type: 'websocket',
        cleanup: jest.fn()
      };
      
      // Allocate resource
      resourceTracker.allocate(mockResource);
      
      expect(resourceTracker.getAllocated()).toContain(mockResource);
      
      // Cleanup resource
      resourceTracker.deallocate(mockResource.id);
      
      expect(mockResource.cleanup).toHaveBeenCalled();
      expect(resourceTracker.getAllocated()).not.toContain(mockResource);
    });

    it('should detect uncleaned resources', () => {
      const resourceTracker = trackResourceCleanup({
        timeout: 1000
      });
      
      jest.useFakeTimers();
      
      const mockResource = {
        id: 'uncleaned-resource',
        type: 'interval',
        cleanup: jest.fn()
      };
      
      resourceTracker.allocate(mockResource);
      
      // Don't cleanup, wait for timeout
      jest.advanceTimersByTime(1500);
      
      const leaks = resourceTracker.detectLeaks();
      
      expect(leaks).toContain(mockResource);
      
      jest.useRealTimers();
    });

    it('should categorize resources by type', () => {
      const resourceTracker = trackResourceCleanup();
      
      const resources = [
        { id: '1', type: 'timeout', cleanup: jest.fn() },
        { id: '2', type: 'interval', cleanup: jest.fn() },
        { id: '3', type: 'websocket', cleanup: jest.fn() },
        { id: '4', type: 'websocket', cleanup: jest.fn() }
      ];
      
      resources.forEach(resource => {
        resourceTracker.allocate(resource);
      });
      
      const byType = resourceTracker.getByType();
      
      expect(byType.timeout).toHaveLength(1);
      expect(byType.interval).toHaveLength(1);
      expect(byType.websocket).toHaveLength(2);
    });
  });

  describe('Leak Report Generation', () => {
    it('should generate comprehensive leak report', () => {
      // Setup various leak sources
      const report = generateLeakReport({
        memoryUsage: {
          current: 80 * 1024 * 1024,
          threshold: 50 * 1024 * 1024,
          growth: 30 * 1024 * 1024
        },
        componentLeaks: [
          { name: 'ComponentA', instances: 5 },
          { name: 'ComponentB', instances: 3 }
        ],
        eventListenerLeaks: [
          { event: 'click', count: 10 },
          { event: 'scroll', count: 5 }
        ],
        resourceLeaks: [
          { type: 'websocket', count: 2 },
          { type: 'interval', count: 3 }
        ]
      });
      
      expect(report).toMatchObject({
        summary: {
          totalIssues: expect.any(Number),
          severity: expect.any(String),
          memoryImpact: expect.any(Number)
        },
        details: {
          memory: expect.any(Object),
          components: expect.any(Array),
          eventListeners: expect.any(Array),
          resources: expect.any(Array)
        },
        recommendations: expect.any(Array)
      });
    });

    it('should prioritize leaks by severity', () => {
      const report = generateLeakReport({
        memoryUsage: { current: 150 * 1024 * 1024, threshold: 100 * 1024 * 1024 },
        componentLeaks: [{ name: 'CriticalComponent', instances: 100 }],
        eventListenerLeaks: [{ event: 'resize', count: 1000 }],
        resourceLeaks: []
      });
      
      expect(report.severity).toBe('critical');
      expect(report.recommendations[0].priority).toBe('high');
    });

    it('should include actionable recommendations', () => {
      const report = generateLeakReport({
        componentLeaks: [{ name: 'ComponentA', instances: 10 }],
        eventListenerLeaks: [{ event: 'scroll', count: 50 }]
      });
      
      expect(report.recommendations).toContainEqual(
        expect.objectContaining({
          issue: expect.stringContaining('Component'),
          action: expect.stringContaining('useEffect cleanup'),
          code: expect.any(String)
        })
      );
      
      expect(report.recommendations).toContainEqual(
        expect.objectContaining({
          issue: expect.stringContaining('event listener'),
          action: expect.stringContaining('removeEventListener'),
          code: expect.any(String)
        })
      );
    });
  });

  describe('Performance Impact', () => {
    it('should minimize performance overhead', () => {
      const startTime = performance.now();
      
      detector.start();
      
      // Simulate normal operation
      for (let i = 0; i < 100; i++) {
        global.performance.memory.usedJSHeapSize = (50 + Math.random()) * 1024 * 1024;
        detector.checkMemory(); // Manual check
      }
      
      detector.stop();
      
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      expect(duration).toBeLessThan(100); // Should be very fast
    });

    it('should throttle expensive operations', () => {
      jest.useFakeTimers();
      
      const expensiveOperation = jest.fn();
      detector.on('expensive-check', expensiveOperation);
      
      detector.start();
      
      // Trigger multiple rapid calls
      for (let i = 0; i < 10; i++) {
        detector.triggerExpensiveCheck();
      }
      
      jest.advanceTimersByTime(1000);
      
      // Should be throttled
      expect(expensiveOperation).toHaveBeenCalledTimes(1);
      
      jest.useRealTimers();
    });
  });

  describe('Integration and Edge Cases', () => {
    it('should handle missing memory API gracefully', () => {
      const originalMemory = global.performance.memory;
      delete global.performance.memory;
      
      const gracefulDetector = new MemoryLeakDetector();
      gracefulDetector.start();
      
      expect(gracefulDetector.isRunning).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Memory API not available')
      );
      
      global.performance.memory = originalMemory;
    });

    it('should handle cleanup on page unload', () => {
      detector.start();
      
      // Simulate page unload
      window.dispatchEvent(new Event('beforeunload'));
      
      expect(detector.isRunning).toBe(false);
    });

    it('should detect circular references', () => {
      const closureDetector = detectClosureLeaks();
      
      const obj1 = { name: 'obj1' };
      const obj2 = { name: 'obj2' };
      obj1.ref = obj2;
      obj2.ref = obj1; // Circular reference
      
      const circularClosure = () => {
        return obj1.ref.ref.name; // Access through circular ref
      };
      
      const analysis = closureDetector.analyzeClosure(circularClosure, 'circularTest');
      
      expect(analysis.circularReferences).toBe(true);
    });

    it('should handle weak references correctly', () => {
      if (typeof WeakRef !== 'undefined') {
        const resourceTracker = trackResourceCleanup({ useWeakRefs: true });
        
        let largeObject = { data: 'x'.repeat(1000000) };
        const weakRef = new WeakRef(largeObject);
        
        resourceTracker.allocate({
          id: 'weak-resource',
          ref: weakRef,
          cleanup: jest.fn()
        });
        
        // Clear strong reference
        largeObject = null;
        
        // Force garbage collection if available
        if (typeof gc === 'function') {
          gc();
        }
        
        // Check if weak reference is cleared
        setTimeout(() => {
          expect(weakRef.deref()).toBeUndefined();
        }, 100);
      }
    });
  });
});