/**
 * Test Validation and Health Check Utilities
 */

export const validateTestEnvironment = () => {
  const checks = {
    hasJestGlobals: typeof jest !== 'undefined',
    hasExpect: typeof expect !== 'undefined',
    hasJSDOMEnvironment: typeof window !== 'undefined' && typeof document !== 'undefined',
    hasTestUtils: typeof global.testUtils !== 'undefined',
    hasWebSocketMock: typeof global.WebSocket !== 'undefined',
    hasResizeObserver: typeof global.ResizeObserver !== 'undefined',
    hasIntersectionObserver: typeof global.IntersectionObserver !== 'undefined',
    hasCanvasMock: typeof HTMLCanvasElement !== 'undefined',
    hasLocalStorageMock: typeof localStorage !== 'undefined',
    hasSessionStorageMock: typeof sessionStorage !== 'undefined',
  };

  const failed = Object.entries(checks).filter(([, passed]) => !passed);
  
  if (failed.length > 0) {
    throw new Error(`Test environment validation failed: ${failed.map(([name]) => name).join(', ')}`);
  }

  return checks;
};

export const runHealthChecks = async () => {
  const healthChecks = [];

  // Check mock WebSocket functionality
  healthChecks.push(async () => {
    const ws = new global.WebSocket('ws://test');
    return new Promise((resolve) => {
      ws.addEventListener('open', () => resolve(true));
      setTimeout(() => resolve(false), 100);
    });
  });

  // Check test utilities
  healthChecks.push(async () => {
    await global.testUtils.flushPromises();
    await global.testUtils.waitForNextTick();
    return true;
  });

  // Check timer functionality
  healthChecks.push(async () => {
    let resolved = false;
    setTimeout(() => { resolved = true; }, 0);
    await global.testUtils.wait(50);
    return resolved;
  });

  const results = await Promise.allSettled(healthChecks.map(check => check()));
  const failures = results.filter(result => result.status === 'rejected' || result.value === false);
  
  if (failures.length > 0) {
    console.warn(`Health check failures: ${failures.length}/${results.length}`);
    return false;
  }

  return true;
};

export const measureTestPerformance = () => {
  const startTime = performance.now();
  const startMemory = process.memoryUsage().heapUsed;

  return {
    stop: () => {
      const endTime = performance.now();
      const endMemory = process.memoryUsage().heapUsed;
      
      return {
        duration: endTime - startTime,
        memoryDelta: endMemory - startMemory,
        memoryDeltaMB: (endMemory - startMemory) / 1024 / 1024,
      };
    }
  };
};

export const detectTestLeaks = () => {
  const initialState = {
    timers: jest.getTimerCount?.() || 0,
    memory: process.memoryUsage().heapUsed,
    openHandles: (process as any)._getActiveHandles?.().length || 0,
    openRequests: (process as any)._getActiveRequests?.().length || 0,
  };

  return {
    check: () => {
      const currentState = {
        timers: jest.getTimerCount?.() || 0,
        memory: process.memoryUsage().heapUsed,
        openHandles: (process as any)._getActiveHandles?.().length || 0,
        openRequests: (process as any)._getActiveRequests?.().length || 0,
      };

      const leaks = {
        timers: currentState.timers - initialState.timers,
        memory: currentState.memory - initialState.memory,
        openHandles: currentState.openHandles - initialState.openHandles,
        openRequests: currentState.openRequests - initialState.openRequests,
      };

      const hasLeaks = Object.values(leaks).some(leak => leak > 0);
      
      if (hasLeaks) {
        console.warn('Potential test leaks detected:', leaks);
      }

      return { hasLeaks, leaks, current: currentState, initial: initialState };
    }
  };
};

export const createTestSnapshot = () => {
  return {
    timestamp: Date.now(),
    memory: process.memoryUsage(),
    timers: jest.getTimerCount?.() || 0,
    environment: {
      nodeEnv: process.env.NODE_ENV,
      testTimeout: (jest as any).getTestTimeout?.() || 'unknown',
    },
    globals: {
      hasTestUtils: typeof global.testUtils !== 'undefined',
      hasWebSocket: typeof global.WebSocket !== 'undefined',
    }
  };
};