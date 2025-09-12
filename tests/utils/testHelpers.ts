/**
 * Enhanced Test Helpers for Stability and Debugging
 */

export const waitFor = async (conditionFn: () => boolean | Promise<boolean>, timeout = 5000, interval = 100): Promise<void> => {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    try {
      const result = await conditionFn();
      if (result) return;
    } catch (error) {
      // Continue waiting even if condition throws
    }
    
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  throw new Error(`Condition not met within ${timeout}ms`);
};

export const waitForNextTick = (): Promise<void> => {
  return new Promise(resolve => setImmediate(resolve));
};

export const waitForTimeout = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

export const flushPromises = async (): Promise<void> => {
  await new Promise(resolve => setImmediate(resolve));
};

export const mockConsole = () => {
  const originalConsole = { ...console };
  const mockMethods = {
    log: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  };
  
  Object.assign(console, mockMethods);
  
  return {
    restore: () => Object.assign(console, originalConsole),
    mocks: mockMethods,
  };
};

export const withTimeout = <T>(promise: Promise<T>, timeoutMs: number, errorMessage?: string): Promise<T> => {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => 
      setTimeout(() => reject(new Error(errorMessage || `Operation timed out after ${timeoutMs}ms`)), timeoutMs)
    )
  ]);
};

export const retryOperation = async <T>(
  operation: () => Promise<T>,
  maxRetries = 3,
  delay = 100
): Promise<T> => {
  let lastError: Error;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxRetries - 1) {
        await waitForTimeout(delay * Math.pow(2, attempt)); // Exponential backoff
      }
    }
  }
  
  throw lastError!;
};

export const suppressConsoleOutput = (methods: Array<keyof Console> = ['log', 'warn', 'error']) => {
  const originalMethods: Partial<Console> = {};
  
  methods.forEach(method => {
    (originalMethods as any)[method] = (console as any)[method];
    (console as any)[method] = jest.fn();
  });
  
  return () => {
    methods.forEach(method => {
      if (originalMethods[method]) {
        (console as any)[method] = originalMethods[method];
      }
    });
  };
};

export const createMockFile = (content: string = '', name: string = 'test-file.txt') => {
  return new File([content], name, { type: 'text/plain' });
};

export const createMockFileList = (files: File[]) => {
  const fileList = {
    length: files.length,
    item: (index: number) => files[index] || null,
    [Symbol.iterator]: function* () {
      for (const file of files) {
        yield file;
      }
    },
  };
  
  Object.defineProperty(fileList, 'length', { value: files.length });
  files.forEach((file, index) => {
    Object.defineProperty(fileList, index, { value: file });
  });
  
  return fileList as FileList;
};

export const mockDateNow = (timestamp: number) => {
  const originalDateNow = Date.now;
  Date.now = jest.fn(() => timestamp);
  
  return () => {
    Date.now = originalDateNow;
  };
};

export const mockPerformanceNow = (value: number) => {
  const originalPerformanceNow = performance.now;
  performance.now = jest.fn(() => value);
  
  return () => {
    performance.now = originalPerformanceNow;
  };
};

export const createStableId = (prefix: string = 'test'): string => {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

// Test isolation helpers
export const isolateTest = (testFn: () => void | Promise<void>) => {
  return async () => {
    const cleanup: Array<() => void> = [];
    
    try {
      // Store original values
      const originalConsole = { ...console };
      const originalDateNow = Date.now;
      const originalPerformanceNow = performance.now;
      
      cleanup.push(() => {
        Object.assign(console, originalConsole);
        Date.now = originalDateNow;
        performance.now = originalPerformanceNow;
      });
      
      await testFn();
    } finally {
      // Always run cleanup
      cleanup.forEach(fn => {
        try {
          fn();
        } catch (error) {
          console.error('Cleanup error:', error);
        }
      });
    }
  };
};

// Mock stability helpers
export const createStableMock = <T extends (...args: any[]) => any>(
  implementation?: T
): jest.MockedFunction<T> => {
  const mock = jest.fn(implementation) as unknown as jest.MockedFunction<T>;
  
  // Add stability methods
  mock.mockResolvedValue = jest.fn((value) => {
    mock.mockImplementation((() => Promise.resolve(value)) as any);
    return mock;
  });
  
  mock.mockRejectedValue = jest.fn((error) => {
    mock.mockImplementation((() => Promise.reject(error)) as any);
    return mock;
  });
  
  return mock;
};

export const debugTest = (message: string, data?: any) => {
  if (process.env.DEBUG_TESTS === 'true') {
    console.log(`[TEST DEBUG] ${message}`, data ? JSON.stringify(data, null, 2) : '');
  }
};