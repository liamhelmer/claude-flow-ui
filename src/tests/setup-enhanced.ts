/**
 * Enhanced Jest Setup for React Testing Library
 * Runs after environment setup for each test file
 */

import '@testing-library/jest-dom';
import 'jest-axe/extend-expect';

// Type declarations for global variables
declare global {
  var __TEST_START_TIME__: number;
  var testCleanup: () => Promise<void>;
}

// Store test start time for duration calculation
(global as any).__TEST_START_TIME__ = Date.now();

// Enhanced cleanup function
(global as any).testCleanup = async () => {
  // Cleanup any remaining timers, promises, etc.
  await new Promise(resolve => setTimeout(resolve, 0));
};

// Mock console methods for cleaner test output
const originalError = console.error;
beforeAll(() => {
  console.error = (...args) => {
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('Warning: ReactDOM.render is deprecated') ||
       args[0].includes('Warning: An invalid form control') ||
       args[0].includes('The pseudo class'))
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  console.error = originalError;
});

// Test environment validation
if (typeof window !== 'undefined') {
  console.log('✅ Enhanced test setup loaded');
}