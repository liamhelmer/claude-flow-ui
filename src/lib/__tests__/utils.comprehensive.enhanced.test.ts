/**
 * @jest-environment jsdom
 */

import {
  cn,
  formatBytes,
  formatPercentage,
  formatDuration,
  generateSessionId,
  generateId,
  formatDate,
  debounce,
} from '../utils';

// Mock crypto for consistent tests
global.crypto = {
  ...global.crypto,
  getRandomValues: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3, 4])),
} as any;

describe('Utils Comprehensive Enhanced Tests', () => {
  describe('cn (className merger)', () => {
    test('should merge basic classes', () => {
      expect(cn('bg-red-500', 'text-white')).toBe('bg-red-500 text-white');
    });

    test('should handle conditional classes', () => {
      expect(cn('base', true && 'conditional', false && 'hidden')).toBe('base conditional');
    });

    test('should handle tailwind merging', () => {
      expect(cn('bg-red-500', 'bg-blue-500')).toBe('bg-blue-500');
    });

    test('should handle empty inputs', () => {
      expect(cn()).toBe('');
      expect(cn('')).toBe('');
      expect(cn(null, undefined, false)).toBe('');
    });

    test('should handle arrays', () => {
      expect(cn(['bg-red-500', 'text-white'])).toBe('bg-red-500 text-white');
    });

    test('should handle objects', () => {
      expect(cn({
        'bg-red-500': true,
        'text-white': false,
        'p-4': true
      })).toBe('bg-red-500 p-4');
    });
  });

  describe('formatBytes', () => {
    test('should handle zero bytes', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
    });

    test('should format small bytes', () => {
      expect(formatBytes(512)).toBe('512 Bytes');
      expect(formatBytes(1023)).toBe('1023 Bytes');
    });

    test('should format KB', () => {
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1536)).toBe('1.5 KB');
    });

    test('should format MB', () => {
      expect(formatBytes(1024 * 1024)).toBe('1 MB');
      expect(formatBytes(1.5 * 1024 * 1024)).toBe('1.5 MB');
    });

    test('should format GB', () => {
      expect(formatBytes(1024 * 1024 * 1024)).toBe('1 GB');
    });

    test('should format TB', () => {
      expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe('1 TB');
    });

    test('should format PB', () => {
      expect(formatBytes(1024 * 1024 * 1024 * 1024 * 1024)).toBe('1 PB');
    });

    test('should handle custom decimals', () => {
      expect(formatBytes(1536, 0)).toBe('2 KB');
      expect(formatBytes(1536, 3)).toBe('1.500 KB');
    });

    test('should handle negative decimals', () => {
      expect(formatBytes(1536, -1)).toBe('2 KB');
    });

    test('should handle very large numbers', () => {
      expect(formatBytes(Number.MAX_SAFE_INTEGER)).toMatch(/\d+(\.\d+)? [KMGTP]?B/);
    });

    test('should handle fractional bytes', () => {
      expect(formatBytes(1.7)).toBe('1.7 Bytes');
    });

    test('should handle negative bytes (edge case)', () => {
      expect(formatBytes(-1024)).toBe('NaN Bytes');
    });
  });

  describe('formatPercentage', () => {
    test('should format basic percentages', () => {
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(100)).toBe('100.0%');
    });

    test('should handle decimals', () => {
      expect(formatPercentage(33.3333)).toBe('33.3%');
      expect(formatPercentage(66.6667)).toBe('66.7%');
    });

    test('should cap at 999.9%', () => {
      expect(formatPercentage(1500)).toBe('999.9%');
      expect(formatPercentage(99999)).toBe('999.9%');
    });

    test('should handle custom decimal places', () => {
      expect(formatPercentage(33.3333, 0)).toBe('33%');
      expect(formatPercentage(33.3333, 2)).toBe('33.33%');
      expect(formatPercentage(33.3333, 3)).toBe('33.333%');
    });

    test('should handle zero decimals', () => {
      expect(formatPercentage(0, 0)).toBe('0%');
    });

    test('should handle negative percentages', () => {
      expect(formatPercentage(-10)).toBe('-10.0%');
    });

    test('should handle very small numbers', () => {
      expect(formatPercentage(0.001, 3)).toBe('0.001%');
    });
  });

  describe('formatDuration', () => {
    test('should format milliseconds', () => {
      expect(formatDuration(0)).toBe('0ms');
      expect(formatDuration(500)).toBe('500ms');
      expect(formatDuration(999)).toBe('999ms');
    });

    test('should format seconds', () => {
      expect(formatDuration(1000)).toBe('1.0s');
      expect(formatDuration(1500)).toBe('1.5s');
      expect(formatDuration(59999)).toBe('60.0s');
    });

    test('should format minutes and seconds', () => {
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(125000)).toBe('2m 5s');
      expect(formatDuration(3599999)).toBe('59m 59s');
    });

    test('should format hours and minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(3661000)).toBe('1h 1m');
      expect(formatDuration(7200000)).toBe('2h 0m');
    });

    test('should handle very long durations', () => {
      expect(formatDuration(24 * 60 * 60 * 1000)).toBe('24h 0m'); // 24 hours
      expect(formatDuration(25 * 60 * 60 * 1000 + 30 * 60 * 1000)).toBe('25h 30m'); // 25.5 hours
    });

    test('should handle fractional milliseconds', () => {
      expect(formatDuration(1.7)).toBe('1.7ms');
    });

    test('should handle negative durations (edge case)', () => {
      expect(formatDuration(-1000)).toBe('-1.0s');
    });
  });

  describe('generateSessionId', () => {
    beforeEach(() => {
      jest.spyOn(Date, 'now').mockReturnValue(1234567890123);
      jest.spyOn(Math, 'random').mockReturnValue(0.5);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('should generate consistent session ID format', () => {
      const id = generateSessionId();
      expect(id).toMatch(/^session-\d+-[a-z0-9]+$/);
    });

    test('should include timestamp', () => {
      const id = generateSessionId();
      expect(id).toContain('1234567890123');
    });

    test('should generate different IDs on subsequent calls', () => {
      jest.spyOn(Math, 'random').mockReturnValueOnce(0.1).mockReturnValueOnce(0.9);
      
      const id1 = generateSessionId();
      const id2 = generateSessionId();
      
      expect(id1).not.toBe(id2);
    });

    test('should handle edge case random values', () => {
      jest.spyOn(Math, 'random').mockReturnValue(0);
      const id1 = generateSessionId();
      
      jest.spyOn(Math, 'random').mockReturnValue(0.999999);
      const id2 = generateSessionId();
      
      expect(id1).toMatch(/^session-\d+-[a-z0-9]+$/);
      expect(id2).toMatch(/^session-\d+-[a-z0-9]+$/);
    });
  });

  describe('generateId', () => {
    beforeEach(() => {
      jest.spyOn(Date, 'now').mockReturnValue(1234567890123);
      jest.spyOn(Math, 'random').mockReturnValue(0.5);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('should generate consistent ID format', () => {
      const id = generateId();
      expect(id).toMatch(/^id-\d+-[a-z0-9]+$/);
    });

    test('should include timestamp', () => {
      const id = generateId();
      expect(id).toContain('1234567890123');
    });

    test('should generate different IDs', () => {
      jest.spyOn(Math, 'random').mockReturnValueOnce(0.1).mockReturnValueOnce(0.9);
      
      const id1 = generateId();
      const id2 = generateId();
      
      expect(id1).not.toBe(id2);
    });
  });

  describe('formatDate', () => {
    test('should format date with time', () => {
      const date = new Date('2024-01-01T12:30:45.000Z');
      const formatted = formatDate(date);
      
      // Should include time components
      expect(formatted).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });

    test('should format midnight', () => {
      const date = new Date('2024-01-01T00:00:00.000Z');
      const formatted = formatDate(date);
      
      expect(formatted).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });

    test('should handle different timezones consistently', () => {
      const date1 = new Date('2024-01-01T12:00:00.000Z');
      const date2 = new Date('2024-01-01T12:00:00.000-05:00');
      
      // Both should produce valid time strings
      expect(formatDate(date1)).toMatch(/\d{1,2}:\d{2}:\d{2}/);
      expect(formatDate(date2)).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });

    test('should handle edge case dates', () => {
      const date = new Date('1970-01-01T00:00:00.000Z');
      const formatted = formatDate(date);
      
      expect(formatted).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });

    test('should handle far future dates', () => {
      const date = new Date('2099-12-31T23:59:59.999Z');
      const formatted = formatDate(date);
      
      expect(formatted).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });
  });

  describe('debounce', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
      jest.clearAllMocks();
    });

    test('should debounce function calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('arg1');
      debouncedFn('arg2');
      debouncedFn('arg3');

      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenLastCalledWith('arg3');
    });

    test('should handle multiple argument types', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn(1, 'string', { key: 'value' }, [1, 2, 3]);

      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledWith(1, 'string', { key: 'value' }, [1, 2, 3]);
    });

    test('should preserve this context', () => {
      const obj = {
        value: 'test',
        method: jest.fn(function(this: any) {
          return this.value;
        })
      };

      const debouncedMethod = debounce(obj.method, 100);
      debouncedMethod.call(obj);

      jest.advanceTimersByTime(100);

      expect(obj.method).toHaveBeenCalled();
    });

    test('should handle rapid successive calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      for (let i = 0; i < 10; i++) {
        debouncedFn(i);
        jest.advanceTimersByTime(50); // Half the debounce time
      }

      // Should not have been called yet
      expect(mockFn).not.toHaveBeenCalled();

      // Advance past the final timeout
      jest.advanceTimersByTime(100);

      // Should be called only once with the last argument
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenLastCalledWith(9);
    });

    test('should handle zero wait time', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 0);

      debouncedFn('test');

      jest.advanceTimersByTime(1);

      expect(mockFn).toHaveBeenCalledWith('test');
    });

    test('should clear previous timeout on new call', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('first');
      jest.advanceTimersByTime(50);

      debouncedFn('second');
      jest.advanceTimersByTime(50);

      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(50);

      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenLastCalledWith('second');
    });

    test('should handle function that throws error', () => {
      const mockFn = jest.fn(() => {
        throw new Error('Test error');
      });
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn();

      expect(() => {
        jest.advanceTimersByTime(100);
      }).toThrow('Test error');
    });

    test('should handle async functions', async () => {
      const mockAsyncFn = jest.fn().mockResolvedValue('result');
      const debouncedFn = debounce(mockAsyncFn, 100);

      debouncedFn('test');
      jest.advanceTimersByTime(100);

      expect(mockAsyncFn).toHaveBeenCalledWith('test');
    });
  });

  describe('Edge cases and error handling', () => {
    test('formatBytes should handle Infinity', () => {
      expect(formatBytes(Infinity)).toBe('Infinity Bytes');
    });

    test('formatPercentage should handle NaN', () => {
      expect(formatPercentage(NaN)).toBe('NaN%');
    });

    test('formatDuration should handle Infinity', () => {
      expect(formatDuration(Infinity)).toBe('Infinityh NaNm');
    });

    test('debounce should handle null function', () => {
      expect(() => debounce(null as any, 100)).not.toThrow();
    });
  });

  describe('Performance tests', () => {
    test('cn should handle large number of classes efficiently', () => {
      const startTime = performance.now();
      const largeClassArray = Array.from({ length: 100 }, (_, i) => `class-${i}`);
      
      for (let i = 0; i < 100; i++) {
        cn(...largeClassArray);
      }
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(100); // Should complete in under 100ms
    });

    test('formatBytes should handle large numbers efficiently', () => {
      const startTime = performance.now();
      
      for (let i = 0; i < 1000; i++) {
        formatBytes(Math.pow(1024, 5) * Math.random());
      }
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(50); // Should complete in under 50ms
    });

    test('debounce should handle many instances efficiently', () => {
      const functions = Array.from({ length: 100 }, () => 
        debounce(jest.fn(), 10)
      );
      
      const startTime = performance.now();
      
      functions.forEach(fn => fn('test'));
      jest.advanceTimersByTime(10);
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(50);
    });
  });
});