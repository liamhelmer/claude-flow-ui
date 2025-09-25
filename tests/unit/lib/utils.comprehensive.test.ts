/**
 * Comprehensive unit tests for utility functions
 * Tests all utility functions with edge cases and performance considerations
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
} from '@/lib/utils';

describe('Utility Functions', () => {
  describe('cn (className merger)', () => {
    it('merges class names correctly', () => {
      expect(cn('class1', 'class2')).toBe('class1 class2');
      expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500');
      expect(cn('p-4', 'p-2')).toBe('p-2');
    });

    it('handles conditional classes', () => {
      expect(cn('base', true && 'conditional')).toBe('base conditional');
      expect(cn('base', false && 'conditional')).toBe('base');
      expect(cn('base', null, 'other')).toBe('base other');
      expect(cn('base', undefined, 'other')).toBe('base other');
    });

    it('handles arrays', () => {
      expect(cn(['class1', 'class2'])).toBe('class1 class2');
      expect(cn(['text-red-500'], ['text-blue-500'])).toBe('text-blue-500');
    });

    it('handles objects', () => {
      expect(cn({
        'class1': true,
        'class2': false,
        'class3': true,
      })).toBe('class1 class3');
    });

    it('handles empty inputs', () => {
      expect(cn()).toBe('');
      expect(cn('', '', '')).toBe('');
      expect(cn(null, undefined, false)).toBe('');
    });

    it('handles complex mixing', () => {
      expect(cn(
        'base-class',
        true && 'conditional-class',
        ['array-class1', 'array-class2'],
        { 'object-class': true, 'hidden-class': false },
        null,
        undefined,
        'final-class'
      )).toBe('base-class conditional-class array-class1 array-class2 object-class final-class');
    });

    it('handles Tailwind CSS conflicts', () => {
      // Text size conflicts
      expect(cn('text-sm', 'text-lg')).toBe('text-lg');

      // Padding conflicts
      expect(cn('p-2', 'px-4', 'py-6')).toBe('px-4 py-6');

      // Background color conflicts
      expect(cn('bg-red-500', 'bg-blue-600')).toBe('bg-blue-600');
    });
  });

  describe('formatBytes', () => {
    it('formats bytes correctly', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
      expect(formatBytes(1)).toBe('1 Bytes');
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1536)).toBe('1.5 KB');
      expect(formatBytes(1048576)).toBe('1 MB');
      expect(formatBytes(1073741824)).toBe('1 GB');
      expect(formatBytes(1099511627776)).toBe('1 TB');
      expect(formatBytes(1125899906842624)).toBe('1 PB');
    });

    it('handles decimal places', () => {
      expect(formatBytes(1536, 0)).toBe('2 KB');
      expect(formatBytes(1536, 1)).toBe('1.5 KB');
      expect(formatBytes(1536, 3)).toBe('1.500 KB');
      expect(formatBytes(1536, -1)).toBe('2 KB'); // Should handle negative decimals
    });

    it('handles edge cases', () => {
      expect(formatBytes(-1)).toBe('NaN Bytes');
      expect(formatBytes(-1024)).toBe('NaN Bytes');
      expect(formatBytes(Number.MAX_SAFE_INTEGER)).toContain('PB');
    });

    it('handles very large numbers', () => {
      const veryLarge = Math.pow(1024, 6); // Beyond PB
      expect(formatBytes(veryLarge)).toBe('NaN Bytes');
    });

    it('preserves trailing zeros for high precision', () => {
      expect(formatBytes(1536, 4)).toBe('1.5000 KB');
      expect(formatBytes(1024, 3)).toBe('1.000 KB');
    });

    it('handles floating point precision', () => {
      expect(formatBytes(1023.9999)).toBe('1024 Bytes');
      expect(formatBytes(1048575.9999)).toBe('1 MB');
    });
  });

  describe('formatPercentage', () => {
    it('formats percentages correctly', () => {
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(100)).toBe('100.0%');
      expect(formatPercentage(33.333)).toBe('33.3%');
    });

    it('handles decimal places', () => {
      expect(formatPercentage(33.333, 0)).toBe('33%');
      expect(formatPercentage(33.333, 2)).toBe('33.33%');
      expect(formatPercentage(33.333, 3)).toBe('33.333%');
    });

    it('caps at 999.9%', () => {
      expect(formatPercentage(1000)).toBe('999.9%');
      expect(formatPercentage(5000)).toBe('999.9%');
      expect(formatPercentage(999.9)).toBe('999.9%');
    });

    it('handles negative values', () => {
      expect(formatPercentage(-10)).toBe('-10.0%');
      expect(formatPercentage(-999.9)).toBe('-999.9%');
      expect(formatPercentage(-1000)).toBe('999.9%'); // Still capped at 999.9
    });

    it('handles edge cases', () => {
      expect(formatPercentage(0.001, 3)).toBe('0.001%');
      expect(formatPercentage(Number.MAX_SAFE_INTEGER)).toBe('999.9%');
      expect(formatPercentage(Number.MIN_SAFE_INTEGER)).toBe('999.9%');
    });
  });

  describe('formatDuration', () => {
    it('formats milliseconds', () => {
      expect(formatDuration(0)).toBe('0ms');
      expect(formatDuration(500)).toBe('500ms');
      expect(formatDuration(999)).toBe('999ms');
    });

    it('formats seconds', () => {
      expect(formatDuration(1000)).toBe('1.0s');
      expect(formatDuration(1500)).toBe('1.5s');
      expect(formatDuration(59999)).toBe('60.0s');
    });

    it('formats minutes and seconds', () => {
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(3599000)).toBe('59m 59s');
    });

    it('formats hours and minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(5400000)).toBe('1h 30m');
      expect(formatDuration(7200000)).toBe('2h 0m');
    });

    it('handles negative durations', () => {
      expect(formatDuration(-1000)).toBe('-1.0s');
      expect(formatDuration(-60000)).toBe('-1m 0s');
      expect(formatDuration(-3600000)).toBe('-1h 0m');
    });

    it('handles very large durations', () => {
      const oneDay = 24 * 60 * 60 * 1000;
      expect(formatDuration(oneDay)).toBe('24h 0m');

      const oneWeek = 7 * oneDay;
      expect(formatDuration(oneWeek)).toBe('168h 0m');
    });

    it('handles edge cases', () => {
      expect(formatDuration(0.5)).toBe('0.5ms');
      expect(formatDuration(Number.MAX_SAFE_INTEGER)).toBeDefined();
    });
  });

  describe('generateSessionId', () => {
    it('generates unique session IDs', () => {
      const id1 = generateSessionId();
      const id2 = generateSessionId();

      expect(id1).not.toBe(id2);
      expect(id1.startsWith('session-')).toBe(true);
      expect(id2.startsWith('session-')).toBe(true);
    });

    it('generates IDs with correct format', () => {
      const id = generateSessionId();
      const parts = id.split('-');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe('session');
      expect(parts[1]).toMatch(/^\d+$/); // Timestamp
      expect(parts[2]).toMatch(/^[a-z0-9]+$/); // Random string
      expect(parts[2]).toHaveLength(9);
    });

    it('generates many unique IDs', () => {
      const ids = new Set();
      const count = 10000;

      for (let i = 0; i < count; i++) {
        ids.add(generateSessionId());
      }

      expect(ids.size).toBe(count); // All unique
    });

    it('includes timestamp for ordering', () => {
      const id1 = generateSessionId();
      // Small delay to ensure different timestamp
      const start = Date.now();
      while (Date.now() === start) {
        // Wait for next millisecond
      }
      const id2 = generateSessionId();

      const timestamp1 = parseInt(id1.split('-')[1]);
      const timestamp2 = parseInt(id2.split('-')[1]);

      expect(timestamp2).toBeGreaterThanOrEqual(timestamp1);
    });
  });

  describe('generateId', () => {
    it('generates unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();

      expect(id1).not.toBe(id2);
      expect(id1.startsWith('id-')).toBe(true);
      expect(id2.startsWith('id-')).toBe(true);
    });

    it('generates IDs with correct format', () => {
      const id = generateId();
      const parts = id.split('-');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe('id');
      expect(parts[1]).toMatch(/^\d+$/);
      expect(parts[2]).toMatch(/^[a-z0-9]+$/);
      expect(parts[2]).toHaveLength(9);
    });

    it('differs from generateSessionId', () => {
      const sessionId = generateSessionId();
      const id = generateId();

      expect(sessionId.startsWith('session-')).toBe(true);
      expect(id.startsWith('id-')).toBe(true);
      expect(sessionId).not.toBe(id);
    });
  });

  describe('formatDate', () => {
    it('formats dates correctly', () => {
      const date = new Date('2023-01-01T15:30:45.123Z');
      const formatted = formatDate(date);

      // Should include hours, minutes, seconds
      expect(formatted).toMatch(/^\d{1,2}:\d{2}:\d{2} [AP]M$/);
    });

    it('handles different times', () => {
      const morning = new Date('2023-01-01T09:05:03Z');
      const afternoon = new Date('2023-01-01T15:30:45Z');
      const evening = new Date('2023-01-01T23:59:59Z');

      expect(formatDate(morning)).toMatch(/AM$/);
      expect(formatDate(afternoon)).toMatch(/PM$/);
      expect(formatDate(evening)).toMatch(/PM$/);
    });

    it('uses consistent formatting', () => {
      const dates = [
        new Date('2023-01-01T00:00:00Z'),
        new Date('2023-06-15T12:30:45Z'),
        new Date('2023-12-31T23:59:59Z'),
      ];

      dates.forEach(date => {
        const formatted = formatDate(date);
        expect(formatted).toMatch(/^\d{1,2}:\d{2}:\d{2} [AP]M$/);
      });
    });

    it('handles timezone correctly', () => {
      const date = new Date('2023-01-01T12:00:00Z');
      const formatted = formatDate(date);

      // Should format in local timezone
      expect(formatted).toBeDefined();
      expect(typeof formatted).toBe('string');
    });

    it('handles invalid dates', () => {
      const invalidDate = new Date('invalid');

      expect(() => formatDate(invalidDate)).not.toThrow();

      // Should handle gracefully (might return "Invalid Date" string)
      const result = formatDate(invalidDate);
      expect(typeof result).toBe('string');
    });
  });

  describe('debounce', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('delays function execution', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('test');
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalledWith('test');
    });

    it('cancels previous calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('first');
      jest.advanceTimersByTime(50);

      debouncedFn('second');
      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('second');
    });

    it('handles multiple arguments', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('arg1', 'arg2', 'arg3');
      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledWith('arg1', 'arg2', 'arg3');
    });

    it('preserves this context', () => {
      const obj = {
        value: 'test',
        method: jest.fn(function(this: any) {
          return this.value;
        }),
      };

      const debouncedMethod = debounce(obj.method, 100);
      debouncedMethod.call(obj);

      jest.advanceTimersByTime(100);

      expect(obj.method).toHaveBeenCalled();
    });

    it('handles rapid successive calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      // Call many times rapidly
      for (let i = 0; i < 10; i++) {
        debouncedFn(`call-${i}`);
        jest.advanceTimersByTime(10);
      }

      // Advance to complete the debounce
      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('call-9'); // Last call
    });

    it('allows immediate execution after delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('first');
      jest.advanceTimersByTime(100);

      debouncedFn('second');
      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledTimes(2);
      expect(mockFn).toHaveBeenNthCalledWith(1, 'first');
      expect(mockFn).toHaveBeenNthCalledWith(2, 'second');
    });

    it('handles function that throws errors', () => {
      const errorFn = jest.fn(() => {
        throw new Error('Test error');
      });
      const debouncedFn = debounce(errorFn, 100);

      debouncedFn();

      expect(() => {
        jest.advanceTimersByTime(100);
      }).toThrow('Test error');

      expect(errorFn).toHaveBeenCalled();
    });

    it('handles zero delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 0);

      debouncedFn('test');
      jest.advanceTimersByTime(0);

      expect(mockFn).toHaveBeenCalledWith('test');
    });

    it('handles negative delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, -100);

      debouncedFn('test');
      jest.advanceTimersByTime(0);

      expect(mockFn).toHaveBeenCalledWith('test');
    });

    it('can be called without arguments', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn();
      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledWith();
    });
  });

  describe('Performance', () => {
    it('handles high-frequency formatting operations', () => {
      const start = performance.now();

      for (let i = 0; i < 10000; i++) {
        formatBytes(i * 1024);
        formatPercentage(i / 100);
        formatDuration(i * 1000);
      }

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(1000); // Should complete in under 1 second
    });

    it('generates many IDs efficiently', () => {
      const start = performance.now();
      const ids = [];

      for (let i = 0; i < 10000; i++) {
        ids.push(generateSessionId());
      }

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(1000);
      expect(new Set(ids).size).toBe(10000); // All unique
    });

    it('handles complex class name merging efficiently', () => {
      const complexClasses = [
        'text-sm md:text-lg lg:text-xl',
        'p-2 md:p-4 lg:p-6',
        'bg-red-500 hover:bg-red-600 focus:bg-red-700',
        'border border-gray-300 rounded-md shadow-sm',
        'transition-all duration-200 ease-in-out',
      ];

      const start = performance.now();

      for (let i = 0; i < 1000; i++) {
        cn(...complexClasses, i % 2 === 0 && 'extra-class', {
          active: i % 3 === 0,
          disabled: i % 5 === 0,
        });
      }

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(100);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('handles null and undefined inputs gracefully', () => {
      expect(() => {
        formatBytes(null as any);
        formatBytes(undefined as any);
        formatPercentage(null as any);
        formatDuration(undefined as any);
      }).not.toThrow();
    });

    it('handles non-numeric string inputs', () => {
      expect(formatBytes(parseFloat('not-a-number'))).toBe('NaN Bytes');
      expect(formatPercentage(parseFloat('invalid'))).toContain('NaN');
      expect(formatDuration(parseFloat('bad-input'))).toContain('NaN');
    });

    it('handles extreme values', () => {
      expect(formatBytes(Number.POSITIVE_INFINITY)).toBe('NaN Bytes');
      expect(formatBytes(Number.NEGATIVE_INFINITY)).toBe('NaN Bytes');
      expect(formatPercentage(Number.POSITIVE_INFINITY)).toBe('999.9%');
      expect(formatDuration(Number.POSITIVE_INFINITY)).toBeDefined();
    });

    it('handles very small numbers', () => {
      expect(formatBytes(Number.MIN_VALUE)).toBe('0 Bytes');
      expect(formatPercentage(Number.MIN_VALUE, 10)).toBe('0.0000000000%');
      expect(formatDuration(0.001)).toBe('0.001ms');
    });
  });

  describe('Type Safety', () => {
    it('maintains correct TypeScript types', () => {
      // These should compile without errors
      const className: string = cn('test');
      const bytes: string = formatBytes(1024);
      const percentage: string = formatPercentage(50);
      const duration: string = formatDuration(1000);
      const sessionId: string = generateSessionId();
      const id: string = generateId();
      const date: string = formatDate(new Date());

      expect(typeof className).toBe('string');
      expect(typeof bytes).toBe('string');
      expect(typeof percentage).toBe('string');
      expect(typeof duration).toBe('string');
      expect(typeof sessionId).toBe('string');
      expect(typeof id).toBe('string');
      expect(typeof date).toBe('string');
    });

    it('debounce preserves function signatures', () => {
      const typedFn = (a: string, b: number): boolean => a.length > b;
      const debouncedFn = debounce(typedFn, 100);

      // Should accept same parameters
      debouncedFn('test', 5);

      jest.useFakeTimers();
      jest.advanceTimersByTime(100);
      jest.useRealTimers();

      expect(typedFn).toHaveBeenCalledWith('test', 5);
    });
  });
});