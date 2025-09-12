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

describe('Utils Functions', () => {
  describe('cn (className utility)', () => {
    it('should merge class names correctly', () => {
      expect(cn('px-4', 'py-2')).toBe('px-4 py-2');
    });

    it('should handle conditional classes', () => {
      expect(cn('base', true && 'conditional', false && 'hidden')).toBe('base conditional');
    });

    it('should merge Tailwind classes correctly', () => {
      expect(cn('px-4', 'px-2')).toBe('px-2');
    });

    it('should handle empty inputs', () => {
      expect(cn()).toBe('');
      expect(cn('')).toBe('');
    });
  });

  describe('formatBytes', () => {
    it('should format zero bytes', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
    });

    it('should format bytes correctly', () => {
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1048576)).toBe('1 MB');
      expect(formatBytes(1073741824)).toBe('1 GB');
    });

    it('should handle decimals correctly', () => {
      expect(formatBytes(1536, 1)).toBe('1.5 KB');
      expect(formatBytes(1536, 0)).toBe('2 KB');
    });

    it('should handle large values', () => {
      expect(formatBytes(1099511627776)).toBe('1 TB');
      expect(formatBytes(1125899906842624)).toBe('1 PB');
    });

    it('should handle fractional bytes', () => {
      expect(formatBytes(500.5)).toBe('500.5 Bytes');
    });

    it('should handle negative decimals parameter', () => {
      expect(formatBytes(1536, -1)).toBe('2 KB');
    });
  });

  describe('formatPercentage', () => {
    it('should format percentages with default decimals', () => {
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(33.333)).toBe('33.3%');
    });

    it('should format percentages with custom decimals', () => {
      expect(formatPercentage(50, 0)).toBe('50%');
      expect(formatPercentage(33.333, 2)).toBe('33.33%');
    });

    it('should handle zero and negative values', () => {
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(-5.5)).toBe('-5.5%');
    });

    it('should handle very large values', () => {
      expect(formatPercentage(999.99)).toBe('999.9%');
    });
  });

  describe('formatDuration', () => {
    it('should format milliseconds', () => {
      expect(formatDuration(500)).toBe('500ms');
      expect(formatDuration(999)).toBe('999ms');
    });

    it('should format seconds', () => {
      expect(formatDuration(1000)).toBe('1.0s');
      expect(formatDuration(1500)).toBe('1.5s');
      expect(formatDuration(59000)).toBe('59.0s');
    });

    it('should format minutes and seconds', () => {
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(3599000)).toBe('59m 59s');
    });

    it('should format hours and minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(3900000)).toBe('1h 5m');
      expect(formatDuration(7320000)).toBe('2h 2m');
    });

    it('should handle zero duration', () => {
      expect(formatDuration(0)).toBe('0ms');
    });

    it('should handle fractional milliseconds', () => {
      expect(formatDuration(500.5)).toBe('500.5ms');
    });
  });

  describe('generateSessionId', () => {
    it('should generate a session ID with correct format', () => {
      const sessionId = generateSessionId();
      expect(sessionId).toMatch(/^session-\d+-[a-z0-9]{9}$/);
    });

    it('should generate unique session IDs', () => {
      const id1 = generateSessionId();
      const id2 = generateSessionId();
      expect(id1).not.toBe(id2);
    });

    it('should start with "session-" prefix', () => {
      const sessionId = generateSessionId();
      expect(sessionId.startsWith('session-')).toBe(true);
    });
  });

  describe('generateId', () => {
    it('should generate an ID with correct format', () => {
      const id = generateId();
      expect(id).toMatch(/^id-\d+-[a-z0-9]{9}$/);
    });

    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toBe(id2);
    });

    it('should start with "id-" prefix', () => {
      const id = generateId();
      expect(id.startsWith('id-')).toBe(true);
    });
  });

  describe('formatDate', () => {
    it('should format date with time only', () => {
      const date = new Date('2023-12-25T14:30:45.000Z');
      const formatted = formatDate(date);
      // Should be in HH:MM:SS format (exact format depends on timezone)
      expect(formatted).toMatch(/^\d{1,2}:\d{2}:\d{2} (AM|PM)$/);
    });

    it('should handle different times', () => {
      const morning = new Date('2023-12-25T09:15:30.000Z');
      const evening = new Date('2023-12-25T21:45:00.000Z');
      
      const morningFormatted = formatDate(morning);
      const eveningFormatted = formatDate(evening);
      
      expect(morningFormatted).toMatch(/^\d{1,2}:\d{2}:\d{2} (AM|PM)$/);
      expect(eveningFormatted).toMatch(/^\d{1,2}:\d{2}:\d{2} (AM|PM)$/);
      expect(morningFormatted).not.toBe(eveningFormatted);
    });
  });

  describe('debounce', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should delay function execution', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('test');
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalledWith('test');
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should cancel previous calls when called again', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('first');
      jest.advanceTimersByTime(50);
      debouncedFn('second');
      
      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalledWith('second');
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should handle multiple arguments', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('arg1', 'arg2', 123);
      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledWith('arg1', 'arg2', 123);
    });

    it('should preserve function context', () => {
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

    it('should work with zero delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 0);

      debouncedFn('test');
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(0);
      expect(mockFn).toHaveBeenCalledWith('test');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle invalid inputs gracefully', () => {
      expect(() => formatBytes(NaN)).not.toThrow();
      expect(() => formatBytes(Infinity)).not.toThrow();
      expect(() => formatBytes(-1)).not.toThrow();
    });

    it('should handle edge case values', () => {
      expect(formatBytes(Number.MAX_SAFE_INTEGER)).toMatch(/\d+(\.\d+)? [A-Z]+/);
      expect(formatPercentage(Number.MAX_SAFE_INTEGER)).toMatch(/[\d.]+%/);
      expect(formatDuration(Number.MAX_SAFE_INTEGER)).toMatch(/\d+h \d+m/);
    });
  });

  describe('Performance', () => {
    it('should execute formatBytes efficiently for large inputs', () => {
      const startTime = performance.now();
      
      for (let i = 0; i < 1000; i++) {
        formatBytes(Math.random() * 1000000000);
      }
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(50); // Should complete in <50ms
    });

    it('should execute debounce efficiently', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 10);
      
      const startTime = performance.now();
      
      // Call multiple times synchronously - debounce should batch them
      for (let i = 0; i < 10; i++) {
        debouncedFn(i);
      }
      
      const endTime = performance.now();
      // Synchronous calls should be fast, actual execution is delayed
      expect(endTime - startTime).toBeLessThan(10);
      
      // The function should not have been called yet (debounced)
      expect(mockFn).not.toHaveBeenCalled();
    });
  });
});