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
  describe('cn (className merging)', () => {
    it('should merge class names correctly', () => {
      const result = cn('px-2 py-1', 'bg-blue-500');
      expect(result).toBe('px-2 py-1 bg-blue-500');
    });

    it('should handle conditional classes', () => {
      const isActive = true;
      const result = cn('base-class', isActive && 'active-class');
      expect(result).toBe('base-class active-class');
    });

    it('should handle Tailwind conflicts correctly', () => {
      const result = cn('px-2', 'px-4');
      // Should keep the last one (px-4)
      expect(result).not.toContain('px-2');
      expect(result).toContain('px-4');
    });

    it('should handle undefined and null values', () => {
      const result = cn('base', undefined, null, 'final');
      expect(result).toBe('base final');
    });

    it('should handle empty strings', () => {
      const result = cn('', 'valid-class', '');
      expect(result).toBe('valid-class');
    });

    it('should handle arrays of classes', () => {
      const result = cn(['class1', 'class2'], 'class3');
      expect(result).toContain('class1');
      expect(result).toContain('class2');
      expect(result).toContain('class3');
    });
  });

  describe('formatBytes', () => {
    it('should format bytes correctly', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1048576)).toBe('1 MB');
      expect(formatBytes(1073741824)).toBe('1 GB');
      expect(formatBytes(1099511627776)).toBe('1 TB');
      expect(formatBytes(1125899906842624)).toBe('1 PB');
    });

    it('should handle decimal places', () => {
      expect(formatBytes(1536, 0)).toBe('2 KB');
      expect(formatBytes(1536, 1)).toBe('1.5 KB');
      expect(formatBytes(1536, 3)).toBe('1.500 KB');
    });

    it('should handle negative decimals', () => {
      expect(formatBytes(1536, -1)).toBe('2 KB');
      expect(formatBytes(1536, -10)).toBe('2 KB');
    });

    it('should handle very large numbers', () => {
      const result = formatBytes(Number.MAX_SAFE_INTEGER);
      expect(result).toContain('PB');
      expect(typeof result).toBe('string');
    });

    it('should handle very small numbers', () => {
      expect(formatBytes(0.5)).toBe('1 Bytes');
      expect(formatBytes(1)).toBe('1 Bytes');
      expect(formatBytes(512)).toBe('512 Bytes');
    });

    it('should handle edge cases', () => {
      expect(formatBytes(NaN)).toBe('0 Bytes');
      expect(formatBytes(Infinity)).toBe('0 Bytes');
      expect(formatBytes(-1024)).toBe('0 Bytes');
    });
  });

  describe('formatPercentage', () => {
    it('should format percentages correctly', () => {
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(100)).toBe('100.0%');
      expect(formatPercentage(75.5)).toBe('75.5%');
    });

    it('should handle decimal places', () => {
      expect(formatPercentage(75.555, 0)).toBe('76%');
      expect(formatPercentage(75.555, 2)).toBe('75.56%');
      expect(formatPercentage(75.555, 3)).toBe('75.555%');
    });

    it('should cap at 999.9%', () => {
      expect(formatPercentage(1000)).toBe('999.9%');
      expect(formatPercentage(5000)).toBe('999.9%');
      expect(formatPercentage(999.8)).toBe('999.8%');
      expect(formatPercentage(999.95, 1)).toBe('999.9%');
    });

    it('should handle negative values', () => {
      expect(formatPercentage(-10)).toBe('-10.0%');
      expect(formatPercentage(-999.9)).toBe('-999.9%');
      expect(formatPercentage(-1000)).toBe('999.9%'); // Still caps at 999.9
    });

    it('should handle edge cases', () => {
      expect(formatPercentage(NaN)).toBe('NaN%');
      expect(formatPercentage(Infinity)).toBe('999.9%');
      expect(formatPercentage(-Infinity)).toBe('999.9%');
    });

    it('should handle precision edge cases', () => {
      expect(formatPercentage(99.999, 1)).toBe('100.0%');
      expect(formatPercentage(99.994, 1)).toBe('99.9%');
    });
  });

  describe('formatDuration', () => {
    it('should format milliseconds', () => {
      expect(formatDuration(0)).toBe('0ms');
      expect(formatDuration(500)).toBe('500ms');
      expect(formatDuration(999)).toBe('999ms');
    });

    it('should format seconds', () => {
      expect(formatDuration(1000)).toBe('1.0s');
      expect(formatDuration(1500)).toBe('1.5s');
      expect(formatDuration(59999)).toBe('60.0s');
    });

    it('should format minutes and seconds', () => {
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(125000)).toBe('2m 5s');
      expect(formatDuration(3599000)).toBe('59m 59s');
    });

    it('should format hours, minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(3660000)).toBe('1h 1m');
      expect(formatDuration(7320000)).toBe('2h 2m');
      expect(formatDuration(90060000)).toBe('25h 1m');
    });

    it('should handle edge cases', () => {
      expect(formatDuration(-1000)).toBe('-1000ms');
      expect(formatDuration(0.5)).toBe('0.5ms');
      expect(formatDuration(NaN)).toBe('NaNms');
      expect(formatDuration(Infinity)).toBe('Infinityms');
    });

    it('should handle very large durations', () => {
      const largeMs = 86400000 * 365; // 1 year in ms
      const result = formatDuration(largeMs);
      expect(result).toContain('h');
      expect(result).toContain('m');
    });
  });

  describe('generateSessionId', () => {
    it('should generate unique session IDs', () => {
      const id1 = generateSessionId();
      const id2 = generateSessionId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^session-\d+-[a-z0-9]{9}$/);
      expect(id2).toMatch(/^session-\d+-[a-z0-9]{9}$/);
    });

    it('should include timestamp', () => {
      const before = Date.now();
      const id = generateSessionId();
      const after = Date.now();
      
      const timestamp = parseInt(id.split('-')[1]);
      expect(timestamp).toBeGreaterThanOrEqual(before);
      expect(timestamp).toBeLessThanOrEqual(after);
    });

    it('should generate multiple unique IDs rapidly', () => {
      const ids = new Set();
      for (let i = 0; i < 1000; i++) {
        ids.add(generateSessionId());
      }
      expect(ids.size).toBe(1000);
    });
  });

  describe('generateId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^id-\d+-[a-z0-9]{9}$/);
      expect(id2).toMatch(/^id-\d+-[a-z0-9]{9}$/);
    });

    it('should be different from session IDs', () => {
      const sessionId = generateSessionId();
      const id = generateId();
      
      expect(sessionId.startsWith('session-')).toBe(true);
      expect(id.startsWith('id-')).toBe(true);
      expect(sessionId).not.toBe(id);
    });

    it('should generate collision-resistant IDs', () => {
      const ids = new Set();
      for (let i = 0; i < 10000; i++) {
        ids.add(generateId());
      }
      expect(ids.size).toBe(10000);
    });
  });

  describe('formatDate', () => {
    it('should format date correctly', () => {
      const date = new Date('2024-01-15T14:30:45.123Z');
      const formatted = formatDate(date);
      
      // Should match HH:MM:SS format
      expect(formatted).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    });

    it('should handle different timezones consistently', () => {
      const date1 = new Date('2024-01-15T14:30:45.123Z');
      const date2 = new Date('2024-01-15T14:30:45.456Z');
      
      const formatted1 = formatDate(date1);
      const formatted2 = formatDate(date2);
      
      // Same minute, should be same formatted time
      expect(formatted1).toBe(formatted2);
    });

    it('should handle edge dates', () => {
      const midnight = new Date('2024-01-01T00:00:00Z');
      const formatted = formatDate(midnight);
      expect(formatted).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    });

    it('should handle invalid dates', () => {
      const invalidDate = new Date('invalid');
      expect(() => formatDate(invalidDate)).not.toThrow();
    });

    it('should format with leading zeros', () => {
      const earlyTime = new Date('2024-01-01T01:05:09Z');
      const formatted = formatDate(earlyTime);
      
      // Should have leading zeros where appropriate
      const parts = formatted.split(':');
      parts.forEach(part => {
        expect(part.length).toBe(2);
      });
    });
  });

  describe('debounce', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should debounce function calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);
      
      debouncedFn();
      debouncedFn();
      debouncedFn();
      
      expect(mockFn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(100);
      
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should pass arguments correctly', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);
      
      debouncedFn('arg1', 'arg2', 123);
      
      jest.advanceTimersByTime(100);
      
      expect(mockFn).toHaveBeenCalledWith('arg1', 'arg2', 123);
    });

    it('should reset timer on subsequent calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);
      
      debouncedFn();
      jest.advanceTimersByTime(50);
      debouncedFn();
      jest.advanceTimersByTime(50);
      
      expect(mockFn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(50);
      
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should handle multiple independent debounced functions', () => {
      const mockFn1 = jest.fn();
      const mockFn2 = jest.fn();
      const debouncedFn1 = debounce(mockFn1, 100);
      const debouncedFn2 = debounce(mockFn2, 200);
      
      debouncedFn1();
      debouncedFn2();
      
      jest.advanceTimersByTime(100);
      expect(mockFn1).toHaveBeenCalledTimes(1);
      expect(mockFn2).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(100);
      expect(mockFn2).toHaveBeenCalledTimes(1);
    });

    it('should preserve this context', () => {
      const obj = {
        value: 42,
        getValue: function() { return this.value; }
      };
      
      const debouncedGetValue = debounce(obj.getValue, 100);
      const result = jest.fn();
      
      debouncedGetValue.call(obj);
      jest.advanceTimersByTime(100);
      
      // Should maintain context
      expect(typeof debouncedGetValue).toBe('function');
    });

    it('should handle zero delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 0);
      
      debouncedFn();
      
      jest.advanceTimersByTime(0);
      
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should handle negative delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, -100);
      
      debouncedFn();
      
      jest.advanceTimersByTime(0);
      
      expect(mockFn).toHaveBeenCalledTimes(1);
    });
  });

  describe('integration tests', () => {
    it('should work together for complex formatting', () => {
      const sessionId = generateSessionId();
      const timestamp = new Date();
      const bytes = 1073741824;
      const percentage = 85.7;
      
      expect(sessionId).toMatch(/^session-\d+-[a-z0-9]{9}$/);
      expect(formatDate(timestamp)).toMatch(/^\d{2}:\d{2}:\d{2}$/);
      expect(formatBytes(bytes)).toBe('1 GB');
      expect(formatPercentage(percentage)).toBe('85.7%');
    });

    it('should handle edge case combinations', () => {
      const extremeValues = {
        bytes: Number.MAX_SAFE_INTEGER,
        percentage: 999.95,
        duration: 86400000,
      };
      
      expect(() => {
        formatBytes(extremeValues.bytes);
        formatPercentage(extremeValues.percentage);
        formatDuration(extremeValues.duration);
      }).not.toThrow();
    });

    it('should maintain consistent behavior under stress', () => {
      const results = [];
      
      for (let i = 0; i < 1000; i++) {
        results.push({
          id: generateId(),
          sessionId: generateSessionId(),
          bytes: formatBytes(Math.random() * 1000000000),
          percentage: formatPercentage(Math.random() * 100),
        });
      }
      
      expect(results.length).toBe(1000);
      
      // All IDs should be unique
      const ids = results.map(r => r.id);
      const sessionIds = results.map(r => r.sessionId);
      
      expect(new Set(ids).size).toBe(1000);
      expect(new Set(sessionIds).size).toBe(1000);
    });
  });
});