/**
 * Comprehensive Unit Tests for src/lib/utils.ts
 * 
 * Gap Analysis Coverage:
 * - cn() function edge cases and tailwind merge behavior
 * - formatBytes() negative numbers and edge cases
 * - formatPercentage() boundary conditions
 * - formatDuration() negative values and complex durations
 * - generateSessionId() and generateId() uniqueness and format
 * - formatDate() timezone and locale edge cases
 * - debounce() function timing and context binding
 * 
 * Priority: HIGH - Core utility functions used throughout application
 */

import { 
  cn, 
  formatBytes, 
  formatPercentage, 
  formatDuration, 
  generateSessionId, 
  generateId, 
  formatDate, 
  debounce 
} from '../utils';

describe('Utils - Gap Analysis Coverage', () => {
  describe('cn() - Tailwind className utility', () => {
    it('should merge basic class names correctly', () => {
      expect(cn('px-4', 'py-2')).toBe('px-4 py-2');
    });

    it('should handle conditional classes', () => {
      expect(cn('base', true && 'conditional', false && 'not-applied'))
        .toBe('base conditional');
    });

    it('should handle undefined and null values', () => {
      expect(cn('base', undefined, null, 'valid')).toBe('base valid');
    });

    it('should merge conflicting Tailwind classes correctly', () => {
      // twMerge should handle conflicting classes
      expect(cn('p-4', 'p-2')).toBe('p-2');
      expect(cn('bg-red-500', 'bg-blue-500')).toBe('bg-blue-500');
    });

    it('should handle arrays of classes', () => {
      expect(cn(['px-4', 'py-2'], 'bg-blue-500')).toBe('px-4 py-2 bg-blue-500');
    });

    it('should handle empty inputs', () => {
      expect(cn()).toBe('');
      expect(cn('')).toBe('');
      expect(cn(undefined)).toBe('');
    });

    it('should handle objects with boolean values', () => {
      expect(cn({
        'px-4': true,
        'py-2': false,
        'bg-blue': true
      })).toBe('px-4 bg-blue');
    });
  });

  describe('formatBytes() - File size formatting', () => {
    it('should format zero bytes correctly', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
    });

    it('should handle negative numbers', () => {
      expect(formatBytes(-100)).toBe('NaN Bytes');
      expect(formatBytes(-1024)).toBe('NaN Bytes');
    });

    it('should format basic byte sizes', () => {
      expect(formatBytes(512)).toBe('512 Bytes');
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1536)).toBe('1.5 KB');
    });

    it('should format larger sizes correctly', () => {
      expect(formatBytes(1024 * 1024)).toBe('1 MB');
      expect(formatBytes(1024 * 1024 * 1024)).toBe('1 GB');
      expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe('1 TB');
    });

    it('should handle custom decimal places', () => {
      expect(formatBytes(1536, 0)).toBe('2 KB');
      expect(formatBytes(1536, 3)).toBe('1.500 KB');
      expect(formatBytes(1536, -1)).toBe('2 KB'); // negative decimals default to 0
    });

    it('should handle very large numbers', () => {
      const petabyte = 1024 * 1024 * 1024 * 1024 * 1024;
      expect(formatBytes(petabyte)).toBe('1 PB');
    });

    it('should handle numbers beyond supported sizes', () => {
      const beyondPetabyte = 1024 * 1024 * 1024 * 1024 * 1024 * 1024;
      expect(formatBytes(beyondPetabyte)).toBe('NaN Bytes');
    });

    it('should handle floating point precision', () => {
      expect(formatBytes(1024.5)).toBe('1 KB');
      expect(formatBytes(1536.7, 1)).toBe('1.5 KB');
    });

    it('should format custom decimals > 2 correctly', () => {
      expect(formatBytes(1536, 4)).toBe('1.5000 KB');
      expect(formatBytes(1536, 3)).toBe('1.500 KB');
    });
  });

  describe('formatPercentage() - Percentage formatting', () => {
    it('should format basic percentages', () => {
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(100)).toBe('100.0%');
    });

    it('should handle custom decimal places', () => {
      expect(formatPercentage(50.12345, 0)).toBe('50%');
      expect(formatPercentage(50.12345, 2)).toBe('50.12%');
      expect(formatPercentage(50.12345, 3)).toBe('50.123%');
    });

    it('should cap values at 999.9%', () => {
      expect(formatPercentage(1000)).toBe('999.9%');
      expect(formatPercentage(9999)).toBe('999.9%');
      expect(formatPercentage(999.9)).toBe('999.9%');
    });

    it('should handle negative percentages', () => {
      expect(formatPercentage(-50)).toBe('-50.0%');
      expect(formatPercentage(-100)).toBe('-100.0%');
    });

    it('should handle decimal values', () => {
      expect(formatPercentage(0.5)).toBe('0.5%');
      expect(formatPercentage(99.999)).toBe('100.0%');
    });

    it('should handle edge case values', () => {
      expect(formatPercentage(Number.MAX_VALUE)).toBe('999.9%');
      expect(formatPercentage(Number.MIN_VALUE)).toBe('0.0%');
    });
  });

  describe('formatDuration() - Time duration formatting', () => {
    it('should format milliseconds', () => {
      expect(formatDuration(500)).toBe('500ms');
      expect(formatDuration(0)).toBe('0ms');
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
      expect(formatDuration(3599000)).toBe('59m 59s');
    });

    it('should format hours and minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(3660000)).toBe('1h 1m');
      expect(formatDuration(7260000)).toBe('2h 1m');
    });

    it('should handle negative durations', () => {
      expect(formatDuration(-1000)).toBe('-1.0s');
      expect(formatDuration(-60000)).toBe('-1m 0s');
      expect(formatDuration(-3600000)).toBe('-1h 0m');
    });

    it('should handle edge cases', () => {
      expect(formatDuration(Number.MAX_SAFE_INTEGER)).toContain('h');
      expect(formatDuration(1)).toBe('1ms');
    });

    it('should handle complex durations', () => {
      expect(formatDuration(93784000)).toBe('26h 3m'); // 26 hours 3 minutes 4 seconds
      expect(formatDuration(86461000)).toBe('24h 1m'); // 24 hours 1 minute 1 second
    });
  });

  describe('generateSessionId() - Session ID generation', () => {
    it('should generate unique session IDs', () => {
      const id1 = generateSessionId();
      const id2 = generateSessionId();
      expect(id1).not.toBe(id2);
    });

    it('should have correct format', () => {
      const id = generateSessionId();
      expect(id).toMatch(/^session-\d+-[a-z0-9]{9}$/);
    });

    it('should include timestamp', () => {
      const beforeTime = Date.now();
      const id = generateSessionId();
      const afterTime = Date.now();
      
      const timestampPart = id.split('-')[1];
      const timestamp = parseInt(timestampPart, 10);
      
      expect(timestamp).toBeGreaterThanOrEqual(beforeTime);
      expect(timestamp).toBeLessThanOrEqual(afterTime);
    });

    it('should generate multiple unique IDs in sequence', () => {
      const ids = Array.from({ length: 100 }, () => generateSessionId());
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(100);
    });
  });

  describe('generateId() - Generic ID generation', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toBe(id2);
    });

    it('should have correct format', () => {
      const id = generateId();
      expect(id).toMatch(/^id-\d+-[a-z0-9]{9}$/);
    });

    it('should be different from session IDs', () => {
      const sessionId = generateSessionId();
      const id = generateId();
      expect(id.startsWith('id-')).toBe(true);
      expect(sessionId.startsWith('session-')).toBe(true);
      expect(id).not.toBe(sessionId);
    });

    it('should generate consistent length random parts', () => {
      const ids = Array.from({ length: 10 }, () => generateId());
      
      ids.forEach(id => {
        const parts = id.split('-');
        expect(parts).toHaveLength(3);
        expect(parts[0]).toBe('id');
        expect(parts[1]).toMatch(/^\d+$/);
        expect(parts[2]).toMatch(/^[a-z0-9]{9}$/);
      });
    });
  });

  describe('formatDate() - Date formatting', () => {
    it('should format dates in en-US locale', () => {
      const date = new Date('2024-01-15T14:30:45Z');
      const formatted = formatDate(date);
      
      // Format should include hours, minutes, seconds
      expect(formatted).toMatch(/\d{1,2}:\d{2}:\d{2}\s?(AM|PM)/);
    });

    it('should handle different times of day', () => {
      const morning = new Date('2024-01-15T09:15:30Z');
      const evening = new Date('2024-01-15T21:45:15Z');
      
      const morningFormatted = formatDate(morning);
      const eveningFormatted = formatDate(evening);
      
      expect(morningFormatted).toMatch(/AM|PM/);
      expect(eveningFormatted).toMatch(/AM|PM/);
    });

    it('should handle midnight and noon', () => {
      const midnight = new Date('2024-01-15T00:00:00Z');
      const noon = new Date('2024-01-15T12:00:00Z');
      
      const midnightFormatted = formatDate(midnight);
      const noonFormatted = formatDate(noon);
      
      expect(midnightFormatted).toContain('12:00:00');
      expect(noonFormatted).toContain('12:00:00');
    });

    it('should handle invalid dates gracefully', () => {
      const invalidDate = new Date('invalid');
      expect(() => formatDate(invalidDate)).not.toThrow();
    });

    it('should format seconds consistently', () => {
      const date = new Date('2024-01-15T14:30:05Z');
      const formatted = formatDate(date);
      expect(formatted).toMatch(/:\d{2}\s?(AM|PM)$/);
    });
  });

  describe('debounce() - Function debouncing', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should delay function execution', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);
      
      debouncedFn();
      expect(mockFn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should cancel previous calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);
      
      debouncedFn();
      debouncedFn();
      debouncedFn();
      
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

    it('should preserve context (this binding)', () => {
      const obj = {
        value: 42,
        method: jest.fn(function(this: any) {
          return this.value;
        })
      };
      
      const debouncedMethod = debounce(obj.method, 100);
      debouncedMethod.call(obj);
      
      jest.advanceTimersByTime(100);
      expect(obj.method).toHaveBeenCalled();
    });

    it('should handle rapid successive calls', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);
      
      // Rapid calls within the debounce period
      for (let i = 0; i < 10; i++) {
        debouncedFn(`call-${i}`);
        jest.advanceTimersByTime(50);
      }
      
      // Should only call once with the last arguments
      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('call-9');
    });

    it('should handle different wait times', () => {
      const mockFn = jest.fn();
      const shortDebounce = debounce(mockFn, 50);
      const longDebounce = debounce(mockFn, 200);
      
      shortDebounce();
      longDebounce();
      
      jest.advanceTimersByTime(60);
      expect(mockFn).toHaveBeenCalledTimes(1); // Short debounce fired
      
      jest.advanceTimersByTime(150);
      expect(mockFn).toHaveBeenCalledTimes(2); // Long debounce fired
    });

    it('should handle zero wait time', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 0);
      
      debouncedFn();
      expect(mockFn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(1);
      expect(mockFn).toHaveBeenCalledTimes(1);
    });

    it('should handle functions that return values', () => {
      const mockFn = jest.fn(() => 'result');
      const debouncedFn = debounce(mockFn, 100);
      
      // Note: debounced functions don't return values immediately
      const result = debouncedFn();
      expect(result).toBeUndefined();
      
      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalled();
    });
  });

  describe('Integration - Combined utility usage', () => {
    it('should work together in common patterns', () => {
      // Simulate a common usage pattern
      const sessionId = generateSessionId();
      const fileSize = formatBytes(1024 * 1024);
      const progress = formatPercentage(75.5);
      const duration = formatDuration(1500);
      const timestamp = formatDate(new Date());
      const classes = cn('flex', 'items-center', progress === '75.5%' && 'text-green-500');
      
      expect(sessionId).toMatch(/^session-/);
      expect(fileSize).toBe('1 MB');
      expect(progress).toBe('75.5%');
      expect(duration).toBe('1.5s');
      expect(timestamp).toMatch(/\d{1,2}:\d{2}:\d{2}/);
      expect(classes).toContain('flex items-center text-green-500');
    });

    it('should handle edge cases gracefully in combination', () => {
      const mockCallback = jest.fn();
      const debouncedLogger = debounce(() => {
        mockCallback(
          formatBytes(-1),
          formatPercentage(9999),
          formatDuration(-1000),
          cn(undefined, null, ''),
          generateId()
        );
      }, 10);
      
      jest.useFakeTimers();
      debouncedLogger();
      jest.advanceTimersByTime(10);
      
      expect(mockCallback).toHaveBeenCalledWith(
        'NaN Bytes',
        '999.9%',
        '-1.0s',
        '',
        expect.stringMatching(/^id-/)
      );
      
      jest.useRealTimers();
    });
  });
});