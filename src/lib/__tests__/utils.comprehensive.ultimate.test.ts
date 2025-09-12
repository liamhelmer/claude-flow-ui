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

describe('Utility Functions', () => {
  describe('cn (className merger)', () => {
    it('combines class names correctly', () => {
      expect(cn('foo', 'bar')).toBe('foo bar');
    });

    it('handles conditional classes', () => {
      expect(cn('foo', true && 'bar', false && 'baz')).toBe('foo bar');
    });

    it('handles undefined and null values', () => {
      expect(cn('foo', undefined, null, 'bar')).toBe('foo bar');
    });

    it('merges Tailwind classes correctly', () => {
      expect(cn('px-2 py-1', 'px-4')).toBe('py-1 px-4');
    });

    it('handles empty input', () => {
      expect(cn()).toBe('');
    });

    it('handles objects with boolean values', () => {
      expect(cn({ 
        'foo': true, 
        'bar': false, 
        'baz': true 
      })).toBe('foo baz');
    });

    it('handles arrays of classes', () => {
      expect(cn(['foo', 'bar'], 'baz')).toBe('foo bar baz');
    });

    it('handles complex combinations', () => {
      expect(cn(
        'base',
        { 'conditional': true, 'hidden': false },
        ['array1', 'array2'],
        undefined,
        'final'
      )).toBe('base conditional array1 array2 final');
    });
  });

  describe('formatBytes', () => {
    it('formats zero bytes', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
    });

    it('formats bytes correctly', () => {
      expect(formatBytes(500)).toBe('500 Bytes');
      expect(formatBytes(1023)).toBe('1023 Bytes');
    });

    it('formats kilobytes correctly', () => {
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1536)).toBe('1.5 KB');
      expect(formatBytes(2048)).toBe('2 KB');
    });

    it('formats megabytes correctly', () => {
      expect(formatBytes(1024 * 1024)).toBe('1 MB');
      expect(formatBytes(1024 * 1024 * 1.5)).toBe('1.5 MB');
      expect(formatBytes(1024 * 1024 * 10)).toBe('10 MB');
    });

    it('formats gigabytes correctly', () => {
      expect(formatBytes(1024 * 1024 * 1024)).toBe('1 GB');
      expect(formatBytes(1024 * 1024 * 1024 * 2.5)).toBe('2.5 GB');
    });

    it('formats terabytes correctly', () => {
      expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe('1 TB');
      expect(formatBytes(1024 * 1024 * 1024 * 1024 * 3)).toBe('3 TB');
    });

    it('formats petabytes correctly', () => {
      expect(formatBytes(1024 * 1024 * 1024 * 1024 * 1024)).toBe('1 PB');
    });

    it('handles custom decimal places', () => {
      expect(formatBytes(1536, 0)).toBe('2 KB');
      expect(formatBytes(1536, 3)).toBe('1.5 KB');
      expect(formatBytes(1536, 1)).toBe('1.5 KB');
    });

    it('handles negative decimal places', () => {
      expect(formatBytes(1536, -1)).toBe('2 KB');
    });

    it('handles large numbers', () => {
      expect(formatBytes(Number.MAX_SAFE_INTEGER)).toMatch(/\d+(\.\d+)? PB/);
    });

    it('handles very small fractions', () => {
      expect(formatBytes(1.5)).toBe('1.5 Bytes');
    });
  });

  describe('formatPercentage', () => {
    it('formats basic percentages', () => {
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(100)).toBe('100.0%');
    });

    it('formats decimal values', () => {
      expect(formatPercentage(25.5)).toBe('25.5%');
      expect(formatPercentage(99.99)).toBe('99.9%');
      expect(formatPercentage(33.333)).toBe('33.3%');
    });

    it('handles custom decimal places', () => {
      expect(formatPercentage(33.333, 0)).toBe('33%');
      expect(formatPercentage(33.333, 2)).toBe('33.33%');
      expect(formatPercentage(33.333, 3)).toBe('33.333%');
    });

    it('caps at maximum value', () => {
      expect(formatPercentage(1000)).toBe('999.9%');
      expect(formatPercentage(9999)).toBe('999.9%');
      expect(formatPercentage(999.9)).toBe('999.9%');
    });

    it('handles negative values', () => {
      expect(formatPercentage(-10)).toBe('-10.0%');
    });

    it('handles edge cases', () => {
      expect(formatPercentage(0.1)).toBe('0.1%');
      expect(formatPercentage(0.01)).toBe('0.0%');
      expect(formatPercentage(999.95)).toBe('999.9%');
      expect(formatPercentage(999.99)).toBe('999.9%');
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
      expect(formatDuration(30000)).toBe('30.0s');
      expect(formatDuration(59999)).toBe('60.0s');
    });

    it('formats minutes and seconds', () => {
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(125000)).toBe('2m 5s');
      expect(formatDuration(3599000)).toBe('59m 59s');
    });

    it('formats hours and minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(3660000)).toBe('1h 1m');
      expect(formatDuration(7200000)).toBe('2h 0m');
      expect(formatDuration(7380000)).toBe('2h 3m');
    });

    it('handles large durations', () => {
      expect(formatDuration(86400000)).toBe('24h 0m'); // 1 day
      expect(formatDuration(90000000)).toBe('25h 0m'); // 25 hours
    });

    it('handles edge cases', () => {
      expect(formatDuration(59000)).toBe('59.0s');
      expect(formatDuration(60001)).toBe('1m 0s');
      expect(formatDuration(3600001)).toBe('1h 0m');
    });
  });

  describe('generateSessionId', () => {
    it('generates unique session IDs', () => {
      const id1 = generateSessionId();
      const id2 = generateSessionId();
      
      expect(id1).not.toBe(id2);
    });

    it('follows the expected format', () => {
      const id = generateSessionId();
      
      expect(id).toMatch(/^session-\d+-[a-z0-9]+$/);
    });

    it('includes timestamp component', () => {
      const beforeTime = Date.now();
      const id = generateSessionId();
      const afterTime = Date.now();
      
      const timestamp = parseInt(id.split('-')[1]);
      expect(timestamp).toBeGreaterThanOrEqual(beforeTime);
      expect(timestamp).toBeLessThanOrEqual(afterTime);
    });

    it('includes random component', () => {
      const id = generateSessionId();
      const parts = id.split('-');
      
      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe('session');
      expect(parts[1]).toMatch(/^\d+$/);
      expect(parts[2]).toMatch(/^[a-z0-9]+$/);
      expect(parts[2].length).toBeGreaterThan(0);
    });

    it('generates different IDs in quick succession', () => {
      const ids = new Set();
      for (let i = 0; i < 100; i++) {
        ids.add(generateSessionId());
      }
      
      expect(ids.size).toBe(100);
    });
  });

  describe('generateId', () => {
    it('generates unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      
      expect(id1).not.toBe(id2);
    });

    it('follows the expected format', () => {
      const id = generateId();
      
      expect(id).toMatch(/^id-\d+-[a-z0-9]+$/);
    });

    it('includes timestamp component', () => {
      const beforeTime = Date.now();
      const id = generateId();
      const afterTime = Date.now();
      
      const timestamp = parseInt(id.split('-')[1]);
      expect(timestamp).toBeGreaterThanOrEqual(beforeTime);
      expect(timestamp).toBeLessThanOrEqual(afterTime);
    });

    it('generates different IDs in quick succession', () => {
      const ids = new Set();
      for (let i = 0; i < 100; i++) {
        ids.add(generateId());
      }
      
      expect(ids.size).toBe(100);
    });

    it('has different prefix than session ID', () => {
      const sessionId = generateSessionId();
      const id = generateId();
      
      expect(sessionId.startsWith('session-')).toBe(true);
      expect(id.startsWith('id-')).toBe(true);
    });
  });

  describe('formatDate', () => {
    it('formats date correctly', () => {
      const date = new Date('2023-12-25T14:30:45.123Z');
      const formatted = formatDate(date);
      
      // Should match HH:MM:SS format
      expect(formatted).toMatch(/^\d{1,2}:\d{2}:\d{2} (AM|PM)$/);
    });

    it('handles different times', () => {
      const morning = new Date('2023-12-25T09:15:30Z');
      const afternoon = new Date('2023-12-25T15:45:20Z');
      const midnight = new Date('2023-12-25T00:00:00Z');
      
      expect(formatDate(morning)).toMatch(/AM$/);
      expect(formatDate(afternoon)).toMatch(/PM$/);
      expect(formatDate(midnight)).toMatch(/AM$/);
    });

    it('uses en-US locale format', () => {
      const date = new Date('2023-12-25T14:30:45Z');
      const formatted = formatDate(date);
      
      // en-US format should include AM/PM
      expect(formatted).toMatch(/(AM|PM)$/);
    });

    it('handles edge cases', () => {
      const newYear = new Date('2024-01-01T00:00:00Z');
      const formatted = formatDate(newYear);
      
      expect(formatted).toMatch(/12:00:00 AM/);
    });

    it('formats seconds correctly', () => {
      const date = new Date('2023-12-25T14:30:05Z');
      const formatted = formatDate(date);
      
      expect(formatted).toMatch(/:05 /);
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
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 1000);
      
      debouncedFn();
      expect(fn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(1000);
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('cancels previous calls', () => {
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 1000);
      
      debouncedFn();
      debouncedFn();
      debouncedFn();
      
      expect(fn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(1000);
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('passes arguments correctly', () => {
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 1000);
      
      debouncedFn('arg1', 'arg2', 123);
      
      jest.advanceTimersByTime(1000);
      expect(fn).toHaveBeenCalledWith('arg1', 'arg2', 123);
    });

    it('preserves this context', () => {
      const obj = {
        value: 42,
        fn: jest.fn(function(this: any) {
          return this.value;
        }),
      };
      
      const debouncedFn = debounce(obj.fn, 1000);
      debouncedFn.call(obj);
      
      jest.advanceTimersByTime(1000);
      expect(obj.fn).toHaveBeenCalled();
    });

    it('handles zero delay', () => {
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 0);
      
      debouncedFn();
      expect(fn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(0);
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('handles multiple calls with different timings', () => {
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 1000);
      
      debouncedFn();
      jest.advanceTimersByTime(500);
      
      debouncedFn();
      jest.advanceTimersByTime(500);
      
      debouncedFn();
      jest.advanceTimersByTime(1000);
      
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('handles rapid successive calls', () => {
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 100);
      
      for (let i = 0; i < 10; i++) {
        debouncedFn(i);
        jest.advanceTimersByTime(50);
      }
      
      expect(fn).not.toHaveBeenCalled();
      
      jest.advanceTimersByTime(100);
      expect(fn).toHaveBeenCalledTimes(1);
      expect(fn).toHaveBeenCalledWith(9); // Last call's arguments
    });

    it('works with different function types', () => {
      const arrowFn = jest.fn((x: number) => x * 2);
      const asyncFn = jest.fn(async (x: number) => Promise.resolve(x));
      
      const debouncedArrow = debounce(arrowFn, 100);
      const debouncedAsync = debounce(asyncFn, 100);
      
      debouncedArrow(5);
      debouncedAsync(10);
      
      jest.advanceTimersByTime(100);
      
      expect(arrowFn).toHaveBeenCalledWith(5);
      expect(asyncFn).toHaveBeenCalledWith(10);
    });

    it('handles cleanup properly', () => {
      const fn = jest.fn();
      const debouncedFn = debounce(fn, 1000);
      
      debouncedFn();
      
      // Clear all timers (simulating component unmount)
      jest.clearAllTimers();
      
      expect(fn).not.toHaveBeenCalled();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    describe('formatBytes edge cases', () => {
      it('handles NaN input', () => {
        expect(formatBytes(NaN)).toBe('NaN Bytes');
      });

      it('handles Infinity', () => {
        expect(formatBytes(Infinity)).toBe('Infinity Bytes');
      });

      it('handles negative numbers', () => {
        expect(formatBytes(-1024)).toBe('-1 KB');
      });
    });

    describe('formatPercentage edge cases', () => {
      it('handles NaN input', () => {
        expect(formatPercentage(NaN)).toBe('NaN%');
      });

      it('handles Infinity', () => {
        expect(formatPercentage(Infinity)).toBe('999.9%');
      });
    });

    describe('formatDuration edge cases', () => {
      it('handles negative durations', () => {
        expect(formatDuration(-1000)).toBe('-1000ms');
      });

      it('handles NaN input', () => {
        expect(formatDuration(NaN)).toBe('NaNms');
      });

      it('handles Infinity', () => {
        expect(formatDuration(Infinity)).toBe('Infinityms');
      });
    });

    describe('formatDate edge cases', () => {
      it('handles invalid dates', () => {
        const invalidDate = new Date('invalid');
        const formatted = formatDate(invalidDate);
        
        expect(formatted).toContain('Invalid Date');
      });

      it('handles extreme dates', () => {
        const extremeDate = new Date('1970-01-01T00:00:00Z');
        const formatted = formatDate(extremeDate);
        
        expect(typeof formatted).toBe('string');
      });
    });

    describe('debounce edge cases', () => {
      beforeEach(() => {
        jest.useFakeTimers();
      });

      afterEach(() => {
        jest.useRealTimers();
      });

      it('handles negative delay', () => {
        const fn = jest.fn();
        const debouncedFn = debounce(fn, -100);
        
        debouncedFn();
        jest.advanceTimersByTime(0);
        
        expect(fn).toHaveBeenCalled();
      });

      it('handles function that throws', () => {
        const throwingFn = jest.fn(() => {
          throw new Error('Test error');
        });
        const debouncedFn = debounce(throwingFn, 100);
        
        debouncedFn();
        
        expect(() => {
          jest.advanceTimersByTime(100);
        }).toThrow('Test error');
      });
    });
  });
});