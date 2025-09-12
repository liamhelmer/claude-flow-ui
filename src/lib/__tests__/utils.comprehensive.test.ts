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

describe('Utils - Comprehensive Tests', () => {
  describe('cn (className utility)', () => {
    it('should merge classes correctly', () => {
      expect(cn('btn', 'btn-primary')).toBe('btn btn-primary');
    });

    it('should handle conditional classes', () => {
      expect(cn('btn', true && 'active', false && 'disabled')).toBe('btn active');
    });

    it('should handle objects', () => {
      expect(cn('btn', { active: true, disabled: false })).toBe('btn active');
    });

    it('should handle arrays', () => {
      expect(cn(['btn', 'btn-primary'])).toBe('btn btn-primary');
    });

    it('should handle empty inputs', () => {
      expect(cn()).toBe('');
      expect(cn('', null, undefined)).toBe('');
    });

    it('should merge tailwind classes properly', () => {
      expect(cn('p-2 p-4')).toBe('p-4');
      expect(cn('bg-red-500', 'bg-blue-500')).toBe('bg-blue-500');
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

    it('should handle decimal places', () => {
      expect(formatBytes(1536, 1)).toBe('1.5 KB');
      expect(formatBytes(1536, 0)).toBe('2 KB');
    });

    it('should handle large values', () => {
      expect(formatBytes(1125899906842624)).toBe('1 PB');
    });

    it('should handle negative decimals', () => {
      expect(formatBytes(1536, -1)).toBe('2 KB');
    });

    it('should handle fractional bytes', () => {
      expect(formatBytes(512.5)).toBe('512.5 Bytes');
    });
  });

  describe('formatPercentage', () => {
    it('should format percentages correctly', () => {
      expect(formatPercentage(50)).toBe('50.0%');
      expect(formatPercentage(33.333, 2)).toBe('33.33%');
    });

    it('should cap at 999.9%', () => {
      expect(formatPercentage(1500)).toBe('999.9%');
      expect(formatPercentage(999.9)).toBe('999.9%');
    });

    it('should handle zero and negative values', () => {
      expect(formatPercentage(0)).toBe('0.0%');
      expect(formatPercentage(-5)).toBe('-5.0%');
    });

    it('should handle different decimal places', () => {
      expect(formatPercentage(50, 0)).toBe('50%');
      expect(formatPercentage(50, 3)).toBe('50.000%');
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
      expect(formatDuration(59999)).toBe('60.0s');
    });

    it('should format minutes and seconds', () => {
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(3599000)).toBe('59m 59s');
    });

    it('should format hours and minutes', () => {
      expect(formatDuration(3600000)).toBe('1h 0m');
      expect(formatDuration(3690000)).toBe('1h 1m');
      expect(formatDuration(7200000)).toBe('2h 0m');
    });

    it('should handle zero duration', () => {
      expect(formatDuration(0)).toBe('0ms');
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
  });

  describe('generateId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^id-\d+-[a-z0-9]{9}$/);
      expect(id2).toMatch(/^id-\d+-[a-z0-9]{9}$/);
    });
  });

  describe('formatDate', () => {
    it('should format date correctly', () => {
      const date = new Date('2025-09-10T15:30:45');
      const formatted = formatDate(date);
      
      expect(formatted).toMatch(/\d{1,2}:\d{2}:\d{2} [AP]M/);
    });

    it('should handle different times', () => {
      const morning = new Date('2025-09-10T09:05:30');
      const evening = new Date('2025-09-10T21:15:45');
      
      const morningFormatted = formatDate(morning);
      const eveningFormatted = formatDate(evening);
      
      expect(morningFormatted).toContain('AM');
      expect(eveningFormatted).toContain('PM');
    });

    it('should handle edge cases', () => {
      const midnight = new Date('2025-09-10T00:00:00');
      const noon = new Date('2025-09-10T12:00:00');
      
      expect(formatDate(midnight)).toContain('12:00:00 AM');
      expect(formatDate(noon)).toContain('12:00:00 PM');
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

      debouncedFn('arg1');
      debouncedFn('arg2');
      debouncedFn('arg3');

      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('arg3');
    });

    it('should preserve function context', () => {
      const obj = {
        value: 'test',
        method: jest.fn(function(this: any) {
          return this.value;
        })
      };

      const debouncedMethod = debounce(obj.method, 100);
      debouncedMethod.call(obj);

      jest.advanceTimersByTime(100);

      expect(obj.method).toHaveBeenCalledTimes(1);
    });

    it('should handle multiple arguments', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 100);

      debouncedFn('arg1', 'arg2', 'arg3');

      jest.advanceTimersByTime(100);

      expect(mockFn).toHaveBeenCalledWith('arg1', 'arg2', 'arg3');
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

    it('should handle zero delay', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 0);

      debouncedFn();
      jest.advanceTimersByTime(0);

      expect(mockFn).toHaveBeenCalledTimes(1);
    });
  });
});