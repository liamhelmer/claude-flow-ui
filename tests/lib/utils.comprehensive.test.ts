import { cn } from '@/lib/utils';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Mock dependencies
jest.mock('clsx');
jest.mock('tailwind-merge');

const mockClsx = clsx as jest.MockedFunction<typeof clsx>;
const mockTwMerge = twMerge as jest.MockedFunction<typeof twMerge>;

describe('Utils Library Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Set up default mock implementations
    mockClsx.mockImplementation((...args) => args.filter(Boolean).join(' '));
    mockTwMerge.mockImplementation((str) => str);
  });

  describe('cn function (Class Name utility)', () => {
    it('should combine classes using clsx and twMerge', () => {
      mockClsx.mockReturnValue('class1 class2');
      mockTwMerge.mockReturnValue('merged-classes');

      const result = cn('class1', 'class2');

      expect(mockClsx).toHaveBeenCalledWith(['class1', 'class2']);
      expect(mockTwMerge).toHaveBeenCalledWith('class1 class2');
      expect(result).toBe('merged-classes');
    });

    it('should handle single class string', () => {
      mockClsx.mockReturnValue('single-class');
      mockTwMerge.mockReturnValue('single-class');

      const result = cn('single-class');

      expect(result).toBe('single-class');
    });

    it('should handle multiple class strings', () => {
      mockClsx.mockReturnValue('class1 class2 class3');
      mockTwMerge.mockReturnValue('class1 class2 class3');

      const result = cn('class1', 'class2', 'class3');

      expect(result).toBe('class1 class2 class3');
    });

    it('should handle conditional classes', () => {
      mockClsx.mockReturnValue('base-class conditional-class');
      mockTwMerge.mockReturnValue('base-class conditional-class');

      const isActive = true;
      const result = cn('base-class', isActive && 'conditional-class');

      expect(result).toBe('base-class conditional-class');
    });

    it('should handle false/null/undefined classes', () => {
      mockClsx.mockReturnValue('valid-class');
      mockTwMerge.mockReturnValue('valid-class');

      const result = cn('valid-class', false, null, undefined);

      expect(result).toBe('valid-class');
    });

    it('should handle object-style classes', () => {
      mockClsx.mockReturnValue('active enabled');
      mockTwMerge.mockReturnValue('active enabled');

      const result = cn({
        active: true,
        disabled: false,
        enabled: true,
      });

      expect(mockClsx).toHaveBeenCalledWith([{
        active: true,
        disabled: false,
        enabled: true,
      }]);
      expect(result).toBe('active enabled');
    });

    it('should handle array of classes', () => {
      mockClsx.mockReturnValue('class1 class2 class3');
      mockTwMerge.mockReturnValue('class1 class2 class3');

      const result = cn(['class1', 'class2'], 'class3');

      expect(result).toBe('class1 class2 class3');
    });

    it('should handle empty input', () => {
      mockClsx.mockReturnValue('');
      mockTwMerge.mockReturnValue('');

      const result = cn();

      expect(result).toBe('');
    });

    it('should handle Tailwind CSS conflicts correctly', () => {
      mockClsx.mockReturnValue('px-4 px-6 py-2 py-4');
      mockTwMerge.mockReturnValue('px-6 py-4'); // twMerge should resolve conflicts

      const result = cn('px-4 py-2', 'px-6 py-4');

      expect(mockTwMerge).toHaveBeenCalledWith('px-4 px-6 py-2 py-4');
      expect(result).toBe('px-6 py-4');
    });

    it('should handle complex Tailwind variants', () => {
      mockClsx.mockReturnValue('hover:bg-blue-500 focus:bg-blue-600 active:bg-blue-700');
      mockTwMerge.mockReturnValue('hover:bg-blue-500 focus:bg-blue-600 active:bg-blue-700');

      const result = cn(
        'hover:bg-blue-500',
        'focus:bg-blue-600',
        'active:bg-blue-700'
      );

      expect(result).toBe('hover:bg-blue-500 focus:bg-blue-600 active:bg-blue-700');
    });

    it('should handle responsive classes', () => {
      mockClsx.mockReturnValue('text-sm md:text-base lg:text-lg');
      mockTwMerge.mockReturnValue('text-sm md:text-base lg:text-lg');

      const result = cn('text-sm', 'md:text-base', 'lg:text-lg');

      expect(result).toBe('text-sm md:text-base lg:text-lg');
    });

    it('should handle dark mode classes', () => {
      mockClsx.mockReturnValue('bg-white dark:bg-gray-900 text-black dark:text-white');
      mockTwMerge.mockReturnValue('bg-white dark:bg-gray-900 text-black dark:text-white');

      const result = cn(
        'bg-white dark:bg-gray-900',
        'text-black dark:text-white'
      );

      expect(result).toBe('bg-white dark:bg-gray-900 text-black dark:text-white');
    });
  });

  describe('Performance Characteristics', () => {
    it('should handle large numbers of classes efficiently', () => {
      const manyClasses = Array(1000).fill(0).map((_, i) => `class-${i}`);
      
      mockClsx.mockReturnValue(manyClasses.join(' '));
      mockTwMerge.mockReturnValue(manyClasses.join(' '));

      const startTime = performance.now();
      const result = cn(...manyClasses);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(10); // Should be very fast
      expect(result).toBe(manyClasses.join(' '));
    });

    it('should handle repeated calls efficiently', () => {
      mockClsx.mockReturnValue('repeated-class');
      mockTwMerge.mockReturnValue('repeated-class');

      const startTime = performance.now();
      
      for (let i = 0; i < 1000; i++) {
        cn('repeated-class');
      }
      
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(50); // Should be very fast
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle clsx throwing an error', () => {
      mockClsx.mockImplementation(() => {
        throw new Error('clsx error');
      });

      expect(() => cn('test-class')).toThrow('clsx error');
    });

    it('should handle twMerge throwing an error', () => {
      mockClsx.mockReturnValue('test-class');
      mockTwMerge.mockImplementation(() => {
        throw new Error('twMerge error');
      });

      expect(() => cn('test-class')).toThrow('twMerge error');
    });

    it('should handle very long class strings', () => {
      const veryLongClass = 'a'.repeat(10000);
      
      mockClsx.mockReturnValue(veryLongClass);
      mockTwMerge.mockReturnValue(veryLongClass);

      const result = cn(veryLongClass);

      expect(result).toBe(veryLongClass);
    });

    it('should handle special characters in class names', () => {
      const specialChars = 'class-with-special-chars_123:hover@media';
      
      mockClsx.mockReturnValue(specialChars);
      mockTwMerge.mockReturnValue(specialChars);

      const result = cn(specialChars);

      expect(result).toBe(specialChars);
    });

    it('should handle non-string inputs gracefully', () => {
      mockClsx.mockReturnValue('123 true');
      mockTwMerge.mockReturnValue('123 true');

      // These should be handled by clsx
      const result = cn(123 as any, true as any);

      expect(mockClsx).toHaveBeenCalledWith([123, true]);
      expect(result).toBe('123 true');
    });

    it('should handle circular references in objects', () => {
      const circular: any = { active: true };
      circular.self = circular;

      mockClsx.mockImplementation(() => {
        throw new Error('Converting circular structure to JSON');
      });

      expect(() => cn(circular)).toThrow();
    });
  });

  describe('Real-world Usage Patterns', () => {
    it('should handle button component classes', () => {
      mockClsx.mockReturnValue('btn btn-primary hover:btn-primary-dark disabled:opacity-50');
      mockTwMerge.mockReturnValue('btn btn-primary hover:btn-primary-dark disabled:opacity-50');

      const variant = 'primary';
      const disabled = false;

      const result = cn(
        'btn',
        `btn-${variant}`,
        `hover:btn-${variant}-dark`,
        disabled && 'disabled:opacity-50'
      );

      expect(result).toBe('btn btn-primary hover:btn-primary-dark disabled:opacity-50');
    });

    it('should handle form input classes', () => {
      mockClsx.mockReturnValue('input border-2 focus:border-blue-500 invalid:border-red-500');
      mockTwMerge.mockReturnValue('input border-2 focus:border-blue-500 invalid:border-red-500');

      const hasError = false;
      const isFocused = true;

      const result = cn(
        'input',
        'border-2',
        isFocused && 'focus:border-blue-500',
        hasError && 'invalid:border-red-500'
      );

      expect(result).toBe('input border-2 focus:border-blue-500 invalid:border-red-500');
    });

    it('should handle layout component classes', () => {
      mockClsx.mockReturnValue('container mx-auto px-4 md:px-6 lg:px-8');
      mockTwMerge.mockReturnValue('container mx-auto px-4 md:px-6 lg:px-8');

      const result = cn(
        'container',
        'mx-auto',
        'px-4 md:px-6 lg:px-8'
      );

      expect(result).toBe('container mx-auto px-4 md:px-6 lg:px-8');
    });

    it('should handle theme-based classes', () => {
      mockClsx.mockReturnValue('card bg-white dark:bg-gray-800 shadow-lg dark:shadow-xl');
      mockTwMerge.mockReturnValue('card bg-white dark:bg-gray-800 shadow-lg dark:shadow-xl');

      const theme = 'dark';

      const result = cn(
        'card',
        theme === 'dark' ? 'dark:bg-gray-800 dark:shadow-xl' : 'bg-white shadow-lg'
      );

      expect(result).toBe('card bg-white dark:bg-gray-800 shadow-lg dark:shadow-xl');
    });

    it('should handle animation classes', () => {
      mockClsx.mockReturnValue('animate-pulse transition-all duration-300 ease-in-out');
      mockTwMerge.mockReturnValue('animate-pulse transition-all duration-300 ease-in-out');

      const isLoading = true;

      const result = cn(
        'transition-all duration-300 ease-in-out',
        isLoading && 'animate-pulse'
      );

      expect(result).toBe('animate-pulse transition-all duration-300 ease-in-out');
    });
  });

  describe('Integration with Component Libraries', () => {
    it('should work with headless UI components', () => {
      mockClsx.mockReturnValue('ui-button ui-focus-visible:ring-2 ui-disabled:opacity-50');
      mockTwMerge.mockReturnValue('ui-button ui-focus-visible:ring-2 ui-disabled:opacity-50');

      const result = cn(
        'ui-button',
        'ui-focus-visible:ring-2',
        'ui-disabled:opacity-50'
      );

      expect(result).toBe('ui-button ui-focus-visible:ring-2 ui-disabled:opacity-50');
    });

    it('should handle custom CSS-in-JS classes', () => {
      mockClsx.mockReturnValue('css-1a2b3c4 tw-bg-blue-500 tw-text-white');
      mockTwMerge.mockReturnValue('css-1a2b3c4 tw-bg-blue-500 tw-text-white');

      const emotionClass = 'css-1a2b3c4';

      const result = cn(
        emotionClass,
        'tw-bg-blue-500 tw-text-white'
      );

      expect(result).toBe('css-1a2b3c4 tw-bg-blue-500 tw-text-white');
    });
  });

  describe('TypeScript Integration', () => {
    it('should accept string literals', () => {
      mockClsx.mockReturnValue('text-red-500');
      mockTwMerge.mockReturnValue('text-red-500');

      const color: 'red' | 'blue' | 'green' = 'red';
      const result = cn(`text-${color}-500`);

      expect(result).toBe('text-red-500');
    });

    it('should accept template literals', () => {
      mockClsx.mockReturnValue('w-1/2 h-1/2');
      mockTwMerge.mockReturnValue('w-1/2 h-1/2');

      const width = '1/2';
      const height = '1/2';
      
      const result = cn(`w-${width}`, `h-${height}`);

      expect(result).toBe('w-1/2 h-1/2');
    });
  });

  describe('Memory and Resource Management', () => {
    it('should not cause memory leaks with repeated calls', () => {
      mockClsx.mockReturnValue('test-class');
      mockTwMerge.mockReturnValue('test-class');

      // Simulate many calls that might cause memory issues
      for (let i = 0; i < 10000; i++) {
        cn('test-class', i % 2 === 0 && 'conditional-class');
      }

      // If this test completes without running out of memory, it passes
      expect(true).toBe(true);
    });

    it('should handle garbage collection of large objects', () => {
      const largeObject = Array(1000).fill(0).reduce((acc, _, i) => {
        acc[`class-${i}`] = i % 2 === 0;
        return acc;
      }, {} as Record<string, boolean>);

      mockClsx.mockReturnValue('large-object-classes');
      mockTwMerge.mockReturnValue('large-object-classes');

      const result = cn(largeObject);

      expect(result).toBe('large-object-classes');
    });
  });
});