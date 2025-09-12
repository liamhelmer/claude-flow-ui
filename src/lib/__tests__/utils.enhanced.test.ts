import { cn } from '../utils';

describe('utils', () => {
  describe('cn function (clsx + tailwind-merge)', () => {
    it('should merge class names without conflicts', () => {
      const result = cn('px-4 py-2', 'px-6 bg-blue-500');
      expect(result).toContain('px-6');
      expect(result).toContain('py-2');
      expect(result).toContain('bg-blue-500');
      expect(result).not.toContain('px-4');
    });

    it('should handle conditional classes', () => {
      const isActive = true;
      const isDisabled = false;

      const result = cn(
        'base-class',
        isActive && 'active-class',
        isDisabled && 'disabled-class',
        'always-class'
      );

      expect(result).toContain('base-class');
      expect(result).toContain('active-class');
      expect(result).toContain('always-class');
      expect(result).not.toContain('disabled-class');
    });

    it('should handle object syntax', () => {
      const result = cn({
        'text-red-500': true,
        'text-blue-500': false,
        'font-bold': true,
        'underline': false,
      });

      expect(result).toContain('text-red-500');
      expect(result).toContain('font-bold');
      expect(result).not.toContain('text-blue-500');
      expect(result).not.toContain('underline');
    });

    it('should handle array of classes', () => {
      const classes = ['text-sm', 'text-gray-600', 'hover:text-gray-800'];
      const result = cn(classes);

      classes.forEach(className => {
        expect(result).toContain(className);
      });
    });

    it('should handle mixed input types', () => {
      const result = cn(
        'base',
        ['array-1', 'array-2'],
        { 'object-true': true, 'object-false': false },
        'string',
        null,
        undefined,
        false,
        'final'
      );

      expect(result).toContain('base');
      expect(result).toContain('array-1');
      expect(result).toContain('array-2');
      expect(result).toContain('object-true');
      expect(result).toContain('string');
      expect(result).toContain('final');
      expect(result).not.toContain('object-false');
    });

    it('should handle empty inputs', () => {
      expect(cn()).toBe('');
      expect(cn('')).toBe('');
      expect(cn(null)).toBe('');
      expect(cn(undefined)).toBe('');
      expect(cn(false)).toBe('');
    });

    it('should handle Tailwind conflicts correctly', () => {
      // Test padding conflicts - both p-4 and px-8 are kept (tailwind-merge behavior)
      const paddingResult = cn('p-4 px-8');
      expect(paddingResult).toContain('px-8');
      expect(paddingResult).toContain('p-4'); // p-4 is kept as-is
      expect(paddingResult).toBe('p-4 px-8'); // Exact result

      // Test background conflicts
      const bgResult = cn('bg-red-500 bg-blue-600');
      expect(bgResult).toContain('bg-blue-600');
      expect(bgResult).not.toContain('bg-red-500');

      // Test text size conflicts
      const textResult = cn('text-sm text-lg text-xl');
      expect(textResult).toContain('text-xl');
      expect(textResult).not.toContain('text-sm');
      expect(textResult).not.toContain('text-lg');
    });

    it('should handle responsive classes', () => {
      const result = cn('w-full sm:w-1/2 md:w-1/3 lg:w-1/4');
      
      expect(result).toContain('w-full');
      expect(result).toContain('sm:w-1/2');
      expect(result).toContain('md:w-1/3');
      expect(result).toContain('lg:w-1/4');
    });

    it('should handle hover and focus states', () => {
      const result = cn(
        'bg-blue-500 hover:bg-blue-600 focus:bg-blue-700',
        'text-white hover:text-gray-100'
      );

      expect(result).toContain('bg-blue-500');
      expect(result).toContain('hover:bg-blue-600');
      expect(result).toContain('focus:bg-blue-700');
      expect(result).toContain('text-white');
      expect(result).toContain('hover:text-gray-100');
    });

    it('should handle arbitrary values', () => {
      const result = cn('w-[200px]', 'w-[300px]');
      expect(result).toContain('w-[300px]');
      expect(result).not.toContain('w-[200px]');
    });

    it('should handle dark mode classes', () => {
      const result = cn('bg-white dark:bg-gray-900 text-black dark:text-white');
      
      expect(result).toContain('bg-white');
      expect(result).toContain('dark:bg-gray-900');
      expect(result).toContain('text-black');
      expect(result).toContain('dark:text-white');
    });

    it('should handle complex Tailwind class combinations', () => {
      const result = cn(
        // Base styles
        'inline-flex items-center justify-center',
        // Padding and sizing
        'px-4 py-2 min-w-[120px]',
        // Typography
        'text-sm font-medium',
        // Colors
        'text-white bg-blue-600 hover:bg-blue-700',
        // Border and effects
        'border border-transparent rounded-md',
        'shadow-sm hover:shadow-md',
        // Focus states
        'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
        // Disabled state
        'disabled:opacity-50 disabled:cursor-not-allowed',
        // Transitions
        'transition-all duration-200 ease-in-out'
      );

      const expectedClasses = [
        'inline-flex', 'items-center', 'justify-center',
        'px-4', 'py-2', 'min-w-[120px]',
        'text-sm', 'font-medium',
        'text-white', 'bg-blue-600', 'hover:bg-blue-700',
        'border', 'border-transparent', 'rounded-md',
        'shadow-sm', 'hover:shadow-md',
        'focus:outline-none', 'focus:ring-2', 'focus:ring-blue-500', 'focus:ring-offset-2',
        'disabled:opacity-50', 'disabled:cursor-not-allowed',
        'transition-all', 'duration-200', 'ease-in-out'
      ];

      expectedClasses.forEach(className => {
        expect(result).toContain(className);
      });
    });

    it('should handle component variants', () => {
      const buttonVariants = {
        primary: 'bg-blue-600 hover:bg-blue-700 text-white',
        secondary: 'bg-gray-200 hover:bg-gray-300 text-gray-900',
        outline: 'border-2 border-blue-600 text-blue-600 hover:bg-blue-50',
      };

      const variant = 'primary';
      const result = cn(
        'px-4 py-2 rounded-md font-medium transition-colors',
        buttonVariants[variant]
      );

      expect(result).toContain('px-4');
      expect(result).toContain('py-2');
      expect(result).toContain('rounded-md');
      expect(result).toContain('font-medium');
      expect(result).toContain('transition-colors');
      expect(result).toContain('bg-blue-600');
      expect(result).toContain('hover:bg-blue-700');
      expect(result).toContain('text-white');
    });

    it('should handle size variants with conflicts', () => {
      const sizeClasses = {
        sm: 'px-3 py-1 text-xs',
        md: 'px-4 py-2 text-sm',
        lg: 'px-6 py-3 text-base',
      };

      // Override default size with larger size
      const result = cn(
        'px-4 py-2 text-sm', // default medium
        sizeClasses.lg // override with large
      );

      expect(result).toContain('px-6');
      expect(result).toContain('py-3');
      expect(result).toContain('text-base');
      expect(result).not.toContain('px-4');
      expect(result).not.toContain('py-2');
      expect(result).not.toContain('text-sm');
    });

    it('should handle whitespace and special characters', () => {
      const result = cn('  px-4  ', '\tpy-2\n', 'bg-blue-500  text-white  ');
      
      expect(result).toContain('px-4');
      expect(result).toContain('py-2');
      expect(result).toContain('bg-blue-500');
      expect(result).toContain('text-white');
    });

    it('should be deterministic with same inputs', () => {
      const classes = ['px-4 py-2', { 'bg-blue-500': true }, 'text-white'];
      
      const result1 = cn(...classes);
      const result2 = cn(...classes);
      
      expect(result1).toBe(result2);
    });

    it('should handle performance with many classes', () => {
      const manyClasses = Array.from({ length: 100 }, (_, i) => `class-${i}`);
      
      const start = performance.now();
      const result = cn(...manyClasses);
      const end = performance.now();
      
      expect(end - start).toBeLessThan(10); // Should be fast
      expect(result).toContain('class-0');
      expect(result).toContain('class-99');
    });

    it('should handle nested arrays and objects', () => {
      const result = cn(
        'base',
        [
          'nested-array-1',
          ['deeply-nested', { 'conditional': true }],
          'nested-array-2'
        ],
        {
          'object-prop': true,
          'nested-object': {
            'deeply-nested-object': false
          }
        }
      );

      expect(result).toContain('base');
      expect(result).toContain('nested-array-1');
      expect(result).toContain('deeply-nested');
      expect(result).toContain('conditional');
      expect(result).toContain('nested-array-2');
      expect(result).toContain('object-prop');
    });

    it('should handle function calls within conditional logic', () => {
      const getConditionalClass = (condition: boolean) => condition ? 'conditional-true' : 'conditional-false';
      const isTrue = true;
      
      const result = cn('base', getConditionalClass(isTrue));
      
      expect(result).toContain('base');
      expect(result).toContain('conditional-true');
      expect(result).not.toContain('conditional-false');
    });
  });
});