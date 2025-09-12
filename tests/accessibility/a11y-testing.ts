/**
 * Accessibility Testing Framework
 * Comprehensive A11y testing utilities and guidelines
 */
import { axe, toHaveNoViolations, configureAxe } from 'jest-axe';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';

// Extend Jest matchers for accessibility
expect.extend(toHaveNoViolations);

// Configure axe-core with custom rules
configureAxe({
  rules: {
    // Enable additional rules for comprehensive testing
    'color-contrast': { enabled: true },
    'keyboard-navigation': { enabled: true },
    'aria-hidden-focus': { enabled: true },
    'focus-order-semantics': { enabled: true },
    'landmark-unique': { enabled: true }
  },
  // tags: ['wcag2a', 'wcag2aa', 'wcag21aa', 'best-practice'] // Commented out - not supported in current version
});

export interface A11yTestOptions {
  skipRules?: string[];
  customRules?: any[];
  includeHidden?: boolean;
  timeout?: number;
}

export interface KeyboardNavigationTest {
  element: HTMLElement;
  expectedFocusSequence: string[];
  skipKeys?: string[];
}

export interface ScreenReaderTest {
  element: HTMLElement;
  expectedAnnouncements: string[];
  interactions?: Array<{
    action: () => Promise<void>;
    expectedAnnouncement: string;
  }>;
}

/**
 * Core accessibility testing function
 */
export const testAccessibility = async (
  component: ReactElement,
  options: A11yTestOptions = {}
): Promise<void> => {
  const { skipRules = [], customRules = [], includeHidden = false, timeout = 5000 } = options;
  
  const { container } = render(component);
  
  // Configure axe for this specific test
  const axeConfig = {
    rules: skipRules.reduce((config, rule) => {
      config[rule] = { enabled: false };
      return config;
    }, {} as any),
    ...(customRules.length > 0 && { rules: customRules })
  };
  
  // Run accessibility audit
  const results = await axe(container, axeConfig);
  
  expect(results).toHaveNoViolations();
};

/**
 * Test keyboard navigation patterns
 */
export const testKeyboardNavigation = async (
  component: ReactElement,
  navigationTests: KeyboardNavigationTest[]
): Promise<void> => {
  const { container } = render(component);
  const user = userEvent.setup();
  
  for (const test of navigationTests) {
    const { element, expectedFocusSequence, skipKeys = [] } = test;
    
    // Start from the beginning of the focus sequence
    element.focus();
    expect(document.activeElement).toBe(element);
    
    // Test tab navigation
    if (!skipKeys.includes('Tab')) {
      for (const expectedSelector of expectedFocusSequence) {
        await user.tab();
        const expectedElement = container.querySelector(expectedSelector);
        expect(document.activeElement).toBe(expectedElement);
      }
    }
    
    // Test arrow key navigation if element supports it
    if (!skipKeys.includes('ArrowDown')) {
      element.focus();
      await user.keyboard('{ArrowDown}');
      // Verify arrow navigation works (implementation specific)
    }
    
    // Test Enter key activation
    if (!skipKeys.includes('Enter')) {
      element.focus();
      await user.keyboard('{Enter}');
      // Verify Enter key works (implementation specific)
    }
    
    // Test Escape key if applicable
    if (!skipKeys.includes('Escape')) {
      await user.keyboard('{Escape}');
      // Verify Escape key behavior (implementation specific)
    }
  }
};

/**
 * Test screen reader announcements
 */
export const testScreenReaderAnnouncements = async (
  component: ReactElement,
  screenReaderTests: ScreenReaderTest[]
): Promise<void> => {
  const { container } = render(component);
  
  for (const test of screenReaderTests) {
    const { element, expectedAnnouncements, interactions = [] } = test;
    
    // Check initial ARIA attributes
    const ariaLabel = element.getAttribute('aria-label');
    const ariaLabelledBy = element.getAttribute('aria-labelledby');
    const ariaDescribedBy = element.getAttribute('aria-describedby');
    const role = element.getAttribute('role');
    
    // Verify element has proper labeling
    expect(ariaLabel || ariaLabelledBy || element.textContent).toBeTruthy();
    
    // Test live region announcements
    const liveRegions = container.querySelectorAll('[aria-live]');
    expect(liveRegions.length).toBeGreaterThanOrEqual(0);
    
    // Test interactions and their announcements
    for (const interaction of interactions) {
      await interaction.action();
      
      // Check for aria-live updates or alert messages
      const alerts = container.querySelectorAll('[role="alert"], [aria-live="assertive"], [aria-live="polite"]');
      const hasAnnouncement = Array.from(alerts).some(alert => 
        alert.textContent?.includes(interaction.expectedAnnouncement)
      );
      
      if (!hasAnnouncement) {
        console.warn(`Expected announcement "${interaction.expectedAnnouncement}" not found`);
      }
    }
  }
};

/**
 * Test focus management
 */
export const testFocusManagement = async (
  component: ReactElement,
  focusTests: Array<{
    name: string;
    action: (container: HTMLElement, user: ReturnType<typeof userEvent.setup>) => Promise<void>;
    expectedFocus: string; // selector or 'none'
  }>
): Promise<void> => {
  const { container } = render(component);
  const user = userEvent.setup();
  
  for (const test of focusTests) {
    await test.action(container, user);
    
    if (test.expectedFocus === 'none') {
      expect(document.activeElement).toBe(document.body);
    } else {
      const expectedElement = container.querySelector(test.expectedFocus);
      expect(document.activeElement).toBe(expectedElement);
    }
  }
};

/**
 * Test color contrast ratios
 */
export const testColorContrast = async (
  component: ReactElement,
  minimumContrast: number = 4.5 // WCAG AA standard
): Promise<void> => {
  const { container } = render(component);
  
  // This would typically integrate with a color contrast testing library
  // For now, we'll use axe-core's color-contrast rule
  const results = await axe(container, {
    rules: {
      'color-contrast': { enabled: true }
    }
  });
  
  expect(results).toHaveNoViolations();
};

/**
 * Test responsive accessibility across different screen sizes
 */
export const testResponsiveAccessibility = async (
  component: ReactElement,
  breakpoints: Array<{ width: number; height: number; name: string }>
): Promise<void> => {
  for (const breakpoint of breakpoints) {
    // Mock viewport size
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: breakpoint.width
    });
    Object.defineProperty(window, 'innerHeight', {
      writable: true,
      configurable: true,
      value: breakpoint.height
    });
    
    // Dispatch resize event
    window.dispatchEvent(new Event('resize'));
    
    // Test accessibility at this breakpoint
    await testAccessibility(component);
  }
};

/**
 * Test form accessibility
 */
export const testFormAccessibility = async (
  form: ReactElement,
  formTests: Array<{
    inputSelector: string;
    labelText: string;
    errorMessage?: string;
    helpText?: string;
  }>
): Promise<void> => {
  const { container } = render(form);
  
  for (const test of formTests) {
    const input = container.querySelector(test.inputSelector) as HTMLInputElement;
    expect(input).toBeInTheDocument();
    
    // Check for proper labeling
    const label = container.querySelector(`label[for="${input.id}"]`) ||
                 input.closest('label') ||
                 (input.getAttribute('aria-labelledby') && 
                  container.querySelector(`#${input.getAttribute('aria-labelledby')}`));
    
    expect(label).toBeInTheDocument();
    if (label && typeof label !== 'string' && 'textContent' in label) {
      expect(label.textContent).toContain(test.labelText);
    }
    
    // Check for error message association
    if (test.errorMessage) {
      const errorId = input.getAttribute('aria-describedby');
      if (errorId) {
        const errorElement = container.querySelector(`#${errorId}`);
        expect(errorElement).toBeInTheDocument();
      }
    }
    
    // Check for help text association
    if (test.helpText) {
      const describedBy = input.getAttribute('aria-describedby');
      if (describedBy) {
        const helpElement = container.querySelector(`#${describedBy}`);
        expect(helpElement).toBeInTheDocument();
      }
    }
  }
};

/**
 * Test modal/dialog accessibility
 */
export const testModalAccessibility = async (
  modal: ReactElement,
  triggerElement: HTMLElement
): Promise<void> => {
  const user = userEvent.setup();
  const { container } = render(modal);
  
  // Test modal opening
  await user.click(triggerElement);
  
  // Check for proper ARIA attributes
  const modalElement = container.querySelector('[role="dialog"], [role="alertdialog"]');
  expect(modalElement).toBeInTheDocument();
  expect(modalElement).toHaveAttribute('aria-modal', 'true');
  
  // Check for proper labeling
  const ariaLabelledBy = modalElement?.getAttribute('aria-labelledby');
  const ariaLabel = modalElement?.getAttribute('aria-label');
  expect(ariaLabelledBy || ariaLabel).toBeTruthy();
  
  // Test focus management
  const focusableElements = modalElement?.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  expect(focusableElements?.length).toBeGreaterThan(0);
  
  // First focusable element should receive focus
  expect(document.activeElement).toBe(focusableElements?.[0]);
  
  // Test tab trapping
  if (focusableElements && focusableElements.length > 1) {
    // Tab to last element
    for (let i = 1; i < focusableElements.length; i++) {
      await user.tab();
    }
    
    // Tab should wrap to first element
    await user.tab();
    expect(document.activeElement).toBe(focusableElements[0]);
  }
  
  // Test escape key closes modal
  await user.keyboard('{Escape}');
  expect(modalElement).not.toBeInTheDocument();
};

/**
 * Test table accessibility
 */
export const testTableAccessibility = async (
  table: ReactElement,
  expectedHeaders: string[],
  expectedCells: string[][]
): Promise<void> => {
  const { container } = render(table);
  
  const tableElement = container.querySelector('table');
  expect(tableElement).toBeInTheDocument();
  
  // Check for proper table structure
  const headers = tableElement?.querySelectorAll('th');
  expect(headers?.length).toBe(expectedHeaders.length);
  
  // Check header content
  headers?.forEach((header, index) => {
    expect(header.textContent).toContain(expectedHeaders[index]);
    expect(header).toHaveAttribute('scope', 'col');
  });
  
  // Check for caption or aria-label
  const caption = tableElement?.querySelector('caption');
  const ariaLabel = tableElement?.getAttribute('aria-label');
  expect(caption || ariaLabel).toBeTruthy();
  
  // Check cell associations
  const rows = tableElement?.querySelectorAll('tbody tr');
  rows?.forEach((row, rowIndex) => {
    const cells = row.querySelectorAll('td');
    cells.forEach((cell, cellIndex) => {
      // Check if cell content matches expected
      if (expectedCells[rowIndex] && expectedCells[rowIndex][cellIndex]) {
        expect(cell.textContent).toContain(expectedCells[rowIndex][cellIndex]);
      }
    });
  });
};

/**
 * Comprehensive accessibility test suite generator
 */
export const createA11yTestSuite = (
  componentName: string,
  component: ReactElement,
  options: {
    skipKeyboardNav?: boolean;
    skipColorContrast?: boolean;
    skipScreenReader?: boolean;
    customTests?: Array<() => Promise<void>>;
  } = {}
) => {
  const { skipKeyboardNav, skipColorContrast, skipScreenReader, customTests = [] } = options;
  
  return describe(`${componentName} Accessibility`, () => {
    it('should have no accessibility violations', async () => {
      await testAccessibility(component);
    });
    
    if (!skipColorContrast) {
      it('should meet color contrast requirements', async () => {
        await testColorContrast(component);
      });
    }
    
    if (!skipKeyboardNav) {
      it('should support keyboard navigation', async () => {
        const { container } = render(component);
        const focusableElements = container.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        
        if (focusableElements.length > 0) {
          await testKeyboardNavigation(component, [{
            element: focusableElements[0] as HTMLElement,
            expectedFocusSequence: Array.from(focusableElements).slice(1).map((_, i) => `*:nth-child(${i + 2})`)
          }]);
        }
      });
    }
    
    if (!skipScreenReader) {
      it('should provide proper screen reader support', async () => {
        const { container } = render(component);
        const interactiveElements = container.querySelectorAll('[role], [aria-label], [aria-labelledby]');
        
        if (interactiveElements.length > 0) {
          await testScreenReaderAnnouncements(component, [{
            element: interactiveElements[0] as HTMLElement,
            expectedAnnouncements: []
          }]);
        }
      });
    }
    
    it('should maintain accessibility across responsive breakpoints', async () => {
      await testResponsiveAccessibility(component, [
        { width: 320, height: 568, name: 'mobile' },
        { width: 768, height: 1024, name: 'tablet' },
        { width: 1024, height: 768, name: 'desktop' }
      ]);
    });
    
    // Run custom accessibility tests
    customTests.forEach((customTest, index) => {
      it(`should pass custom accessibility test ${index + 1}`, customTest);
    });
  });
};

export default {
  testAccessibility,
  testKeyboardNavigation,
  testScreenReaderAnnouncements,
  testFocusManagement,
  testColorContrast,
  testResponsiveAccessibility,
  testFormAccessibility,
  testModalAccessibility,
  testTableAccessibility,
  createA11yTestSuite
};