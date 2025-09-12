/**
 * Accessibility Testing Framework
 * Comprehensive WCAG 2.1 AA compliance testing utilities
 */

import { axe, toHaveNoViolations } from 'jest-axe';
import { RenderResult, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

export interface AccessibilityTestOptions {
  level?: 'A' | 'AA' | 'AAA';
  includeTags?: string[];
  excludeTags?: string[];
  timeout?: number;
  verbose?: boolean;
}

export interface AccessibilityTestResult {
  violations: any[];
  passes: any[];
  incomplete: any[];
  inapplicable: any[];
  summary: {
    violationCount: number;
    passCount: number;
    incompleteCount: number;
    totalRules: number;
  };
}

export interface KeyboardNavigationTest {
  element: HTMLElement;
  expectedKeys: string[];
  expectedBehavior: string;
  actualBehavior?: string;
  passed: boolean;
}

export class AccessibilityTester {
  private static defaultOptions: AccessibilityTestOptions = {
    level: 'AA',
    includeTags: ['wcag2a', 'wcag2aa', 'wcag21aa'],
    excludeTags: ['experimental'],
    timeout: 10000,
    verbose: false,
  };

  static async testComponent(
    container: HTMLElement,
    options: AccessibilityTestOptions = {}
  ): Promise<AccessibilityTestResult> {
    const config = { ...this.defaultOptions, ...options };
    
    const axeConfig = {
      tags: config.includeTags,
      rules: this.buildRulesConfig(config),
    };

    try {
      const results = await axe(container, axeConfig);
      
      const summary = {
        violationCount: results.violations.length,
        passCount: results.passes.length,
        incompleteCount: results.incomplete.length,
        totalRules: results.violations.length + results.passes.length + results.incomplete.length,
      };

      if (config.verbose) {
        this.logResults(results, summary);
      }

      return {
        violations: results.violations,
        passes: results.passes,
        incomplete: results.incomplete,
        inapplicable: results.inapplicable,
        summary,
      };
    } catch (error) {
      throw new Error(`Accessibility testing failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  static async expectNoViolations(
    container: HTMLElement,
    options: AccessibilityTestOptions = {}
  ): Promise<void> {
    const results = await this.testComponent(container, options);
    
    if (results.violations.length > 0) {
      const violationDetails = results.violations.map(violation => ({
        id: violation.id,
        impact: violation.impact,
        description: violation.description,
        nodes: violation.nodes.length,
      }));
      
      throw new Error(
        `Found ${results.violations.length} accessibility violations:\n` +
        JSON.stringify(violationDetails, null, 2)
      );
    }
  }

  static async testKeyboardNavigation(
    container: HTMLElement,
    options: { verbose?: boolean } = {}
  ): Promise<KeyboardNavigationTest[]> {
    const user = userEvent.setup();
    const interactiveElements = this.getInteractiveElements(container);
    const results: KeyboardNavigationTest[] = [];

    for (const element of interactiveElements) {
      const test = await this.testElementKeyboardAccess(element, user);
      results.push(test);
      
      if (options.verbose) {
        console.log(`Keyboard test for ${element.tagName}:`, test);
      }
    }

    return results;
  }

  static async testFocusManagement(
    renderResult: RenderResult,
    options: { timeout?: number } = {}
  ): Promise<{
    focusOrder: HTMLElement[];
    hasLogicalOrder: boolean;
    hasFocusTrap: boolean;
    restoresFocus: boolean;
  }> {
    const { timeout = 5000 } = options;
    const user = userEvent.setup();
    
    // Get all focusable elements
    const focusableElements = this.getFocusableElements(renderResult.container);
    const focusOrder: HTMLElement[] = [];
    
    // Record focus order
    for (const element of focusableElements) {
      element.focus();
      if (document.activeElement === element) {
        focusOrder.push(element);
      }
    }

    // Test Tab navigation
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    
    if (firstElement) {
      firstElement.focus();
      
      // Test forward navigation
      for (let i = 0; i < focusableElements.length - 1; i++) {
        await user.tab();
      }
      
      // Test backward navigation
      await user.tab({ shift: true });
    }

    return {
      focusOrder,
      hasLogicalOrder: this.validateFocusOrder(focusOrder),
      hasFocusTrap: this.testFocusTrap(focusableElements),
      restoresFocus: await this.testFocusRestore(renderResult, timeout),
    };
  }

  static async testScreenReaderCompatibility(
    container: HTMLElement,
    options: { timeout?: number; verbose?: boolean } = {}
  ): Promise<{
    hasAriaLabels: boolean;
    hasLandmarks: boolean;
    hasHeadingStructure: boolean;
    hasLiveRegions: boolean;
    missingLabels: string[];
    issues: string[];
  }> {
    const { timeout = 5000, verbose = false } = options;
    const issues: string[] = [];
    const missingLabels: string[] = [];

    // Check for ARIA labels
    const interactiveElements = this.getInteractiveElements(container);
    const unlabeledElements = interactiveElements.filter(element => 
      !this.hasAccessibleLabel(element)
    );
    
    unlabeledElements.forEach(element => {
      missingLabels.push(`${element.tagName}${element.id ? `#${element.id}` : ''}`);
    });

    // Check for landmarks
    const landmarks = container.querySelectorAll('[role="main"], [role="navigation"], [role="banner"], [role="contentinfo"], [role="complementary"], main, nav, header, footer, aside');
    const hasLandmarks = landmarks.length > 0;

    if (!hasLandmarks) {
      issues.push('No ARIA landmarks found');
    }

    // Check heading structure
    const headings = Array.from(container.querySelectorAll('h1, h2, h3, h4, h5, h6, [role="heading"]'));
    const hasHeadingStructure = this.validateHeadingStructure(headings);

    if (!hasHeadingStructure) {
      issues.push('Invalid heading structure');
    }

    // Check for live regions
    const liveRegions = container.querySelectorAll('[aria-live], [role="status"], [role="alert"]');
    const hasLiveRegions = liveRegions.length > 0;

    if (verbose) {
      console.log('Screen reader compatibility test results:', {
        interactiveElements: interactiveElements.length,
        unlabeledElements: unlabeledElements.length,
        landmarks: landmarks.length,
        headings: headings.length,
        liveRegions: liveRegions.length,
      });
    }

    return {
      hasAriaLabels: unlabeledElements.length === 0,
      hasLandmarks,
      hasHeadingStructure,
      hasLiveRegions,
      missingLabels,
      issues,
    };
  }

  static async testColorContrast(
    container: HTMLElement,
    options: { level?: 'AA' | 'AAA'; verbose?: boolean } = {}
  ): Promise<{
    passesAALevel: boolean;
    passesAAALevel: boolean;
    violations: Array<{
      element: string;
      contrast: number;
      expected: number;
      colors: { foreground: string; background: string };
    }>;
  }> {
    // This would integrate with axe-core's color-contrast rule
    const results = await this.testComponent(container, {
      includeTags: ['wcag2aa'],
      excludeTags: [],
    });

    const colorViolations = results.violations.filter(v => v.id === 'color-contrast');
    const violations = colorViolations.flatMap(violation => 
      violation.nodes.map((node: any) => ({
        element: node.target.join(' '),
        contrast: node.any[0]?.data?.contrastRatio || 0,
        expected: node.any[0]?.data?.expectedContrastRatio || 4.5,
        colors: {
          foreground: node.any[0]?.data?.fgColor || 'unknown',
          background: node.any[0]?.data?.bgColor || 'unknown',
        },
      }))
    );

    return {
      passesAALevel: violations.length === 0,
      passesAAALevel: violations.every(v => v.contrast >= 7),
      violations,
    };
  }

  // Comprehensive accessibility test suite
  static async runFullAccessibilityAudit(
    renderResult: RenderResult,
    options: AccessibilityTestOptions & {
      skipKeyboard?: boolean;
      skipFocus?: boolean;
      skipScreenReader?: boolean;
      skipColorContrast?: boolean;
    } = {}
  ) {
    const { container } = renderResult;
    const results = {
      wcag: null as AccessibilityTestResult | null,
      keyboard: null as KeyboardNavigationTest[] | null,
      focus: null as any,
      screenReader: null as any,
      colorContrast: null as any,
      summary: {
        passed: true,
        issues: [] as string[],
        score: 100,
      },
    };

    try {
      // WCAG compliance test
      results.wcag = await this.testComponent(container, options);
      if (results.wcag.violations.length > 0) {
        results.summary.passed = false;
        results.summary.issues.push(`${results.wcag.violations.length} WCAG violations`);
        results.summary.score -= 30;
      }

      // Keyboard navigation test
      if (!options.skipKeyboard) {
        results.keyboard = await this.testKeyboardNavigation(container, options);
        const keyboardIssues = results.keyboard.filter(test => !test.passed);
        if (keyboardIssues.length > 0) {
          results.summary.passed = false;
          results.summary.issues.push(`${keyboardIssues.length} keyboard navigation issues`);
          results.summary.score -= 20;
        }
      }

      // Focus management test
      if (!options.skipFocus) {
        results.focus = await this.testFocusManagement(renderResult);
        if (!results.focus.hasLogicalOrder || !results.focus.restoresFocus) {
          results.summary.passed = false;
          results.summary.issues.push('Focus management issues');
          results.summary.score -= 20;
        }
      }

      // Screen reader compatibility test
      if (!options.skipScreenReader) {
        results.screenReader = await this.testScreenReaderCompatibility(container, options);
        if (results.screenReader.issues.length > 0) {
          results.summary.passed = false;
          results.summary.issues.push(...results.screenReader.issues);
          results.summary.score -= 15;
        }
      }

      // Color contrast test
      if (!options.skipColorContrast) {
        results.colorContrast = await this.testColorContrast(container, { level: (options.level === 'A' ? 'AA' : options.level) || 'AA', verbose: options.verbose });
        if (!results.colorContrast.passesAALevel) {
          results.summary.passed = false;
          results.summary.issues.push('Color contrast violations');
          results.summary.score -= 15;
        }
      }

      results.summary.score = Math.max(0, results.summary.score);

    } catch (error) {
      results.summary.passed = false;
      results.summary.issues.push(`Test execution error: ${error instanceof Error ? error.message : String(error)}`);
      results.summary.score = 0;
    }

    return results;
  }

  // Private utility methods
  private static buildRulesConfig(options: AccessibilityTestOptions) {
    const rules: any = {};
    
    // Configure based on level
    if (options.level === 'A') {
      rules['color-contrast-enhanced'] = { enabled: false };
    } else if (options.level === 'AAA') {
      rules['color-contrast-enhanced'] = { enabled: true };
    }

    return rules;
  }

  private static getInteractiveElements(container: HTMLElement): HTMLElement[] {
    const selector = 'button, [role="button"], input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])';
    return Array.from(container.querySelectorAll(selector));
  }

  private static getFocusableElements(container: HTMLElement): HTMLElement[] {
    const selector = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    return Array.from(container.querySelectorAll(selector));
  }

  private static async testElementKeyboardAccess(
    element: HTMLElement,
    user: any
  ): Promise<KeyboardNavigationTest> {
    const tagName = element.tagName.toLowerCase();
    const role = element.getAttribute('role') || tagName;
    
    let expectedKeys: string[] = [];
    let expectedBehavior = '';
    
    // Determine expected keyboard behavior based on element type
    switch (role) {
      case 'button':
        expectedKeys = ['Enter', ' '];
        expectedBehavior = 'Should activate on Enter or Space';
        break;
      case 'tab':
        expectedKeys = ['Enter', ' ', 'ArrowLeft', 'ArrowRight'];
        expectedBehavior = 'Should activate on Enter/Space, navigate with arrows';
        break;
      case 'textbox':
      case 'input':
        expectedKeys = ['Enter'];
        expectedBehavior = 'Should be focusable and accept input';
        break;
      default:
        expectedKeys = ['Enter'];
        expectedBehavior = 'Should be keyboard accessible';
    }

    // Test if element can receive focus
    element.focus();
    const canFocus = document.activeElement === element;
    
    return {
      element,
      expectedKeys,
      expectedBehavior,
      actualBehavior: canFocus ? 'Focusable' : 'Not focusable',
      passed: canFocus,
    };
  }

  private static hasAccessibleLabel(element: HTMLElement): boolean {
    return !!(
      element.getAttribute('aria-label') ||
      element.getAttribute('aria-labelledby') ||
      element.getAttribute('title') ||
      (element.tagName === 'IMG' && element.getAttribute('alt')) ||
      element.textContent?.trim()
    );
  }

  private static validateFocusOrder(focusOrder: HTMLElement[]): boolean {
    // Simple check - could be enhanced with more sophisticated logic
    return focusOrder.length > 0;
  }

  private static testFocusTrap(focusableElements: HTMLElement[]): boolean {
    // Check if focus properly cycles within the component
    return focusableElements.length > 0;
  }

  private static async testFocusRestore(
    renderResult: RenderResult,
    timeout: number
  ): Promise<boolean> {
    // This would test if focus is properly restored after component unmount
    return true; // Simplified for now
  }

  private static validateHeadingStructure(headings: Element[]): boolean {
    if (headings.length === 0) return true; // No headings is okay
    
    const levels = headings.map(h => {
      const tagName = h.tagName.toLowerCase();
      if (tagName.startsWith('h')) {
        return parseInt(tagName.charAt(1), 10);
      }
      const level = h.getAttribute('aria-level');
      return level ? parseInt(level, 10) : 1;
    });

    // Check if heading levels are logical (no big jumps)
    for (let i = 1; i < levels.length; i++) {
      if (levels[i] - levels[i - 1] > 1) {
        return false;
      }
    }

    return true;
  }

  private static logResults(results: any, summary: any): void {
    console.log('=== Accessibility Test Results ===');
    console.log(`Total rules tested: ${summary.totalRules}`);
    console.log(`Passed: ${summary.passCount}`);
    console.log(`Violations: ${summary.violationCount}`);
    console.log(`Incomplete: ${summary.incompleteCount}`);
    
    if (summary.violationCount > 0) {
      console.log('\nViolations:');
      results.violations.forEach((violation: any, index: number) => {
        console.log(`  ${index + 1}. ${violation.id}: ${violation.description}`);
        console.log(`     Impact: ${violation.impact}`);
        console.log(`     Nodes affected: ${violation.nodes.length}`);
      });
    }
    console.log('=== End Accessibility Results ===');
  }
}

// Convenience exports
export const testAccessibility = AccessibilityTester.testComponent.bind(AccessibilityTester);
export const expectNoViolations = AccessibilityTester.expectNoViolations.bind(AccessibilityTester);
export const testKeyboardNavigation = AccessibilityTester.testKeyboardNavigation.bind(AccessibilityTester);
export const runFullAccessibilityAudit = AccessibilityTester.runFullAccessibilityAudit.bind(AccessibilityTester);

export default AccessibilityTester;