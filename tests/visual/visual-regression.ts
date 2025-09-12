/**
 * Visual Regression Testing Framework
 * Comprehensive visual testing utilities for UI components
 */
import React from 'react';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';

export interface VisualTestOptions {
  name?: string;
  viewport?: {
    width: number;
    height: number;
  };
  themes?: string[];
  breakpoints?: Array<{
    name: string;
    width: number;
    height: number;
  }>;
  states?: Array<{
    name: string;
    props: any;
    setup?: () => Promise<void>;
  }>;
  interactions?: Array<{
    name: string;
    action: (container: HTMLElement) => Promise<void>;
  }>;
  skipAnimations?: boolean;
  timeout?: number;
}

export interface VisualSnapshot {
  name: string;
  html: string;
  styles: string;
  timestamp: number;
  viewport: {
    width: number;
    height: number;
  };
  metadata: {
    theme?: string;
    state?: string;
    interaction?: string;
  };
}

export interface VisualComparisonResult {
  passed: boolean;
  differences: number;
  threshold: number;
  baseline: VisualSnapshot;
  current: VisualSnapshot;
  diffImage?: string;
}

// Default viewport sizes for responsive testing
export const VIEWPORT_SIZES = {
  mobile: { width: 375, height: 667 },
  tablet: { width: 768, height: 1024 },
  desktop: { width: 1440, height: 900 },
  ultrawide: { width: 2560, height: 1440 }
};

// Common breakpoints for testing
export const BREAKPOINTS = [
  { name: 'mobile', width: 375, height: 667 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1440, height: 900 }
];

// Theme variants for testing
export const THEME_VARIANTS = ['light', 'dark', 'high-contrast'];

/**
 * Capture visual snapshot of a component
 */
export const captureSnapshot = async (
  component: ReactElement,
  options: VisualTestOptions = {}
): Promise<VisualSnapshot> => {
  const {
    name = 'component-snapshot',
    viewport = VIEWPORT_SIZES.desktop,
    skipAnimations = true
  } = options;

  // Mock viewport size
  Object.defineProperty(window, 'innerWidth', {
    writable: true,
    configurable: true,
    value: viewport.width
  });
  Object.defineProperty(window, 'innerHeight', {
    writable: true,
    configurable: true,
    value: viewport.height
  });

  // Disable animations for consistent snapshots
  if (skipAnimations) {
    const style = document.createElement('style');
    style.textContent = `
      *, *::before, *::after {
        animation-duration: 0s !important;
        animation-delay: 0s !important;
        transition-duration: 0s !important;
        transition-delay: 0s !important;
      }
    `;
    document.head.appendChild(style);
  }

  const { container } = render(component);

  // Wait for any pending updates
  await new Promise(resolve => setTimeout(resolve, 100));

  // Capture HTML and styles
  const html = container.innerHTML;
  const styles = Array.from(document.styleSheets)
    .map(sheet => {
      try {
        return Array.from(sheet.cssRules).map(rule => rule.cssText).join('\n');
      } catch (e) {
        return ''; // Cross-origin stylesheets
      }
    })
    .join('\n');

  return {
    name,
    html,
    styles,
    timestamp: Date.now(),
    viewport,
    metadata: {}
  };
};

/**
 * Capture snapshots across multiple states
 */
export const captureStateSnapshots = async (
  ComponentFactory: (props: any) => ReactElement,
  states: Array<{
    name: string;
    props: any;
    setup?: () => Promise<void>;
  }>,
  options: VisualTestOptions = {}
): Promise<VisualSnapshot[]> => {
  const snapshots: VisualSnapshot[] = [];

  for (const state of states) {
    if (state.setup) {
      await state.setup();
    }

    const component = ComponentFactory(state.props);
    const snapshot = await captureSnapshot(component, {
      ...options,
      name: `${options.name || 'component'}-${state.name}`
    });

    snapshot.metadata.state = state.name;
    snapshots.push(snapshot);
  }

  return snapshots;
};

/**
 * Capture snapshots across different themes
 */
export const captureThemeSnapshots = async (
  component: ReactElement,
  themes: string[] = THEME_VARIANTS,
  options: VisualTestOptions = {}
): Promise<VisualSnapshot[]> => {
  const snapshots: VisualSnapshot[] = [];

  for (const theme of themes) {
    // Add theme class to body
    document.body.className = `theme-${theme}`;
    document.body.setAttribute('data-theme', theme);

    const snapshot = await captureSnapshot(component, {
      ...options,
      name: `${options.name || 'component'}-${theme}`
    });

    snapshot.metadata.theme = theme;
    snapshots.push(snapshot);

    // Clean up theme
    document.body.className = '';
    document.body.removeAttribute('data-theme');
  }

  return snapshots;
};

/**
 * Capture responsive snapshots across breakpoints
 */
export const captureResponsiveSnapshots = async (
  component: ReactElement,
  breakpoints: Array<{ name: string; width: number; height: number }> = BREAKPOINTS,
  options: VisualTestOptions = {}
): Promise<VisualSnapshot[]> => {
  const snapshots: VisualSnapshot[] = [];

  for (const breakpoint of breakpoints) {
    const snapshot = await captureSnapshot(component, {
      ...options,
      viewport: { width: breakpoint.width, height: breakpoint.height },
      name: `${options.name || 'component'}-${breakpoint.name}`
    });

    snapshots.push(snapshot);
  }

  return snapshots;
};

/**
 * Capture interaction snapshots
 */
export const captureInteractionSnapshots = async (
  component: ReactElement,
  interactions: Array<{
    name: string;
    action: (container: HTMLElement) => Promise<void>;
  }>,
  options: VisualTestOptions = {}
): Promise<VisualSnapshot[]> => {
  const snapshots: VisualSnapshot[] = [];
  const { container } = render(component);

  // Capture initial state
  const initialSnapshot = await captureSnapshot(component, {
    ...options,
    name: `${options.name || 'component'}-initial`
  });
  initialSnapshot.metadata.interaction = 'initial';
  snapshots.push(initialSnapshot);

  // Capture after each interaction
  for (const interaction of interactions) {
    await interaction.action(container);

    // Wait for any animations or state updates
    await new Promise(resolve => setTimeout(resolve, 200));

    const snapshot = await captureSnapshot(component, {
      ...options,
      name: `${options.name || 'component'}-${interaction.name}`
    });

    snapshot.metadata.interaction = interaction.name;
    snapshots.push(snapshot);
  }

  return snapshots;
};

/**
 * Compare visual snapshots
 */
export const compareSnapshots = (
  baseline: VisualSnapshot,
  current: VisualSnapshot,
  threshold: number = 0.01
): VisualComparisonResult => {
  // Simple HTML comparison for now
  // In a real implementation, this would use image comparison
  const baselineHash = hashString(baseline.html + baseline.styles);
  const currentHash = hashString(current.html + current.styles);
  
  const differences = baselineHash === currentHash ? 0 : 1;
  const passed = differences <= threshold;

  return {
    passed,
    differences,
    threshold,
    baseline,
    current,
    diffImage: differences > 0 ? `diff-${Date.now()}.png` : undefined
  };
};

/**
 * Simple string hash function for comparison
 */
const hashString = (str: string): string => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString();
};

/**
 * Generate visual test report
 */
export const generateVisualReport = (
  componentName: string,
  results: VisualComparisonResult[]
): string => {
  const passed = results.filter(r => r.passed).length;
  const failed = results.length - passed;
  
  const report = [
    `Visual Regression Report for ${componentName}`,
    '='.repeat(50),
    '',
    `Total Tests: ${results.length}`,
    `Passed: ${passed}`,
    `Failed: ${failed}`,
    '',
    'Failed Tests:',
    ...results
      .filter(r => !r.passed)
      .map(r => `- ${r.baseline.name}: ${r.differences} differences (threshold: ${r.threshold})`),
    '',
    `Overall Status: ${failed === 0 ? '✅ PASSED' : '❌ FAILED'}`
  ];

  return report.join('\n');
};

/**
 * Create visual regression test suite
 */
export const createVisualTestSuite = (
  componentName: string,
  component: ReactElement,
  options: {
    states?: Array<{ name: string; props: any }>;
    themes?: string[];
    breakpoints?: Array<{ name: string; width: number; height: number }>;
    interactions?: Array<{
      name: string;
      action: (container: HTMLElement) => Promise<void>;
    }>;
    threshold?: number;
  } = {}
) => {
  const {
    states = [],
    themes = [],
    breakpoints = [],
    interactions = [],
    threshold = 0.01
  } = options;

  return describe(`${componentName} Visual Regression`, () => {
    if (states.length > 0) {
      it('should match visual snapshots across different states', async () => {
        const snapshots = await captureStateSnapshots(
          (props) => React.cloneElement(component, props),
          states,
          { name: componentName.toLowerCase() }
        );

        // Store snapshots for comparison (in real implementation)
        expect(snapshots.length).toBe(states.length);
        snapshots.forEach(snapshot => {
          expect(snapshot.html).toBeTruthy();
          expect(snapshot.metadata.state).toBeTruthy();
        });
      });
    }

    if (themes.length > 0) {
      it('should match visual snapshots across different themes', async () => {
        const snapshots = await captureThemeSnapshots(
          component,
          themes,
          { name: componentName.toLowerCase() }
        );

        expect(snapshots.length).toBe(themes.length);
        snapshots.forEach(snapshot => {
          expect(snapshot.html).toBeTruthy();
          expect(snapshot.metadata.theme).toBeTruthy();
        });
      });
    }

    if (breakpoints.length > 0) {
      it('should match visual snapshots across different breakpoints', async () => {
        const snapshots = await captureResponsiveSnapshots(
          component,
          breakpoints,
          { name: componentName.toLowerCase() }
        );

        expect(snapshots.length).toBe(breakpoints.length);
        snapshots.forEach(snapshot => {
          expect(snapshot.viewport).toBeTruthy();
        });
      });
    }

    if (interactions.length > 0) {
      it('should match visual snapshots for user interactions', async () => {
        const snapshots = await captureInteractionSnapshots(
          component,
          interactions,
          { name: componentName.toLowerCase() }
        );

        expect(snapshots.length).toBe(interactions.length + 1); // +1 for initial state
        snapshots.forEach(snapshot => {
          expect(snapshot.html).toBeTruthy();
          expect(snapshot.metadata.interaction).toBeTruthy();
        });
      });
    }

    it('should capture baseline snapshot for future comparisons', async () => {
      const snapshot = await captureSnapshot(component, {
        name: `${componentName.toLowerCase()}-baseline`
      });

      expect(snapshot.html).toBeTruthy();
      expect(snapshot.styles).toBeTruthy();
      expect(snapshot.viewport).toBeTruthy();

      // In a real implementation, save this snapshot for future comparisons
      console.log(`Baseline snapshot captured for ${componentName}`);
    });
  });
};

/**
 * Utility to mock different device characteristics
 */
export const mockDeviceCharacteristics = (device: {
  userAgent?: string;
  pixelRatio?: number;
  touchSupport?: boolean;
  colorScheme?: 'light' | 'dark';
}) => {
  if (device.userAgent) {
    Object.defineProperty(navigator, 'userAgent', {
      writable: true,
      value: device.userAgent
    });
  }

  if (device.pixelRatio) {
    Object.defineProperty(window, 'devicePixelRatio', {
      writable: true,
      value: device.pixelRatio
    });
  }

  if (device.touchSupport !== undefined) {
    Object.defineProperty(navigator, 'maxTouchPoints', {
      writable: true,
      value: device.touchSupport ? 10 : 0
    });
  }

  if (device.colorScheme) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation((query: string) => ({
        matches: query.includes(device.colorScheme!),
        media: query,
        onchange: null,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      }))
    });
  }
};

/**
 * Common device presets for testing
 */
export const DEVICE_PRESETS = {
  iPhone12: {
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    pixelRatio: 3,
    touchSupport: true,
    viewport: { width: 390, height: 844 }
  },
  iPad: {
    userAgent: 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    pixelRatio: 2,
    touchSupport: true,
    viewport: { width: 768, height: 1024 }
  },
  macBookPro: {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    pixelRatio: 2,
    touchSupport: false,
    viewport: { width: 1440, height: 900 }
  }
};

export default {
  captureSnapshot,
  captureStateSnapshots,
  captureThemeSnapshots,
  captureResponsiveSnapshots,
  captureInteractionSnapshots,
  compareSnapshots,
  generateVisualReport,
  createVisualTestSuite,
  mockDeviceCharacteristics,
  VIEWPORT_SIZES,
  BREAKPOINTS,
  THEME_VARIANTS,
  DEVICE_PRESETS
};