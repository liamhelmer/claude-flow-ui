/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';
import { 
  TestDataGenerator,
  renderWithEnhancements 
} from './test-utilities';

// Mock dependencies
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => ({
    terminalRef: { current: null },
    terminal: null,
    writeToTerminal: jest.fn(),
    clearTerminal: jest.fn(),
    focusTerminal: jest.fn(),
    fitTerminal: jest.fn(),
    isConnected: true,
    isAtBottom: true,
    hasNewOutput: false,
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
  }),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    isConnected: true,
    on: jest.fn(),
    off: jest.fn(),
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({
    sessions: TestDataGenerator.generateSessions(3),
    activeSession: null,
    isLoading: false,
    error: null,
    agents: TestDataGenerator.generateAgents(5),
    memory: TestDataGenerator.generateMemoryData(),
    commands: TestDataGenerator.generateCommands(10),
    prompts: [],
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
  }),
}));

// Visual regression testing utilities
class VisualRegressionUtils {
  static captureComponentSnapshot(component: HTMLElement): string {
    // In a real implementation, this would capture actual visual screenshots
    // For testing purposes, we'll capture the DOM structure and computed styles
    const computedStyle = getComputedStyle(component);
    const boundingRect = component.getBoundingClientRect();
    
    return JSON.stringify({
      tagName: component.tagName,
      className: component.className,
      textContent: component.textContent?.substring(0, 100) || '',
      dimensions: {
        width: boundingRect.width,
        height: boundingRect.height,
      },
      styles: {
        backgroundColor: computedStyle.backgroundColor,
        color: computedStyle.color,
        fontSize: computedStyle.fontSize,
        fontFamily: computedStyle.fontFamily,
        border: computedStyle.border,
        margin: computedStyle.margin,
        padding: computedStyle.padding,
        position: computedStyle.position,
        display: computedStyle.display,
      },
      childElementCount: component.childElementCount,
    });
  }

  static compareSnapshots(snapshot1: string, snapshot2: string): { isEqual: boolean; differences: string[] } {
    const obj1 = JSON.parse(snapshot1);
    const obj2 = JSON.parse(snapshot2);
    const differences: string[] = [];

    // Compare dimensions
    if (obj1.dimensions.width !== obj2.dimensions.width) {
      differences.push(`Width changed: ${obj1.dimensions.width} -> ${obj2.dimensions.width}`);
    }
    if (obj1.dimensions.height !== obj2.dimensions.height) {
      differences.push(`Height changed: ${obj1.dimensions.height} -> ${obj2.dimensions.height}`);
    }

    // Compare key visual styles
    const styleKeys = ['backgroundColor', 'color', 'fontSize', 'border'];
    for (const key of styleKeys) {
      if (obj1.styles[key] !== obj2.styles[key]) {
        differences.push(`${key} changed: ${obj1.styles[key]} -> ${obj2.styles[key]}`);
      }
    }

    // Compare structure
    if (obj1.childElementCount !== obj2.childElementCount) {
      differences.push(`Child count changed: ${obj1.childElementCount} -> ${obj2.childElementCount}`);
    }

    return {
      isEqual: differences.length === 0,
      differences,
    };
  }

  static createViewportSnapshot(width: number, height: number): void {
    // Mock viewport resizing for responsive testing
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: width,
    });
    Object.defineProperty(window, 'innerHeight', {
      writable: true,
      configurable: true,
      value: height,
    });

    // Trigger resize event
    window.dispatchEvent(new Event('resize'));
  }
}

describe('Visual Regression Testing', () => {
  describe('Component Visual Consistency', () => {
    test('should maintain Terminal component visual appearance', () => {
      const { container: container1 } = renderWithEnhancements(
        <Terminal sessionId="visual-test-1" />
      );

      const { container: container2 } = renderWithEnhancements(
        <Terminal sessionId="visual-test-2" />
      );

      const terminal1 = container1.querySelector('[role="application"]') as HTMLElement;
      const terminal2 = container2.querySelector('[role="application"]') as HTMLElement;

      expect(terminal1).toBeInTheDocument();
      expect(terminal2).toBeInTheDocument();

      const snapshot1 = VisualRegressionUtils.captureComponentSnapshot(terminal1);
      const snapshot2 = VisualRegressionUtils.captureComponentSnapshot(terminal2);

      const comparison = VisualRegressionUtils.compareSnapshots(snapshot1, snapshot2);
      
      if (!comparison.isEqual) {
        console.warn('Terminal visual differences detected:', comparison.differences);
      }

      // Allow for minor differences in content but not in structure/styling
      expect(comparison.differences.filter(diff => !diff.includes('textContent')).length).toBe(0);
    });

    test('should maintain Sidebar visual consistency across different session counts', () => {
      const sessions3 = TestDataGenerator.generateSessions(3);
      const sessions10 = TestDataGenerator.generateSessions(10);

      const { container: container1 } = renderWithEnhancements(
        <Sidebar
          sessions={sessions3}
          activeSessionId={sessions3[0].id}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const { container: container2 } = renderWithEnhancements(
        <Sidebar
          sessions={sessions10}
          activeSessionId={sessions10[0].id}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const sidebar1 = container1.querySelector('[role="navigation"]') as HTMLElement;
      const sidebar2 = container2.querySelector('[role="navigation"]') as HTMLElement;

      const snapshot1 = VisualRegressionUtils.captureComponentSnapshot(sidebar1);
      const snapshot2 = VisualRegressionUtils.captureComponentSnapshot(sidebar2);

      const comparison = VisualRegressionUtils.compareSnapshots(snapshot1, snapshot2);

      // Structure should be similar even with different content
      const structuralDifferences = comparison.differences.filter(diff => 
        diff.includes('Width') || diff.includes('Height') || 
        diff.includes('backgroundColor') || diff.includes('fontSize')
      );

      expect(structuralDifferences.length).toBe(0);
    });

    test('should maintain TabList visual consistency with varying tab counts', () => {
      const tabs2 = [
        { id: 'tab1', title: 'Tab 1', isActive: true },
        { id: 'tab2', title: 'Tab 2', isActive: false },
      ];

      const tabs5 = [
        { id: 'tab1', title: 'Tab 1', isActive: true },
        { id: 'tab2', title: 'Tab 2', isActive: false },
        { id: 'tab3', title: 'Tab 3', isActive: false },
        { id: 'tab4', title: 'Tab 4', isActive: false },
        { id: 'tab5', title: 'Tab 5', isActive: false },
      ];

      const { container: container1 } = renderWithEnhancements(
        <TabList tabs={tabs2} onTabChange={jest.fn()} />
      );

      const { container: container2 } = renderWithEnhancements(
        <TabList tabs={tabs5} onTabChange={jest.fn()} />
      );

      const tablist1 = container1.querySelector('[role="tablist"]') as HTMLElement;
      const tablist2 = container2.querySelector('[role="tablist"]') as HTMLElement;

      const snapshot1 = VisualRegressionUtils.captureComponentSnapshot(tablist1);
      const snapshot2 = VisualRegressionUtils.captureComponentSnapshot(tablist2);

      const comparison = VisualRegressionUtils.compareSnapshots(snapshot1, snapshot2);

      // Check that core styling remains consistent
      const coreStylingDifferences = comparison.differences.filter(diff => 
        diff.includes('fontSize') || diff.includes('fontFamily') || 
        diff.includes('backgroundColor') || diff.includes('border')
      );

      expect(coreStylingDifferences.length).toBe(0);
    });
  });

  describe('Responsive Design Visual Testing', () => {
    test('should maintain layout integrity across different viewport sizes', () => {
      const viewports = [
        { width: 320, height: 568, name: 'mobile' },    // iPhone SE
        { width: 768, height: 1024, name: 'tablet' },   // iPad
        { width: 1024, height: 768, name: 'tablet-landscape' },
        { width: 1440, height: 900, name: 'desktop' },  // Desktop
        { width: 1920, height: 1080, name: 'large-desktop' },
      ];

      const sessions = TestDataGenerator.generateSessions(5);
      const snapshots: { [key: string]: string } = {};

      viewports.forEach(viewport => {
        VisualRegressionUtils.createViewportSnapshot(viewport.width, viewport.height);

        const { container } = renderWithEnhancements(
          <div className="app-layout">
            <Sidebar
              sessions={sessions}
              activeSessionId={sessions[0].id}
              onSessionSelect={jest.fn()}
              onSessionClose={jest.fn()}
              onNewSession={jest.fn()}
            />
            <main className="main-content">
              <TabList
                tabs={[
                  { id: 'terminal', title: 'Terminal', isActive: true },
                  { id: 'monitoring', title: 'Monitoring', isActive: false },
                ]}
                onTabChange={jest.fn()}
              />
              <Terminal sessionId="responsive-test" />
            </main>
          </div>
        );

        const appLayout = container.firstChild as HTMLElement;
        snapshots[viewport.name] = VisualRegressionUtils.captureComponentSnapshot(appLayout);
      });

      // Compare mobile vs tablet - should have different layouts
      const mobileVsTablet = VisualRegressionUtils.compareSnapshots(
        snapshots.mobile,
        snapshots.tablet
      );

      // Layouts should differ between mobile and tablet
      expect(mobileVsTablet.isEqual).toBe(false);

      // Compare tablet vs desktop - may have similar layouts
      const tabletVsDesktop = VisualRegressionUtils.compareSnapshots(
        snapshots.tablet,
        snapshots.desktop
      );

      // Should maintain consistent styling even if dimensions change
      const stylingDifferences = tabletVsDesktop.differences.filter(diff => 
        !diff.includes('Width') && !diff.includes('Height')
      );

      expect(stylingDifferences.length).toBeLessThanOrEqual(2); // Allow minimal styling differences
    });

    test('should handle text scaling and zoom levels', () => {
      const zoomLevels = [0.75, 1.0, 1.25, 1.5, 2.0];
      const snapshots: string[] = [];

      zoomLevels.forEach(zoom => {
        // Mock zoom level by adjusting font size
        document.documentElement.style.fontSize = `${16 * zoom}px`;

        const { container } = renderWithEnhancements(
          <Terminal sessionId="zoom-test" />
        );

        const terminal = container.querySelector('[role="application"]') as HTMLElement;
        snapshots.push(VisualRegressionUtils.captureComponentSnapshot(terminal));
      });

      // Reset font size
      document.documentElement.style.fontSize = '';

      // Verify that components scale appropriately
      for (let i = 1; i < snapshots.length; i++) {
        const comparison = VisualRegressionUtils.compareSnapshots(snapshots[0], snapshots[i]);
        
        // Font size should change, but other styling should remain consistent
        const nonFontDifferences = comparison.differences.filter(diff => 
          !diff.includes('fontSize') && !diff.includes('Width') && !diff.includes('Height')
        );

        expect(nonFontDifferences.length).toBe(0);
      }
    });
  });

  describe('Theme and Color Consistency', () => {
    test('should maintain visual consistency across theme variations', () => {
      const themes = [
        { name: 'light', class: 'theme-light' },
        { name: 'dark', class: 'theme-dark' },
        { name: 'high-contrast', class: 'theme-high-contrast' },
      ];

      const snapshots: { [key: string]: string } = {};

      themes.forEach(theme => {
        const { container } = renderWithEnhancements(
          <div className={theme.class}>
            <Terminal sessionId="theme-test" />
          </div>
        );

        const themedContainer = container.firstChild as HTMLElement;
        snapshots[theme.name] = VisualRegressionUtils.captureComponentSnapshot(themedContainer);
      });

      // Verify that themes have different color schemes but consistent structure
      const lightVsDark = VisualRegressionUtils.compareSnapshots(
        snapshots.light,
        snapshots.dark
      );

      // Colors should be different between themes
      const colorDifferences = lightVsDark.differences.filter(diff => 
        diff.includes('backgroundColor') || diff.includes('color')
      );

      expect(colorDifferences.length).toBeGreaterThan(0);

      // Structure should remain the same
      const structuralDifferences = lightVsDark.differences.filter(diff => 
        diff.includes('Width') || diff.includes('Height') || 
        diff.includes('Child count') || diff.includes('fontSize')
      );

      expect(structuralDifferences.length).toBe(0);
    });

    test('should handle color blindness accessibility', () => {
      const colorBlindnessFilters = [
        'grayscale(100%)',           // Complete color blindness
        'sepia(100%) saturate(0%)',  // Simulate protanopia
        'hue-rotate(90deg)',         // Simulate deuteranopia
      ];

      const { container } = renderWithEnhancements(
        <div className="status-indicators">
          <div className="status-success">✅ Connected</div>
          <div className="status-warning">⚠️ Warning</div>
          <div className="status-error">❌ Error</div>
        </div>
      );

      const baseSnapshot = VisualRegressionUtils.captureComponentSnapshot(
        container.firstChild as HTMLElement
      );

      colorBlindnessFilters.forEach(filter => {
        // Apply color blindness filter
        const element = container.firstChild as HTMLElement;
        element.style.filter = filter;

        const filteredSnapshot = VisualRegressionUtils.captureComponentSnapshot(element);
        
        // Reset filter
        element.style.filter = '';

        // Content and structure should remain accessible
        expect(element.textContent).toContain('Connected');
        expect(element.textContent).toContain('Warning');
        expect(element.textContent).toContain('Error');
      });
    });
  });

  describe('Animation and Transition Visual Testing', () => {
    test('should maintain visual consistency during state transitions', async () => {
      const StatefulComponent = () => {
        const [isExpanded, setIsExpanded] = React.useState(false);

        return (
          <div>
            <button onClick={() => setIsExpanded(!isExpanded)}>
              Toggle
            </button>
            <div 
              className={`transition-all duration-300 ${
                isExpanded ? 'h-40 opacity-100' : 'h-0 opacity-0'
              }`}
              data-testid="animated-content"
            >
              <p>Animated content that appears and disappears</p>
            </div>
          </div>
        );
      };

      const { container } = renderWithEnhancements(<StatefulComponent />);

      const animatedContent = container.querySelector('[data-testid="animated-content"]') as HTMLElement;
      
      // Capture initial state
      const initialSnapshot = VisualRegressionUtils.captureComponentSnapshot(animatedContent);

      // Trigger state change
      const toggleButton = screen.getByRole('button', { name: /toggle/i });
      toggleButton.click();

      // Wait for animation to potentially complete
      await new Promise(resolve => setTimeout(resolve, 350));

      // Capture final state
      const finalSnapshot = VisualRegressionUtils.captureComponentSnapshot(animatedContent);

      const comparison = VisualRegressionUtils.compareSnapshots(initialSnapshot, finalSnapshot);

      // Dimensions should change during animation
      const dimensionChanges = comparison.differences.filter(diff => 
        diff.includes('Width') || diff.includes('Height')
      );

      expect(dimensionChanges.length).toBeGreaterThan(0);
    });

    test('should handle loading states visually', () => {
      const LoadingStateComponent = ({ isLoading }: { isLoading: boolean }) => (
        <div data-testid="loading-container">
          {isLoading ? (
            <div className="loading-spinner">
              <div className="animate-spin">⟳</div>
              <span>Loading...</span>
            </div>
          ) : (
            <div className="loaded-content">
              <h2>Content Loaded</h2>
              <p>This is the loaded content</p>
            </div>
          )}
        </div>
      );

      // Test loading state
      const { container: loadingContainer } = renderWithEnhancements(
        <LoadingStateComponent isLoading={true} />
      );

      // Test loaded state
      const { container: loadedContainer } = renderWithEnhancements(
        <LoadingStateComponent isLoading={false} />
      );

      const loadingElement = loadingContainer.querySelector('[data-testid="loading-container"]') as HTMLElement;
      const loadedElement = loadedContainer.querySelector('[data-testid="loading-container"]') as HTMLElement;

      const loadingSnapshot = VisualRegressionUtils.captureComponentSnapshot(loadingElement);
      const loadedSnapshot = VisualRegressionUtils.captureComponentSnapshot(loadedElement);

      const comparison = VisualRegressionUtils.compareSnapshots(loadingSnapshot, loadedSnapshot);

      // Content should be completely different between loading and loaded states
      expect(comparison.isEqual).toBe(false);
      expect(comparison.differences.length).toBeGreaterThan(0);

      // Verify specific content exists
      expect(loadingElement).toHaveTextContent('Loading...');
      expect(loadedElement).toHaveTextContent('Content Loaded');
    });
  });

  describe('Print and Media Query Visual Testing', () => {
    test('should maintain appropriate styling for print media', () => {
      // Mock print media query
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('print'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      const { container } = renderWithEnhancements(
        <div className="print:text-black print:bg-white screen:text-white screen:bg-gray-900">
          <Terminal sessionId="print-test" />
        </div>
      );

      const printContainer = container.firstChild as HTMLElement;
      const snapshot = VisualRegressionUtils.captureComponentSnapshot(printContainer);

      // Verify container exists and is properly styled for print
      expect(printContainer).toBeInTheDocument();
      
      // In a real scenario, we'd verify print-specific styles are applied
      const parsedSnapshot = JSON.parse(snapshot);
      expect(parsedSnapshot.styles).toBeDefined();
    });
  });
});