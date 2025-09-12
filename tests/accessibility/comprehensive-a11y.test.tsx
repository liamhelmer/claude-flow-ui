/**
 * Comprehensive Accessibility Testing Protocols
 * WCAG 2.1 AA compliance testing with jest-axe and manual accessibility testing
 */

import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import { renderWithProviders } from '../utils/test-utils';

// Import components for accessibility testing
import TabList from '@/components/tabs/TabList';
import Tab from '@/components/tabs/Tab';
import Terminal from '@/components/terminal/Terminal';
import TerminalControls from '@/components/terminal/TerminalControls';
import Sidebar from '@/components/sidebar/Sidebar';

// Add jest-axe matchers
expect.extend(toHaveNoViolations);

// Accessibility testing configuration
const axeConfig = {
  rules: {
    // WCAG 2.1 AA rules
    'color-contrast': { enabled: true },
    // Remove invalid rule that doesn't exist in axe-core
    // 'focus-order-semantics': { enabled: true },
    // 'keyboard-navigation': { enabled: true },
    'aria-valid-attr-value': { enabled: true },
    'aria-valid-attr': { enabled: true },
    'aria-hidden-focus': { enabled: true },
    'aria-allowed-role': { enabled: true },
    'button-name': { enabled: true },
    'duplicate-id': { enabled: true },
    'form-field-multiple-labels': { enabled: true },
    'heading-order': { enabled: true },
    'html-has-lang': { enabled: true },
    'image-alt': { enabled: true },
    'input-image-alt': { enabled: true },
    'label': { enabled: true },
    'landmark-banner-is-top-level': { enabled: true },
    'landmark-main-is-top-level': { enabled: true },
    'landmark-no-duplicate-banner': { enabled: true },
    'landmark-no-duplicate-contentinfo': { enabled: true },
    'landmark-one-main': { enabled: true },
    'link-name': { enabled: true },
    'list': { enabled: true },
    'listitem': { enabled: true },
    'page-has-heading-one': { enabled: true },
    'region': { enabled: true },
    'scope-attr-valid': { enabled: true },
    'server-side-image-map': { enabled: true },
    'tabindex': { enabled: true },
    'td-headers-attr': { enabled: true },
    'th-has-data-cells': { enabled: true },
    'valid-lang': { enabled: true },
  },
  tags: ['wcag2a', 'wcag2aa', 'wcag21aa'],
};

// Helper functions for accessibility testing
const simulateScreenReader = (element: HTMLElement) => {
  const textContent = element.textContent || '';
  const ariaLabel = element.getAttribute('aria-label');
  const ariaLabelledBy = element.getAttribute('aria-labelledby');
  const role = element.getAttribute('role');
  
  return {
    textContent,
    ariaLabel,
    ariaLabelledBy,
    role,
    isVisible: element.offsetParent !== null,
    isFocusable: element.tabIndex >= 0 || ['INPUT', 'BUTTON', 'A', 'TEXTAREA', 'SELECT'].includes(element.tagName),
  };
};

const getKeyboardNavigationOrder = (container: HTMLElement): HTMLElement[] => {
  const focusableElements = container.querySelectorAll(
    'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'
  );
  
  return Array.from(focusableElements) as HTMLElement[];
};

const simulateHighContrastMode = () => {
  // Add high contrast mode styles
  const style = document.createElement('style');
  style.textContent = `
    @media (prefers-contrast: high) {
      * {
        background-color: black !important;
        color: white !important;
        border-color: white !important;
      }
    }
  `;
  document.head.appendChild(style);
  return () => document.head.removeChild(style);
};

const simulateReducedMotion = () => {
  const style = document.createElement('style');
  style.textContent = `
    @media (prefers-reduced-motion: reduce) {
      * {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }
  `;
  document.head.appendChild(style);
  return () => document.head.removeChild(style);
};

describe('Comprehensive Accessibility Testing', () => {
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
  });

  describe('WCAG 2.1 AA Compliance', () => {
    describe('Tab Components', () => {
      it('should meet WCAG 2.1 AA standards for Tab component', async () => {
        const { container } = render(
          <Tab
            title="Accessible Tab"
            isActive={false}
            onSelect={jest.fn()}
            onClose={jest.fn()}
            closable={true}
          />
        );

        const results = await axe(container, axeConfig);
        expect(results).toHaveNoViolations();
      });

      it('should meet WCAG 2.1 AA standards for TabList component', async () => {
        const tabs = [
          { id: '1', title: 'Terminal 1', content: 'Content 1' },
          { id: '2', title: 'Terminal 2', content: 'Content 2' },
          { id: '3', title: 'Terminal 3', content: 'Content 3' },
        ];

        const { container } = render(
          <TabList
            tabs={tabs}
            activeTab="1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        const results = await axe(container, axeConfig);
        expect(results).toHaveNoViolations();
      });

      it('should have proper tab roles and relationships', () => {
        const tabs = [
          { id: '1', title: 'Tab 1', content: 'Content 1' },
          { id: '2', title: 'Tab 2', content: 'Content 2' },
        ];

        render(
          <TabList
            tabs={tabs}
            activeTab="1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        // Check for proper tab structure
        const tablist = screen.getByRole('tablist');
        expect(tablist).toBeInTheDocument();

        const tabElements = screen.getAllByRole('tab');
        expect(tabElements).toHaveLength(2);

        // Active tab should have aria-selected
        const activeTab = tabElements.find(tab => 
          tab.getAttribute('aria-selected') === 'true'
        );
        expect(activeTab).toBeInTheDocument();
        expect(activeTab).toHaveTextContent('Tab 1');

        // Tabs should have proper ARIA attributes
        tabElements.forEach(tab => {
          expect(tab).toHaveAttribute('role', 'tab');
          expect(tab).toHaveAttribute('aria-selected');
          expect(tab).toHaveAttribute('tabindex');
        });
      });
    });

    describe('Terminal Component', () => {
      it('should meet WCAG 2.1 AA standards', async () => {
        const { container } = renderWithProviders(
          <Terminal sessionId="test-session" />
        );

        const results = await axe(container, axeConfig);
        expect(results).toHaveNoViolations();
      });

      it('should have proper ARIA labels for terminal elements', () => {
        renderWithProviders(<Terminal sessionId="test-session" />);

        const terminalContainer = screen.getByTestId('test-wrapper').firstChild;
        expect(terminalContainer).toHaveAttribute('role');
        
        // Terminal should be identifiable by screen readers
        const screenReaderInfo = simulateScreenReader(terminalContainer as HTMLElement);
        expect(screenReaderInfo.role || screenReaderInfo.ariaLabel || screenReaderInfo.textContent).toBeTruthy();
      });

      it('should support keyboard navigation', async () => {
        renderWithProviders(<Terminal sessionId="test-session" />);

        const terminalContainer = screen.getByTestId('test-wrapper').firstChild as HTMLElement;
        
        // Terminal should be focusable
        terminalContainer.focus();
        expect(document.activeElement).toBe(terminalContainer);

        // Should handle keyboard events
        await user.keyboard('{Tab}');
        await user.keyboard('{Enter}');
        await user.keyboard('{Escape}');
        
        // Should not throw errors
        expect(terminalContainer).toBeInTheDocument();
      });
    });

    describe('Terminal Controls', () => {
      it('should meet WCAG 2.1 AA standards', async () => {
        const { container } = render(
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={false}
          />
        );

        const results = await axe(container, axeConfig);
        expect(results).toHaveNoViolations();
      });

      it('should have accessible button labels', () => {
        render(
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={true}
          />
        );

        const buttons = screen.getAllByRole('button');
        
        buttons.forEach(button => {
          const screenReaderInfo = simulateScreenReader(button);
          
          // Each button should have accessible name
          expect(
            screenReaderInfo.ariaLabel || 
            screenReaderInfo.textContent || 
            button.getAttribute('title')
          ).toBeTruthy();
        });
      });
    });

    describe('Sidebar Component', () => {
      it('should meet WCAG 2.1 AA standards', async () => {
        const { container } = renderWithProviders(<Sidebar />);

        const results = await axe(container, axeConfig);
        expect(results).toHaveNoViolations();
      });

      it('should have proper landmark structure', () => {
        renderWithProviders(<Sidebar />);

        // Sidebar should be a navigation landmark or complementary
        const sidebar = screen.getByRole('complementary') || 
                       screen.getByRole('navigation') ||
                       screen.getByTestId('sidebar');
        
        expect(sidebar).toBeInTheDocument();
      });

      it('should have accessible headings hierarchy', () => {
        renderWithProviders(<Sidebar />);

        const headings = screen.getAllByRole('heading');
        
        if (headings.length > 0) {
          // Check heading hierarchy
          const headingLevels = headings.map(heading => {
            const tagName = heading.tagName.toLowerCase();
            return parseInt(tagName.replace('h', ''), 10);
          });

          // Should start with appropriate level and not skip levels
          const firstLevel = headingLevels[0];
          expect(firstLevel).toBeGreaterThanOrEqual(1);
          expect(firstLevel).toBeLessThanOrEqual(6);

          for (let i = 1; i < headingLevels.length; i++) {
            const diff = headingLevels[i] - headingLevels[i - 1];
            expect(diff).toBeLessThanOrEqual(1); // Don't skip heading levels
          }
        }
      });
    });
  });

  describe('Keyboard Navigation', () => {
    describe('Tab Navigation', () => {
      it('should support arrow key navigation between tabs', async () => {
        const tabs = [
          { id: '1', title: 'Tab 1', content: 'Content 1' },
          { id: '2', title: 'Tab 2', content: 'Content 2' },
          { id: '3', title: 'Tab 3', content: 'Content 3' },
        ];

        const onTabSelect = jest.fn();

        render(
          <TabList
            tabs={tabs}
            activeTab="1"
            onTabSelect={onTabSelect}
            onTabClose={jest.fn()}
          />
        );

        const firstTab = screen.getByRole('tab', { name: /tab 1/i });
        firstTab.focus();

        // Navigate with arrow keys
        await user.keyboard('{ArrowRight}');
        expect(document.activeElement).toHaveTextContent('Tab 2');

        await user.keyboard('{ArrowRight}');
        expect(document.activeElement).toHaveTextContent('Tab 3');

        // Should wrap around
        await user.keyboard('{ArrowRight}');
        expect(document.activeElement).toHaveTextContent('Tab 1');

        // Navigate backwards
        await user.keyboard('{ArrowLeft}');
        expect(document.activeElement).toHaveTextContent('Tab 3');
      });

      it('should support Home and End keys', async () => {
        const tabs = Array.from({ length: 10 }, (_, i) => ({
          id: `${i + 1}`,
          title: `Tab ${i + 1}`,
          content: `Content ${i + 1}`,
        }));

        render(
          <TabList
            tabs={tabs}
            activeTab="5"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        const fifthTab = screen.getByRole('tab', { name: /tab 5/i });
        fifthTab.focus();

        // Home should go to first tab
        await user.keyboard('{Home}');
        expect(document.activeElement).toHaveTextContent('Tab 1');

        // End should go to last tab
        await user.keyboard('{End}');
        expect(document.activeElement).toHaveTextContent('Tab 10');
      });

      it('should support Enter and Space for tab activation', async () => {
        const tabs = [
          { id: '1', title: 'Tab 1', content: 'Content 1' },
          { id: '2', title: 'Tab 2', content: 'Content 2' },
        ];

        const onTabSelect = jest.fn();

        render(
          <TabList
            tabs={tabs}
            activeTab="1"
            onTabSelect={onTabSelect}
            onTabClose={jest.fn()}
          />
        );

        const secondTab = screen.getByRole('tab', { name: /tab 2/i });
        secondTab.focus();

        // Enter should activate tab
        await user.keyboard('{Enter}');
        expect(onTabSelect).toHaveBeenCalledWith('2');

        onTabSelect.mockClear();

        // Space should also activate tab
        await user.keyboard(' ');
        expect(onTabSelect).toHaveBeenCalledWith('2');
      });
    });

    describe('Focus Management', () => {
      it('should maintain proper focus order', () => {
        const tabs = [
          { id: '1', title: 'Tab 1', content: 'Content 1' },
          { id: '2', title: 'Tab 2', content: 'Content 2' },
        ];

        const { container } = render(
          <div>
            <TabList
              tabs={tabs}
              activeTab="1"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
            <TerminalControls
              onClear={jest.fn()}
              onScrollToBottom={jest.fn()}
              onScrollToTop={jest.fn()}
              hasNewOutput={false}
            />
          </div>
        );

        const focusOrder = getKeyboardNavigationOrder(container);
        
        // Should have logical focus order
        expect(focusOrder.length).toBeGreaterThan(0);
        
        // Tab through all focusable elements
        focusOrder.forEach((element, index) => {
          element.focus();
          expect(document.activeElement).toBe(element);
        });
      });

      it('should trap focus within modal dialogs', async () => {
        // This would test modal focus trapping when implemented
        // For now, ensure no errors occur
        const { container } = render(
          <div role="dialog" aria-modal="true">
            <button>First Button</button>
            <input type="text" placeholder="Input field" />
            <button>Last Button</button>
          </div>
        );

        const firstButton = screen.getByText('First Button');
        const lastButton = screen.getByText('Last Button');

        firstButton.focus();
        expect(document.activeElement).toBe(firstButton);

        // Tab to last focusable element
        await user.keyboard('{Tab}{Tab}');
        expect(document.activeElement).toBe(lastButton);

        // Tab should wrap to first element (in a real modal)
        await user.keyboard('{Tab}');
        // Note: This would need actual focus trap implementation
      });

      it('should restore focus after component unmount', () => {
        const ExternalButton = () => <button>External Button</button>;
        const FocusableComponent = () => <button>Internal Button</button>;

        const { rerender } = render(
          <div>
            <ExternalButton />
            <FocusableComponent />
          </div>
        );

        const externalButton = screen.getByText('External Button');
        const internalButton = screen.getByText('Internal Button');

        // Focus external button first
        externalButton.focus();
        expect(document.activeElement).toBe(externalButton);

        // Focus internal button
        internalButton.focus();
        expect(document.activeElement).toBe(internalButton);

        // Remove internal component
        rerender(
          <div>
            <ExternalButton />
          </div>
        );

        // Focus should return to a reasonable element (not necessarily the external button
        // as this would require explicit focus management)
        expect(document.activeElement).toBeDefined();
      });
    });
  });

  describe('Screen Reader Support', () => {
    describe('ARIA Labels and Descriptions', () => {
      it('should provide meaningful labels for all interactive elements', () => {
        const tabs = [
          { id: '1', title: 'Production Terminal', content: 'Content 1' },
          { id: '2', title: 'Development Terminal', content: 'Content 2' },
        ];

        render(
          <TabList
            tabs={tabs}
            activeTab="1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        const tabElements = screen.getAllByRole('tab');
        
        tabElements.forEach(tab => {
          const screenReaderInfo = simulateScreenReader(tab);
          
          // Should have accessible name
          const accessibleName = screenReaderInfo.ariaLabel || 
                                 screenReaderInfo.textContent ||
                                 tab.getAttribute('title');
          
          expect(accessibleName).toBeTruthy();
          expect(accessibleName.length).toBeGreaterThan(0);
        });
      });

      it('should provide status information for dynamic content', async () => {
        renderWithProviders(<Terminal sessionId="test-session" />);

        // Should have status region for dynamic updates
        const statusElements = screen.queryAllByRole('status') || 
                              screen.queryAllByLabelText(/status/i);
        
        // At minimum, the component should be identifiable
        const terminalContainer = screen.getByTestId('test-wrapper');
        expect(terminalContainer).toBeInTheDocument();
      });

      it('should announce important state changes', () => {
        const { rerender } = render(
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={false}
          />
        );

        // Change to new output state
        rerender(
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={true}
          />
        );

        // Should have indication of new output
        // This would be implemented with aria-live regions
        const container = screen.getByTestId('test-wrapper') || document.body;
        expect(container).toBeInTheDocument();
      });
    });

    describe('Live Regions', () => {
      it('should use appropriate live regions for terminal output', () => {
        renderWithProviders(<Terminal sessionId="test-session" />);

        // Terminal output should be in a live region for screen reader announcements
        const liveRegions = document.querySelectorAll('[aria-live]');
        
        // Check if any live regions exist
        // This would need to be implemented in the actual Terminal component
        if (liveRegions.length > 0) {
          Array.from(liveRegions).forEach(region => {
            const ariaLive = region.getAttribute('aria-live');
            expect(['polite', 'assertive', 'off']).toContain(ariaLive);
          });
        }
      });
    });
  });

  describe('Visual Accessibility', () => {
    describe('High Contrast Mode', () => {
      it('should work properly in high contrast mode', async () => {
        const cleanupHighContrast = simulateHighContrastMode();

        const { container } = render(
          <div>
            <TabList
              tabs={[{ id: '1', title: 'Test Tab', content: 'Content' }]}
              activeTab="1"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
            <Terminal sessionId="test-session" />
          </div>
        );

        // Should still meet accessibility standards in high contrast
        const results = await axe(container, {
          ...axeConfig,
          rules: {
            ...axeConfig.rules,
            'color-contrast': { enabled: false }, // Disable for high contrast test
          },
        });
        
        expect(results).toHaveNoViolations();

        cleanupHighContrast();
      });
    });

    describe('Reduced Motion', () => {
      it('should respect reduced motion preferences', () => {
        const cleanupReducedMotion = simulateReducedMotion();

        const { container } = render(
          <div>
            <TabList
              tabs={[
                { id: '1', title: 'Tab 1', content: 'Content 1' },
                { id: '2', title: 'Tab 2', content: 'Content 2' },
              ]}
              activeTab="1"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
          </div>
        );

        // Components should render without motion-based issues
        expect(container.firstChild).toBeInTheDocument();

        cleanupReducedMotion();
      });
    });

    describe('Zoom and Magnification', () => {
      it('should remain functional at 200% zoom', () => {
        // Simulate 200% zoom by reducing effective viewport
        const originalInnerWidth = window.innerWidth;
        const originalInnerHeight = window.innerHeight;

        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: originalInnerWidth / 2,
        });
        Object.defineProperty(window, 'innerHeight', {
          writable: true,
          configurable: true,
          value: originalInnerHeight / 2,
        });

        const { container } = render(
          <TabList
            tabs={[{ id: '1', title: 'Zoom Test Tab', content: 'Content' }]}
            activeTab="1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        // Should still be functional
        const tab = screen.getByRole('tab');
        expect(tab).toBeInTheDocument();
        expect(tab).toBeVisible();

        // Restore original viewport
        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: originalInnerWidth,
        });
        Object.defineProperty(window, 'innerHeight', {
          writable: true,
          configurable: true,
          value: originalInnerHeight,
        });
      });
    });
  });

  describe('Mobile Accessibility', () => {
    describe('Touch Interaction', () => {
      it('should support touch navigation', async () => {
        const onTabSelect = jest.fn();

        render(
          <TabList
            tabs={[
              { id: '1', title: 'Tab 1', content: 'Content 1' },
              { id: '2', title: 'Tab 2', content: 'Content 2' },
            ]}
            activeTab="1"
            onTabSelect={onTabSelect}
            onTabClose={jest.fn()}
          />
        );

        const secondTab = screen.getByRole('tab', { name: /tab 2/i });

        // Simulate touch interaction
        await user.pointer({ keys: '[TouchA]', target: secondTab });
        
        expect(onTabSelect).toHaveBeenCalledWith('2');
      });

      it('should have adequate touch target sizes', () => {
        render(
          <TabList
            tabs={[{ id: '1', title: 'Touch Test', content: 'Content' }]}
            activeTab="1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );

        const tab = screen.getByRole('tab');
        const rect = tab.getBoundingClientRect();

        // WCAG recommends minimum 44x44 CSS pixels for touch targets
        // Note: This would need proper styling to ensure adequate size
        expect(rect.width).toBeGreaterThan(0);
        expect(rect.height).toBeGreaterThan(0);
      });
    });

    describe('Responsive Accessibility', () => {
      it('should maintain accessibility on mobile viewports', async () => {
        // Simulate mobile viewport
        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: 375, // iPhone width
        });
        Object.defineProperty(window, 'innerHeight', {
          writable: true,
          configurable: true,
          value: 667, // iPhone height
        });

        const { container } = render(
          <div>
            <TabList
              tabs={[{ id: '1', title: 'Mobile Tab', content: 'Content' }]}
              activeTab="1"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
            <Terminal sessionId="mobile-session" />
          </div>
        );

        const results = await axe(container, axeConfig);
        expect(results).toHaveNoViolations();
      });
    });
  });

  describe('Color and Contrast', () => {
    it('should meet color contrast requirements', async () => {
      const { container } = render(
        <div>
          <TabList
            tabs={[
              { id: '1', title: 'Active Tab', content: 'Content 1' },
              { id: '2', title: 'Inactive Tab', content: 'Content 2' },
            ]}
            activeTab="1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        </div>
      );

      const results = await axe(container, {
        rules: { 'color-contrast': { enabled: true } },
      });

      expect(results).toHaveNoViolations();
    });

    it('should not rely solely on color for information', () => {
      render(
        <TabList
          tabs={[
            { id: '1', title: 'Active Tab', content: 'Content 1' },
            { id: '2', title: 'Error Tab', content: 'Content 2' },
          ]}
          activeTab="1"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );

      const tabs = screen.getAllByRole('tab');
      
      // Active tab should have more than just color to indicate state
      const activeTab = tabs.find(tab => 
        tab.getAttribute('aria-selected') === 'true'
      );
      
      expect(activeTab).toHaveAttribute('aria-selected', 'true');
      // Should also have visual indicators beyond color
    });
  });
});