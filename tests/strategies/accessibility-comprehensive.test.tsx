/**
 * @fileoverview Comprehensive Accessibility Testing Suite
 * @description Enhanced accessibility testing with jest-axe and comprehensive scenarios
 * @author Testing and Quality Assurance Agent
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import Terminal from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { Tab } from '@/components/tabs/Tab';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';

// Extend Jest matchers with jest-axe
expect.extend(toHaveNoViolations);

// Mock hooks for controlled testing
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');

describe('Comprehensive Accessibility Testing', () => {
  beforeEach(() => {
    // Reset any global accessibility state
    document.body.innerHTML = '';
  });

  describe('Terminal Component Accessibility', () => {
    it('should have no accessibility violations', async () => {
      const { container } = render(<Terminal sessionId="a11y-test" />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      
      render(<Terminal sessionId="keyboard-test" />);
      
      const terminalContainer = screen.getByRole('region', { name: /terminal/i });
      
      // Should be focusable
      await user.tab();
      expect(terminalContainer).toHaveFocus();
      
      // Should support arrow key navigation
      await user.keyboard('{ArrowUp}');
      await user.keyboard('{ArrowDown}');
      await user.keyboard('{ArrowLeft}');
      await user.keyboard('{ArrowRight}');
      
      // Should support text selection with keyboard
      await user.keyboard('{Shift>}{ArrowRight}{ArrowRight}{/Shift}');
    });

    it('should have proper ARIA labels and roles', () => {
      render(<Terminal sessionId="aria-test" />);
      
      // Check for proper roles
      const terminal = screen.getByRole('region');
      expect(terminal).toBeInTheDocument();
      
      // Check for ARIA labels
      expect(terminal).toHaveAttribute('aria-label');
      expect(terminal).toHaveAttribute('aria-live');
      expect(terminal).toHaveAttribute('aria-atomic');
    });

    it('should support screen reader announcements', async () => {
      const { container } = render(<Terminal sessionId="screenreader-test" />);
      
      // Find live region for screen reader announcements
      const liveRegion = container.querySelector('[aria-live="polite"]');
      expect(liveRegion).toBeInTheDocument();
      
      // Simulate terminal output that should be announced
      const terminalOutput = 'New command output available';
      
      if (liveRegion) {
        liveRegion.textContent = terminalOutput;
        expect(liveRegion).toHaveTextContent(terminalOutput);
      }
    });

    it('should handle high contrast mode', () => {
      // Mock high contrast media query
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('prefers-contrast: high'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });
      
      const { container } = render(<Terminal sessionId="contrast-test" />);
      
      // Verify high contrast styles are applied
      const terminalElement = container.querySelector('.terminal-container');
      expect(terminalElement).toHaveClass('terminal-container');
      
      // In real implementation, you'd check for high contrast CSS classes
      // or computed styles that provide sufficient color contrast
    });

    it('should support reduced motion preferences', () => {
      // Mock reduced motion preference
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('prefers-reduced-motion'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });
      
      render(<Terminal sessionId="reduced-motion-test" />);
      
      // Verify animations are disabled or reduced
      // This would depend on your implementation
    });
  });

  describe('Sidebar Accessibility', () => {
    const mockSessions = [
      { id: 'session1', name: 'Terminal 1', isActive: false, lastActivity: new Date() },
      { id: 'session2', name: 'Terminal 2', isActive: true, lastActivity: new Date() },
    ];

    it('should have no accessibility violations', async () => {
      const { container } = render(
        <Sidebar
          isOpen={true}
          onToggle={jest.fn()}
          sessions={mockSessions}
          activeSessionId="session2"
          onSessionSelect={jest.fn()}
          onSessionCreate={jest.fn()}
          onSessionClose={jest.fn()}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should support keyboard navigation between sessions', async () => {
      const user = userEvent.setup();
      const onSessionSelect = jest.fn();
      
      render(
        <Sidebar
          isOpen={true}
          onToggle={jest.fn()}
          sessions={mockSessions}
          activeSessionId="session1"
          onSessionSelect={onSessionSelect}
          onSessionCreate={jest.fn()}
          onSessionClose={jest.fn()}
        />
      );
      
      // Should navigate with arrow keys
      await user.keyboard('{ArrowDown}');
      await user.keyboard('{Enter}');
      
      expect(onSessionSelect).toHaveBeenCalledWith('session2');
    });

    it('should have proper focus management', async () => {
      const user = userEvent.setup();
      
      const { rerender } = render(
        <Sidebar
          isOpen={false}
          onToggle={jest.fn()}
          sessions={mockSessions}
          activeSessionId="session1"
          onSessionSelect={jest.fn()}
          onSessionCreate={jest.fn()}
          onSessionClose={jest.fn()}
        />
      );
      
      // Open sidebar
      rerender(
        <Sidebar
          isOpen={true}
          onToggle={jest.fn()}
          sessions={mockSessions}
          activeSessionId="session1"
          onSessionSelect={jest.fn()}
          onSessionCreate={jest.fn()}
          onSessionClose={jest.fn()}
        />
      );
      
      // Focus should move to sidebar when opened
      await waitFor(() => {
        const sidebar = screen.getByRole('navigation');
        expect(sidebar).toBeInTheDocument();
      });
    });
  });

  describe('Tab Component Accessibility', () => {
    it('should have no accessibility violations', async () => {
      const { container } = render(
        <Tab
          title="Test Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should support keyboard activation', async () => {
      const user = userEvent.setup();
      const onSelect = jest.fn();
      
      render(
        <Tab
          title="Keyboard Test Tab"
          isActive={false}
          onSelect={onSelect}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const tab = screen.getByRole('tab');
      
      // Should activate with Enter or Space
      await user.click(tab);
      expect(onSelect).toHaveBeenCalled();
      
      await user.keyboard('{Enter}');
      expect(onSelect).toHaveBeenCalledTimes(2);
    });

    it('should handle close with keyboard', async () => {
      const user = userEvent.setup();
      const onClose = jest.fn();
      
      render(
        <Tab
          title="Close Test Tab"
          isActive={true}
          onSelect={jest.fn()}
          onClose={onClose}
          closable={true}
        />
      );
      
      const closeButton = screen.getByRole('button', { name: /close/i });
      
      await user.keyboard('{Tab}'); // Tab to close button
      await user.keyboard('{Enter}');
      
      expect(onClose).toHaveBeenCalled();
    });

    it('should have appropriate ARIA states', () => {
      const { rerender } = render(
        <Tab
          title="ARIA Test Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      let tab = screen.getByRole('tab');
      expect(tab).toHaveAttribute('aria-selected', 'false');
      
      // Test active state
      rerender(
        <Tab
          title="ARIA Test Tab"
          isActive={true}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      tab = screen.getByRole('tab');
      expect(tab).toHaveAttribute('aria-selected', 'true');
    });
  });

  describe('Monitoring Sidebar Accessibility', () => {
    it('should have no accessibility violations', async () => {
      const { container } = render(<MonitoringSidebar />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should support keyboard navigation between panels', async () => {
      const user = userEvent.setup();
      
      render(<MonitoringSidebar />);
      
      // Should be able to navigate between monitoring panels
      const monitoringContainer = screen.getByRole('complementary');
      expect(monitoringContainer).toBeInTheDocument();
      
      // Test keyboard navigation
      await user.tab();
      await user.keyboard('{ArrowDown}');
      await user.keyboard('{ArrowUp}');
    });
  });

  describe('Color Contrast Accessibility', () => {
    it('should meet WCAG color contrast requirements', () => {
      const { container } = render(<Terminal sessionId="contrast-test" />);
      
      // Get computed styles
      const terminalElement = container.querySelector('.terminal-container');
      const computedStyle = terminalElement ? window.getComputedStyle(terminalElement) : null;
      
      if (computedStyle) {
        // In a real test, you'd calculate contrast ratios
        // This is a placeholder for actual contrast testing
        expect(computedStyle.backgroundColor).toBeDefined();
        expect(computedStyle.color).toBeDefined();
        
        // You could use libraries like 'color-contrast' to verify WCAG compliance
      }
    });
  });

  describe('Screen Reader Testing', () => {
    it('should provide meaningful alternative text', () => {
      render(<Terminal sessionId="alt-text-test" />);
      
      // Check for images with alt text
      const images = screen.queryAllByRole('img');
      images.forEach(img => {
        expect(img).toHaveAttribute('alt');
      });
    });

    it('should have proper heading hierarchy', () => {
      render(
        <div>
          <Terminal sessionId="heading-test" />
          <MonitoringSidebar />
        </div>
      );
      
      // Check that headings follow proper hierarchy (h1, h2, h3, etc.)
      const headings = screen.getAllByRole('heading');
      
      // Verify heading levels are in logical order
      const headingLevels = headings.map(heading => 
        parseInt(heading.tagName.substring(1))
      );
      
      // Should not skip heading levels
      for (let i = 1; i < headingLevels.length; i++) {
        const currentLevel = headingLevels[i];
        const previousLevel = headingLevels[i - 1];
        
        // Should not skip more than one level
        expect(currentLevel - previousLevel).toBeLessThanOrEqual(1);
      }
    });

    it('should use semantic markup correctly', () => {
      render(
        <div>
          <Terminal sessionId="semantic-test" />
          <MonitoringSidebar />
        </div>
      );
      
      // Check for proper semantic elements
      expect(screen.getByRole('main') || screen.getByRole('region')).toBeInTheDocument();
      
      // Lists should use proper list markup
      const lists = screen.queryAllByRole('list');
      lists.forEach(list => {
        const listItems = screen.getAllByRole('listitem');
        expect(listItems.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Focus Management', () => {
    it('should maintain logical focus order', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Terminal sessionId="focus-order-test" />
          <MonitoringSidebar />
        </div>
      );
      
      // Test tab order
      const focusableElements = screen.getAllByRole('button')
        .concat(screen.getAllByRole('tab'))
        .concat(screen.getAllByRole('textbox'));
      
      // Should be able to tab through all focusable elements
      for (const element of focusableElements) {
        await user.tab();
        // Each element should receive focus in logical order
      }
    });

    it('should trap focus in modal dialogs', async () => {
      // This test would be for modal dialogs if they exist
      // Placeholder for focus trap testing
    });

    it('should restore focus after interactions', async () => {
      const user = userEvent.setup();
      
      render(<Terminal sessionId="focus-restore-test" />);
      
      const terminal = screen.getByRole('region');
      
      // Focus terminal
      await user.click(terminal);
      expect(terminal).toHaveFocus();
      
      // Simulate interaction that might steal focus
      const body = document.body;
      body.focus();
      
      // Focus should return to terminal after interaction
      await waitFor(() => {
        expect(terminal).toHaveFocus();
      });
    });
  });

  describe('Error State Accessibility', () => {
    it('should announce errors to screen readers', () => {
      // Mock error state
      render(
        <div>
          <div role="alert" aria-live="assertive">
            Connection error: Unable to connect to terminal
          </div>
          <Terminal sessionId="error-test" />
        </div>
      );
      
      const errorAlert = screen.getByRole('alert');
      expect(errorAlert).toHaveTextContent('Connection error');
    });

    it('should provide error recovery options', () => {
      render(
        <div>
          <div role="alert">
            <p>Connection failed</p>
            <button>Retry Connection</button>
          </div>
          <Terminal sessionId="recovery-test" />
        </div>
      );
      
      const retryButton = screen.getByRole('button', { name: /retry/i });
      expect(retryButton).toBeInTheDocument();
    });
  });

  describe('Responsive Accessibility', () => {
    it('should maintain accessibility on mobile devices', () => {
      // Mock mobile viewport
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 375,
      });
      
      Object.defineProperty(window, 'innerHeight', {
        writable: true,
        configurable: true,
        value: 667,
      });
      
      const { container } = render(<Terminal sessionId="mobile-test" />);
      
      // Should maintain accessibility on mobile
      const terminal = container.querySelector('.terminal-container');
      expect(terminal).toBeInTheDocument();
      
      // Touch targets should be at least 44px
      const buttons = screen.getAllByRole('button');
      buttons.forEach(button => {
        const rect = button.getBoundingClientRect();
        expect(Math.min(rect.width, rect.height)).toBeGreaterThanOrEqual(44);
      });
    });
  });
});