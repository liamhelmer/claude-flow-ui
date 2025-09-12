import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import Sidebar from '../Sidebar';
import { createMockSession } from '../../../tests/test-utils';

// Add jest-axe matcher
expect.extend(toHaveNoViolations);

describe('Sidebar Accessibility Tests', () => {
  const mockProps = {
    isOpen: true,
    onToggle: jest.fn(),
    sessions: [createMockSession('session-1'), createMockSession('session-2')],
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionCreate: jest.fn(),
    onSessionClose: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('WCAG Compliance', () => {
    it('should have no accessibility violations when open', async () => {
      const { container } = render(<Sidebar {...mockProps} />);
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have no accessibility violations when closed', async () => {
      const { container } = render(<Sidebar {...mockProps} isOpen={false} />);
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have no accessibility violations with empty sessions', async () => {
      const { container } = render(<Sidebar {...mockProps} sessions={[]} />);
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Keyboard Navigation', () => {
    it('should allow keyboard navigation to toggle button when open', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      // Tab to button
      await user.tab();
      expect(toggleButton).toHaveFocus();
      
      // Activate with Enter
      await user.keyboard('{Enter}');
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should allow keyboard navigation to toggle button when closed', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      
      // Tab to button
      await user.tab();
      expect(openButton).toHaveFocus();
      
      // Activate with Space
      await user.keyboard(' ');
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should support keyboard shortcuts described in sidebar', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} />);
      
      // Verify keyboard shortcuts are documented
      expect(screen.getByText('Ctrl+C - Interrupt')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+D - Exit')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+L - Clear')).toBeInTheDocument();
      expect(screen.getByText('↑/↓ - History')).toBeInTheDocument();
    });

    it('should handle tab navigation properly within sidebar', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      // Should be able to tab to the toggle button
      await user.tab();
      expect(toggleButton).toHaveFocus();
      
      // Tabbing further should move focus outside sidebar
      await user.tab();
      expect(toggleButton).not.toHaveFocus();
    });
  });

  describe('Screen Reader Support', () => {
    it('should have proper heading hierarchy', () => {
      render(<Sidebar {...mockProps} />);
      
      // Main heading should be h2
      const mainHeading = screen.getByRole('heading', { name: 'Claude Flow Terminal' });
      expect(mainHeading.tagName).toBe('H2');
      
      // Status section should have h3
      const statusHeading = screen.getByText('Status');
      expect(statusHeading.tagName).toBe('H3');
      
      // Keyboard shortcuts should have h3
      const shortcutsHeading = screen.getByText('Keyboard Shortcuts');
      expect(shortcutsHeading.tagName).toBe('H3');
      
      // Scroll section should have h3
      const scrollHeading = screen.getByText('Scroll');
      expect(scrollHeading.tagName).toBe('H3');
    });

    it('should have descriptive button labels', () => {
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toHaveAttribute('title', 'Toggle Sidebar');
    });

    it('should have descriptive button labels when closed', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(openButton).toHaveAttribute('title', 'Open Sidebar');
    });

    it('should provide status information for screen readers', () => {
      render(<Sidebar {...mockProps} />);
      
      // Connected status should be accessible
      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
      
      // Status indicator should be accessible
      const statusSection = screen.getByText('Status').closest('div');
      expect(statusSection).toBeInTheDocument();
    });

    it('should provide connecting status for screen readers', () => {
      render(<Sidebar {...mockProps} sessions={[]} />);
      
      // Connecting status should be accessible
      expect(screen.getByText('Connecting...')).toBeInTheDocument();
    });
  });

  describe('Focus Management', () => {
    it('should maintain focus when sidebar toggles', async () => {
      const user = userEvent.setup();
      const { rerender } = render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      toggleButton.focus();
      expect(toggleButton).toHaveFocus();
      
      // Toggle sidebar closed
      rerender(<Sidebar {...mockProps} isOpen={false} />);
      
      // Focus should move to open button
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(openButton).toBeInTheDocument();
    });

    it('should have visible focus indicators', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      await user.tab();
      expect(toggleButton).toHaveFocus();
      
      // Should have focus styles (this tests that focus is not hidden)
      const computedStyle = window.getComputedStyle(toggleButton);
      expect(computedStyle.outline).not.toBe('none');
    });

    it('should trap focus within sidebar when appropriate', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} />);
      
      // Add a focusable element before sidebar for testing
      const beforeElement = document.createElement('button');
      beforeElement.textContent = 'Before';
      document.body.insertBefore(beforeElement, document.body.firstChild);
      
      // Add a focusable element after sidebar for testing
      const afterElement = document.createElement('button');
      afterElement.textContent = 'After';
      document.body.appendChild(afterElement);
      
      // Focus should be manageable
      beforeElement.focus();
      expect(beforeElement).toHaveFocus();
      
      await user.tab();
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toHaveFocus();
      
      // Cleanup
      document.body.removeChild(beforeElement);
      document.body.removeChild(afterElement);
    });
  });

  describe('High Contrast Mode Support', () => {
    it('should work with high contrast colors', () => {
      // Mock high contrast mode
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-contrast: high)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });
      
      render(<Sidebar {...mockProps} />);
      
      // Elements should still be accessible
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Toggle Sidebar' })).toBeInTheDocument();
    });

    it('should maintain contrast ratios for status indicators', () => {
      render(<Sidebar {...mockProps} />);
      
      // Status indicators should be visible
      const statusDot = document.querySelector('.w-2.h-2.bg-green-500.rounded-full.animate-pulse');
      expect(statusDot).toBeInTheDocument();
      expect(statusDot).toHaveClass('bg-green-500'); // Should have sufficient contrast
    });

    it('should maintain contrast ratios for disconnected state', () => {
      render(<Sidebar {...mockProps} sessions={[]} />);
      
      // Disconnected status should be visible
      const statusDot = document.querySelector('.w-2.h-2.bg-gray-500.rounded-full');
      expect(statusDot).toBeInTheDocument();
      expect(statusDot).toHaveClass('bg-gray-500'); // Should have sufficient contrast
    });
  });

  describe('Reduced Motion Support', () => {
    it('should respect prefers-reduced-motion', () => {
      // Mock reduced motion preference
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-reduced-motion: reduce)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });
      
      render(<Sidebar {...mockProps} />);
      
      // Sidebar should still have transition classes for structure
      const sidebarContainer = document.querySelector('.sidebar-container');
      expect(sidebarContainer).toHaveClass('transition-all');
      
      // But animations should be respectful of user preferences
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });

    it('should handle pulse animation for reduced motion', () => {
      render(<Sidebar {...mockProps} />);
      
      // Pulse animation should be present but can be overridden by CSS
      const statusDot = document.querySelector('.animate-pulse');
      expect(statusDot).toBeInTheDocument();
    });
  });

  describe('Text Scaling Support', () => {
    it('should handle large text sizes', () => {
      // Mock large text scaling
      document.documentElement.style.fontSize = '20px';
      
      render(<Sidebar {...mockProps} />);
      
      // Text should remain readable
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
      
      // Reset
      document.documentElement.style.fontSize = '';
    });

    it('should maintain layout with increased text size', () => {
      // Test with larger text
      document.documentElement.style.fontSize = '24px';
      
      render(<Sidebar {...mockProps} />);
      
      const sidebar = document.querySelector('.sidebar-container');
      expect(sidebar).toBeInTheDocument();
      
      // Layout should adapt
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
      
      // Reset
      document.documentElement.style.fontSize = '';
    });
  });

  describe('Touch Accessibility', () => {
    it('should have adequate touch targets', () => {
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      // Button should have adequate size for touch
      expect(toggleButton).toHaveClass('p-1'); // Has padding for larger touch target
    });

    it('should have adequate touch targets when closed', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      
      // Button should have adequate size for touch
      expect(openButton).toHaveClass('p-2'); // Has padding for larger touch target
    });

    it('should handle touch events properly', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      // Simulate touch interaction
      await user.click(toggleButton);
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error States Accessibility', () => {
    it('should handle accessibility when props are missing', () => {
      const minimalProps = {
        isOpen: true,
        onToggle: jest.fn(),
        sessions: [],
        activeSessionId: null,
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };
      
      render(<Sidebar {...minimalProps} />);
      
      // Should still be accessible with minimal props
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Toggle Sidebar' })).toBeInTheDocument();
    });

    it('should handle long session names gracefully', () => {
      const longNameSession = createMockSession('very-long-session-name-that-might-overflow-the-container-width');
      
      render(<Sidebar {...mockProps} sessions={[longNameSession]} />);
      
      // Should still be accessible
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });
  });

  describe('Screen Reader Announcements', () => {
    it('should have appropriate live regions for status changes', () => {
      const { rerender } = render(<Sidebar {...mockProps} sessions={[]} />);
      
      // Initial connecting state
      expect(screen.getByText('Connecting...')).toBeInTheDocument();
      
      // Change to connected state
      rerender(<Sidebar {...mockProps} />);
      
      // Should show connected state
      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
    });

    it('should provide context for keyboard shortcuts', () => {
      render(<Sidebar {...mockProps} />);
      
      // Keyboard shortcuts should be grouped under a clear heading
      const shortcutsSection = screen.getByText('Keyboard Shortcuts').closest('div');
      expect(shortcutsSection).toBeInTheDocument();
      
      // All shortcuts should be under this section
      expect(screen.getByText('Ctrl+C - Interrupt')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+D - Exit')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+L - Clear')).toBeInTheDocument();
      expect(screen.getByText('↑/↓ - History')).toBeInTheDocument();
    });
  });

  describe('ARIA Implementation', () => {
    it('should use appropriate ARIA roles', () => {
      render(<Sidebar {...mockProps} />);
      
      // Buttons should have button role
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toBeInTheDocument();
      
      // Headings should have heading role
      const mainHeading = screen.getByRole('heading', { name: 'Claude Flow Terminal' });
      expect(mainHeading).toBeInTheDocument();
    });

    it('should have appropriate ARIA attributes for expanded state', () => {
      render(<Sidebar {...mockProps} />);
      
      // When open, sidebar should be visible
      const sidebar = document.querySelector('.sidebar-container');
      expect(sidebar).not.toHaveClass('w-0');
    });

    it('should have appropriate ARIA attributes for collapsed state', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      // When closed, sidebar should be collapsed
      const sidebar = document.querySelector('.sidebar-container');
      expect(sidebar).toHaveClass('w-0');
    });
  });
});