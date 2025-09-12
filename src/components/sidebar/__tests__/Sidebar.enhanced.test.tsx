import React from 'react';
import { render, screen, fireEvent, waitFor } from '@/tests/test-utils';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import Sidebar from '../Sidebar';
import type { TerminalSession } from '@/types';

expect.extend(toHaveNoViolations);

describe('Sidebar Enhanced Tests', () => {
  const mockSessions: TerminalSession[] = [
    {
      id: 'session-1',
      name: 'Terminal 1',
      status: 'connected',
      createdAt: '2023-01-01T00:00:00Z',
      lastActivity: '2023-01-01T01:00:00Z'
    },
    {
      id: 'session-2',
      name: 'Terminal 2', 
      status: 'connecting',
      createdAt: '2023-01-01T00:30:00Z',
      lastActivity: '2023-01-01T01:15:00Z'
    }
  ];

  const defaultProps = {
    isOpen: true,
    onToggle: jest.fn(),
    sessions: mockSessions,
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionCreate: jest.fn(),
    onSessionClose: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Sidebar Open State', () => {
    it('renders sidebar content when open', () => {
      render(<Sidebar {...defaultProps} />);
      
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
    });

    it('applies correct width classes when open', () => {
      render(<Sidebar {...defaultProps} />);
      
      const container = document.querySelector('.sidebar-container');
      expect(container).toHaveClass('w-64');
      expect(container).not.toHaveClass('w-0');
    });

    it('shows terminal connected status when sessions exist', () => {
      render(<Sidebar {...defaultProps} />);
      
      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
      
      const statusIndicator = document.querySelector('.bg-green-500.animate-pulse');
      expect(statusIndicator).toBeInTheDocument();
    });

    it('shows connecting status when no sessions exist', () => {
      render(<Sidebar {...defaultProps} sessions={[]} />);
      
      expect(screen.getByText('Connecting...')).toBeInTheDocument();
      
      const statusIndicator = document.querySelector('.bg-gray-500');
      expect(statusIndicator).toBeInTheDocument();
      expect(statusIndicator).not.toHaveClass('animate-pulse');
    });
  });

  describe('Sidebar Closed State', () => {
    it('does not render sidebar content when closed', () => {
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();
      expect(screen.queryByText('Status')).not.toBeInTheDocument();
    });

    it('applies correct width classes when closed', () => {
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      const container = document.querySelector('.sidebar-container');
      expect(container).toHaveClass('w-0');
      expect(container).not.toHaveClass('w-64');
    });

    it('shows toggle button when closed', () => {
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(toggleButton).toBeInTheDocument();
      expect(toggleButton).toHaveClass('fixed', 'top-4', 'left-4', 'z-50');
    });

    it('does not show toggle button when open', () => {
      render(<Sidebar {...defaultProps} isOpen={true} />);
      
      expect(screen.queryByRole('button', { name: 'Open Sidebar' })).not.toBeInTheDocument();
    });
  });

  describe('Toggle Functionality', () => {
    it('calls onToggle when close button is clicked (open state)', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...defaultProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      await user.click(closeButton);
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('calls onToggle when open button is clicked (closed state)', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      await user.click(openButton);
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('supports keyboard interaction on toggle buttons', async () => {
      const user = userEvent.setup();
      render(<Sidebar {...defaultProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      await user.keyboard('{Tab}');
      await user.keyboard('{Enter}');
      
      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });
  });

  describe('Content Sections', () => {
    it('renders status section with correct information', () => {
      render(<Sidebar {...defaultProps} />);
      
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
    });

    it('renders keyboard shortcuts section', () => {
      render(<Sidebar {...defaultProps} />);
      
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+C - Interrupt')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+D - Exit')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+L - Clear')).toBeInTheDocument();
      expect(screen.getByText('↑/↓ - History')).toBeInTheDocument();
    });

    it('renders scroll information section', () => {
      render(<Sidebar {...defaultProps} />);
      
      expect(screen.getByText('Scroll')).toBeInTheDocument();
      expect(screen.getByText(/Use mouse wheel or touchpad to scroll/)).toBeInTheDocument();
    });
  });

  describe('Responsive Behavior', () => {
    it('handles overflow content properly', () => {
      render(<Sidebar {...defaultProps} />);
      
      const contentArea = document.querySelector('.flex-1.overflow-y-auto');
      expect(contentArea).toBeInTheDocument();
      expect(contentArea).toHaveClass('overflow-y-auto', 'p-4');
    });

    it('maintains proper layout with flex properties', () => {
      render(<Sidebar {...defaultProps} />);
      
      const container = document.querySelector('.sidebar-container');
      const content = document.querySelector('.flex.flex-col.h-full');
      
      expect(container).toHaveClass('flex', 'flex-col');
      expect(content).toHaveClass('flex', 'flex-col', 'h-full');
    });
  });

  describe('Animation and Transitions', () => {
    it('applies transition classes for smooth animation', () => {
      render(<Sidebar {...defaultProps} />);
      
      const container = document.querySelector('.sidebar-container');
      expect(container).toHaveClass('transition-all', 'duration-300', 'ease-in-out');
    });

    it('applies hover effects on toggle buttons', () => {
      render(<Sidebar {...defaultProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toHaveClass('hover:bg-sidebar-hover', 'transition-colors');
    });

    it('applies hover effects on closed state button', () => {
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(openButton).toHaveClass('hover:bg-gray-700', 'transition-colors');
    });
  });

  describe('Status Indicator Logic', () => {
    it('shows correct status for different session states', () => {
      render(<Sidebar {...defaultProps} sessions={[]} />);
      
      expect(screen.getByText('Connecting...')).toBeInTheDocument();
      expect(screen.getByText('Connecting...')).toHaveClass('text-gray-400');
    });

    it('animates status indicator when connected', () => {
      render(<Sidebar {...defaultProps} />);
      
      const indicator = document.querySelector('.bg-green-500.animate-pulse');
      expect(indicator).toBeInTheDocument();
    });

    it('does not animate status indicator when disconnected', () => {
      render(<Sidebar {...defaultProps} sessions={[]} />);
      
      const indicator = document.querySelector('.bg-gray-500');
      expect(indicator).toBeInTheDocument();
      expect(indicator).not.toHaveClass('animate-pulse');
    });
  });

  describe('Accessibility', () => {
    it('has no accessibility violations', async () => {
      const { container } = render(<Sidebar {...defaultProps} />);
      const results = await axe(container);
      
      expect(results).toHaveNoViolations();
    });

    it('provides proper button labels and titles', () => {
      render(<Sidebar {...defaultProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toHaveAttribute('title', 'Toggle Sidebar');
    });

    it('provides proper button labels in closed state', () => {
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(openButton).toHaveAttribute('title', 'Open Sidebar');
    });

    it('maintains proper heading hierarchy', () => {
      render(<Sidebar {...defaultProps} />);
      
      const mainHeading = screen.getByRole('heading', { level: 2 });
      expect(mainHeading).toHaveTextContent('Claude Flow Terminal');
      
      const subHeadings = screen.getAllByRole('heading', { level: 3 });
      expect(subHeadings).toHaveLength(3);
      expect(subHeadings[0]).toHaveTextContent('Status');
      expect(subHeadings[1]).toHaveTextContent('Keyboard Shortcuts');
      expect(subHeadings[2]).toHaveTextContent('Scroll');
    });
  });

  describe('SVG Icons', () => {
    it('renders close icon in toggle button', () => {
      render(<Sidebar {...defaultProps} />);
      
      const svg = document.querySelector('svg[viewBox="0 0 24 24"]');
      expect(svg).toBeInTheDocument();
      expect(svg).toHaveClass('w-4', 'h-4');
      
      const path = svg?.querySelector('path[d*="M6 18L18 6M6 6l12 12"]');
      expect(path).toBeInTheDocument();
    });

    it('renders hamburger icon in open button when closed', () => {
      render(<Sidebar {...defaultProps} isOpen={false} />);
      
      const svg = document.querySelector('svg.text-gray-300');
      expect(svg).toBeInTheDocument();
      expect(svg).toHaveClass('w-4', 'h-4');
      
      const path = svg?.querySelector('path[d*="M4 6h16M4 12h16M4 18h16"]');
      expect(path).toBeInTheDocument();
    });
  });

  describe('Edge Cases', () => {
    it('handles undefined sessions gracefully', () => {
      const propsWithUndefinedSessions = {
        ...defaultProps,
        sessions: undefined as any
      };
      
      expect(() => render(<Sidebar {...propsWithUndefinedSessions} />)).not.toThrow();
    });

    it('handles rapid toggle state changes', async () => {
      const { rerender } = render(<Sidebar {...defaultProps} isOpen={true} />);
      
      for (let i = 0; i < 10; i++) {
        rerender(<Sidebar {...defaultProps} isOpen={i % 2 === 0} />);
      }
      
      // Should not throw and should render final state correctly
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });

    it('handles missing callback props gracefully', () => {
      const propsWithoutCallbacks = {
        ...defaultProps,
        onToggle: undefined as any
      };
      
      expect(() => render(<Sidebar {...propsWithoutCallbacks} />)).not.toThrow();
    });
  });

  describe('Styling and Layout', () => {
    it('applies correct border styles', () => {
      render(<Sidebar {...defaultProps} />);
      
      const header = document.querySelector('.border-b.border-sidebar-border');
      expect(header).toBeInTheDocument();
    });

    it('applies correct spacing classes', () => {
      render(<Sidebar {...defaultProps} />);
      
      const header = document.querySelector('.p-4');
      const content = document.querySelector('.overflow-y-auto.p-4');
      const shortcuts = document.querySelector('.space-y-4');
      
      expect(header).toBeInTheDocument();
      expect(content).toBeInTheDocument();
      expect(shortcuts).toBeInTheDocument();
    });

    it('applies correct text styling for different elements', () => {
      render(<Sidebar {...defaultProps} />);
      
      const mainHeading = screen.getByText('Claude Flow Terminal');
      expect(mainHeading).toHaveClass('text-lg', 'font-semibold');
      
      const subHeading = screen.getByText('Status');
      expect(subHeading).toHaveClass('text-sm', 'font-medium', 'text-gray-400');
      
      const shortcutText = screen.getByText('Ctrl+C - Interrupt');
      expect(shortcutText).toHaveClass('text-xs');
    });
  });

  describe('Performance', () => {
    it('renders efficiently with large session lists', () => {
      const manySessions = Array.from({ length: 100 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i}`,
        status: 'connected' as const,
        createdAt: '2023-01-01T00:00:00Z',
        lastActivity: '2023-01-01T01:00:00Z'
      }));
      
      const startTime = performance.now();
      render(<Sidebar {...defaultProps} sessions={manySessions} />);
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100);
    });

    it('handles rapid prop updates efficiently', async () => {
      const { rerender } = render(<Sidebar {...defaultProps} />);
      
      const startTime = performance.now();
      
      for (let i = 0; i < 20; i++) {
        rerender(<Sidebar {...defaultProps} isOpen={i % 2 === 0} activeSessionId={`session-${i % 2 + 1}`} />);
      }
      
      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(100);
    });
  });

  describe('Integration Behavior', () => {
    it('maintains state consistency during open/close cycles', () => {
      const { rerender } = render(<Sidebar {...defaultProps} isOpen={true} />);
      
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      
      rerender(<Sidebar {...defaultProps} isOpen={false} />);
      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Open Sidebar' })).toBeInTheDocument();
      
      rerender(<Sidebar {...defaultProps} isOpen={true} />);
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Open Sidebar' })).not.toBeInTheDocument();
    });
  });
});