import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import Sidebar from '@/components/sidebar/Sidebar';
import type { TerminalSession, SidebarProps } from '@/types';

describe('Sidebar', () => {
  const mockSessions: TerminalSession[] = [
    {
      id: 'session-1',
      name: 'Terminal 1',
      created: new Date(),
      lastActivity: new Date(),
    },
    {
      id: 'session-2',
      name: 'Terminal 2',
      created: new Date(),
      lastActivity: new Date(),
    },
  ];

  const defaultProps: SidebarProps = {
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

  describe('when sidebar is open', () => {
    it('renders sidebar with header and title', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByTitle('Toggle Sidebar')).toBeInTheDocument();
    });

    it('shows connected status when sessions exist', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
      
      const statusIndicator = screen.getByText('Terminal Connected').previousElementSibling;
      expect(statusIndicator).toHaveClass('bg-green-500');
      expect(statusIndicator).toHaveClass('animate-pulse');
    });

    it('shows connecting status when no sessions exist', () => {
      const noSessionsProps = {
        ...defaultProps,
        sessions: [],
      };

      render(<Sidebar {...noSessionsProps} />);

      expect(screen.getByText('Connecting...')).toBeInTheDocument();
      
      const statusIndicator = screen.getByText('Connecting...').previousElementSibling;
      expect(statusIndicator).toHaveClass('bg-gray-500');
    });

    it('displays keyboard shortcuts', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+C - Interrupt')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+D - Exit')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+L - Clear')).toBeInTheDocument();
      expect(screen.getByText('↑/↓ - History')).toBeInTheDocument();
    });

    it('displays scroll information', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByText('Scroll')).toBeInTheDocument();
      expect(screen.getByText('Use mouse wheel or touchpad to scroll through output history')).toBeInTheDocument();
    });

    it('calls onToggle when close button is clicked', () => {
      render(<Sidebar {...defaultProps} />);

      const closeButton = screen.getByTitle('Toggle Sidebar');
      fireEvent.click(closeButton);

      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('has correct width when open', () => {
      render(<Sidebar {...defaultProps} />);

      const sidebarContainer = screen.getByText('Claude Flow Terminal').closest('.sidebar-container');
      expect(sidebarContainer).toHaveClass('w-64');
    });

    it('shows status section', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByText('Status')).toBeInTheDocument();
    });

    it('renders with proper layout classes', () => {
      render(<Sidebar {...defaultProps} />);

      const sidebarContainer = screen.getByText('Claude Flow Terminal').closest('.sidebar-container');
      expect(sidebarContainer).toHaveClass('flex');
      expect(sidebarContainer).toHaveClass('flex-col');
      expect(sidebarContainer).toHaveClass('h-full');
      expect(sidebarContainer).toHaveClass('overflow-hidden');
    });
  });

  describe('when sidebar is closed', () => {
    const closedProps = {
      ...defaultProps,
      isOpen: false,
    };

    it('has zero width when closed', () => {
      render(<Sidebar {...closedProps} />);

      const sidebarContainer = document.querySelector('.sidebar-container');
      expect(sidebarContainer).toHaveClass('w-0');
    });

    it('shows toggle button when closed', () => {
      render(<Sidebar {...closedProps} />);

      const openButton = screen.getByTitle('Open Sidebar');
      expect(openButton).toBeInTheDocument();
      expect(openButton).toHaveClass('fixed');
      expect(openButton).toHaveClass('top-4');
      expect(openButton).toHaveClass('left-4');
      expect(openButton).toHaveClass('z-50');
    });

    it('calls onToggle when open button is clicked', () => {
      render(<Sidebar {...closedProps} />);

      const openButton = screen.getByTitle('Open Sidebar');
      fireEvent.click(openButton);

      expect(defaultProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('does not render sidebar content when closed', () => {
      render(<Sidebar {...closedProps} />);

      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();
      expect(screen.queryByText('Status')).not.toBeInTheDocument();
      expect(screen.queryByText('Keyboard Shortcuts')).not.toBeInTheDocument();
    });

    it('shows hamburger menu icon in toggle button', () => {
      render(<Sidebar {...closedProps} />);

      const openButton = screen.getByTitle('Open Sidebar');
      const svg = openButton.querySelector('svg');
      expect(svg).toBeInTheDocument();
      expect(svg).toHaveClass('w-4');
      expect(svg).toHaveClass('h-4');
      expect(svg).toHaveClass('text-gray-300');
    });
  });

  describe('animations and transitions', () => {
    it('applies transition classes to sidebar container', () => {
      render(<Sidebar {...defaultProps} />);

      const sidebarContainer = document.querySelector('.sidebar-container');
      expect(sidebarContainer).toHaveClass('transition-all');
      expect(sidebarContainer).toHaveClass('duration-300');
      expect(sidebarContainer).toHaveClass('ease-in-out');
    });

    it('applies transition classes to toggle buttons', () => {
      render(<Sidebar {...defaultProps} />);

      const closeButton = screen.getByTitle('Toggle Sidebar');
      expect(closeButton).toHaveClass('transition-colors');
    });
  });

  describe('accessibility', () => {
    it('has proper ARIA labels and titles', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByTitle('Toggle Sidebar')).toBeInTheDocument();
    });

    it('has proper ARIA labels when closed', () => {
      const closedProps = {
        ...defaultProps,
        isOpen: false,
      };

      render(<Sidebar {...closedProps} />);

      expect(screen.getByTitle('Open Sidebar')).toBeInTheDocument();
    });

    it('uses semantic heading elements', () => {
      render(<Sidebar {...defaultProps} />);

      expect(screen.getByRole('heading', { name: 'Claude Flow Terminal' })).toBeInTheDocument();
    });
  });

  describe('responsive behavior', () => {
    it('handles different session counts', () => {
      const manySessions: TerminalSession[] = Array.from({ length: 10 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i + 1}`,
        created: new Date(),
        lastActivity: new Date(),
      }));

      const manySessionsProps = {
        ...defaultProps,
        sessions: manySessions,
      };

      render(<Sidebar {...manySessionsProps} />);

      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
    });

    it('handles empty activeSessionId', () => {
      const noActiveProps = {
        ...defaultProps,
        activeSessionId: null,
      };

      render(<Sidebar {...noActiveProps} />);

      // Should still render normally
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });
  });

  describe('styling and theme', () => {
    it('applies correct border and background classes', () => {
      render(<Sidebar {...defaultProps} />);

      const header = screen.getByText('Claude Flow Terminal').closest('div');
      expect(header).toHaveClass('border-b');
      expect(header).toHaveClass('border-sidebar-border');
    });

    it('applies correct hover states', () => {
      render(<Sidebar {...defaultProps} />);

      const closeButton = screen.getByTitle('Toggle Sidebar');
      expect(closeButton).toHaveClass('hover:bg-sidebar-hover');
    });

    it('uses consistent spacing', () => {
      render(<Sidebar {...defaultProps} />);

      const content = screen.getByText('Status').closest('div');
      expect(content).toHaveClass('space-y-4');
    });
  });

  describe('edge cases', () => {
    it('handles undefined props gracefully', () => {
      const minimalProps = {
        isOpen: true,
        onToggle: jest.fn(),
        sessions: [],
        activeSessionId: null,
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };

      expect(() => render(<Sidebar {...minimalProps} />)).not.toThrow();
    });

    it('handles rapid open/close toggling', () => {
      const { rerender } = render(<Sidebar {...defaultProps} />);

      // Toggle to closed
      rerender(<Sidebar {...defaultProps} isOpen={false} />);
      expect(screen.getByTitle('Open Sidebar')).toBeInTheDocument();

      // Toggle back to open
      rerender(<Sidebar {...defaultProps} isOpen={true} />);
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });
  });
});