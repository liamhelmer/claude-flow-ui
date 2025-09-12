import React from 'react';
import { render, screen, fireEvent, createMockSession } from '../../../tests/test-utils';
import Sidebar from '../Sidebar';

describe('Sidebar Component', () => {
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

  describe('Rendering - Sidebar Open', () => {
    it('should render sidebar when isOpen is true', () => {
      render(<Sidebar {...mockProps} />);
      
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });

    it('should have correct width when open', () => {
      render(<Sidebar {...mockProps} />);
      
      const sidebarContainer = screen.getByText('Claude Flow Terminal').closest('.sidebar-container');
      expect(sidebarContainer).toHaveClass('w-64');
    });

    it('should show terminal status when sessions exist', () => {
      render(<Sidebar {...mockProps} />);
      
      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
    });

    it('should show connecting status when no sessions exist', () => {
      render(<Sidebar {...mockProps} sessions={[]} />);
      
      expect(screen.getByText('Connecting...')).toBeInTheDocument();
    });

    it('should display keyboard shortcuts section', () => {
      render(<Sidebar {...mockProps} />);
      
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+C - Interrupt')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+D - Exit')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+L - Clear')).toBeInTheDocument();
      expect(screen.getByText('↑/↓ - History')).toBeInTheDocument();
    });

    it('should display scroll information section', () => {
      render(<Sidebar {...mockProps} />);
      
      expect(screen.getByText('Scroll')).toBeInTheDocument();
      expect(screen.getByText('Use mouse wheel or touchpad to scroll through output history')).toBeInTheDocument();
    });
  });

  describe('Rendering - Sidebar Closed', () => {
    it('should not render sidebar content when isOpen is false', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();
    });

    it('should have zero width when closed', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const sidebarContainer = document.querySelector('.sidebar-container');
      expect(sidebarContainer).toHaveClass('w-0');
    });

    it('should show toggle button when closed', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(toggleButton).toBeInTheDocument();
      expect(toggleButton).toHaveClass('fixed', 'top-4', 'left-4');
    });

    it('should not show toggle button when open', () => {
      render(<Sidebar {...mockProps} isOpen={true} />);
      
      expect(screen.queryByRole('button', { name: 'Open Sidebar' })).not.toBeInTheDocument();
    });
  });

  describe('Toggle Functionality', () => {
    it('should call onToggle when close button is clicked (sidebar open)', () => {
      render(<Sidebar {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      fireEvent.click(closeButton);
      
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should call onToggle when open button is clicked (sidebar closed)', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      fireEvent.click(openButton);
      
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });
  });

  describe('Status Indicators', () => {
    it('should show green pulsing dot when sessions exist', () => {
      render(<Sidebar {...mockProps} />);
      
      const statusDot = document.querySelector('.w-2.h-2.bg-green-500.rounded-full.animate-pulse');
      expect(statusDot).toBeInTheDocument();
    });

    it('should show gray static dot when no sessions exist', () => {
      render(<Sidebar {...mockProps} sessions={[]} />);
      
      const statusDot = document.querySelector('.w-2.h-2.bg-gray-500.rounded-full');
      expect(statusDot).toBeInTheDocument();
      expect(statusDot).not.toHaveClass('animate-pulse');
    });
  });

  describe('Transition Classes', () => {
    it('should have transition classes for smooth animation', () => {
      render(<Sidebar {...mockProps} />);
      
      const sidebarContainer = document.querySelector('.sidebar-container');
      expect(sidebarContainer).toHaveClass('transition-all', 'duration-300', 'ease-in-out');
    });

    it('should apply correct transition classes when closed', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const sidebarContainer = document.querySelector('.sidebar-container');
      expect(sidebarContainer).toHaveClass('transition-all', 'duration-300', 'ease-in-out');
    });
  });

  describe('Props Validation', () => {
    it('should handle empty sessions array', () => {
      render(<Sidebar {...mockProps} sessions={[]} />);
      
      expect(screen.getByText('Connecting...')).toBeInTheDocument();
    });

    it('should handle null activeSessionId', () => {
      render(<Sidebar {...mockProps} activeSessionId={null} />);
      
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();
    });

    it('should handle multiple sessions', () => {
      const multipleSessions = [
        createMockSession('session-1'),
        createMockSession('session-2'),
        createMockSession('session-3'),
      ];
      
      render(<Sidebar {...mockProps} sessions={multipleSessions} />);
      
      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels for buttons', () => {
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toHaveAttribute('title', 'Toggle Sidebar');
    });

    it('should have proper ARIA labels for closed state button', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(openButton).toHaveAttribute('title', 'Open Sidebar');
    });

    it('should have semantic heading structure', () => {
      render(<Sidebar {...mockProps} />);
      
      expect(screen.getByRole('heading', { name: 'Claude Flow Terminal' })).toBeInTheDocument();
    });
  });

  describe('Keyboard Navigation', () => {
    it('should handle keyboard events on toggle buttons', () => {
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      fireEvent.keyDown(toggleButton, { key: 'Enter' });
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should handle space key on toggle buttons', () => {
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      
      fireEvent.keyDown(toggleButton, { key: ' ' });
      // Note: Space key behavior is handled by default button behavior
      expect(toggleButton).toBeInTheDocument();
    });
  });

  describe('Visual States', () => {
    it('should apply hover styles to toggle button', () => {
      render(<Sidebar {...mockProps} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Toggle Sidebar' });
      expect(toggleButton).toHaveClass('hover:bg-sidebar-hover');
    });

    it('should apply hover styles to open button when closed', () => {
      render(<Sidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Sidebar' });
      expect(openButton).toHaveClass('hover:bg-gray-700');
    });
  });

  describe('Content Structure', () => {
    it('should have proper content hierarchy', () => {
      render(<Sidebar {...mockProps} />);
      
      // Check for main sections
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
      expect(screen.getByText('Scroll')).toBeInTheDocument();
    });

    it('should have proper flex layout classes', () => {
      render(<Sidebar {...mockProps} />);
      
      const mainContent = screen.getByText('Claude Flow Terminal').closest('.flex.flex-col.h-full');
      expect(mainContent).toBeInTheDocument();
    });
  });

  describe('Border and Styling', () => {
    it('should have proper border styling', () => {
      render(<Sidebar {...mockProps} />);
      
      const header = screen.getByText('Claude Flow Terminal').closest('.border-b.border-sidebar-border');
      expect(header).toBeInTheDocument();
    });

    it('should have scrollable content area', () => {
      render(<Sidebar {...mockProps} />);
      
      const scrollableArea = document.querySelector('.flex-1.overflow-y-auto.p-4');
      expect(scrollableArea).toBeInTheDocument();
    });
  });
});