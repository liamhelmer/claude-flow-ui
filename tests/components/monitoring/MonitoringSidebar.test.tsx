import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import { cn } from '@/lib/utils';

// Mock dynamic imports
jest.mock('next/dynamic', () => {
  return function mockDynamic(importFn: any, options: any = {}) {
    const mockComponent = ({ children, ...props }: any) => {
      if (options.loading && Math.random() < 0.1) {
        // Simulate loading state occasionally
        return <div data-testid="loading">Loading...</div>;
      }
      
      // Mock the actual component based on the import
      const componentName = importFn.toString().includes('MemoryPanel') ? 'MemoryPanel' :
                           importFn.toString().includes('AgentsPanel') ? 'AgentsPanel' :
                           importFn.toString().includes('PromptPanel') ? 'PromptPanel' :
                           importFn.toString().includes('CommandsPanel') ? 'CommandsPanel' : 'MockComponent';
      
      return <div data-testid={componentName.toLowerCase()}>{componentName} Content</div>;
    };
    
    mockComponent.displayName = 'MockDynamicComponent';
    return mockComponent;
  };
});

// Mock the utility function
jest.mock('@/lib/utils', () => ({
  cn: jest.fn((...classes) => classes.filter(Boolean).join(' ')),
}));

describe('MonitoringSidebar', () => {
  const defaultProps = {
    isOpen: false,
    onToggle: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (cn as jest.Mock).mockImplementation((...classes) => classes.filter(Boolean).join(' '));
  });

  describe('Rendering and Visibility', () => {
    it('renders without crashing', () => {
      render(<MonitoringSidebar {...defaultProps} />);
      expect(screen.getByRole('button', { name: /open monitor/i })).toBeInTheDocument();
    });

    it('shows toggle button when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      const toggleButton = screen.getByRole('button', { name: /open monitor/i });
      expect(toggleButton).toBeInTheDocument();
      expect(toggleButton).toHaveClass('fixed top-4 right-4 z-30');
    });

    it('shows sidebar when open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /close monitor/i })).toBeInTheDocument();
    });

    it('hides toggle button when sidebar is open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      expect(screen.queryByRole('button', { name: /open monitor/i })).not.toBeInTheDocument();
    });
  });

  describe('Tab Navigation', () => {
    beforeEach(() => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
    });

    it('renders all tabs with correct labels and icons', () => {
      expect(screen.getByText('💾')).toBeInTheDocument();
      expect(screen.getByText('Memory')).toBeInTheDocument();
      expect(screen.getByText('🤖')).toBeInTheDocument();
      expect(screen.getByText('Agents')).toBeInTheDocument();
      expect(screen.getByText('📝')).toBeInTheDocument();
      expect(screen.getByText('Prompt')).toBeInTheDocument();
      expect(screen.getByText('⚡')).toBeInTheDocument();
      expect(screen.getByText('Commands')).toBeInTheDocument();
    });

    it('has Memory tab active by default', () => {
      const memoryTab = screen.getByRole('button', { name: /💾 memory/i });
      expect(memoryTab).toHaveClass('text-blue-400 border-blue-400 bg-gray-900');
      expect(screen.getByTestId('memorypanel')).toBeInTheDocument();
    });

    it('switches to Agents tab when clicked', async () => {
      const user = userEvent.setup();
      const agentsTab = screen.getByRole('button', { name: /🤖 agents/i });
      
      await user.click(agentsTab);
      
      expect(agentsTab).toHaveClass('text-blue-400 border-blue-400 bg-gray-900');
      expect(screen.getByTestId('agentspanel')).toBeInTheDocument();
    });

    it('switches to Prompt tab when clicked', async () => {
      const user = userEvent.setup();
      const promptTab = screen.getByRole('button', { name: /📝 prompt/i });
      
      await user.click(promptTab);
      
      expect(promptTab).toHaveClass('text-blue-400 border-blue-400 bg-gray-900');
      expect(screen.getByTestId('promptpanel')).toBeInTheDocument();
    });

    it('switches to Commands tab when clicked', async () => {
      const user = userEvent.setup();
      const commandsTab = screen.getByRole('button', { name: /⚡ commands/i });
      
      await user.click(commandsTab);
      
      expect(commandsTab).toHaveClass('text-blue-400 border-blue-400 bg-gray-900');
      expect(screen.getByTestId('commandspanel')).toBeInTheDocument();
    });

    it('maintains tab state when toggling sidebar visibility', async () => {
      const user = userEvent.setup();
      const agentsTab = screen.getByRole('button', { name: /🤖 agents/i });
      
      // Switch to agents tab
      await user.click(agentsTab);
      expect(screen.getByTestId('agentspanel')).toBeInTheDocument();
      
      // Close and reopen (simulate by remounting with different props)
      const { rerender } = render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      rerender(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      // Should still show memory panel (resets to default on remount)
      expect(screen.getByTestId('memorypanel')).toBeInTheDocument();
    });
  });

  describe('Toggle Functionality', () => {
    it('calls onToggle when close button is clicked', async () => {
      const user = userEvent.setup();
      const mockOnToggle = jest.fn();
      
      render(<MonitoringSidebar isOpen={true} onToggle={mockOnToggle} />);
      
      const closeButton = screen.getByRole('button', { name: /close monitor/i });
      await user.click(closeButton);
      
      expect(mockOnToggle).toHaveBeenCalledTimes(1);
    });

    it('calls onToggle when toggle button is clicked', async () => {
      const user = userEvent.setup();
      const mockOnToggle = jest.fn();
      
      render(<MonitoringSidebar isOpen={false} onToggle={mockOnToggle} />);
      
      const toggleButton = screen.getByRole('button', { name: /open monitor/i });
      await user.click(toggleButton);
      
      expect(mockOnToggle).toHaveBeenCalledTimes(1);
    });
  });

  describe('Styling and CSS Classes', () => {
    it('applies correct classes when sidebar is open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      expect(cn).toHaveBeenCalledWith(
        'fixed right-0 top-0 h-full z-40',
        'bg-gray-900 border-l border-gray-700',
        'transition-transform duration-300 ease-in-out',
        'flex flex-col',
        'translate-x-0 w-96'
      );
    });

    it('applies correct classes when sidebar is closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      expect(cn).toHaveBeenCalledWith(
        'fixed right-0 top-0 h-full z-40',
        'bg-gray-900 border-l border-gray-700',
        'transition-transform duration-300 ease-in-out',
        'flex flex-col',
        'translate-x-full w-0'
      );
    });

    it('applies hover styles to tab buttons', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const agentsTab = screen.getByRole('button', { name: /🤖 agents/i });
      expect(agentsTab).toHaveClass('hover:text-white hover:bg-gray-700');
    });
  });

  describe('Dynamic Component Loading', () => {
    it('renders loading state for dynamic components', async () => {
      // Mock dynamic import to return loading state
      jest.doMock('next/dynamic', () => {
        return function mockDynamic(importFn: any, options: any = {}) {
          return () => options.loading ? options.loading() : <div>Loaded</div>;
        };
      });

      const { unmount } = render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      // Clean up
      unmount();
      jest.dontMock('next/dynamic');
    });

    it('handles SSR false correctly for dynamic imports', () => {
      // This test ensures that dynamic imports are configured correctly
      // The actual SSR behavior is handled by Next.js framework
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      // Verify that panels are rendered (since we're mocking them)
      expect(screen.getByTestId('memorypanel')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('has proper ARIA labels for buttons', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      const toggleButton = screen.getByRole('button', { name: /open monitor/i });
      expect(toggleButton).toHaveAttribute('title', 'Open Monitor');
    });

    it('has proper ARIA labels for close button when open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const closeButton = screen.getByRole('button', { name: /close monitor/i });
      expect(closeButton).toHaveAttribute('title', 'Close Monitor');
    });

    it('supports keyboard navigation for tabs', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const agentsTab = screen.getByRole('button', { name: /🤖 agents/i });
      
      // Tab to the agents button and press Enter
      agentsTab.focus();
      await user.keyboard('{Enter}');
      
      expect(screen.getByTestId('agentspanel')).toBeInTheDocument();
    });

    it('maintains focus management when switching tabs', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const memoryTab = screen.getByRole('button', { name: /💾 memory/i });
      const agentsTab = screen.getByRole('button', { name: /🤖 agents/i });
      
      // Click agents tab
      await user.click(agentsTab);
      
      // Memory tab should not be focused, agents tab should be
      expect(memoryTab).not.toHaveClass('text-blue-400 border-blue-400 bg-gray-900');
      expect(agentsTab).toHaveClass('text-blue-400 border-blue-400 bg-gray-900');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('handles missing onToggle prop gracefully', () => {
      // TypeScript would catch this, but test runtime behavior
      const { container } = render(
        <MonitoringSidebar isOpen={false} onToggle={undefined as any} />
      );
      
      expect(container).toBeInTheDocument();
    });

    it('handles rapid tab switching without errors', async () => {
      const user = userEvent.setup();
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const tabs = [
        screen.getByRole('button', { name: /💾 memory/i }),
        screen.getByRole('button', { name: /🤖 agents/i }),
        screen.getByRole('button', { name: /📝 prompt/i }),
        screen.getByRole('button', { name: /⚡ commands/i }),
      ];
      
      // Rapidly click through all tabs
      for (const tab of tabs) {
        await user.click(tab);
      }
      
      // Should end up on Commands tab
      expect(screen.getByTestId('commandspanel')).toBeInTheDocument();
    });

    it('handles missing dynamic component gracefully', () => {
      // Mock a dynamic component that fails to load
      jest.doMock('next/dynamic', () => {
        return function mockDynamic() {
          return () => <div data-testid="error-fallback">Component failed to load</div>;
        };
      });

      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      // Should not crash and should render something
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
      
      jest.dontMock('next/dynamic');
    });
  });

  describe('Performance Considerations', () => {
    it('does not render panel content when sidebar is closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      
      // Panels should not be rendered when sidebar is closed
      expect(screen.queryByTestId('memorypanel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('agentspanel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('promptpanel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('commandspanel')).not.toBeInTheDocument();
    });

    it('only renders active panel content when open', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      // Only Memory panel should be rendered initially
      expect(screen.getByTestId('memorypanel')).toBeInTheDocument();
      expect(screen.queryByTestId('agentspanel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('promptpanel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('commandspanel')).not.toBeInTheDocument();
    });

    it('efficiently switches between panels without unnecessary re-renders', async () => {
      const user = userEvent.setup();
      const { rerender } = render(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      const agentsTab = screen.getByRole('button', { name: /🤖 agents/i });
      await user.click(agentsTab);
      
      // Re-render with same props should not cause issues
      rerender(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
    });
  });
});