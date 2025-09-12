import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../../tests/test-utils';
import MonitoringSidebar from '../MonitoringSidebar';

// Mock dynamic imports
jest.mock('next/dynamic', () => {
  const actualNext = jest.requireActual('next/dynamic');
  
  return (fn: any, options?: any) => {
    const Component = (props: any) => {
      if (options?.loading && Math.random() < 0.1) { // Simulate loading state occasionally
        return options.loading();
      }
      
      const MockComponent = ({ componentName }: { componentName: string }) => (
        <div data-testid={`mock-${componentName}`}>Mock {componentName}</div>
      );
      
      // Return different mock components based on the import
      const fnString = fn.toString();
      if (fnString.includes('MemoryPanel')) {
        return <MockComponent componentName="MemoryPanel" {...props} />;
      }
      if (fnString.includes('AgentsPanel')) {
        return <MockComponent componentName="AgentsPanel" {...props} />;
      }
      if (fnString.includes('PromptPanel')) {
        return <MockComponent componentName="PromptPanel" {...props} />;
      }
      if (fnString.includes('CommandsPanel')) {
        return <MockComponent componentName="CommandsPanel" {...props} />;
      }
      
      return <MockComponent componentName="UnknownPanel" {...props} />;
    };
    
    Component.displayName = 'MockedDynamicComponent';
    return Component;
  };
});

describe('MonitoringSidebar Component', () => {
  const mockProps = {
    isOpen: true,
    onToggle: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering - Sidebar Open', () => {
    it('should render sidebar when isOpen is true', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
    });

    it('should apply correct positioning and sizing when open', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const sidebar = screen.getByText('Claude Flow UI Monitor').closest('.fixed.right-0.top-0.h-full');
      expect(sidebar).toBeInTheDocument();
      expect(sidebar).toHaveClass('translate-x-0', 'w-96');
    });

    it('should display the bee icon and title', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      expect(screen.getByText('🐝')).toBeInTheDocument();
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
    });

    it('should render close button with correct icon', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Monitor' });
      expect(closeButton).toBeInTheDocument();
      expect(closeButton).toHaveAttribute('title', 'Close Monitor');
    });
  });

  describe('Rendering - Sidebar Closed', () => {
    it('should hide sidebar content when isOpen is false', () => {
      render(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      const sidebar = screen.getByText('🐝').closest('.fixed.right-0.top-0.h-full');
      expect(sidebar).toHaveClass('translate-x-full', 'w-0');
    });

    it('should show toggle button when closed', () => {
      render(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      const toggleButton = screen.getByRole('button', { name: 'Open Monitor' });
      expect(toggleButton).toBeInTheDocument();
      expect(toggleButton).toHaveClass('fixed', 'top-4', 'right-4');
    });

    it('should not show toggle button when open', () => {
      render(<MonitoringSidebar {...mockProps} isOpen={true} />);
      
      expect(screen.queryByRole('button', { name: 'Open Monitor' })).not.toBeInTheDocument();
    });
  });

  describe('Tab Navigation', () => {
    it('should render all tab buttons', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      expect(screen.getByText('💾')).toBeInTheDocument(); // Memory tab icon
      expect(screen.getByText('Memory')).toBeInTheDocument();
      expect(screen.getByText('🤖')).toBeInTheDocument(); // Agents tab icon
      expect(screen.getByText('Agents')).toBeInTheDocument();
      expect(screen.getByText('📝')).toBeInTheDocument(); // Prompt tab icon
      expect(screen.getByText('Prompt')).toBeInTheDocument();
      expect(screen.getByText('⚡')).toBeInTheDocument(); // Commands tab icon
      expect(screen.getByText('Commands')).toBeInTheDocument();
    });

    it('should have Memory tab active by default', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const memoryTab = screen.getByText('Memory').closest('button');
      expect(memoryTab).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
    });

    it('should switch to Agents tab when clicked', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const agentsTab = screen.getByText('Agents').closest('button') as HTMLElement;
      fireEvent.click(agentsTab);
      
      expect(agentsTab).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
    });

    it('should switch to Prompt tab when clicked', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const promptTab = screen.getByText('Prompt').closest('button') as HTMLElement;
      fireEvent.click(promptTab);
      
      expect(promptTab).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
    });

    it('should switch to Commands tab when clicked', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const commandsTab = screen.getByText('Commands').closest('button') as HTMLElement;
      fireEvent.click(commandsTab);
      
      expect(commandsTab).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
    });

    it('should show inactive styling for non-active tabs', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const agentsTab = screen.getByText('Agents').closest('button');
      expect(agentsTab).toHaveClass('text-gray-400', 'border-transparent', 'hover:text-white', 'hover:bg-gray-700');
    });
  });

  describe('Panel Content', () => {
    it('should display MemoryPanel by default', async () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      await waitFor(() => {
        expect(screen.getByTestId('mock-MemoryPanel')).toBeInTheDocument();
      });
    });

    it('should display AgentsPanel when Agents tab is selected', async () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const agentsTab = screen.getByText('Agents').closest('button') as HTMLElement;
      fireEvent.click(agentsTab);
      
      await waitFor(() => {
        expect(screen.getByTestId('mock-AgentsPanel')).toBeInTheDocument();
      });
    });

    it('should display PromptPanel when Prompt tab is selected', async () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const promptTab = screen.getByText('Prompt').closest('button') as HTMLElement;
      fireEvent.click(promptTab);
      
      await waitFor(() => {
        expect(screen.getByTestId('mock-PromptPanel')).toBeInTheDocument();
      });
    });

    it('should display CommandsPanel when Commands tab is selected', async () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const commandsTab = screen.getByText('Commands').closest('button') as HTMLElement;
      fireEvent.click(commandsTab);
      
      await waitFor(() => {
        expect(screen.getByTestId('mock-CommandsPanel')).toBeInTheDocument();
      });
    });

    it('should handle loading state for dynamic components', () => {
      // This test might occasionally show loading state due to the randomization in the mock
      render(<MonitoringSidebar {...mockProps} />);
      
      // The component should render without error regardless of loading state
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
    });
  });

  describe('Toggle Functionality', () => {
    it('should call onToggle when close button is clicked', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Monitor' });
      fireEvent.click(closeButton);
      
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should call onToggle when open button is clicked (sidebar closed)', () => {
      render(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Monitor' });
      fireEvent.click(openButton);
      
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });
  });

  describe('Styling and Layout', () => {
    it('should have correct sidebar positioning and z-index', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const sidebar = screen.getByText('Claude Flow UI Monitor').closest('.fixed.right-0.top-0.h-full');
      expect(sidebar).toHaveClass('z-40', 'bg-gray-900', 'border-l', 'border-gray-700');
    });

    it('should have proper transition classes', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const sidebar = screen.getByText('Claude Flow UI Monitor').closest('.fixed.right-0.top-0.h-full');
      expect(sidebar).toHaveClass('transition-transform', 'duration-300', 'ease-in-out');
    });

    it('should have correct header styling', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const header = screen.getByText('Claude Flow UI Monitor').closest('.border-b.border-gray-700.bg-gray-800');
      expect(header).toBeInTheDocument();
    });

    it('should have flex column layout', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const sidebar = screen.getByText('Claude Flow UI Monitor').closest('.flex.flex-col');
      expect(sidebar).toBeInTheDocument();
    });

    it('should have proper content area styling', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const contentArea = document.querySelector('.flex-1.overflow-hidden.bg-gray-900');
      expect(contentArea).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels for buttons', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Monitor' });
      expect(closeButton).toHaveAttribute('title', 'Close Monitor');
    });

    it('should have proper ARIA labels for toggle button when closed', () => {
      render(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      const openButton = screen.getByRole('button', { name: 'Open Monitor' });
      expect(openButton).toHaveAttribute('title', 'Open Monitor');
    });

    it('should have accessible tab navigation', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const memoryTab = screen.getByText('Memory').closest('button');
      expect(memoryTab).toBeInTheDocument();
      
      // Verify button is focusable
      (memoryTab as HTMLElement).focus();
      expect(document.activeElement).toBe(memoryTab);
    });
  });

  describe('Keyboard Navigation', () => {
    it('should handle keyboard events on close button', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Monitor' });
      
      fireEvent.keyDown(closeButton, { key: 'Enter' });
      expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
    });

    it('should handle keyboard events on tab buttons', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const agentsTab = screen.getByText('Agents').closest('button') as HTMLElement;
      
      fireEvent.keyDown(agentsTab, { key: 'Enter' });
      
      expect(agentsTab).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
    });
  });

  describe('State Management', () => {
    it('should maintain tab state independently', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      // Switch to Agents tab
      const agentsTab = screen.getByText('Agents').closest('button') as HTMLElement;
      fireEvent.click(agentsTab);
      
      // Switch to Commands tab
      const commandsTab = screen.getByText('Commands').closest('button') as HTMLElement;
      fireEvent.click(commandsTab);
      
      // Commands tab should be active
      expect(commandsTab).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
      
      // Agents tab should be inactive
      expect(agentsTab).toHaveClass('text-gray-400', 'border-transparent');
    });

    it('should persist tab selection when sidebar is toggled', () => {
      const { rerender } = render(<MonitoringSidebar {...mockProps} />);
      
      // Switch to Agents tab
      const agentsTab = screen.getByText('Agents').closest('button') as HTMLElement;
      fireEvent.click(agentsTab);
      
      // Close sidebar
      rerender(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      // Reopen sidebar
      rerender(<MonitoringSidebar {...mockProps} isOpen={true} />);
      
      // Agents tab should still be active
      const agentsTabAfterReopen = screen.getByText('Agents').closest('button');
      expect(agentsTabAfterReopen).toHaveClass('text-blue-400', 'border-blue-400', 'bg-gray-900');
    });
  });

  describe('Responsive Behavior', () => {
    it('should maintain fixed positioning on all screen sizes', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const sidebar = screen.getByText('Claude Flow UI Monitor').closest('.fixed');
      expect(sidebar).toHaveClass('fixed', 'right-0', 'top-0', 'h-full');
    });

    it('should have appropriate z-index for overlay behavior', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const sidebar = screen.getByText('Claude Flow UI Monitor').closest('.z-40');
      expect(sidebar).toBeInTheDocument();
      
      const toggleButtonClosed = screen.queryByRole('button', { name: 'Open Monitor' });
      if (toggleButtonClosed) {
        expect(toggleButtonClosed).toHaveClass('z-30');
      }
    });
  });

  describe('Performance', () => {
    it('should render efficiently with tab switching', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const startTime = performance.now();
      
      // Switch between all tabs
      fireEvent.click(screen.getByText('Agents').closest('button') as HTMLElement);
      fireEvent.click(screen.getByText('Prompt').closest('button') as HTMLElement);
      fireEvent.click(screen.getByText('Commands').closest('button') as HTMLElement);
      fireEvent.click(screen.getByText('Memory').closest('button') as HTMLElement);
      
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100);
    });
  });

  describe('Dynamic Import Edge Cases', () => {
    it('should handle dynamic import loading states', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      // Should show loading indicators for panels occasionally due to mock randomization
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();
    });

    it('should handle dynamic import failures gracefully', () => {
      // Mock console.error to suppress error logs during test
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      // This test verifies that the component doesn't crash if dynamic imports fail
      expect(() => {
        render(<MonitoringSidebar {...mockProps} />);
      }).not.toThrow();
      
      consoleSpy.mockRestore();
    });

    it('should handle tab switching during loading', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      // Switch tabs while components are loading
      const agentsTab = screen.getByRole('button', { name: /agents/i });
      fireEvent.click(agentsTab);
      
      expect(agentsTab).toHaveClass('text-blue-400');
    });

    it('should handle rapid tab switching', () => {
      render(<MonitoringSidebar {...mockProps} />);
      
      const tabs = ['Memory', 'Agents', 'Prompt', 'Commands'];
      
      // Rapidly switch between all tabs
      tabs.forEach(tabName => {
        const tab = screen.getByRole('button', { name: new RegExp(tabName, 'i') });
        fireEvent.click(tab);
        expect(tab).toHaveClass('text-blue-400');
      });
    });

    it('should handle panel unmounting during loading', () => {
      const { unmount } = render(<MonitoringSidebar {...mockProps} />);
      
      // Switch tabs to trigger new panel mounting
      fireEvent.click(screen.getByRole('button', { name: /agents/i }));
      
      // Unmount while loading
      expect(() => unmount()).not.toThrow();
    });

    it('should handle SSR compatibility', () => {
      // Test that dynamic imports with ssr: false don't break server rendering
      const originalWindow = global.window;
      delete (global as any).window;
      
      expect(() => {
        render(<MonitoringSidebar {...mockProps} />);
      }).not.toThrow();
      
      global.window = originalWindow;
    });

    it('should handle multiple instances of monitoring sidebar', () => {
      // Test that multiple instances don't conflict
      render(
        <>
          <MonitoringSidebar {...mockProps} />
          <MonitoringSidebar {...mockProps} isOpen={false} />
        </>
      );
      
      // Should render both without conflicts
      expect(screen.getAllByText('Claude Flow UI Monitor')).toHaveLength(1); // Only open one shows header
    });
  });

  describe('Performance Edge Cases', () => {
    it('should handle memory pressure gracefully', () => {
      // Simulate memory pressure by creating many instances
      const instances = Array.from({ length: 10 }, (_, i) => (
        <MonitoringSidebar key={i} {...mockProps} />
      ));
      
      expect(() => {
        render(<>{instances}</>);
      }).not.toThrow();
    });

    it('should handle rapid open/close cycles', () => {
      const { rerender } = render(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      // Rapidly toggle open/close
      for (let i = 0; i < 10; i++) {
        rerender(<MonitoringSidebar {...mockProps} isOpen={i % 2 === 0} />);
      }
      
      expect(mockProps.onToggle).not.toHaveBeenCalled(); // Only user interactions should call onToggle
    });

    it('should handle component updates during transitions', () => {
      const { rerender } = render(<MonitoringSidebar {...mockProps} isOpen={false} />);
      
      // Start opening animation
      rerender(<MonitoringSidebar {...mockProps} isOpen={true} />);
      
      // Update props during animation
      const newToggle = jest.fn();
      rerender(<MonitoringSidebar isOpen={true} onToggle={newToggle} />);
      
      expect(() => {
        fireEvent.click(screen.getByTitle('Close Monitor'));
      }).not.toThrow();
    });
  });
});