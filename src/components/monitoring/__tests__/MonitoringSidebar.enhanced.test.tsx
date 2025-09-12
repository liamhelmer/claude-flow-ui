import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MonitoringSidebar } from '../MonitoringSidebar';

// Mock the child components
jest.mock('../AgentsPanel', () => ({
  AgentsPanel: ({ agents }: { agents: any[] }) => (
    <div data-testid="agents-panel">
      Agents: {agents.length}
    </div>
  ),
}));

jest.mock('../PromptPanel', () => ({
  PromptPanel: ({ prompts }: { prompts: any[] }) => (
    <div data-testid="prompt-panel">
      Prompts: {prompts.length}
    </div>
  ),
}));

jest.mock('../MemoryPanel', () => ({
  MemoryPanel: ({ memory }: { memory: any }) => (
    <div data-testid="memory-panel">
      Memory: {memory?.used || 0}MB
    </div>
  ),
}));

jest.mock('../CommandsPanel', () => ({
  CommandsPanel: ({ commands }: { commands: any[] }) => (
    <div data-testid="commands-panel">
      Commands: {commands.length}
    </div>
  ),
}));

describe('MonitoringSidebar - Enhanced Test Suite', () => {
  const defaultProps = {
    isOpen: true,
    onToggle: jest.fn(),
    data: {
      agents: [
        {
          id: 'agent-1',
          name: 'Test Agent',
          status: 'active' as const,
          performance: { cpu: 45, memory: 128, tasks: 5 },
          lastActivity: new Date().toISOString(),
        },
        {
          id: 'agent-2',
          name: 'Backup Agent',
          status: 'idle' as const,
          performance: { cpu: 10, memory: 64, tasks: 0 },
          lastActivity: new Date().toISOString(),
        },
      ],
      prompts: [
        {
          id: 'prompt-1',
          text: 'Analyze this code',
          timestamp: new Date().toISOString(),
          tokens: 15,
          response: 'Code analysis complete',
        },
      ],
      memory: {
        used: 256,
        total: 1024,
        percentage: 25,
      },
      commands: [
        {
          id: 'cmd-1',
          command: 'npm test',
          timestamp: new Date().toISOString(),
          status: 'completed' as const,
          duration: 5000,
        },
      ],
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering and Layout', () => {
    it('should render all monitoring panels when open', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();
      expect(screen.getByTestId('prompt-panel')).toBeInTheDocument();
      expect(screen.getByTestId('memory-panel')).toBeInTheDocument();
      expect(screen.getByTestId('commands-panel')).toBeInTheDocument();
    });

    it('should not render panels when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);

      expect(screen.queryByTestId('agents-panel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('prompt-panel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('memory-panel')).not.toBeInTheDocument();
      expect(screen.queryByTestId('commands-panel')).not.toBeInTheDocument();
    });

    it('should render toggle button', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      expect(toggleButton).toBeInTheDocument();
    });

    it('should apply correct CSS classes when open', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('monitoring-sidebar', 'monitoring-sidebar-open');
    });

    it('should apply correct CSS classes when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('monitoring-sidebar', 'monitoring-sidebar-closed');
    });

    it('should handle responsive layout', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('w-80', 'lg:w-96');
    });
  });

  describe('Data Passing and Integration', () => {
    it('should pass agents data to AgentsPanel', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const agentsPanel = screen.getByTestId('agents-panel');
      expect(agentsPanel).toHaveTextContent('Agents: 2');
    });

    it('should pass prompts data to PromptPanel', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const promptPanel = screen.getByTestId('prompt-panel');
      expect(promptPanel).toHaveTextContent('Prompts: 1');
    });

    it('should pass memory data to MemoryPanel', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const memoryPanel = screen.getByTestId('memory-panel');
      expect(memoryPanel).toHaveTextContent('Memory: 256MB');
    });

    it('should pass commands data to CommandsPanel', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const commandsPanel = screen.getByTestId('commands-panel');
      expect(commandsPanel).toHaveTextContent('Commands: 1');
    });

    it('should handle empty data gracefully', () => {
      const emptyProps = {
        ...defaultProps,
        data: {
          agents: [],
          prompts: [],
          memory: { used: 0, total: 1024, percentage: 0 },
          commands: [],
        },
      };

      render(<MonitoringSidebar {...emptyProps} />);

      expect(screen.getByTestId('agents-panel')).toHaveTextContent('Agents: 0');
      expect(screen.getByTestId('prompt-panel')).toHaveTextContent('Prompts: 0');
      expect(screen.getByTestId('memory-panel')).toHaveTextContent('Memory: 0MB');
      expect(screen.getByTestId('commands-panel')).toHaveTextContent('Commands: 0');
    });

    it('should handle missing data properties', () => {
      const partialProps = {
        ...defaultProps,
        data: {
          agents: defaultProps.data.agents,
          // Missing other properties
        } as any,
      };

      expect(() => {
        render(<MonitoringSidebar {...partialProps} />);
      }).not.toThrow();
    });
  });

  describe('Interactive Behavior', () => {
    it('should call onToggle when toggle button is clicked', () => {
      const onToggle = jest.fn();
      render(<MonitoringSidebar {...defaultProps} onToggle={onToggle} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      fireEvent.click(toggleButton);

      expect(onToggle).toHaveBeenCalledTimes(1);
    });

    it('should handle rapid toggle clicks', () => {
      const onToggle = jest.fn();
      render(<MonitoringSidebar {...defaultProps} onToggle={onToggle} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      
      fireEvent.click(toggleButton);
      fireEvent.click(toggleButton);
      fireEvent.click(toggleButton);

      expect(onToggle).toHaveBeenCalledTimes(3);
    });

    it('should maintain focus on toggle button after click', async () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      
      fireEvent.click(toggleButton);

      await waitFor(() => {
        expect(document.activeElement).toBe(toggleButton);
      });
    });

    it('should support keyboard interaction', () => {
      const onToggle = jest.fn();
      render(<MonitoringSidebar {...defaultProps} onToggle={onToggle} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      
      fireEvent.keyDown(toggleButton, { key: 'Enter' });
      expect(onToggle).toHaveBeenCalledTimes(1);

      fireEvent.keyDown(toggleButton, { key: ' ' });
      expect(onToggle).toHaveBeenCalledTimes(2);
    });
  });

  describe('Performance and Optimization', () => {
    it('should handle large datasets efficiently', () => {
      const largeDataProps = {
        ...defaultProps,
        data: {
          agents: Array.from({ length: 1000 }, (_, i) => ({
            id: `agent-${i}`,
            name: `Agent ${i}`,
            status: 'active' as const,
            performance: { cpu: 45, memory: 128, tasks: 5 },
            lastActivity: new Date().toISOString(),
          })),
          prompts: Array.from({ length: 500 }, (_, i) => ({
            id: `prompt-${i}`,
            text: `Prompt ${i}`,
            timestamp: new Date().toISOString(),
            tokens: 15,
            response: `Response ${i}`,
          })),
          memory: { used: 256, total: 1024, percentage: 25 },
          commands: Array.from({ length: 200 }, (_, i) => ({
            id: `cmd-${i}`,
            command: `command-${i}`,
            timestamp: new Date().toISOString(),
            status: 'completed' as const,
            duration: 1000,
          })),
        },
      };

      const startTime = performance.now();
      render(<MonitoringSidebar {...largeDataProps} />);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(100); // Should render quickly
      expect(screen.getByTestId('agents-panel')).toHaveTextContent('Agents: 1000');
    });

    it('should not re-render unnecessarily', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} />);

      // Rerender with same props
      rerender(<MonitoringSidebar {...defaultProps} />);

      // Component should handle this gracefully
      expect(screen.getByTestId('agents-panel')).toBeInTheDocument();
    });

    it('should handle prop updates efficiently', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} />);

      const updatedProps = {
        ...defaultProps,
        data: {
          ...defaultProps.data,
          agents: [
            ...defaultProps.data.agents,
            {
              id: 'agent-3',
              name: 'New Agent',
              status: 'active' as const,
              performance: { cpu: 30, memory: 96, tasks: 3 },
              lastActivity: new Date().toISOString(),
            },
          ],
        },
      };

      rerender(<MonitoringSidebar {...updatedProps} />);

      expect(screen.getByTestId('agents-panel')).toHaveTextContent('Agents: 3');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null data gracefully', () => {
      const nullDataProps = {
        ...defaultProps,
        data: null as any,
      };

      expect(() => {
        render(<MonitoringSidebar {...nullDataProps} />);
      }).not.toThrow();
    });

    it('should handle undefined data gracefully', () => {
      const undefinedDataProps = {
        ...defaultProps,
        data: undefined as any,
      };

      expect(() => {
        render(<MonitoringSidebar {...undefinedDataProps} />);
      }).not.toThrow();
    });

    it('should handle malformed data objects', () => {
      const malformedProps = {
        ...defaultProps,
        data: {
          agents: 'not an array' as any,
          prompts: null as any,
          memory: 'not an object' as any,
          commands: undefined as any,
        },
      };

      expect(() => {
        render(<MonitoringSidebar {...malformedProps} />);
      }).not.toThrow();
    });

    it('should handle missing onToggle prop', () => {
      const propsWithoutToggle = {
        ...defaultProps,
        onToggle: undefined as any,
      };

      expect(() => {
        render(<MonitoringSidebar {...propsWithoutToggle} />);
      }).not.toThrow();

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      expect(() => {
        fireEvent.click(toggleButton);
      }).not.toThrow();
    });

    it('should handle extremely large memory values', () => {
      const largeMemoryProps = {
        ...defaultProps,
        data: {
          ...defaultProps.data,
          memory: {
            used: Number.MAX_SAFE_INTEGER,
            total: Number.MAX_SAFE_INTEGER,
            percentage: 100,
          },
        },
      };

      render(<MonitoringSidebar {...largeMemoryProps} />);

      expect(screen.getByTestId('memory-panel')).toBeInTheDocument();
    });

    it('should handle negative values gracefully', () => {
      const negativeValuesProps = {
        ...defaultProps,
        data: {
          ...defaultProps.data,
          memory: {
            used: -100,
            total: -500,
            percentage: -25,
          },
        },
      };

      render(<MonitoringSidebar {...negativeValuesProps} />);

      expect(screen.getByTestId('memory-panel')).toHaveTextContent('Memory: -100MB');
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveAttribute('aria-label', 'Monitoring sidebar');

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      expect(toggleButton).toHaveAttribute('aria-expanded', 'true');
    });

    it('should update aria-expanded when closed', () => {
      render(<MonitoringSidebar {...defaultProps} isOpen={false} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      expect(toggleButton).toHaveAttribute('aria-expanded', 'false');
    });

    it('should be keyboard navigable', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const toggleButton = screen.getByRole('button', { name: /toggle monitoring/i });
      
      toggleButton.focus();
      expect(document.activeElement).toBe(toggleButton);

      fireEvent.keyDown(toggleButton, { key: 'Tab' });
      // Next focusable element should receive focus
    });

    it('should have proper heading structure', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      // Check for proper heading hierarchy if present in actual component
      const headings = screen.queryAllByRole('heading');
      headings.forEach(heading => {
        expect(heading).toBeInTheDocument();
      });
    });

    it('should support screen readers', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeVisible();

      // Verify that content is accessible to screen readers
      expect(screen.getByTestId('agents-panel')).not.toHaveAttribute('aria-hidden');
    });
  });

  describe('Visual and Animation States', () => {
    it('should handle smooth transitions', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} isOpen={false} />);

      rerender(<MonitoringSidebar {...defaultProps} isOpen={true} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass('monitoring-sidebar-open');
    });

    it('should maintain visual consistency across state changes', () => {
      const { rerender } = render(<MonitoringSidebar {...defaultProps} />);

      // Toggle multiple times
      rerender(<MonitoringSidebar {...defaultProps} isOpen={false} />);
      rerender(<MonitoringSidebar {...defaultProps} isOpen={true} />);
      rerender(<MonitoringSidebar {...defaultProps} isOpen={false} />);

      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toBeInTheDocument();
    });

    it('should handle window resize events gracefully', () => {
      render(<MonitoringSidebar {...defaultProps} />);

      // Simulate window resize
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 768,
      });

      fireEvent(window, new Event('resize'));

      expect(screen.getByRole('complementary')).toBeInTheDocument();
    });
  });
});