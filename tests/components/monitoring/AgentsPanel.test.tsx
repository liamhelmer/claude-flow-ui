import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../test-utils';
import { createMockAgent } from '../../test-utils';
import AgentsPanel from '@/components/monitoring/AgentsPanel';

const mockUseWebSocket = jest.requireMock('@/hooks/useWebSocket').useWebSocket;

describe('AgentsPanel Component', () => {
  const mockOnFn = jest.fn();
  const mockOffFn = jest.fn();

  const defaultWebSocketMock = {
    on: mockOnFn,
    off: mockOffFn,
    isConnected: true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseWebSocket.mockReturnValue(defaultWebSocketMock);
  });

  describe('Connection States', () => {
    it('should show disconnected state when not connected', () => {
      mockUseWebSocket.mockReturnValue({
        ...defaultWebSocketMock,
        isConnected: false,
      });

      render(<AgentsPanel />);
      
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should show no agents message initially', () => {
      render(<AgentsPanel />);
      
      expect(screen.getByText('No active agents')).toBeInTheDocument();
    });

    it('should register WebSocket event handlers on mount', () => {
      render(<AgentsPanel />);
      
      expect(mockOnFn).toHaveBeenCalledWith('agent-update', expect.any(Function));
      expect(mockOnFn).toHaveBeenCalledWith('agent-spawned', expect.any(Function));
      expect(mockOnFn).toHaveBeenCalledWith('agent-status', expect.any(Function));
    });

    it('should unregister WebSocket event handlers on unmount', () => {
      const { unmount } = render(<AgentsPanel />);
      
      unmount();
      
      expect(mockOffFn).toHaveBeenCalledWith('agent-update', expect.any(Function));
      expect(mockOffFn).toHaveBeenCalledWith('agent-spawned', expect.any(Function));
      expect(mockOffFn).toHaveBeenCalledWith('agent-status', expect.any(Function));
    });
  });

  describe('Agent Display', () => {
    it('should display agents when spawned', async () => {
      let agentSpawnedHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-spawned') {
          agentSpawnedHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const mockAgent = {
        agentId: 'agent-123',
        name: 'Test Agent',
        type: 'worker',
      };

      await waitFor(() => {
        agentSpawnedHandler(mockAgent);
      });

      await waitFor(() => {
        expect(screen.getByText('Test Agent')).toBeInTheDocument();
        expect(screen.getByText('Type: worker')).toBeInTheDocument();
        expect(screen.getByText('initializing')).toBeInTheDocument();
      });
    });

    it('should show agent state with correct styling and icons', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const agentStates = [
        { agentId: 'agent-1', state: 'idle' },
        { agentId: 'agent-2', state: 'busy' },
        { agentId: 'agent-3', state: 'error' },
      ];

      for (const agent of agentStates) {
        await waitFor(() => {
          agentStatusHandler(agent);
        });
      }

      await waitFor(() => {
        expect(screen.getByText('💤')).toBeInTheDocument(); // idle
        expect(screen.getByText('🔥')).toBeInTheDocument(); // busy
        expect(screen.getByText('❌')).toBeInTheDocument(); // error
      });
    });

    it('should display current task when available', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      await waitFor(() => {
        agentStatusHandler({
          agentId: 'agent-123',
          state: 'busy',
          currentTask: 'Processing user request',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('Task: Processing user request')).toBeInTheDocument();
      });
    });

    it('should show health indicators as colored bars', async () => {
      let agentUpdateHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-update') {
          agentUpdateHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const mockAgentData = createMockAgent('agent-123');
      await waitFor(() => {
        agentUpdateHandler({
          agentId: 'agent-123',
          agent: mockAgentData,
        });
      });

      await waitFor(() => {
        const healthBars = document.querySelectorAll('.h-1.bg-gray-700');
        expect(healthBars).toHaveLength(3); // responsiveness, performance, reliability
      });
    });
  });

  describe('Agent Selection', () => {
    it('should select agent when clicked', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      await waitFor(() => {
        agentStatusHandler({ agentId: 'agent-123', state: 'idle' });
      });

      await waitFor(() => {
        const agentElement = screen.getByText('Agent-agent-12');
        fireEvent.click(agentElement.closest('.cursor-pointer')!);
      });

      await waitFor(() => {
        expect(screen.getByText('Agent Details')).toBeInTheDocument();
      });
    });

    it('should show selected agent details', async () => {
      let agentUpdateHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-update') {
          agentUpdateHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const mockAgent = createMockAgent('agent-123456789');
      await waitFor(() => {
        agentUpdateHandler({
          agentId: 'agent-123456789',
          agent: {
            ...mockAgent,
            metrics: {
              tasksCompleted: 5,
              avgResponseTime: 150,
              errorRate: 0.1,
            },
          },
        });
      });

      // Select the agent
      await waitFor(() => {
        const agentElement = screen.getByText('Agent-agent-12');
        fireEvent.click(agentElement.closest('.cursor-pointer')!);
      });

      await waitFor(() => {
        expect(screen.getByText('agent-123456...')).toBeInTheDocument(); // truncated ID
        expect(screen.getByText('100%')).toBeInTheDocument(); // responsiveness
        expect(screen.getByText('5')).toBeInTheDocument(); // tasks completed
        expect(screen.getByText('150ms')).toBeInTheDocument(); // avg response time
      });
    });

    it('should highlight selected agent', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      await waitFor(() => {
        agentStatusHandler({ agentId: 'agent-123', state: 'idle' });
      });

      await waitFor(() => {
        const agentElement = screen.getByText('Agent-agent-12');
        const agentContainer = agentElement.closest('.cursor-pointer')!;
        fireEvent.click(agentContainer);
      });

      await waitFor(() => {
        const selectedAgent = document.querySelector('.border-blue-500.bg-blue-500\\/10');
        expect(selectedAgent).toBeInTheDocument();
      });
    });
  });

  describe('Agent State Management', () => {
    it('should handle agent updates correctly', async () => {
      let agentUpdateHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-update') {
          agentUpdateHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const initialAgent = createMockAgent('agent-123');
      const updatedAgent = { ...initialAgent, state: 'busy' as const };

      // Initial agent
      await waitFor(() => {
        agentUpdateHandler({ agentId: 'agent-123', agent: initialAgent });
      });

      // Updated agent
      await waitFor(() => {
        agentUpdateHandler({ agentId: 'agent-123', agent: updatedAgent });
      });

      await waitFor(() => {
        expect(screen.getByText('busy')).toBeInTheDocument();
      });
    });

    it('should create new agent if it does not exist in status update', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      await waitFor(() => {
        agentStatusHandler({
          agentId: 'new-agent-456',
          state: 'busy',
          currentTask: 'New task',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('Agent-new-agen')).toBeInTheDocument();
        expect(screen.getByText('busy')).toBeInTheDocument();
        expect(screen.getByText('Task: New task')).toBeInTheDocument();
      });
    });
  });

  describe('State Colors and Icons', () => {
    it('should use correct colors for different states', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const states = ['initializing', 'idle', 'busy', 'error', 'terminated'];
      
      for (let i = 0; i < states.length; i++) {
        await waitFor(() => {
          agentStatusHandler({
            agentId: `agent-${i}`,
            state: states[i],
          });
        });
      }

      await waitFor(() => {
        expect(document.querySelector('.text-blue-400')).toBeInTheDocument(); // initializing
        expect(document.querySelector('.text-gray-400')).toBeInTheDocument(); // idle
        expect(document.querySelector('.text-green-400')).toBeInTheDocument(); // busy
        expect(document.querySelector('.text-red-400')).toBeInTheDocument(); // error
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed agent data gracefully', async () => {
      let agentSpawnedHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-spawned') {
          agentSpawnedHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const malformedData = {
        // Missing agentId
        type: 'worker',
      };

      expect(() => {
        agentSpawnedHandler(malformedData);
      }).not.toThrow();
    });

    it('should handle undefined agent data in updates', async () => {
      let agentUpdateHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-update') {
          agentUpdateHandler = handler;
        }
      });

      render(<AgentsPanel />);

      expect(() => {
        agentUpdateHandler({ agentId: 'test', agent: null });
      }).not.toThrow();

      expect(() => {
        agentUpdateHandler({});
      }).not.toThrow();
    });
  });

  describe('Performance', () => {
    it('should handle many agents efficiently', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      const startTime = performance.now();
      
      // Create 50 agents
      for (let i = 0; i < 50; i++) {
        agentStatusHandler({
          agentId: `agent-${i}`,
          state: 'idle',
        });
      }

      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(200); // Should complete in <200ms

      await waitFor(() => {
        const agentElements = document.querySelectorAll('.cursor-pointer');
        expect(agentElements).toHaveLength(50);
      });
    });
  });

  describe('Accessibility', () => {
    it('should be keyboard navigable', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      await waitFor(() => {
        agentStatusHandler({ agentId: 'agent-123', state: 'idle' });
      });

      await waitFor(() => {
        const agentElement = document.querySelector('.cursor-pointer');
        expect(agentElement).toBeInTheDocument();
        
        // Should be clickable for keyboard users
        agentElement!.focus();
        expect(document.activeElement).toBe(agentElement);
      });
    });

    it('should have appropriate semantic structure', async () => {
      let agentStatusHandler: Function;

      mockOnFn.mockImplementation((event: string, handler: Function) => {
        if (event === 'agent-status') {
          agentStatusHandler = handler;
        }
      });

      render(<AgentsPanel />);

      await waitFor(() => {
        agentStatusHandler({ agentId: 'agent-123', state: 'idle' });
      });

      // Select agent to show details
      await waitFor(() => {
        const agentElement = screen.getByText('Agent-agent-12');
        fireEvent.click(agentElement.closest('.cursor-pointer')!);
      });

      await waitFor(() => {
        expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Agent Details');
      });
    });
  });
});