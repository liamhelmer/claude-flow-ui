import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { act } from '@testing-library/react';
import AgentsPanel from '../AgentsPanel';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the useWebSocket hook
jest.mock('@/hooks/useWebSocket');

const mockWebSocket = {
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
};

const mockAgent = {
  id: 'agent-123',
  type: 'worker',
  name: 'Test Agent',
  state: 'idle' as const,
  health: {
    responsiveness: 95,
    performance: 88,
    reliability: 100,
  },
  currentTask: 'Processing data',
  lastActivity: '2023-12-25T10:30:00Z',
  metrics: {
    tasksCompleted: 5,
    avgResponseTime: 150,
    errorRate: 2,
  },
};

const busyAgent = {
  ...mockAgent,
  id: 'agent-456',
  name: 'Busy Agent',
  state: 'busy' as const,
  currentTask: 'Analyzing logs',
  health: {
    responsiveness: 78,
    performance: 92,
    reliability: 85,
  },
};

const errorAgent = {
  ...mockAgent,
  id: 'agent-789',
  name: 'Error Agent',
  state: 'error' as const,
  currentTask: undefined,
  health: {
    responsiveness: 25,
    performance: 10,
    reliability: 0,
  },
};

describe('AgentsPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
  });

  describe('connection states', () => {
    it('should show disconnected state when not connected', () => {
      (useWebSocket as jest.Mock).mockReturnValue({
        ...mockWebSocket,
        isConnected: false,
      });

      render(<AgentsPanel />);

      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should show empty state when connected but no agents', () => {
      render(<AgentsPanel />);

      expect(screen.getByText('No active agents')).toBeInTheDocument();
    });
  });

  describe('agent rendering', () => {
    it('should render agent list correctly', () => {
      render(<AgentsPanel />);

      // Get the handler for agent-spawned event
      const agentSpawnedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-spawned')[1];

      // Simulate agent being spawned
      act(() => {
        agentSpawnedHandler({
          agentId: mockAgent.id,
          type: mockAgent.type,
          name: mockAgent.name,
        });
      });

      expect(screen.getByText('Test Agent')).toBeInTheDocument();
      expect(screen.getByText('Type: worker')).toBeInTheDocument();
      expect(screen.getByText('initializing')).toBeInTheDocument();
    });

    it('should render multiple agents', () => {
      render(<AgentsPanel />);

      const agentSpawnedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-spawned')[1];
      const agentStatusHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-status')[1];

      // Simulate multiple agents
      act(() => {
        agentSpawnedHandler({
          agentId: mockAgent.id,
          type: mockAgent.type,
          name: mockAgent.name,
        });
        agentSpawnedHandler({
          agentId: busyAgent.id,
          type: busyAgent.type,
          name: busyAgent.name,
        });
      });

      // Update statuses
      act(() => {
        agentStatusHandler({
          agentId: mockAgent.id,
          state: mockAgent.state,
          currentTask: mockAgent.currentTask,
        });
        agentStatusHandler({
          agentId: busyAgent.id,
          state: busyAgent.state,
          currentTask: busyAgent.currentTask,
        });
      });

      expect(screen.getByText('Test Agent')).toBeInTheDocument();
      expect(screen.getByText('Busy Agent')).toBeInTheDocument();
      expect(screen.getByText('idle')).toBeInTheDocument();
      expect(screen.getByText('busy')).toBeInTheDocument();
    });

    it('should display correct state icons and colors', () => {
      render(<AgentsPanel />);

      const agentSpawnedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-spawned')[1];
      const agentStatusHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-status')[1];

      // Spawn different state agents
      act(() => {
        agentSpawnedHandler({
          agentId: 'idle-agent',
          name: 'Idle Agent',
        });
        agentSpawnedHandler({
          agentId: 'busy-agent',
          name: 'Busy Agent',
        });
        agentSpawnedHandler({
          agentId: 'error-agent',
          name: 'Error Agent',
        });
      });

      act(() => {
        agentStatusHandler({ agentId: 'idle-agent', state: 'idle' });
        agentStatusHandler({ agentId: 'busy-agent', state: 'busy' });
        agentStatusHandler({ agentId: 'error-agent', state: 'error' });
      });

      // Check for state badges
      expect(screen.getByText('idle')).toBeInTheDocument();
      expect(screen.getByText('busy')).toBeInTheDocument();
      expect(screen.getByText('error')).toBeInTheDocument();

      // Check for icons (emojis)
      expect(screen.getByText('💤')).toBeInTheDocument(); // idle
      expect(screen.getByText('🔥')).toBeInTheDocument(); // busy
      expect(screen.getByText('❌')).toBeInTheDocument(); // error
    });

    it('should display current task when available', () => {
      render(<AgentsPanel />);

      const agentStatusHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-status')[1];

      act(() => {
        agentStatusHandler({
          agentId: 'task-agent',
          state: 'busy',
          currentTask: 'Processing important data',
        });
      });

      expect(screen.getByText('Task: Processing important data')).toBeInTheDocument();
    });

    it('should not display task section when no current task', () => {
      render(<AgentsPanel />);

      const agentStatusHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-status')[1];

      act(() => {
        agentStatusHandler({
          agentId: 'no-task-agent',
          state: 'idle',
        });
      });

      expect(screen.queryByText(/Task:/)).not.toBeInTheDocument();
    });
  });

  describe('agent selection and details', () => {
    it('should select agent when clicked', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: mockAgent.id,
          agent: mockAgent,
        });
      });

      const agentCard = screen.getByText('Test Agent').closest('div[role="button"], div');
      expect(agentCard).toBeInTheDocument();

      act(() => {
        fireEvent.click(agentCard!);
      });

      // Should show agent details
      expect(screen.getByText('Agent Details')).toBeInTheDocument();
      expect(screen.getByText(/agent-123/)).toBeInTheDocument();
    });

    it('should display agent details correctly', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: mockAgent.id,
          agent: mockAgent,
        });
      });

      // Select the agent
      const agentCard = screen.getByText('Test Agent').closest('div');
      act(() => {
        fireEvent.click(agentCard!);
      });

      // Check agent details
      expect(screen.getByText('Agent Details')).toBeInTheDocument();
      expect(screen.getByText('95%')).toBeInTheDocument(); // responsiveness
      expect(screen.getByText('88%')).toBeInTheDocument(); // performance
      expect(screen.getByText('100%')).toBeInTheDocument(); // reliability
    });

    it('should display agent metrics when available', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: mockAgent.id,
          agent: mockAgent,
        });
      });

      // Select the agent
      const agentCard = screen.getByText('Test Agent').closest('div');
      act(() => {
        fireEvent.click(agentCard!);
      });

      // Check metrics
      expect(screen.getByText('5')).toBeInTheDocument(); // tasks completed
      expect(screen.getByText('150ms')).toBeInTheDocument(); // avg response time
    });

    it('should not display metrics section when unavailable', () => {
      const agentWithoutMetrics = { ...mockAgent, metrics: undefined };
      
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: agentWithoutMetrics.id,
          agent: agentWithoutMetrics,
        });
      });

      // Select the agent
      const agentCard = screen.getByText('Test Agent').closest('div');
      act(() => {
        fireEvent.click(agentCard!);
      });

      expect(screen.queryByText('Tasks:')).not.toBeInTheDocument();
      expect(screen.queryByText('Avg Response:')).not.toBeInTheDocument();
    });

    it('should update selected agent highlighting', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({ agentId: mockAgent.id, agent: mockAgent });
        agentUpdateHandler({ agentId: busyAgent.id, agent: busyAgent });
      });

      const firstAgentCard = screen.getByText('Test Agent').closest('div');
      const secondAgentCard = screen.getByText('Busy Agent').closest('div');

      // Select first agent
      act(() => {
        fireEvent.click(firstAgentCard!);
      });

      expect(firstAgentCard).toHaveClass('border-blue-500');
      expect(secondAgentCard).not.toHaveClass('border-blue-500');

      // Select second agent
      act(() => {
        fireEvent.click(secondAgentCard!);
      });

      expect(firstAgentCard).not.toHaveClass('border-blue-500');
      expect(secondAgentCard).toHaveClass('border-blue-500');
    });
  });

  describe('health indicators', () => {
    it('should render health bars with correct widths', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: mockAgent.id,
          agent: mockAgent,
        });
      });

      const healthBars = screen.container.querySelectorAll('.h-1.bg-green-500, .h-1.bg-blue-500, .h-1.bg-purple-500');
      
      expect(healthBars).toHaveLength(3);
      expect(healthBars[0]).toHaveStyle({ width: '95%' }); // responsiveness
      expect(healthBars[1]).toHaveStyle({ width: '88%' }); // performance
      expect(healthBars[2]).toHaveStyle({ width: '100%' }); // reliability
    });

    it('should handle zero health values', () => {
      const unhealthyAgent = {
        ...mockAgent,
        health: {
          responsiveness: 0,
          performance: 0,
          reliability: 0,
        },
      };

      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: unhealthyAgent.id,
          agent: unhealthyAgent,
        });
      });

      const healthBars = screen.container.querySelectorAll('.h-1.bg-green-500, .h-1.bg-blue-500, .h-1.bg-purple-500');
      
      expect(healthBars).toHaveLength(3);
      healthBars.forEach(bar => {
        expect(bar).toHaveStyle({ width: '0%' });
      });
    });
  });

  describe('event handling', () => {
    it('should set up WebSocket event listeners on mount', () => {
      render(<AgentsPanel />);

      expect(mockWebSocket.on).toHaveBeenCalledWith('agent-update', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('agent-spawned', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('agent-status', expect.any(Function));
    });

    it('should clean up event listeners on unmount', () => {
      const { unmount } = render(<AgentsPanel />);

      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('agent-update', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('agent-spawned', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('agent-status', expect.any(Function));
    });

    it('should handle agent-update events', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      act(() => {
        agentUpdateHandler({
          agentId: mockAgent.id,
          agent: mockAgent,
        });
      });

      expect(screen.getByText('Test Agent')).toBeInTheDocument();
    });

    it('should handle agent-spawned events', () => {
      render(<AgentsPanel />);

      const agentSpawnedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-spawned')[1];

      act(() => {
        agentSpawnedHandler({
          agentId: 'new-agent-id',
          type: 'analyzer',
          name: 'New Agent',
        });
      });

      expect(screen.getByText('New Agent')).toBeInTheDocument();
      expect(screen.getByText('Type: analyzer')).toBeInTheDocument();
      expect(screen.getByText('initializing')).toBeInTheDocument();
    });

    it('should handle agent-status events for existing agents', () => {
      render(<AgentsPanel />);

      const agentSpawnedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-spawned')[1];
      const agentStatusHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-status')[1];

      // First spawn an agent
      act(() => {
        agentSpawnedHandler({
          agentId: 'status-agent',
          name: 'Status Agent',
        });
      });

      // Then update its status
      act(() => {
        agentStatusHandler({
          agentId: 'status-agent',
          state: 'busy',
          currentTask: 'Updating status',
        });
      });

      expect(screen.getByText('busy')).toBeInTheDocument();
      expect(screen.getByText('Task: Updating status')).toBeInTheDocument();
    });

    it('should handle agent-status events for non-existing agents', () => {
      render(<AgentsPanel />);

      const agentStatusHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-status')[1];

      // Update status for non-existing agent (should create it)
      act(() => {
        agentStatusHandler({
          agentId: 'unknown-agent',
          state: 'error',
          currentTask: 'Unknown task',
        });
      });

      expect(screen.getByText('Agent-unknown-a')).toBeInTheDocument(); // truncated name
      expect(screen.getByText('error')).toBeInTheDocument();
      expect(screen.getByText('Task: Unknown task')).toBeInTheDocument();
    });
  });

  describe('edge cases', () => {
    it('should handle missing agentId in update events', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      expect(() => {
        act(() => {
          agentUpdateHandler({
            agent: mockAgent,
            // missing agentId
          });
        });
      }).not.toThrow();
    });

    it('should handle missing agent data in update events', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      expect(() => {
        act(() => {
          agentUpdateHandler({
            agentId: 'test-agent',
            // missing agent data
          });
        });
      }).not.toThrow();
    });

    it('should handle empty agent name', () => {
      render(<AgentsPanel />);

      const agentSpawnedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-spawned')[1];

      act(() => {
        agentSpawnedHandler({
          agentId: 'nameless-agent-id',
          type: 'worker',
          // name is missing, should use default
        });
      });

      expect(screen.getByText('Agent-nameless-')).toBeInTheDocument();
    });

    it('should truncate agent ID display correctly', () => {
      render(<AgentsPanel />);

      const agentUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'agent-update')[1];

      const longIdAgent = {
        ...mockAgent,
        id: 'very-long-agent-id-that-should-be-truncated-in-details',
      };

      act(() => {
        agentUpdateHandler({
          agentId: longIdAgent.id,
          agent: longIdAgent,
        });
      });

      // Select the agent to see details
      const agentCard = screen.getByText('Test Agent').closest('div');
      act(() => {
        fireEvent.click(agentCard!);
      });

      // Should show truncated ID
      expect(screen.getByText(/very-long-ag\.\.\./)).toBeInTheDocument();
    });
  });
});