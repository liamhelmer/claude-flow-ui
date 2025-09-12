import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import AgentsPanel from '@/components/monitoring/AgentsPanel';

// Mock the useWebSocket hook
const mockUseWebSocket = {
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
};

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => mockUseWebSocket,
}));

describe('AgentsPanel - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUseWebSocket.isConnected = true;
  });

  describe('Connection State Handling', () => {
    it('shows disconnected state when WebSocket is not connected', () => {
      mockUseWebSocket.isConnected = false;

      render(<AgentsPanel />);

      expect(screen.getByText('Disconnected')).toBeInTheDocument();
      expect(screen.queryByText('No active agents')).not.toBeInTheDocument();
    });

    it('shows agent panel content when connected', () => {
      mockUseWebSocket.isConnected = true;

      render(<AgentsPanel />);

      expect(screen.queryByText('Disconnected')).not.toBeInTheDocument();
      expect(screen.getByText('No active agents')).toBeInTheDocument();
    });

    it('registers event listeners on mount', () => {
      render(<AgentsPanel />);

      expect(mockUseWebSocket.on).toHaveBeenCalledWith('agent-update', expect.any(Function));
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('agent-spawned', expect.any(Function));
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('agent-status', expect.any(Function));
    });

    it('removes event listeners on unmount', () => {
      const { unmount } = render(<AgentsPanel />);

      unmount();

      expect(mockUseWebSocket.off).toHaveBeenCalledWith('agent-update', expect.any(Function));
      expect(mockUseWebSocket.off).toHaveBeenCalledWith('agent-spawned', expect.any(Function));
      expect(mockUseWebSocket.off).toHaveBeenCalledWith('agent-status', expect.any(Function));
    });
  });

  describe('Agent Management', () => {
    it('handles agent spawned events', () => {
      render(<AgentsPanel />);

      // Get the handler function
      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(
        call => call[0] === 'agent-spawned'
      )?.[1];

      act(() => {
        spawnedHandler({
          agentId: 'agent-1',
          type: 'researcher',
          name: 'Research Agent',
        });
      });

      expect(screen.getByText('Research Agent')).toBeInTheDocument();
      expect(screen.getByText('Type: researcher')).toBeInTheDocument();
      expect(screen.getByText('initializing')).toBeInTheDocument();
    });

    it('handles agent spawned with default values', () => {
      render(<AgentsPanel />);

      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];

      act(() => {\n        spawnedHandler({\n          agentId: 'agent-2',\n        });\n      });

      expect(screen.getByText('Agent-agent-2')).toBeInTheDocument();\n      expect(screen.getByText('Type: worker')).toBeInTheDocument();\n      expect(screen.getByText('initializing')).toBeInTheDocument();\n    });\n\n    it('handles agent update events', () => {\n      render(<AgentsPanel />);\n\n      const updateHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-update'\n      )?.[1];\n\n      // First spawn an agent\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      act(() => {\n        spawnedHandler({\n          agentId: 'agent-1',\n          type: 'researcher',\n          name: 'Research Agent',\n        });\n      });\n\n      // Then update it\n      const updatedAgent = {\n        id: 'agent-1',\n        type: 'researcher',\n        name: 'Updated Research Agent',\n        state: 'busy',\n        health: {\n          responsiveness: 95,\n          performance: 90,\n          reliability: 100,\n        },\n        currentTask: 'Analyzing data',\n      };\n\n      act(() => {\n        updateHandler({\n          agentId: 'agent-1',\n          agent: updatedAgent,\n        });\n      });\n\n      expect(screen.getByText('Updated Research Agent')).toBeInTheDocument();\n      expect(screen.getByText('busy')).toBeInTheDocument();\n      expect(screen.getByText('Task: Analyzing data')).toBeInTheDocument();\n    });\n\n    it('handles agent status events for existing agents', () => {\n      render(<AgentsPanel />);\n\n      const statusHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-status'\n      )?.[1];\n\n      // First spawn an agent\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      act(() => {\n        spawnedHandler({\n          agentId: 'agent-1',\n          type: 'researcher',\n          name: 'Research Agent',\n        });\n      });\n\n      // Update status\n      act(() => {\n        statusHandler({\n          agentId: 'agent-1',\n          state: 'busy',\n          currentTask: 'Processing request',\n        });\n      });\n\n      expect(screen.getByText('busy')).toBeInTheDocument();\n      expect(screen.getByText('Task: Processing request')).toBeInTheDocument();\n    });\n\n    it('creates new agent from status event if not exists', () => {\n      render(<AgentsPanel />);\n\n      const statusHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-status'\n      )?.[1];\n\n      act(() => {\n        statusHandler({\n          agentId: 'new-agent',\n          state: 'idle',\n          currentTask: 'Waiting for task',\n        });\n      });\n\n      expect(screen.getByText('Agent-new-agen')).toBeInTheDocument();\n      expect(screen.getByText('Type: worker')).toBeInTheDocument();\n      expect(screen.getByText('idle')).toBeInTheDocument();\n      expect(screen.getByText('Task: Waiting for task')).toBeInTheDocument();\n    });\n  });\n\n  describe('Agent Display and Interaction', () => {\n    beforeEach(() => {\n      // Set up a test agent\n      render(<AgentsPanel />);\n\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      act(() => {\n        spawnedHandler({\n          agentId: 'test-agent',\n          type: 'researcher',\n          name: 'Test Agent',\n        });\n      });\n    });\n\n    it('displays agent with correct styling based on state', () => {\n      const agentCard = screen.getByText('Test Agent').closest('div');\n      expect(agentCard).toHaveClass('cursor-pointer', 'transition-all');\n    });\n\n    it('shows agent health indicators', () => {\n      // Health bars should be present\n      const healthBars = document.querySelectorAll('.h-1.bg-gray-700');\n      expect(healthBars).toHaveLength(3); // responsiveness, performance, reliability\n    });\n\n    it('displays agent state with correct icon and color', () => {\n      expect(screen.getByText('⚙️')).toBeInTheDocument(); // initializing icon\n      expect(screen.getByText('initializing')).toBeInTheDocument();\n\n      const statusBadge = screen.getByText('initializing');\n      expect(statusBadge).toHaveClass('text-blue-400', 'bg-blue-400/10');\n    });\n\n    it('handles agent selection', () => {\n      const agentCard = screen.getByText('Test Agent').closest('div');\n      \n      fireEvent.click(agentCard!);\n\n      // Should show agent details\n      expect(screen.getByText('Agent Details')).toBeInTheDocument();\n      expect(screen.getByText('ID:')).toBeInTheDocument();\n      expect(screen.getByText('Responsiveness:')).toBeInTheDocument();\n    });\n\n    it('shows selected agent with different styling', () => {\n      const agentCard = screen.getByText('Test Agent').closest('div');\n      \n      fireEvent.click(agentCard!);\n\n      expect(agentCard).toHaveClass('border-blue-500', 'bg-blue-500/10');\n    });\n\n    it('displays task information when available', () => {\n      const statusHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-status'\n      )?.[1];\n\n      act(() => {\n        statusHandler({\n          agentId: 'test-agent',\n          state: 'busy',\n          currentTask: 'Analyzing requirements',\n        });\n      });\n\n      expect(screen.getByText('Task: Analyzing requirements')).toBeInTheDocument();\n    });\n  });\n\n  describe('Agent Details Panel', () => {\n    beforeEach(() => {\n      render(<AgentsPanel />);\n\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      act(() => {\n        spawnedHandler({\n          agentId: 'detailed-agent',\n          type: 'researcher',\n          name: 'Detailed Agent',\n        });\n      });\n\n      // Update with full details\n      const updateHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-update'\n      )?.[1];\n\n      act(() => {\n        updateHandler({\n          agentId: 'detailed-agent',\n          agent: {\n            id: 'detailed-agent',\n            type: 'researcher',\n            name: 'Detailed Agent',\n            state: 'busy',\n            health: {\n              responsiveness: 85,\n              performance: 92,\n              reliability: 98,\n            },\n            currentTask: 'Research task',\n            metrics: {\n              tasksCompleted: 15,\n              avgResponseTime: 250,\n              errorRate: 0.02,\n            },\n          },\n        });\n      });\n    });\n\n    it('shows detailed agent information when selected', () => {\n      const agentCard = screen.getByText('Detailed Agent').closest('div');\n      fireEvent.click(agentCard!);\n\n      expect(screen.getByText('Agent Details')).toBeInTheDocument();\n      expect(screen.getByText('85%')).toBeInTheDocument(); // responsiveness\n      expect(screen.getByText('92%')).toBeInTheDocument(); // performance\n      expect(screen.getByText('98%')).toBeInTheDocument(); // reliability\n    });\n\n    it('displays agent metrics when available', () => {\n      const agentCard = screen.getByText('Detailed Agent').closest('div');\n      fireEvent.click(agentCard!);\n\n      expect(screen.getByText('Tasks:')).toBeInTheDocument();\n      expect(screen.getByText('15')).toBeInTheDocument();\n      expect(screen.getByText('Avg Response:')).toBeInTheDocument();\n      expect(screen.getByText('250ms')).toBeInTheDocument();\n    });\n\n    it('truncates long agent IDs in details', () => {\n      const agentCard = screen.getByText('Detailed Agent').closest('div');\n      fireEvent.click(agentCard!);\n\n      // Should show truncated ID (first 12 chars + ...)\n      expect(screen.getByText('detailed-age...')).toBeInTheDocument();\n    });\n\n    it('hides details panel when no agent is selected', () => {\n      expect(screen.queryByText('Agent Details')).not.toBeInTheDocument();\n    });\n  });\n\n  describe('Agent State Management', () => {\n    const stateTestCases = [\n      { state: 'initializing', icon: '⚙️', color: 'text-blue-400' },\n      { state: 'idle', icon: '💤', color: 'text-gray-400' },\n      { state: 'busy', icon: '🔥', color: 'text-green-400' },\n      { state: 'error', icon: '❌', color: 'text-red-400' },\n      { state: 'terminated', icon: '⛔', color: 'text-gray-600' },\n    ];\n\n    stateTestCases.forEach(({ state, icon, color }) => {\n      it(`displays correct icon and color for ${state} state`, () => {\n        render(<AgentsPanel />);\n\n        const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n          call => call[0] === 'agent-spawned'\n        )?.[1];\n\n        act(() => {\n          spawnedHandler({\n            agentId: `agent-${state}`,\n            type: 'worker',\n            name: `Agent ${state}`,\n          });\n        });\n\n        const statusHandler = mockUseWebSocket.on.mock.calls.find(\n          call => call[0] === 'agent-status'\n        )?.[1];\n\n        act(() => {\n          statusHandler({\n            agentId: `agent-${state}`,\n            state: state,\n          });\n        });\n\n        expect(screen.getByText(icon)).toBeInTheDocument();\n        const statusBadge = screen.getByText(state);\n        expect(statusBadge).toHaveClass(color);\n      });\n    });\n  });\n\n  describe('Error Handling and Edge Cases', () => {\n    it('handles missing agent data gracefully', () => {\n      render(<AgentsPanel />);\n\n      const updateHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-update'\n      )?.[1];\n\n      expect(() => {\n        act(() => {\n          updateHandler({\n            agentId: 'missing-agent',\n            agent: null,\n          });\n        });\n      }).not.toThrow();\n    });\n\n    it('handles malformed agent data', () => {\n      render(<AgentsPanel />);\n\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      expect(() => {\n        act(() => {\n          spawnedHandler({\n            // Missing required fields\n          });\n        });\n      }).not.toThrow();\n    });\n\n    it('handles agent updates for non-existent agents', () => {\n      render(<AgentsPanel />);\n\n      const updateHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-update'\n      )?.[1];\n\n      expect(() => {\n        act(() => {\n          updateHandler({\n            agentId: 'non-existent',\n            agent: {\n              id: 'non-existent',\n              name: 'Ghost Agent',\n              type: 'phantom',\n              state: 'idle',\n              health: { responsiveness: 100, performance: 100, reliability: 100 },\n            },\n          });\n        });\n      }).not.toThrow();\n    });\n\n    it('maintains agent order when updating', () => {\n      render(<AgentsPanel />);\n\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      // Spawn multiple agents\n      act(() => {\n        spawnedHandler({ agentId: 'agent-1', name: 'Agent 1' });\n        spawnedHandler({ agentId: 'agent-2', name: 'Agent 2' });\n        spawnedHandler({ agentId: 'agent-3', name: 'Agent 3' });\n      });\n\n      const agentNames = screen.getAllByText(/Agent \\d/).map(el => el.textContent);\n      expect(agentNames).toEqual(['Agent 1', 'Agent 2', 'Agent 3']);\n\n      // Update middle agent\n      const updateHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-update'\n      )?.[1];\n\n      act(() => {\n        updateHandler({\n          agentId: 'agent-2',\n          agent: {\n            id: 'agent-2',\n            name: 'Updated Agent 2',\n            type: 'worker',\n            state: 'busy',\n            health: { responsiveness: 100, performance: 100, reliability: 100 },\n          },\n        });\n      });\n\n      const updatedNames = screen.getAllByText(/Agent \\d|Updated Agent \\d/).map(el => el.textContent);\n      expect(updatedNames).toEqual(['Agent 1', 'Updated Agent 2', 'Agent 3']);\n    });\n  });\n\n  describe('Performance and Optimization', () => {\n    it('handles rapid agent updates without performance issues', () => {\n      render(<AgentsPanel />);\n\n      const updateHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-update'\n      )?.[1];\n\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      // Spawn an agent first\n      act(() => {\n        spawnedHandler({\n          agentId: 'rapid-agent',\n          name: 'Rapid Agent',\n        });\n      });\n\n      // Perform many rapid updates\n      act(() => {\n        for (let i = 0; i < 100; i++) {\n          updateHandler({\n            agentId: 'rapid-agent',\n            agent: {\n              id: 'rapid-agent',\n              name: `Rapid Agent ${i}`,\n              type: 'worker',\n              state: i % 2 === 0 ? 'busy' : 'idle',\n              health: {\n                responsiveness: Math.random() * 100,\n                performance: Math.random() * 100,\n                reliability: Math.random() * 100,\n              },\n            },\n          });\n        }\n      });\n\n      // Should still render correctly\n      expect(screen.getByText('Rapid Agent 99')).toBeInTheDocument();\n    });\n\n    it('efficiently manages large numbers of agents', () => {\n      render(<AgentsPanel />);\n\n      const spawnedHandler = mockUseWebSocket.on.mock.calls.find(\n        call => call[0] === 'agent-spawned'\n      )?.[1];\n\n      // Spawn many agents\n      act(() => {\n        for (let i = 0; i < 50; i++) {\n          spawnedHandler({\n            agentId: `agent-${i}`,\n            name: `Agent ${i}`,\n            type: 'worker',\n          });\n        }\n      });\n\n      // Should render all agents\n      expect(screen.getAllByText(/Agent \\d+/)).toHaveLength(50);\n    });\n  });\n});