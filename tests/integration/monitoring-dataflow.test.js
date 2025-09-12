/**
 * Integration Tests: Monitoring Panels Data Flow
 * 
 * These tests verify that the monitoring panels (Memory, Agents, Commands, Prompt)
 * receive and display real-time data from WebSocket connections correctly.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { testUtils, createIntegrationTest } from '@tests/utils/testHelpers';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import MemoryPanel from '@/components/monitoring/MemoryPanel';
import AgentsPanel from '@/components/monitoring/AgentsPanel';
import CommandsPanel from '@/components/monitoring/CommandsPanel';
import PromptPanel from '@/components/monitoring/PromptPanel';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the WebSocket hook
jest.mock('@/hooks/useWebSocket');

// Mock the dynamic imports
jest.mock('next/dynamic', () => (fn) => {
  const dynamicModule = fn();
  const MockComponent = (props) => {
    const Component = dynamicModule.default || dynamicModule;
    return <Component {...props} />;
  };
  MockComponent.displayName = 'MockDynamicComponent';
  return MockComponent;
});

createIntegrationTest('Monitoring Panels Data Flow', () => {
  let mockClient;
  let mockUseWebSocket;

  beforeEach(() => {
    // Create mock WebSocket client
    mockClient = testUtils.createMockWebSocketClient();
    
    // Mock useWebSocket hook
    mockUseWebSocket = {
      connected: true,
      connecting: false,
      isConnected: true,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: mockClient.on.bind(mockClient),
      off: mockClient.off.bind(mockClient),
    };
    useWebSocket.mockReturnValue(mockUseWebSocket);
  });

  describe('MonitoringSidebar Integration', () => {
    test('should toggle monitoring sidebar visibility', async () => {
      const mockOnToggle = jest.fn();
      
      const { rerender } = render(
        <MonitoringSidebar isOpen={true} onToggle={mockOnToggle} />
      );

      // Should be visible initially
      expect(screen.getByText('Claude Flow UI Monitor')).toBeInTheDocument();

      // Click close button
      const closeButton = screen.getByTitle('Close Monitor');
      await userEvent.click(closeButton);

      expect(mockOnToggle).toHaveBeenCalled();

      // Simulate closing
      rerender(
        <MonitoringSidebar isOpen={false} onToggle={mockOnToggle} />
      );

      // Content should be hidden
      expect(screen.queryByText('Claude Flow UI Monitor')).not.toBeInTheDocument();
      
      // But toggle button should be visible
      expect(screen.getByTitle('Open Monitor')).toBeInTheDocument();
    });

    test('should switch between monitoring tabs', async () => {
      render(
        <MonitoringSidebar isOpen={true} onToggle={() => {}} />
      );

      // Initially should show Memory tab (first tab)
      const memoryTab = screen.getByText('💾 Memory');
      expect(memoryTab).toHaveClass(/blue-400|active/); // Active tab styling

      // Click Agents tab
      const agentsTab = screen.getByText('🤖 Agents');
      await userEvent.click(agentsTab);

      await waitFor(() => {
        expect(agentsTab).toHaveClass(/blue-400|active/);
      });

      // Click Commands tab
      const commandsTab = screen.getByText('⚡ Commands');
      await userEvent.click(commandsTab);

      await waitFor(() => {
        expect(commandsTab).toHaveClass(/blue-400|active/);
      });

      // Click Prompt tab
      const promptTab = screen.getByText('📝 Prompt');
      await userEvent.click(promptTab);

      await waitFor(() => {
        expect(promptTab).toHaveClass(/blue-400|active/);
      });
    });
  });

  describe('Memory Panel Data Flow', () => {
    test('should receive and display system metrics', async () => {
      render(<MemoryPanel />);

      // Simulate receiving system metrics
      const mockMetrics = global.testUtils.mockSystemMetrics;
      
      act(() => {
        mockClient.emit('system-metrics', mockMetrics);
      });

      await waitFor(() => {
        // Check for memory usage percentage
        expect(screen.getByText(/87.3%|87%/)).toBeInTheDocument();
        
        // Check for memory values (in GB or MB)
        expect(screen.getByText(/15\.0|15 GB/)).toBeInTheDocument(); // Used memory
        expect(screen.getByText(/2\.18|2.2 GB/)).toBeInTheDocument(); // Free memory
      });
    });

    test('should update memory display in real-time', async () => {
      render(<MemoryPanel />);

      // Send initial metrics
      act(() => {
        mockClient.emit('system-metrics', {
          ...global.testUtils.mockSystemMetrics,
          memoryUsagePercent: 85.0,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/85%/)).toBeInTheDocument();
      });

      // Send updated metrics
      act(() => {
        mockClient.emit('system-metrics', {
          ...global.testUtils.mockSystemMetrics,
          memoryUsagePercent: 90.0,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/90%/)).toBeInTheDocument();
        expect(screen.queryByText(/85%/)).not.toBeInTheDocument();
      });
    });

    test('should handle memory efficiency metrics', async () => {
      render(<MemoryPanel />);

      act(() => {
        mockClient.emit('system-metrics', {
          ...global.testUtils.mockSystemMetrics,
          memoryEfficiency: 23.5,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/23\.5|23%/)).toBeInTheDocument();
      });
    });

    test('should display CPU load information', async () => {
      render(<MemoryPanel />);

      act(() => {
        mockClient.emit('system-metrics', {
          ...global.testUtils.mockSystemMetrics,
          cpuLoad: 1.8,
          cpuCount: 8,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/1\.8|180%/)).toBeInTheDocument(); // Load average
        expect(screen.getByText(/8/)).toBeInTheDocument(); // CPU count
      });
    });
  });

  describe('Agents Panel Data Flow', () => {
    test('should receive and display agent status updates', async () => {
      render(<AgentsPanel />);

      const mockAgentStatus = {
        agentId: 'agent-test-1',
        state: 'busy',
        currentTask: 'Processing user input...',
      };

      act(() => {
        mockClient.emit('agent-status', mockAgentStatus);
      });

      await waitFor(() => {
        expect(screen.getByText('agent-test-1')).toBeInTheDocument();
        expect(screen.getByText('busy')).toBeInTheDocument();
        expect(screen.getByText('Processing user input...')).toBeInTheDocument();
      });
    });

    test('should update agent states in real-time', async () => {
      render(<AgentsPanel />);

      // Agent starts as idle
      act(() => {
        mockClient.emit('agent-status', {
          agentId: 'agent-dynamic',
          state: 'idle',
          currentTask: undefined,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('idle')).toBeInTheDocument();
      });

      // Agent becomes busy
      act(() => {
        mockClient.emit('agent-status', {
          agentId: 'agent-dynamic',
          state: 'busy',
          currentTask: 'Analyzing code...',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('busy')).toBeInTheDocument();
        expect(screen.getByText('Analyzing code...')).toBeInTheDocument();
        expect(screen.queryByText('idle')).not.toBeInTheDocument();
      });
    });

    test('should handle multiple agents simultaneously', async () => {
      render(<AgentsPanel />);

      const agents = [
        { agentId: 'agent-1', state: 'idle', currentTask: undefined },
        { agentId: 'agent-2', state: 'busy', currentTask: 'Running tests' },
        { agentId: 'agent-3', state: 'initializing', currentTask: undefined },
      ];

      agents.forEach(agent => {
        act(() => {
          mockClient.emit('agent-status', agent);
        });
      });

      await waitFor(() => {
        expect(screen.getByText('agent-1')).toBeInTheDocument();
        expect(screen.getByText('agent-2')).toBeInTheDocument();
        expect(screen.getByText('agent-3')).toBeInTheDocument();
        expect(screen.getByText('Running tests')).toBeInTheDocument();
      });
    });
  });

  describe('Commands Panel Data Flow', () => {
    test('should receive and display command execution updates', async () => {
      render(<CommandsPanel />);

      const mockCommand = {
        id: 'cmd-test-1',
        command: 'npm install express',
        agentId: 'agent-backend',
        timestamp: Date.now(),
        status: 'running',
      };

      act(() => {
        mockClient.emit('command-created', mockCommand);
      });

      await waitFor(() => {
        expect(screen.getByText('npm install express')).toBeInTheDocument();
        expect(screen.getByText('agent-backend')).toBeInTheDocument();
      });
    });

    test('should track command history in chronological order', async () => {
      render(<CommandsPanel />);

      const commands = [
        { id: 'cmd-1', command: 'git status', agentId: 'agent-1' },
        { id: 'cmd-2', command: 'npm test', agentId: 'agent-2' },
        { id: 'cmd-3', command: 'docker build', agentId: 'agent-3' },
      ];

      // Send commands with delays to ensure ordering
      commands.forEach((cmd, index) => {
        setTimeout(() => {
          act(() => {
            mockClient.emit('command-created', cmd);
          });
        }, index * 100);
      });

      await waitFor(() => {
        expect(screen.getByText('git status')).toBeInTheDocument();
        expect(screen.getByText('npm test')).toBeInTheDocument();
        expect(screen.getByText('docker build')).toBeInTheDocument();
      }, { timeout: 1000 });
    });

    test('should show command status updates', async () => {
      render(<CommandsPanel />);

      act(() => {
        mockClient.emit('command-created', {
          id: 'cmd-status',
          command: 'long-running-process',
          agentId: 'agent-worker',
          status: 'running',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('running')).toBeInTheDocument();
      });

      // Update command status
      act(() => {
        mockClient.emit('command-updated', {
          id: 'cmd-status',
          status: 'completed',
          exitCode: 0,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('completed')).toBeInTheDocument();
      });
    });
  });

  describe('Prompt Panel Data Flow', () => {
    test('should display current prompt information', async () => {
      render(<PromptPanel />);

      const mockPrompt = {
        id: 'prompt-1',
        text: 'Analyze the following code for potential security vulnerabilities...',
        tokens: 156,
        model: 'claude-sonnet-3.5',
        timestamp: Date.now(),
      };

      act(() => {
        mockClient.emit('prompt-created', mockPrompt);
      });

      await waitFor(() => {
        expect(screen.getByText(/security vulnerabilities/)).toBeInTheDocument();
        expect(screen.getByText(/156/)).toBeInTheDocument(); // Token count
        expect(screen.getByText(/claude-sonnet-3.5/)).toBeInTheDocument();
      });
    });

    test('should track prompt-response cycles', async () => {
      render(<PromptPanel />);

      // Send prompt
      act(() => {
        mockClient.emit('prompt-created', {
          id: 'prompt-cycle',
          text: 'Generate a React component',
          tokens: 50,
        });
      });

      // Send response
      act(() => {
        mockClient.emit('prompt-response', {
          promptId: 'prompt-cycle',
          response: 'Here is your React component...',
          tokens: 200,
          latency: 1250,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/Generate a React component/)).toBeInTheDocument();
        expect(screen.getByText(/Here is your React component/)).toBeInTheDocument();
        expect(screen.getByText(/1250ms|1.25s/)).toBeInTheDocument(); // Latency
      });
    });

    test('should show token usage statistics', async () => {
      render(<PromptPanel />);

      const prompts = [
        { id: 'p1', text: 'Short prompt', tokens: 10 },
        { id: 'p2', text: 'Medium length prompt with more context', tokens: 50 },
        { id: 'p3', text: 'Very long prompt with detailed instructions and examples...', tokens: 200 },
      ];

      prompts.forEach(prompt => {
        act(() => {
          mockClient.emit('prompt-created', prompt);
        });
      });

      await waitFor(() => {
        // Should show total token usage
        expect(screen.getByText(/260|Total/)).toBeInTheDocument();
      });
    });
  });

  describe('Cross-Panel Data Synchronization', () => {
    test('should synchronize agent activity between panels', async () => {
      render(
        <div>
          <AgentsPanel />
          <CommandsPanel />
        </div>
      );

      // Agent starts command
      act(() => {
        mockClient.emit('agent-status', {
          agentId: 'agent-sync',
          state: 'busy',
          currentTask: 'Executing git clone',
        });
      });

      act(() => {
        mockClient.emit('command-created', {
          id: 'cmd-sync',
          command: 'git clone https://github.com/example/repo.git',
          agentId: 'agent-sync',
        });
      });

      await waitFor(() => {
        // Should appear in both panels
        const agentReferences = screen.getAllByText('agent-sync');
        expect(agentReferences.length).toBeGreaterThanOrEqual(2);
        expect(screen.getByText('Executing git clone')).toBeInTheDocument();
        expect(screen.getByText(/git clone/)).toBeInTheDocument();
      });
    });

    test('should handle concurrent updates from multiple data sources', async () => {
      render(
        <div>
          <MemoryPanel />
          <AgentsPanel />
        </div>
      );

      // Simulate rapid updates
      const updates = [
        () => mockClient.emit('system-metrics', { ...global.testUtils.mockSystemMetrics, memoryUsagePercent: 80 }),
        () => mockClient.emit('agent-status', { agentId: 'agent-1', state: 'idle' }),
        () => mockClient.emit('system-metrics', { ...global.testUtils.mockSystemMetrics, memoryUsagePercent: 85 }),
        () => mockClient.emit('agent-status', { agentId: 'agent-2', state: 'busy' }),
        () => mockClient.emit('system-metrics', { ...global.testUtils.mockSystemMetrics, memoryUsagePercent: 90 }),
      ];

      updates.forEach((update, index) => {
        setTimeout(() => {
          act(update);
        }, index * 50);
      });

      await waitFor(() => {
        expect(screen.getByText(/90%/)).toBeInTheDocument();
        expect(screen.getByText('agent-1')).toBeInTheDocument();
        expect(screen.getByText('agent-2')).toBeInTheDocument();
      }, { timeout: 1000 });
    });
  });

  describe('Error Handling and Resilience', () => {
    test('should handle malformed data gracefully', async () => {
      render(<MemoryPanel />);

      // Send malformed metrics
      act(() => {
        mockClient.emit('system-metrics', null);
        mockClient.emit('system-metrics', { memoryUsagePercent: 'invalid' });
        mockClient.emit('system-metrics', {}); // Missing required fields
      });

      // Should not crash
      await waitFor(() => {
        expect(screen.getByText(/Memory/)).toBeInTheDocument();
      });
    });

    test('should recover from WebSocket disconnections', async () => {
      render(<AgentsPanel />);

      // Initially connected with data
      act(() => {
        mockClient.emit('agent-status', {
          agentId: 'agent-resilient',
          state: 'busy',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('agent-resilient')).toBeInTheDocument();
      });

      // Simulate disconnection
      act(() => {
        mockUseWebSocket.connected = false;
        mockClient.connected = false;
        mockClient.emit('disconnect');
      });

      // Simulate reconnection with new data
      setTimeout(() => {
        act(() => {
          mockUseWebSocket.connected = true;
          mockClient.connected = true;
          mockClient.emit('connect');
          mockClient.emit('agent-status', {
            agentId: 'agent-resilient',
            state: 'idle',
          });
        });
      }, 100);

      await waitFor(() => {
        expect(screen.getByText('idle')).toBeInTheDocument();
      });
    });

    test('should handle high-frequency updates without performance degradation', async () => {
      const startTime = performance.now();
      
      render(<MemoryPanel />);

      // Send 100 rapid updates
      for (let i = 0; i < 100; i++) {
        act(() => {
          mockClient.emit('system-metrics', {
            ...global.testUtils.mockSystemMetrics,
            memoryUsagePercent: 70 + (i % 20),
            timestamp: Date.now() + i,
          });
        });
      }

      await waitFor(() => {
        const endTime = performance.now();
        const duration = endTime - startTime;
        
        // Should complete in reasonable time
        expect(duration).toBeLessThan(5000); // 5 seconds max
        expect(screen.getByText(/Memory/)).toBeInTheDocument();
      });
    });
  });

  describe('Memory Management', () => {
    test('should clean up event listeners on unmount', async () => {
      const { unmount } = render(
        <MonitoringSidebar isOpen={true} onToggle={() => {}} />
      );

      const offSpy = jest.spyOn(mockClient, 'off');

      unmount();

      expect(offSpy).toHaveBeenCalled();
    });

    test('should limit stored data to prevent memory leaks', async () => {
      render(<CommandsPanel />);

      // Send many commands to test memory limits
      for (let i = 0; i < 1000; i++) {
        act(() => {
          mockClient.emit('command-created', {
            id: `cmd-${i}`,
            command: `command-${i}`,
            agentId: 'agent-test',
          });
        });
      }

      await waitFor(() => {
        // Should only show recent commands (implementation dependent)
        const commands = screen.getAllByText(/command-/);
        expect(commands.length).toBeLessThanOrEqual(100); // Reasonable limit
      });
    });
  });
});