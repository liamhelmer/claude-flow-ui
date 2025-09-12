import { render, screen, fireEvent, act } from '@testing-library/react';
import CommandsPanel from '../CommandsPanel';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the useWebSocket hook
jest.mock('@/hooks/useWebSocket');

const mockWebSocket = {
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
};

const createMockCommand = (overrides = {}) => ({
  id: 'cmd-123',
  command: 'npm test',
  agentId: 'agent-456',
  status: 'pending' as const,
  startTime: Date.now(),
  ...overrides,
});

describe('CommandsPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
    
    // Mock Date.now for consistent timestamps
    jest.spyOn(Date, 'now').mockReturnValue(1609459200000); // 2021-01-01
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('connection states', () => {
    it('should show disconnected state when not connected', () => {
      (useWebSocket as jest.Mock).mockReturnValue({
        ...mockWebSocket,
        isConnected: false,
      });

      render(<CommandsPanel />);

      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should show panel content when connected', () => {
      render(<CommandsPanel />);

      expect(screen.getByText('All (0)')).toBeInTheDocument();
      expect(screen.getByText('Running (0)')).toBeInTheDocument();
      expect(screen.getByText('Completed (0)')).toBeInTheDocument();
      expect(screen.getByText('Failed (0)')).toBeInTheDocument();
    });
  });

  describe('empty state', () => {
    it('should show no commands message when empty', () => {
      render(<CommandsPanel />);

      expect(screen.getByText('No commands')).toBeInTheDocument();
    });

    it('should show filtered empty message', () => {
      render(<CommandsPanel />);

      // Switch to running filter
      fireEvent.click(screen.getByText('Running (0)'));
      expect(screen.getByText('No running commands')).toBeInTheDocument();
    });
  });

  describe('filter tabs', () => {
    it('should render all filter options', () => {
      render(<CommandsPanel />);

      expect(screen.getByText('All (0)')).toBeInTheDocument();
      expect(screen.getByText('Running (0)')).toBeInTheDocument();
      expect(screen.getByText('Completed (0)')).toBeInTheDocument();
      expect(screen.getByText('Failed (0)')).toBeInTheDocument();
    });

    it('should switch between filters', () => {
      render(<CommandsPanel />);

      const runningFilter = screen.getByText('Running (0)');
      fireEvent.click(runningFilter);

      expect(runningFilter).toHaveClass('bg-blue-500', 'text-white');
      expect(screen.getByText('All (0)')).toHaveClass('bg-gray-700', 'text-gray-400');
    });

    it('should update filter counts correctly', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create a command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-1',
          command: 'npm test',
          agentId: 'agent-1',
        });
      });

      expect(screen.getByText('All (1)')).toBeInTheDocument();

      // Update to running
      act(() => {
        commandUpdateHandler({
          id: 'cmd-1',
          status: 'running',
        });
      });

      expect(screen.getByText('Running (1)')).toBeInTheDocument();

      // Update to completed
      act(() => {
        commandUpdateHandler({
          id: 'cmd-1',
          status: 'completed',
        });
      });

      expect(screen.getByText('Completed (1)')).toBeInTheDocument();
      expect(screen.getByText('Running (0)')).toBeInTheDocument();
    });
  });

  describe('command creation', () => {
    it('should handle command-created events', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm test',
          agentId: 'agent-456',
        });
      });

      expect(screen.getByText('npm test')).toBeInTheDocument();
      expect(screen.getByText('Agent: agent-45')).toBeInTheDocument();
      expect(screen.getByText('pending')).toBeInTheDocument();
      expect(screen.getByText('⏳')).toBeInTheDocument();
    });

    it('should generate ID when not provided', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      expect(() => {
        act(() => {
          commandCreatedHandler({
            command: 'test command without id',
          });
        });
      }).not.toThrow();

      expect(screen.getByText('test command without id')).toBeInTheDocument();
    });

    it('should limit commands to 100 items', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      // Create 105 commands
      act(() => {
        for (let i = 0; i < 105; i++) {
          commandCreatedHandler({
            id: `cmd-${i}`,
            command: `command ${i}`,
          });
        }
      });

      expect(screen.getByText('All (100)')).toBeInTheDocument();
    });
  });

  describe('command updates', () => {
    it('should handle command-update events', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm test',
        });
      });

      // Update to running
      act(() => {
        commandUpdateHandler({
          id: 'cmd-123',
          status: 'running',
        });
      });

      expect(screen.getByText('running')).toBeInTheDocument();
      expect(screen.getByText('🔄')).toBeInTheDocument();
    });

    it('should calculate duration when command completes', () => {
      jest.spyOn(Date, 'now')
        .mockReturnValueOnce(1609459200000) // Start time
        .mockReturnValueOnce(1609459205000); // End time (5 seconds later)

      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm test',
        });
      });

      // Update to completed
      act(() => {
        commandUpdateHandler({
          id: 'cmd-123',
          status: 'completed',
        });
      });

      expect(screen.getByText('5.00s')).toBeInTheDocument();
    });

    it('should handle updates for non-existing commands', () => {
      render(<CommandsPanel />);

      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      expect(() => {
        act(() => {
          commandUpdateHandler({
            id: 'non-existing-cmd',
            status: 'completed',
          });
        });
      }).not.toThrow();
    });
  });

  describe('command output', () => {
    it('should handle command-output events', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandOutputHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-output')[1];

      // Create command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm test',
        });
      });

      // Add output
      act(() => {
        commandOutputHandler({
          id: 'cmd-123',
          output: 'Test output line 1\n',
        });
      });

      // Select command to see output
      const commandCard = screen.getByText('npm test').closest('div');
      fireEvent.click(commandCard!);

      expect(screen.getByText('Command Output')).toBeInTheDocument();
      expect(screen.getByText('Test output line 1')).toBeInTheDocument();
    });

    it('should append multiple output chunks', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandOutputHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-output')[1];

      // Create command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm test',
        });
      });

      // Add multiple output chunks
      act(() => {
        commandOutputHandler({
          id: 'cmd-123',
          output: 'Line 1\n',
        });
        commandOutputHandler({
          id: 'cmd-123',
          output: 'Line 2\n',
        });
      });

      // Select command to see output
      const commandCard = screen.getByText('npm test').closest('div');
      fireEvent.click(commandCard!);

      expect(screen.getByText('Line 1\nLine 2')).toBeInTheDocument();
    });
  });

  describe('command selection and details', () => {
    it('should select command when clicked', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm test',
          agentId: 'agent-456',
        });
      });

      const commandCard = screen.getByText('npm test').closest('div');
      fireEvent.click(commandCard!);

      expect(commandCard).toHaveClass('border-blue-500');
      expect(screen.getByText('Command Output')).toBeInTheDocument();
    });

    it('should display command details correctly', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'npm run build',
          agentId: 'agent-456',
        });
      });

      const commandCard = screen.getByText('npm run build').closest('div');
      fireEvent.click(commandCard!);

      expect(screen.getByText('Command:')).toBeInTheDocument();
      expect(screen.getByText('npm run build')).toBeInTheDocument();
      expect(screen.getByText('Started:')).toBeInTheDocument();
    });

    it('should show error output when available', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'failing-command',
        });
      });

      // Update with error
      act(() => {
        commandUpdateHandler({
          id: 'cmd-123',
          status: 'failed',
          error: 'Command not found',
        });
      });

      // Select command
      const commandCard = screen.getByText('failing-command').closest('div');
      fireEvent.click(commandCard!);

      expect(screen.getByText('Command not found')).toBeInTheDocument();
    });

    it('should show duration when command is completed', () => {
      const startTime = 1609459200000;
      const endTime = 1609459203000; // 3 seconds later
      
      jest.spyOn(Date, 'now')
        .mockReturnValueOnce(startTime)
        .mockReturnValueOnce(endTime);

      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'test-command',
        });
      });

      // Complete command
      act(() => {
        commandUpdateHandler({
          id: 'cmd-123',
          status: 'completed',
        });
      });

      // Select command
      const commandCard = screen.getByText('test-command').closest('div');
      fireEvent.click(commandCard!);

      expect(screen.getByText('Duration:')).toBeInTheDocument();
      expect(screen.getByText('3.00s')).toBeInTheDocument();
    });
  });

  describe('status indicators', () => {
    it('should show correct status colors and icons for all states', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Test each status
      const statuses = ['pending', 'running', 'completed', 'failed'] as const;
      const icons = ['⏳', '🔄', '✅', '❌'];

      statuses.forEach((status, index) => {
        act(() => {
          commandCreatedHandler({
            id: `cmd-${status}`,
            command: `${status}-command`,
          });
          
          if (status !== 'pending') {
            commandUpdateHandler({
              id: `cmd-${status}`,
              status: status,
            });
          }
        });

        expect(screen.getByText(status)).toBeInTheDocument();
        expect(screen.getByText(icons[index])).toBeInTheDocument();
      });
    });

    it('should show progress bar for running commands', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create running command
      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'long-running-command',
        });
        commandUpdateHandler({
          id: 'cmd-123',
          status: 'running',
        });
      });

      const progressBar = screen.container.querySelector('.animate-pulse');
      expect(progressBar).toBeInTheDocument();
      expect(progressBar).toHaveClass('bg-blue-500');
    });
  });

  describe('filtering', () => {
    beforeEach(() => {
      const { rerender } = render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      // Create commands with different statuses
      act(() => {
        commandCreatedHandler({
          id: 'cmd-pending',
          command: 'pending-cmd',
        });
        commandCreatedHandler({
          id: 'cmd-running',
          command: 'running-cmd',
        });
        commandCreatedHandler({
          id: 'cmd-completed',
          command: 'completed-cmd',
        });
        commandCreatedHandler({
          id: 'cmd-failed',
          command: 'failed-cmd',
        });

        commandUpdateHandler({
          id: 'cmd-running',
          status: 'running',
        });
        commandUpdateHandler({
          id: 'cmd-completed',
          status: 'completed',
        });
        commandUpdateHandler({
          id: 'cmd-failed',
          status: 'failed',
        });
      });
    });

    it('should show all commands by default', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      act(() => {
        commandCreatedHandler({
          id: 'cmd-1',
          command: 'test-cmd',
        });
      });

      expect(screen.getByText('test-cmd')).toBeInTheDocument();
    });

    it('should filter by running status', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      act(() => {
        commandCreatedHandler({ id: 'cmd-1', command: 'pending-cmd' });
        commandCreatedHandler({ id: 'cmd-2', command: 'running-cmd' });
        commandUpdateHandler({ id: 'cmd-2', status: 'running' });
      });

      // Filter to running
      fireEvent.click(screen.getByText('Running (1)'));

      expect(screen.getByText('running-cmd')).toBeInTheDocument();
      expect(screen.queryByText('pending-cmd')).not.toBeInTheDocument();
    });

    it('should filter by completed status', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];
      const commandUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-update')[1];

      act(() => {
        commandCreatedHandler({ id: 'cmd-1', command: 'pending-cmd' });
        commandCreatedHandler({ id: 'cmd-2', command: 'completed-cmd' });
        commandUpdateHandler({ id: 'cmd-2', status: 'completed' });
      });

      // Filter to completed
      fireEvent.click(screen.getByText('Completed (1)'));

      expect(screen.getByText('completed-cmd')).toBeInTheDocument();
      expect(screen.queryByText('pending-cmd')).not.toBeInTheDocument();
    });
  });

  describe('event listener cleanup', () => {
    it('should set up WebSocket event listeners on mount', () => {
      render(<CommandsPanel />);

      expect(mockWebSocket.on).toHaveBeenCalledWith('command-created', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('command-update', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('command-output', expect.any(Function));
    });

    it('should clean up event listeners on unmount', () => {
      const { unmount } = render(<CommandsPanel />);

      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('command-created', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('command-update', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('command-output', expect.any(Function));
    });
  });

  describe('edge cases', () => {
    it('should handle missing command data gracefully', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      expect(() => {
        act(() => {
          commandCreatedHandler({
            // Missing command field
            id: 'test-id',
          });
        });
      }).not.toThrow();
    });

    it('should handle commands without agent ID', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: 'test-command',
          // No agentId
        });
      });

      expect(screen.getByText('test-command')).toBeInTheDocument();
      expect(screen.queryByText(/Agent:/)).not.toBeInTheDocument();
    });

    it('should truncate long command names', () => {
      render(<CommandsPanel />);

      const longCommand = 'a'.repeat(200);
      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      act(() => {
        commandCreatedHandler({
          id: 'cmd-123',
          command: longCommand,
        });
      });

      const commandElement = screen.container.querySelector('code.truncate');
      expect(commandElement).toBeInTheDocument();
      expect(commandElement?.textContent).toBe(longCommand);
    });

    it('should handle malformed timestamps gracefully', () => {
      render(<CommandsPanel />);

      const commandCreatedHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'command-created')[1];

      expect(() => {
        act(() => {
          commandCreatedHandler({
            id: 'cmd-123',
            command: 'test-command',
            startTime: 'invalid-timestamp',
          });
        });
      }).not.toThrow();
    });
  });
});