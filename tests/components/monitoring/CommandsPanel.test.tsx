import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import CommandsPanel from '@/components/monitoring/CommandsPanel';

// Mock the useWebSocket hook
const mockOn = jest.fn();
const mockOff = jest.fn();
const mockIsConnected = jest.fn();

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    on: mockOn,
    off: mockOff,
    isConnected: mockIsConnected(),
  }),
}));

describe('CommandsPanel', () => {
  let commandCreatedHandler: ((data: any) => void) | null = null;
  let commandUpdateHandler: ((data: any) => void) | null = null;
  let commandOutputHandler: ((data: any) => void) | null = null;

  beforeEach(() => {
    jest.clearAllMocks();
    mockIsConnected.mockReturnValue(true);
    
    // Set up handler references
    mockOn.mockImplementation((event: string, handler: any) => {
      if (event === 'command-created') {
        commandCreatedHandler = handler;
      } else if (event === 'command-update') {
        commandUpdateHandler = handler;
      } else if (event === 'command-output') {
        commandOutputHandler = handler;
      }
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    commandCreatedHandler = null;
    commandUpdateHandler = null;
    commandOutputHandler = null;
  });

  describe('Connection States', () => {
    it('should display disconnected state when WebSocket is not connected', () => {
      mockIsConnected.mockReturnValue(false);
      
      render(<CommandsPanel />);
      
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should display empty state when connected but no commands', () => {
      render(<CommandsPanel />);
      
      expect(screen.getByText('No commands')).toBeInTheDocument();
    });
  });

  describe('WebSocket Event Handling', () => {
    it('should register event listeners on mount', () => {
      render(<CommandsPanel />);
      
      expect(mockOn).toHaveBeenCalledWith('command-created', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('command-update', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('command-output', expect.any(Function));
    });

    it('should unregister event listeners on unmount', () => {
      const { unmount } = render(<CommandsPanel />);
      
      unmount();
      
      expect(mockOff).toHaveBeenCalledWith('command-created', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('command-update', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('command-output', expect.any(Function));
    });
  });

  describe('Command Creation', () => {
    it('should handle command creation events', async () => {
      render(<CommandsPanel />);
      
      const commandData = {
        id: 'cmd-123',
        command: 'npm install',
        agentId: 'agent-456',
      };

      act(() => {
        commandCreatedHandler?.(commandData);
      });

      await waitFor(() => {
        expect(screen.getByText('npm install')).toBeInTheDocument();
        expect(screen.getByText('pending')).toBeInTheDocument();
        expect(screen.getByText('Agent: agent-45')).toBeInTheDocument(); // Truncated ID
      });
    });

    it('should generate random ID if not provided', async () => {
      render(<CommandsPanel />);
      
      const commandData = {
        command: 'ls -la',
      };

      act(() => {
        commandCreatedHandler?.(commandData);
      });

      await waitFor(() => {
        expect(screen.getByText('ls -la')).toBeInTheDocument();
      });
    });
  });

  describe('Command Updates', () => {
    beforeEach(async () => {
      render(<CommandsPanel />);
      
      // Create initial command
      act(() => {
        commandCreatedHandler?.({
          id: 'cmd-123',
          command: 'npm test',
          agentId: 'agent-456',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('npm test')).toBeInTheDocument();
      });
    });

    it('should update command status', async () => {
      act(() => {
        commandUpdateHandler?.({
          id: 'cmd-123',
          status: 'running',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('running')).toBeInTheDocument();
        expect(screen.getByText('🔄')).toBeInTheDocument();
      });
    });

    it('should calculate duration on completion', async () => {
      const startTime = Date.now();
      
      act(() => {
        commandUpdateHandler?.({
          id: 'cmd-123',
          status: 'completed',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('completed')).toBeInTheDocument();
        expect(screen.getByText('✅')).toBeInTheDocument();
        // Duration should be calculated and displayed
        expect(screen.getByText(/\d+\.\d+s/)).toBeInTheDocument();
      });
    });

    it('should handle failed commands', async () => {
      act(() => {
        commandUpdateHandler?.({
          id: 'cmd-123',
          status: 'failed',
          error: 'Command failed with exit code 1',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('failed')).toBeInTheDocument();
        expect(screen.getByText('❌')).toBeInTheDocument();
      });
    });
  });

  describe('Command Output', () => {
    beforeEach(async () => {
      render(<CommandsPanel />);
      
      // Create initial command
      act(() => {
        commandCreatedHandler?.({
          id: 'cmd-123',
          command: 'echo hello',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('echo hello')).toBeInTheDocument();
      });
    });

    it('should append command output', async () => {
      act(() => {
        commandOutputHandler?.({
          id: 'cmd-123',
          output: 'Hello, World!\n',
        });
      });

      // Click on command to view details
      const user = userEvent.setup();
      await user.click(screen.getByText('echo hello'));

      await waitFor(() => {
        expect(screen.getByText('Command Output')).toBeInTheDocument();
        expect(screen.getByText('Hello, World!')).toBeInTheDocument();
      });
    });

    it('should accumulate multiple output chunks', async () => {
      act(() => {
        commandOutputHandler?.({
          id: 'cmd-123',
          output: 'Line 1\n',
        });
      });

      act(() => {
        commandOutputHandler?.({
          id: 'cmd-123',
          output: 'Line 2\n',
        });
      });

      const user = userEvent.setup();
      await user.click(screen.getByText('echo hello'));

      await waitFor(() => {
        // Check if both lines are present in the output
        const outputElement = screen.getByText('Command Output').parentElement?.querySelector('pre');
        expect(outputElement).toBeInTheDocument();
        expect(outputElement?.textContent).toContain('Line 1');
        expect(outputElement?.textContent).toContain('Line 2');
      });
    });
  });

  describe('Filter Functionality', () => {
    beforeEach(async () => {
      render(<CommandsPanel />);
      
      // Create commands with different statuses
      const commands = [
        { id: 'cmd-1', command: 'cmd1', status: 'running' },
        { id: 'cmd-2', command: 'cmd2', status: 'completed' },
        { id: 'cmd-3', command: 'cmd3', status: 'failed' },
      ];

      for (const cmd of commands) {
        act(() => {
          commandCreatedHandler?.(cmd);
        });
        
        if (cmd.status !== 'pending') {
          act(() => {
            commandUpdateHandler?.({ id: cmd.id, status: cmd.status });
          });
        }
      }

      await waitFor(() => {
        expect(screen.getByText('cmd1')).toBeInTheDocument();
        expect(screen.getByText('cmd2')).toBeInTheDocument();
        expect(screen.getByText('cmd3')).toBeInTheDocument();
      });
    });

    it('should filter commands by status', async () => {
      const user = userEvent.setup();
      
      // Click on 'running' filter button specifically
      const runningButton = screen.getByRole('button', { name: /running \(1\)/i });
      await user.click(runningButton);

      await waitFor(() => {
        expect(screen.getByText('cmd1')).toBeInTheDocument();
        expect(screen.queryByText('cmd2')).not.toBeInTheDocument();
        expect(screen.queryByText('cmd3')).not.toBeInTheDocument();
      });
    });

    it('should show command counts in filter tabs', async () => {
      await waitFor(() => {
        expect(screen.getByText(/All \(3\)/)).toBeInTheDocument();
        expect(screen.getByText(/Running \(1\)/)).toBeInTheDocument();
        expect(screen.getByText(/Completed \(1\)/)).toBeInTheDocument();
        expect(screen.getByText(/Failed \(1\)/)).toBeInTheDocument();
      });
    });

    it('should show filtered empty state', async () => {
      const user = userEvent.setup();
      
      // Filter by running status
      const runningButton = screen.getByRole('button', { name: /running \(1\)/i });
      await user.click(runningButton);
      
      // Update all commands to completed
      act(() => {
        commandUpdateHandler?.({ id: 'cmd-1', status: 'completed' });
      });

      await waitFor(() => {
        expect(screen.getByText('No running commands')).toBeInTheDocument();
      });
    });
  });

  describe('Command Selection and Details', () => {
    beforeEach(async () => {
      render(<CommandsPanel />);
      
      act(() => {
        commandCreatedHandler?.({
          id: 'cmd-123',
          command: 'test command',
          agentId: 'agent-456',
        });
      });

      // Update with output and error
      act(() => {
        commandOutputHandler?.({
          id: 'cmd-123',
          output: 'Command output here\n',
        });
      });

      act(() => {
        commandUpdateHandler?.({
          id: 'cmd-123',
          status: 'failed',
          error: 'Error message here',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('test command')).toBeInTheDocument();
      });
    });

    it('should select and display command details', async () => {
      const user = userEvent.setup();
      
      await user.click(screen.getByText('test command'));

      await waitFor(() => {
        expect(screen.getByText('Command Output')).toBeInTheDocument();
        expect(screen.getByText('Command output here')).toBeInTheDocument();
        expect(screen.getByText('Error message here')).toBeInTheDocument();
        expect(screen.getByText('Started:')).toBeInTheDocument();
        expect(screen.getByText('Duration:')).toBeInTheDocument();
      });
    });

    it('should highlight selected command', async () => {
      const user = userEvent.setup();
      
      // Find the command element in the command list (not in the details panel)
      const commandElements = screen.getAllByText('test command');
      const commandListElement = commandElements.find(el => 
        el.closest('.cursor-pointer') && 
        !el.closest('.border-t') // not in the details panel
      );
      
      expect(commandListElement).toBeInTheDocument();
      const commandContainer = commandListElement!.closest('.cursor-pointer');
      expect(commandContainer).not.toHaveClass('border-blue-500');
      
      await user.click(commandListElement!);

      await waitFor(() => {
        expect(commandContainer).toHaveClass('border-blue-500');
      });
    });
  });

  describe('Command Limits', () => {
    it('should limit commands to 100 entries', async () => {
      render(<CommandsPanel />);
      
      // Add 105 commands
      for (let i = 0; i < 105; i++) {
        act(() => {
          commandCreatedHandler?.({
            id: `cmd-${i}`,
            command: `command ${i}`,
          });
        });
      }

      await waitFor(() => {
        // Should only show most recent 100 commands
        expect(screen.getByText('command 104')).toBeInTheDocument();
        expect(screen.queryByText('command 4')).not.toBeInTheDocument();
      });
    });
  });

  describe('Progress Indicators', () => {
    it('should show animated progress bar for running commands', async () => {
      render(<CommandsPanel />);
      
      act(() => {
        commandCreatedHandler?.({
          id: 'cmd-123',
          command: 'long running task',
        });
      });

      act(() => {
        commandUpdateHandler?.({
          id: 'cmd-123',
          status: 'running',
        });
      });

      await waitFor(() => {
        expect(screen.getByText('long running task')).toBeInTheDocument();
        const progressBar = document.querySelector('.bg-blue-500.animate-pulse');
        expect(progressBar).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('should support keyboard navigation', async () => {
      render(<CommandsPanel />);
      
      act(() => {
        commandCreatedHandler?.({
          id: 'cmd-123',
          command: 'test command',
        });
      });

      await waitFor(() => {
        // Find the command container element (should be the parent div with cursor-pointer)
        const commandElement = screen.getByText('test command').closest('.cursor-pointer');
        expect(commandElement).toBeInTheDocument();
        expect(commandElement).toHaveClass('cursor-pointer');
        expect(commandElement).toHaveAttribute('tabIndex', '0');
      });
    });

    it('should have proper semantic structure', async () => {
      render(<CommandsPanel />);
      
      // Check for proper headings and sections
      const filterButtons = screen.getAllByRole('button');
      expect(filterButtons.length).toBeGreaterThan(0);
      
      // All filter buttons should have proper text content
      expect(screen.getByText(/All/)).toBeInTheDocument();
      expect(screen.getByText(/Running/)).toBeInTheDocument();
      expect(screen.getByText(/Completed/)).toBeInTheDocument();
      expect(screen.getByText(/Failed/)).toBeInTheDocument();
    });
  });

  describe('Performance', () => {
    it('should handle rapid command updates efficiently', async () => {
      render(<CommandsPanel />);
      
      // Simulate rapid updates
      const commandId = 'cmd-rapid';
      
      act(() => {
        commandCreatedHandler?.({ id: commandId, command: 'rapid test' });
      });

      // Send many updates in quick succession
      for (let i = 0; i < 50; i++) {
        act(() => {
          commandOutputHandler?.({
            id: commandId,
            output: `Output line ${i}\n`,
          });
        });
      }

      await waitFor(() => {
        expect(screen.getByText('rapid test')).toBeInTheDocument();
      });

      // Component should remain responsive
      const user = userEvent.setup();
      await user.click(screen.getByText('rapid test'));

      await waitFor(() => {
        expect(screen.getByText('Command Output')).toBeInTheDocument();
      });
    });
  });
});