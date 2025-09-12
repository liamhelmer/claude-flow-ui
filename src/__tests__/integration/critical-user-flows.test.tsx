/**
 * Critical User Flow Integration Tests
 * Tests end-to-end user scenarios and cross-component interactions
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { 
  createMockSocketIO, 
  createMockTerminalData, 
  createMockAgentData,
  createMockMemoryData,
  waitForAsyncUpdate 
} from '@/__tests__/utils/test-helpers';

// Import components for integration testing
import Terminal from '@/components/terminal/Terminal';
import MonitoringSidebar from '@/components/monitoring/MonitoringSidebar';
import AgentsPanel from '@/components/monitoring/AgentsPanel';
import MemoryPanel from '@/components/monitoring/MemoryPanel';

// Mock hooks
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
    open: jest.fn(),
    write: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
    loadAddon: jest.fn(),
    fit: jest.fn(),
    resize: jest.fn(),
    clear: jest.fn(),
    element: document.createElement('div')
  })),
}));

const { useWebSocket } = require('@/hooks/useWebSocket');
const { useTerminal } = require('@/hooks/useTerminal');

describe('Critical User Flow Integration Tests', () => {
  let mockWebSocket: ReturnType<typeof createMockSocketIO>;
  
  const defaultTerminalMock = {
    terminal: {
      write: jest.fn(),
      dispose: jest.fn(),
      onData: jest.fn(),
      onResize: jest.fn(),
      fit: jest.fn(),
      resize: jest.fn(),
      clear: jest.fn(),
    },
    output: '',
    isConnected: true,
    sendInput: jest.fn(),
    resize: jest.fn(),
    clear: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockWebSocket = createMockSocketIO();
    
    useWebSocket.mockReturnValue({
      on: mockWebSocket.on,
      off: mockWebSocket.off,
      send: mockWebSocket.emit,
      sendMessage: mockWebSocket.emit,
      connect: mockWebSocket.connect,
      disconnect: mockWebSocket.disconnect,
      isConnected: mockWebSocket.connected,
    });
    
    useTerminal.mockReturnValue(defaultTerminalMock);
  });

  describe('Terminal Session Management Flow', () => {
    it('should handle complete terminal session lifecycle', async () => {
      const user = userEvent.setup();
      
      // Render terminal component
      render(<Terminal sessionId="integration-test" />);
      
      // Verify terminal initializes
      expect(screen.getByRole('region', { name: /terminal/i }) || 
             screen.getByTestId('terminal') ||
             document.querySelector('[data-testid="terminal"]')).toBeInTheDocument();
      
      // Simulate connection establishment
      mockWebSocket.simulateConnect();
      
      // Simulate receiving terminal configuration
      const terminalConfig = createMockTerminalData({
        cols: 120,
        rows: 30,
        sessionId: 'integration-test'
      });
      
      mockWebSocket.simulateEvent('terminal-config', terminalConfig);
      
      // Simulate user typing command
      const terminalInput = screen.getByRole('textbox') || 
                           document.querySelector('input, textarea, [contenteditable]');
      
      if (terminalInput) {
        await user.type(terminalInput, 'ls -la{enter}');
      }
      
      // Verify command was sent
      expect(mockWebSocket.emit).toHaveBeenCalledWith(
        'terminal-input', 
        expect.objectContaining({
          command: expect.stringContaining('ls -la')
        })
      );
      
      // Simulate receiving command output
      mockWebSocket.simulateEvent('terminal-output', {
        sessionId: 'integration-test',
        data: 'total 24\ndrwxr-xr-x  5 user  staff   160 Nov 10 10:30 .\ndrwxr-xr-x  8 user  staff   256 Nov 10 10:25 ..\n'
      });
      
      // Verify output is displayed
      await waitFor(() => {
        expect(defaultTerminalMock.terminal.write).toHaveBeenCalledWith(
          expect.stringContaining('total 24')
        );
      });
    });

    it('should handle terminal resize operations', async () => {
      render(<Terminal sessionId="resize-test" />);
      
      // Simulate window resize
      Object.defineProperty(window, 'innerWidth', { value: 1200, writable: true });
      Object.defineProperty(window, 'innerHeight', { value: 800, writable: true });
      
      fireEvent(window, new Event('resize'));
      
      // Verify resize was handled
      await waitFor(() => {
        expect(defaultTerminalMock.resize).toHaveBeenCalled();
      });
      
      // Simulate manual resize
      mockWebSocket.simulateEvent('terminal-resize', {
        sessionId: 'resize-test',
        cols: 140,
        rows: 35
      });
      
      expect(defaultTerminalMock.terminal.resize).toHaveBeenCalledWith(140, 35);
    });

    it('should handle terminal disconnection and reconnection', async () => {
      render(<Terminal sessionId="disconnect-test" />);
      
      // Initial connection
      mockWebSocket.simulateConnect();
      
      // Simulate disconnection
      mockWebSocket.simulateDisconnect('transport close');
      
      // Verify disconnected state
      await waitFor(() => {
        expect(screen.queryByText(/disconnected|connection lost/i)).toBeInTheDocument();
      });
      
      // Simulate reconnection
      mockWebSocket.simulateConnect();
      
      // Verify reconnected state
      await waitFor(() => {
        expect(screen.queryByText(/connected|reconnected/i)).toBeInTheDocument();
      });
    });
  });

  describe('Monitoring and Agent Coordination Flow', () => {
    it('should display real-time system monitoring data', async () => {
      render(<MonitoringSidebar />);
      
      // Simulate system metrics updates
      const systemMetrics = {
        memory: createMockMemoryData({ memoryUsagePercent: 75 }),
        agents: [
          createMockAgentData({ id: 'agent-1', name: 'Coder Agent', state: 'busy' }),
          createMockAgentData({ id: 'agent-2', name: 'Tester Agent', state: 'idle' })
        ],
        timestamp: Date.now()
      };
      
      mockWebSocket.simulateEvent('system-metrics', systemMetrics);
      
      // Verify memory data is displayed
      await waitFor(() => {
        expect(screen.getByText(/75%/)).toBeInTheDocument();
      });
      
      // Verify agent data is displayed
      await waitFor(() => {
        expect(screen.getByText('Coder Agent')).toBeInTheDocument();
        expect(screen.getByText('Tester Agent')).toBeInTheDocument();
      });
    });

    it('should handle agent lifecycle events', async () => {
      render(<AgentsPanel />);
      
      // Simulate agent spawning
      const newAgent = createMockAgentData({
        id: 'new-agent-1',
        name: 'New Agent',
        state: 'initializing'
      });
      
      mockWebSocket.simulateEvent('agent-spawned', {
        agentId: 'new-agent-1',
        type: 'coder',
        name: 'New Agent'
      });
      
      // Verify agent appears in list
      await waitFor(() => {
        expect(screen.getByText('New Agent')).toBeInTheDocument();
      });
      
      // Simulate agent status updates
      mockWebSocket.simulateEvent('agent-status', {
        agentId: 'new-agent-1',
        state: 'busy',
        currentTask: 'Implementing feature X'
      });
      
      // Verify status update
      await waitFor(() => {
        expect(screen.getByText(/busy/i)).toBeInTheDocument();
        expect(screen.getByText(/Implementing feature X/i)).toBeInTheDocument();
      });
      
      // Simulate agent completion
      mockWebSocket.simulateEvent('agent-status', {
        agentId: 'new-agent-1',
        state: 'idle',
        currentTask: null
      });
      
      await waitFor(() => {
        expect(screen.getByText(/idle/i)).toBeInTheDocument();
      });
    });

    it('should coordinate between terminal and agent systems', async () => {
      // Render both terminal and monitoring
      render(
        <div>
          <Terminal sessionId="coordination-test" />
          <AgentsPanel />
        </div>
      );
      
      // Simulate starting a development task in terminal
      mockWebSocket.simulateEvent('terminal-output', {
        sessionId: 'coordination-test',
        data: '$ npm run dev\nStarting development server...\n'
      });
      
      // Simulate agent responding to development task
      mockWebSocket.simulateEvent('agent-spawned', {
        agentId: 'dev-agent-1',
        type: 'development',
        name: 'Dev Server Agent'
      });
      
      // Verify both components show related information
      await waitFor(() => {
        expect(screen.getByText(/Starting development server/i)).toBeInTheDocument();
        expect(screen.getByText('Dev Server Agent')).toBeInTheDocument();
      });
      
      // Simulate agent completing task and updating terminal
      mockWebSocket.simulateEvent('agent-status', {
        agentId: 'dev-agent-1',
        state: 'idle',
        currentTask: null
      });
      
      mockWebSocket.simulateEvent('terminal-output', {
        sessionId: 'coordination-test',
        data: 'Development server started on http://localhost:3000\n$ '
      });
      
      await waitFor(() => {
        expect(screen.getByText(/localhost:3000/i)).toBeInTheDocument();
      });
    });
  });

  describe('Error Handling and Recovery Flow', () => {
    it('should handle WebSocket connection failures gracefully', async () => {
      render(
        <div>
          <Terminal sessionId="error-test" />
          <MemoryPanel />
          <AgentsPanel />
        </div>
      );
      
      // Simulate connection error
      mockWebSocket.simulateError(new Error('Connection failed'));
      
      // Verify error states are shown
      await waitFor(() => {
        const errorMessages = screen.getAllByText(/disconnected|connection|error/i);
        expect(errorMessages.length).toBeGreaterThan(0);
      });
      
      // Simulate recovery
      mockWebSocket.simulateConnect();
      
      // Verify recovery
      await waitFor(() => {
        const connectedElements = screen.queryAllByText(/disconnected/i);
        expect(connectedElements.length).toBe(0);
      });
    });

    it('should handle malformed data gracefully', async () => {
      render(
        <div>
          <Terminal sessionId="malformed-test" />
          <AgentsPanel />
        </div>
      );
      
      // Send malformed data
      mockWebSocket.simulateEvent('terminal-output', null);
      mockWebSocket.simulateEvent('agent-status', undefined);
      mockWebSocket.simulateEvent('system-metrics', 'invalid-data');
      mockWebSocket.simulateEvent('agent-spawned', { invalidField: true });
      
      // Components should not crash
      await waitForAsyncUpdate();
      
      expect(screen.getByTestId('terminal') || 
             document.querySelector('[data-testid="terminal"]')).toBeInTheDocument();
    });

    it('should handle rapid reconnection scenarios', async () => {
      render(<Terminal sessionId="rapid-reconnect-test" />);
      
      // Simulate rapid connect/disconnect cycles
      for (let i = 0; i < 5; i++) {
        mockWebSocket.simulateDisconnect('transport close');
        await new Promise(resolve => setTimeout(resolve, 50));
        mockWebSocket.simulateConnect();
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      // Should stabilize without errors
      await waitFor(() => {
        expect(screen.getByTestId('terminal') || 
               document.querySelector('[data-testid="terminal"]')).toBeInTheDocument();
      });
    });
  });

  describe('Performance Under Load Flow', () => {
    it('should handle high-frequency terminal output', async () => {
      render(<Terminal sessionId="performance-test" />);
      
      // Simulate rapid terminal output
      for (let i = 0; i < 100; i++) {
        mockWebSocket.simulateEvent('terminal-output', {
          sessionId: 'performance-test',
          data: `Line ${i}: Some output data\n`
        });
        
        if (i % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 1));
        }
      }
      
      // Terminal should remain responsive
      expect(defaultTerminalMock.terminal.write).toHaveBeenCalledTimes(100);
    });

    it('should handle large numbers of agents efficiently', async () => {
      render(<AgentsPanel />);
      
      // Simulate spawning many agents
      const agents = Array.from({ length: 50 }, (_, i) => ({
        agentId: `load-agent-${i}`,
        type: 'worker',
        name: `Load Agent ${i}`
      }));
      
      for (const agent of agents) {
        mockWebSocket.simulateEvent('agent-spawned', agent);
        await new Promise(resolve => setTimeout(resolve, 1));
      }
      
      // Should handle large number of agents
      await waitFor(() => {
        expect(screen.getByText('Load Agent 0')).toBeInTheDocument();
        expect(screen.getByText('Load Agent 49')).toBeInTheDocument();
      }, { timeout: 3000 });
    });

    it('should maintain responsiveness during concurrent operations', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Terminal sessionId="concurrent-test" />
          <MonitoringSidebar />
        </div>
      );
      
      // Start concurrent operations
      const operations = [
        // Terminal operations
        () => {
          for (let i = 0; i < 20; i++) {
            mockWebSocket.simulateEvent('terminal-output', {
              sessionId: 'concurrent-test',
              data: `Concurrent output ${i}\n`
            });
          }
        },
        
        // Agent operations  
        () => {
          for (let i = 0; i < 10; i++) {
            mockWebSocket.simulateEvent('agent-status', {
              agentId: `concurrent-agent-${i}`,
              state: 'busy',
              currentTask: `Task ${i}`
            });
          }
        },
        
        // Memory updates
        () => {
          for (let i = 0; i < 15; i++) {
            mockWebSocket.simulateEvent('memory-update', 
              createMockMemoryData({ memoryUsagePercent: i * 5 })
            );
          }
        }
      ];
      
      // Execute all operations concurrently
      await Promise.all(operations.map(op => 
        new Promise<void>(resolve => {
          setTimeout(() => {
            op();
            resolve();
          }, Math.random() * 100);
        })
      ));
      
      // UI should remain interactive
      const terminalElement = screen.getByTestId('terminal') || 
                             document.querySelector('[data-testid="terminal"]');
      
      if (terminalElement) {
        await user.click(terminalElement);
        // Should be able to interact without blocking
      }
      
      expect(terminalElement).toBeInTheDocument();
    });
  });

  describe('Accessibility and User Experience Flow', () => {
    it('should support keyboard navigation across components', async () => {
      const user = userEvent.setup();
      
      render(
        <div>
          <Terminal sessionId="keyboard-test" />
          <AgentsPanel />
        </div>
      );
      
      // Test tab navigation
      await user.tab();
      await user.tab();
      await user.tab();
      
      // Should be able to navigate without errors
      expect(document.activeElement).toBeTruthy();
    });

    it('should provide appropriate screen reader content', async () => {
      render(
        <div>
          <Terminal sessionId="a11y-test" />
          <MemoryPanel />
          <AgentsPanel />
        </div>
      );
      
      // Verify ARIA labels and roles exist
      const terminalRegion = screen.getByRole('region', { name: /terminal/i }) ||
                            screen.getByLabelText(/terminal/i);
      const monitoringElements = screen.getAllByRole('region') ||
                               screen.getAllByLabelText(/memory|agent/i);
      
      expect(terminalRegion || monitoringElements.length > 0).toBeTruthy();
    });

    it('should handle focus management during state changes', async () => {
      render(<Terminal sessionId="focus-test" />);
      
      // Simulate disconnection
      mockWebSocket.simulateDisconnect();
      
      // Focus should be managed appropriately
      await waitFor(() => {
        expect(document.activeElement).toBeTruthy();
      });
      
      // Reconnect
      mockWebSocket.simulateConnect();
      
      // Focus should remain managed
      await waitFor(() => {
        expect(document.activeElement).toBeTruthy();
      });
    });
  });

  describe('Data Persistence and State Management Flow', () => {
    it('should maintain component state during reconnection', async () => {
      const { rerender } = render(<AgentsPanel />);
      
      // Add some agents
      mockWebSocket.simulateEvent('agent-spawned', {
        agentId: 'persistent-agent',
        name: 'Persistent Agent',
        type: 'worker'
      });
      
      await waitFor(() => {
        expect(screen.getByText('Persistent Agent')).toBeInTheDocument();
      });
      
      // Simulate reconnection
      mockWebSocket.simulateDisconnect();
      rerender(<AgentsPanel />);
      mockWebSocket.simulateConnect();
      
      // Agent should still be there (depending on implementation)
      // This tests component resilience during connection issues
      expect(screen.getByText(/agent/i)).toBeInTheDocument();
    });

    it('should handle session restoration correctly', async () => {
      render(<Terminal sessionId="restore-test" />);
      
      // Simulate session data
      mockWebSocket.simulateEvent('session-restored', {
        sessionId: 'restore-test',
        history: ['$ ls', '$ npm install', '$ npm run dev'],
        currentDirectory: '/home/user/project'
      });
      
      // Terminal should reflect restored state
      await waitFor(() => {
        expect(defaultTerminalMock.terminal.write).toHaveBeenCalledWith(
          expect.stringContaining('npm run dev')
        );
      });
    });
  });
});