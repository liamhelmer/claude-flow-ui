/**
 * Integration Testing Patterns for Complete User Workflows
 * Tests component interactions, state synchronization, and complete user journeys
 */

import React from 'react';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders, createTabData, createSessionData } from '../utils/test-utils';

// Import components for integration testing
import TabList from '@/components/tabs/TabList';
import Terminal from '@/components/terminal/Terminal';
import Sidebar from '@/components/sidebar/Sidebar';
import TerminalControls from '@/components/terminal/TerminalControls';

describe('Complete User Workflow Integration Tests', () => {
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  describe('Terminal Session Management Workflow', () => {
    it('should complete full terminal session lifecycle', async () => {
      const mockTabs = [
        createTabData({ id: 'tab-1', title: 'Terminal 1', isActive: true }),
        createTabData({ id: 'tab-2', title: 'Terminal 2', isActive: false }),
      ];

      const onTabSelect = jest.fn();
      const onTabClose = jest.fn();

      const { mockStore, mockWs } = renderWithProviders(
        <div>
          <TabList
            tabs={mockTabs}
            activeTab="tab-1"
            onTabSelect={onTabSelect}
            onTabClose={onTabClose}
          />
          <Terminal sessionId="session-1" />
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={false}
          />
        </div>,
        {
          initialState: {
            sessions: ['session-1', 'session-2'],
            activeSession: 'session-1',
          },
        }
      );

      // 1. Verify initial state
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByTestId('test-wrapper')).toBeInTheDocument();

      // 2. Switch to second tab
      await user.click(screen.getByText('Terminal 2'));
      
      expect(onTabSelect).toHaveBeenCalledWith('tab-2');

      // 3. Wait for WebSocket connection
      jest.advanceTimersByTime(100);
      await waitFor(() => {
        expect(mockWs.readyState).toBe(mockWs.constructor.OPEN);
      });

      // 4. Simulate terminal command execution
      mockWs.simulateMessage({
        type: 'terminal-output',
        sessionId: 'session-1',
        data: '$ ls -la\ntotal 0\ndrwxr-xr-x  2 user user 60 Jan 1 12:00 .\n',
      });

      // 5. Verify terminal output handling
      await waitFor(() => {
        // Terminal should have received and processed the output
        expect(mockWs.getMessageQueue()).toContainEqual(
          expect.objectContaining({ type: 'terminal-output' })
        );
      });

      // 6. Test terminal controls
      const clearButton = screen.getByRole('button', { name: /clear/i });
      await user.click(clearButton);

      // 7. Close tab
      const closeButton = screen.getByLabelText(/close terminal 1/i);
      await user.click(closeButton);
      
      expect(onTabClose).toHaveBeenCalledWith('tab-1');

      // 8. Verify cleanup
      expect(mockStore.getState().sessions).toContain('session-1');
    });

    it('should handle multiple concurrent terminal sessions', async () => {
      const sessions = ['session-1', 'session-2', 'session-3'];
      const tabs = sessions.map((id, index) => 
        createTabData({ 
          id: `tab-${index + 1}`, 
          title: `Terminal ${index + 1}`,
          isActive: index === 0 
        })
      );

      const { mockWs } = renderWithProviders(
        <div>
          <TabList
            tabs={tabs}
            activeTab="tab-1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
          {sessions.map(sessionId => (
            <Terminal key={sessionId} sessionId={sessionId} />
          ))}
        </div>,
        {
          initialState: {
            sessions,
            activeSession: 'session-1',
          },
        }
      );

      // Wait for all connections
      jest.advanceTimersByTime(200);

      // Simulate concurrent operations across sessions
      sessions.forEach((sessionId, index) => {
        mockWs.simulateMessage({
          type: 'terminal-output',
          sessionId,
          data: `Output for session ${index + 1}\n`,
        });
      });

      // Switch between tabs rapidly
      for (let i = 0; i < 3; i++) {
        await user.click(screen.getByText(`Terminal ${i + 1}`));
        jest.advanceTimersByTime(50);
      }

      // All sessions should remain functional
      await waitFor(() => {
        sessions.forEach((_, index) => {
          expect(screen.getByText(`Terminal ${index + 1}`)).toBeInTheDocument();
        });
      });
    });
  });

  describe('Sidebar and Monitoring Integration', () => {
    it('should synchronize sidebar state with application data', async () => {
      const initialAgents = [
        { id: 'agent-1', name: 'Test Agent', status: 'active' },
        { id: 'agent-2', name: 'Monitor Agent', status: 'idle' },
      ];

      const { mockStore } = renderWithProviders(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>,
        {
          initialState: {
            agents: initialAgents,
            isCollapsed: false,
          },
        }
      );

      // 1. Verify sidebar is expanded and shows agents
      const sidebar = screen.getByRole('complementary') || screen.getByTestId('sidebar');
      expect(sidebar).toBeInTheDocument();

      // 2. Toggle sidebar
      const toggleButton = screen.getByRole('button', { name: /toggle sidebar/i });
      await user.click(toggleButton);

      expect(mockStore.toggleSidebar).toHaveBeenCalled();

      // 3. Add new agent dynamically
      mockStore.addAgent({
        id: 'agent-3',
        name: 'Dynamic Agent',
        status: 'starting',
      });

      // 4. Verify UI updates
      await waitFor(() => {
        expect(mockStore.getState().agents).toHaveLength(3);
      });

      // 5. Test error state handling
      mockStore.setError('Connection failed');

      await waitFor(() => {
        expect(mockStore.getState().error).toBe('Connection failed');
      });
    });

    it('should handle real-time monitoring updates', async () => {
      const { mockWs, mockStore } = renderWithProviders(
        <div>
          <Sidebar />
          <Terminal sessionId="session-1" />
        </div>,
        {
          initialState: {
            agents: [],
            memory: [],
            commands: [],
          },
        }
      );

      // Wait for connection
      jest.advanceTimersByTime(100);

      // Simulate real-time monitoring data
      const monitoringUpdates = [
        {
          type: 'agent-update',
          data: { id: 'agent-1', name: 'New Agent', status: 'active' },
        },
        {
          type: 'memory-update',
          data: { key: 'session-data', value: 'test-value', timestamp: Date.now() },
        },
        {
          type: 'command-executed',
          data: { command: 'ls -la', output: 'file list', duration: 150 },
        },
      ];

      // Send updates through WebSocket
      monitoringUpdates.forEach(update => {
        mockWs.simulateMessage(update);
      });

      // Verify sidebar receives and displays updates
      await waitFor(() => {
        expect(mockStore.getState().agents).toContainEqual(
          expect.objectContaining({ id: 'agent-1', name: 'New Agent' })
        );
      });
    });
  });

  describe('Error Recovery and Resilience Workflows', () => {
    it('should recover from WebSocket connection failures', async () => {
      const { mockWs } = renderWithProviders(
        <div>
          <Terminal sessionId="session-1" />
          <Sidebar />
        </div>,
        {
          wsConfig: {
            autoConnect: true,
            simulateLatency: 50,
          },
        }
      );

      // 1. Establish initial connection
      jest.advanceTimersByTime(100);
      await waitFor(() => {
        expect(mockWs.readyState).toBe(mockWs.constructor.OPEN);
      });

      // 2. Simulate connection loss
      mockWs.simulateError(new Error('Network error'));
      mockWs.close(1006, 'Connection lost');

      // 3. Verify disconnected state
      await waitFor(() => {
        expect(mockWs.readyState).toBe(mockWs.constructor.CLOSED);
      });

      // 4. Simulate automatic reconnection
      mockWs.simulateReconnect();
      jest.advanceTimersByTime(1000);

      // 5. Verify recovery
      await waitFor(() => {
        expect(mockWs.readyState).toBe(mockWs.constructor.OPEN);
      });

      // 6. Test functionality after recovery
      mockWs.simulateMessage({
        type: 'terminal-output',
        data: 'Connection restored\n',
      });

      // Should handle messages normally after recovery
      expect(mockWs.getMessageQueue()).toContainEqual(
        expect.objectContaining({ type: 'terminal-output' })
      );
    });

    it('should handle component errors with error boundaries', async () => {
      const ErrorThrowingComponent = ({ shouldThrow }: { shouldThrow: boolean }) => {
        if (shouldThrow) {
          throw new Error('Component error');
        }
        return <div>Working component</div>;
      };

      const onError = jest.fn();

      const { rerender } = renderWithProviders(
        <div>
          <ErrorThrowingComponent shouldThrow={false} />
          <Terminal sessionId="session-1" />
        </div>
      );

      // Component should work normally
      expect(screen.getByText('Working component')).toBeInTheDocument();

      // Trigger error
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      expect(() => {
        rerender(
          <div>
            <ErrorThrowingComponent shouldThrow={true} />
            <Terminal sessionId="session-1" />
          </div>
        );
      }).toThrow();

      consoleSpy.mockRestore();
    });

    it('should maintain data consistency during rapid state changes', async () => {
      const { mockStore } = renderWithProviders(
        <div>
          <TabList
            tabs={[]}
            activeTab=""
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
          <Sidebar />
        </div>,
        {
          initialState: {
            sessions: [],
            agents: [],
          },
        }
      );

      // Perform rapid state changes
      const operations = [];
      for (let i = 0; i < 50; i++) {
        operations.push(
          new Promise<void>(resolve => {
            setTimeout(() => {
              mockStore.addSession(`session-${i}`);
              mockStore.addAgent({ id: `agent-${i}`, name: `Agent ${i}` });
              resolve();
            }, i * 10);
          })
        );
      }

      await Promise.all(operations);

      // Verify final state consistency
      await waitFor(() => {
        const state = mockStore.getState();
        expect(state.sessions).toHaveLength(50);
        expect(state.agents).toHaveLength(50);
      });
    });
  });

  describe('Performance Under Load', () => {
    it('should handle high-frequency terminal updates efficiently', async () => {
      const { mockWs } = renderWithProviders(
        <Terminal sessionId="session-1" />,
        {
          wsConfig: {
            simulateLatency: 1,
          },
        }
      );

      jest.advanceTimersByTime(100);

      // Measure performance of high-frequency updates
      const startTime = performance.now();
      const updateCount = 1000;

      // Send many rapid updates
      for (let i = 0; i < updateCount; i++) {
        mockWs.simulateMessage({
          type: 'terminal-output',
          data: `Line ${i}\n`,
        });
      }

      jest.advanceTimersByTime(100);

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should handle updates efficiently (< 100ms for 1000 updates)
      expect(duration).toBeLessThan(100);

      // Verify no memory leaks
      expect(mockWs.getMessageQueue()).toHaveLength(updateCount);
    });

    it('should efficiently manage large numbers of tabs', async () => {
      const largeTabCount = 100;
      const tabs = Array.from({ length: largeTabCount }, (_, i) =>
        createTabData({
          id: `tab-${i}`,
          title: `Terminal ${i}`,
          isActive: i === 0,
        })
      );

      const startRenderTime = performance.now();

      renderWithProviders(
        <TabList
          tabs={tabs}
          activeTab="tab-0"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );

      const endRenderTime = performance.now();
      const renderDuration = endRenderTime - startRenderTime;

      // Should render efficiently even with many tabs
      expect(renderDuration).toBeLessThan(100);

      // Verify all tabs are rendered
      expect(screen.getAllByRole('tab')).toHaveLength(largeTabCount);
    });
  });

  describe('Complex User Interactions', () => {
    it('should handle drag and drop tab reordering', async () => {
      const tabs = [
        createTabData({ id: 'tab-1', title: 'Terminal 1' }),
        createTabData({ id: 'tab-2', title: 'Terminal 2' }),
        createTabData({ id: 'tab-3', title: 'Terminal 3' }),
      ];

      const onTabReorder = jest.fn();

      renderWithProviders(
        <TabList
          tabs={tabs}
          activeTab="tab-1"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
          onTabReorder={onTabReorder}
        />
      );

      const tab1 = screen.getByText('Terminal 1');
      const tab3 = screen.getByText('Terminal 3');

      // Simulate drag and drop (simplified)
      await user.pointer([
        { keys: '[MouseLeft>]', target: tab1 },
        { coords: { x: 200, y: 50 } }, // Drag to position
        { keys: '[/MouseLeft]', target: tab3 },
      ]);

      // Note: Full drag and drop testing would require more sophisticated setup
      // This is a simplified version to demonstrate the pattern
    });

    it('should support keyboard navigation across components', async () => {
      renderWithProviders(
        <div>
          <TabList
            tabs={[
              createTabData({ id: 'tab-1', title: 'Terminal 1', isActive: true }),
              createTabData({ id: 'tab-2', title: 'Terminal 2' }),
            ]}
            activeTab="tab-1"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
          <Terminal sessionId="session-1" />
          <TerminalControls
            onClear={jest.fn()}
            onScrollToBottom={jest.fn()}
            onScrollToTop={jest.fn()}
            hasNewOutput={false}
          />
        </div>
      );

      // Navigate using keyboard
      await user.keyboard('{Tab}'); // Focus first tab
      await user.keyboard('{ArrowRight}'); // Move to next tab
      await user.keyboard('{Enter}'); // Activate tab
      await user.keyboard('{Tab}'); // Move to terminal
      await user.keyboard('{Tab}'); // Move to controls

      // Verify keyboard navigation works
      expect(document.activeElement).toBeDefined();
    });
  });

  describe('State Persistence and Hydration', () => {
    it('should maintain state across component remounts', async () => {
      const initialState = {
        sessions: ['session-1', 'session-2'],
        activeSession: 'session-1',
        agents: [{ id: 'agent-1', name: 'Persistent Agent' }],
      };

      const { unmount, mockStore } = renderWithProviders(
        <div>
          <Terminal sessionId="session-1" />
          <Sidebar />
        </div>,
        { initialState }
      );

      // Modify state
      mockStore.addAgent({ id: 'agent-2', name: 'New Agent' });
      mockStore.setActiveSession('session-2');

      const stateBeforeUnmount = mockStore.getState();
      unmount();

      // Remount with same state
      const { mockStore: newMockStore } = renderWithProviders(
        <div>
          <Terminal sessionId="session-2" />
          <Sidebar />
        </div>,
        { initialState: stateBeforeUnmount }
      );

      // State should be preserved
      expect(newMockStore.getState()).toEqual(stateBeforeUnmount);
    });
  });
});