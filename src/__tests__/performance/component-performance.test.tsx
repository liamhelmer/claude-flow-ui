import React from 'react';
import { render, fireEvent, waitFor } from '@testing-library/react';
import { act } from 'react-test-renderer';
import Tab from '@/components/tabs/Tab';
import TabList from '@/components/tabs/TabList';
import Terminal from '@/components/terminal/Terminal';
import { AgentsPanel } from '@/components/monitoring/AgentsPanel';
import { PromptPanel } from '@/components/monitoring/PromptPanel';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies for performance testing
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@/lib/state/store');
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');
jest.mock('react-tabs');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

// Performance measurement utility
const measurePerformance = async (operation: () => Promise<void> | void, label: string) => {
  const start = performance.now();
  await operation();
  const end = performance.now();
  const duration = end - start;
  
  console.log(`${label}: ${duration.toFixed(2)}ms`);
  return duration;
};

// Performance threshold constants (in milliseconds)
const PERFORMANCE_THRESHOLDS = {
  RENDER_TIME: 100,      // Initial render should be under 100ms
  UPDATE_TIME: 50,       // Updates should be under 50ms
  BULK_OPERATIONS: 200,  // Bulk operations should be under 200ms
  INTERACTION_TIME: 16,  // User interactions should be under 16ms (60fps)
};

describe('Component Performance Tests', () => {
  beforeEach(() => {
    // Setup mock implementations
    mockUseWebSocket.mockReturnValue({
      connected: true,
      connecting: false,
      isConnected: true,
      sendData: jest.fn(),
      sendMessage: jest.fn(),
      resizeTerminal: jest.fn(),
      createSession: jest.fn(),
      destroySession: jest.fn(),
      listSessions: jest.fn(),
      connect: jest.fn(),
      disconnect: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
    });

    mockUseTerminal.mockReturnValue({
      terminalRef: { current: null },
      terminal: null,
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      destroyTerminal: jest.fn(),
      scrollToBottom: jest.fn(),
      scrollToTop: jest.fn(),
      isAtBottom: true,
      hasNewOutput: false,
      isConnected: true,
    });

    mockUseAppStore.mockReturnValue({
      agents: [],
      prompts: [],
      memory: [],
      commands: [],
      sessions: [],
      activeSession: 'session-1',
      isCollapsed: false,
      error: null,
      loading: false,
      setError: jest.fn(),
      setLoading: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      setActiveSession: jest.fn(),
      toggleSidebar: jest.fn(),
    });
    
    jest.clearAllMocks();
  });

  describe('Tab Component Performance', () => {
    it('should render single tab quickly', async () => {
      const duration = await measurePerformance(() => {
        render(
          <Tab
            title="Performance Test Tab"
            isActive={false}
            onSelect={jest.fn()}
            onClose={jest.fn()}
            closable={true}
          />
        );
      }, 'Single Tab Render');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.RENDER_TIME);
    });

    it('should handle rapid state changes efficiently', async () => {
      let isActive = false;
      const onSelect = jest.fn();
      const onClose = jest.fn();
      
      const { rerender } = render(
        <Tab
          title="State Change Test"
          isActive={isActive}
          onSelect={onSelect}
          onClose={onClose}
          closable={true}
        />
      );
      
      const duration = await measurePerformance(async () => {
        // Perform 100 rapid state changes
        for (let i = 0; i < 100; i++) {
          isActive = !isActive;
          await act(async () => {
            rerender(
              <Tab
                title={`State Change Test ${i}`}
                isActive={isActive}
                onSelect={onSelect}
                onClose={onClose}
                closable={true}
              />
            );
          });
        }
      }, 'Tab State Changes (100x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });

    it('should handle click events efficiently', async () => {
      const onSelect = jest.fn();
      const { container } = render(
        <Tab
          title="Click Test"
          isActive={false}
          onSelect={onSelect}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const tabElement = container.querySelector('.tab-button');
      
      const duration = await measurePerformance(() => {
        for (let i = 0; i < 100; i++) {
          fireEvent.click(tabElement!);
        }
      }, 'Tab Clicks (100x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.INTERACTION_TIME * 100);
      expect(onSelect).toHaveBeenCalledTimes(100);
    });
  });

  describe('TabList Component Performance', () => {
    const generateTabs = (count: number) => {
      return Array.from({ length: count }, (_, i) => ({
        id: `tab-${i}`,
        title: `Tab ${i + 1}`,
        content: `Content for tab ${i + 1}`,
      }));
    };

    it('should render small tab list quickly', async () => {
      const tabs = generateTabs(5);
      
      const duration = await measurePerformance(() => {
        render(
          <TabList
            tabs={tabs}
            activeTab="tab-0"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );
      }, 'Small TabList Render (5 tabs)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.RENDER_TIME);
    });

    it('should render large tab list efficiently', async () => {
      const tabs = generateTabs(100);
      
      const duration = await measurePerformance(() => {
        render(
          <TabList
            tabs={tabs}
            activeTab="tab-50"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );
      }, 'Large TabList Render (100 tabs)');
      
      // Large list should still be reasonably fast
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });

    it('should handle active tab changes efficiently', async () => {
      const tabs = generateTabs(50);
      let activeTab = 'tab-0';
      
      const { rerender } = render(
        <TabList
          tabs={tabs}
          activeTab={activeTab}
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const duration = await measurePerformance(async () => {
        // Switch between tabs rapidly
        for (let i = 0; i < 50; i++) {
          activeTab = `tab-${i}`;
          await act(async () => {
            rerender(
              <TabList
                tabs={tabs}
                activeTab={activeTab}
                onTabSelect={jest.fn()}
                onTabClose={jest.fn()}
              />
            );
          });
        }
      }, 'Tab Switching (50x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });

    it('should handle dynamic tab list updates', async () => {
      let tabs = generateTabs(10);
      
      const { rerender } = render(
        <TabList
          tabs={tabs}
          activeTab="tab-0"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const duration = await measurePerformance(async () => {
        // Add tabs dynamically
        for (let i = 10; i < 60; i++) {
          tabs = [...tabs, { id: `tab-${i}`, title: `Tab ${i + 1}`, content: `Content ${i + 1}` }];
          await act(async () => {
            rerender(
              <TabList
                tabs={tabs}
                activeTab="tab-0"
                onTabSelect={jest.fn()}
                onTabClose={jest.fn()}
              />
            );
          });
        }
      }, 'Dynamic Tab Addition (50 tabs)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });
  });

  describe('Terminal Component Performance', () => {
    it('should render terminal quickly', async () => {
      const duration = await measurePerformance(() => {
        render(<Terminal sessionId="perf-test-session" />);
      }, 'Terminal Render');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.RENDER_TIME);
    });

    it('should handle session changes efficiently', async () => {
      let sessionId = 'session-1';
      
      const { rerender } = render(<Terminal sessionId={sessionId} />);
      
      const duration = await measurePerformance(async () => {
        // Simulate rapid session switching
        for (let i = 2; i <= 51; i++) {
          sessionId = `session-${i}`;
          await act(async () => {
            rerender(<Terminal sessionId={sessionId} />);
          });
        }
      }, 'Terminal Session Switching (50x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });

    it('should handle rapid data updates efficiently', async () => {
      const mockWriteToTerminal = jest.fn();
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        writeToTerminal: mockWriteToTerminal,
      });
      
      render(<Terminal sessionId="data-test-session" />);
      
      const duration = await measurePerformance(() => {
        // Simulate rapid terminal output
        for (let i = 0; i < 1000; i++) {
          mockWriteToTerminal(`Line ${i} - Some terminal output\n`);
        }
      }, 'Terminal Data Updates (1000x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
      expect(mockWriteToTerminal).toHaveBeenCalledTimes(1000);
    });
  });

  describe('Monitoring Component Performance', () => {
    it('should render AgentsPanel efficiently', async () => {
      // Mock large dataset
      mockUseAppStore.mockReturnValue({
        ...mockUseAppStore(),
        agents: Array.from({ length: 100 }, (_, i) => ({
          id: `agent-${i}`,
          name: `Agent ${i}`,
          status: i % 2 === 0 ? 'active' : 'inactive',
          lastSeen: new Date().toISOString(),
        })),
      });
      
      const duration = await measurePerformance(() => {
        render(<AgentsPanel />);
      }, 'AgentsPanel Render (100 agents)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.RENDER_TIME);
    });

    it('should render PromptPanel efficiently', async () => {
      // Mock large prompt history
      mockUseAppStore.mockReturnValue({
        ...mockUseAppStore(),
        prompts: Array.from({ length: 500 }, (_, i) => ({
          id: `prompt-${i}`,
          text: `Prompt ${i} - ${"x".repeat(100)}`, // Longer prompts
          timestamp: new Date().toISOString(),
          response: `Response ${i} - ${"y".repeat(200)}`,
        })),
      });
      
      const duration = await measurePerformance(() => {
        render(<PromptPanel />);
      }, 'PromptPanel Render (500 prompts)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });

    it('should handle rapid data updates in monitoring panels', async () => {
      const { rerender } = render(<AgentsPanel />);
      
      const duration = await measurePerformance(async () => {
        // Simulate rapid agent status updates
        for (let i = 0; i < 100; i++) {
          const agents = Array.from({ length: 10 }, (_, j) => ({
            id: `agent-${j}`,
            name: `Agent ${j}`,
            status: Math.random() > 0.5 ? 'active' : 'inactive',
            lastSeen: new Date().toISOString(),
          }));
          
          mockUseAppStore.mockReturnValue({
            ...mockUseAppStore(),
            agents,
          });
          
          await act(async () => {
            rerender(<AgentsPanel />);
          });
        }
      }, 'Agent Status Updates (100x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });
  });

  describe('Memory Performance Tests', () => {
    it('should not cause memory leaks with frequent re-renders', async () => {
      const { rerender, unmount } = render(
        <Tab
          title="Memory Test"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      // Get initial memory usage
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Perform many re-renders
      for (let i = 0; i < 1000; i++) {
        await act(async () => {
          rerender(
            <Tab
              title={`Memory Test ${i}`}
              isActive={i % 2 === 0}
              onSelect={jest.fn()}
              onClose={jest.fn()}
              closable={true}
            />
          );
        });
        
        // Force garbage collection every 100 iterations
        if (i % 100 === 0 && global.gc) {
          global.gc();
        }
      }
      
      unmount();
      
      // Force final garbage collection
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    it('should cleanup event listeners properly', async () => {
      const mockOn = jest.fn();
      const mockOff = jest.fn();
      
      mockUseWebSocket.mockReturnValue({
        ...mockUseWebSocket(),
        on: mockOn,
        off: mockOff,
      });
      
      const { unmount } = render(<Terminal sessionId="cleanup-test" />);
      
      // Should have registered event listeners
      expect(mockOn).toHaveBeenCalled();
      
      unmount();
      
      // Should have cleaned up event listeners
      expect(mockOff).toHaveBeenCalled();
      expect(mockOff).toHaveBeenCalledTimes(mockOn.mock.calls.length);
    });
  });

  describe('Concurrent Operations Performance', () => {
    it('should handle multiple components rendering simultaneously', async () => {
      const tabs = Array.from({ length: 20 }, (_, i) => ({
        id: `tab-${i}`,
        title: `Tab ${i}`,
        content: `Content ${i}`,
      }));
      
      const duration = await measurePerformance(() => {
        // Render multiple components at once
        render(
          <div>
            <TabList
              tabs={tabs}
              activeTab="tab-0"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
            <Terminal sessionId="concurrent-1" />
            <Terminal sessionId="concurrent-2" />
            <AgentsPanel />
            <PromptPanel />
          </div>
        );
      }, 'Concurrent Component Render');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });

    it('should handle simultaneous updates across components', async () => {
      const { rerender } = render(
        <div>
          <Terminal sessionId="update-test-1" />
          <Terminal sessionId="update-test-2" />
          <AgentsPanel />
        </div>
      );
      
      const duration = await measurePerformance(async () => {
        // Simulate simultaneous updates
        for (let i = 0; i < 50; i++) {
          await act(async () => {
            rerender(
              <div>
                <Terminal sessionId={`update-test-1-${i}`} />
                <Terminal sessionId={`update-test-2-${i}`} />
                <AgentsPanel key={i} />
              </div>
            );
          });
        }
      }, 'Simultaneous Component Updates (50x)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });
  });

  describe('Large Data Set Performance', () => {
    it('should handle very large tab lists', async () => {
      const largeTabs = Array.from({ length: 1000 }, (_, i) => ({
        id: `large-tab-${i}`,
        title: `Large Tab ${i} - ${'x'.repeat(50)}`,
        content: `Content ${i} - ${'y'.repeat(1000)}`,
      }));
      
      const duration = await measurePerformance(() => {
        render(
          <TabList
            tabs={largeTabs}
            activeTab="large-tab-500"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );
      }, 'Very Large TabList (1000 tabs)');
      
      // Should still render within reasonable time
      expect(duration).toBeLessThan(1000); // 1 second max for extreme cases
    });

    it('should handle complex title strings efficiently', async () => {
      const complexTabs = Array.from({ length: 100 }, (_, i) => ({
        id: `complex-${i}`,
        title: `🚀 Terminal Session #${i} (Production) - Running complex command with very long output ${"x".repeat(100)} - Status: ${i % 3 === 0 ? 'Running' : i % 3 === 1 ? 'Completed' : 'Failed'} 🔥`,
        content: `Complex content ${i}`,
      }));
      
      const duration = await measurePerformance(() => {
        render(
          <TabList
            tabs={complexTabs}
            activeTab="complex-50"
            onTabSelect={jest.fn()}
            onTabClose={jest.fn()}
          />
        );
      }, 'Complex Title TabList (100 tabs)');
      
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BULK_OPERATIONS);
    });
  });
});
