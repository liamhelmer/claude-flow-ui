/**
 * Performance Testing Benchmarks and Patterns
 * Comprehensive performance testing for Claude Flow UI components
 */

import React from 'react';
import { render, cleanup } from '@testing-library/react';
import { renderWithProviders, measureRenderTime, measureMemoryUsage } from '../utils/test-utils';

// Import components for performance testing
import TabList from '@/components/tabs/TabList';
import Terminal from '@/components/terminal/Terminal';
import Sidebar from '@/components/sidebar/Sidebar';

// Performance test utilities
interface PerformanceMetrics {
  renderTime: number;
  memoryUsage: number;
  componentCount: number;
  rerenderTime?: number;
  memoryLeak?: number;
}

interface PerformanceBudget {
  maxRenderTime: number;
  maxMemoryUsage: number;
  maxRerenderTime: number;
  maxMemoryLeak: number;
}

const PERFORMANCE_BUDGETS: Record<string, PerformanceBudget> = {
  small: {
    maxRenderTime: 16, // 60fps budget
    maxMemoryUsage: 5 * 1024 * 1024, // 5MB
    maxRerenderTime: 8, // Half frame budget
    maxMemoryLeak: 1 * 1024 * 1024, // 1MB
  },
  medium: {
    maxRenderTime: 33, // 30fps budget
    maxMemoryUsage: 15 * 1024 * 1024, // 15MB
    maxRerenderTime: 16, // Frame budget
    maxMemoryLeak: 3 * 1024 * 1024, // 3MB
  },
  large: {
    maxRenderTime: 66, // 15fps budget
    maxMemoryUsage: 50 * 1024 * 1024, // 50MB
    maxRerenderTime: 33, // Two frame budget
    maxMemoryLeak: 10 * 1024 * 1024, // 10MB
  },
};

const measureComponentPerformance = <T extends Record<string, any>>(
  Component: React.ComponentType<T>,
  props: T,
  iterations = 10
): PerformanceMetrics => {
  const renderTimes: number[] = [];
  const memoryUsages: number[] = [];
  
  for (let i = 0; i < iterations; i++) {
    const renderTime = measureRenderTime(() => {
      render(<Component {...props} />);
    });
    
    const memoryUsage = measureMemoryUsage(() => {
      // Simulate component operations
      cleanup();
    });
    
    renderTimes.push(renderTime);
    memoryUsages.push(Math.abs(memoryUsage));
  }
  
  return {
    renderTime: renderTimes.reduce((a, b) => a + b, 0) / renderTimes.length,
    memoryUsage: memoryUsages.reduce((a, b) => a + b, 0) / memoryUsages.length,
    componentCount: 1,
  };
};

const createLargeDataset = (size: number) => ({
  tabs: Array.from({ length: size }, (_, i) => ({
    id: `tab-${i}`,
    title: `Terminal ${i + 1}`,
    content: `Content for terminal ${i + 1}`,
    isActive: i === 0,
    closable: true,
  })),
  sessions: Array.from({ length: size }, (_, i) => `session-${i}`),
  agents: Array.from({ length: size }, (_, i) => ({
    id: `agent-${i}`,
    name: `Agent ${i + 1}`,
    status: 'active',
    lastSeen: new Date().toISOString(),
  })),
});

describe('Performance Benchmarks', () => {
  beforeEach(() => {
    // Clear any existing timers and force garbage collection
    jest.clearAllTimers();
    if (global.gc) {
      global.gc();
    }
  });

  describe('Component Rendering Performance', () => {
    describe('TabList Component', () => {
      it('should render small tab lists within performance budget', () => {
        const { tabs } = createLargeDataset(5);
        const budget = PERFORMANCE_BUDGETS.small;
        
        const metrics = measureComponentPerformance(
          TabList,
          {
            tabs,
            activeTab: 'tab-0',
            onTabSelect: jest.fn(),
            onTabClose: jest.fn(),
          }
        );
        
        expect(metrics.renderTime).toBeLessThan(budget.maxRenderTime);
        expect(metrics.memoryUsage).toBeLessThan(budget.maxMemoryUsage);
      });

      it('should render medium tab lists within performance budget', () => {
        const { tabs } = createLargeDataset(25);
        const budget = PERFORMANCE_BUDGETS.medium;
        
        const metrics = measureComponentPerformance(
          TabList,
          {
            tabs,
            activeTab: 'tab-0',
            onTabSelect: jest.fn(),
            onTabClose: jest.fn(),
          }
        );
        
        expect(metrics.renderTime).toBeLessThan(budget.maxRenderTime);
        expect(metrics.memoryUsage).toBeLessThan(budget.maxMemoryUsage);
      });

      it('should render large tab lists within performance budget', () => {
        const { tabs } = createLargeDataset(100);
        const budget = PERFORMANCE_BUDGETS.large;
        
        const metrics = measureComponentPerformance(
          TabList,
          {
            tabs,
            activeTab: 'tab-0',
            onTabSelect: jest.fn(),
            onTabClose: jest.fn(),
          }
        );
        
        expect(metrics.renderTime).toBeLessThan(budget.maxRenderTime);
        expect(metrics.memoryUsage).toBeLessThan(budget.maxMemoryUsage);
      });

      it('should handle rapid tab switching efficiently', async () => {
        const { tabs } = createLargeDataset(20);
        let activeTab = 'tab-0';
        
        const { rerender } = render(
          <TabList
            tabs={tabs}
            activeTab={activeTab}
            onTabSelect={(id) => { activeTab = id; }}
            onTabClose={jest.fn()}
          />
        );
        
        const budget = PERFORMANCE_BUDGETS.small;
        const switchTimes: number[] = [];
        
        // Measure tab switching performance
        for (let i = 0; i < 10; i++) {
          const newActiveTab = `tab-${i}`;
          const switchTime = measureRenderTime(() => {
            rerender(
              <TabList
                tabs={tabs}
                activeTab={newActiveTab}
                onTabSelect={(id) => { activeTab = id; }}
                onTabClose={jest.fn()}
              />
            );
          });
          switchTimes.push(switchTime);
        }
        
        const averageSwitchTime = switchTimes.reduce((a, b) => a + b, 0) / switchTimes.length;
        expect(averageSwitchTime).toBeLessThan(budget.maxRerenderTime);
      });
    });

    describe('Terminal Component', () => {
      it('should render terminal within performance budget', () => {
        const budget = PERFORMANCE_BUDGETS.medium;
        
        const metrics = measureComponentPerformance(
          Terminal,
          { sessionId: 'test-session' }
        );
        
        expect(metrics.renderTime).toBeLessThan(budget.maxRenderTime);
        expect(metrics.memoryUsage).toBeLessThan(budget.maxMemoryUsage);
      });

      it('should handle frequent terminal updates efficiently', () => {
        const { mockWs } = renderWithProviders(
          <Terminal sessionId="test-session" />
        );
        
        const budget = PERFORMANCE_BUDGETS.medium;
        const updateCount = 1000;
        const updates: string[] = [];
        
        // Generate large number of updates
        for (let i = 0; i < updateCount; i++) {
          updates.push(`Line ${i}: ${'x'.repeat(50)}\n`);
        }
        
        const updateTime = measureRenderTime(() => {
          updates.forEach(update => {
            mockWs.simulateMessage({
              type: 'terminal-output',
              data: update,
            });
          });
        });
        
        // Should handle many updates efficiently
        expect(updateTime).toBeLessThan(budget.maxRenderTime * 10); // 10x budget for bulk operations
      });

      it('should handle terminal resizing efficiently', () => {
        const { container } = renderWithProviders(
          <Terminal sessionId="test-session" />
        );
        
        const budget = PERFORMANCE_BUDGETS.small;
        const resizeTimes: number[] = [];
        
        // Simulate multiple resize events
        for (let i = 0; i < 20; i++) {
          const resizeTime = measureRenderTime(() => {
            // Mock container size change
            Object.defineProperty(container, 'clientWidth', {
              configurable: true,
              value: 800 + i * 10,
            });
            Object.defineProperty(container, 'clientHeight', {
              configurable: true,
              value: 600 + i * 5,
            });
            
            // Trigger resize event
            window.dispatchEvent(new Event('resize'));
          });
          
          resizeTimes.push(resizeTime);
        }
        
        const averageResizeTime = resizeTimes.reduce((a, b) => a + b, 0) / resizeTimes.length;
        expect(averageResizeTime).toBeLessThan(budget.maxRerenderTime);
      });
    });

    describe('Sidebar Component', () => {
      it('should render sidebar with large datasets efficiently', () => {
        const { agents } = createLargeDataset(100);
        const budget = PERFORMANCE_BUDGETS.medium;
        
        const metrics = measureComponentPerformance(
          () => <Sidebar />,
          {},
          5 // Fewer iterations for complex component
        );
        
        expect(metrics.renderTime).toBeLessThan(budget.maxRenderTime);
        expect(metrics.memoryUsage).toBeLessThan(budget.maxMemoryUsage);
      });
    });
  });

  describe('Memory Management Performance', () => {
    it('should not leak memory during component lifecycle', () => {
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const iterations = 50;
      
      for (let i = 0; i < iterations; i++) {
        const { unmount } = render(
          <Terminal sessionId={`session-${i}`} />
        );
        unmount();
      }
      
      // Force garbage collection
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Should not leak significant memory
      expect(memoryIncrease).toBeLessThan(PERFORMANCE_BUDGETS.medium.maxMemoryLeak);
    });

    it('should handle rapid component mounting/unmounting efficiently', () => {
      const budget = PERFORMANCE_BUDGETS.medium;
      const mountUnmountCycles = 100;
      
      const cycleTime = measureRenderTime(() => {
        for (let i = 0; i < mountUnmountCycles; i++) {
          const { unmount } = render(
            <TabList
              tabs={[{ id: 'tab-1', title: 'Test Tab', content: 'Test' }]}
              activeTab="tab-1"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
          );
          unmount();
        }
      });
      
      expect(cycleTime / mountUnmountCycles).toBeLessThan(budget.maxRerenderTime);
    });

    it('should efficiently manage WebSocket connections', () => {
      const connectionCount = 10;
      const connections: any[] = [];
      
      const createTime = measureRenderTime(() => {
        for (let i = 0; i < connectionCount; i++) {
          const { mockWs, unmount } = renderWithProviders(
            <Terminal sessionId={`session-${i}`} />
          );
          connections.push({ mockWs, unmount });
        }
      });
      
      const cleanupTime = measureRenderTime(() => {
        connections.forEach(({ unmount }) => unmount());
      });
      
      const budget = PERFORMANCE_BUDGETS.medium;
      expect(createTime / connectionCount).toBeLessThan(budget.maxRenderTime);
      expect(cleanupTime / connectionCount).toBeLessThan(budget.maxRerenderTime);
    });
  });

  describe('Interaction Performance', () => {
    it('should handle rapid user interactions efficiently', async () => {
      const { tabs } = createLargeDataset(20);
      const onTabSelect = jest.fn();
      
      const { container } = render(
        <TabList
          tabs={tabs}
          activeTab="tab-0"
          onTabSelect={onTabSelect}
          onTabClose={jest.fn()}
        />
      );
      
      const tabElements = container.querySelectorAll('[role="tab"]');
      const budget = PERFORMANCE_BUDGETS.small;
      
      // Simulate rapid clicking
      const clickTime = measureRenderTime(() => {
        tabElements.forEach((tab, index) => {
          // Simulate click event
          const clickEvent = new MouseEvent('click', { bubbles: true });
          tab.dispatchEvent(clickEvent);
        });
      });
      
      expect(clickTime / tabElements.length).toBeLessThan(budget.maxRerenderTime);
      expect(onTabSelect).toHaveBeenCalledTimes(tabElements.length);
    });

    it('should handle keyboard navigation efficiently', () => {
      const { tabs } = createLargeDataset(50);
      
      const { container } = render(
        <TabList
          tabs={tabs}
          activeTab="tab-0"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const firstTab = container.querySelector('[role="tab"]') as HTMLElement;
      const budget = PERFORMANCE_BUDGETS.small;
      
      // Simulate keyboard navigation
      const navigationTime = measureRenderTime(() => {
        for (let i = 0; i < 20; i++) {
          const keyEvent = new KeyboardEvent('keydown', {
            key: 'ArrowRight',
            bubbles: true,
          });
          firstTab.dispatchEvent(keyEvent);
        }
      });
      
      expect(navigationTime / 20).toBeLessThan(budget.maxRerenderTime);
    });
  });

  describe('Large Scale Performance Tests', () => {
    it('should handle enterprise-scale data volumes', () => {
      const enterpriseDataset = createLargeDataset(500);
      const budget = PERFORMANCE_BUDGETS.large;
      
      const renderTime = measureRenderTime(() => {
        render(
          <div>
            <TabList
              tabs={enterpriseDataset.tabs.slice(0, 100)} // Limit visible tabs
              activeTab="tab-0"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
            <Sidebar />
          </div>
        );
      });
      
      expect(renderTime).toBeLessThan(budget.maxRenderTime * 2); // Allow 2x budget for complex scenarios
    });

    it('should maintain performance with high-frequency updates', () => {
      const { mockWs } = renderWithProviders(
        <div>
          <Terminal sessionId="session-1" />
          <Terminal sessionId="session-2" />
          <Terminal sessionId="session-3" />
        </div>
      );
      
      const budget = PERFORMANCE_BUDGETS.medium;
      const updateFrequency = 100; // Updates per second
      const duration = 1000; // 1 second test
      
      const updateTime = measureRenderTime(() => {
        for (let i = 0; i < updateFrequency; i++) {
          setTimeout(() => {
            mockWs.simulateMessage({
              type: 'terminal-output',
              sessionId: `session-${(i % 3) + 1}`,
              data: `High frequency update ${i}\n`,
            });
          }, (i / updateFrequency) * duration);
        }
        
        // Advance timers to process all updates
        jest.advanceTimersByTime(duration);
      });
      
      expect(updateTime / updateFrequency).toBeLessThan(budget.maxRerenderTime);
    });

    it('should handle stress testing scenarios', () => {
      const stressTestData = {
        tabs: createLargeDataset(200).tabs,
        terminals: Array.from({ length: 50 }, (_, i) => `session-${i}`),
        updates: Array.from({ length: 10000 }, (_, i) => ({
          type: 'terminal-output',
          sessionId: `session-${i % 50}`,
          data: `Stress test output ${i}\n`,
        })),
      };
      
      const budget = PERFORMANCE_BUDGETS.large;
      
      const stressTestTime = measureRenderTime(() => {
        const { mockWs } = renderWithProviders(
          <div>
            <TabList
              tabs={stressTestData.tabs.slice(0, 50)}
              activeTab="tab-0"
              onTabSelect={jest.fn()}
              onTabClose={jest.fn()}
            />
            {stressTestData.terminals.slice(0, 10).map(sessionId => (
              <Terminal key={sessionId} sessionId={sessionId} />
            ))}
          </div>
        );
        
        // Send stress test updates
        stressTestData.updates.forEach((update, index) => {
          setTimeout(() => {
            mockWs.simulateMessage(update);
          }, index % 100); // Batch updates
        });
        
        jest.advanceTimersByTime(1000);
      });
      
      expect(stressTestTime).toBeLessThan(budget.maxRenderTime * 5); // 5x budget for stress tests
    });
  });

  describe('Performance Regression Detection', () => {
    const BASELINE_METRICS = {
      tabList: { renderTime: 15, memoryUsage: 2 * 1024 * 1024 },
      terminal: { renderTime: 25, memoryUsage: 5 * 1024 * 1024 },
      sidebar: { renderTime: 20, memoryUsage: 3 * 1024 * 1024 },
    };
    
    it('should not regress TabList performance', () => {
      const { tabs } = createLargeDataset(10);
      
      const metrics = measureComponentPerformance(
        TabList,
        {
          tabs,
          activeTab: 'tab-0',
          onTabSelect: jest.fn(),
          onTabClose: jest.fn(),
        }
      );
      
      // Allow 20% performance regression tolerance
      expect(metrics.renderTime).toBeLessThan(BASELINE_METRICS.tabList.renderTime * 1.2);
      expect(metrics.memoryUsage).toBeLessThan(BASELINE_METRICS.tabList.memoryUsage * 1.2);
    });

    it('should not regress Terminal performance', () => {
      const metrics = measureComponentPerformance(
        Terminal,
        { sessionId: 'test-session' }
      );
      
      expect(metrics.renderTime).toBeLessThan(BASELINE_METRICS.terminal.renderTime * 1.2);
      expect(metrics.memoryUsage).toBeLessThan(BASELINE_METRICS.terminal.memoryUsage * 1.2);
    });
  });
});

// Performance test reporting utilities
export const generatePerformanceReport = (metrics: PerformanceMetrics[], componentName: string) => {
  const report = {
    component: componentName,
    averageRenderTime: metrics.reduce((sum, m) => sum + m.renderTime, 0) / metrics.length,
    averageMemoryUsage: metrics.reduce((sum, m) => sum + m.memoryUsage, 0) / metrics.length,
    maxRenderTime: Math.max(...metrics.map(m => m.renderTime)),
    maxMemoryUsage: Math.max(...metrics.map(m => m.memoryUsage)),
    sampleSize: metrics.length,
    timestamp: new Date().toISOString(),
  };
  
  console.log(`Performance Report for ${componentName}:`, report);
  return report;
};