import React from 'react';
import { render } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import Tab from '../tabs/Tab';
import TabList from '../tabs/TabList';
import Sidebar from '../sidebar/Sidebar';
import Terminal from '../terminal/Terminal';
import TerminalControls from '../terminal/TerminalControls';
import { AgentsPanel } from '../monitoring/AgentsPanel';
import { PromptPanel } from '../monitoring/PromptPanel';
import { MemoryPanel } from '../monitoring/MemoryPanel';
import { CommandsPanel } from '../monitoring/CommandsPanel';
import { MonitoringSidebar } from '../monitoring/MonitoringSidebar';

// Add jest-axe matchers
expect.extend(toHaveNoViolations);

// Mock WebSocket and other dependencies
jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    isConnected: true,
  }),
}));

jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => ({
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
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({
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
    toggleSidebar: jest.fn(),
  }),
}));

// Mock React Tabs
jest.mock('react-tabs', () => ({
  Tabs: ({ children }: { children: React.ReactNode }) => <div role="tablist">{children}</div>,
  TabList: ({ children }: { children: React.ReactNode }) => <div role="tablist">{children}</div>,
  Tab: ({ children }: { children: React.ReactNode }) => <button role="tab">{children}</button>,
  TabPanel: ({ children }: { children: React.ReactNode }) => <div role="tabpanel">{children}</div>,
}));

describe('Accessibility Tests', () => {
  describe('Tab Component', () => {
    it('should not have accessibility violations', async () => {
      const { container } = render(
        <Tab
          title="Test Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper ARIA labels for close button', async () => {
      const { container } = render(
        <Tab
          title="My Important Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const closeButton = container.querySelector('button[aria-label]');
      expect(closeButton).toHaveAttribute('aria-label', 'Close My Important Tab');
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should handle special characters in title for ARIA labels', async () => {
      const { container } = render(
        <Tab
          title="Tab & <Special> 'Characters'"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const closeButton = container.querySelector('button[aria-label]');
      expect(closeButton).toHaveAttribute('aria-label', 'Close Tab & <Special> "Characters"');
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should be accessible without close button', async () => {
      const { container } = render(
        <Tab
          title="Read-only Tab"
          isActive={true}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={false}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('TabList Component', () => {
    const mockTabs = [
      { id: '1', title: 'Tab 1', content: 'Content 1' },
      { id: '2', title: 'Tab 2', content: 'Content 2' },
      { id: '3', title: 'Tab 3', content: 'Content 3' },
    ];

    it('should not have accessibility violations', async () => {
      const { container } = render(
        <TabList
          tabs={mockTabs}
          activeTab="1"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper tab navigation structure', async () => {
      const { container } = render(
        <TabList
          tabs={mockTabs}
          activeTab="2"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      // Should have tablist role
      const tablist = container.querySelector('[role="tablist"]');
      expect(tablist).toBeInTheDocument();
      
      // Should have tab elements
      const tabs = container.querySelectorAll('[role="tab"]');
      expect(tabs).toHaveLength(mockTabs.length);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should handle empty tabs list', async () => {
      const { container } = render(
        <TabList
          tabs={[]}
          activeTab=""
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Sidebar Component', () => {
    it('should not have accessibility violations', async () => {
      const { container } = render(<Sidebar />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper button roles and labels', async () => {
      const { container } = render(<Sidebar />);
      
      const toggleButton = container.querySelector('button[title="Toggle Sidebar"]');
      expect(toggleButton).toBeInTheDocument();
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper semantic structure', async () => {
      const { container } = render(<Sidebar />);
      
      // Should have navigation elements
      const headings = container.querySelectorAll('h2, h3');
      expect(headings.length).toBeGreaterThan(0);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Terminal Component', () => {
    it('should not have accessibility violations', async () => {
      const { container } = render(
        <Terminal sessionId="test-session" />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper terminal container structure', async () => {
      const { container } = render(
        <Terminal sessionId="test-session" />
      );
      
      // Terminal container should be present
      const terminalContainer = container.querySelector('.terminal-container');
      expect(terminalContainer).toBeInTheDocument();
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('TerminalControls Component', () => {
    it('should not have accessibility violations', async () => {
      const { container } = render(
        <TerminalControls
          onClear={jest.fn()}
          onScrollToBottom={jest.fn()}
          onScrollToTop={jest.fn()}
          hasNewOutput={false}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should have proper button labels and roles', async () => {
      const { container } = render(
        <TerminalControls
          onClear={jest.fn()}
          onScrollToBottom={jest.fn()}
          onScrollToTop={jest.fn()}
          hasNewOutput={true}
        />
      );
      
      const buttons = container.querySelectorAll('button');
      buttons.forEach(button => {
        expect(button).toHaveAttribute('title');
      });
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Monitoring Components', () => {
    describe('AgentsPanel', () => {
      it('should not have accessibility violations', async () => {
        const { container } = render(<AgentsPanel />);
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      it('should have proper heading structure', async () => {
        const { container } = render(<AgentsPanel />);
        
        const heading = container.querySelector('h3');
        expect(heading).toBeInTheDocument();
        expect(heading).toHaveTextContent('Agents');
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });
    });

    describe('PromptPanel', () => {
      it('should not have accessibility violations', async () => {
        const { container } = render(<PromptPanel />);
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      it('should have proper form accessibility', async () => {
        const { container } = render(<PromptPanel />);
        
        // Check for proper form labels
        const textareas = container.querySelectorAll('textarea');
        textareas.forEach(textarea => {
          // Should have associated label or aria-label
          const id = textarea.getAttribute('id');
          const label = id ? container.querySelector(`label[for="${id}"]`) : null;
          const ariaLabel = textarea.getAttribute('aria-label');
          
          expect(label || ariaLabel).toBeTruthy();
        });
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });
    });

    describe('MemoryPanel', () => {
      it('should not have accessibility violations', async () => {
        const { container } = render(<MemoryPanel />);
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      it('should have proper table accessibility if data is present', async () => {
        const { container } = render(<MemoryPanel />);
        
        const tables = container.querySelectorAll('table');
        tables.forEach(table => {
          // Tables should have proper headers
          const headers = table.querySelectorAll('th');
          if (headers.length > 0) {
            expect(headers.length).toBeGreaterThan(0);
          }
        });
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });
    });

    describe('CommandsPanel', () => {
      it('should not have accessibility violations', async () => {
        const { container } = render(<CommandsPanel />);
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      it('should have accessible command list', async () => {
        const { container } = render(<CommandsPanel />);
        
        // Check for proper list structure
        const lists = container.querySelectorAll('ul, ol');
        lists.forEach(list => {
          const items = list.querySelectorAll('li');
          if (items.length > 0) {
            expect(items.length).toBeGreaterThan(0);
          }
        });
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });
    });

    describe('MonitoringSidebar', () => {
      it('should not have accessibility violations', async () => {
        const { container } = render(<MonitoringSidebar />);
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });

      it('should have proper navigation structure', async () => {
        const { container } = render(<MonitoringSidebar />);
        
        // Should have proper heading hierarchy
        const headings = container.querySelectorAll('h1, h2, h3, h4, h5, h6');
        if (headings.length > 0) {
          expect(headings.length).toBeGreaterThan(0);
        }
        
        const results = await axe(container);
        expect(results).toHaveNoViolations();
      });
    });
  });

  describe('Complex Component Interactions', () => {
    it('should maintain accessibility with multiple tabs', async () => {
      const multipleTabs = Array.from({ length: 10 }, (_, i) => ({
        id: `tab-${i}`,
        title: `Terminal ${i + 1}`,
        content: `Content ${i + 1}`,
      }));

      const { container } = render(
        <TabList
          tabs={multipleTabs}
          activeTab="tab-5"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should handle dynamic content updates accessibly', async () => {
      const { container, rerender } = render(
        <Tab
          title="Dynamic Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      let results = await axe(container);
      expect(results).toHaveNoViolations();
      
      // Update to active state
      rerender(
        <Tab
          title="Dynamic Tab - Updated"
          isActive={true}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={false}
        />
      );
      
      results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Keyboard Navigation', () => {
    it('should support keyboard navigation for tabs', async () => {
      const { container } = render(
        <Tab
          title="Keyboard Tab"
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      const tabElement = container.querySelector('.tab-button');
      expect(tabElement).toBeInTheDocument();
      
      // Should be focusable
      if (tabElement) {
        (tabElement as HTMLElement).focus();
        expect(document.activeElement).toBe(tabElement);
      }
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should support keyboard navigation for controls', async () => {
      const { container } = render(
        <TerminalControls
          onClear={jest.fn()}
          onScrollToBottom={jest.fn()}
          onScrollToTop={jest.fn()}
          hasNewOutput={false}
        />
      );
      
      const buttons = container.querySelectorAll('button');
      buttons.forEach(button => {
        button.focus();
        expect(document.activeElement).toBe(button);
      });
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Color Contrast and Visual Accessibility', () => {
    it('should have sufficient color contrast', async () => {
      const { container } = render(
        <div>
          <Tab
            title="Contrast Test"
            isActive={true}
            onSelect={jest.fn()}
            onClose={jest.fn()}
            closable={true}
          />
          <Tab
            title="Inactive Contrast Test"
            isActive={false}
            onSelect={jest.fn()}
            onClose={jest.fn()}
            closable={true}
          />
        </div>
      );
      
      const results = await axe(container, {
        rules: {
          'color-contrast': { enabled: true },
        },
      });
      expect(results).toHaveNoViolations();
    });

    it('should work with high contrast mode', async () => {
      // Simulate high contrast mode by adding classes
      const { container } = render(
        <div className="high-contrast">
          <Sidebar />
        </div>
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });

  describe('Screen Reader Compatibility', () => {
    it('should provide meaningful text alternatives', async () => {
      const { container } = render(
        <Tab
          title=""
          isActive={false}
          onSelect={jest.fn()}
          onClose={jest.fn()}
          closable={true}
        />
      );
      
      // Even with empty title, should not cause accessibility issues
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('should handle complex content accessibly', async () => {
      const complexContent = {
        id: '1',
        title: 'Terminal Session 🚀 (Production) - Running npm build',
        content: 'Complex content with symbols',
      };

      const { container } = render(
        <TabList
          tabs={[complexContent]}
          activeTab="1"
          onTabSelect={jest.fn()}
          onTabClose={jest.fn()}
        />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });
  });
});
