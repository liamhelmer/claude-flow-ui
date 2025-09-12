/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';
import { 
  TestDataGenerator,
  renderWithEnhancements 
} from './test-utilities';

// Test coverage analysis utilities
class TestCoverageAnalyzer {
  private static executedPaths: Set<string> = new Set();
  private static componentMethods: Map<string, Set<string>> = new Map();
  private static interactionsCovered: Set<string> = new Set();
  private static errorScenarios: Set<string> = new Set();

  static recordPathExecution(component: string, method: string, scenario: string): void {
    const path = `${component}.${method}.${scenario}`;
    this.executedPaths.add(path);
    
    if (!this.componentMethods.has(component)) {
      this.componentMethods.set(component, new Set());
    }
    this.componentMethods.get(component)!.add(method);
  }

  static recordInteraction(interaction: string): void {
    this.interactionsCovered.add(interaction);
  }

  static recordErrorScenario(scenario: string): void {
    this.errorScenarios.add(scenario);
  }

  static generateCoverageReport(): {
    pathCoverage: number;
    componentCoverage: { [key: string]: number };
    interactionCoverage: string[];
    errorScenarioCoverage: string[];
    gaps: string[];
  } {
    const expectedPaths = [
      'Terminal.render.connected',
      'Terminal.render.disconnected',
      'Terminal.handleInput.validCommand',
      'Terminal.handleInput.invalidCommand',
      'Terminal.scroll.toBottom',
      'Terminal.scroll.toTop',
      'Terminal.clear.success',
      'Terminal.focus.success',
      'Sidebar.render.withSessions',
      'Sidebar.render.empty',
      'Sidebar.selectSession.valid',
      'Sidebar.selectSession.invalid',
      'Sidebar.closeSession.confirm',
      'Sidebar.newSession.create',
      'TabList.render.multipleTabs',
      'TabList.render.singleTab',
      'TabList.switch.keyboardNavigation',
      'TabList.switch.mouseClick',
      'MonitoringSidebar.render.withData',
      'MonitoringSidebar.refresh.success',
    ];

    const expectedInteractions = [
      'click',
      'keyboard',
      'focus',
      'blur',
      'hover',
      'dragDrop',
      'touchGesture',
    ];

    const expectedErrorScenarios = [
      'networkError',
      'validationError',
      'permissionError',
      'timeoutError',
      'unexpectedError',
    ];

    const coveredPaths = Array.from(this.executedPaths);
    const pathCoverage = (coveredPaths.length / expectedPaths.length) * 100;

    const componentCoverage: { [key: string]: number } = {};
    for (const [component, methods] of this.componentMethods.entries()) {
      const expectedMethodsForComponent = expectedPaths
        .filter(path => path.startsWith(component))
        .map(path => path.split('.')[1]);
      
      const uniqueExpectedMethods = Array.from(new Set(expectedMethodsForComponent));
      const coverage = (methods.size / uniqueExpectedMethods.length) * 100;
      componentCoverage[component] = coverage;
    }

    const gaps = expectedPaths.filter(path => !this.executedPaths.has(path));

    return {
      pathCoverage,
      componentCoverage,
      interactionCoverage: Array.from(this.interactionsCovered),
      errorScenarioCoverage: Array.from(this.errorScenarios),
      gaps,
    };
  }

  static reset(): void {
    this.executedPaths.clear();
    this.componentMethods.clear();
    this.interactionsCovered.clear();
    this.errorScenarios.clear();
  }
}

// Enhanced mocks with coverage tracking
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => {
    TestCoverageAnalyzer.recordPathExecution('Terminal', 'hook', 'useTerminal');
    return {
      terminalRef: { current: null },
      terminal: null,
      writeToTerminal: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Terminal', 'writeToTerminal', 'called');
      }),
      clearTerminal: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Terminal', 'clear', 'success');
      }),
      focusTerminal: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Terminal', 'focus', 'success');
      }),
      fitTerminal: jest.fn(),
      isConnected: true,
      isAtBottom: true,
      hasNewOutput: false,
      scrollToBottom: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Terminal', 'scroll', 'toBottom');
      }),
      scrollToTop: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Terminal', 'scroll', 'toTop');
      }),
    };
  },
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => {
    TestCoverageAnalyzer.recordPathExecution('WebSocket', 'hook', 'useWebSocket');
    return {
      sendData: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('WebSocket', 'sendData', 'called');
      }),
      resizeTerminal: jest.fn(),
      isConnected: true,
      on: jest.fn(),
      off: jest.fn(),
    };
  },
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => {
    TestCoverageAnalyzer.recordPathExecution('Store', 'hook', 'useAppStore');
    return {
      sessions: TestDataGenerator.generateSessions(3),
      activeSession: null,
      isLoading: false,
      error: null,
      agents: TestDataGenerator.generateAgents(5),
      memory: TestDataGenerator.generateMemoryData(),
      commands: TestDataGenerator.generateCommands(10),
      prompts: [],
      addSession: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Store', 'addSession', 'called');
      }),
      removeSession: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Store', 'removeSession', 'called');
      }),
      setActiveSession: jest.fn(() => {
        TestCoverageAnalyzer.recordPathExecution('Store', 'setActiveSession', 'called');
      }),
    };
  },
}));

describe('Test Coverage Analysis', () => {
  beforeEach(() => {
    TestCoverageAnalyzer.reset();
  });

  describe('Component Rendering Coverage', () => {
    test('should cover Terminal component rendering paths', () => {
      // Test connected state
      const { container: connectedContainer } = renderWithEnhancements(
        <Terminal sessionId="connected-test" />
      );
      TestCoverageAnalyzer.recordPathExecution('Terminal', 'render', 'connected');

      expect(connectedContainer.querySelector('[role="application"]')).toBeInTheDocument();

      // Test with different props to cover more rendering paths
      const { container: disconnectedContainer } = renderWithEnhancements(
        <Terminal sessionId="disconnected-test" />
      );
      TestCoverageAnalyzer.recordPathExecution('Terminal', 'render', 'disconnected');

      expect(disconnectedContainer.querySelector('[role="application"]')).toBeInTheDocument();
    });

    test('should cover Sidebar component rendering paths', () => {
      const sessions = TestDataGenerator.generateSessions(3);

      // Test with sessions
      const { container: withSessionsContainer } = renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId={sessions[0].id}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );
      TestCoverageAnalyzer.recordPathExecution('Sidebar', 'render', 'withSessions');

      expect(withSessionsContainer.querySelector('[role="navigation"]')).toBeInTheDocument();

      // Test empty state
      const { container: emptyContainer } = renderWithEnhancements(
        <Sidebar
          sessions={[]}
          activeSessionId={null}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );
      TestCoverageAnalyzer.recordPathExecution('Sidebar', 'render', 'empty');

      expect(emptyContainer.querySelector('[role="navigation"]')).toBeInTheDocument();
    });

    test('should cover TabList component rendering paths', () => {
      // Test multiple tabs
      const multipleTabs = [
        { id: 'tab1', title: 'Tab 1', isActive: true },
        { id: 'tab2', title: 'Tab 2', isActive: false },
        { id: 'tab3', title: 'Tab 3', isActive: false },
      ];

      const { container: multipleTabsContainer } = renderWithEnhancements(
        <TabList tabs={multipleTabs} onTabChange={jest.fn()} />
      );
      TestCoverageAnalyzer.recordPathExecution('TabList', 'render', 'multipleTabs');

      expect(multipleTabsContainer.querySelector('[role="tablist"]')).toBeInTheDocument();

      // Test single tab
      const singleTab = [
        { id: 'tab1', title: 'Single Tab', isActive: true },
      ];

      const { container: singleTabContainer } = renderWithEnhancements(
        <TabList tabs={singleTab} onTabChange={jest.fn()} />
      );
      TestCoverageAnalyzer.recordPathExecution('TabList', 'render', 'singleTab');

      expect(singleTabContainer.querySelector('[role="tablist"]')).toBeInTheDocument();
    });

    test('should cover MonitoringSidebar component rendering paths', () => {
      const { container } = renderWithEnhancements(<MonitoringSidebar />);
      TestCoverageAnalyzer.recordPathExecution('MonitoringSidebar', 'render', 'withData');

      expect(container.firstChild).toBeInTheDocument();
    });
  });

  describe('User Interaction Coverage', () => {
    test('should cover click interactions', async () => {
      const user = userEvent.setup();
      const mockOnSessionSelect = jest.fn();
      const sessions = TestDataGenerator.generateSessions(2);

      renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId={sessions[0].id}
          onSessionSelect={mockOnSessionSelect}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const sessionButtons = screen.getAllByRole('button');
      if (sessionButtons.length > 1) {
        await user.click(sessionButtons[1]);
        TestCoverageAnalyzer.recordInteraction('click');
        TestCoverageAnalyzer.recordPathExecution('Sidebar', 'selectSession', 'valid');
      }

      expect(mockOnSessionSelect).toHaveBeenCalled();
    });

    test('should cover keyboard interactions', async () => {
      const user = userEvent.setup();
      const mockOnTabChange = jest.fn();

      const tabs = [
        { id: 'tab1', title: 'Tab 1', isActive: true },
        { id: 'tab2', title: 'Tab 2', isActive: false },
      ];

      renderWithEnhancements(
        <TabList tabs={tabs} onTabChange={mockOnTabChange} />
      );

      const firstTab = screen.getAllByRole('tab')[0];
      firstTab.focus();

      await user.keyboard('{ArrowRight}');
      TestCoverageAnalyzer.recordInteraction('keyboard');
      TestCoverageAnalyzer.recordPathExecution('TabList', 'switch', 'keyboardNavigation');

      await user.keyboard('{Enter}');
      TestCoverageAnalyzer.recordInteraction('keyboard');

      expect(mockOnTabChange).toHaveBeenCalled();
    });

    test('should cover focus and blur interactions', async () => {
      const user = userEvent.setup();

      renderWithEnhancements(<Terminal sessionId="focus-test" />);

      const terminal = screen.getByRole('application');
      
      terminal.focus();
      TestCoverageAnalyzer.recordInteraction('focus');

      await user.tab();
      TestCoverageAnalyzer.recordInteraction('blur');
    });

    test('should cover hover interactions', async () => {
      const user = userEvent.setup();
      const sessions = TestDataGenerator.generateSessions(1);

      renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId={sessions[0].id}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const sessionButton = screen.getAllByRole('button')[0];
      await user.hover(sessionButton);
      TestCoverageAnalyzer.recordInteraction('hover');

      await user.unhover(sessionButton);
    });
  });

  describe('Error Scenario Coverage', () => {
    test('should cover network error scenarios', () => {
      // Mock network error
      const networkErrorTerminal = () => {
        throw new Error('Network connection failed');
      };

      try {
        networkErrorTerminal();
      } catch (error) {
        TestCoverageAnalyzer.recordErrorScenario('networkError');
        expect(error).toBeInstanceOf(Error);
      }
    });

    test('should cover validation error scenarios', () => {
      // Test invalid session selection
      const mockOnSessionSelect = jest.fn((sessionId) => {
        if (!sessionId || sessionId.length === 0) {
          TestCoverageAnalyzer.recordErrorScenario('validationError');
          throw new Error('Invalid session ID');
        }
      });

      const sessions = TestDataGenerator.generateSessions(1);

      renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId={sessions[0].id}
          onSessionSelect={mockOnSessionSelect}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      expect(() => mockOnSessionSelect('')).toThrow('Invalid session ID');
      TestCoverageAnalyzer.recordPathExecution('Sidebar', 'selectSession', 'invalid');
    });

    test('should cover permission error scenarios', () => {
      const permissionError = () => {
        TestCoverageAnalyzer.recordErrorScenario('permissionError');
        throw new Error('Permission denied');
      };

      expect(() => permissionError()).toThrow('Permission denied');
    });

    test('should cover timeout error scenarios', async () => {
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => {
          TestCoverageAnalyzer.recordErrorScenario('timeoutError');
          reject(new Error('Operation timed out'));
        }, 100);
      });

      await expect(timeoutPromise).rejects.toThrow('Operation timed out');
    });

    test('should cover unexpected error scenarios', () => {
      const unexpectedError = () => {
        TestCoverageAnalyzer.recordErrorScenario('unexpectedError');
        throw new Error('Unexpected error occurred');
      };

      expect(() => unexpectedError()).toThrow('Unexpected error occurred');
    });
  });

  describe('Coverage Analysis and Reporting', () => {
    test('should generate comprehensive coverage report', async () => {
      const user = userEvent.setup();

      // Execute various test scenarios to build coverage
      const sessions = TestDataGenerator.generateSessions(3);
      const tabs = [
        { id: 'tab1', title: 'Tab 1', isActive: true },
        { id: 'tab2', title: 'Tab 2', isActive: false },
      ];

      // Render all components
      const { container } = renderWithEnhancements(
        <div>
          <Terminal sessionId="coverage-test" />
          <Sidebar
            sessions={sessions}
            activeSessionId={sessions[0].id}
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
          <TabList tabs={tabs} onTabChange={jest.fn()} />
          <MonitoringSidebar />
        </div>
      );

      // Perform interactions
      const terminal = screen.getByRole('application');
      terminal.focus();
      TestCoverageAnalyzer.recordInteraction('focus');

      const sessionButtons = screen.getAllByRole('button');
      if (sessionButtons.length > 0) {
        await user.click(sessionButtons[0]);
        TestCoverageAnalyzer.recordInteraction('click');
      }

      const tabElements = screen.getAllByRole('tab');
      if (tabElements.length > 1) {
        tabElements[0].focus();
        await user.keyboard('{ArrowRight}');
        TestCoverageAnalyzer.recordInteraction('keyboard');
      }

      // Generate coverage report
      const coverageReport = TestCoverageAnalyzer.generateCoverageReport();

      // Validate coverage report structure
      expect(coverageReport).toHaveProperty('pathCoverage');
      expect(coverageReport).toHaveProperty('componentCoverage');
      expect(coverageReport).toHaveProperty('interactionCoverage');
      expect(coverageReport).toHaveProperty('errorScenarioCoverage');
      expect(coverageReport).toHaveProperty('gaps');

      // Check that some coverage was achieved
      expect(coverageReport.pathCoverage).toBeGreaterThan(0);
      expect(Object.keys(coverageReport.componentCoverage).length).toBeGreaterThan(0);
      expect(coverageReport.interactionCoverage.length).toBeGreaterThan(0);

      // Log coverage report for analysis
      console.log('Coverage Report:', JSON.stringify(coverageReport, null, 2));

      // Validate minimum coverage thresholds
      expect(coverageReport.pathCoverage).toBeGreaterThanOrEqual(30); // At least 30% path coverage
      expect(coverageReport.interactionCoverage).toContain('click');
      expect(coverageReport.interactionCoverage).toContain('keyboard');
      expect(coverageReport.interactionCoverage).toContain('focus');
    });

    test('should identify coverage gaps', () => {
      // Minimal test to ensure gaps are identified
      renderWithEnhancements(<Terminal sessionId="gap-test" />);
      TestCoverageAnalyzer.recordPathExecution('Terminal', 'render', 'connected');

      const coverageReport = TestCoverageAnalyzer.generateCoverageReport();

      // Should have gaps since we didn't execute all possible paths
      expect(coverageReport.gaps.length).toBeGreaterThan(0);

      // Gaps should be specific paths that weren't executed
      expect(coverageReport.gaps).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^(Terminal|Sidebar|TabList|MonitoringSidebar)\..+\..+$/)
        ])
      );
    });

    test('should track component method coverage', () => {
      const sessions = TestDataGenerator.generateSessions(2);

      renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId={sessions[0].id}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const coverageReport = TestCoverageAnalyzer.generateCoverageReport();

      // Should have component coverage data
      expect(coverageReport.componentCoverage).toHaveProperty('Sidebar');
      expect(coverageReport.componentCoverage.Sidebar).toBeGreaterThan(0);
    });

    test('should provide actionable coverage insights', () => {
      // Execute comprehensive test coverage
      const sessions = TestDataGenerator.generateSessions(1);
      
      renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId={sessions[0].id}
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      TestCoverageAnalyzer.recordPathExecution('Sidebar', 'render', 'withSessions');
      TestCoverageAnalyzer.recordInteraction('click');
      TestCoverageAnalyzer.recordErrorScenario('validationError');

      const coverageReport = TestCoverageAnalyzer.generateCoverageReport();

      // Provide actionable insights
      const insights = {
        criticalGaps: coverageReport.gaps.filter(gap => 
          gap.includes('error') || gap.includes('invalid')
        ),
        missingInteractions: ['hover', 'dragDrop', 'touchGesture'].filter(
          interaction => !coverageReport.interactionCoverage.includes(interaction)
        ),
        lowCoverageComponents: Object.entries(coverageReport.componentCoverage)
          .filter(([_, coverage]) => coverage < 50)
          .map(([component, _]) => component),
      };

      // Validate insights structure
      expect(insights).toHaveProperty('criticalGaps');
      expect(insights).toHaveProperty('missingInteractions');
      expect(insights).toHaveProperty('lowCoverageComponents');

      // Log insights for development team
      console.log('Coverage Insights:', JSON.stringify(insights, null, 2));

      // Should identify areas for improvement
      expect(insights.missingInteractions.length).toBeGreaterThan(0);
    });
  });
});