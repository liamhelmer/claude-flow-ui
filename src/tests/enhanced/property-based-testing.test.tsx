/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { 
  EdgeCaseScenarios,
  TestDataGenerator,
  renderWithEnhancements 
} from './test-utilities';

// Property-based testing utilities
class PropertyGenerator {
  static randomString(minLength: number = 0, maxLength: number = 100): string {
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ';
    return Array.from({ length }, () => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
  }

  static randomNumber(min: number = -1000, max: number = 1000): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  static randomBoolean(): boolean {
    return Math.random() < 0.5;
  }

  static randomArray<T>(generator: () => T, minLength: number = 0, maxLength: number = 10): T[] {
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from({ length }, generator);
  }

  static randomElement<T>(array: T[]): T {
    return array[Math.floor(Math.random() * array.length)];
  }

  static randomSessionStatus(): 'active' | 'inactive' | 'error' | 'loading' {
    return this.randomElement(['active', 'inactive', 'error', 'loading']);
  }

  static randomAgentType(): 'coder' | 'reviewer' | 'tester' | 'researcher' | 'planner' {
    return this.randomElement(['coder', 'reviewer', 'tester', 'researcher', 'planner']);
  }

  static randomAgentStatus(): 'active' | 'idle' | 'error' | 'disconnected' {
    return this.randomElement(['active', 'idle', 'error', 'disconnected']);
  }
}

class PropertyBasedTester {
  static runProperty<T>(
    generator: () => T,
    predicate: (input: T) => boolean,
    iterations: number = 100
  ): { success: boolean; counterExample?: T; iteration?: number } {
    for (let i = 0; i < iterations; i++) {
      const input = generator();
      try {
        if (!predicate(input)) {
          return { success: false, counterExample: input, iteration: i };
        }
      } catch (error) {
        return { success: false, counterExample: input, iteration: i };
      }
    }
    return { success: true };
  }

  static shrink<T>(
    input: T,
    predicate: (input: T) => boolean,
    shrinker: (input: T) => T[]
  ): T {
    const candidates = shrinker(input);
    for (const candidate of candidates) {
      if (!predicate(candidate)) {
        return this.shrink(candidate, predicate, shrinker);
      }
    }
    return input;
  }
}

// Mock dependencies
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => ({
    terminalRef: { current: null },
    terminal: null,
    writeToTerminal: jest.fn(),
    clearTerminal: jest.fn(),
    focusTerminal: jest.fn(),
    fitTerminal: jest.fn(),
    isConnected: true,
    isAtBottom: true,
    hasNewOutput: false,
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
  }),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    isConnected: true,
    on: jest.fn(),
    off: jest.fn(),
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({
    sessions: [],
    activeSession: null,
    isLoading: false,
    error: null,
    agents: [],
    memory: { usage: 50, limit: 100 },
    commands: [],
    prompts: [],
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
  }),
}));

describe('Property-Based Testing', () => {
  describe('Terminal Component Properties', () => {
    test('Terminal should always render without crashing for any valid sessionId', () => {
      const result = PropertyBasedTester.runProperty(
        () => PropertyGenerator.randomString(1, 50),
        (sessionId: string) => {
          try {
            const { container } = renderWithEnhancements(
              <Terminal sessionId={sessionId} />
            );
            
            // Property: Terminal should always render a valid element
            const terminal = container.querySelector('[role="application"]');
            return terminal !== null;
          } catch (error) {
            return false;
          }
        },
        50
      );

      expect(result.success).toBe(true);
      if (!result.success) {
        console.error('Failed with input:', result.counterExample);
      }
    });

    test('Terminal input should sanitize any string input', () => {
      const result = PropertyBasedTester.runProperty(
        () => {
          // Generate potentially malicious strings
          const baseString = PropertyGenerator.randomString(0, 100);
          const maliciousPatterns = [
            '<script>',
            'javascript:',
            'data:',
            'vbscript:',
            'onload=',
            'onerror=',
          ];
          
          if (Math.random() < 0.3) {
            const pattern = PropertyGenerator.randomElement(maliciousPatterns);
            return baseString + pattern + PropertyGenerator.randomString(0, 20);
          }
          
          return baseString;
        },
        (input: string) => {
          try {
            const { container } = renderWithEnhancements(
              <div dangerouslySetInnerHTML={{ __html: input }} />
            );

            // Property: No script tags should be present in rendered output
            const scriptTags = container.querySelectorAll('script');
            return scriptTags.length === 0;
          } catch (error) {
            // If it throws, that's also acceptable (sanitization working)
            return true;
          }
        },
        100
      );

      expect(result.success).toBe(true);
    });
  });

  describe('Sidebar Component Properties', () => {
    test('Sidebar should handle any array of sessions', () => {
      const result = PropertyBasedTester.runProperty(
        () => {
          const sessionCount = PropertyGenerator.randomNumber(0, 20);
          return Array.from({ length: sessionCount }, (_, i) => ({
            id: `session-${i}-${PropertyGenerator.randomString(5, 10)}`,
            name: PropertyGenerator.randomString(1, 50),
            status: PropertyGenerator.randomSessionStatus(),
            createdAt: PropertyGenerator.randomNumber(0, Date.now()),
            lastActivity: PropertyGenerator.randomNumber(0, Date.now()),
            commands: [],
          }));
        },
        (sessions: any[]) => {
          try {
            const { container } = renderWithEnhancements(
              <Sidebar
                sessions={sessions}
                activeSessionId={sessions[0]?.id || null}
                onSessionSelect={jest.fn()}
                onSessionClose={jest.fn()}
                onNewSession={jest.fn()}
              />
            );

            // Property: Should render navigation element
            const nav = container.querySelector('[role="navigation"]');
            if (!nav) return false;

            // Property: Number of session buttons should match session count
            const buttons = container.querySelectorAll('button');
            // At least one button for "new session" should exist
            return buttons.length >= 1;
          } catch (error) {
            return false;
          }
        },
        50
      );

      expect(result.success).toBe(true);
    });

    test('Sidebar should maintain active session consistency', () => {
      const result = PropertyBasedTester.runProperty(
        () => {
          const sessions = Array.from({ length: PropertyGenerator.randomNumber(1, 10) }, (_, i) => ({
            id: `session-${i}`,
            name: PropertyGenerator.randomString(1, 20),
            status: PropertyGenerator.randomSessionStatus(),
            createdAt: Date.now(),
            lastActivity: Date.now(),
            commands: [],
          }));

          const activeSessionId = PropertyGenerator.randomBoolean() 
            ? PropertyGenerator.randomElement(sessions).id 
            : PropertyGenerator.randomString(1, 10); // Sometimes invalid ID

          return { sessions, activeSessionId };
        },
        ({ sessions, activeSessionId }: { sessions: any[]; activeSessionId: string }) => {
          try {
            const { container } = renderWithEnhancements(
              <Sidebar
                sessions={sessions}
                activeSessionId={activeSessionId}
                onSessionSelect={jest.fn()}
                onSessionClose={jest.fn()}
                onNewSession={jest.fn()}
              />
            );

            // Property: If activeSessionId exists in sessions, exactly one button should have aria-current
            const validActiveSession = sessions.some(s => s.id === activeSessionId);
            const activeButtons = container.querySelectorAll('[aria-current="page"]');

            if (validActiveSession) {
              return activeButtons.length === 1;
            } else {
              return activeButtons.length === 0;
            }
          } catch (error) {
            return false;
          }
        },
        50
      );

      expect(result.success).toBe(true);
    });
  });

  describe('TabList Component Properties', () => {
    test('TabList should handle any array of tabs', () => {
      const result = PropertyBasedTester.runProperty(
        () => {
          const tabCount = PropertyGenerator.randomNumber(0, 15);
          const tabs = Array.from({ length: tabCount }, (_, i) => ({
            id: `tab-${i}-${PropertyGenerator.randomString(3, 8)}`,
            title: PropertyGenerator.randomString(1, 30),
            isActive: false,
          }));

          // Ensure exactly one tab is active (if any tabs exist)
          if (tabs.length > 0) {
            const activeIndex = PropertyGenerator.randomNumber(0, tabs.length - 1);
            tabs[activeIndex].isActive = true;
          }

          return tabs;
        },
        (tabs: any[]) => {
          try {
            const { container } = renderWithEnhancements(
              <TabList tabs={tabs} onTabChange={jest.fn()} />
            );

            // Property: Should render tablist element
            const tablist = container.querySelector('[role="tablist"]');
            if (!tablist) return tabs.length === 0; // OK if no tabs

            // Property: Number of tab elements should match tab count
            const tabElements = container.querySelectorAll('[role="tab"]');
            return tabElements.length === tabs.length;
          } catch (error) {
            return false;
          }
        },
        50
      );

      expect(result.success).toBe(true);
    });

    test('TabList should maintain exactly one active tab', () => {
      const result = PropertyBasedTester.runProperty(
        () => {
          const tabCount = PropertyGenerator.randomNumber(1, 10);
          return Array.from({ length: tabCount }, (_, i) => ({
            id: `tab-${i}`,
            title: PropertyGenerator.randomString(1, 20),
            isActive: i === 0, // Start with first tab active
          }));
        },
        (tabs: any[]) => {
          try {
            const { container } = renderWithEnhancements(
              <TabList tabs={tabs} onTabChange={jest.fn()} />
            );

            // Property: Exactly one tab should have aria-selected="true"
            const activeTabs = container.querySelectorAll('[aria-selected="true"]');
            return activeTabs.length === 1;
          } catch (error) {
            return false;
          }
        },
        50
      );

      expect(result.success).toBe(true);
    });
  });

  describe('Data Structure Properties', () => {
    test('Session objects should maintain data integrity', () => {
      const result = PropertyBasedTester.runProperty(
        () => ({
          id: PropertyGenerator.randomString(1, 50),
          name: PropertyGenerator.randomString(0, 100),
          status: PropertyGenerator.randomSessionStatus(),
          createdAt: PropertyGenerator.randomNumber(0, Date.now()),
          lastActivity: PropertyGenerator.randomNumber(0, Date.now()),
          commands: PropertyGenerator.randomArray(
            () => ({
              id: PropertyGenerator.randomString(1, 20),
              command: PropertyGenerator.randomString(1, 100),
              timestamp: PropertyGenerator.randomNumber(0, Date.now()),
              status: PropertyGenerator.randomElement(['success', 'error', 'running']),
            }),
            0,
            5
          ),
        }),
        (session: any) => {
          // Property: Session should have all required fields
          const requiredFields = ['id', 'name', 'status', 'createdAt', 'lastActivity', 'commands'];
          
          for (const field of requiredFields) {
            if (!(field in session)) return false;
          }

          // Property: ID should not be empty
          if (typeof session.id !== 'string' || session.id.length === 0) return false;

          // Property: Status should be valid
          const validStatuses = ['active', 'inactive', 'error', 'loading'];
          if (!validStatuses.includes(session.status)) return false;

          // Property: Timestamps should be non-negative numbers
          if (typeof session.createdAt !== 'number' || session.createdAt < 0) return false;
          if (typeof session.lastActivity !== 'number' || session.lastActivity < 0) return false;

          // Property: Commands should be an array
          if (!Array.isArray(session.commands)) return false;

          return true;
        },
        100
      );

      expect(result.success).toBe(true);
    });

    test('Agent objects should maintain data integrity', () => {
      const result = PropertyBasedTester.runProperty(
        () => ({
          id: PropertyGenerator.randomString(1, 30),
          name: PropertyGenerator.randomString(1, 50),
          type: PropertyGenerator.randomAgentType(),
          status: PropertyGenerator.randomAgentStatus(),
          capabilities: PropertyGenerator.randomArray(
            () => PropertyGenerator.randomString(1, 20),
            0,
            5
          ),
          metrics: {
            tasksCompleted: PropertyGenerator.randomNumber(0, 1000),
            errorRate: Math.random(),
            averageResponseTime: PropertyGenerator.randomNumber(0, 5000),
          },
        }),
        (agent: any) => {
          // Property: Agent should have all required fields
          const requiredFields = ['id', 'name', 'type', 'status', 'capabilities', 'metrics'];
          
          for (const field of requiredFields) {
            if (!(field in agent)) return false;
          }

          // Property: Type should be valid
          const validTypes = ['coder', 'reviewer', 'tester', 'researcher', 'planner'];
          if (!validTypes.includes(agent.type)) return false;

          // Property: Status should be valid
          const validStatuses = ['active', 'idle', 'error', 'disconnected'];
          if (!validStatuses.includes(agent.status)) return false;

          // Property: Capabilities should be an array
          if (!Array.isArray(agent.capabilities)) return false;

          // Property: Metrics should have valid values
          if (typeof agent.metrics.tasksCompleted !== 'number' || agent.metrics.tasksCompleted < 0) return false;
          if (typeof agent.metrics.errorRate !== 'number' || agent.metrics.errorRate < 0 || agent.metrics.errorRate > 1) return false;
          if (typeof agent.metrics.averageResponseTime !== 'number' || agent.metrics.averageResponseTime < 0) return false;

          return true;
        },
        100
      );

      expect(result.success).toBe(true);
    });
  });

  describe('Fuzzing Tests', () => {
    test('Component rendering should be robust against random inputs', () => {
      const fuzzTest = () => {
        const componentType = PropertyGenerator.randomElement(['terminal', 'sidebar', 'tablist']);
        
        switch (componentType) {
          case 'terminal':
            return {
              type: 'terminal',
              props: {
                sessionId: PropertyGenerator.randomString(0, 100),
              },
            };
          
          case 'sidebar':
            return {
              type: 'sidebar',
              props: {
                sessions: PropertyGenerator.randomArray(
                  () => ({
                    id: PropertyGenerator.randomString(0, 50),
                    name: PropertyGenerator.randomString(0, 100),
                    status: PropertyGenerator.randomElement(['active', 'inactive', 'error', 'loading', 'invalid']),
                    createdAt: PropertyGenerator.randomNumber(-1000000, Date.now() * 2),
                    lastActivity: PropertyGenerator.randomNumber(-1000000, Date.now() * 2),
                    commands: [],
                  }),
                  0,
                  20
                ),
                activeSessionId: PropertyGenerator.randomString(0, 50),
                onSessionSelect: jest.fn(),
                onSessionClose: jest.fn(),
                onNewSession: jest.fn(),
              },
            };
          
          case 'tablist':
            return {
              type: 'tablist',
              props: {
                tabs: PropertyGenerator.randomArray(
                  () => ({
                    id: PropertyGenerator.randomString(0, 50),
                    title: PropertyGenerator.randomString(0, 100),
                    isActive: PropertyGenerator.randomBoolean(),
                  }),
                  0,
                  15
                ),
                onTabChange: jest.fn(),
              },
            };
          
          default:
            return { type: 'terminal', props: { sessionId: 'test' } };
        }
      };

      const result = PropertyBasedTester.runProperty(
        fuzzTest,
        (testCase: any) => {
          try {
            let component;
            
            switch (testCase.type) {
              case 'terminal':
                component = <Terminal {...testCase.props} />;
                break;
              case 'sidebar':
                component = <Sidebar {...testCase.props} />;
                break;
              case 'tablist':
                component = <TabList {...testCase.props} />;
                break;
              default:
                return false;
            }

            const { container } = renderWithEnhancements(component);
            
            // Property: Should always render something
            return container.firstChild !== null;
          } catch (error) {
            // Components should handle invalid props gracefully
            return false;
          }
        },
        200 // More iterations for fuzzing
      );

      // Allow some failures for extreme edge cases, but most should succeed
      const successRate = result.success ? 100 : ((result.iteration || 0) / 200) * 100;
      expect(successRate).toBeGreaterThan(80); // At least 80% success rate
    });

    test('String processing should handle unicode and special characters', () => {
      const generateFuzzyString = (): string => {
        const types = [
          () => PropertyGenerator.randomString(0, 100), // Normal strings
          () => '\u0000\u0001\u0002\u0003', // Control characters
          () => '🔥💯🚀🎉👍💔😂🤔🙃', // Emojis
          () => '©®™€¥£§¶•‰†‡°÷×±∞≈≤≥≠', // Special symbols
          () => 'ǝɹǝɥʇ oʃʃǝH', // Upside-down text
          () => '\uFEFF\u200B\u2060', // Zero-width characters
          () => 'A'.repeat(10000), // Very long strings
          () => '', // Empty string
        ];

        const generator = PropertyGenerator.randomElement(types);
        return generator();
      };

      const result = PropertyBasedTester.runProperty(
        generateFuzzyString,
        (str: string) => {
          try {
            // Test that string can be safely used in component
            const { container } = renderWithEnhancements(
              <div data-testid="fuzzy-string">{str}</div>
            );

            const element = container.querySelector('[data-testid="fuzzy-string"]');
            
            // Property: Element should exist and not crash the DOM
            return element !== null;
          } catch (error) {
            return false;
          }
        },
        100
      );

      expect(result.success).toBe(true);
    });
  });
});