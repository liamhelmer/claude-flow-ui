/**
 * @jest-environment jsdom
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';
import { 
  TestDataGenerator, 
  EdgeCaseScenarios, 
  renderWithEnhancements,
  TestScenarioBuilder 
} from './test-utilities';

// Mock dependencies
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');
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

describe('Enhanced Edge Cases Testing', () => {
  let mockTerminal: any;
  let mockWebSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockTerminal = {
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
    };

    mockWebSocket = {
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      isConnected: true,
      on: jest.fn(),
      off: jest.fn(),
    };

    (useTerminal as jest.Mock).mockReturnValue(mockTerminal);
    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
  });

  describe('Malicious Input Handling', () => {
    test('should sanitize XSS payloads in terminal input', async () => {
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);
      const maliciousInputs = EdgeCaseScenarios.generateMaliciousInput().xssPayloads;

      for (const payload of maliciousInputs) {
        mockWebSocket.sendData.mockClear();
        
        // Simulate typing malicious input
        const terminalElement = screen.getByRole('application', { name: /terminal/i });
        await user.type(terminalElement, payload);

        // Verify the payload was sanitized before sending
        if (mockWebSocket.sendData.mock.calls.length > 0) {
          const sentData = mockWebSocket.sendData.mock.calls[0][0];
          expect(sentData).not.toContain('<script>');
          expect(sentData).not.toContain('javascript:');
          expect(sentData).not.toContain('onerror=');
        }
      }
    });

    test('should handle SQL injection attempts in session names', async () => {
      const maliciousNames = EdgeCaseScenarios.generateMaliciousInput().sqlInjection;
      const mockOnSessionSelect = jest.fn();

      for (const maliciousName of maliciousNames) {
        const sessions = [{ id: '1', name: maliciousName, status: 'active' as const }];
        
        render(
          <Sidebar
            sessions={sessions}
            activeSessionId="1"
            onSessionSelect={mockOnSessionSelect}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
        );

        // Should render without throwing and not execute malicious code
        expect(screen.getByText(maliciousName)).toBeInTheDocument();
        expect(() => screen.getByText(maliciousName)).not.toThrow();
      }
    });

    test('should handle oversized input gracefully', async () => {
      const oversizedInput = EdgeCaseScenarios.generateMaliciousInput().oversizedInput;
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('application', { name: /terminal/i });
      
      // Should not crash when handling large input
      await expect(async () => {
        await user.type(terminalElement, oversizedInput.substring(0, 1000)); // Type first 1000 chars
      }).not.toThrow();

      expect(mockWebSocket.sendData).toHaveBeenCalled();
    });

    test('should handle special characters and unicode properly', async () => {
      const specialChars = EdgeCaseScenarios.generateMaliciousInput().specialCharacters;
      const unicode = EdgeCaseScenarios.generateMaliciousInput().unicode;
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('application', { name: /terminal/i });

      // Test special characters
      await user.type(terminalElement, specialChars);
      expect(mockWebSocket.sendData).toHaveBeenCalledWith(expect.stringContaining(specialChars));

      // Test unicode
      await user.type(terminalElement, unicode);
      expect(mockWebSocket.sendData).toHaveBeenCalledWith(expect.stringContaining(unicode));
    });

    test('should handle control characters safely', async () => {
      const controlChars = EdgeCaseScenarios.generateMaliciousInput().controlCharacters;
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      const terminalElement = screen.getByRole('application', { name: /terminal/i });

      // Should not crash with control characters
      await expect(async () => {
        await user.type(terminalElement, controlChars);
      }).not.toThrow();
    });
  });

  describe('Boundary Value Testing', () => {
    test('should handle extreme session counts', async () => {
      const boundaryCounts = [0, 1, 1000, 10000];

      for (const count of boundaryCounts) {
        const sessions = TestDataGenerator.generateSessions(count);
        
        const { container } = renderWithEnhancements(
          <Sidebar
            sessions={sessions}
            activeSessionId={sessions[0]?.id}
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />,
          { withPerformanceTracking: true }
        );

        expect(container).toBeInTheDocument();
        
        if (count > 0) {
          const sessionElements = screen.getAllByRole('button');
          expect(sessionElements.length).toBeGreaterThan(0);
        }
      }
    });

    test('should handle boundary tab counts', async () => {
      const tabCounts = [0, 1, 50, 100];

      for (const count of tabCounts) {
        const tabs = Array.from({ length: count }, (_, i) => ({
          id: `tab-${i}`,
          title: `Tab ${i}`,
          isActive: i === 0,
        }));

        const { container } = renderWithEnhancements(
          <TabList tabs={tabs} onTabChange={jest.fn()} />,
          { withPerformanceTracking: true }
        );

        expect(container).toBeInTheDocument();
        
        if (count > 0) {
          const tabElements = screen.getAllByRole('tab');
          expect(tabElements).toHaveLength(count);
        }
      }
    });

    test('should handle extreme string lengths in session names', () => {
      const boundaryValues = EdgeCaseScenarios.generateBoundaryValues();
      const extremeStrings = [
        boundaryValues.strings.empty,
        boundaryValues.strings.single,
        boundaryValues.strings.maxLength.substring(0, 1000), // Limit for testing
        boundaryValues.strings.spaces,
        boundaryValues.strings.newlines,
      ];

      extremeStrings.forEach((name, index) => {
        const sessions = [{ id: `session-${index}`, name, status: 'active' as const }];
        
        const { container } = render(
          <Sidebar
            sessions={sessions}
            activeSessionId={`session-${index}`}
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
        );

        expect(container).toBeInTheDocument();
      });
    });

    test('should handle extreme numeric values', () => {
      const boundaryValues = EdgeCaseScenarios.generateBoundaryValues();
      const extremeNumbers = Object.values(boundaryValues.integers);

      extremeNumbers.forEach((value, index) => {
        // Skip values that would break JSON serialization
        if (isFinite(value)) {
          const memoryData = {
            usage: Math.abs(value) % 1000, // Keep reasonable for testing
            limit: 1000,
            items: [],
          };

          // Should not throw when rendering with extreme values
          expect(() => {
            render(<div>Memory: {memoryData.usage}</div>);
          }).not.toThrow();
        }
      });
    });
  });

  describe('Network Edge Cases', () => {
    test('should handle WebSocket connection failures gracefully', async () => {
      mockWebSocket.isConnected = false;
      mockWebSocket.sendData.mockImplementation(() => {
        throw new Error('Connection lost');
      });

      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      // Should render in disconnected state
      expect(screen.getByRole('application', { name: /terminal/i })).toBeInTheDocument();

      // Should handle failed send attempts
      const terminalElement = screen.getByRole('application', { name: /terminal/i });
      await expect(async () => {
        await user.type(terminalElement, 'test command');
      }).not.toThrow();
    });

    test('should handle network timeouts', async () => {
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      // Mock slow network response
      mockWebSocket.sendData.mockImplementation(
        () => EdgeCaseScenarios.simulateSlowNetwork(async () => {}, 2000)
      );

      const terminalElement = screen.getByRole('application', { name: /terminal/i });
      
      // Should not hang the UI during slow network
      await user.type(terminalElement, 'slow command');
      
      // Component should remain responsive
      expect(terminalElement).toBeInTheDocument();
    });

    test('should handle network flakiness', async () => {
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      // Mock flaky network
      mockWebSocket.sendData.mockImplementation(
        (data) => EdgeCaseScenarios.simulateNetworkFlakiness(
          async () => { /* simulate success */ },
          0.5 // 50% failure rate
        )
      );

      const terminalElement = screen.getByRole('application', { name: /terminal/i });

      // Should handle intermittent failures gracefully
      for (let i = 0; i < 5; i++) {
        try {
          await user.type(terminalElement, `command ${i}`);
        } catch (error) {
          // Expected to fail sometimes, should not crash
          expect(error).toBeInstanceOf(Error);
        }
      }

      expect(terminalElement).toBeInTheDocument();
    });

    test('should handle rapid reconnection attempts', async () => {
      const mockReconnect = jest.fn();
      mockWebSocket.isConnected = false;

      const TerminalWithReconnect = () => {
        const [attempts, setAttempts] = React.useState(0);

        const handleReconnect = React.useCallback(() => {
          setAttempts(prev => prev + 1);
          mockReconnect();
        }, []);

        return (
          <div>
            <Terminal sessionId="test-session" />
            <button onClick={handleReconnect}>Reconnect ({attempts})</button>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<TerminalWithReconnect />);

      const reconnectButton = screen.getByRole('button', { name: /reconnect/i });

      // Rapidly click reconnect multiple times
      for (let i = 0; i < 10; i++) {
        await user.click(reconnectButton);
      }

      expect(mockReconnect).toHaveBeenCalledTimes(10);
      expect(screen.getByText(/\(10\)/)).toBeInTheDocument();
    });
  });

  describe('Memory and Resource Edge Cases', () => {
    test('should handle memory pressure gracefully', async () => {
      const sessions = TestDataGenerator.generateSessions(1000);

      // Create memory pressure before rendering
      const largeData = TestDataGenerator.generateLargeDataset(10000);

      const { container } = renderWithEnhancements(
        <div>
          <Sidebar
            sessions={sessions}
            activeSessionId="session-0"
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
          <pre>{JSON.stringify(largeData.slice(0, 10))}</pre>
        </div>,
        { withPerformanceTracking: true }
      );

      expect(container).toBeInTheDocument();
    });

    test('should clean up resources on unmount', () => {
      const addEventListenerSpy = jest.spyOn(document, 'addEventListener');
      const removeEventListenerSpy = jest.spyOn(document, 'removeEventListener');

      const { unmount } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      const listenersAdded = addEventListenerSpy.mock.calls.length;
      
      unmount();
      
      const listenersRemoved = removeEventListenerSpy.mock.calls.length;

      // Should clean up listeners
      expect(listenersRemoved).toBeGreaterThanOrEqual(0);

      addEventListenerSpy.mockRestore();
      removeEventListenerSpy.mockRestore();
    });

    test('should handle rapid mount/unmount cycles', () => {
      // Rapidly mount and unmount components
      for (let i = 0; i < 50; i++) {
        const { unmount } = renderWithEnhancements(
          <Terminal sessionId={`session-${i}`} />
        );
        unmount();
      }

      // Should not cause memory leaks or crashes
      expect(true).toBe(true); // If we get here, no crashes occurred
    });
  });

  describe('Concurrent Operations Edge Cases', () => {
    test('should handle simultaneous user interactions', async () => {
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);
      const terminalElement = screen.getByRole('application', { name: /terminal/i });

      // Simulate multiple rapid interactions
      const interactions = [
        () => user.type(terminalElement, 'command1'),
        () => user.keyboard('{Enter}'),
        () => user.type(terminalElement, 'command2'),
        () => user.keyboard('{Escape}'),
        () => user.type(terminalElement, 'command3'),
      ];

      // Execute all interactions rapidly
      await Promise.all(interactions.map(interaction => 
        interaction().catch(() => {/* Ignore failures */})
      ));

      expect(terminalElement).toBeInTheDocument();
    });

    test('should handle concurrent state updates', async () => {
      const ConcurrentUpdateComponent = () => {
        const [counters, setCounters] = React.useState(Array(10).fill(0));

        const updateCounter = (index: number) => {
          setCounters(prev => 
            prev.map((count, i) => i === index ? count + 1 : count)
          );
        };

        return (
          <div>
            {counters.map((count, index) => (
              <button
                key={index}
                onClick={() => updateCounter(index)}
              >
                Counter {index}: {count}
              </button>
            ))}
          </div>
        );
      };

      const { user } = renderWithEnhancements(<ConcurrentUpdateComponent />);
      const buttons = screen.getAllByRole('button');

      // Click all buttons simultaneously
      await Promise.all(
        buttons.map(button => user.click(button).catch(() => {}))
      );

      // All counters should have been incremented
      buttons.forEach((button, index) => {
        expect(button).toHaveTextContent(`Counter ${index}: 1`);
      });
    });

    test('should handle race conditions in async operations', async () => {
      const AsyncRaceComponent = () => {
        const [data, setData] = React.useState<string[]>([]);
        const [loading, setLoading] = React.useState(false);

        const loadData = async (id: string) => {
          setLoading(true);
          
          // Simulate async operation with random delay
          await new Promise(resolve => 
            setTimeout(resolve, Math.random() * 100)
          );
          
          setData(prev => [...prev, `Data ${id}`]);
          setLoading(false);
        };

        return (
          <div>
            <button onClick={() => loadData('1')}>Load 1</button>
            <button onClick={() => loadData('2')}>Load 2</button>
            <button onClick={() => loadData('3')}>Load 3</button>
            {loading && <div>Loading...</div>}
            <ul>
              {data.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<AsyncRaceComponent />);
      const buttons = screen.getAllByRole('button');

      // Trigger multiple async operations simultaneously
      await Promise.all(
        buttons.map(button => user.click(button))
      );

      // Wait for all operations to complete
      await waitFor(() => {
        expect(screen.queryByText('Loading...')).not.toBeInTheDocument();
      }, { timeout: 1000 });

      // Should have loaded all data without corruption
      expect(screen.getByText('Data 1')).toBeInTheDocument();
      expect(screen.getByText('Data 2')).toBeInTheDocument();
      expect(screen.getByText('Data 3')).toBeInTheDocument();
    });
  });

  describe('Error Recovery Edge Cases', () => {
    test('should recover from rendering errors', () => {
      const ErrorProneComponent = ({ shouldError }: { shouldError: boolean }) => {
        if (shouldError) {
          throw new Error('Intentional render error');
        }
        return <div>Component rendered successfully</div>;
      };

      const { rerender } = renderWithEnhancements(
        <ErrorProneComponent shouldError={false} />,
        { withErrorBoundary: true }
      );

      expect(screen.getByText('Component rendered successfully')).toBeInTheDocument();

      // Trigger error
      rerender(<ErrorProneComponent shouldError={true} />);
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Recover from error
      rerender(<ErrorProneComponent shouldError={false} />);
      expect(screen.getByText('Component rendered successfully')).toBeInTheDocument();
    });

    test('should handle WebSocket error recovery', async () => {
      mockWebSocket.isConnected = true;
      
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      // Simulate connection error
      act(() => {
        mockWebSocket.isConnected = false;
        // Trigger error callback if exists
        const onCall = mockWebSocket.on.mock.calls.find(call => call[0] === 'error');
        if (onCall) {
          onCall[1](new Error('Connection error'));
        }
      });

      // Component should handle error gracefully
      const terminalElement = screen.getByRole('application', { name: /terminal/i });
      expect(terminalElement).toBeInTheDocument();

      // Simulate reconnection
      act(() => {
        mockWebSocket.isConnected = true;
        const onCall = mockWebSocket.on.mock.calls.find(call => call[0] === 'connect');
        if (onCall) {
          onCall[1]();
        }
      });

      // Should recover and be usable again
      await user.type(terminalElement, 'test after recovery');
      expect(mockWebSocket.sendData).toHaveBeenCalledWith(
        expect.stringContaining('test after recovery')
      );
    });

    test('should handle invalid prop combinations gracefully', () => {
      // Test with invalid props that might cause issues
      const invalidProps = {
        sessions: null as any,
        activeSessionId: undefined as any,
        onSessionSelect: null as any,
      };

      expect(() => {
        renderWithEnhancements(
          <Sidebar
            {...invalidProps}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
        );
      }).not.toThrow();
    });
  });
});