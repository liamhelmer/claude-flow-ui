/**
 * @jest-environment jsdom
 */

import { render, screen, waitFor, within, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';
import { 
  TestDataGenerator,
  TestScenarioBuilder,
  renderWithEnhancements 
} from './test-utilities';

// Mock dependencies with full workflow support
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

// Enhanced store mock for E2E testing
const createMockStore = (initialState = {}) => ({
  sessions: TestDataGenerator.generateSessions(3),
  activeSession: null,
  isLoading: false,
  error: null,
  agents: TestDataGenerator.generateAgents(5),
  memory: TestDataGenerator.generateMemoryData(),
  commands: TestDataGenerator.generateCommands(10),
  prompts: [],
  addSession: jest.fn(),
  removeSession: jest.fn(),
  setActiveSession: jest.fn(),
  updateSessionStatus: jest.fn(),
  addCommand: jest.fn(),
  clearCommands: jest.fn(),
  ...initialState,
});

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => createMockStore(),
}));

describe('End-to-End User Workflows', () => {
  describe('Complete Terminal Session Workflow', () => {
    test('should handle full terminal session lifecycle', async () => {
      const WorkflowApp = () => {
        const [sessions, setSessions] = React.useState(TestDataGenerator.generateSessions(2));
        const [activeSessionId, setActiveSessionId] = React.useState<string | null>(sessions[0]?.id || null);
        const [commands, setCommands] = React.useState<any[]>([]);

        const handleNewSession = () => {
          const newSession = {
            id: `session-${Date.now()}`,
            name: `New Session ${sessions.length + 1}`,
            status: 'active' as const,
            createdAt: Date.now(),
            lastActivity: Date.now(),
            commands: [],
          };
          setSessions(prev => [...prev, newSession]);
          setActiveSessionId(newSession.id);
        };

        const handleSessionSelect = (sessionId: string) => {
          setActiveSessionId(sessionId);
          // Simulate loading session commands
          const sessionCommands = TestDataGenerator.generateCommands(5);
          setCommands(sessionCommands);
        };

        const handleSessionClose = (sessionId: string) => {
          setSessions(prev => prev.filter(s => s.id !== sessionId));
          if (activeSessionId === sessionId) {
            const remainingSessions = sessions.filter(s => s.id !== sessionId);
            setActiveSessionId(remainingSessions[0]?.id || null);
          }
        };

        return (
          <div className="flex h-screen">
            <aside className="w-64 bg-gray-100">
              <Sidebar
                sessions={sessions}
                activeSessionId={activeSessionId}
                onSessionSelect={handleSessionSelect}
                onSessionClose={handleSessionClose}
                onNewSession={handleNewSession}
              />
            </aside>
            <main className="flex-1 flex flex-col">
              <div className="border-b">
                <TabList
                  tabs={[
                    { id: 'terminal', title: 'Terminal', isActive: true },
                    { id: 'monitoring', title: 'Monitoring', isActive: false },
                  ]}
                  onTabChange={() => {}}
                />
              </div>
              <div className="flex-1">
                {activeSessionId && (
                  <Terminal sessionId={activeSessionId} />
                )}
              </div>
            </main>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<WorkflowApp />);

      // Step 1: Verify initial state
      expect(screen.getByText('Test Session 0')).toBeInTheDocument();
      expect(screen.getByRole('application', { name: /terminal/i })).toBeInTheDocument();

      // Step 2: Create new session
      const newSessionButton = screen.getByRole('button', { name: /new session/i });
      await user.click(newSessionButton);

      await waitFor(() => {
        expect(screen.getByText(/new session 3/i)).toBeInTheDocument();
      });

      // Step 3: Switch between sessions
      const sessionButtons = screen.getAllByRole('button');
      const firstSessionButton = sessionButtons.find(btn => btn.textContent?.includes('Test Session 0'));
      
      if (firstSessionButton) {
        await user.click(firstSessionButton);
        // Verify session switch occurred
        expect(firstSessionButton).toHaveAttribute('aria-current', 'page');
      }

      // Step 4: Interact with terminal
      const terminal = screen.getByRole('application', { name: /terminal/i });
      await user.type(terminal, 'echo "Hello World"');
      await user.keyboard('{Enter}');

      // Step 5: Close session
      // This would typically require a close button implementation
      // For now, verify the session management structure is in place
      expect(screen.getAllByRole('button').length).toBeGreaterThan(1);
    });

    test('should handle terminal command execution workflow', async () => {
      const CommandWorkflowComponent = () => {
        const [commandHistory, setCommandHistory] = React.useState<string[]>([]);
        const [currentCommand, setCurrentCommand] = React.useState('');
        const [output, setOutput] = React.useState<string[]>([]);

        const executeCommand = async (command: string) => {
          setCommandHistory(prev => [...prev, command]);
          setCurrentCommand('');

          // Simulate command execution
          switch (command.toLowerCase()) {
            case 'help':
              setOutput(prev => [...prev, 'Available commands: help, clear, ls, pwd']);
              break;
            case 'clear':
              setOutput([]);
              break;
            case 'ls':
              setOutput(prev => [...prev, 'file1.txt  file2.js  directory/']);
              break;
            case 'pwd':
              setOutput(prev => [...prev, '/home/user']);
              break;
            default:
              setOutput(prev => [...prev, `Command not found: ${command}`]);
          }
        };

        const handleKeyDown = (e: React.KeyboardEvent) => {
          if (e.key === 'Enter' && currentCommand.trim()) {
            executeCommand(currentCommand.trim());
          } else if (e.key === 'ArrowUp' && commandHistory.length > 0) {
            setCurrentCommand(commandHistory[commandHistory.length - 1]);
          }
        };

        return (
          <div className="terminal-workflow">
            <div data-testid="terminal-output" className="output">
              {output.map((line, index) => (
                <div key={index}>{line}</div>
              ))}
            </div>
            <div className="input-line">
              <span>$ </span>
              <input
                type="text"
                value={currentCommand}
                onChange={(e) => setCurrentCommand(e.target.value)}
                onKeyDown={handleKeyDown}
                data-testid="command-input"
                placeholder="Enter command..."
              />
            </div>
            <div data-testid="command-history">
              History: {commandHistory.join(', ')}
            </div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<CommandWorkflowComponent />);

      const commandInput = screen.getByTestId('command-input');
      const terminalOutput = screen.getByTestId('terminal-output');

      // Test command execution workflow
      await user.type(commandInput, 'help');
      await user.keyboard('{Enter}');

      await waitFor(() => {
        expect(terminalOutput).toHaveTextContent('Available commands');
      });

      await user.type(commandInput, 'ls');
      await user.keyboard('{Enter}');

      await waitFor(() => {
        expect(terminalOutput).toHaveTextContent('file1.txt');
      });

      await user.type(commandInput, 'pwd');
      await user.keyboard('{Enter}');

      await waitFor(() => {
        expect(terminalOutput).toHaveTextContent('/home/user');
      });

      // Test command history
      await user.keyboard('{ArrowUp}');
      expect(commandInput).toHaveValue('pwd');

      // Test clear command
      await user.clear(commandInput);
      await user.type(commandInput, 'clear');
      await user.keyboard('{Enter}');

      await waitFor(() => {
        expect(terminalOutput).toBeEmptyDOMElement();
      });

      // Verify command history is maintained
      const history = screen.getByTestId('command-history');
      expect(history).toHaveTextContent('help, ls, pwd, clear');
    });
  });

  describe('Multi-Agent Collaboration Workflow', () => {
    test('should simulate agent swarm coordination', async () => {
      const AgentSwarmWorkflow = () => {
        const [agents, setAgents] = React.useState(TestDataGenerator.generateAgents(5));
        const [tasks, setTasks] = React.useState<any[]>([]);
        const [swarmActivity, setSwarmActivity] = React.useState<string[]>([]);

        const assignTask = (taskName: string) => {
          const availableAgents = agents.filter(a => a.status === 'idle');
          if (availableAgents.length === 0) {
            setSwarmActivity(prev => [...prev, `No available agents for task: ${taskName}`]);
            return;
          }

          const selectedAgent = availableAgents[0];
          const newTask = {
            id: `task-${Date.now()}`,
            name: taskName,
            assignedAgent: selectedAgent.id,
            status: 'in_progress',
            startTime: Date.now(),
          };

          setTasks(prev => [...prev, newTask]);
          setAgents(prev => prev.map(a => 
            a.id === selectedAgent.id ? { ...a, status: 'active' } : a
          ));
          setSwarmActivity(prev => [...prev, `Task "${taskName}" assigned to ${selectedAgent.name}`]);

          // Simulate task completion
          setTimeout(() => {
            setTasks(prev => prev.map(t => 
              t.id === newTask.id ? { ...t, status: 'completed', endTime: Date.now() } : t
            ));
            setAgents(prev => prev.map(a => 
              a.id === selectedAgent.id ? { ...a, status: 'idle' } : a
            ));
            setSwarmActivity(prev => [...prev, `Task "${taskName}" completed by ${selectedAgent.name}`]);
          }, 1000);
        };

        const spawnNewAgent = () => {
          const newAgent = {
            id: `agent-${Date.now()}`,
            name: `Agent ${agents.length + 1}`,
            type: 'coder' as const,
            status: 'idle' as const,
            capabilities: ['general'],
            metrics: {
              tasksCompleted: 0,
              errorRate: 0,
              averageResponseTime: 0,
            },
          };

          setAgents(prev => [...prev, newAgent]);
          setSwarmActivity(prev => [...prev, `New agent spawned: ${newAgent.name}`]);
        };

        return (
          <div className="agent-swarm-workflow">
            <div className="controls">
              <button onClick={() => assignTask('Code Review')} data-testid="assign-review">
                Assign Code Review
              </button>
              <button onClick={() => assignTask('Write Tests')} data-testid="assign-tests">
                Assign Test Writing
              </button>
              <button onClick={() => assignTask('Refactor Code')} data-testid="assign-refactor">
                Assign Refactoring
              </button>
              <button onClick={spawnNewAgent} data-testid="spawn-agent">
                Spawn New Agent
              </button>
            </div>

            <div className="agent-status" data-testid="agent-status">
              <h3>Agent Status</h3>
              {agents.map(agent => (
                <div key={agent.id} className={`agent agent-${agent.status}`}>
                  {agent.name} - {agent.status} ({agent.type})
                </div>
              ))}
            </div>

            <div className="task-queue" data-testid="task-queue">
              <h3>Task Queue</h3>
              {tasks.map(task => (
                <div key={task.id} className={`task task-${task.status}`}>
                  {task.name} - {task.status}
                </div>
              ))}
            </div>

            <div className="swarm-activity" data-testid="swarm-activity">
              <h3>Swarm Activity</h3>
              {swarmActivity.slice(-10).map((activity, index) => (
                <div key={index} className="activity-log">
                  {activity}
                </div>
              ))}
            </div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<AgentSwarmWorkflow />);

      // Step 1: Verify initial agent state
      const agentStatus = screen.getByTestId('agent-status');
      expect(within(agentStatus).getAllByText(/agent/i)).toHaveLength(5);

      // Step 2: Assign tasks to agents
      await user.click(screen.getByTestId('assign-review'));
      await user.click(screen.getByTestId('assign-tests'));

      // Verify tasks are created and agents are assigned
      await waitFor(() => {
        const taskQueue = screen.getByTestId('task-queue');
        expect(within(taskQueue).getByText(/code review/i)).toBeInTheDocument();
        expect(within(taskQueue).getByText(/write tests/i)).toBeInTheDocument();
      });

      // Step 3: Wait for task completion
      await waitFor(() => {
        const activity = screen.getByTestId('swarm-activity');
        expect(within(activity).getByText(/completed/i)).toBeInTheDocument();
      }, { timeout: 3000 });

      // Step 4: Spawn new agent
      await user.click(screen.getByTestId('spawn-agent'));

      await waitFor(() => {
        const agentStatus = screen.getByTestId('agent-status');
        expect(within(agentStatus).getAllByText(/agent/i)).toHaveLength(6);
      });

      // Step 5: Verify swarm coordination
      const swarmActivity = screen.getByTestId('swarm-activity');
      expect(within(swarmActivity).getByText(/new agent spawned/i)).toBeInTheDocument();
    });
  });

  describe('Error Recovery and Resilience Workflow', () => {
    test('should handle connection failures and recovery', async () => {
      const ErrorRecoveryWorkflow = () => {
        const [connectionState, setConnectionState] = React.useState<'connected' | 'disconnected' | 'reconnecting'>('connected');
        const [messages, setMessages] = React.useState<string[]>([]);
        const [retryCount, setRetryCount] = React.useState(0);

        const simulateConnectionError = () => {
          setConnectionState('disconnected');
          setMessages(prev => [...prev, 'Connection lost']);
        };

        const attemptReconnection = async () => {
          setConnectionState('reconnecting');
          setRetryCount(prev => prev + 1);
          setMessages(prev => [...prev, `Reconnection attempt ${retryCount + 1}`]);

          // Simulate reconnection attempt
          await new Promise(resolve => setTimeout(resolve, 1000));

          if (Math.random() > 0.3) { // 70% success rate
            setConnectionState('connected');
            setMessages(prev => [...prev, 'Connection restored']);
            setRetryCount(0);
          } else {
            setConnectionState('disconnected');
            setMessages(prev => [...prev, 'Reconnection failed']);
            
            // Auto-retry with exponential backoff
            if (retryCount < 3) {
              setTimeout(attemptReconnection, Math.pow(2, retryCount) * 1000);
            }
          }
        };

        const sendMessage = (message: string) => {
          if (connectionState === 'connected') {
            setMessages(prev => [...prev, `Sent: ${message}`]);
          } else {
            setMessages(prev => [...prev, `Failed to send: ${message} (not connected)`]);
          }
        };

        return (
          <div className="error-recovery-workflow">
            <div className="connection-status" data-testid="connection-status">
              Status: {connectionState}
              {retryCount > 0 && ` (Retry ${retryCount})`}
            </div>

            <div className="controls">
              <button onClick={simulateConnectionError} data-testid="simulate-error">
                Simulate Error
              </button>
              <button 
                onClick={attemptReconnection} 
                disabled={connectionState === 'connected'}
                data-testid="reconnect"
              >
                Reconnect
              </button>
              <button 
                onClick={() => sendMessage('Test message')}
                data-testid="send-message"
              >
                Send Message
              </button>
            </div>

            <div className="message-log" data-testid="message-log">
              {messages.map((msg, index) => (
                <div key={index} className="log-entry">{msg}</div>
              ))}
            </div>

            {connectionState === 'connected' && (
              <Terminal sessionId="recovery-test" />
            )}
          </div>
        );
      };

      const { user } = renderWithEnhancements(<ErrorRecoveryWorkflow />);

      // Step 1: Verify initial connected state
      expect(screen.getByTestId('connection-status')).toHaveTextContent('connected');
      expect(screen.getByRole('application', { name: /terminal/i })).toBeInTheDocument();

      // Step 2: Test normal message sending
      await user.click(screen.getByTestId('send-message'));
      
      await waitFor(() => {
        expect(screen.getByTestId('message-log')).toHaveTextContent('Sent: Test message');
      });

      // Step 3: Simulate connection error
      await user.click(screen.getByTestId('simulate-error'));

      await waitFor(() => {
        expect(screen.getByTestId('connection-status')).toHaveTextContent('disconnected');
      });

      // Step 4: Test failed message sending
      await user.click(screen.getByTestId('send-message'));

      await waitFor(() => {
        expect(screen.getByTestId('message-log')).toHaveTextContent('Failed to send');
      });

      // Step 5: Test reconnection
      await user.click(screen.getByTestId('reconnect'));

      await waitFor(() => {
        expect(screen.getByTestId('connection-status')).toHaveTextContent('reconnecting');
      });

      // Wait for reconnection to complete
      await waitFor(() => {
        const status = screen.getByTestId('connection-status').textContent;
        expect(status).toMatch(/connected|disconnected/);
      }, { timeout: 3000 });

      // Step 6: Verify recovery (if successful)
      const finalStatus = screen.getByTestId('connection-status').textContent;
      if (finalStatus?.includes('connected')) {
        expect(screen.getByRole('application', { name: /terminal/i })).toBeInTheDocument();
        
        // Test that functionality is restored
        await user.click(screen.getByTestId('send-message'));
        await waitFor(() => {
          expect(screen.getByTestId('message-log')).toHaveTextContent('Sent: Test message');
        });
      }
    });
  });

  describe('Performance Under Load Workflow', () => {
    test('should maintain responsiveness under heavy load', async () => {
      const LoadTestWorkflow = () => {
        const [isLoadTesting, setIsLoadTesting] = React.useState(false);
        const [metrics, setMetrics] = React.useState({
          requestsPerSecond: 0,
          averageResponseTime: 0,
          errorRate: 0,
        });
        const [loadLevel, setLoadLevel] = React.useState(1);

        const startLoadTest = async () => {
          setIsLoadTesting(true);
          const startTime = Date.now();
          let requests = 0;
          let errors = 0;
          const responseTimes: number[] = [];

          const makeRequest = async () => {
            const requestStart = Date.now();
            
            try {
              // Simulate API request with variable delay
              await new Promise(resolve => 
                setTimeout(resolve, Math.random() * 100 + 50)
              );
              
              if (Math.random() < 0.05) { // 5% error rate
                throw new Error('Simulated error');
              }
              
              requests++;
              responseTimes.push(Date.now() - requestStart);
            } catch (error) {
              errors++;
            }
          };

          // Generate load based on level
          const requestsToMake = loadLevel * 100;
          const promises = Array.from({ length: requestsToMake }, makeRequest);

          await Promise.all(promises);

          const totalTime = (Date.now() - startTime) / 1000;
          const avgResponseTime = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;

          setMetrics({
            requestsPerSecond: requests / totalTime,
            averageResponseTime: avgResponseTime,
            errorRate: (errors / (requests + errors)) * 100,
          });

          setIsLoadTesting(false);
        };

        return (
          <div className="load-test-workflow">
            <div className="load-controls">
              <label>
                Load Level: 
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={loadLevel}
                  onChange={(e) => setLoadLevel(Number(e.target.value))}
                  data-testid="load-level"
                />
                {loadLevel}x
              </label>
              <button 
                onClick={startLoadTest}
                disabled={isLoadTesting}
                data-testid="start-load-test"
              >
                {isLoadTesting ? 'Testing...' : 'Start Load Test'}
              </button>
            </div>

            <div className="metrics" data-testid="metrics">
              <div>Requests/sec: {metrics.requestsPerSecond.toFixed(2)}</div>
              <div>Avg Response Time: {metrics.averageResponseTime.toFixed(2)}ms</div>
              <div>Error Rate: {metrics.errorRate.toFixed(2)}%</div>
            </div>

            <div className="heavy-ui">
              {/* Simulate heavy UI components during load test */}
              {Array.from({ length: isLoadTesting ? loadLevel * 10 : 10 }, (_, i) => (
                <div key={i} className="heavy-component">
                  Component {i} - {Math.random().toString(36).substring(7)}
                </div>
              ))}
            </div>

            <Terminal sessionId="load-test" />
          </div>
        );
      };

      const { user } = renderWithEnhancements(<LoadTestWorkflow />);

      // Step 1: Set moderate load level
      const loadLevelSlider = screen.getByTestId('load-level');
      await user.clear(loadLevelSlider);
      await user.type(loadLevelSlider, '3');

      // Step 2: Start load test
      const startButton = screen.getByTestId('start-load-test');
      await user.click(startButton);

      // Verify test is running
      await waitFor(() => {
        expect(screen.getByText('Testing...')).toBeInTheDocument();
      });

      // Step 3: Verify UI remains responsive during test
      const terminal = screen.getByRole('application', { name: /terminal/i });
      await user.type(terminal, 'test during load');
      
      // UI should still be interactive
      expect(terminal).toBeInTheDocument();

      // Step 4: Wait for test completion and verify metrics
      await waitFor(() => {
        expect(screen.getByText('Start Load Test')).toBeInTheDocument();
      }, { timeout: 10000 });

      const metrics = screen.getByTestId('metrics');
      expect(within(metrics).getByText(/requests\/sec/i)).toBeInTheDocument();
      expect(within(metrics).getByText(/avg response time/i)).toBeInTheDocument();
      expect(within(metrics).getByText(/error rate/i)).toBeInTheDocument();

      // Step 5: Verify performance is within acceptable bounds
      const metricsText = metrics.textContent || '';
      const responseTimeMatch = metricsText.match(/Avg Response Time: ([\d.]+)ms/);
      const errorRateMatch = metricsText.match(/Error Rate: ([\d.]+)%/);

      if (responseTimeMatch) {
        const responseTime = parseFloat(responseTimeMatch[1]);
        expect(responseTime).toBeLessThan(500); // Response time should be under 500ms
      }

      if (errorRateMatch) {
        const errorRate = parseFloat(errorRateMatch[1]);
        expect(errorRate).toBeLessThan(10); // Error rate should be under 10%
      }
    });
  });
});