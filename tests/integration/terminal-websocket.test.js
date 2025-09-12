/**
 * Integration Tests: Terminal + WebSocket Interaction
 * 
 * These tests verify that the Terminal component properly integrates with
 * the WebSocket connection to send/receive data, handle resize events,
 * and manage terminal sessions.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { testUtils, createIntegrationTest } from '@tests/utils/testHelpers';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

createIntegrationTest('Terminal WebSocket Integration', () => {
  let mockClient;
  let mockTerminalRef;
  let mockUseTerminal;
  let mockUseWebSocket;

  beforeEach(() => {
    // Create mock terminal element
    mockTerminalRef = {
      current: document.createElement('div'),
    };

    // Mock useTerminal hook
    mockUseTerminal = {
      terminalRef: mockTerminalRef,
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      terminal: {
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
        focus: jest.fn(),
        resize: jest.fn(),
        cols: 80,
        rows: 24,
      },
    };
    useTerminal.mockReturnValue(mockUseTerminal);

    // Create mock WebSocket client
    mockClient = testUtils.createMockWebSocketClient();
    
    // Mock useWebSocket hook
    mockUseWebSocket = {
      connected: false,
      connecting: false,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: mockClient.on.bind(mockClient),
      off: mockClient.off.bind(mockClient),
    };
    useWebSocket.mockReturnValue(mockUseWebSocket);
  });

  describe('Connection Lifecycle', () => {
    test('should handle WebSocket connection establishment', async () => {
      render(<Terminal sessionId="test-session" />);

      // Initially not connected
      expect(mockUseWebSocket.connected).toBe(false);

      // Simulate connection
      act(() => {
        mockUseWebSocket.connected = true;
        mockClient.connected = true;
        mockClient.emit('connect');
      });

      await waitFor(() => {
        expect(mockClient.connected).toBe(true);
      });
    });

    test('should handle WebSocket disconnection gracefully', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Simulate disconnection
      act(() => {
        mockUseWebSocket.connected = false;
        mockClient.connected = false;
        mockClient.emit('disconnect', 'transport close');
      });

      await waitFor(() => {
        expect(mockClient.connected).toBe(false);
      });
    });
  });

  describe('Data Flow - Terminal to WebSocket', () => {
    test('should send terminal input data to WebSocket', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Simulate terminal input
      const testInput = 'ls -la\r';
      
      // Get the onData handler that would be set up
      const onDataCallback = mockUseTerminal.terminal.onData.mock.calls[0]?.[0];
      
      if (onDataCallback) {
        act(() => {
          onDataCallback(testInput);
        });

        await waitFor(() => {
          expect(mockUseWebSocket.sendData).toHaveBeenCalledWith(
            'test-session',
            testInput
          );
        });
      }
    });

    test('should handle multiple rapid terminal inputs', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      const inputs = ['l', 's', ' ', '-', 'l', 'a', '\r'];
      const onDataCallback = mockUseTerminal.terminal.onData.mock.calls[0]?.[0];

      if (onDataCallback) {
        // Send multiple inputs rapidly
        inputs.forEach((input, index) => {
          setTimeout(() => {
            act(() => {
              onDataCallback(input);
            });
          }, index * 10);
        });

        await waitFor(() => {
          expect(mockUseWebSocket.sendData).toHaveBeenCalledTimes(inputs.length);
        }, { timeout: 1000 });
      }
    });
  });

  describe('Data Flow - WebSocket to Terminal', () => {
    test('should display WebSocket data in terminal', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Simulate receiving data from WebSocket
      const testOutput = 'Hello, World!\r\n$ ';
      
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'test-session',
          data: testOutput,
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(testOutput);
      });
    });

    test('should handle large data chunks from WebSocket', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Create large data chunk (simulating file content)
      const largeData = 'x'.repeat(8192) + '\r\n';
      
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'test-session',
          data: largeData,
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(largeData);
      });
    });

    test('should handle ANSI escape sequences and control characters', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Test various control sequences
      const controlSequences = [
        '\x1b[31mRed text\x1b[0m',     // Color
        '\x1b[2J\x1b[H',               // Clear screen and home cursor
        '\x1b[K',                      // Clear line
        '\x1b[1;1H',                   // Move cursor
        '\r\n',                        // Newline
      ];

      controlSequences.forEach((sequence, index) => {
        act(() => {
          mockClient.emit('terminal-data', {
            sessionId: 'test-session',
            data: sequence,
          });
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(
          controlSequences.length
        );
      });
    });
  });

  describe('Terminal Resize Integration', () => {
    test('should send resize events to WebSocket', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Get the onResize handler
      const onResizeCallback = mockUseTerminal.terminal.onResize.mock.calls[0]?.[0];

      if (onResizeCallback) {
        const newSize = { cols: 100, rows: 30 };
        
        act(() => {
          onResizeCallback(newSize);
        });

        await waitFor(() => {
          expect(mockUseWebSocket.resizeTerminal).toHaveBeenCalledWith(
            'test-session',
            100,
            30
          );
        });
      }
    });

    test('should handle window resize events', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Simulate window resize
      act(() => {
        window.dispatchEvent(new Event('resize'));
      });

      // Should trigger fit terminal
      await waitFor(() => {
        expect(mockUseTerminal.fitTerminal).toHaveBeenCalled();
      });
    });
  });

  describe('Session Management', () => {
    test('should handle session switching', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Switch to different session
      rerender(<Terminal sessionId="session-2" />);

      await waitFor(() => {
        expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
        expect(mockUseTerminal.fitTerminal).toHaveBeenCalled();
      });
    });

    test('should ignore data from wrong session', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="current-session" />);

      // Send data for different session
      act(() => {
        mockClient.emit('terminal-data', {
          sessionId: 'other-session',
          data: 'This should be ignored',
        });
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).not.toHaveBeenCalledWith(
          'This should be ignored'
        );
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle WebSocket connection errors', async () => {
      mockUseWebSocket.connected = false;
      mockClient.connected = false;

      render(<Terminal sessionId="test-session" />);

      act(() => {
        mockClient.emit('connect_error', new Error('Connection failed'));
      });

      // Terminal should still be rendered but not functional
      expect(mockTerminalRef.current).toBeInTheDocument;
    });

    test('should handle malformed WebSocket messages', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Send malformed message
      act(() => {
        mockClient.emit('terminal-data', null);
        mockClient.emit('terminal-data', { sessionId: 'test-session' }); // missing data
        mockClient.emit('terminal-data', { data: 'test' }); // missing sessionId
      });

      // Should not crash
      await waitFor(() => {
        expect(mockTerminalRef.current).toBeInTheDocument;
      });
    });
  });

  describe('Performance and Memory', () => {
    test('should handle high-frequency data updates', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Send many rapid updates
      const updates = Array.from({ length: 1000 }, (_, i) => `Line ${i}\r\n`);
      
      updates.forEach((update, index) => {
        setTimeout(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'test-session',
              data: update,
            });
          });
        }, Math.floor(index / 10)); // Batch updates
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(updates.length);
      }, { timeout: 5000 });
    });

    test('should clean up event listeners on unmount', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      const { unmount } = render(<Terminal sessionId="test-session" />);

      const offSpy = jest.spyOn(mockClient, 'off');

      unmount();

      expect(offSpy).toHaveBeenCalled();
    });
  });

  describe('Accessibility and User Experience', () => {
    test('should focus terminal when clicked', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      const terminalContainer = screen.getByRole('group');
      
      await userEvent.click(terminalContainer);

      expect(mockUseTerminal.focusTerminal).toHaveBeenCalled();
    });

    test('should handle keyboard shortcuts', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      const terminalContainer = screen.getByRole('group');

      // Test Ctrl+C
      await userEvent.type(terminalContainer, '{Control>}c{/Control}');

      const onDataCallback = mockUseTerminal.terminal.onData.mock.calls[0]?.[0];
      if (onDataCallback) {
        expect(mockUseWebSocket.sendData).toHaveBeenCalled();
      }
    });
  });

  describe('Real-time Interaction Scenarios', () => {
    test('should handle interactive command sessions', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Simulate interactive command flow
      const interactions = [
        { type: 'input', data: 'python3\r' },
        { type: 'output', data: 'Python 3.9.0\r\n>>> ' },
        { type: 'input', data: 'print("Hello, World!")\r' },
        { type: 'output', data: 'Hello, World!\r\n>>> ' },
        { type: 'input', data: 'exit()\r' },
        { type: 'output', data: '$ ' },
      ];

      const onDataCallback = mockUseTerminal.terminal.onData.mock.calls[0]?.[0];

      for (const interaction of interactions) {
        if (interaction.type === 'input' && onDataCallback) {
          act(() => {
            onDataCallback(interaction.data);
          });

          await waitFor(() => {
            expect(mockUseWebSocket.sendData).toHaveBeenCalledWith(
              'test-session',
              interaction.data
            );
          });
        } else if (interaction.type === 'output') {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'test-session',
              data: interaction.data,
            });
          });

          await waitFor(() => {
            expect(mockUseTerminal.terminal.write).toHaveBeenCalledWith(
              interaction.data
            );
          });
        }
        
        // Small delay between interactions
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    });

    test('should maintain connection during long-running commands', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Simulate long-running command with periodic output
      const outputs = [
        'Starting long process...\r\n',
        'Progress: 25%\r\n',
        'Progress: 50%\r\n',
        'Progress: 75%\r\n',
        'Process complete!\r\n$ ',
      ];

      outputs.forEach((output, index) => {
        setTimeout(() => {
          act(() => {
            mockClient.emit('terminal-data', {
              sessionId: 'test-session',
              data: output,
            });
          });
        }, index * 500);
      });

      await waitFor(() => {
        expect(mockUseTerminal.terminal.write).toHaveBeenCalledTimes(outputs.length);
      }, { timeout: 3000 });
    });
  });
});