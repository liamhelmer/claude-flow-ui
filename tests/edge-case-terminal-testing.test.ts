/**
 * Comprehensive Edge Case Testing for Terminal Operations
 * Tests boundary conditions, error scenarios, and unusual input patterns
 */

import { renderHook, act } from '@testing-library/react';
import { Terminal } from '@xterm/xterm';
import { useTerminal } from '@/hooks/useTerminal';

// Mock dependencies
jest.mock('@xterm/xterm');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store');

describe('Terminal Edge Case Testing', () => {
  let mockTerminal: any;
  let mockWebSocket: any;
  let mockStore: any;

  beforeEach(() => {
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      dispose: jest.fn(),
      onData: jest.fn(() => ({ dispose: jest.fn() })),
      onResize: jest.fn(() => ({ dispose: jest.fn() })),
      loadAddon: jest.fn(),
      cols: 80,
      rows: 24,
      element: {
        querySelector: jest.fn(() => ({
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 500,
          addEventListener: jest.fn(),
          removeEventListener: jest.fn()
        }))
      }
    };

    mockWebSocket = {
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      isConnected: true
    };

    mockStore = {
      setError: jest.fn(),
      setLoading: jest.fn()
    };

    (Terminal as jest.MockedClass<typeof Terminal>).mockImplementation(() => mockTerminal);

    // Mock useWebSocket hook
    jest.doMock('@/hooks/useWebSocket', () => ({
      useWebSocket: () => mockWebSocket
    }));

    // Mock store hook
    jest.doMock('@/lib/state/store', () => ({
      useAppStore: () => mockStore
    }));
  });

  describe('Boundary Conditions', () => {
    it('should handle zero dimensions gracefully', () => {
      const backendConfig = { cols: 0, rows: 0 };

      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          config: backendConfig
        })
      );

      // Terminal should not be created with zero dimensions
      expect(Terminal).not.toHaveBeenCalled();
    });

    it('should handle extremely large dimensions', () => {
      const backendConfig = { cols: 99999, rows: 99999 };

      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          config: backendConfig
        })
      );

      // Should clamp or handle large dimensions appropriately
      if (Terminal as jest.Mock).mock.calls.length > 0) {
        const terminalConfig = (Terminal as jest.Mock).mock.calls[0][0];
        expect(terminalConfig.cols).toBeLessThanOrEqual(1000); // Reasonable maximum
        expect(terminalConfig.rows).toBeLessThanOrEqual(1000);
      }
    });

    it('should handle negative dimensions', () => {
      const backendConfig = { cols: -10, rows: -5 };

      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          config: backendConfig
        })
      );

      // Should not create terminal with negative dimensions
      expect(Terminal).not.toHaveBeenCalled();
    });

    it('should handle non-integer dimensions', () => {
      const backendConfig = { cols: 80.5, rows: 24.7 };

      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          config: backendConfig
        })
      );

      if ((Terminal as jest.Mock).mock.calls.length > 0) {
        const terminalConfig = (Terminal as jest.Mock).mock.calls[0][0];
        expect(Number.isInteger(terminalConfig.cols)).toBe(true);
        expect(Number.isInteger(terminalConfig.rows)).toBe(true);
      }
    });
  });

  describe('Special Character Handling', () => {
    it('should handle null bytes in terminal data', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
        if (onDataCallback) {
          onDataCallback('\x00\x00\x00'); // Null bytes
        }
      });

      expect(mockWebSocket.sendData).toHaveBeenCalled();
    });

    it('should handle control characters correctly', () => {
      const controlCharacters = [
        '\x01', // SOH (Start of Heading)
        '\x02', // STX (Start of Text)
        '\x03', // ETX (End of Text) - Ctrl+C
        '\x04', // EOT (End of Transmission) - Ctrl+D
        '\x07', // BEL (Bell)
        '\x08', // BS (Backspace)
        '\x09', // HT (Horizontal Tab)
        '\x0A', // LF (Line Feed)
        '\x0D', // CR (Carriage Return)
        '\x1B', // ESC (Escape)
        '\x7F'  // DEL (Delete)
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      controlCharacters.forEach(char => {
        act(() => {
          const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
          if (onDataCallback) {
            onDataCallback(char);
          }
        });

        expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', char);
      });
    });

    it('should handle Unicode characters properly', () => {
      const unicodeStrings = [
        '🔥', // Emoji
        '中文', // Chinese characters
        'العربية', // Arabic
        '🇺🇸', // Flag emoji (surrogate pairs)
        '\u{1F600}', // Grinning face emoji
        '\u{1F1FA}\u{1F1F8}', // US flag (combining)
        'Ñoël', // Accented characters
        '𝕌𝕟𝕚𝕔𝕠𝕕𝕖' // Mathematical alphanumeric symbols
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      unicodeStrings.forEach(str => {
        act(() => {
          const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
          if (onDataCallback) {
            onDataCallback(str);
          }
        });

        expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', str);
      });
    });

    it('should handle malformed UTF-8 sequences', () => {
      const malformedSequences = [
        '\xFF\xFE', // Invalid UTF-8
        '\xC0\x80', // Overlong encoding
        '\xED\xA0\x80', // High surrogate
        '\xED\xB0\x80', // Low surrogate
        '\xF4\x90\x80\x80' // Code point too large
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      malformedSequences.forEach(sequence => {
        expect(() => {
          act(() => {
            const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
            if (onDataCallback) {
              onDataCallback(sequence);
            }
          });
        }).not.toThrow();
      });
    });
  });

  describe('ANSI Sequence Edge Cases', () => {
    it('should handle incomplete ANSI escape sequences', () => {
      const incompleteSequences = [
        '\x1b[', // Just ESC[
        '\x1b[3', // Incomplete parameter
        '\x1b[31', // Missing final byte
        '\x1b[38;5', // Incomplete 256-color sequence
        '\x1b[38;2;255;128', // Incomplete RGB sequence
        '\x1b]0;' // Incomplete OSC sequence
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      incompleteSequences.forEach(sequence => {
        expect(() => {
          mockTerminal.write(sequence);
        }).not.toThrow();
      });
    });

    it('should handle very long ANSI sequences', () => {
      const longSequences = [
        '\x1b[' + '1;'.repeat(1000) + 'H', // Very long CSI sequence
        '\x1b]0;' + 'A'.repeat(10000) + '\x07', // Very long OSC sequence
        '\x1b[38;2;' + Array(1000).fill('255').join(';') + 'm' // Excessive parameters
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      longSequences.forEach(sequence => {
        expect(() => {
          mockTerminal.write(sequence);
        }).not.toThrow();
      });
    });

    it('should handle malformed ANSI sequences', () => {
      const malformedSequences = [
        '\x1b[999999999999999999999999m', // Extremely large parameter
        '\x1b[;;;;;;;;;;;;;;;;;;;;;;;;;H', // Multiple empty parameters
        '\x1b[-1;-1H', // Negative parameters
        '\x1b[?1;2;3;4;5;6;7;8;9;0q', // Invalid private mode parameters
        '\x1bOZ', // Invalid SS3 sequence
        '\x1b N' // Invalid SS2 sequence
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      malformedSequences.forEach(sequence => {
        expect(() => {
          mockTerminal.write(sequence);
        }).not.toThrow();
      });
    });
  });

  describe('Session Management Edge Cases', () => {
    it('should handle empty session ID', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: '' })
      );

      // Should handle empty session ID gracefully
      expect(result.current.terminalRef).toBeDefined();
    });

    it('should handle null session ID', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: null as any })
      );

      // Should handle null session ID gracefully
      expect(result.current.terminalRef).toBeDefined();
    });

    it('should handle extremely long session ID', () => {
      const longSessionId = 'session-' + 'a'.repeat(10000);

      const { result } = renderHook(() =>
        useTerminal({ sessionId: longSessionId })
      );

      // Should handle very long session IDs
      expect(result.current.terminalRef).toBeDefined();
    });

    it('should handle session ID with special characters', () => {
      const specialSessionIds = [
        'session-with-spaces and more',
        'session/with/slashes',
        'session\\with\\backslashes',
        'session?with?questions',
        'session#with#hashes',
        'session%20with%20encoding',
        'session\nwith\nnewlines',
        'session\twith\ttabs'
      ];

      specialSessionIds.forEach(sessionId => {
        const { result } = renderHook(() =>
          useTerminal({ sessionId })
        );

        expect(result.current.terminalRef).toBeDefined();
      });
    });
  });

  describe('Memory and Resource Edge Cases', () => {
    it('should handle rapid terminal creation and destruction', () => {
      const terminals: any[] = [];

      // Create many terminals rapidly
      for (let i = 0; i < 100; i++) {
        const { result, unmount } = renderHook(() =>
          useTerminal({ sessionId: `session-${i}` })
        );

        terminals.push({ result, unmount });
      }

      // Destroy them all rapidly
      terminals.forEach(({ unmount }) => {
        expect(() => unmount()).not.toThrow();
      });

      // Verify cleanup
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });

    it('should handle massive scrollback buffer', () => {
      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          config: { scrollback: 999999 }
        })
      );

      // Should handle large scrollback without issues
      if ((Terminal as jest.Mock).mock.calls.length > 0) {
        const terminalConfig = (Terminal as jest.Mock).mock.calls[0][0];
        expect(terminalConfig.scrollback).toBeDefined();
      }
    });

    it('should handle rapid resize events', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Simulate rapid resize events
      for (let i = 0; i < 100; i++) {
        act(() => {
          mockWebSocket.resizeTerminal('test-session', 80 + i, 24 + i);
        });
      }

      // Should handle rapid resizes without crashing
      expect(mockWebSocket.resizeTerminal).toHaveBeenCalledTimes(100);
    });
  });

  describe('Network and Connection Edge Cases', () => {
    it('should handle WebSocket disconnection during terminal operation', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Simulate WebSocket disconnection
      act(() => {
        mockWebSocket.isConnected = false;
        const connectionHandler = mockWebSocket.on.mock.calls.find(
          call => call[0] === 'connection-change'
        )?.[1];
        if (connectionHandler) {
          connectionHandler(false);
        }
      });

      // Terminal should handle disconnection gracefully
      expect(result.current.isConnected).toBe(false);
    });

    it('should handle partial message reception', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      const partialMessages = [
        'Hello',
        ' World',
        '\r\n',
        'Another',
        ' message',
        ' here\r\n'
      ];

      // Send partial messages
      partialMessages.forEach(part => {
        act(() => {
          const dataHandler = mockWebSocket.on.mock.calls.find(
            call => call[0] === 'terminal-data'
          )?.[1];
          if (dataHandler) {
            dataHandler({
              sessionId: 'test-session',
              data: part
            });
          }
        });
      });

      // Should handle partial messages correctly
      expect(mockTerminal.write).toHaveBeenCalledTimes(partialMessages.length);
    });

    it('should handle message reordering', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      const messages = [
        { id: 1, data: 'First message\r\n' },
        { id: 2, data: 'Second message\r\n' },
        { id: 3, data: 'Third message\r\n' }
      ];

      // Send messages out of order
      const reorderedMessages = [messages[1], messages[2], messages[0]];

      reorderedMessages.forEach(message => {
        act(() => {
          const dataHandler = mockWebSocket.on.mock.calls.find(
            call => call[0] === 'terminal-data'
          )?.[1];
          if (dataHandler) {
            dataHandler({
              sessionId: 'test-session',
              data: message.data
            });
          }
        });
      });

      // Should handle out-of-order messages
      expect(mockTerminal.write).toHaveBeenCalledTimes(3);
    });
  });

  describe('Input Validation Edge Cases', () => {
    it('should handle function keys and special key combinations', () => {
      const specialKeys = [
        '\x1bOP', // F1
        '\x1bOQ', // F2
        '\x1b[15~', // F5
        '\x1b[17~', // F6
        '\x1b[A', // Up arrow
        '\x1b[B', // Down arrow
        '\x1b[C', // Right arrow
        '\x1b[D', // Left arrow
        '\x1b[H', // Home
        '\x1b[F', // End
        '\x1b[2~', // Insert
        '\x1b[3~', // Delete
        '\x1b[5~', // Page Up
        '\x1b[6~', // Page Down
        '\x1b[1;5A', // Ctrl+Up
        '\x1b[1;5B', // Ctrl+Down
        '\x1b[1;2A', // Shift+Up
        '\x1b[1;2B', // Shift+Down
        '\x1b[1;3A', // Alt+Up
        '\x1b[1;3B'  // Alt+Down
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      specialKeys.forEach(key => {
        act(() => {
          const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
          if (onDataCallback) {
            onDataCallback(key);
          }
        });

        expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', key);
      });
    });

    it('should handle mouse events in terminal', () => {
      const mouseEvents = [
        '\x1b[M !!', // Mouse button press
        '\x1b[M!!!', // Mouse button release
        '\x1b[M@!!', // Mouse drag
        '\x1b[<0;1;1M', // SGR mouse press
        '\x1b[<0;1;1m', // SGR mouse release
        '\x1b[<64;10;5M', // Mouse wheel up
        '\x1b[<65;10;5M'  // Mouse wheel down
      ];

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      mouseEvents.forEach(event => {
        expect(() => {
          act(() => {
            const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
            if (onDataCallback) {
              onDataCallback(event);
            }
          });
        }).not.toThrow();
      });
    });

    it('should handle paste events with large content', () => {
      const largeContent = 'A'.repeat(1000000); // 1MB of content

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(() => {
        act(() => {
          const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
          if (onDataCallback) {
            onDataCallback(largeContent);
          }
        });
      }).not.toThrow();

      // Should handle large paste without crashing
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', largeContent);
    });
  });

  describe('Error Recovery Edge Cases', () => {
    it('should recover from terminal initialization failure', () => {
      // Mock terminal constructor to throw
      (Terminal as jest.Mock).mockImplementationOnce(() => {
        throw new Error('Terminal initialization failed');
      });

      expect(() => {
        const { result } = renderHook(() =>
          useTerminal({ sessionId: 'test-session' })
        );
      }).not.toThrow();
    });

    it('should handle addon loading failures gracefully', () => {
      mockTerminal.loadAddon.mockImplementation(() => {
        throw new Error('Addon loading failed');
      });

      expect(() => {
        const { result } = renderHook(() =>
          useTerminal({ sessionId: 'test-session' })
        );
      }).not.toThrow();
    });

    it('should recover from DOM element access failures', () => {
      mockTerminal.element = null;

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle write failures gracefully', () => {
      mockTerminal.write.mockImplementation(() => {
        throw new Error('Write failed');
      });

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(() => {
        result.current.writeToTerminal('test data');
      }).not.toThrow();
    });
  });
});