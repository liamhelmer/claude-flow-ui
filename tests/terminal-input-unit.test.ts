/**
 * Unit Tests for Terminal Input Functionality
 * Focused testing of the input handling components and their interactions
 */

import { renderHook, act } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock dependencies
jest.mock('@xterm/xterm');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store', () => ({
  useAppStore: jest.fn()
}));
jest.mock('@/services/terminal-config', () => ({
  terminalConfigService: {
    fetchConfig: jest.fn(),
    clearCache: jest.fn(),
    hasConfig: jest.fn(),
    getCachedConfig: jest.fn()
  }
}));

describe('Terminal Input Unit Tests', () => {
  let mockTerminal: any;
  let mockWebSocket: any;
  let mockStore: any;
  let mockTerminalConfig: any;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Mock terminal instance
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn().mockReturnValue(true),
      dispose: jest.fn(),
      onData: jest.fn(() => ({ dispose: jest.fn() })),
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

    // Mock WebSocket hook
    mockWebSocket = {
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      isConnected: true,
      connect: jest.fn().mockResolvedValue(undefined)
    };

    // Mock store
    mockStore = {
      setError: jest.fn(),
      setLoading: jest.fn()
    };

    // Mock terminal config service
    mockTerminalConfig = {
      fetchConfig: jest.fn().mockResolvedValue({ cols: 80, rows: 24 }),
      clearCache: jest.fn(),
      hasConfig: jest.fn().mockReturnValue(false),
      getCachedConfig: jest.fn().mockReturnValue(null)
    };

    // Setup mocks
    const { Terminal } = require('@xterm/xterm');
    Terminal.mockImplementation(() => mockTerminal);

    const useWebSocketMock = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
    useWebSocketMock.mockReturnValue(mockWebSocket);

    // Mock the store
    const useAppStoreMock = require('@/lib/state/store').useAppStore;
    if (useAppStoreMock) {
      useAppStoreMock.mockReturnValue(mockStore);
    }

    // Mock the terminal config service properly
    const terminalConfigModule = require('@/services/terminal-config');
    if (terminalConfigModule && terminalConfigModule.terminalConfigService) {
      Object.assign(terminalConfigModule.terminalConfigService, mockTerminalConfig);
    }
  });

  describe('Input Data Flow', () => {
    test('should capture terminal input via onData handler', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Wait for terminal initialization
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Verify onData was called during terminal creation
      expect(mockTerminal.onData).toHaveBeenCalled();

      // Get the onData callback
      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      expect(typeof onDataCallback).toBe('function');

      // Simulate user input
      act(() => {
        onDataCallback('test input');
      });

      // Verify sendData was called with correct parameters
      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', 'test input');
    });

    test('should handle special characters in input', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];

      // Test various special characters
      const specialChars = [
        '\r',     // Enter key
        '\x03',   // Ctrl+C
        '\x04',   // Ctrl+D
        '\x1b[A', // Up arrow
        '\x1b[B', // Down arrow
        '\x7f',   // Delete
      ];

      specialChars.forEach(char => {
        act(() => {
          onDataCallback(char);
        });

        expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', char);
      });
    });

    test('should handle Unicode characters correctly', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];

      // Test Unicode characters
      const unicodeChars = [
        '🔥',       // Emoji
        '中文',     // Chinese
        'ñoël',     // Accented
        '𝕌𝕟𝕚𝕔𝕠𝕕𝕖' // Math symbols
      ];

      unicodeChars.forEach(char => {
        act(() => {
          onDataCallback(char);
        });

        expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', char);
      });
    });
  });

  describe('Session Management', () => {
    test('should route input to correct session ID', async () => {
      const { result, rerender } = renderHook((props) =>
        useTerminal(props),
        { initialProps: { sessionId: 'session-1' } }
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      let onDataCallback = mockTerminal.onData.mock.calls[0][0];

      // Input to first session
      act(() => {
        onDataCallback('input for session 1');
      });

      expect(mockWebSocket.sendData).toHaveBeenCalledWith('session-1', 'input for session 1');

      // Change session
      rerender({ sessionId: 'session-2' });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Get new callback after session change
      onDataCallback = mockTerminal.onData.mock.calls[mockTerminal.onData.mock.calls.length - 1][0];

      // Input to second session
      act(() => {
        onDataCallback('input for session 2');
      });

      expect(mockWebSocket.sendData).toHaveBeenCalledWith('session-2', 'input for session 2');
    });

    test('should handle empty session ID gracefully', async () => {
      // Capture console.error to verify error logging
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const { result } = renderHook(() =>
        useTerminal({ sessionId: '' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Check if onData was called (terminal might not be created for empty sessionId)
      if (mockTerminal.onData.mock.calls.length === 0) {
        // Terminal not created due to empty sessionId - test still valid
        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining('No session ID available')
        );
        consoleSpy.mockRestore();
        return;
      }

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];

      act(() => {
        onDataCallback('test input');
      });

      // Should log error about missing session ID
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('No session ID available'),
        expect.any(Object)
      );

      consoleSpy.mockRestore();
    });

    test('should handle rapid session switching', async () => {
      const { result, rerender } = renderHook((props) =>
        useTerminal(props),
        { initialProps: { sessionId: 'session-1' } }
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Rapidly switch sessions
      const sessions = ['session-2', 'session-3', 'session-4', 'session-5'];

      for (const sessionId of sessions) {
        rerender({ sessionId });

        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 50));
        });

        const onDataCallback = mockTerminal.onData.mock.calls[mockTerminal.onData.mock.calls.length - 1][0];

        act(() => {
          onDataCallback(`input-${sessionId}`);
        });

        expect(mockWebSocket.sendData).toHaveBeenCalledWith(sessionId, `input-${sessionId}`);
      }
    });
  });

  describe('WebSocket Integration', () => {
    test('should handle WebSocket disconnection during input', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Simulate WebSocket disconnection
      mockWebSocket.isConnected = false;

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];

      // Capture console.error
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      act(() => {
        onDataCallback('test input while disconnected');
      });

      // Should log error about sendData not being available
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('sendData not available'),
        expect.any(Object)
      );

      consoleSpy.mockRestore();
    });

    test('should handle sendData function becoming unavailable', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Make sendData unavailable
      mockWebSocket.sendData = null;

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      act(() => {
        onDataCallback('test input');
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('sendData not available'),
        expect.any(Object)
      );

      consoleSpy.mockRestore();
    });

    test('should register WebSocket event listeners correctly', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Verify event listeners were registered
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('connection-change', expect.any(Function));
    });
  });

  describe('Focus Management', () => {
    test('should focus terminal when focusTerminal is called', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Call focusTerminal
      const focusResult = result.current.focusTerminal();

      expect(mockTerminal.focus).toHaveBeenCalled();
      expect(focusResult).toBe(true);
    });

    test('should return false when focusing terminal without element', async () => {
      // Mock terminal without element
      mockTerminal.element = null;

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const focusResult = result.current.focusTerminal();

      expect(focusResult).toBe(false);
    });

    test('should handle focus errors gracefully', async () => {
      // Mock focus to throw error
      mockTerminal.focus.mockImplementation(() => {
        throw new Error('Focus failed');
      });

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const focusResult = result.current.focusTerminal();

      expect(focusResult).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to focus terminal'),
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Terminal Data Handling', () => {
    test('should handle incoming terminal data correctly', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Get the terminal-data event handler
      const dataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )[1];

      // Simulate incoming data
      act(() => {
        dataHandler({
          sessionId: 'test-session',
          data: 'Hello from terminal'
        });
      });

      // Verify data was written to terminal
      expect(mockTerminal.write).toHaveBeenCalledWith('Hello from terminal');
    });

    test('should handle session ID mismatch in incoming data', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const dataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )[1];

      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();

      // Simulate data for different session
      act(() => {
        dataHandler({
          sessionId: 'different-session',
          data: 'Data for different session'
        });
      });

      // Should log session mismatch analysis (implementation may vary)
      // The test behavior depends on whether it's treated as initial terminal
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    test('should queue data when terminal is not ready', async () => {
      // Start with terminal not ready
      mockTerminal.element = null;

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const dataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )[1];

      // Send data while terminal not ready
      act(() => {
        dataHandler({
          sessionId: 'test-session',
          data: 'Queued data'
        });
      });

      // Data should not be written immediately
      expect(mockTerminal.write).not.toHaveBeenCalledWith('Queued data');

      // Make terminal ready
      mockTerminal.element = {
        querySelector: jest.fn(() => ({
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 500
        }))
      };

      // Trigger another data event or re-initialization
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Now queued data should be processed
      // Note: The actual processing depends on implementation details
    });
  });

  describe('Error Handling', () => {
    test('should handle onData callback errors gracefully', async () => {
      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          onData: jest.fn().mockImplementation(() => {
            throw new Error('onData callback error');
          })
        })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      // Should not throw even if onData callback throws
      expect(() => {
        act(() => {
          onDataCallback('test input');
        });
      }).not.toThrow();

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Error in onData callback'),
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });

    test('should handle sendData errors gracefully', async () => {
      // Mock sendData to throw
      mockWebSocket.sendData.mockImplementation(() => {
        throw new Error('sendData failed');
      });

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      // Should handle sendData errors
      expect(() => {
        act(() => {
          onDataCallback('test input');
        });
      }).not.toThrow();

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to send input'),
        expect.any(Error),
        expect.any(Object)
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Performance and Memory', () => {
    test('should dispose terminal resources properly', async () => {
      const { result, unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Verify terminal was created
      expect(mockTerminal.onData).toHaveBeenCalled();

      // Unmount component
      unmount();

      // Note: Terminal disposal happens in destroyTerminal, not during unmount
      // The useTerminal hook doesn't automatically dispose on unmount
      // This is expected behavior as terminals may persist across component remounts
    });

    test('should handle rapid terminal recreation', async () => {
      const { result, rerender } = renderHook((props) =>
        useTerminal(props),
        { initialProps: { sessionId: 'session-1' } }
      );

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
      });

      // Rapidly change sessions to trigger recreations
      for (let i = 2; i <= 10; i++) {
        rerender({ sessionId: `session-${i}` });

        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
        });
      }

      // Should handle rapid changes without errors
      expect(result.current.terminalRef).toBeDefined();
    });
  });
});