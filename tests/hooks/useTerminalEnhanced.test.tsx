import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { Terminal } from '@xterm/xterm';

// Mock dependencies
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(),
}));

jest.mock('@xterm/addon-serialize', () => ({
  SerializeAddon: jest.fn(),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    isConnected: true,
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({}),
}));

describe('useTerminal', () => {
  let mockTerminal: any;
  let mockSendData: jest.Mock;
  let mockResizeTerminal: jest.Mock;
  let mockOn: jest.Mock;
  let mockOff: jest.Mock;
  let mockContainer: HTMLDivElement;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock terminal instance
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      dispose: jest.fn(),
      resize: jest.fn(),
      onData: jest.fn(),
      loadAddon: jest.fn(),
      cols: 120,
      rows: 40,
      element: {
        querySelector: jest.fn(() => ({
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          scrollTop: 0,
          scrollHeight: 100,
          clientHeight: 50,
        })),
      },
    };

    (Terminal as jest.Mock).mockImplementation(() => mockTerminal);

    // Mock WebSocket functions
    mockSendData = jest.fn();
    mockResizeTerminal = jest.fn();
    mockOn = jest.fn();
    mockOff = jest.fn();

    jest.doMock('@/hooks/useWebSocket', () => ({
      useWebSocket: () => ({
        sendData: mockSendData,
        resizeTerminal: mockResizeTerminal,
        on: mockOn,
        off: mockOff,
        isConnected: true,
      }),
    }));

    // Mock DOM container
    mockContainer = document.createElement('div');
    Object.defineProperty(document, 'createElement', {
      value: jest.fn(() => mockContainer),
    });

    // Mock requestAnimationFrame
    global.requestAnimationFrame = jest.fn((cb) => {
      setTimeout(cb, 0);
      return 1;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('initialization', () => {
    it('should initialize with correct default configuration', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(result.current.terminal).toBeNull(); // Initially null
      expect(result.current.isConnected).toBe(true);
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });

    it('should create terminal with custom configuration', async () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Custom Font',
      };

      renderHook(() =>
        useTerminal({ 
          sessionId: 'test-session',
          config: customConfig 
        })
      );

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(
          expect.objectContaining({
            fontSize: 16,
            fontFamily: 'Custom Font',
          })
        );
      });
    });

    it('should handle backend terminal configuration', async () => {
      let configHandler: ((data: any) => void) | undefined;

      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'terminal-config') {
          configHandler = handler;
        }
      });

      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Simulate backend config
      act(() => {
        configHandler?.({
          sessionId: 'test-session',
          cols: 100,
          rows: 30,
        });
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(
          expect.objectContaining({
            cols: 100,
            rows: 30,
          })
        );
      });
    });
  });

  describe('terminal operations', () => {
    let hook: any;

    beforeEach(async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );
      hook = result;

      // Wait for initialization
      await waitFor(() => {
        expect(mockTerminal.open).toHaveBeenCalled();
      });
    });

    it('should write data to terminal', () => {
      act(() => {
        hook.current.writeToTerminal('test data');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('test data');
    });

    it('should clear terminal', () => {
      act(() => {
        hook.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', () => {
      act(() => {
        hook.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('should scroll to bottom', () => {
      const mockViewport = {
        scrollTop: 0,
        scrollHeight: 100,
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      act(() => {
        hook.current.scrollToBottom();
      });

      // Should use requestAnimationFrame
      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should scroll to top', () => {
      const mockViewport = {
        scrollTop: 50,
        scrollHeight: 100,
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      act(() => {
        hook.current.scrollToTop();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });
  });

  describe('WebSocket event handling', () => {
    let terminalDataHandler: ((data: any) => void) | undefined;
    let terminalErrorHandler: ((data: any) => void) | undefined;
    let connectionHandler: ((connected: boolean) => void) | undefined;

    beforeEach(() => {
      mockOn.mockImplementation((event: string, handler: any) => {
        switch (event) {
          case 'terminal-data':
            terminalDataHandler = handler;
            break;
          case 'terminal-error':
            terminalErrorHandler = handler;
            break;
          case 'connection-change':
            connectionHandler = handler;
            break;
        }
      });
    });

    it('should handle terminal data events', async () => {
      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(mockOn).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      const testData = {
        sessionId: 'test-session',
        data: 'terminal output',
      };

      act(() => {
        terminalDataHandler?.(testData);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('terminal output');
    });

    it('should handle terminal error events', async () => {
      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      const errorData = {
        sessionId: 'test-session',
        error: 'Connection failed',
      };

      act(() => {
        terminalErrorHandler?.(errorData);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Connection failed')
      );
    });

    it('should handle connection change events', async () => {
      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        connectionHandler?.(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Disconnected')
      );

      act(() => {
        connectionHandler?.(true);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Connected')
      );
    });

    it('should ignore events for wrong session', async () => {
      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      const wrongSessionData = {
        sessionId: 'wrong-session',
        data: 'should not appear',
      };

      const writeCallCount = mockTerminal.write.mock.calls.length;

      act(() => {
        terminalDataHandler?.(wrongSessionData);
      });

      expect(mockTerminal.write).toHaveBeenCalledTimes(writeCallCount);
    });
  });

  describe('scroll position tracking', () => {
    let hook: any;

    beforeEach(async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );
      hook = result;

      await waitFor(() => {
        expect(mockTerminal.open).toHaveBeenCalled();
      });
    });

    it('should track scroll position', () => {
      expect(hook.current.isAtBottom).toBe(true);
      expect(hook.current.hasNewOutput).toBe(false);
    });

    it('should update scroll position when new output arrives', async () => {
      // Mock viewport at middle position
      const mockViewport = {
        scrollTop: 25,
        scrollHeight: 100,
        clientHeight: 50,
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      let terminalDataHandler: ((data: any) => void) | undefined;

      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'terminal-data') {
          terminalDataHandler = handler;
        }
      });

      const testData = {
        sessionId: 'test-session',
        data: 'new output',
      };

      act(() => {
        terminalDataHandler?.(testData);
      });

      // Should preserve scroll position and set new output indicator
      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });
  });

  describe('terminal input handling', () => {
    it('should handle terminal input and send to WebSocket', async () => {
      const onData = jest.fn();
      
      renderHook(() =>
        useTerminal({ 
          sessionId: 'test-session',
          onData 
        })
      );

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const dataHandler = mockTerminal.onData.mock.calls[0][0];

      act(() => {
        dataHandler('user input');
      });

      expect(mockSendData).toHaveBeenCalledWith('test-session', 'user input');
      expect(onData).toHaveBeenCalledWith('user input');
    });
  });

  describe('cleanup', () => {
    it('should cleanup terminal on unmount', async () => {
      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(mockTerminal.open).toHaveBeenCalled();
      });

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
      expect(mockOff).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('terminal-config', expect.any(Function));
    });

    it('should cleanup scroll listeners', async () => {
      const mockViewport = {
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      };

      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(mockViewport.addEventListener).toHaveBeenCalledWith('scroll', expect.any(Function));
      });

      unmount();

      expect(mockViewport.removeEventListener).toHaveBeenCalledWith('scroll', expect.any(Function));
    });
  });

  describe('performance optimizations', () => {
    it('should handle rapid data updates without performance issues', async () => {
      let terminalDataHandler: ((data: any) => void) | undefined;

      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'terminal-data') {
          terminalDataHandler = handler;
        }
      });

      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Send 100 rapid updates
      for (let i = 0; i < 100; i++) {
        act(() => {
          terminalDataHandler?.({
            sessionId: 'test-session',
            data: `update ${i}`,
          });
        });
      }

      expect(mockTerminal.write).toHaveBeenCalledTimes(100);
    });

    it('should use fixed terminal dimensions for performance', async () => {
      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(
          expect.objectContaining({
            scrollback: 10000,
            smoothScrollDuration: 0,
            allowTransparency: false,
            screenReaderMode: false,
          })
        );
      });
    });
  });

  describe('error handling', () => {
    it('should handle terminal creation failure gracefully', () => {
      (Terminal as jest.Mock).mockImplementation(() => {
        throw new Error('Terminal creation failed');
      });

      expect(() => {
        renderHook(() =>
          useTerminal({ sessionId: 'test-session' })
        );
      }).not.toThrow();
    });

    it('should handle missing container element', () => {
      mockContainer = null as any;

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Should not create terminal without container
      expect(result.current.terminal).toBeNull();
    });

    it('should handle WebSocket errors gracefully', async () => {
      mockSendData.mockImplementation(() => {
        throw new Error('WebSocket error');
      });

      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const dataHandler = mockTerminal.onData.mock.calls[0][0];

      expect(() => {
        act(() => {
          dataHandler('user input');
        });
      }).not.toThrow();
    });
  });

  describe('accessibility', () => {
    it('should configure terminal for accessibility', async () => {
      renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(
          expect.objectContaining({
            cursorBlink: true,
            minimumContrastRatio: 1,
            drawBoldTextInBrightColors: true,
            convertEol: true,
          })
        );
      });
    });

    it('should provide proper focus management', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(mockTerminal.focus).toHaveBeenCalled();
      });

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalledTimes(2);
    });
  });
});