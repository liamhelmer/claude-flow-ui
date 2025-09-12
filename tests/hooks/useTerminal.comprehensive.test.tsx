import { renderHook, act } from '@testing-library/react';
import { waitFor } from '@testing-library/dom';
import { useTerminal } from '@/hooks/useTerminal';
import { Terminal } from '@xterm/xterm';
import { SerializeAddon } from '@xterm/addon-serialize';
import { WebLinksAddon } from '@xterm/addon-web-links';

// Mock the xterm.js Terminal and addons
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');
jest.mock('@xterm/addon-web-links');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store');

const MockedTerminal = Terminal as jest.MockedClass<typeof Terminal>;
const MockedSerializeAddon = SerializeAddon as jest.MockedClass<typeof SerializeAddon>;
const MockedWebLinksAddon = WebLinksAddon as jest.MockedClass<typeof WebLinksAddon>;

// Mock DOM elements
const createMockElement = () => ({
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  scrollTop: 0,
  scrollHeight: 1000,
  clientHeight: 500,
  querySelector: jest.fn(() => ({
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    scrollTop: 0,
    scrollHeight: 1000,
    clientHeight: 500,
  })),
});

describe('useTerminal - Comprehensive Tests', () => {
  let mockTerminal: jest.Mocked<Terminal>;
  let mockSerializeAddon: jest.Mocked<SerializeAddon>;
  let mockWebLinksAddon: jest.Mocked<WebLinksAddon>;
  let mockSendData: jest.Mock;
  let mockResizeTerminal: jest.Mock;
  let mockOn: jest.Mock;
  let mockOff: jest.Mock;
  let mockViewport: any;

  beforeEach(() => {
    // Create mock viewport
    mockViewport = createMockElement();
    
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      dispose: jest.fn(),
      onData: jest.fn(),
      onResize: jest.fn(),
      loadAddon: jest.fn(),
      cols: 80,
      rows: 24,
      buffer: {
        active: {
          cursorX: 0,
          cursorY: 0,
        },
      },
      element: {
        querySelector: jest.fn(() => mockViewport),
      },
    } as any;

    mockSerializeAddon = {} as any;
    mockWebLinksAddon = {} as any;

    mockSendData = jest.fn();
    mockResizeTerminal = jest.fn();
    mockOn = jest.fn();
    mockOff = jest.fn();

    MockedTerminal.mockImplementation(() => mockTerminal);
    MockedSerializeAddon.mockImplementation(() => mockSerializeAddon);
    MockedWebLinksAddon.mockImplementation(() => mockWebLinksAddon);

    // Mock useWebSocket
    const useWebSocket = require('@/hooks/useWebSocket').useWebSocket;
    useWebSocket.mockReturnValue({
      sendData: mockSendData,
      resizeTerminal: mockResizeTerminal,
      on: mockOn,
      off: mockOff,
      isConnected: true,
    });

    // Mock container ref
    const mockContainer = document.createElement('div');
    jest.spyOn(document, 'createElement').mockReturnValue(mockContainer);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();
  });

  describe('Terminal Configuration and Initialization', () => {
    it('waits for backend terminal config before creating terminal', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Should not create terminal without backend config
      expect(MockedTerminal).not.toHaveBeenCalled();
      expect(result.current.backendTerminalConfig).toBeNull();
    });

    it('creates terminal when backend config is available', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Simulate receiving backend config
      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(result.current.backendTerminalConfig).toEqual({ cols: 80, rows: 24 });
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });
    });

    it('applies backend dimensions to terminal config', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 100, rows: 30 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalledWith(
          expect.objectContaining({
            cols: 100,
            rows: 30,
          })
        );
      });
    });

    it('recreates terminal when dimensions change', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Initial config
      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalledTimes(1);
      });

      // Change dimensions
      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 100, rows: 30 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.dispose).toHaveBeenCalled();
        expect(MockedTerminal).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('Advanced Terminal Configuration', () => {
    it('configures terminal with comprehensive options', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalledWith(
          expect.objectContaining({
            scrollback: 10000,
            scrollOnUserInput: true,
            smoothScrollDuration: 0,
            convertEol: true,
            allowTransparency: false,
            windowsMode: false,
            disableStdin: false,
            allowProposedApi: true,
            macOptionIsMeta: true,
            cursorStyle: 'block',
            cursorBlink: true,
            drawBoldTextInBrightColors: true,
            screenKeys: true,
          })
        );
      });
    });

    it('loads required addons', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedSerializeAddon).toHaveBeenCalled();
        expect(MockedWebLinksAddon).toHaveBeenCalled();
        expect(mockTerminal.loadAddon).toHaveBeenCalledWith(mockSerializeAddon);
        expect(mockTerminal.loadAddon).toHaveBeenCalledWith(mockWebLinksAddon);
      });
    });

    it('applies custom config when provided', async () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Fira Code',
        cursorBlink: false,
      };

      renderHook(() =>
        useTerminal({ sessionId: 'test-session', config: customConfig })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalledWith(
          expect.objectContaining({
            fontSize: 16,
            fontFamily: 'Fira Code',
            cursorBlink: false,
          })
        );
      });
    });
  });

  describe('Data Handling and Echo Management', () => {
    it('sends data to WebSocket when terminal receives input', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      
      act(() => {
        onDataCallback('user input');
      });

      expect(mockSendData).toHaveBeenCalledWith('test-session', 'user input');
    });

    it('calls custom onData callback when provided', async () => {
      const mockOnData = jest.fn();
      
      renderHook(() =>
        useTerminal({ sessionId: 'test-session', onData: mockOnData })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      
      act(() => {
        onDataCallback('test input');
      });

      expect(mockOnData).toHaveBeenCalledWith('test input');
    });

    it('handles cursor position requests', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      
      act(() => {
        onDataCallback('\x1b[6n'); // Cursor position request
      });

      expect(mockSendData).toHaveBeenCalledWith('test-session', '\x1b[6n');
    });

    it('tracks cursor position from terminal data', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockOn).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      const dataHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      
      act(() => {
        dataHandler({
          sessionId: 'test-session',
          data: '\x1b[5;10R', // Cursor position report
          metadata: { hasCursorReport: true },
        });
      });

      // Should process cursor position update
      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[5;10R');
    });
  });

  describe('Scroll Management', () => {
    it('provides scroll management functions', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(typeof result.current.scrollToBottom).toBe('function');
      expect(typeof result.current.scrollToTop).toBe('function');
      expect(typeof result.current.isAtBottom).toBe('boolean');
      expect(typeof result.current.hasNewOutput).toBe('boolean');
    });

    it('tracks scroll position correctly', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Initial state should be at bottom
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });

    it('handles auto-scroll when at bottom', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockOn).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      const dataHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      
      // Simulate data when at bottom
      act(() => {
        dataHandler({
          sessionId: 'test-session',
          data: 'new output\n',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('new output\n');
    });

    it('preserves scroll position when not at bottom', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.element.querySelector).toHaveBeenCalled();
      });

      // Set up scroll position tracking
      jest.useFakeTimers();
      
      act(() => {
        jest.advanceTimersByTime(100); // Trigger scroll listener setup
      });

      expect(mockViewport.addEventListener).toHaveBeenCalledWith('scroll', expect.any(Function));
      
      jest.useRealTimers();
    });
  });

  describe('Terminal Operations', () => {
    it('writes data to terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      act(() => {
        result.current.writeToTerminal('test output');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('test output');
    });

    it('clears terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('focuses terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('handles operations on uninitialized terminal gracefully', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Operations should not throw when terminal is not initialized
      expect(() => {
        result.current.writeToTerminal('test');
        result.current.clearTerminal();
        result.current.focusTerminal();
        result.current.fitTerminal();
      }).not.toThrow();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('handles terminal creation errors gracefully', () => {
      MockedTerminal.mockImplementation(() => {
        throw new Error('Terminal creation failed');
      });

      expect(() => {
        renderHook(() => useTerminal({ sessionId: 'test-session' }));
      }).not.toThrow();
    });

    it('handles write errors gracefully', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      mockTerminal.write.mockImplementation(() => {
        throw new Error('Write failed');
      });

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      // Should not throw
      expect(() => {
        result.current.writeToTerminal('test');
      }).not.toThrow();
    });

    it('handles terminal data for wrong session gracefully', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockOn).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      });

      const dataHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      
      // Send data for different session
      act(() => {
        dataHandler({
          sessionId: 'other-session',
          data: 'wrong session data',
        });
      });

      // Should not write to terminal
      expect(mockTerminal.write).not.toHaveBeenCalledWith('wrong session data');
    });
  });

  describe('Cleanup and Memory Management', () => {
    it('cleans up terminal on unmount', async () => {
      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
      expect(mockOff).toHaveBeenCalledTimes(4); // For each event type
    });

    it('cleans up scroll listeners', async () => {
      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.element.querySelector).toHaveBeenCalled();
      });

      jest.useFakeTimers();
      act(() => {
        jest.advanceTimersByTime(100);
      });
      jest.useRealTimers();

      unmount();

      expect(mockViewport.removeEventListener).toHaveBeenCalledWith('scroll', expect.any(Function));
    });

    it('prevents memory leaks on rapid re-initialization', async () => {
      const { rerender } = renderHook(
        ({ sessionId }) => useTerminal({ sessionId }),
        { initialProps: { sessionId: 'session-1' } }
      );

      // Initialize first terminal
      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'session-1', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      // Change session rapidly
      rerender({ sessionId: 'session-2' });
      rerender({ sessionId: 'session-3' });

      // Should clean up previous terminals
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });
});