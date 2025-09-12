import { renderHook, act, waitFor } from '@testing-library/react';
import { Terminal } from '@xterm/xterm';
import { SerializeAddon } from '@xterm/addon-serialize';
import { useTerminal } from '../useTerminal';
import { useWebSocket } from '../useWebSocket';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');
jest.mock('../useWebSocket');
jest.mock('@/lib/state/store');

const MockTerminal = Terminal as jest.MockedClass<typeof Terminal>;
const MockSerializeAddon = SerializeAddon as jest.MockedClass<typeof SerializeAddon>;
const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useTerminal', () => {
  let mockTerminal: jest.Mocked<Terminal>;
  let mockSerializeAddon: jest.Mocked<SerializeAddon>;
  let mockWebSocket: any;
  let mockOnData: jest.Mock;
  let containerElement: HTMLDivElement;

  const defaultProps = {
    sessionId: 'test-session',
    config: {},
  };

  beforeEach(() => {
    // Create mock terminal instance
    mockTerminal = {
      element: null,
      cols: 80,
      rows: 24,
      open: jest.fn(),
      write: jest.fn(),
      onData: jest.fn(),
      dispose: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      loadAddon: jest.fn(),
    } as any;

    MockTerminal.mockImplementation(() => mockTerminal);

    // Create mock serialize addon
    mockSerializeAddon = {} as any;
    MockSerializeAddon.mockImplementation(() => mockSerializeAddon);

    // Create mock websocket
    mockWebSocket = {
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      isConnected: true,
    };

    mockUseWebSocket.mockReturnValue(mockWebSocket);
    mockUseAppStore.mockReturnValue({} as any);

    mockOnData = jest.fn();

    // Create container element
    containerElement = document.createElement('div');
    
    // Mock DOM methods
    Object.defineProperty(mockTerminal, 'element', {
      get: () => ({
        querySelector: jest.fn().mockReturnValue({
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 400,
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
        }),
      }),
      configurable: true,
    });

    // Clear mocks
    jest.clearAllMocks();
    
    // Mock RAF
    global.requestAnimationFrame = jest.fn((cb) => {
      cb(0);
      return 0;
    });
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('initialization without backend config', () => {
    it('should not create terminal without backend config', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      expect(MockTerminal).not.toHaveBeenCalled();
      expect(result.current.terminal).toBeNull();
    });

    it('should wait for backend terminal configuration', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      expect(MockTerminal).not.toHaveBeenCalled();
      
      // Simulate receiving backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();
      
      // Now terminal should be created
      expect(MockTerminal).toHaveBeenCalled();
    });
  });

  describe('terminal initialization with backend config', () => {
    beforeEach(() => {
      // Simulate backend config being available
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();
    });

    it('should create terminal with backend dimensions', () => {
      expect(MockTerminal).toHaveBeenCalledWith(
        expect.objectContaining({
          cols: 80,
          rows: 24,
          theme: expect.any(Object),
          fontSize: 14,
          fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        })
      );
    });

    it('should load serialize addon', () => {
      expect(MockSerializeAddon).toHaveBeenCalled();
      expect(mockTerminal.loadAddon).toHaveBeenCalledWith(mockSerializeAddon);
    });

    it('should open terminal in container', () => {
      const { result } = renderHook(() => useTerminal({
        ...defaultProps,
        onData: mockOnData,
      }));

      // Set container ref
      act(() => {
        (result.current.terminalRef as any).current = containerElement;
      });

      expect(mockTerminal.open).toHaveBeenCalled();
    });

    it('should set up data handler', () => {
      expect(mockTerminal.onData).toHaveBeenCalledWith(expect.any(Function));
    });
  });

  describe('terminal data handling', () => {
    let dataHandler: (data: string) => void;

    beforeEach(() => {
      renderHook(() => useTerminal({
        ...defaultProps,
        onData: mockOnData,
      }));

      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      dataHandler = mockTerminal.onData.mock.calls[0][0];
    });

    it('should send data to websocket on terminal input', () => {
      const testData = 'ls -la\r';
      
      act(() => {
        dataHandler(testData);
      });

      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', testData);
    });

    it('should call onData callback', () => {
      const testData = 'test input';
      
      act(() => {
        dataHandler(testData);
      });

      expect(mockOnData).toHaveBeenCalledWith(testData);
    });

    it('should handle special key combinations', () => {
      const specialKeys = ['\r', '\n', '\x03', '\x04', '\x1b[A', '\x1b[B'];
      
      specialKeys.forEach(key => {
        act(() => {
          dataHandler(key);
        });
        
        expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', key);
      });
    });
  });

  describe('incoming terminal data handling', () => {
    let handleTerminalData: (data: any) => void;

    beforeEach(() => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      handleTerminalData = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-data'
      )?.[1];
    });

    it('should write incoming data to terminal', () => {
      const testData = { sessionId: 'test-session', data: 'Hello World' };
      
      act(() => {
        handleTerminalData(testData);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Hello World');
    });

    it('should ignore data for different session', () => {
      const testData = { sessionId: 'different-session', data: 'Hello World' };
      
      act(() => {
        handleTerminalData(testData);
      });

      expect(mockTerminal.write).not.toHaveBeenCalled();
    });

    it('should handle ANSI escape sequences', () => {
      const ansiData = { 
        sessionId: 'test-session', 
        data: '\x1b[31mRed Text\x1b[0m' 
      };
      
      act(() => {
        handleTerminalData(ansiData);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[31mRed Text\x1b[0m');
    });

    it('should handle binary data', () => {
      const binaryData = { 
        sessionId: 'test-session', 
        data: '\x00\x01\x02\x03' 
      };
      
      act(() => {
        handleTerminalData(binaryData);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x00\x01\x02\x03');
    });
  });

  describe('scroll management', () => {
    let viewport: any;

    beforeEach(() => {
      viewport = {
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 400,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      };

      Object.defineProperty(mockTerminal, 'element', {
        get: () => ({ querySelector: jest.fn().mockReturnValue(viewport) }),
        configurable: true,
      });
    });

    it('should detect when user is at bottom', async () => {
      const { result, rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      expect(result.current.isAtBottom).toBe(true);
    });

    it('should auto-scroll when at bottom', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      const handleTerminalData = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-data'
      )?.[1];

      viewport.scrollTop = 600; // At bottom
      
      act(() => {
        handleTerminalData({ sessionId: 'test-session', data: 'new output' });
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should preserve scroll position when not at bottom', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      const handleTerminalData = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-data'
      )?.[1];

      viewport.scrollTop = 100; // Not at bottom
      const originalScrollTop = viewport.scrollTop;
      
      act(() => {
        handleTerminalData({ sessionId: 'test-session', data: 'new output' });
      });

      expect(global.requestAnimationFrame).toHaveBeenCalledWith(expect.any(Function));
    });

    it('should show new output indicator when not at bottom', () => {
      const { result, rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config  
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      const handleTerminalData = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-data'
      )?.[1];

      viewport.scrollTop = 100; // Not at bottom
      
      act(() => {
        handleTerminalData({ sessionId: 'test-session', data: 'important output' });
      });

      expect(result.current.hasNewOutput).toBe(true);
    });
  });

  describe('terminal control methods', () => {
    beforeEach(() => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();
    });

    it('should write data to terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      act(() => {
        result.current.writeToTerminal('Hello World');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Hello World');
    });

    it('should clear terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('should handle scroll to bottom', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      const viewport = {
        scrollTop: 0,
        scrollHeight: 1000,
      };
      
      Object.defineProperty(mockTerminal, 'element', {
        get: () => ({ querySelector: jest.fn().mockReturnValue(viewport) }),
        configurable: true,
      });

      act(() => {
        result.current.scrollToBottom();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should handle scroll to top', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      const viewport = {
        scrollTop: 500,
        scrollHeight: 1000,
      };
      
      Object.defineProperty(mockTerminal, 'element', {
        get: () => ({ querySelector: jest.fn().mockReturnValue(viewport) }),
        configurable: true,
      });

      act(() => {
        result.current.scrollToTop();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });
  });

  describe('terminal lifecycle', () => {
    it('should destroy terminal on unmount', () => {
      const { unmount, rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
    });

    it('should recreate terminal when dimensions change', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Initial setup
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      expect(MockTerminal).toHaveBeenCalledTimes(1);

      // Change dimensions
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 100, 
          rows: 30 
        });
      });

      rerender();

      expect(mockTerminal.dispose).toHaveBeenCalled();
      expect(MockTerminal).toHaveBeenCalledTimes(2);
    });

    it('should not recreate terminal if dimensions are same', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      expect(MockTerminal).toHaveBeenCalledTimes(1);

      // Send same dimensions
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      expect(mockTerminal.dispose).not.toHaveBeenCalled();
      expect(MockTerminal).toHaveBeenCalledTimes(1);
    });
  });

  describe('error handling', () => {
    it('should handle terminal error messages', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      const handleTerminalError = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-error'
      )?.[1];

      act(() => {
        handleTerminalError({ sessionId: 'test-session', error: 'Command not found' });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[31mCommand not found\x1b[0m\r\n');
    });

    it('should handle connection state changes', () => {
      const { rerender } = renderHook(() => useTerminal(defaultProps));
      
      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      const handleConnectionChange = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'connection-change'
      )?.[1];

      act(() => {
        handleConnectionChange(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\r\n\x1b[90m[\x1b[31mDisconnected\x1b[90m]\x1b[0m\r\n');
    });

    it('should handle methods being called without terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultProps));
      
      expect(() => {
        act(() => {
          result.current.writeToTerminal('test');
          result.current.clearTerminal();
          result.current.focusTerminal();
          result.current.scrollToBottom();
          result.current.scrollToTop();
        });
      }).not.toThrow();
    });
  });

  describe('cleanup', () => {
    it('should clean up event listeners on unmount', () => {
      const { unmount } = renderHook(() => useTerminal(defaultProps));
      
      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-config', expect.any(Function));
    });

    it('should clean up scroll listeners', () => {
      const { unmount, rerender } = renderHook(() => useTerminal(defaultProps));
      
      const removeEventListenerSpy = jest.fn();
      const viewport = {
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 400,
        addEventListener: jest.fn(),
        removeEventListener: removeEventListenerSpy,
      };

      Object.defineProperty(mockTerminal, 'element', {
        get: () => ({ querySelector: jest.fn().mockReturnValue(viewport) }),
        configurable: true,
      });

      // Setup backend config
      const handleTerminalConfig = mockWebSocket.on.mock.calls.find(
        (call: any[]) => call[0] === 'terminal-config'
      )?.[1];
      
      act(() => {
        handleTerminalConfig?.({ 
          sessionId: 'test-session', 
          cols: 80, 
          rows: 24 
        });
      });

      rerender();

      // Add scroll cleanup to terminal
      (mockTerminal as any).scrollCleanup = jest.fn();

      unmount();

      expect((mockTerminal as any).scrollCleanup).toHaveBeenCalled();
    });
  });
});