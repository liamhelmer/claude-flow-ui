import { renderHook, act } from '@testing-library/react';
import { useTerminal } from '../useTerminal';
import { useWebSocket } from '../useWebSocket';
import { Terminal } from '@xterm/xterm';

// Mock dependencies
jest.mock('../useWebSocket');
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');
jest.mock('@/lib/state/store');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const MockTerminal = Terminal as jest.MockedClass<typeof Terminal>;

// Create a more realistic terminal mock
const createMockTerminal = () => {
  const mockTerminal = {
    cols: 80,
    rows: 24,
    element: null as HTMLElement | null,
    open: jest.fn(),
    write: jest.fn(),
    clear: jest.fn(),
    focus: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(),
    loadAddon: jest.fn(),
  };
  
  // Create a mock terminal element with viewport
  const mockElement = document.createElement('div');
  const mockViewport = document.createElement('div');
  mockViewport.className = 'xterm-viewport';
  mockElement.appendChild(mockViewport);
  
  // Mock element property with proper structure
  Object.defineProperty(mockTerminal, 'element', {
    get: () => mockElement,
    configurable: true,
  });
  
  return mockTerminal;
};

describe('useTerminal Scroll Error Handling', () => {
  const defaultOptions = {
    sessionId: 'test-session',
    config: {},
  };
  
  const mockWebSocketReturn = {
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    isConnected: true,
  };
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    mockUseWebSocket.mockReturnValue(mockWebSocketReturn as any);
    
    // Reset DOM
    document.body.innerHTML = '';
    
    // Mock RAF for scroll animations
    global.requestAnimationFrame = jest.fn((cb) => {
      cb(0);
      return 0;
    });
  });
  
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Scroll Position Error Handling', () => {
    it('should handle missing viewport element gracefully', () => {
      const mockTerminal = createMockTerminal();
      
      // Remove viewport from element
      if (mockTerminal.element) {
        mockTerminal.element.innerHTML = '';
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Create container element
      const container = document.createElement('div');
      document.body.appendChild(container);
      
      act(() => {
        if (result.current.terminalRef.current) {
          result.current.terminalRef.current = container;
        }
      });
      
      // Trigger scroll methods - should not throw
      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle null terminal element gracefully', () => {
      const mockTerminal = createMockTerminal();
      
      // Set element to null
      Object.defineProperty(mockTerminal, 'element', {
        get: () => null,
        configurable: true,
      });
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle corrupted viewport properties', () => {
      const mockTerminal = createMockTerminal();
      
      // Create viewport with corrupted properties
      const corruptedViewport = document.createElement('div');
      corruptedViewport.className = 'xterm-viewport';
      
      // Break scrollHeight property
      Object.defineProperty(corruptedViewport, 'scrollHeight', {
        get: () => { throw new Error('Corrupted scrollHeight'); },
        configurable: true,
      });
      
      if (mockTerminal.element) {
        mockTerminal.element.innerHTML = '';
        mockTerminal.element.appendChild(corruptedViewport);
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Should handle corrupted properties gracefully
      expect(() => {
        result.current.scrollToBottom();
      }).not.toThrow();
    });
  });

  describe('Scroll Event Listener Error Handling', () => {
    it('should handle addEventListener failure gracefully', () => {
      const mockTerminal = createMockTerminal();
      
      // Mock addEventListener to throw
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        mockViewport.addEventListener = jest.fn(() => {
          throw new Error('addEventListener failed');
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Should not throw when addEventListener fails
      expect(() => {
        // This would trigger the addEventListener in useEffect
        const container = document.createElement('div');
        result.current.terminalRef.current = container;
      }).not.toThrow();
    });

    it('should handle removeEventListener failure gracefully', () => {
      const mockTerminal = createMockTerminal();
      
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        mockViewport.removeEventListener = jest.fn(() => {
          throw new Error('removeEventListener failed');
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result, unmount } = renderHook(() => useTerminal(defaultOptions));
      
      // Create container to initialize terminal
      const container = document.createElement('div');
      result.current.terminalRef.current = container;
      
      // Should not throw when cleanup fails
      expect(() => {
        unmount();
      }).not.toThrow();
    });

    it('should handle scroll event with missing properties', () => {
      const mockTerminal = createMockTerminal();
      let scrollHandler: (() => void) | null = null;
      
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        mockViewport.addEventListener = jest.fn((event, handler) => {
          if (event === 'scroll') {
            scrollHandler = handler as () => void;
          }
        });
        
        // Remove scroll properties
        Object.defineProperty(mockViewport, 'scrollTop', {
          get: () => undefined,
          configurable: true,
        });
        Object.defineProperty(mockViewport, 'scrollHeight', {
          get: () => undefined,
          configurable: true,
        });
        Object.defineProperty(mockViewport, 'clientHeight', {
          get: () => undefined,
          configurable: true,
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      renderHook(() => useTerminal(defaultOptions));
      
      // Should handle missing scroll properties gracefully
      expect(() => {
        if (scrollHandler) {
          scrollHandler();
        }
      }).not.toThrow();
    });
  });

  describe('Scroll Animation Error Handling', () => {
    it('should handle requestAnimationFrame failure', () => {
      global.requestAnimationFrame = jest.fn(() => {
        throw new Error('RAF failed');
      });
      
      const mockTerminal = createMockTerminal();
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Should handle RAF failure gracefully
      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle scroll position corruption during animation', () => {
      const mockTerminal = createMockTerminal();
      
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        let scrollSetCount = 0;
        Object.defineProperty(mockViewport, 'scrollTop', {
          get: () => 0,
          set: () => {
            scrollSetCount++;
            if (scrollSetCount > 1) {
              throw new Error('Scroll position corrupted');
            }
          },
          configurable: true,
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // First scroll should work, second should handle error
      result.current.scrollToBottom();
      
      expect(() => {
        result.current.scrollToBottom();
      }).not.toThrow();
    });
  });

  describe('Auto-scroll Error Handling', () => {
    it('should handle terminal data with corrupted viewport', () => {
      const mockTerminal = createMockTerminal();
      let terminalDataHandler: ((data: any) => void) | null = null;
      
      mockWebSocketReturn.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          terminalDataHandler = handler;
        }
      });
      
      // Corrupt viewport after creation
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        Object.defineProperty(mockViewport, 'scrollTop', {
          get: () => { throw new Error('Corrupted scrollTop'); },
          set: () => { throw new Error('Cannot set scrollTop'); },
          configurable: true,
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      renderHook(() => useTerminal(defaultOptions));
      
      // Should handle corrupted viewport during auto-scroll
      expect(() => {
        if (terminalDataHandler) {
          terminalDataHandler({
            sessionId: 'test-session',
            data: 'test output\n',
          });
        }
      }).not.toThrow();
    });

    it('should handle state updates with missing setters', () => {
      const mockTerminal = createMockTerminal();
      let terminalDataHandler: ((data: any) => void) | null = null;
      
      mockWebSocketReturn.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          terminalDataHandler = handler;
        }
      });
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      renderHook(() => useTerminal(defaultOptions));
      
      // Should handle state updates gracefully even with errors
      expect(() => {
        if (terminalDataHandler) {
          terminalDataHandler({
            sessionId: 'test-session',
            data: 'test output\n',
          });
        }
      }).not.toThrow();
    });
  });

  describe('Edge Case Error Recovery', () => {
    it('should recover from scroll position calculation errors', () => {
      const mockTerminal = createMockTerminal();
      
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        let callCount = 0;
        
        // First call throws, subsequent calls work
        Object.defineProperty(mockViewport, 'scrollHeight', {
          get: () => {
            callCount++;
            if (callCount === 1) {
              throw new Error('First call fails');
            }
            return 1000;
          },
          configurable: true,
        });
        
        Object.defineProperty(mockViewport, 'scrollTop', {
          get: () => 0,
          set: jest.fn(),
          configurable: true,
        });
        
        Object.defineProperty(mockViewport, 'clientHeight', {
          get: () => 400,
          configurable: true,
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // First call should handle error gracefully
      expect(() => {
        result.current.scrollToBottom();
      }).not.toThrow();
      
      // Second call should work normally
      expect(() => {
        result.current.scrollToBottom();
      }).not.toThrow();
    });

    it('should handle concurrent scroll operations', async () => {
      const mockTerminal = createMockTerminal();
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Trigger multiple concurrent scroll operations
      const scrollPromises = [
        Promise.resolve(result.current.scrollToBottom()),
        Promise.resolve(result.current.scrollToTop()),
        Promise.resolve(result.current.scrollToBottom()),
        Promise.resolve(result.current.scrollToTop()),
      ];
      
      // Should handle concurrent operations without errors
      await expect(Promise.all(scrollPromises)).resolves.not.toThrow();
    });

    it('should handle memory pressure during scroll operations', () => {
      const mockTerminal = createMockTerminal();
      
      // Simulate memory pressure by making operations slow
      global.requestAnimationFrame = jest.fn((cb) => {
        setTimeout(() => cb(0), 100); // Slow RAF
        return 0;
      });
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Should handle slow operations gracefully
      expect(() => {
        for (let i = 0; i < 100; i++) {
          result.current.scrollToBottom();
        }
      }).not.toThrow();
    });
  });

  describe('DOM Manipulation Error Handling', () => {
    it('should handle querySelector failures', () => {
      const mockTerminal = createMockTerminal();
      
      // Mock querySelector to fail
      if (mockTerminal.element) {
        mockTerminal.element.querySelector = jest.fn(() => {
          throw new Error('querySelector failed');
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle DOM mutations during scroll', () => {
      const mockTerminal = createMockTerminal();
      
      const mockViewport = mockTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (mockViewport) {
        let mutationCount = 0;
        
        Object.defineProperty(mockViewport, 'scrollTop', {
          get: () => 0,
          set: () => {
            mutationCount++;
            if (mutationCount === 2) {
              // Simulate DOM mutation removing the element
              mockViewport.remove();
            }
          },
          configurable: true,
        });
      }
      
      MockTerminal.mockImplementation(() => mockTerminal as any);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Should handle DOM mutations gracefully
      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToBottom(); // This triggers DOM mutation
        result.current.scrollToBottom(); // This should handle missing element
      }).not.toThrow();
    });
  });
});