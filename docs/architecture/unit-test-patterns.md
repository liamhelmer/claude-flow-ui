# Unit Test Architecture Patterns

## Modular Unit Testing Design Principles

### Architecture Overview
This document defines modular unit testing patterns for the Claude Flow UI terminal/websocket application, ensuring each test file remains under 500 lines while maintaining comprehensive coverage.

### Core Design Principles

1. **Single Responsibility**: Each test file focuses on one component/module
2. **Isolation**: Complete independence from external services
3. **Predictability**: Deterministic test outcomes
4. **Performance**: Fast execution (<500ms per test file)
5. **Maintainability**: Clear, readable test structure

## Component Testing Patterns

### Terminal Component Testing Pattern

```typescript
// tests/unit/components/terminal/Terminal.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Terminal } from '@/components/Terminal';
import { mockWebSocket, mockTerminalSession } from '@tests/mocks';

describe('Terminal Component', () => {
  // Setup and teardown patterns
  beforeEach(() => {
    mockWebSocket.clear();
    mockTerminalSession.reset();
  });

  describe('Component Initialization', () => {
    it('should render terminal container with default size', () => {
      render(<Terminal />);
      const terminal = screen.getByRole('main', { name: /terminal/i });
      expect(terminal).toHaveClass('terminal-container');
    });

    it('should initialize xterm with correct configuration', () => {
      render(<Terminal />);
      expect(mockTerminalSession.init).toHaveBeenCalledWith({
        cols: 80,
        rows: 24,
        theme: expect.objectContaining({
          background: '#1e1e1e',
          foreground: '#d4d4d4'
        })
      });
    });
  });

  describe('WebSocket Integration', () => {
    it('should establish websocket connection on mount', async () => {
      render(<Terminal />);
      await waitFor(() => {
        expect(mockWebSocket.connect).toHaveBeenCalledWith(
          expect.stringContaining('/terminal')
        );
      });
    });

    it('should handle websocket message reception', async () => {
      render(<Terminal />);

      mockWebSocket.emit('message', {
        type: 'output',
        data: 'Hello Terminal!'
      });

      await waitFor(() => {
        expect(mockTerminalSession.write).toHaveBeenCalledWith('Hello Terminal!');
      });
    });
  });

  describe('User Interactions', () => {
    it('should send input through websocket on key press', async () => {
      render(<Terminal />);
      const terminalElement = screen.getByRole('main');

      fireEvent.keyDown(terminalElement, {
        key: 'Enter',
        code: 'Enter'
      });

      expect(mockWebSocket.send).toHaveBeenCalledWith({
        type: 'input',
        data: '\r'
      });
    });
  });

  describe('Error Handling', () => {
    it('should display error state on websocket failure', async () => {
      render(<Terminal />);

      mockWebSocket.emit('error', new Error('Connection failed'));

      await waitFor(() => {
        expect(screen.getByText(/connection error/i)).toBeInTheDocument();
      });
    });
  });
});
```

### Hook Testing Pattern

```typescript
// tests/unit/hooks/useTerminal.test.tsx
import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { mockWebSocket } from '@tests/mocks';

describe('useTerminal Hook', () => {
  beforeEach(() => {
    mockWebSocket.clear();
  });

  describe('Hook Initialization', () => {
    it('should initialize with default state', () => {
      const { result } = renderHook(() => useTerminal());

      expect(result.current.isConnected).toBe(false);
      expect(result.current.terminalRef.current).toBeNull();
      expect(result.current.sessionId).toBeNull();
    });
  });

  describe('Connection Management', () => {
    it('should establish connection when connect is called', async () => {
      const { result } = renderHook(() => useTerminal());

      await act(async () => {
        result.current.connect();
      });

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
        expect(mockWebSocket.connect).toHaveBeenCalled();
      });
    });

    it('should cleanup connection on unmount', () => {
      const { unmount } = renderHook(() => useTerminal());

      unmount();

      expect(mockWebSocket.disconnect).toHaveBeenCalled();
    });
  });

  describe('Data Handling', () => {
    it('should handle incoming terminal output', async () => {
      const { result } = renderHook(() => useTerminal());

      await act(async () => {
        result.current.connect();
      });

      act(() => {
        mockWebSocket.emit('output', 'Terminal output');
      });

      expect(result.current.output).toContain('Terminal output');
    });
  });

  describe('Error States', () => {
    it('should set error state on connection failure', async () => {
      const { result } = renderHook(() => useTerminal());

      mockWebSocket.mockConnectionFailure();

      await act(async () => {
        result.current.connect();
      });

      expect(result.current.error).toBeTruthy();
      expect(result.current.isConnected).toBe(false);
    });
  });
});
```

### Service Testing Pattern

```typescript
// tests/unit/lib/websocket/WebSocketClient.test.ts
import { WebSocketClient } from '@/lib/websocket/WebSocketClient';
import { mockSocket } from '@tests/mocks';

describe('WebSocketClient', () => {
  let client: WebSocketClient;

  beforeEach(() => {
    client = new WebSocketClient();
    mockSocket.clear();
  });

  afterEach(() => {
    client.disconnect();
  });

  describe('Connection Management', () => {
    it('should establish connection with correct URL', () => {
      const url = 'ws://localhost:8080/terminal';

      client.connect(url);

      expect(mockSocket.connect).toHaveBeenCalledWith(url);
      expect(client.isConnected()).toBe(true);
    });

    it('should handle connection timeout', (done) => {
      const url = 'ws://localhost:8080/terminal';

      client.connect(url, { timeout: 1000 });

      setTimeout(() => {
        expect(client.isConnected()).toBe(false);
        done();
      }, 1100);
    });
  });

  describe('Message Handling', () => {
    it('should send message when connected', () => {
      client.connect('ws://localhost:8080');

      const message = { type: 'input', data: 'test' };
      client.send(message);

      expect(mockSocket.send).toHaveBeenCalledWith(JSON.stringify(message));
    });

    it('should queue messages when disconnected', () => {
      const message = { type: 'input', data: 'test' };
      client.send(message);

      expect(client.getQueuedMessages()).toContain(message);
    });
  });

  describe('Event Listeners', () => {
    it('should register and trigger event listeners', () => {
      const mockListener = jest.fn();

      client.on('message', mockListener);
      client.connect('ws://localhost:8080');

      mockSocket.emit('message', { data: 'test' });

      expect(mockListener).toHaveBeenCalledWith({ data: 'test' });
    });
  });
});
```

## Test Organization Patterns

### File Structure Pattern

```
tests/unit/
├── components/
│   ├── terminal/
│   │   ├── Terminal.test.tsx           # Main terminal component
│   │   ├── TerminalControls.test.tsx   # Control panel
│   │   └── TerminalTabs.test.tsx       # Tab management
│   ├── monitoring/
│   │   ├── SystemMonitor.test.tsx      # System metrics
│   │   ├── AgentsPanel.test.tsx        # Agent management
│   │   └── PerformanceChart.test.tsx   # Performance visualization
│   └── sidebar/
│       ├── Sidebar.test.tsx            # Navigation sidebar
│       ├── FileExplorer.test.tsx       # File browser
│       └── SettingsPanel.test.tsx      # User settings
├── hooks/
│   ├── terminal/
│   │   ├── useTerminal.test.tsx        # Terminal state management
│   │   ├── useTerminalResize.test.tsx  # Size handling
│   │   └── useTerminalHistory.test.tsx # Command history
│   ├── websocket/
│   │   ├── useWebSocket.test.tsx       # WebSocket connection
│   │   ├── useWebSocketAuth.test.tsx   # Authentication
│   │   └── useWebSocketReconnect.test.tsx # Reconnection logic
│   └── state/
│       ├── useAppState.test.tsx        # Global state
│       ├── useSettingsState.test.tsx   # User preferences
│       └── useSessionState.test.tsx    # Session management
├── lib/
│   ├── websocket/
│   │   ├── WebSocketClient.test.ts     # Core client
│   │   ├── MessageHandler.test.ts      # Message processing
│   │   └── ConnectionManager.test.ts   # Connection lifecycle
│   ├── api/
│   │   ├── ApiClient.test.ts           # HTTP client
│   │   ├── AuthService.test.ts         # Authentication
│   │   └── ErrorHandler.test.ts        # Error management
│   └── utils/
│       ├── formatters.test.ts          # Data formatting
│       ├── validators.test.ts          # Input validation
│       └── helpers.test.ts             # Utility functions
└── services/
    ├── TerminalService.test.ts         # Terminal business logic
    ├── MonitoringService.test.ts       # System monitoring
    └── ConfigService.test.ts           # Configuration management
```

### Mock Patterns

```typescript
// tests/mocks/websocket.js
export const mockWebSocket = {
  connect: jest.fn(),
  disconnect: jest.fn(),
  send: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  clear: jest.fn(() => {
    jest.clearAllMocks();
  }),
  mockConnectionFailure: jest.fn(() => {
    mockWebSocket.connect.mockRejectedValue(new Error('Connection failed'));
  })
};
```

```typescript
// tests/mocks/xterm.js
export const mockTerminal = {
  open: jest.fn(),
  write: jest.fn(),
  writeln: jest.fn(),
  clear: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  resize: jest.fn()
};
```

### Factory Pattern for Test Data

```typescript
// tests/factories/terminal-factory.ts
export class TerminalDataFactory {
  static createTerminalMessage(overrides = {}) {
    return {
      id: `msg-${Date.now()}`,
      type: 'output',
      data: 'default terminal output',
      timestamp: new Date().toISOString(),
      sessionId: 'test-session-123',
      ...overrides
    };
  }

  static createWebSocketEvent(type = 'message', data = {}) {
    return {
      type,
      data: {
        ...this.createTerminalMessage(),
        ...data
      }
    };
  }

  static createTerminalState(overrides = {}) {
    return {
      isConnected: false,
      sessionId: null,
      output: [],
      input: '',
      history: [],
      currentDirectory: '/home/user',
      ...overrides
    };
  }
}
```

## Testing Utilities

### Test Helper Functions

```typescript
// tests/utils/test-helpers.ts
export const TestHelpers = {
  // Wait for async operations
  async waitForCondition(condition: () => boolean, timeout = 5000) {
    const start = Date.now();
    while (!condition() && Date.now() - start < timeout) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    if (!condition()) {
      throw new Error(`Condition not met within ${timeout}ms`);
    }
  },

  // Simulate user typing
  async simulateTyping(element: HTMLElement, text: string, delay = 50) {
    for (const char of text) {
      fireEvent.keyDown(element, { key: char });
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  },

  // Create mock terminal element
  createMockTerminal() {
    const element = document.createElement('div');
    element.className = 'xterm-screen';
    element.setAttribute('role', 'main');
    return element;
  }
};
```

### Custom Matchers

```typescript
// tests/utils/custom-matchers.ts
expect.extend({
  toBeWebSocketMessage(received, expected) {
    const pass = received.type === expected.type &&
                 received.data === expected.data;

    if (pass) {
      return {
        message: () => `Expected not to be WebSocket message`,
        pass: true
      };
    } else {
      return {
        message: () => `Expected WebSocket message with type "${expected.type}" and data "${expected.data}"`,
        pass: false
      };
    }
  },

  toHaveTerminalOutput(received, expected) {
    const terminal = received.querySelector('.xterm-screen');
    const hasOutput = terminal && terminal.textContent.includes(expected);

    return {
      message: () => hasOutput
        ? `Expected terminal not to contain "${expected}"`
        : `Expected terminal to contain "${expected}"`,
      pass: hasOutput
    };
  }
});
```

## Performance Testing Patterns

### Component Performance Tests

```typescript
// tests/unit/performance/terminal-performance.test.tsx
import { render, cleanup } from '@testing-library/react';
import { Terminal } from '@/components/Terminal';
import { performance } from 'perf_hooks';

describe('Terminal Performance', () => {
  afterEach(cleanup);

  it('should render within performance budget', () => {
    const startTime = performance.now();

    render(<Terminal />);

    const endTime = performance.now();
    const renderTime = endTime - startTime;

    expect(renderTime).toBeLessThan(100); // 100ms budget
  });

  it('should handle large output efficiently', async () => {
    const { rerender } = render(<Terminal />);
    const largeOutput = 'x'.repeat(10000);

    const startTime = performance.now();

    rerender(<Terminal output={largeOutput} />);

    const endTime = performance.now();
    const updateTime = endTime - startTime;

    expect(updateTime).toBeLessThan(200); // 200ms budget for large updates
  });
});
```

### Memory Leak Tests

```typescript
// tests/unit/performance/memory-leaks.test.tsx
describe('Memory Leak Prevention', () => {
  it('should cleanup event listeners on unmount', () => {
    const { unmount } = render(<Terminal />);
    const addEventListenerSpy = jest.spyOn(window, 'addEventListener');
    const removeEventListenerSpy = jest.spyOn(window, 'removeEventListener');

    unmount();

    expect(removeEventListenerSpy).toHaveBeenCalledTimes(
      addEventListenerSpy.mock.calls.length
    );
  });

  it('should dispose of WebSocket connections', () => {
    const { unmount } = render(<Terminal />);
    const mockClose = jest.fn();

    // Mock WebSocket
    global.WebSocket = jest.fn(() => ({
      close: mockClose
    }));

    unmount();

    expect(mockClose).toHaveBeenCalled();
  });
});
```

## Accessibility Testing Patterns

```typescript
// tests/unit/accessibility/terminal-a11y.test.tsx
import { render } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import { Terminal } from '@/components/Terminal';

expect.extend(toHaveNoViolations);

describe('Terminal Accessibility', () => {
  it('should not have accessibility violations', async () => {
    const { container } = render(<Terminal />);
    const results = await axe(container);

    expect(results).toHaveNoViolations();
  });

  it('should support keyboard navigation', () => {
    render(<Terminal />);
    const terminal = screen.getByRole('main');

    expect(terminal).toHaveAttribute('tabindex', '0');
    expect(terminal).toHaveAttribute('aria-label', 'Terminal');
  });

  it('should provide screen reader support', () => {
    const { container } = render(<Terminal />);
    const liveRegion = container.querySelector('[aria-live]');

    expect(liveRegion).toBeInTheDocument();
    expect(liveRegion).toHaveAttribute('aria-live', 'polite');
  });
});
```

## Coverage Analysis Patterns

### Coverage Configuration

```typescript
// tests/unit/coverage/coverage-helpers.ts
export const CoverageHelpers = {
  // Ensure all branches are tested
  testAllBranches(componentName: string, branches: string[]) {
    describe(`${componentName} - Branch Coverage`, () => {
      branches.forEach(branch => {
        it(`should test ${branch} branch`, () => {
          // Branch-specific test implementation
        });
      });
    });
  },

  // Test error boundaries
  testErrorScenarios(componentName: string, errorScenarios: string[]) {
    describe(`${componentName} - Error Coverage`, () => {
      errorScenarios.forEach(scenario => {
        it(`should handle ${scenario} error`, () => {
          // Error scenario test implementation
        });
      });
    });
  }
};
```

This modular unit testing architecture ensures comprehensive coverage while maintaining manageable file sizes and clear separation of concerns. Each pattern focuses on specific testing needs while supporting the overall goal of reliable, maintainable test suites.