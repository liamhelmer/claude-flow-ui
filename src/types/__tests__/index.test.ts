import type {
  TerminalSession,
  WebSocketMessage,
  AppState,
  TerminalProps,
  SidebarProps,
  TabProps,
  Theme,
  TerminalConfig,
} from '../index';

describe('Type Definitions', () => {
  describe('TerminalSession', () => {
    it('should have correct structure', () => {
      const session: TerminalSession = {
        id: 'session-123',
        name: 'Test Terminal',
        isActive: true,
        lastActivity: new Date('2023-01-01T12:00:00Z'),
      };

      expect(typeof session.id).toBe('string');
      expect(typeof session.name).toBe('string');
      expect(typeof session.isActive).toBe('boolean');
      expect(session.lastActivity).toBeInstanceOf(Date);
    });

    it('should enforce required properties', () => {
      // TypeScript compilation test - these should not compile if types are wrong
      const validSession: TerminalSession = {
        id: 'test',
        name: 'Test',
        isActive: false,
        lastActivity: new Date(),
      };

      expect(validSession).toBeDefined();

      // These would cause TypeScript errors if uncommented:
      // const invalidSession1: TerminalSession = {}; // Missing required properties
      // const invalidSession2: TerminalSession = {
      //   id: 123, // Wrong type - should be string
      //   name: 'Test',
      //   isActive: false,
      //   lastActivity: new Date(),
      // };
    });

    it('should handle different date formats', () => {
      const sessions: TerminalSession[] = [
        {
          id: '1',
          name: 'Session 1',
          isActive: true,
          lastActivity: new Date(),
        },
        {
          id: '2',
          name: 'Session 2',
          isActive: false,
          lastActivity: new Date('2023-01-01'),
        },
        {
          id: '3',
          name: 'Session 3',
          isActive: true,
          lastActivity: new Date(Date.now() - 3600000), // 1 hour ago
        },
      ];

      sessions.forEach((session) => {
        expect(session.lastActivity).toBeInstanceOf(Date);
        expect(session.lastActivity.getTime()).not.toBeNaN();
      });
    });

    it('should support special characters in session names', () => {
      const specialSessions: TerminalSession[] = [
        {
          id: 'emoji-session',
          name: '🚀 Terminal',
          isActive: true,
          lastActivity: new Date(),
        },
        {
          id: 'unicode-session',
          name: 'Café Terminal',
          isActive: false,
          lastActivity: new Date(),
        },
        {
          id: 'symbols-session',
          name: 'Terminal #1 (Main)',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      specialSessions.forEach((session) => {
        expect(typeof session.name).toBe('string');
        expect(session.name.length).toBeGreaterThan(0);
      });
    });
  });

  describe('WebSocketMessage', () => {
    it('should support all message types', () => {
      const messages: WebSocketMessage[] = [
        { type: 'data', sessionId: 'session-1', data: 'test data' },
        { type: 'resize', sessionId: 'session-1', cols: 80, rows: 24 },
        { type: 'create' },
        { type: 'destroy', sessionId: 'session-1' },
        { type: 'list' },
      ];

      messages.forEach((message) => {
        expect(['data', 'resize', 'create', 'destroy', 'list']).toContain(message.type);
      });
    });

    it('should handle data messages correctly', () => {
      const dataMessage: WebSocketMessage = {
        type: 'data',
        sessionId: 'session-123',
        data: 'echo "Hello World"',
      };

      expect(dataMessage.type).toBe('data');
      expect(dataMessage.sessionId).toBe('session-123');
      expect(dataMessage.data).toBe('echo "Hello World"');
      expect(dataMessage.cols).toBeUndefined();
      expect(dataMessage.rows).toBeUndefined();
    });

    it('should handle resize messages correctly', () => {
      const resizeMessage: WebSocketMessage = {
        type: 'resize',
        sessionId: 'session-456',
        cols: 120,
        rows: 30,
      };

      expect(resizeMessage.type).toBe('resize');
      expect(resizeMessage.sessionId).toBe('session-456');
      expect(resizeMessage.cols).toBe(120);
      expect(resizeMessage.rows).toBe(30);
      expect(resizeMessage.data).toBeUndefined();
    });

    it('should handle control messages without sessionId', () => {
      const controlMessages: WebSocketMessage[] = [
        { type: 'create' },
        { type: 'list' },
      ];

      controlMessages.forEach((message) => {
        expect(message.sessionId).toBeUndefined();
        expect(message.data).toBeUndefined();
        expect(message.cols).toBeUndefined();
        expect(message.rows).toBeUndefined();
      });
    });

    it('should handle special data content', () => {
      const specialMessages: WebSocketMessage[] = [
        { type: 'data', sessionId: 'test', data: '' }, // Empty string
        { type: 'data', sessionId: 'test', data: '\x1b[31mRed text\x1b[0m' }, // ANSI codes
        { type: 'data', sessionId: 'test', data: 'Line 1\nLine 2\r\nLine 3' }, // Newlines
        { type: 'data', sessionId: 'test', data: '🚀 Rocket emoji' }, // Unicode
        { type: 'data', sessionId: 'test', data: 'Command with "quotes" and \'apostrophes\'' }, // Quotes
      ];

      specialMessages.forEach((message) => {
        expect(typeof message.data).toBe('string');
      });
    });
  });

  describe('AppState', () => {
    it('should have correct structure', () => {
      const state: AppState = {
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: true,
        loading: false,
        error: null,
      };

      expect(Array.isArray(state.terminalSessions)).toBe(true);
      expect(state.activeSessionId).toBeNull();
      expect(typeof state.sidebarOpen).toBe('boolean');
      expect(typeof state.loading).toBe('boolean');
      expect(state.error).toBeNull();
    });

    it('should handle different states correctly', () => {
      const states: AppState[] = [
        {
          terminalSessions: [],
          activeSessionId: null,
          sidebarOpen: true,
          loading: true,
          error: null,
        },
        {
          terminalSessions: [
            {
              id: 'session-1',
              name: 'Main Terminal',
              isActive: true,
              lastActivity: new Date(),
            },
          ],
          activeSessionId: 'session-1',
          sidebarOpen: false,
          loading: false,
          error: null,
        },
        {
          terminalSessions: [],
          activeSessionId: null,
          sidebarOpen: true,
          loading: false,
          error: 'Connection failed',
        },
      ];

      states.forEach((state) => {
        expect(typeof state.loading).toBe('boolean');
        expect(typeof state.sidebarOpen).toBe('boolean');
        expect(Array.isArray(state.terminalSessions)).toBe(true);
        
        if (state.activeSessionId !== null) {
          expect(typeof state.activeSessionId).toBe('string');
        }
        
        if (state.error !== null) {
          expect(typeof state.error).toBe('string');
        }
      });
    });

    it('should maintain consistency between activeSessionId and terminalSessions', () => {
      const sessionWithActive: AppState = {
        terminalSessions: [
          {
            id: 'session-1',
            name: 'Terminal 1',
            isActive: true,
            lastActivity: new Date(),
          },
          {
            id: 'session-2',
            name: 'Terminal 2',
            isActive: false,
            lastActivity: new Date(),
          },
        ],
        activeSessionId: 'session-1',
        sidebarOpen: true,
        loading: false,
        error: null,
      };

      const activeSession = sessionWithActive.terminalSessions.find(
        (s) => s.id === sessionWithActive.activeSessionId
      );
      
      expect(activeSession).toBeDefined();
      expect(activeSession?.isActive).toBe(true);
    });
  });

  describe('TerminalProps', () => {
    it('should have required sessionId', () => {
      const props: TerminalProps = {
        sessionId: 'terminal-session-123',
      };

      expect(typeof props.sessionId).toBe('string');
      expect(props.className).toBeUndefined();
    });

    it('should handle optional className', () => {
      const propsWithClass: TerminalProps = {
        sessionId: 'terminal-session-456',
        className: 'custom-terminal-class',
      };

      expect(typeof propsWithClass.sessionId).toBe('string');
      expect(typeof propsWithClass.className).toBe('string');
    });

    it('should support various className formats', () => {
      const classNameFormats: TerminalProps[] = [
        { sessionId: 'test', className: 'single-class' },
        { sessionId: 'test', className: 'multiple classes here' },
        { sessionId: 'test', className: 'with-dashes and_underscores' },
        { sessionId: 'test', className: '' }, // Empty className
      ];

      classNameFormats.forEach((props) => {
        if (props.className !== undefined) {
          expect(typeof props.className).toBe('string');
        }
      });
    });
  });

  describe('SidebarProps', () => {
    it('should have correct structure', () => {
      const props: SidebarProps = {
        isOpen: true,
        onToggle: jest.fn(),
        sessions: [],
        activeSessionId: null,
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };

      expect(typeof props.isOpen).toBe('boolean');
      expect(typeof props.onToggle).toBe('function');
      expect(Array.isArray(props.sessions)).toBe(true);
      expect(typeof props.onSessionSelect).toBe('function');
      expect(typeof props.onSessionCreate).toBe('function');
      expect(typeof props.onSessionClose).toBe('function');
    });

    it('should handle function signatures correctly', () => {
      const mockHandlers = {
        onToggle: jest.fn(),
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };

      const props: SidebarProps = {
        isOpen: false,
        sessions: [
          {
            id: 'session-1',
            name: 'Test Session',
            isActive: true,
            lastActivity: new Date(),
          },
        ],
        activeSessionId: 'session-1',
        ...mockHandlers,
      };

      // Test function calls
      props.onToggle();
      props.onSessionSelect('session-2');
      props.onSessionCreate();
      props.onSessionClose('session-1');

      expect(mockHandlers.onToggle).toHaveBeenCalledWith();
      expect(mockHandlers.onSessionSelect).toHaveBeenCalledWith('session-2');
      expect(mockHandlers.onSessionCreate).toHaveBeenCalledWith();
      expect(mockHandlers.onSessionClose).toHaveBeenCalledWith('session-1');
    });
  });

  describe('TabProps', () => {
    it('should have required properties', () => {
      const props: TabProps = {
        title: 'Tab Title',
        isActive: false,
        onSelect: jest.fn(),
        onClose: jest.fn(),
      };

      expect(typeof props.title).toBe('string');
      expect(typeof props.isActive).toBe('boolean');
      expect(typeof props.onSelect).toBe('function');
      expect(typeof props.onClose).toBe('function');
      expect(props.closable).toBeUndefined();
    });

    it('should handle optional closable property', () => {
      const propsClosable: TabProps = {
        title: 'Closable Tab',
        isActive: true,
        onSelect: jest.fn(),
        onClose: jest.fn(),
        closable: true,
      };

      const propsNotClosable: TabProps = {
        title: 'Non-closable Tab',
        isActive: false,
        onSelect: jest.fn(),
        onClose: jest.fn(),
        closable: false,
      };

      expect(propsClosable.closable).toBe(true);
      expect(propsNotClosable.closable).toBe(false);
    });

    it('should support various title formats', () => {
      const titleFormats: TabProps[] = [
        {
          title: 'Simple Title',
          isActive: false,
          onSelect: jest.fn(),
          onClose: jest.fn(),
        },
        {
          title: 'Title with Special Characters !@#$%',
          isActive: false,
          onSelect: jest.fn(),
          onClose: jest.fn(),
        },
        {
          title: '🚀 Tab with Emoji',
          isActive: false,
          onSelect: jest.fn(),
          onClose: jest.fn(),
        },
        {
          title: 'Very Long Title That Might Need Truncation in the UI',
          isActive: false,
          onSelect: jest.fn(),
          onClose: jest.fn(),
        },
      ];

      titleFormats.forEach((props) => {
        expect(typeof props.title).toBe('string');
        expect(props.title.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Theme', () => {
    it('should only allow valid theme values', () => {
      const validThemes: Theme[] = ['dark', 'light'];
      
      validThemes.forEach((theme) => {
        expect(['dark', 'light']).toContain(theme);
      });

      // TypeScript compilation test - this should not compile:
      // const invalidTheme: Theme = 'blue'; // Should cause error
    });

    it('should work in conditional logic', () => {
      const themes: Theme[] = ['dark', 'light'];

      themes.forEach((theme) => {
        if (theme === 'dark') {
          expect(theme).toBe('dark');
        } else if (theme === 'light') {
          expect(theme).toBe('light');
        } else {
          // This should never execute with valid Theme types
          fail(`Unexpected theme value: ${theme}`);
        }
      });
    });
  });

  describe('TerminalConfig', () => {
    it('should have correct structure', () => {
      const config: TerminalConfig = {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'JetBrains Mono',
        cursorBlink: true,
        scrollback: 1000,
      };

      expect(['dark', 'light']).toContain(config.theme);
      expect(typeof config.fontSize).toBe('number');
      expect(typeof config.fontFamily).toBe('string');
      expect(typeof config.cursorBlink).toBe('boolean');
      expect(typeof config.scrollback).toBe('number');
    });

    it('should handle different configuration values', () => {
      const configs: TerminalConfig[] = [
        {
          theme: 'dark',
          fontSize: 12,
          fontFamily: 'Menlo',
          cursorBlink: false,
          scrollback: 500,
        },
        {
          theme: 'light',
          fontSize: 16,
          fontFamily: 'Monaco, monospace',
          cursorBlink: true,
          scrollback: 9999,
        },
        {
          theme: 'dark',
          fontSize: 14,
          fontFamily: 'Courier New',
          cursorBlink: true,
          scrollback: 0, // No scrollback
        },
      ];

      configs.forEach((config) => {
        expect(config.fontSize).toBeGreaterThanOrEqual(0);
        expect(config.scrollback).toBeGreaterThanOrEqual(0);
        expect(config.fontFamily.length).toBeGreaterThan(0);
        expect(['dark', 'light']).toContain(config.theme);
        expect(typeof config.cursorBlink).toBe('boolean');
      });
    });

    it('should validate reasonable configuration values', () => {
      const config: TerminalConfig = {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'JetBrains Mono',
        cursorBlink: true,
        scrollback: 1000,
      };

      // Validate reasonable ranges
      expect(config.fontSize).toBeGreaterThan(6);
      expect(config.fontSize).toBeLessThan(72);
      expect(config.scrollback).toBeGreaterThanOrEqual(0);
      expect(config.fontFamily.trim()).not.toBe('');
    });
  });

  describe('Type composition and relationships', () => {
    it('should work together in complex scenarios', () => {
      const sessions: TerminalSession[] = [
        {
          id: 'session-1',
          name: 'Main Terminal',
          isActive: true,
          lastActivity: new Date(),
        },
        {
          id: 'session-2',
          name: 'Secondary Terminal',
          isActive: false,
          lastActivity: new Date(Date.now() - 60000),
        },
      ];

      const appState: AppState = {
        terminalSessions: sessions,
        activeSessionId: 'session-1',
        sidebarOpen: true,
        loading: false,
        error: null,
      };

      const sidebarProps: SidebarProps = {
        isOpen: appState.sidebarOpen,
        sessions: appState.terminalSessions,
        activeSessionId: appState.activeSessionId,
        onToggle: jest.fn(),
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };

      const terminalProps: TerminalProps = {
        sessionId: appState.activeSessionId!,
        className: 'main-terminal',
      };

      const terminalConfig: TerminalConfig = {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'JetBrains Mono',
        cursorBlink: true,
        scrollback: 1000,
      };

      // Validate the composition
      expect(sidebarProps.sessions).toEqual(sessions);
      expect(terminalProps.sessionId).toBe('session-1');
      expect(terminalConfig.theme).toBe('dark');

      // Test that active session exists in sessions array
      const activeSession = sidebarProps.sessions.find(
        (s) => s.id === sidebarProps.activeSessionId
      );
      expect(activeSession).toBeDefined();
      expect(activeSession?.isActive).toBe(true);
    });

    it('should handle empty/null states correctly', () => {
      const emptyAppState: AppState = {
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: false,
        loading: true,
        error: 'Connection error',
      };

      expect(emptyAppState.terminalSessions).toHaveLength(0);
      expect(emptyAppState.activeSessionId).toBeNull();
      expect(emptyAppState.error).not.toBeNull();

      // Sidebar with no sessions
      const emptySidebar: SidebarProps = {
        isOpen: false,
        sessions: [],
        activeSessionId: null,
        onToggle: jest.fn(),
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };

      expect(emptySidebar.sessions).toHaveLength(0);
      expect(emptySidebar.activeSessionId).toBeNull();
    });
  });

  describe('Type compatibility and evolution', () => {
    it('should maintain backward compatibility', () => {
      // Test that types can be extended without breaking existing code
      interface ExtendedTerminalSession extends TerminalSession {
        environment?: string;
        workingDirectory?: string;
      }

      const extendedSession: ExtendedTerminalSession = {
        id: 'session-extended',
        name: 'Extended Session',
        isActive: true,
        lastActivity: new Date(),
        environment: 'production',
        workingDirectory: '/home/user',
      };

      // Should still work as a regular TerminalSession
      const regularSession: TerminalSession = extendedSession;
      expect(regularSession.id).toBe('session-extended');
      expect(regularSession.name).toBe('Extended Session');
    });

    it('should support union types for extensibility', () => {
      type ExtendedWebSocketMessage = WebSocketMessage | {
        type: 'custom';
        customData: string;
      };

      const messages: ExtendedWebSocketMessage[] = [
        { type: 'data', sessionId: 'session-1', data: 'test' },
        { type: 'custom', customData: 'custom payload' },
      ];

      messages.forEach((message) => {
        expect(message.type).toBeDefined();
        if ('customData' in message) {
          expect(typeof message.customData).toBe('string');
        }
      });
    });
  });
});

// Additional tests for runtime type checking and validation
describe('Runtime Type Validation', () => {
  const isTerminalSession = (obj: any): obj is TerminalSession => {
    return (
      typeof obj === 'object' &&
      obj !== null &&
      typeof obj.id === 'string' &&
      typeof obj.name === 'string' &&
      typeof obj.isActive === 'boolean' &&
      obj.lastActivity instanceof Date
    );
  };

  const isWebSocketMessage = (obj: any): obj is WebSocketMessage => {
    return (
      typeof obj === 'object' &&
      obj !== null &&
      typeof obj.type === 'string' &&
      ['data', 'resize', 'create', 'destroy', 'list'].includes(obj.type)
    );
  };

  it('should validate TerminalSession at runtime', () => {
    const validSession = {
      id: 'session-1',
      name: 'Test Session',
      isActive: true,
      lastActivity: new Date(),
    };

    const invalidSessions = [
      null,
      undefined,
      {},
      { id: 'session-1' }, // Missing properties
      { id: 123, name: 'Test', isActive: true, lastActivity: new Date() }, // Wrong type
      { id: 'session-1', name: 'Test', isActive: 'true', lastActivity: new Date() }, // Wrong type
    ];

    expect(isTerminalSession(validSession)).toBe(true);
    
    invalidSessions.forEach((invalid) => {
      expect(isTerminalSession(invalid)).toBe(false);
    });
  });

  it('should validate WebSocketMessage at runtime', () => {
    const validMessages = [
      { type: 'data', sessionId: 'session-1', data: 'test' },
      { type: 'resize', cols: 80, rows: 24 },
      { type: 'create' },
      { type: 'list' },
    ];

    const invalidMessages = [
      null,
      undefined,
      {},
      { type: 'invalid-type' },
      { type: 123 },
    ];

    validMessages.forEach((valid) => {
      expect(isWebSocketMessage(valid)).toBe(true);
    });

    invalidMessages.forEach((invalid) => {
      expect(isWebSocketMessage(invalid)).toBe(false);
    });
  });
});