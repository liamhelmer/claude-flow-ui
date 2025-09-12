import type {
  TerminalSession,
  WebSocketMessage,
  AppState,
  TerminalProps,
  SidebarProps,
  TabProps,
  Theme,
  TerminalConfig,
} from '@/types';

describe('Type Definitions', () => {
  describe('TerminalSession', () => {
    it('should allow valid TerminalSession objects', () => {
      const validSession: TerminalSession = {
        id: 'session-123',
        name: 'Test Session',
        isActive: true,
        lastActivity: new Date(),
      };
      
      expect(validSession.id).toBe('session-123');
      expect(validSession.name).toBe('Test Session');
      expect(validSession.isActive).toBe(true);
      expect(validSession.lastActivity).toBeInstanceOf(Date);
    });

    it('should work with minimal required fields', () => {
      const session: TerminalSession = {
        id: 'minimal-session',
        name: 'Minimal',
        isActive: false,
        lastActivity: new Date('2023-01-01'),
      };
      
      expect(session).toBeDefined();
      expect(typeof session.id).toBe('string');
      expect(typeof session.name).toBe('string');
      expect(typeof session.isActive).toBe('boolean');
      expect(session.lastActivity instanceof Date).toBe(true);
    });
  });

  describe('WebSocketMessage', () => {
    it('should allow data message type', () => {
      const dataMessage: WebSocketMessage = {
        type: 'data',
        sessionId: 'session-123',
        data: 'Hello, terminal!',
      };
      
      expect(dataMessage.type).toBe('data');
      expect(dataMessage.sessionId).toBe('session-123');
      expect(dataMessage.data).toBe('Hello, terminal!');
    });

    it('should allow resize message type', () => {
      const resizeMessage: WebSocketMessage = {
        type: 'resize',
        sessionId: 'session-123',
        cols: 80,
        rows: 24,
      };
      
      expect(resizeMessage.type).toBe('resize');
      expect(resizeMessage.cols).toBe(80);
      expect(resizeMessage.rows).toBe(24);
    });

    it('should allow create message type', () => {
      const createMessage: WebSocketMessage = {
        type: 'create',
      };
      
      expect(createMessage.type).toBe('create');
    });

    it('should allow destroy message type', () => {
      const destroyMessage: WebSocketMessage = {
        type: 'destroy',
        sessionId: 'session-to-destroy',
      };
      
      expect(destroyMessage.type).toBe('destroy');
      expect(destroyMessage.sessionId).toBe('session-to-destroy');
    });

    it('should allow list message type', () => {
      const listMessage: WebSocketMessage = {
        type: 'list',
      };
      
      expect(listMessage.type).toBe('list');
    });

    it('should allow optional fields', () => {
      const message: WebSocketMessage = {
        type: 'data',
        sessionId: undefined,
        data: undefined,
        cols: undefined,
        rows: undefined,
      };
      
      expect(message.type).toBe('data');
      expect(message.sessionId).toBeUndefined();
    });
  });

  describe('AppState', () => {
    it('should represent complete application state', () => {
      const sessions: TerminalSession[] = [
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
      ];

      const appState: AppState = {
        terminalSessions: sessions,
        activeSessionId: 'session-1',
        sidebarOpen: true,
        loading: false,
        error: null,
      };
      
      expect(appState.terminalSessions).toHaveLength(2);
      expect(appState.activeSessionId).toBe('session-1');
      expect(appState.sidebarOpen).toBe(true);
      expect(appState.loading).toBe(false);
      expect(appState.error).toBeNull();
    });

    it('should allow null activeSessionId', () => {
      const appState: AppState = {
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: false,
        loading: true,
        error: 'Something went wrong',
      };
      
      expect(appState.activeSessionId).toBeNull();
      expect(appState.error).toBe('Something went wrong');
    });

    it('should allow empty sessions array', () => {
      const appState: AppState = {
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: true,
        loading: false,
        error: null,
      };
      
      expect(appState.terminalSessions).toEqual([]);
    });
  });

  describe('TerminalProps', () => {
    it('should require sessionId', () => {
      const props: TerminalProps = {
        sessionId: 'terminal-session-123',
      };
      
      expect(props.sessionId).toBe('terminal-session-123');
      expect(props.className).toBeUndefined();
    });

    it('should allow optional className', () => {
      const props: TerminalProps = {
        sessionId: 'terminal-session-456',
        className: 'custom-terminal-class',
      };
      
      expect(props.sessionId).toBe('terminal-session-456');
      expect(props.className).toBe('custom-terminal-class');
    });
  });

  describe('SidebarProps', () => {
    it('should contain all required sidebar properties', () => {
      const sessions: TerminalSession[] = [
        {
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
      ];

      const props: SidebarProps = {
        isOpen: true,
        onToggle: () => {},
        sessions: sessions,
        activeSessionId: 'session-1',
        onSessionSelect: (sessionId: string) => {},
        onSessionCreate: () => {},
        onSessionClose: (sessionId: string) => {},
      };
      
      expect(props.isOpen).toBe(true);
      expect(typeof props.onToggle).toBe('function');
      expect(props.sessions).toHaveLength(1);
      expect(props.activeSessionId).toBe('session-1');
      expect(typeof props.onSessionSelect).toBe('function');
      expect(typeof props.onSessionCreate).toBe('function');
      expect(typeof props.onSessionClose).toBe('function');
    });

    it('should allow null activeSessionId', () => {
      const props: SidebarProps = {
        isOpen: false,
        onToggle: jest.fn(),
        sessions: [],
        activeSessionId: null,
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };
      
      expect(props.activeSessionId).toBeNull();
    });

    it('should work with function props', () => {
      const mockToggle = jest.fn();
      const mockSelect = jest.fn();
      const mockCreate = jest.fn();
      const mockClose = jest.fn();

      const props: SidebarProps = {
        isOpen: true,
        onToggle: mockToggle,
        sessions: [],
        activeSessionId: null,
        onSessionSelect: mockSelect,
        onSessionCreate: mockCreate,
        onSessionClose: mockClose,
      };
      
      // Test that functions can be called
      props.onToggle();
      props.onSessionSelect('session-id');
      props.onSessionCreate();
      props.onSessionClose('session-id');
      
      expect(mockToggle).toHaveBeenCalled();
      expect(mockSelect).toHaveBeenCalledWith('session-id');
      expect(mockCreate).toHaveBeenCalled();
      expect(mockClose).toHaveBeenCalledWith('session-id');
    });
  });

  describe('TabProps', () => {
    it('should require basic tab properties', () => {
      const props: TabProps = {
        title: 'Tab Title',
        isActive: true,
        onSelect: () => {},
        onClose: () => {},
      };
      
      expect(props.title).toBe('Tab Title');
      expect(props.isActive).toBe(true);
      expect(typeof props.onSelect).toBe('function');
      expect(typeof props.onClose).toBe('function');
    });

    it('should allow optional closable property', () => {
      const props: TabProps = {
        title: 'Closable Tab',
        isActive: false,
        onSelect: jest.fn(),
        onClose: jest.fn(),
        closable: true,
      };
      
      expect(props.closable).toBe(true);
    });

    it('should work without closable property', () => {
      const props: TabProps = {
        title: 'Non-closable Tab',
        isActive: false,
        onSelect: jest.fn(),
        onClose: jest.fn(),
      };
      
      expect(props.closable).toBeUndefined();
    });

    it('should allow closable to be false', () => {
      const props: TabProps = {
        title: 'Tab',
        isActive: true,
        onSelect: jest.fn(),
        onClose: jest.fn(),
        closable: false,
      };
      
      expect(props.closable).toBe(false);
    });
  });

  describe('Theme', () => {
    it('should allow dark theme', () => {
      const theme: Theme = 'dark';
      expect(theme).toBe('dark');
    });

    it('should allow light theme', () => {
      const theme: Theme = 'light';
      expect(theme).toBe('light');
    });

    it('should work in conditional logic', () => {
      const isDark = (theme: Theme) => theme === 'dark';
      
      expect(isDark('dark')).toBe(true);
      expect(isDark('light')).toBe(false);
    });
  });

  describe('TerminalConfig', () => {
    it('should contain all terminal configuration options', () => {
      const config: TerminalConfig = {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'Monaco, monospace',
        cursorBlink: true,
        scrollback: 1000,
      };
      
      expect(config.theme).toBe('dark');
      expect(config.fontSize).toBe(14);
      expect(config.fontFamily).toBe('Monaco, monospace');
      expect(config.cursorBlink).toBe(true);
      expect(config.scrollback).toBe(1000);
    });

    it('should work with light theme', () => {
      const config: TerminalConfig = {
        theme: 'light',
        fontSize: 12,
        fontFamily: 'Consolas',
        cursorBlink: false,
        scrollback: 500,
      };
      
      expect(config.theme).toBe('light');
      expect(config.fontSize).toBe(12);
      expect(config.cursorBlink).toBe(false);
    });

    it('should allow different font configurations', () => {
      const configs: TerminalConfig[] = [
        {
          theme: 'dark',
          fontSize: 10,
          fontFamily: 'Courier New',
          cursorBlink: true,
          scrollback: 100,
        },
        {
          theme: 'light',
          fontSize: 16,
          fontFamily: 'JetBrains Mono',
          cursorBlink: false,
          scrollback: 5000,
        },
      ];
      
      expect(configs[0].fontSize).toBe(10);
      expect(configs[0].fontFamily).toBe('Courier New');
      expect(configs[1].fontSize).toBe(16);
      expect(configs[1].fontFamily).toBe('JetBrains Mono');
    });
  });

  describe('Type Combinations and Relationships', () => {
    it('should work with AppState containing TerminalSessions', () => {
      const session: TerminalSession = {
        id: 'combo-session',
        name: 'Combo Test',
        isActive: true,
        lastActivity: new Date(),
      };

      const state: AppState = {
        terminalSessions: [session],
        activeSessionId: session.id,
        sidebarOpen: true,
        loading: false,
        error: null,
      };
      
      expect(state.terminalSessions[0]).toBe(session);
      expect(state.activeSessionId).toBe(session.id);
    });

    it('should work with SidebarProps using AppState data', () => {
      const sessions: TerminalSession[] = [
        {
          id: 'sidebar-session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        },
        {
          id: 'sidebar-session-2',
          name: 'Terminal 2',
          isActive: false,
          lastActivity: new Date(),
        },
      ];

      const appState: AppState = {
        terminalSessions: sessions,
        activeSessionId: 'sidebar-session-1',
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
      
      expect(sidebarProps.isOpen).toBe(true);
      expect(sidebarProps.sessions).toHaveLength(2);
      expect(sidebarProps.activeSessionId).toBe('sidebar-session-1');
    });

    it('should work with WebSocketMessage for different operations', () => {
      const messages: WebSocketMessage[] = [
        { type: 'create' },
        { type: 'data', sessionId: 'session-1', data: 'command output' },
        { type: 'resize', sessionId: 'session-1', cols: 100, rows: 30 },
        { type: 'destroy', sessionId: 'session-1' },
        { type: 'list' },
      ];
      
      expect(messages).toHaveLength(5);
      expect(messages[0].type).toBe('create');
      expect(messages[1].type).toBe('data');
      expect(messages[2].type).toBe('resize');
      expect(messages[3].type).toBe('destroy');
      expect(messages[4].type).toBe('list');
    });
  });

  describe('Type Safety and Validation', () => {
    it('should enforce required properties', () => {
      // These should not compile if TypeScript is properly configured
      // but we can test the types are used correctly
      
      const createValidSession = (): TerminalSession => ({
        id: 'required-id',
        name: 'Required Name',
        isActive: true,
        lastActivity: new Date(),
      });
      
      const session = createValidSession();
      expect(session).toBeDefined();
      expect(session.id).toBeTruthy();
      expect(session.name).toBeTruthy();
      expect(typeof session.isActive).toBe('boolean');
    });

    it('should work with generic functions', () => {
      const processMessage = <T extends WebSocketMessage>(message: T): T => {
        return { ...message };
      };
      
      const dataMessage = processMessage({
        type: 'data' as const,
        sessionId: 'test-session',
        data: 'test data',
      });
      
      expect(dataMessage.type).toBe('data');
      expect(dataMessage.sessionId).toBe('test-session');
    });

    it('should support discriminated unions', () => {
      const handleMessage = (message: WebSocketMessage) => {
        switch (message.type) {
          case 'data':
            return message.data; // TypeScript knows data exists
          case 'resize':
            return { cols: message.cols, rows: message.rows }; // TypeScript knows cols/rows exist
          case 'create':
          case 'destroy':
          case 'list':
            return message.sessionId; // Optional field
          default:
            return null;
        }
      };
      
      const dataResult = handleMessage({
        type: 'data',
        sessionId: 'session-1',
        data: 'output',
      });
      
      const resizeResult = handleMessage({
        type: 'resize',
        cols: 80,
        rows: 24,
      });
      
      expect(dataResult).toBe('output');
      expect(resizeResult).toEqual({ cols: 80, rows: 24 });
    });
  });
});