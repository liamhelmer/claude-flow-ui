/**
 * Comprehensive type validation tests
 * Tests type safety and interface contracts
 */

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

// Mock implementations for testing
const mockTerminalSession: TerminalSession = {
  id: 'test-session-1',
  name: 'Test Terminal',
  isActive: true,
  lastActivity: new Date('2025-01-01T00:00:00.000Z'),
};

const mockWebSocketMessage: WebSocketMessage = {
  type: 'data',
  sessionId: 'test-session',
  data: 'test data',
  cols: 80,
  rows: 24,
};

const mockAppState: AppState = {
  terminalSessions: [mockTerminalSession],
  activeSessionId: 'test-session-1',
  sidebarOpen: true,
  loading: false,
  error: null,
};

const mockTerminalProps: TerminalProps = {
  sessionId: 'test-session',
  className: 'test-class',
};

const mockSidebarProps: SidebarProps = {
  isOpen: true,
  onToggle: () => {},
  sessions: [mockTerminalSession],
  activeSessionId: 'test-session-1',
  onSessionSelect: (sessionId: string) => {},
  onSessionCreate: () => {},
  onSessionClose: (sessionId: string) => {},
};

const mockTabProps: TabProps = {
  title: 'Test Tab',
  isActive: true,
  onSelect: () => {},
  onClose: () => {},
  closable: true,
};

const mockTerminalConfig: TerminalConfig = {
  theme: 'dark',
  fontSize: 14,
  fontFamily: 'Consolas',
  cursorBlink: true,
  scrollback: 1000,
  cols: 80,
  rows: 24,
};

describe('Type Definitions - Comprehensive Tests', () => {
  describe('TerminalSession', () => {
    it('should have correct structure and types', () => {
      expect(typeof mockTerminalSession.id).toBe('string');
      expect(typeof mockTerminalSession.name).toBe('string');
      expect(typeof mockTerminalSession.isActive).toBe('boolean');
      expect(mockTerminalSession.lastActivity).toBeInstanceOf(Date);
    });

    it('should validate required properties', () => {
      const session: TerminalSession = {
        id: 'required-id',
        name: 'Required Name',
        isActive: false,
        lastActivity: new Date(),
      };

      expect(session).toBeDefined();
      expect(session.id).toBeTruthy();
      expect(session.name).toBeTruthy();
      expect(typeof session.isActive).toBe('boolean');
    });

    it('should handle edge case values', () => {
      const edgeCaseSession: TerminalSession = {
        id: '',
        name: '',
        isActive: false,
        lastActivity: new Date(0), // Unix epoch
      };

      expect(edgeCaseSession.id).toBe('');
      expect(edgeCaseSession.name).toBe('');
      expect(edgeCaseSession.isActive).toBe(false);
      expect(edgeCaseSession.lastActivity.getTime()).toBe(0);
    });
  });

  describe('WebSocketMessage', () => {
    it('should have correct message types', () => {
      const messageTypes: WebSocketMessage['type'][] = [
        'data',
        'resize',
        'create',
        'destroy',
        'list',
      ];

      messageTypes.forEach(type => {
        const message: WebSocketMessage = { type };
        expect(message.type).toBe(type);
      });
    });

    it('should handle data messages', () => {
      const dataMessage: WebSocketMessage = {
        type: 'data',
        sessionId: 'session-1',
        data: 'terminal output',
      };

      expect(dataMessage.type).toBe('data');
      expect(dataMessage.sessionId).toBe('session-1');
      expect(dataMessage.data).toBe('terminal output');
    });

    it('should handle resize messages', () => {
      const resizeMessage: WebSocketMessage = {
        type: 'resize',
        sessionId: 'session-1',
        cols: 100,
        rows: 30,
      };

      expect(resizeMessage.type).toBe('resize');
      expect(resizeMessage.cols).toBe(100);
      expect(resizeMessage.rows).toBe(30);
    });

    it('should handle messages without optional fields', () => {
      const basicMessage: WebSocketMessage = {
        type: 'create',
      };

      expect(basicMessage.type).toBe('create');
      expect(basicMessage.sessionId).toBeUndefined();
      expect(basicMessage.data).toBeUndefined();
      expect(basicMessage.cols).toBeUndefined();
      expect(basicMessage.rows).toBeUndefined();
    });
  });

  describe('AppState', () => {
    it('should have correct structure and types', () => {
      expect(Array.isArray(mockAppState.terminalSessions)).toBe(true);
      expect(typeof mockAppState.activeSessionId).toBe('string');
      expect(typeof mockAppState.sidebarOpen).toBe('boolean');
      expect(typeof mockAppState.loading).toBe('boolean');
      expect(mockAppState.error).toBeNull();
    });

    it('should handle empty state', () => {
      const emptyState: AppState = {
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: false,
        loading: false,
        error: null,
      };

      expect(emptyState.terminalSessions).toHaveLength(0);
      expect(emptyState.activeSessionId).toBeNull();
      expect(emptyState.error).toBeNull();
    });

    it('should handle error state', () => {
      const errorState: AppState = {
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: true,
        loading: false,
        error: 'Connection failed',
      };

      expect(typeof errorState.error).toBe('string');
      expect(errorState.error).toBe('Connection failed');
    });
  });

  describe('TerminalProps', () => {
    it('should have required sessionId', () => {
      expect(typeof mockTerminalProps.sessionId).toBe('string');
      expect(mockTerminalProps.sessionId).toBeTruthy();
    });

    it('should have optional className', () => {
      const propsWithoutClass: TerminalProps = {
        sessionId: 'test',
      };

      expect(propsWithoutClass.className).toBeUndefined();

      const propsWithClass: TerminalProps = {
        sessionId: 'test',
        className: 'custom-class',
      };

      expect(propsWithClass.className).toBe('custom-class');
    });
  });

  describe('SidebarProps', () => {
    it('should have all required properties', () => {
      expect(typeof mockSidebarProps.isOpen).toBe('boolean');
      expect(typeof mockSidebarProps.onToggle).toBe('function');
      expect(Array.isArray(mockSidebarProps.sessions)).toBe(true);
      expect(typeof mockSidebarProps.activeSessionId).toBe('string');
      expect(typeof mockSidebarProps.onSessionSelect).toBe('function');
      expect(typeof mockSidebarProps.onSessionCreate).toBe('function');
      expect(typeof mockSidebarProps.onSessionClose).toBe('function');
    });

    it('should handle null activeSessionId', () => {
      const propsWithNullActive: SidebarProps = {
        ...mockSidebarProps,
        activeSessionId: null,
      };

      expect(propsWithNullActive.activeSessionId).toBeNull();
    });

    it('should validate callback signatures', () => {
      const callbacks = {
        onToggle: jest.fn(),
        onSessionSelect: jest.fn(),
        onSessionCreate: jest.fn(),
        onSessionClose: jest.fn(),
      };

      const props: SidebarProps = {
        isOpen: true,
        onToggle: callbacks.onToggle,
        sessions: [],
        activeSessionId: null,
        onSessionSelect: callbacks.onSessionSelect,
        onSessionCreate: callbacks.onSessionCreate,
        onSessionClose: callbacks.onSessionClose,
      };

      // Test callback calls
      props.onToggle();
      props.onSessionSelect('test-id');
      props.onSessionCreate();
      props.onSessionClose('test-id');

      expect(callbacks.onToggle).toHaveBeenCalled();
      expect(callbacks.onSessionSelect).toHaveBeenCalledWith('test-id');
      expect(callbacks.onSessionCreate).toHaveBeenCalled();
      expect(callbacks.onSessionClose).toHaveBeenCalledWith('test-id');
    });
  });

  describe('TabProps', () => {
    it('should have required properties', () => {
      expect(typeof mockTabProps.title).toBe('string');
      expect(typeof mockTabProps.isActive).toBe('boolean');
      expect(typeof mockTabProps.onSelect).toBe('function');
      expect(typeof mockTabProps.onClose).toBe('function');
    });

    it('should handle optional closable property', () => {
      const nonClosableTab: TabProps = {
        title: 'Non-closable',
        isActive: false,
        onSelect: () => {},
        onClose: () => {},
      };

      expect(nonClosableTab.closable).toBeUndefined();

      const closableTab: TabProps = {
        ...nonClosableTab,
        closable: true,
      };

      expect(closableTab.closable).toBe(true);
    });
  });

  describe('Theme', () => {
    it('should only allow valid theme values', () => {
      const darkTheme: Theme = 'dark';
      const lightTheme: Theme = 'light';

      expect(darkTheme).toBe('dark');
      expect(lightTheme).toBe('light');
    });
  });

  describe('TerminalConfig', () => {
    it('should have correct structure and types', () => {
      expect(mockTerminalConfig.theme).toBe('dark');
      expect(typeof mockTerminalConfig.fontSize).toBe('number');
      expect(typeof mockTerminalConfig.fontFamily).toBe('string');
      expect(typeof mockTerminalConfig.cursorBlink).toBe('boolean');
      expect(typeof mockTerminalConfig.scrollback).toBe('number');
      expect(typeof mockTerminalConfig.cols).toBe('number');
      expect(typeof mockTerminalConfig.rows).toBe('number');
    });

    it('should handle different theme values', () => {
      const lightConfig: TerminalConfig = {
        ...mockTerminalConfig,
        theme: 'light',
      };

      expect(lightConfig.theme).toBe('light');
    });

    it('should validate numeric constraints', () => {
      const config: TerminalConfig = {
        theme: 'dark',
        fontSize: 12,
        fontFamily: 'monospace',
        cursorBlink: false,
        scrollback: 2000,
        cols: 120,
        rows: 40,
      };

      expect(config.fontSize).toBeGreaterThan(0);
      expect(config.scrollback).toBeGreaterThanOrEqual(0);
      expect(config.cols).toBeGreaterThan(0);
      expect(config.rows).toBeGreaterThan(0);
    });
  });

  describe('Type Compatibility and Integration', () => {
    it('should work with array operations', () => {
      const sessions: TerminalSession[] = [
        mockTerminalSession,
        {
          id: 'session-2',
          name: 'Terminal 2',
          isActive: false,
          lastActivity: new Date(),
        },
      ];

      expect(sessions).toHaveLength(2);
      expect(sessions.every(session => typeof session.id === 'string')).toBe(true);
    });

    it('should work with object spreading', () => {
      const updatedSession: TerminalSession = {
        ...mockTerminalSession,
        name: 'Updated Name',
        isActive: false,
      };

      expect(updatedSession.id).toBe(mockTerminalSession.id);
      expect(updatedSession.name).toBe('Updated Name');
      expect(updatedSession.isActive).toBe(false);
      expect(updatedSession.lastActivity).toBe(mockTerminalSession.lastActivity);
    });

    it('should work with partial updates', () => {
      const updates: Partial<TerminalSession> = {
        name: 'Partially Updated',
      };

      const updatedSession: TerminalSession = {
        ...mockTerminalSession,
        ...updates,
      };

      expect(updatedSession.name).toBe('Partially Updated');
      expect(updatedSession.id).toBe(mockTerminalSession.id);
    });
  });

  describe('Type Guards and Validation', () => {
    it('should validate WebSocket message types', () => {
      const isValidMessageType = (type: string): type is WebSocketMessage['type'] => {
        return ['data', 'resize', 'create', 'destroy', 'list'].includes(type);
      };

      expect(isValidMessageType('data')).toBe(true);
      expect(isValidMessageType('invalid')).toBe(false);
    });

    it('should validate theme types', () => {
      const isValidTheme = (theme: string): theme is Theme => {
        return ['dark', 'light'].includes(theme);
      };

      expect(isValidTheme('dark')).toBe(true);
      expect(isValidTheme('light')).toBe(true);
      expect(isValidTheme('blue')).toBe(false);
    });
  });
});