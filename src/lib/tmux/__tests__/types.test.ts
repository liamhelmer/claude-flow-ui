/**
 * Comprehensive unit tests for tmux type definitions
 * Tests TypeScript type validation, interface completeness, and data integrity
 */

import { TmuxPane, TmuxWindow, TmuxSession } from '../types';

describe('Tmux Type Definitions', () => {
  describe('TmuxPane Interface', () => {
    it('should validate complete TmuxPane structure', () => {
      const validPane: TmuxPane = {
        id: 1,
        active: true,
        width: 80,
        height: 24,
        x: 0,
        y: 0,
        command: 'bash',
        pid: 12345,
        title: 'Terminal',
        output: 'Hello World'
      };

      // Type validation through assignment
      expect(validPane.id).toBe(1);
      expect(validPane.active).toBe(true);
      expect(validPane.width).toBe(80);
      expect(validPane.height).toBe(24);
      expect(validPane.x).toBe(0);
      expect(validPane.y).toBe(0);
      expect(validPane.command).toBe('bash');
      expect(validPane.pid).toBe(12345);
      expect(validPane.title).toBe('Terminal');
      expect(validPane.output).toBe('Hello World');
    });

    it('should handle minimum TmuxPane values', () => {
      const minPane: TmuxPane = {
        id: 0,
        active: false,
        width: 1,
        height: 1,
        x: 0,
        y: 0,
        command: '',
        pid: 0,
        title: '',
        output: ''
      };

      expect(minPane.id).toBe(0);
      expect(minPane.active).toBe(false);
      expect(minPane.width).toBe(1);
      expect(minPane.height).toBe(1);
    });

    it('should handle large TmuxPane values', () => {
      const largePane: TmuxPane = {
        id: Number.MAX_SAFE_INTEGER,
        active: true,
        width: 999999,
        height: 999999,
        x: 999999,
        y: 999999,
        command: 'a'.repeat(1000),
        pid: Number.MAX_SAFE_INTEGER,
        title: 'b'.repeat(1000),
        output: 'c'.repeat(10000)
      };

      expect(largePane.id).toBe(Number.MAX_SAFE_INTEGER);
      expect(largePane.command.length).toBe(1000);
      expect(largePane.output.length).toBe(10000);
    });
  });

  describe('TmuxWindow Interface', () => {
    it('should validate complete TmuxWindow structure', () => {
      const validPane: TmuxPane = {
        id: 1,
        active: true,
        width: 80,
        height: 24,
        x: 0,
        y: 0,
        command: 'bash',
        pid: 12345,
        title: 'Terminal',
        output: 'Hello World'
      };

      const validWindow: TmuxWindow = {
        id: 1,
        name: 'main',
        active: true,
        layout: 'even-horizontal',
        panes: [validPane]
      };

      expect(validWindow.id).toBe(1);
      expect(validWindow.name).toBe('main');
      expect(validWindow.active).toBe(true);
      expect(validWindow.layout).toBe('even-horizontal');
      expect(validWindow.panes).toHaveLength(1);
      expect(validWindow.panes[0]).toBe(validPane);
    });

    it('should handle TmuxWindow with multiple panes', () => {
      const pane1: TmuxPane = {
        id: 1,
        active: true,
        width: 40,
        height: 24,
        x: 0,
        y: 0,
        command: 'bash',
        pid: 12345,
        title: 'Terminal 1',
        output: 'Output 1'
      };

      const pane2: TmuxPane = {
        id: 2,
        active: false,
        width: 40,
        height: 24,
        x: 40,
        y: 0,
        command: 'vim',
        pid: 12346,
        title: 'Terminal 2',
        output: 'Output 2'
      };

      const multiPaneWindow: TmuxWindow = {
        id: 1,
        name: 'development',
        active: true,
        layout: 'even-vertical',
        panes: [pane1, pane2]
      };

      expect(multiPaneWindow.panes).toHaveLength(2);
      expect(multiPaneWindow.panes[0].id).toBe(1);
      expect(multiPaneWindow.panes[1].id).toBe(2);
    });

    it('should handle TmuxWindow with empty panes array', () => {
      const emptyWindow: TmuxWindow = {
        id: 1,
        name: 'empty',
        active: false,
        layout: 'main-horizontal',
        panes: []
      };

      expect(emptyWindow.panes).toHaveLength(0);
      expect(Array.isArray(emptyWindow.panes)).toBe(true);
    });

    it('should validate common tmux layouts', () => {
      const layouts = [
        'even-horizontal',
        'even-vertical',
        'main-horizontal',
        'main-vertical',
        'tiled'
      ];

      layouts.forEach(layout => {
        const window: TmuxWindow = {
          id: 1,
          name: 'test',
          active: true,
          layout,
          panes: []
        };

        expect(window.layout).toBe(layout);
      });
    });
  });

  describe('TmuxSession Interface', () => {
    it('should validate complete TmuxSession structure', () => {
      const validPane: TmuxPane = {
        id: 1,
        active: true,
        width: 80,
        height: 24,
        x: 0,
        y: 0,
        command: 'bash',
        pid: 12345,
        title: 'Terminal',
        output: 'Hello World'
      };

      const validWindow: TmuxWindow = {
        id: 1,
        name: 'main',
        active: true,
        layout: 'even-horizontal',
        panes: [validPane]
      };

      const validSession: TmuxSession = {
        id: 'session-1',
        name: 'development',
        created: 1640995200000,
        lastAccessed: 1640995800000,
        status: 'active',
        socketPath: '/tmp/tmux-1000/default',
        workingDirectory: '/home/user/project',
        environment: {
          'PATH': '/usr/bin:/bin',
          'HOME': '/home/user',
          'USER': 'user'
        },
        windows: [validWindow]
      };

      expect(validSession.id).toBe('session-1');
      expect(validSession.name).toBe('development');
      expect(validSession.created).toBe(1640995200000);
      expect(validSession.lastAccessed).toBe(1640995800000);
      expect(validSession.status).toBe('active');
      expect(validSession.socketPath).toBe('/tmp/tmux-1000/default');
      expect(validSession.workingDirectory).toBe('/home/user/project');
      expect(validSession.environment['PATH']).toBe('/usr/bin:/bin');
      expect(validSession.windows).toHaveLength(1);
    });

    it('should validate session status values', () => {
      const activeSession: TmuxSession = {
        id: 'session-1',
        name: 'active-session',
        created: Date.now(),
        lastAccessed: Date.now(),
        status: 'active',
        socketPath: '/tmp/tmux-1000/active',
        workingDirectory: '/home/user',
        environment: {},
        windows: []
      };

      const deadSession: TmuxSession = {
        id: 'session-2',
        name: 'dead-session',
        created: Date.now(),
        lastAccessed: Date.now(),
        status: 'dead',
        socketPath: '/tmp/tmux-1000/dead',
        workingDirectory: '/home/user',
        environment: {},
        windows: []
      };

      expect(activeSession.status).toBe('active');
      expect(deadSession.status).toBe('dead');
    });

    it('should handle session with multiple windows', () => {
      const window1: TmuxWindow = {
        id: 1,
        name: 'editor',
        active: true,
        layout: 'main-vertical',
        panes: []
      };

      const window2: TmuxWindow = {
        id: 2,
        name: 'server',
        active: false,
        layout: 'even-horizontal',
        panes: []
      };

      const multiWindowSession: TmuxSession = {
        id: 'session-multi',
        name: 'development',
        created: Date.now(),
        lastAccessed: Date.now(),
        status: 'active',
        socketPath: '/tmp/tmux-1000/multi',
        workingDirectory: '/home/user/project',
        environment: {},
        windows: [window1, window2]
      };

      expect(multiWindowSession.windows).toHaveLength(2);
      expect(multiWindowSession.windows[0].name).toBe('editor');
      expect(multiWindowSession.windows[1].name).toBe('server');
    });

    it('should handle complex environment variables', () => {
      const complexEnv = {
        'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
        'HOME': '/home/user',
        'USER': 'user',
        'SHELL': '/bin/bash',
        'LANG': 'en_US.UTF-8',
        'TERM': 'screen-256color',
        'TMUX': '/tmp/tmux-1000/default,12345,0',
        'PWD': '/home/user/project',
        'OLDPWD': '/home/user',
        'NODE_ENV': 'development',
        'API_KEY': 'secret-key-12345'
      };

      const sessionWithEnv: TmuxSession = {
        id: 'env-session',
        name: 'env-test',
        created: Date.now(),
        lastAccessed: Date.now(),
        status: 'active',
        socketPath: '/tmp/tmux-1000/env',
        workingDirectory: '/home/user/project',
        environment: complexEnv,
        windows: []
      };

      expect(Object.keys(sessionWithEnv.environment)).toHaveLength(11);
      expect(sessionWithEnv.environment['NODE_ENV']).toBe('development');
      expect(sessionWithEnv.environment['TMUX']).toContain('tmux-1000');
    });

    it('should handle empty environment object', () => {
      const sessionEmptyEnv: TmuxSession = {
        id: 'empty-env',
        name: 'minimal',
        created: Date.now(),
        lastAccessed: Date.now(),
        status: 'active',
        socketPath: '/tmp/tmux-1000/minimal',
        workingDirectory: '/home/user',
        environment: {},
        windows: []
      };

      expect(Object.keys(sessionEmptyEnv.environment)).toHaveLength(0);
      expect(sessionEmptyEnv.environment).toEqual({});
    });
  });

  describe('Type Consistency and Integration', () => {
    it('should maintain consistent IDs across related objects', () => {
      const paneId = 1;
      const windowId = 2;
      const sessionId = 'session-3';

      const pane: TmuxPane = {
        id: paneId,
        active: true,
        width: 80,
        height: 24,
        x: 0,
        y: 0,
        command: 'bash',
        pid: 12345,
        title: 'Terminal',
        output: ''
      };

      const window: TmuxWindow = {
        id: windowId,
        name: 'main',
        active: true,
        layout: 'even-horizontal',
        panes: [pane]
      };

      const session: TmuxSession = {
        id: sessionId,
        name: 'test',
        created: Date.now(),
        lastAccessed: Date.now(),
        status: 'active',
        socketPath: '/tmp/tmux-1000/test',
        workingDirectory: '/home/user',
        environment: {},
        windows: [window]
      };

      expect(session.windows[0].panes[0].id).toBe(paneId);
      expect(session.windows[0].id).toBe(windowId);
      expect(session.id).toBe(sessionId);
    });

    it('should handle deeply nested tmux structure', () => {
      // Create complex nested structure
      const panes: TmuxPane[] = Array.from({ length: 4 }, (_, i) => ({
        id: i + 1,
        active: i === 0,
        width: 40,
        height: 12,
        x: (i % 2) * 40,
        y: Math.floor(i / 2) * 12,
        command: `process-${i + 1}`,
        pid: 10000 + i,
        title: `Pane ${i + 1}`,
        output: `Output from pane ${i + 1}`
      }));

      const windows: TmuxWindow[] = Array.from({ length: 3 }, (_, i) => ({
        id: i + 1,
        name: `window-${i + 1}`,
        active: i === 0,
        layout: ['even-horizontal', 'even-vertical', 'tiled'][i],
        panes: i === 0 ? panes : []
      }));

      const complexSession: TmuxSession = {
        id: 'complex-session',
        name: 'development-env',
        created: Date.now() - 86400000, // 1 day ago
        lastAccessed: Date.now(),
        status: 'active',
        socketPath: '/tmp/tmux-1000/development-env',
        workingDirectory: '/home/user/workspace/project',
        environment: {
          'NODE_ENV': 'development',
          'DEBUG': 'app:*',
          'PORT': '3000'
        },
        windows
      };

      expect(complexSession.windows).toHaveLength(3);
      expect(complexSession.windows[0].panes).toHaveLength(4);
      expect(complexSession.windows[1].panes).toHaveLength(0);
      expect(complexSession.windows[2].panes).toHaveLength(0);
      
      // Verify all panes in first window
      complexSession.windows[0].panes.forEach((pane, index) => {
        expect(pane.id).toBe(index + 1);
        expect(pane.command).toBe(`process-${index + 1}`);
      });
    });

    it('should handle edge cases and validation scenarios', () => {
      // Test with unusual but valid data
      const edgeCaseSession: TmuxSession = {
        id: '',  // Empty string ID
        name: '   ',  // Whitespace name
        created: 0,  // Unix epoch
        lastAccessed: Number.MAX_SAFE_INTEGER,
        status: 'dead',
        socketPath: '/',  // Root path
        workingDirectory: '//',  // Double slash
        environment: {
          '': 'empty-key',  // Empty key
          'special-chars': 'value!@#$%^&*()',
          'unicode': '🚀🔥💻'
        },
        windows: []
      };

      expect(edgeCaseSession.id).toBe('');
      expect(edgeCaseSession.name).toBe('   ');
      expect(edgeCaseSession.created).toBe(0);
      expect(edgeCaseSession.environment['']).toBe('empty-key');
      expect(edgeCaseSession.environment['unicode']).toBe('🚀🔥💻');
    });
  });

  describe('Type Guards and Validation Helpers', () => {
    it('should provide type validation patterns', () => {
      // Helper functions that could be created for runtime validation
      const isValidTmuxPane = (obj: any): obj is TmuxPane => {
        return obj !== null &&
          obj !== undefined &&
          typeof obj === 'object' &&
          typeof obj.id === 'number' &&
          typeof obj.active === 'boolean' &&
          typeof obj.width === 'number' &&
          typeof obj.height === 'number' &&
          typeof obj.x === 'number' &&
          typeof obj.y === 'number' &&
          typeof obj.command === 'string' &&
          typeof obj.pid === 'number' &&
          typeof obj.title === 'string' &&
          typeof obj.output === 'string';
      };

      const validPane: TmuxPane = {
        id: 1,
        active: true,
        width: 80,
        height: 24,
        x: 0,
        y: 0,
        command: 'bash',
        pid: 12345,
        title: 'Terminal',
        output: 'Hello'
      };

      const invalidPane = {
        id: '1',  // Wrong type
        active: 'true',  // Wrong type
        width: 80
        // Missing required properties
      };

      expect(isValidTmuxPane(validPane)).toBe(true);
      expect(isValidTmuxPane(invalidPane)).toBe(false);
      expect(isValidTmuxPane(null)).toBe(false);
      expect(isValidTmuxPane(undefined)).toBe(false);
    });

    it('should validate session status enum values', () => {
      const validStatuses: Array<'active' | 'dead'> = ['active', 'dead'];
      
      validStatuses.forEach(status => {
        const session: TmuxSession = {
          id: 'test',
          name: 'test',
          created: Date.now(),
          lastAccessed: Date.now(),
          status,
          socketPath: '/tmp/test',
          workingDirectory: '/home',
          environment: {},
          windows: []
        };

        expect(['active', 'dead']).toContain(session.status);
      });
    });
  });
});