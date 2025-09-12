import { TmuxSession, TmuxWindow, TmuxPane } from '../../src/lib/tmux/types';
import fs from 'fs';
import path from 'path';

/**
 * Comprehensive fixture utilities for tmux testing
 */

export class TmuxFixtures {
  private static instance: TmuxFixtures;
  private mockSessions = new Map<string, TmuxSession>();
  private mockSocketFiles = new Map<string, any>();
  private fixtureDir = path.join(process.cwd(), 'tests', 'fixtures', 'tmux-data');

  static getInstance(): TmuxFixtures {
    if (!TmuxFixtures.instance) {
      TmuxFixtures.instance = new TmuxFixtures();
    }
    return TmuxFixtures.instance;
  }

  /**
   * Creates a comprehensive test session with multiple windows and panes
   */
  createComplexSession(sessionId: string = 'complex-test-session'): TmuxSession {
    const session: TmuxSession = {
      id: sessionId,
      name: sessionId,
      created: Date.now() - 3600000, // 1 hour ago
      lastAccessed: Date.now() - 300000, // 5 minutes ago
      status: 'active',
      socketPath: `/tmp/tmux-sockets/${sessionId}`,
      workingDirectory: '/home/user/project',
      environment: {
        TERM: 'xterm-256color',
        SHELL: '/bin/bash',
        PATH: '/usr/local/bin:/usr/bin:/bin',
        CLAUDE_FLOW_SESSION: sessionId,
      },
      windows: [
        {
          id: 0,
          name: 'claude-flow-main',
          active: true,
          layout: 'tiled',
          panes: [
            {
              id: 0,
              active: true,
              width: 120,
              height: 30,
              x: 0,
              y: 0,
              command: 'claude-flow tdd "implement user authentication"',
              pid: 12345,
              title: 'claude-flow',
              output: this.getClaudeFlowOutput(),
            }
          ]
        },
        {
          id: 1,
          name: 'monitoring',
          active: false,
          layout: 'main-horizontal',
          panes: [
            {
              id: 1,
              active: false,
              width: 120,
              height: 20,
              x: 0,
              y: 0,
              command: 'htop',
              pid: 12346,
              title: 'system monitor',
              output: this.getHtopOutput(),
            },
            {
              id: 2,
              active: false,
              width: 120,
              height: 10,
              x: 0,
              y: 20,
              command: 'tail -f /var/log/claude-flow.log',
              pid: 12347,
              title: 'logs',
              output: this.getLogOutput(),
            }
          ]
        },
        {
          id: 2,
          name: 'shell',
          active: false,
          layout: 'even-vertical',
          panes: [
            {
              id: 3,
              active: false,
              width: 60,
              height: 30,
              x: 0,
              y: 0,
              command: 'bash',
              pid: 12348,
              title: 'shell-1',
              output: '$ ls -la\ntotal 24\ndrwxr-xr-x  3 user user 4096 Jan  1 00:00 .\n$ ',
            },
            {
              id: 4,
              active: false,
              width: 60,
              height: 30,
              x: 60,
              y: 0,
              command: 'bash',
              pid: 12349,
              title: 'shell-2',
              output: '$ git status\nOn branch main\nnothing to commit, working tree clean\n$ ',
            }
          ]
        }
      ]
    };

    this.mockSessions.set(sessionId, session);
    this.createMockSocketFile(session.socketPath);
    
    return session;
  }

  /**
   * Creates a minimal test session
   */
  createSimpleSession(sessionId: string = 'simple-test-session'): TmuxSession {
    const session: TmuxSession = {
      id: sessionId,
      name: sessionId,
      created: Date.now(),
      lastAccessed: Date.now(),
      status: 'active',
      socketPath: `/tmp/tmux-sockets/${sessionId}`,
      workingDirectory: '/tmp',
      environment: {
        TERM: 'xterm-256color',
        SHELL: '/bin/bash',
      },
      windows: [
        {
          id: 0,
          name: 'main',
          active: true,
          layout: 'tiled',
          panes: [
            {
              id: 0,
              active: true,
              width: 80,
              height: 24,
              x: 0,
              y: 0,
              command: 'bash',
              pid: 54321,
              title: 'simple session',
              output: '$ echo "Hello from tmux"\nHello from tmux\n$ ',
            }
          ]
        }
      ]
    };

    this.mockSessions.set(sessionId, session);
    this.createMockSocketFile(session.socketPath);
    
    return session;
  }

  /**
   * Creates a session with long output for scrollback testing
   */
  createLongOutputSession(sessionId: string = 'long-output-session', outputLines: number = 10000): TmuxSession {
    const longOutput = Array.from({ length: outputLines }, (_, i) => 
      `Line ${i + 1}: ${this.generateRandomContent()}`
    ).join('\n') + '\n$ ';

    const session: TmuxSession = {
      id: sessionId,
      name: sessionId,
      created: Date.now() - 7200000, // 2 hours ago
      lastAccessed: Date.now(),
      status: 'active',
      socketPath: `/tmp/tmux-sockets/${sessionId}`,
      workingDirectory: '/tmp',
      environment: {},
      windows: [
        {
          id: 0,
          name: 'long-output',
          active: true,
          layout: 'tiled',
          panes: [
            {
              id: 0,
              active: true,
              width: 120,
              height: 50,
              x: 0,
              y: 0,
              command: 'bash',
              pid: 99999,
              title: 'long output test',
              output: longOutput,
            }
          ]
        }
      ]
    };

    this.mockSessions.set(sessionId, session);
    this.createMockSocketFile(session.socketPath);
    
    return session;
  }

  /**
   * Creates a session that simulates a crashed claude-flow process
   */
  createCrashedSession(sessionId: string = 'crashed-session'): TmuxSession {
    const crashOutput = `
$ claude-flow tdd "implement feature X"
🚀 Starting Claude Flow TDD...
📋 Analyzing requirements...
🧪 Creating tests...
💻 Implementing solution...
Segmentation fault (core dumped)

[Process exited with code 139]
$ `;

    const session: TmuxSession = {
      id: sessionId,
      name: sessionId,
      created: Date.now() - 1800000, // 30 minutes ago
      lastAccessed: Date.now() - 600000, // 10 minutes ago
      status: 'dead',
      socketPath: `/tmp/tmux-sockets/${sessionId}`,
      workingDirectory: '/home/user/failed-project',
      environment: {},
      windows: [
        {
          id: 0,
          name: 'crashed-claude-flow',
          active: true,
          layout: 'tiled',
          panes: [
            {
              id: 0,
              active: true,
              width: 80,
              height: 24,
              x: 0,
              y: 0,
              command: 'bash',
              pid: 0, // Process died
              title: 'crashed session',
              output: crashOutput,
            }
          ]
        }
      ]
    };

    this.mockSessions.set(sessionId, session);
    // Don't create socket file for crashed session
    
    return session;
  }

  /**
   * Creates multiple sessions for concurrent testing
   */
  createConcurrentSessions(count: number = 5): TmuxSession[] {
    const sessions: TmuxSession[] = [];
    
    for (let i = 0; i < count; i++) {
      const sessionId = `concurrent-session-${i}`;
      const session = this.createSimpleSession(sessionId);
      
      // Modify each session to have different characteristics
      session.windows[0].panes[0].command = `claude-flow worker-${i}`;
      session.windows[0].panes[0].output = `$ claude-flow worker-${i}\n🤖 Worker ${i} started\n⚡ Processing tasks...\n`;
      session.workingDirectory = `/tmp/worker-${i}`;
      
      sessions.push(session);
    }
    
    return sessions;
  }

  /**
   * Creates test data files for complex scenarios
   */
  async createTestDataFiles(): Promise<void> {
    if (!fs.existsSync(this.fixtureDir)) {
      fs.mkdirSync(this.fixtureDir, { recursive: true });
    }

    // Create sample command history
    const commandHistory = [
      'claude-flow --help',
      'claude-flow sparc modes',
      'claude-flow swarm init --topology mesh',
      'claude-flow agent spawn --type coder --name "test-coder"',
      'claude-flow tdd "create user service"',
      'git status',
      'npm test',
      'git add .',
      'git commit -m "Add user service with tests"',
      'claude-flow performance report',
    ];

    fs.writeFileSync(
      path.join(this.fixtureDir, 'command-history.txt'),
      commandHistory.join('\n')
    );

    // Create sample session configurations
    const sessionConfigs = {
      development: {
        windows: ['claude-flow-main', 'testing', 'monitoring', 'shell'],
        defaultCommand: 'claude-flow tdd',
        workingDirectory: '/home/user/development',
      },
      production: {
        windows: ['claude-flow-prod', 'logs', 'metrics'],
        defaultCommand: 'claude-flow agent spawn --type production-validator',
        workingDirectory: '/opt/claude-flow',
      },
    };

    fs.writeFileSync(
      path.join(this.fixtureDir, 'session-configs.json'),
      JSON.stringify(sessionConfigs, null, 2)
    );

    // Create sample tmux configuration
    const tmuxConfig = `
# Claude Flow tmux configuration
set-option -g prefix C-b
bind-key C-b send-prefix

# Window management
bind-key c new-window -c "#{pane_current_path}"
bind-key | split-window -h -c "#{pane_current_path}"
bind-key - split-window -v -c "#{pane_current_path}"

# Claude Flow specific bindings
bind-key F new-window 'claude-flow sparc modes'
bind-key S new-window 'claude-flow swarm init --topology adaptive'
bind-key T new-window 'claude-flow tdd'

# Status bar
set-option -g status-left "[#S] "
set-option -g status-right "#{?client_prefix,🔥,} %H:%M %d-%b-%y"
set-option -g status-style "bg=colour234,fg=colour137"
`;

    fs.writeFileSync(
      path.join(this.fixtureDir, 'tmux.conf'),
      tmuxConfig
    );
  }

  /**
   * Simulates tmux server responses for various commands
   */
  getTmuxCommandOutput(command: string, args: string[]): string {
    const [subcommand] = args;

    switch (subcommand) {
      case 'list-sessions':
        return Array.from(this.mockSessions.values())
          .filter(s => s.status === 'active')
          .map(s => `${s.name}: ${s.windows.length} windows (created ${new Date(s.created).toLocaleString()}) [${s.windows[0]?.panes[0]?.width || 80}x${s.windows[0]?.panes[0]?.height || 24}]`)
          .join('\n');

      case 'has-session':
        const sessionName = args[args.indexOf('-t') + 1];
        return this.mockSessions.has(sessionName) ? '' : 'session not found';

      case 'capture-pane':
        const captureSession = args[args.indexOf('-t') + 1];
        const session = this.mockSessions.get(captureSession);
        return session?.windows[0]?.panes[0]?.output || '';

      case 'list-windows':
        const windowSession = args[args.indexOf('-t') + 1];
        const windowSessionData = this.mockSessions.get(windowSession);
        return windowSessionData?.windows.map((w, i) => 
          `${i}: ${w.name}${w.active ? '*' : '-'} (${w.panes.length} panes)`
        ).join('\n') || '';

      case 'list-panes':
        const paneSession = args[args.indexOf('-t') + 1];
        const paneSessionData = this.mockSessions.get(paneSession);
        return paneSessionData?.windows[0]?.panes.map((p, i) => 
          `${i}: [${p.width}x${p.height}] [${p.command}] (${p.active ? 'active' : 'inactive'})`
        ).join('\n') || '';

      default:
        return '';
    }
  }

  /**
   * Generates realistic claude-flow output
   */
  private getClaudeFlowOutput(): string {
    return `
$ claude-flow tdd "implement user authentication"
🚀 Starting Claude Flow TDD Workflow...

📋 SPECIFICATION Phase
   ├── Analyzing requirements: user authentication
   ├── Identifying key components: login, signup, session management
   └── Creating user stories... ✓

🧪 TEST DESIGN Phase
   ├── Creating unit tests for UserService
   ├── Creating integration tests for auth endpoints
   ├── Setting up test fixtures
   └── Test suite created ✓

🏗️  ARCHITECTURE Phase
   ├── Designing authentication flow
   ├── Planning database schema
   ├── Setting up middleware structure
   └── Architecture documented ✓

⚡ IMPLEMENTATION Phase
   ├── Implementing UserService class... ✓
   ├── Creating auth middleware... ✓
   ├── Building login endpoint... ✓
   ├── Building signup endpoint... 🔄 In Progress
   │   └── Adding validation logic...
   │   └── Implementing password hashing...
   │   └── Creating database integration...
   
Current Status: 75% Complete
Next: Complete signup endpoint and run integration tests

[Agent: coder-001] Working on password validation
[Agent: tester-002] Preparing test scenarios
[Agent: reviewer-003] Reviewing security patterns

$ `;
  }

  /**
   * Generates realistic htop output
   */
  private getHtopOutput(): string {
    return `
  1  [██████████████████████████████████████████████████ 52.3%]   Tasks: 127, 64 thr; 2 running
  2  [█████████████████████████████████████████████████  48.9%]   Load average: 1.23 0.87 0.64 
  3  [███████████████████████████████████████████████    41.2%]   Uptime: 2 days, 14:23:17
  4  [████████████████████████████████████████████████   45.7%]   
  Mem[████████████████████████████████████████████  14.2G/16.0G]
  Swp[                                              0K/2.00G]

    PID USER      PRI  NI  VIRT   RES   SHR S CPU% MEM%   TIME+  Command
  12345 user       20   0  856M  124M   45M S 15.2  0.8  2:34.56 node server.js
  12346 user       20   0  1.2G  256M   78M S 12.8  1.6  1:45.23 claude-flow tdd
  12347 user       20   0  234M   89M   32M S  8.4  0.6  0:34.12 node websocket-server.js
   1234 user       20   0  145M   67M   23M S  3.2  0.4  0:12.45 tmux: server
   5678 root       20   0  234M   45M   21M S  1.8  0.3  5:23.67 systemd
   9876 user       20   0   89M   23M   12M S  0.8  0.1  0:05.43 bash
`;
  }

  /**
   * Generates realistic log output
   */
  private getLogOutput(): string {
    return `
[2025-01-01T12:34:56.789Z] INFO  [claude-flow] Starting TDD workflow for user authentication
[2025-01-01T12:34:57.123Z] INFO  [swarm] Initialized mesh topology with 3 agents
[2025-01-01T12:34:57.456Z] INFO  [agent-coder] Starting implementation phase
[2025-01-01T12:34:58.789Z] DEBUG [tmux-session] Session created: tdd-auth-session-001
[2025-01-01T12:35:00.123Z] INFO  [test-runner] Running 15 unit tests...
[2025-01-01T12:35:02.456Z] PASS  [test-runner] UserService.test.ts - 8/8 tests passed
[2025-01-01T12:35:03.789Z] PASS  [test-runner] AuthMiddleware.test.ts - 5/5 tests passed
[2025-01-01T12:35:05.123Z] WARN  [security] Password validation needs strengthening
[2025-01-01T12:35:06.456Z] INFO  [agent-reviewer] Code review completed - 2 suggestions
[2025-01-01T12:35:07.789Z] INFO  [performance] Memory usage: 245MB, CPU: 23%
[2025-01-01T12:35:09.123Z] INFO  [git-integration] Auto-commit: "Implement user signup validation"
`;
  }

  /**
   * Generates random content for testing
   */
  private generateRandomContent(): string {
    const samples = [
      'Processing user authentication request...',
      'Database connection established successfully',
      'Validating input parameters',
      'Generating secure password hash',
      'Creating user session token',
      'Logging security event',
      'Updating user preferences',
      'Running automated tests',
      'Checking code coverage metrics',
      'Optimizing query performance',
      'Deploying to staging environment',
      'Monitoring system health',
    ];
    
    return samples[Math.floor(Math.random() * samples.length)];
  }

  /**
   * Creates mock socket file entries
   */
  private createMockSocketFile(socketPath: string): void {
    this.mockSocketFiles.set(socketPath, {
      path: socketPath,
      created: Date.now(),
      permissions: 0o600,
      uid: process.getuid?.() || 1000,
      gid: process.getgid?.() || 1000,
      size: 0,
      isSocket: true,
    });
  }

  /**
   * Retrieves a mock session by ID
   */
  getSession(sessionId: string): TmuxSession | undefined {
    return this.mockSessions.get(sessionId);
  }

  /**
   * Retrieves all mock sessions
   */
  getAllSessions(): TmuxSession[] {
    return Array.from(this.mockSessions.values());
  }

  /**
   * Clears all mock data
   */
  clearAll(): void {
    this.mockSessions.clear();
    this.mockSocketFiles.clear();
  }

  /**
   * Simulates session state changes
   */
  simulateSessionDeath(sessionId: string): void {
    const session = this.mockSessions.get(sessionId);
    if (session) {
      session.status = 'dead';
      session.windows.forEach(window => {
        window.panes.forEach(pane => {
          pane.pid = 0;
          pane.output += '\n[Process exited]\n';
        });
      });
    }
  }

  /**
   * Simulates adding new output to a session
   */
  simulateOutput(sessionId: string, newOutput: string, windowId: number = 0, paneId: number = 0): void {
    const session = this.mockSessions.get(sessionId);
    if (session && session.windows[windowId]?.panes[paneId]) {
      session.windows[windowId].panes[paneId].output += newOutput;
      session.lastAccessed = Date.now();
    }
  }

  /**
   * Simulates window/pane creation
   */
  addWindow(sessionId: string, windowName: string): void {
    const session = this.mockSessions.get(sessionId);
    if (session) {
      const newWindowId = session.windows.length;
      session.windows.push({
        id: newWindowId,
        name: windowName,
        active: false,
        layout: 'tiled',
        panes: [{
          id: 0,
          active: true,
          width: 80,
          height: 24,
          x: 0,
          y: 0,
          command: 'bash',
          pid: Math.floor(Math.random() * 90000) + 10000,
          title: windowName,
          output: `$ # New window: ${windowName}\n$ `,
        }]
      });
    }
  }

  /**
   * Exports fixture data for external testing tools
   */
  exportFixtures(): any {
    return {
      sessions: Object.fromEntries(this.mockSessions),
      sockets: Object.fromEntries(this.mockSocketFiles),
      metadata: {
        generated: Date.now(),
        totalSessions: this.mockSessions.size,
        totalSockets: this.mockSocketFiles.size,
      }
    };
  }
}

// Export singleton instance
export const tmuxFixtures = TmuxFixtures.getInstance();

// Export helper functions for test setup
export const setupTmuxFixtures = () => {
  beforeEach(() => {
    tmuxFixtures.clearAll();
  });
};

export const createTestSessions = () => {
  return {
    simple: tmuxFixtures.createSimpleSession(),
    complex: tmuxFixtures.createComplexSession(),
    longOutput: tmuxFixtures.createLongOutputSession(),
    crashed: tmuxFixtures.createCrashedSession(),
    concurrent: tmuxFixtures.createConcurrentSessions(),
  };
};