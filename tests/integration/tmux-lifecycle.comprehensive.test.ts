/**
 * Comprehensive Tmux Session Lifecycle Integration Tests
 * Tests tmux session creation, management, and cleanup
 */

import { spawn, ChildProcess } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';

// Mock child_process for testing
jest.mock('child_process', () => ({
  spawn: jest.fn(),
}));

const mockSpawn = spawn as jest.MockedFunction<typeof spawn>;

interface MockProcess {
  pid: number;
  stdout: {
    on: jest.Mock;
    pipe: jest.Mock;
    setEncoding: jest.Mock;
  };
  stderr: {
    on: jest.Mock;
    pipe: jest.Mock;
    setEncoding: jest.Mock;
  };
  stdin: {
    write: jest.Mock;
    end: jest.Mock;
  };
  on: jest.Mock;
  kill: jest.Mock;
  removeAllListeners: jest.Mock;
  exitCode: number | null;
  killed: boolean;
}

describe('Tmux Session Lifecycle Integration Tests', () => {
  let mockProcess: MockProcess;

  beforeEach(() => {
    mockProcess = {
      pid: 12345,
      stdout: {
        on: jest.fn(),
        pipe: jest.fn(),
        setEncoding: jest.fn(),
      },
      stderr: {
        on: jest.fn(),
        pipe: jest.fn(),
        setEncoding: jest.fn(),
      },
      stdin: {
        write: jest.fn(),
        end: jest.fn(),
      },
      on: jest.fn(),
      kill: jest.fn(),
      removeAllListeners: jest.fn(),
      exitCode: null,
      killed: false,
    };

    mockSpawn.mockReturnValue(mockProcess as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Session Creation', () => {
    test('should create new tmux session with proper configuration', async () => {
      const createSession = (sessionName: string, options: any = {}) => {
        const args = [
          'new-session',
          '-d',
          '-s', sessionName,
          '-x', (options.cols || 80).toString(),
          '-y', (options.rows || 24).toString(),
        ];

        if (options.workingDir) {
          args.push('-c', options.workingDir);
        }

        return spawn('tmux', args);
      };

      const sessionName = 'test-session-1';
      const options = { cols: 120, rows: 40, workingDir: '/home/user' };

      const process = createSession(sessionName, options);

      expect(mockSpawn).toHaveBeenCalledWith('tmux', [
        'new-session',
        '-d',
        '-s', sessionName,
        '-x', '120',
        '-y', '40',
        '-c', '/home/user',
      ]);

      expect(process).toBe(mockProcess);
    });

    test('should handle session creation failure gracefully', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') {
          setTimeout(() => callback(new Error('tmux command not found')), 10);
        }
      });

      const createSession = (sessionName: string) => {
        const process = spawn('tmux', ['new-session', '-d', '-s', sessionName]);
        
        return new Promise((resolve, reject) => {
          process.on('error', reject);
          process.on('exit', (code) => {
            if (code === 0) {
              resolve(sessionName);
            } else {
              reject(new Error(`Session creation failed with code ${code}`));
            }
          });
        });
      };

      await expect(createSession('test-session')).rejects.toThrow('tmux command not found');
    });

    test('should create session with unique names when conflicts occur', async () => {
      let attemptCount = 0;
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          attemptCount++;
          // First attempt fails (session exists), second succeeds
          const exitCode = attemptCount === 1 ? 1 : 0;
          setTimeout(() => callback(exitCode), 10);
        }
      });

      const createUniqueSession = async (baseName: string): Promise<string> => {
        let sessionName = baseName;
        let attempt = 0;
        
        while (attempt < 10) {
          try {
            const process = spawn('tmux', ['new-session', '-d', '-s', sessionName]);
            
            const result = await new Promise<number>((resolve) => {
              process.on('exit', resolve);
            });

            if (result === 0) {
              return sessionName;
            }
            
            attempt++;
            sessionName = `${baseName}-${attempt}`;
          } catch (error) {
            throw error;
          }
        }
        
        throw new Error('Could not create unique session name');
      };

      const sessionName = await createUniqueSession('test-session');
      expect(sessionName).toBe('test-session-1');
      expect(attemptCount).toBe(2);
    });
  });

  describe('Session Management', () => {
    test('should list active sessions correctly', async () => {
      const mockSessionsOutput = 'session-1: 1 windows (created Wed Sep 11 12:00:00 2024)\nsession-2: 2 windows (created Wed Sep 11 12:05:00 2024)\n';
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') {
          setTimeout(() => callback(Buffer.from(mockSessionsOutput)), 10);
        }
      });

      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), 20);
        }
      });

      const listSessions = (): Promise<string[]> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', ['list-sessions']);
          let output = '';

          process.stdout.on('data', (data) => {
            output += data.toString();
          });

          process.on('exit', (code) => {
            if (code === 0) {
              const sessions = output
                .trim()
                .split('\n')
                .filter(line => line.length > 0)
                .map(line => line.split(':')[0]);
              resolve(sessions);
            } else {
              reject(new Error(`Failed to list sessions: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      const sessions = await listSessions();
      expect(sessions).toEqual(['session-1', 'session-2']);
    });

    test('should handle session attachment and detachment', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), 10);
        }
      });

      const attachToSession = (sessionName: string): Promise<void> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', ['attach-session', '-t', sessionName]);
          
          process.on('exit', (code) => {
            if (code === 0) {
              resolve();
            } else {
              reject(new Error(`Failed to attach to session: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      const detachFromSession = (sessionName: string): Promise<void> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', ['detach-client', '-s', sessionName]);
          
          process.on('exit', (code) => {
            if (code === 0) {
              resolve();
            } else {
              reject(new Error(`Failed to detach from session: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      await expect(attachToSession('test-session')).resolves.toBeUndefined();
      await expect(detachFromSession('test-session')).resolves.toBeUndefined();
    });

    test('should resize session windows correctly', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), 10);
        }
      });

      const resizeSession = (sessionName: string, cols: number, rows: number): Promise<void> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', [
            'resize-window',
            '-t', sessionName,
            '-x', cols.toString(),
            '-y', rows.toString(),
          ]);

          process.on('exit', (code) => {
            if (code === 0) {
              resolve();
            } else {
              reject(new Error(`Failed to resize session: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      await expect(resizeSession('test-session', 120, 40)).resolves.toBeUndefined();
      
      expect(mockSpawn).toHaveBeenCalledWith('tmux', [
        'resize-window',
        '-t', 'test-session',
        '-x', '120',
        '-y', '40',
      ]);
    });
  });

  describe('Session Communication', () => {
    test('should send commands to session successfully', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), 10);
        }
      });

      const sendCommand = (sessionName: string, command: string): Promise<void> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', [
            'send-keys',
            '-t', sessionName,
            command,
            'Enter',
          ]);

          process.on('exit', (code) => {
            if (code === 0) {
              resolve();
            } else {
              reject(new Error(`Failed to send command: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      const command = 'ls -la';
      await expect(sendCommand('test-session', command)).resolves.toBeUndefined();
      
      expect(mockSpawn).toHaveBeenCalledWith('tmux', [
        'send-keys',
        '-t', 'test-session',
        command,
        'Enter',
      ]);
    });

    test('should capture session output correctly', async () => {
      const mockOutput = 'total 42\ndrwxr-xr-x 5 user user 4096 Sep 11 12:00 .\ndrwxr-xr-x 3 user user 4096 Sep 11 11:00 ..\n';
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') {
          setTimeout(() => callback(Buffer.from(mockOutput)), 10);
        }
      });

      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), 20);
        }
      });

      const captureOutput = (sessionName: string): Promise<string> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', [
            'capture-pane',
            '-t', sessionName,
            '-p',
          ]);

          let output = '';
          process.stdout.on('data', (data) => {
            output += data.toString();
          });

          process.on('exit', (code) => {
            if (code === 0) {
              resolve(output);
            } else {
              reject(new Error(`Failed to capture output: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      const output = await captureOutput('test-session');
      expect(output).toBe(mockOutput);
    });

    test('should handle binary data transmission', async () => {
      const binaryData = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xFF]);
      
      mockProcess.stdin.write.mockImplementation((data) => {
        expect(Buffer.isBuffer(data) || typeof data === 'string').toBe(true);
        return true;
      });

      const sendBinaryData = (sessionName: string, data: Buffer): Promise<void> => {
        return new Promise((resolve) => {
          const process = spawn('tmux', ['send-keys', '-t', sessionName]);
          process.stdin.write(data);
          process.stdin.end();
          resolve();
        });
      };

      await sendBinaryData('test-session', binaryData);
      expect(mockProcess.stdin.write).toHaveBeenCalledWith(binaryData);
    });
  });

  describe('Session Cleanup and Termination', () => {
    test('should kill session gracefully', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), 10);
        }
      });

      const killSession = (sessionName: string): Promise<void> => {
        return new Promise((resolve, reject) => {
          const process = spawn('tmux', ['kill-session', '-t', sessionName]);
          
          process.on('exit', (code) => {
            if (code === 0) {
              resolve();
            } else {
              reject(new Error(`Failed to kill session: ${code}`));
            }
          });

          process.on('error', reject);
        });
      };

      await expect(killSession('test-session')).resolves.toBeUndefined();
      
      expect(mockSpawn).toHaveBeenCalledWith('tmux', [
        'kill-session',
        '-t', 'test-session',
      ]);
    });

    test('should clean up orphaned sessions on server restart', async () => {
      // Mock tmux server restart scenario
      let serverState = 'running';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          const exitCode = serverState === 'running' ? 0 : 1;
          setTimeout(() => callback(exitCode), 10);
        }
      });

      const cleanupOrphanedSessions = async (): Promise<string[]> => {
        try {
          // First, try to list sessions
          const process = spawn('tmux', ['list-sessions']);
          
          const exitCode = await new Promise<number>((resolve) => {
            process.on('exit', resolve);
          });

          if (exitCode !== 0) {
            // No tmux server running, no sessions to clean up
            return [];
          }

          // If server is running, kill all sessions
          const killProcess = spawn('tmux', ['kill-server']);
          await new Promise<number>((resolve) => {
            killProcess.on('exit', resolve);
          });

          return ['server-killed'];
        } catch (error) {
          return ['cleanup-failed'];
        }
      };

      // Simulate server not running
      serverState = 'stopped';
      let result = await cleanupOrphanedSessions();
      expect(result).toEqual([]);

      // Simulate server running
      serverState = 'running';
      result = await cleanupOrphanedSessions();
      expect(result).toEqual(['server-killed']);
    });

    test('should handle zombie process cleanup', async () => {
      const zombieProcesses: MockProcess[] = [];
      
      // Create several mock processes that become zombies
      for (let i = 0; i < 5; i++) {
        const zombie = { ...mockProcess, pid: 12345 + i, killed: false };
        zombieProcesses.push(zombie);
      }

      const cleanupZombies = (processes: MockProcess[]): number => {
        let cleaned = 0;
        processes.forEach(proc => {
          if (!proc.killed) {
            proc.kill('SIGTERM');
            proc.killed = true;
            cleaned++;
          }
        });
        return cleaned;
      };

      const cleanedCount = cleanupZombies(zombieProcesses);
      expect(cleanedCount).toBe(5);
      
      zombieProcesses.forEach(proc => {
        expect(proc.kill).toHaveBeenCalledWith('SIGTERM');
        expect(proc.killed).toBe(true);
      });
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle tmux server not available', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') {
          setTimeout(() => callback(new Error('ENOENT: no such file or directory, spawn tmux')), 10);
        }
      });

      const checkTmuxAvailability = (): Promise<boolean> => {
        return new Promise((resolve) => {
          const process = spawn('tmux', ['-V']);
          
          process.on('error', () => resolve(false));
          process.on('exit', (code) => resolve(code === 0));
        });
      };

      const isAvailable = await checkTmuxAvailability();
      expect(isAvailable).toBe(false);
    });

    test('should recover from session corruption', async () => {
      let attemptCount = 0;
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          attemptCount++;
          // First attempt fails (corrupted), second succeeds after cleanup
          const exitCode = attemptCount === 1 ? 1 : 0;
          setTimeout(() => callback(exitCode), 10);
        }
      });

      const recoverSession = async (sessionName: string): Promise<boolean> => {
        try {
          // Try to attach to existing session
          let process = spawn('tmux', ['attach-session', '-t', sessionName]);
          let exitCode = await new Promise<number>((resolve) => {
            process.on('exit', resolve);
          });

          if (exitCode !== 0) {
            // Session may be corrupted, try to kill and recreate
            process = spawn('tmux', ['kill-session', '-t', sessionName]);
            await new Promise<number>((resolve) => {
              process.on('exit', resolve);
            });

            // Create new session
            process = spawn('tmux', ['new-session', '-d', '-s', sessionName]);
            exitCode = await new Promise<number>((resolve) => {
              process.on('exit', resolve);
            });

            return exitCode === 0;
          }

          return true;
        } catch (error) {
          return false;
        }
      };

      const recovered = await recoverSession('corrupted-session');
      expect(recovered).toBe(true);
      expect(attemptCount).toBe(2);
    });

    test('should handle concurrent session operations safely', async () => {
      const operations = [];
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => callback(0), Math.random() * 100);
        }
      });

      const performConcurrentOperations = async (sessionName: string): Promise<string[]> => {
        const operations = [
          spawn('tmux', ['send-keys', '-t', sessionName, 'echo "op1"', 'Enter']),
          spawn('tmux', ['send-keys', '-t', sessionName, 'echo "op2"', 'Enter']),
          spawn('tmux', ['resize-window', '-t', sessionName, '-x', '100', '-y', '30']),
          spawn('tmux', ['capture-pane', '-t', sessionName, '-p']),
        ];

        const results = await Promise.allSettled(operations.map(op => 
          new Promise<string>((resolve, reject) => {
            op.on('exit', (code) => code === 0 ? resolve('success') : reject('failed'));
            op.on('error', reject);
          })
        ));

        return results.map(result => 
          result.status === 'fulfilled' ? result.value : 'failed'
        );
      };

      const results = await performConcurrentOperations('concurrent-session');
      
      // All operations should complete (successfully or not) without hanging
      expect(results).toHaveLength(4);
      expect(mockSpawn).toHaveBeenCalledTimes(4);
    });
  });

  describe('Performance and Resource Management', () => {
    test('should manage session count limits', () => {
      const MAX_SESSIONS = 10;
      const activeSessions = new Set<string>();

      const canCreateSession = (sessionName: string): boolean => {
        if (activeSessions.size >= MAX_SESSIONS) {
          return false;
        }
        activeSessions.add(sessionName);
        return true;
      };

      const removeSession = (sessionName: string): boolean => {
        return activeSessions.delete(sessionName);
      };

      // Create sessions up to limit
      for (let i = 0; i < MAX_SESSIONS; i++) {
        expect(canCreateSession(`session-${i}`)).toBe(true);
      }

      // Should reject additional sessions
      expect(canCreateSession('overflow-session')).toBe(false);

      // Remove a session and try again
      expect(removeSession('session-0')).toBe(true);
      expect(canCreateSession('new-session')).toBe(true);
    });

    test('should monitor session memory usage', () => {
      const sessions = new Map<string, { pid: number; memoryUsage: number }>();

      const trackSessionMemory = (sessionName: string, pid: number, memoryMB: number) => {
        sessions.set(sessionName, { pid, memoryUsage: memoryMB });
      };

      const getHighMemorySessions = (thresholdMB: number): string[] => {
        return Array.from(sessions.entries())
          .filter(([_, data]) => data.memoryUsage > thresholdMB)
          .map(([name]) => name);
      };

      // Track some sessions with different memory usage
      trackSessionMemory('light-session', 1001, 50);
      trackSessionMemory('heavy-session', 1002, 200);
      trackSessionMemory('normal-session', 1003, 100);

      const highMemorySessions = getHighMemorySessions(150);
      expect(highMemorySessions).toEqual(['heavy-session']);

      const allSessions = getHighMemorySessions(0);
      expect(allSessions).toHaveLength(3);
    });
  });
});