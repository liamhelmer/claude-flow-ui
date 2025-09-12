/**
 * Type definitions for tmux session management
 */

export interface TmuxPane {
  id: number;
  active: boolean;
  width: number;
  height: number;
  x: number;
  y: number;
  command: string;
  pid: number;
  title: string;
  output: string;
}

export interface TmuxWindow {
  id: number;
  name: string;
  active: boolean;
  layout: string;
  panes: TmuxPane[];
}

export interface TmuxSession {
  id: string;
  name: string;
  created: number;
  lastAccessed: number;
  status: 'active' | 'dead';
  socketPath: string;
  workingDirectory: string;
  environment: Record<string, string>;
  windows: TmuxWindow[];
}