export interface TerminalSession {
  id: string;
  name: string;
  isActive: boolean;
  lastActivity: Date;
}

export interface WebSocketMessage {
  type: 'data' | 'resize' | 'create' | 'destroy' | 'list';
  sessionId?: string;
  data?: string;
  cols?: number;
  rows?: number;
}

export interface AppState {
  terminalSessions: TerminalSession[];
  activeSessionId: string | null;
  sidebarOpen: boolean;
  loading: boolean;
  error: string | null;
}

export interface TerminalProps {
  sessionId: string;
  className?: string;
}

export interface TerminalControlsProps {
  onRefresh: () => void;
  onScrollToTop: () => void;
  onScrollToBottom: () => void;
  isAtBottom: boolean;
  hasNewOutput: boolean;
  isRefreshing?: boolean;
  terminalConfig?: { cols: number; rows: number } | null;
}

export interface SidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  sessions: TerminalSession[];
  activeSessionId: string | null;
  onSessionSelect: (sessionId: string) => void;
  onSessionCreate: () => void;
  onSessionClose: (sessionId: string) => void;
  terminalControls?: TerminalControlsProps;
}

export interface TabProps {
  title: string;
  isActive: boolean;
  onSelect: () => void;
  onClose: () => void;
  closable?: boolean;
}

export type Theme = 'dark' | 'light';

export interface TerminalConfig {
  theme: Theme;
  fontSize: number;
  fontFamily: string;
  cursorBlink: boolean;
  scrollback: number;
  cols: number;
  rows: number;
}