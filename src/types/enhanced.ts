/**
 * Enhanced TypeScript type definitions for Claude Flow UI
 * Provides comprehensive type safety and documentation for all interfaces
 */

import { ReactNode } from 'react';

/**
 * Terminal session interface
 * Represents a single terminal session with its metadata
 */
export interface TerminalSession {
  /** Unique identifier for the terminal session */
  id: string;
  /** Display name for the terminal session */
  name: string;
  /** Whether this session is currently active/selected */
  isActive: boolean;
  /** Timestamp of last activity in this session */
  lastActivity: Date;
  /** Optional metadata about the session */
  metadata?: {
    /** The command that started this terminal */
    command?: string;
    /** Current working directory */
    workingDirectory?: string;
    /** Environment variables */
    environment?: Record<string, string>;
    /** Process ID of the terminal process */
    pid?: number;
    /** Exit code if the terminal has exited */
    exitCode?: number;
    /** Signal that terminated the terminal if applicable */
    signal?: string;
  };
}

/**
 * Supported WebSocket message types
 */
export type WebSocketMessageType =
  | 'data'
  | 'resize'
  | 'create'
  | 'destroy'
  | 'list'
  | 'switch-session'
  | 'terminal-data'
  | 'terminal-error'
  | 'terminal-config'
  | 'session-created'
  | 'session-destroyed'
  | 'terminal-spawned'
  | 'terminal-closed'
  | 'connection-change'
  | 'refresh-history'
  | 'ping'
  | 'pong'
  | 'ack';

/**
 * WebSocket message interface
 * Defines the structure of messages sent between client and server
 */
export interface WebSocketMessage {
  /** Message type identifier */
  type: WebSocketMessageType;
  /** Target session ID (optional for broadcast messages) */
  sessionId?: string;
  /** Message payload data */
  data?: any;
  /** Number of columns for resize messages */
  cols?: number;
  /** Number of rows for resize messages */
  rows?: number;
  /** Timestamp when message was created */
  timestamp?: number;
  /** Message ID for tracking and acknowledgments */
  messageId?: string;
  /** Whether this message requires acknowledgment */
  requiresAck?: boolean;
}

/**
 * Connection status enumeration
 */
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/**
 * Performance metrics interface
 */
export interface PerformanceMetrics {
  /** Number of messages sent/received */
  messageCount: number;
  /** Average response time in milliseconds */
  averageResponseTime: number;
  /** Number of reconnection attempts */
  reconnectAttempts: number;
  /** Last successful connection timestamp */
  lastConnectedAt?: Date;
  /** Memory usage statistics */
  memoryUsage?: {
    /** Used heap size in bytes */
    usedJSHeapSize?: number;
    /** Total heap size in bytes */
    totalJSHeapSize?: number;
    /** Heap size limit in bytes */
    jsHeapSizeLimit?: number;
  };
}

/**
 * Application state interface
 * Defines the global state structure for the application
 */
export interface AppState {
  /** Array of all terminal sessions */
  terminalSessions: TerminalSession[];
  /** ID of the currently active/selected session */
  activeSessionId: string | null;
  /** Whether the sidebar is open/visible */
  sidebarOpen: boolean;
  /** Whether the app is in a loading state */
  loading: boolean;
  /** Current error message if any */
  error: string | null;
  /** Connection status to the backend */
  connectionStatus?: ConnectionStatus;
  /** Performance metrics for monitoring */
  performance?: PerformanceMetrics;
}

/**
 * Terminal configuration interface
 * Defines the visual and behavioral settings for terminal instances
 */
export interface TerminalConfig {
  /** Terminal color theme - defaults to 'dark' */
  theme: 'dark' | 'light';
  /** Font size in pixels - defaults to 14 */
  fontSize: number;
  /** Font family for terminal text - defaults to monospace */
  fontFamily: string;
  /** Whether cursor should blink - defaults to true */
  cursorBlink: boolean;
  /** Number of lines to keep in scrollback buffer - defaults to 50000 */
  scrollback: number;
  /** Number of columns (characters per line) */
  cols: number;
  /** Number of rows (lines) visible in terminal */
  rows: number;
  /** Whether to enable WebGL rendering for better performance */
  enableWebGL?: boolean;
  /** Whether to enable Unicode 11 support */
  enableUnicode11?: boolean;
}

/**
 * Terminal backend configuration
 */
export interface TerminalBackendConfig {
  /** Terminal columns configured on backend */
  cols: number;
  /** Terminal rows configured on backend */
  rows: number;
  /** Shell executable path */
  shell?: string;
  /** Environment variables */
  env?: Record<string, string>;
  /** Working directory */
  cwd?: string;
  /** Whether terminal supports colors */
  supportsColor?: boolean;
  /** Terminal type (e.g., 'xterm-256color') */
  termType?: string;
}

/**
 * Terminal resize event interface
 * Triggered when terminal dimensions change
 */
export interface TerminalResizeEvent {
  /** Session ID of the terminal being resized */
  sessionId: string;
  /** New number of columns */
  cols: number;
  /** New number of rows */
  rows: number;
  /** Timestamp of the resize event */
  timestamp?: number;
  /** Whether the resize was triggered by user action */
  userTriggered?: boolean;
}

/**
 * Terminal data event interface
 * Represents data flowing to/from a terminal
 */
export interface TerminalDataEvent {
  /** Session ID of the terminal */
  sessionId: string;
  /** Raw terminal data (usually ANSI escaped text) */
  data: string;
  /** Optional metadata about the data */
  metadata?: {
    /** Character encoding used */
    encoding?: string;
    /** Whether data contains binary content */
    binary?: boolean;
    /** Size of the data in bytes */
    size?: number;
    /** Whether this data contains cursor position reports */
    hasCursorReport?: boolean;
    /** Whether this data changes echo state */
    hasEchoChange?: boolean;
    /** Current echo state if changed */
    echoState?: 'on' | 'off';
    /** Timestamp when data was generated */
    timestamp?: number;
  };
}

/**
 * Component prop interfaces
 */

export interface TerminalProps {
  /** Session ID for the terminal */
  sessionId: string;
  /** Additional CSS classes */
  className?: string;
  /** Whether to auto-focus on mount */
  autoFocus?: boolean;
  /** Callback for terminal ready state */
  onReady?: () => void;
  /** Callback for terminal errors */
  onError?: (error: Error) => void;
}

export interface TerminalControlsProps {
  /** Refresh terminal content */
  onRefresh: () => void;
  /** Scroll to top of terminal */
  onScrollToTop: () => void;
  /** Scroll to bottom of terminal */
  onScrollToBottom: () => void;
  /** Whether terminal is scrolled to bottom */
  isAtBottom: boolean;
  /** Whether there's new output above current view */
  hasNewOutput: boolean;
  /** Whether refresh is in progress */
  isRefreshing?: boolean;
  /** Terminal configuration from backend */
  terminalConfig?: TerminalBackendConfig | null;
  /** Whether terminal is connected */
  isConnected?: boolean;
}

export interface SidebarProps {
  /** Whether sidebar is open */
  isOpen: boolean;
  /** Toggle sidebar visibility */
  onToggle: () => void;
  /** Array of terminal sessions */
  sessions: TerminalSession[];
  /** Currently active session ID */
  activeSessionId: string | null;
  /** Select a terminal session */
  onSessionSelect: (sessionId: string) => void;
  /** Create a new terminal session */
  onSessionCreate: () => void;
  /** Close a terminal session */
  onSessionClose: (sessionId: string) => void;
  /** Terminal controls props */
  terminalControls?: TerminalControlsProps;
  /** Whether creation is in progress */
  isCreating?: boolean;
  /** Error message if any */
  error?: string | null;
}

export interface TabProps {
  /** Tab title */
  title: string;
  /** Whether tab is currently active */
  isActive: boolean;
  /** Select this tab */
  onSelect: () => void;
  /** Close this tab */
  onClose: () => void;
  /** Whether tab can be closed */
  closable?: boolean;
  /** Additional CSS classes */
  className?: string;
  /** Icon component */
  icon?: ReactNode;
}

/**
 * Error boundary props interface
 */
export interface ErrorBoundaryProps {
  /** Child components to wrap */
  children: ReactNode;
  /** Custom fallback component to show on error */
  fallback?: ReactNode;
  /** Error callback function */
  onError?: (error: Error, errorInfo: any) => void;
  /** Error boundary level for different UI treatments */
  level?: 'page' | 'component';
  /** Name for debugging and logging */
  name?: string;
}

/**
 * Hook options interfaces
 */
export interface UseTerminalOptions {
  /** Session ID for the terminal */
  sessionId: string;
  /** Optional terminal configuration overrides */
  config?: Partial<TerminalConfig>;
  /** Callback for terminal data */
  onData?: (data: string) => void;
  /** Whether to auto-focus the terminal */
  autoFocus?: boolean;
  /** Whether to auto-scroll to bottom on new output */
  autoScroll?: boolean;
}

export interface UseWebSocketOptions {
  /** WebSocket server URL */
  url?: string;
  /** Auto-connect on mount */
  autoConnect?: boolean;
  /** Reconnection settings */
  reconnect?: {
    /** Maximum number of reconnection attempts */
    maxAttempts: number;
    /** Delay between reconnection attempts in ms */
    delay: number;
    /** Maximum delay between attempts in ms */
    maxDelay: number;
  };
}

/**
 * API response interfaces
 */
export interface ApiResponse<T = any> {
  /** Whether the request was successful */
  success: boolean;
  /** Response data */
  data?: T;
  /** Error message if request failed */
  error?: string;
  /** Additional metadata */
  meta?: {
    /** Request timestamp */
    timestamp: string;
    /** Request ID for tracking */
    requestId: string;
    /** API version */
    version: string;
  };
}

export interface TerminalApiResponse extends ApiResponse<{
  /** Terminal session data */
  terminal: TerminalSession;
  /** Backend configuration */
  config: TerminalBackendConfig;
}> {}

export interface TerminalListApiResponse extends ApiResponse<{
  /** Array of terminal sessions */
  terminals: TerminalSession[];
  /** Total count */
  total: number;
}> {}

/**
 * Utility types
 */

/** Function that takes no arguments and returns void */
export type VoidFunction = () => void;

/** Function that takes one argument and returns void */
export type Callback<T = any> = (arg: T) => void;

/** Async function that takes one argument and returns a promise */
export type AsyncCallback<T = any, R = void> = (arg: T) => Promise<R>;

/** Event handler function signature */
export type EventHandler<T = any> = (event: T) => void;

/** Partial recursive type for deep partial objects */
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

/** Make specific properties required */
export type RequireFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

/** Omit multiple properties */
export type OmitMultiple<T, K extends keyof T> = Omit<T, K>;

/** Pick multiple properties and make them required */
export type PickRequired<T, K extends keyof T> = Required<Pick<T, K>>;

/** Extract promise return type */
export type PromiseType<T extends Promise<any>> = T extends Promise<infer U> ? U : never;

/** Extract function return type */
export type ReturnTypeOf<T extends (...args: any[]) => any> = ReturnType<T>;

/** Make all properties optional recursively */
export type DeepOptional<T> = {
  [P in keyof T]?: T[P] extends object ? DeepOptional<T[P]> : T[P];
};

/** Theme type */
export type Theme = 'dark' | 'light';

/** Status indicators */
export type Status = 'idle' | 'loading' | 'success' | 'error';

/** Size variants */
export type Size = 'xs' | 'sm' | 'md' | 'lg' | 'xl';

/** Color variants */
export type ColorVariant = 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info';

