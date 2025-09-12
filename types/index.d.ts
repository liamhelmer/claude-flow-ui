#!/usr/bin/env node

/**
 * @liamhelmer/claude-flow-ui - Type definitions
 * A modern web-based terminal and monitoring interface for Claude Flow
 */

export interface ClaudeFlowUIOptions {
  /** Port number for the web server */
  port?: number;
  /** Terminal size in format "colsxrows" */
  terminalSize?: string;
  /** Additional arguments to pass to claude-flow */
  claudeFlowArgs?: string[];
}

export interface TerminalConfig {
  /** Terminal columns */
  cols: number;
  /** Terminal rows */
  rows: number;
}

export interface ServerConfig {
  /** HTTP server port */
  port: number;
  /** WebSocket server port */
  wsPort: number;
  /** Development mode */
  dev: boolean;
}

/**
 * Main export - the executable server
 * Can be used as: npx @liamhelmer/claude-flow-ui [options] [claude-flow-args]
 */
declare const claudeFlowUI: {
  /** Default export is the server executable */
  default: void;
};

export default claudeFlowUI;

/**
 * Command line interface for claude-flow-ui
 * 
 * @example
 * ```bash
 * npx @liamhelmer/claude-flow-ui --port 3000
 * npx @liamhelmer/claude-flow-ui --port 8080 swarm --objective "task"
 * ```
 */
export declare function main(args?: string[]): void;

export {};