'use client';

import { useEffect, useState } from 'react';
import { useTerminal } from '@/hooks/useTerminal';
import TerminalControls from './TerminalControls';
import { cn } from '@/lib/utils';
import type { TerminalProps } from '@/types';

export default function Terminal({ sessionId, className }: TerminalProps) {
  console.debug('[Terminal Component] 🔧 Rendering with sessionId:', sessionId, typeof sessionId);
  
  const {
    terminalRef,
    terminal,
    backendTerminalConfig,
    focusTerminal,
    fitTerminal,
    scrollToBottom,
    scrollToTop,
    refreshTerminal,
    isAtBottom,
    hasNewOutput,
    configError,
    configRequestInProgress,
  } = useTerminal({
    sessionId,
  });
  
  console.debug('[Terminal Component] 🔧 Hook result:', {
    terminalRef: terminalRef,
    hasTerminal: !!terminal,
    backendConfig: backendTerminalConfig,
    configError,
    configRequestInProgress,
    sessionId: sessionId
  });

  const [isRefreshing, setIsRefreshing] = useState(false);

  // Handle refresh with loading state
  const handleRefresh = () => {
    setIsRefreshing(true);
    refreshTerminal();
    // Reset refreshing state after a delay
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  // Focus terminal when session becomes active
  useEffect(() => {
    const timer = setTimeout(() => {
      focusTerminal();
      // Add extra delay for fitTerminal to ensure element dimensions are available
      setTimeout(() => {
        fitTerminal();
      }, 200);
    }, 100);

    return () => clearTimeout(timer);
  }, [sessionId, focusTerminal, fitTerminal]);

  // Handle click to focus terminal
  const handleClick = () => {
    focusTerminal();
  };

  // Show loading or error states
  const getDisplayState = () => {
    if (configError) {
      return { 
        type: 'error' as const, 
        message: `Failed to load terminal configuration: ${configError}`,
        width: 500,
        height: 200
      };
    }
    
    if (configRequestInProgress || !backendTerminalConfig) {
      return { 
        type: 'loading' as const, 
        message: 'Loading terminal configuration...',
        width: 400,
        height: 200
      };
    }
    
    return { type: 'ready' as const };
  };
  
  // Calculate dynamic terminal dimensions from backend configuration
  const getTerminalDimensions = () => {
    // Use backend terminal configuration for window sizing
    if (!backendTerminalConfig) return { width: 400, height: 300 }; // Minimal fallback when no backend config
    
    const cols = backendTerminalConfig.cols;
    const rows = backendTerminalConfig.rows;
    
    // If no backend dimensions are available yet, use minimal size
    if (!cols || !rows) {
      return { width: 400, height: 300 };
    }
    
    // Approximate: 8px char width, 20px line height for monospace
    const width = (cols * 8) + 100; // Extra for controls and padding
    const height = (rows * 20) + 100; // Extra for padding
    return { width, height };
  };

  const displayState = getDisplayState();
  const { width: terminalWidth, height: terminalHeight } = displayState.type === 'ready' 
    ? getTerminalDimensions()
    : { width: displayState.width, height: displayState.height };

  return (
    <div className={cn(
      'terminal-outer-container flex justify-center items-center h-full bg-gray-950 p-4',
      className
    )}>
      {/* Dynamic-size terminal box */}
      <div 
        className={cn(
          'terminal-container relative flex bg-[#1e1e1e] border border-gray-700 rounded-lg shadow-2xl',
          displayState.type !== 'ready' && 'items-center justify-center'
        )}
        style={{
          width: `${terminalWidth}px`,
          height: `${terminalHeight}px`,
          maxWidth: `${terminalWidth}px`,
          maxHeight: `${terminalHeight}px`,
          minWidth: `${terminalWidth}px`,
          minHeight: `${terminalHeight}px`,
          flexShrink: 0,
          flexGrow: 0
        }}
      >
        
        {/* Show loading or error states */}
        {displayState.type === 'loading' && (
          <div className="flex flex-col items-center justify-center text-gray-300">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-400 mb-4"></div>
            <div className="text-sm">{displayState.message}</div>
          </div>
        )}
        
        {displayState.type === 'error' && (
          <div className="flex flex-col items-center justify-center text-red-400 px-4">
            <div className="text-4xl mb-4">⚠️</div>
            <div className="text-sm text-center">{displayState.message}</div>
            <button 
              onClick={() => window.location.reload()} 
              className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
            >
              Retry
            </button>
          </div>
        )}
        
        {/* Terminal Content - only show when ready */}
        {displayState.type === 'ready' && (
          <div 
            className="flex-1 cursor-text select-text"
            onClick={handleClick}
          >
            <div
              ref={(el) => {
                console.debug('[Terminal Component] 🔧 Ref callback called:', el);
                if (terminalRef && typeof terminalRef === 'object' && 'current' in terminalRef) {
                  terminalRef.current = el;
                }
              }}
              className="xterm-wrapper"
              style={{
                position: 'relative',
              }}
            />
          </div>
        )}

      </div>
    </div>
  );
}