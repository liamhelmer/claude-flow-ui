'use client';

import { useEffect, useState } from 'react';
import { useTerminal } from '@/hooks/useTerminal';
import TerminalControls from './TerminalControls';
import { cn } from '@/lib/utils';
import { useCallback } from 'react';
import type { TerminalProps } from '@/types';

export default function Terminal({ sessionId, className }: TerminalProps) {
  console.debug('[Terminal Component] 🔧 Rendering with sessionId:', sessionId, typeof sessionId);
  console.debug('[Terminal Component] 🔧 Component render state:', {
    hasSessionId: !!sessionId,
    sessionIdType: typeof sessionId,
    sessionIdValue: sessionId
  });
  
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

  // PRODUCTION FIX: Enhanced focus management with production-specific timing
  useEffect(() => {
    if (!sessionId) return;

    console.debug('[Terminal Component] 🎯 Session changed, scheduling focus for:', sessionId, 'env:', process.env.NODE_ENV);

    // PRODUCTION FIX: More aggressive focus attempts in production
    let attempts = 0;
    const maxAttempts = process.env.NODE_ENV === 'production' ? 10 : 5;
    const baseDelay = process.env.NODE_ENV === 'production' ? 50 : 100;

    const attemptFocus = () => {
      attempts++;
      console.debug(`[Terminal Component] 🎯 Focus attempt ${attempts} for session:`, sessionId);

      const success = focusTerminal();

      if (!success && attempts < maxAttempts) {
        // PRODUCTION FIX: Different retry strategy for production
        const delay = process.env.NODE_ENV === 'production'
          ? baseDelay * Math.min(attempts, 3)  // Cap delay growth in production
          : attempts * baseDelay;
        setTimeout(attemptFocus, delay);
      } else if (success) {
        console.debug('[Terminal Component] ✅ Terminal focus successful');
        // PRODUCTION FIX: Immediate fit in production, delayed in development
        const fitDelay = process.env.NODE_ENV === 'production' ? 10 : 50;
        setTimeout(() => {
          fitTerminal();
        }, fitDelay);
      } else {
        console.warn('[Terminal Component] ⚠️ Failed to focus terminal after', maxAttempts, 'attempts');
      }
    };

    // PRODUCTION FIX: Faster initial attempt in production
    const initialDelay = process.env.NODE_ENV === 'production' ? 25 : 100;
    const timer = setTimeout(attemptFocus, initialDelay);

    return () => clearTimeout(timer);
  }, [sessionId, focusTerminal, fitTerminal]);

  // Handle click to focus terminal with enhanced validation
  const handleClick = useCallback(() => {
    console.debug('[Terminal Component] 🎯 Click detected, attempting to focus terminal');
    const success = focusTerminal();
    if (!success) {
      console.warn('[Terminal Component] ⚠️ Focus failed - terminal may not be ready');
      // Retry focus after a short delay
      setTimeout(() => {
        const retrySuccess = focusTerminal();
        if (retrySuccess) {
          console.debug('[Terminal Component] ✅ Focus succeeded on retry');
        } else {
          console.error('[Terminal Component] ❌ Focus failed on retry - terminal input may not work');
        }
      }, 100);
    }
  }, [focusTerminal]);

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
  console.debug('[Terminal Component] 🔧 Display state:', displayState);
  const { width: terminalWidth, height: terminalHeight } = displayState.type === 'ready'
    ? getTerminalDimensions()
    : { width: displayState.width, height: displayState.height };

  return (
    <div className={cn(
      'terminal-outer-container flex justify-start items-start h-full bg-gray-950',
      className
    )}>
      {/* Dynamic-size terminal box - aligned to top-left without padding */}
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
        
        {/* Terminal Content - always render container but hide content when not ready */}
        <div
          className={cn(
            "flex-1 cursor-text select-text",
            // PRODUCTION FIX: Add production-specific classes for better rendering
            process.env.NODE_ENV === 'production' && "transform-gpu will-change-transform"
          )}
          onClick={handleClick}
          style={{
            position: 'relative'
          }}
        >
          <div
            ref={useCallback((element: HTMLDivElement | null) => {
              // PRODUCTION FIX: Always log ref changes for debugging
              console.debug('[Terminal Component] 🔧 Stable ref callback:', {
                hasElement: !!element,
                sessionId,
                env: process.env.NODE_ENV,
                elementClass: element?.className
              });
              if (terminalRef && 'current' in terminalRef) {
                // Only set the ref if we have an actual element
                // Don't clear it when React passes null during re-renders
                if (element) {
                  terminalRef.current = element;
                  console.debug('[Terminal Component] 🔧 Container element attached to ref');

                  // PRODUCTION FIX: Mark container as active to prevent disconnection
                  if (process.env.NODE_ENV === 'production') {
                    element.classList.add('terminal-active');
                    element.setAttribute('data-session-id', sessionId);
                  }
                } else {
                  console.debug('[Terminal Component] 🔧 Ignoring null callback - preserving existing container');
                }
              }
            }, [terminalRef, sessionId])}
            className={cn(
              "xterm-wrapper",
              // PRODUCTION FIX: Production-specific optimizations
              process.env.NODE_ENV === 'production' && "backface-visibility-hidden translate3d-0"
            )}
            style={{
              position: 'relative',
              visibility: displayState.type === 'ready' ? 'visible' : 'hidden',
              // PRODUCTION FIX: Force GPU acceleration in production
              ...(process.env.NODE_ENV === 'production' && {
                transform: 'translateZ(0)',
                willChange: 'transform'
              })
            }}
          />
        </div>

      </div>
    </div>
  );
}