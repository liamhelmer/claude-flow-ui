import { useEffect, useRef, useCallback, useMemo, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { SerializeAddon } from '@xterm/addon-serialize';
import { useWebSocket } from './useWebSocket';
import { useAppStore } from '@/lib/state/store';
import { terminalConfigService, type TerminalBackendConfig } from '@/services/terminal-config';
import type { TerminalConfig } from '@/types';

// Track if we've logged the waiting message to avoid spam
let hasLoggedWaiting = false;

// Performance optimization: Debounce scroll position checks
const debounce = <T extends (...args: any[]) => void>(func: T, wait: number): T => {
  let timeout: NodeJS.Timeout;
  return ((...args: any[]) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  }) as T;
};

interface UseTerminalOptions {
  sessionId: string;
  config?: Partial<TerminalConfig>;
  onData?: (data: string) => void;
}

export const useTerminal = ({
  sessionId,
  config = {},
  onData
}: UseTerminalOptions) => {
  const terminalRef = useRef<Terminal | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const sessionIdRef = useRef<string>(sessionId);
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [hasNewOutput, setHasNewOutput] = useState(false);
  const [backendTerminalConfig, setBackendTerminalConfig] = useState<TerminalBackendConfig | null>(null);
  // Track echo state and cursor position for proper handling
  const [echoEnabled, setEchoEnabled] = useState(true);
  const [lastCursorPosition, setLastCursorPosition] = useState({ row: 1, col: 1 });
  // Track scroll position for better scrollback behavior - use refs to avoid re-renders
  const scrollHistoryRef = useRef<{position: number, timestamp: number}[]>([]);
  const scrollPositionRef = useRef<number>(0);
  const pendingDataRef = useRef<any[]>([]);
  // Add refs for handlers to prevent stale closures in production
  const handleTerminalDataRef = useRef<(data: any) => void>();
  const handleTerminalErrorRef = useRef<(data: any) => void>();
  const handleConnectionChangeRef = useRef<(connected: boolean) => void>();
  const { sendData, sendMessage, resizeTerminal, on, off, isConnected, connect } = useWebSocket();
  const [configRequestInProgress, setConfigRequestInProgress] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [configRequested, setConfigRequested] = useState(false);
  // Create a unique ID for this hook instance to track listeners
  const hookInstanceId = useRef(Math.random().toString(36).substr(2, 9));

  // Keep sessionIdRef in sync with sessionId prop - CRITICAL: Must be synchronous
  // Use useLayoutEffect to ensure sessionId is updated before any other effects run
  useEffect(() => {
    // Synchronously update the sessionId ref to prevent race conditions
    sessionIdRef.current = sessionId;
    console.debug('[Terminal] 🔧 SessionId ref updated to:', sessionId);
  }, [sessionId]);

  const terminalConfig = useMemo(() => {
    console.debug(`[Terminal] 🔧 terminalConfig useMemo executing - backendTerminalConfig:`, backendTerminalConfig);

    // If no backend config, return minimal config to prevent creation
    if (!backendTerminalConfig) {
      // Only log once per session to avoid spam during re-renders
      if (!hasLoggedWaiting) {
        console.debug('[Terminal] ⏳ Waiting for backend terminal configuration...');
        hasLoggedWaiting = true;
      }
      return {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        cursorBlink: true,
        scrollback: 999999,
        cols: 0, // Zero dimensions prevent terminal creation
        rows: 0, // Zero dimensions prevent terminal creation
      };
    }

    // Reset the wait logged flag and log success when we have config
    if (hasLoggedWaiting) {
      console.debug('[Terminal] ✅ Backend terminal configuration received!');
      hasLoggedWaiting = false;
    }

    const backendCols = backendTerminalConfig.cols;
    const backendRows = backendTerminalConfig.rows;

    const defaultConfig: TerminalConfig = {
      theme: 'dark',
      fontSize: 14,
      fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
      cursorBlink: true,
      scrollback: 999999,  // Effectively unlimited scrollback
      cols: backendCols,  // Use ONLY backend-configured columns
      rows: backendRows,  // Use ONLY backend-configured rows
    };

    console.debug(`[Terminal] 🔧 Config calculated: ${backendCols}x${backendRows} (backend config: available)`);
    return { ...defaultConfig, ...config };
  }, [config, backendTerminalConfig]);

  // Store values in refs so initTerminal can access current values
  const terminalConfigRef = useRef(terminalConfig);
  const sendDataRef = useRef(sendData);
  const onDataRef = useRef(onData);
  const isAtBottomRef = useRef(isAtBottom);
  const hasNewOutputRef = useRef(hasNewOutput);

  // Update refs when values change
  useEffect(() => {
    terminalConfigRef.current = terminalConfig;
  }, [terminalConfig]);

  useEffect(() => {
    sendDataRef.current = sendData;
  }, [sendData]);

  useEffect(() => {
    onDataRef.current = onData;
  }, [onData]);

  useEffect(() => {
    isAtBottomRef.current = isAtBottom;
  }, [isAtBottom]);

  useEffect(() => {
    hasNewOutputRef.current = hasNewOutput;
  }, [hasNewOutput]);

  const initTerminal = useCallback(() => {
    console.debug('[Terminal] 🔧 initTerminal: Starting check...', {
      hasContainer: !!containerRef.current,
      containerElement: containerRef.current,
      hasTerminal: !!terminalRef.current,
      hasConfig: !!terminalConfig,
      cols: terminalConfig?.cols,
      rows: terminalConfig?.rows,
      isConnected,
      hasSendData: typeof sendData === 'function'
    });

    // REMOVED container check - we'll create terminal in memory and attach later

    if (terminalRef.current) {
      console.debug('[Terminal] 🔧 initTerminal: Terminal already exists - skipping creation');
      return;
    }

    const currentConfig = terminalConfigRef.current;

    if (!currentConfig || currentConfig.cols === 0 || currentConfig.rows === 0) {
      console.debug('[Terminal] 🔧 initTerminal: Invalid config', {
        hasConfig: !!currentConfig,
        cols: currentConfig?.cols,
        rows: currentConfig?.rows
      });
      return;
    }

    // Verify we have a working sendData function
    if (!sendData || typeof sendData !== 'function') {
      console.error('[Terminal] 🔧 initTerminal: sendData not available, terminal input will not work!');
      return;
    }
    
    console.debug('[Terminal] 🔧 initTerminal: Creating terminal with verified dimensions:', currentConfig.cols, 'x', currentConfig.rows);

    const terminal = new Terminal({
      // CRITICAL: Single theme configuration optimized for ANSI support
      theme: {
        background: '#1e1e1e',
        foreground: '#f0f0f0',
        cursor: '#00ff00',
        cursorAccent: '#1e1e1e',
        selectionBackground: 'rgba(255, 255, 255, 0.3)',
        selectionInactiveBackground: 'rgba(255, 255, 255, 0.1)',
        
        // Standard ANSI colors (0-7)
        black: '#000000',
        red: '#cd3131',
        green: '#0dbc79',
        yellow: '#e5e510',
        blue: '#2472c8',
        magenta: '#bc3fbc',
        cyan: '#11a8cd',
        white: '#e5e5e5',
        
        // Bright ANSI colors (8-15)
        brightBlack: '#666666',
        brightRed: '#f14c4c',
        brightGreen: '#23d18b',
        brightYellow: '#f5f543',
        brightBlue: '#3b8eea',
        brightMagenta: '#d670d6',
        brightCyan: '#29b8db',
        brightWhite: '#ffffff'
      },
      
      // Font and display settings
      fontSize: currentConfig.fontSize,
      fontFamily: currentConfig.fontFamily,
      fontWeight: 'normal',
      fontWeightBold: 'bold',
      
      // Terminal dimensions
      cols: currentConfig.cols,
      rows: currentConfig.rows,
      
      // CRITICAL: ANSI and escape sequence handling
      allowProposedApi: true,     // Enable experimental APIs for better ANSI support
      convertEol: true,           // Handle line endings properly  
      disableStdin: false,        // Enable input
      drawBoldTextInBrightColors: true,  // Use bright colors for bold text
      
      // Enhanced scrolling and performance
      scrollback: 50000,          // Large scrollback buffer for history
      scrollOnUserInput: true,    // Auto-scroll on input when at bottom
      smoothScrollDuration: 0,    // Disable smooth scrolling for performance
      fastScrollModifier: 'shift',
      fastScrollSensitivity: 5,
      scrollSensitivity: 1,
      
      // Cursor configuration
      cursorBlink: true,
      cursorStyle: 'block',
      cursorInactiveStyle: 'outline',
      
      // Input and keyboard handling
      macOptionIsMeta: true,
      macOptionClickForcesSelection: false,
      
      // Selection and interaction
      altClickMovesCursor: false,
      rightClickSelectsWord: false,
      wordSeparator: ' ()[]{}\'\"',
      
      // Performance and rendering
      allowTransparency: false,   // Better performance
      windowsMode: false,         // Unix-style handling
      minimumContrastRatio: 1,    // Don't adjust contrast automatically
      rescaleOverlappingGlyphs: true,
      
      // Terminal features
      tabStopWidth: 8,
      // Debugging and logging
      
      // Advanced features
      screenReaderMode: false    // Optimize for performance
      
      // CRITICAL: Renderer selection - will be overridden by Canvas addon
    });

    // Load addons for better ANSI support and functionality
    const serializeAddon = new SerializeAddon();
    terminal.loadAddon(serializeAddon);
    
    // Function to open terminal after all critical addons are loaded
    const openTerminalWithAddons = () => {
      // Check if container is available
      if (containerRef.current) {
        terminal.open(containerRef.current);
        console.debug('[Terminal] 🎨 Terminal opened with renderer');
      } else {
        console.warn('[Terminal] ⚠️ Container not available yet, deferring terminal.open()');
        // Store terminal for later attachment when container becomes available
        terminalRef.current = terminal;
      }
    };
    
    // Dynamically load addons only on client side to avoid SSR issues
    if (typeof window !== 'undefined') {
      // Try to load WebGL addon first for best performance
      import('@xterm/addon-webgl').then(({ WebglAddon }) => {
        const webglAddon = new WebglAddon();
        
        // Check if WebGL is supported by opening terminal first (if container available)
        if (containerRef.current) {
          terminal.open(containerRef.current);
        } else {
          console.warn('[Terminal] ⚠️ Container not available for WebGL test, skipping WebGL');
          throw new Error('Container not available for WebGL');
        }
        
        try {
          terminal.loadAddon(webglAddon);
          console.debug('[Terminal] 🚀 WebGL renderer loaded successfully for maximum performance');
        } catch (webglError) {
          console.warn('[Terminal] ⚠️ WebGL not supported, falling back to Canvas renderer:', webglError);
          
          // Fallback to Canvas addon
          import('@xterm/addon-canvas').then(({ CanvasAddon }) => {
            const canvasAddon = new CanvasAddon();
            terminal.loadAddon(canvasAddon);
            console.debug('[Terminal] ✅ Canvas addon loaded as fallback renderer');
          }).catch(canvasError => {
            console.warn('[Terminal] ⚠️ Canvas addon also failed, using DOM renderer:', canvasError);
          });
        }
        
        // Load other addons after renderer is ready
        Promise.all([
          import('@xterm/addon-web-links').then(({ WebLinksAddon }) => {
            const webLinksAddon = new WebLinksAddon();
            terminal.loadAddon(webLinksAddon);
            console.debug('[Terminal] ✅ WebLinks addon loaded');
          }),
          import('@xterm/addon-unicode11').then(({ Unicode11Addon }) => {
            const unicode11Addon = new Unicode11Addon();
            terminal.loadAddon(unicode11Addon);
            terminal.unicode.activeVersion = '11';
            console.debug('[Terminal] ✅ Unicode11 addon loaded for better character support');
          })
        ]).catch(err => {
          console.warn('[Terminal] ⚠️ Some non-critical addons failed to load:', err);
        });
        
      }).catch(err => {
        console.warn('[Terminal] ⚠️ Failed to load WebGL addon, falling back to Canvas:', err);
        
        // Fallback to Canvas addon
        import('@xterm/addon-canvas').then(({ CanvasAddon }) => {
          const canvasAddon = new CanvasAddon();
          terminal.loadAddon(canvasAddon);
          console.debug('[Terminal] ✅ Canvas addon loaded as fallback renderer');
          
          // Open terminal with Canvas renderer
          openTerminalWithAddons();
          
          // Load other addons after Canvas is ready
          Promise.all([
            import('@xterm/addon-web-links').then(({ WebLinksAddon }) => {
              const webLinksAddon = new WebLinksAddon();
              terminal.loadAddon(webLinksAddon);
              console.debug('[Terminal] ✅ WebLinks addon loaded');
            }),
            import('@xterm/addon-unicode11').then(({ Unicode11Addon }) => {
              const unicode11Addon = new Unicode11Addon();
              terminal.loadAddon(unicode11Addon);
              terminal.unicode.activeVersion = '11';
              console.debug('[Terminal] ✅ Unicode11 addon loaded for better character support');
            })
          ]).catch(err => {
            console.warn('[Terminal] ⚠️ Some non-critical addons failed to load:', err);
          });
        }).catch(canvasErr => {
          console.warn('[Terminal] ⚠️ Failed to load Canvas addon (fallback to DOM renderer):', canvasErr);
          // Fallback to DOM renderer
          openTerminalWithAddons();
        });
      });
    } else {
      // Server-side: just open the terminal
      openTerminalWithAddons();
    }
    
    // Let xterm.js handle cursor positioning naturally
    // Don't override write method as it can interfere with cursor positioning
    
    // Don't load fit addon - we're using fixed dimensions
    // Note: terminal.open() is now handled by openTerminalWithAddons() after Canvas addon loads
    
    // Use backend-configured dimensions - do not resize the backend terminal
    const { cols, rows } = terminal;
    console.debug(`[Terminal] Frontend terminal created with dimensions: ${cols}x${rows} (backend controls actual PTY size)`);

    // Optimized scroll position tracking with debouncing
    const checkScrollPosition = debounce(() => {
      const viewport = terminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (!viewport) return;

      const scrollTop = viewport.scrollTop;
      const scrollHeight = viewport.scrollHeight;
      const clientHeight = viewport.clientHeight;
      const threshold = 50; // pixels from bottom
      const atBottom = scrollHeight - scrollTop - clientHeight < threshold;

      // Only update refs (no re-render)
      scrollPositionRef.current = scrollTop;

      // Batch state updates to prevent unnecessary re-renders
      const updates: (() => void)[] = [];

      if (atBottom !== isAtBottomRef.current) {
        updates.push(() => setIsAtBottom(atBottom));
      }

      if (atBottom && hasNewOutputRef.current) {
        updates.push(() => setHasNewOutput(false));
      }

      // Apply all updates in a single batch
      if (updates.length > 0) {
        updates.forEach(update => update());
      }

      // Record scroll position in history less frequently
      const now = Date.now();
      const lastHistory = scrollHistoryRef.current[scrollHistoryRef.current.length - 1];
      if (!lastHistory || now - lastHistory.timestamp > 100) {
        scrollHistoryRef.current = [
          ...scrollHistoryRef.current,
          { position: scrollTop, timestamp: now }
        ].slice(-10); // Keep only last 10 positions
      }
    }, 16); // ~60fps debouncing

    // Add scroll and wheel listeners to viewport after a delay to ensure it's ready
    setTimeout(() => {
      const viewport = terminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (viewport) {
        viewport.addEventListener('scroll', checkScrollPosition);
        
        // Add wheel event handler for proper scrollback behavior
        let wheelTimeout: NodeJS.Timeout | null = null;
        const handleWheel = (e: WheelEvent) => {
          // Don't prevent default - let xterm handle the wheel event naturally
          // This ensures proper scrollback behavior
          
          // Throttle wheel events to prevent excessive re-renders
          if (wheelTimeout) {
            clearTimeout(wheelTimeout);
          }
          
          wheelTimeout = setTimeout(() => {
            checkScrollPosition();
            wheelTimeout = null;
          }, 16); // ~1 frame delay at 60fps
        };
        
        viewport.addEventListener('wheel', handleWheel, { passive: true });
        
        // Store cleanup functions
        (terminal as any).wheelCleanup = () => {
          viewport.removeEventListener('wheel', handleWheel);
          if (wheelTimeout) {
            clearTimeout(wheelTimeout);
          }
        };
        
        // Initial check
        checkScrollPosition();
      }
    }, 100);

    // Don't show welcome message - let the PTY handle it
    
    // Enhanced terminal input handling with robust session routing
    const onDataDisposable = terminal.onData((data) => {
      console.debug(`[Terminal] 🎯 Input received: ${JSON.stringify(data)} (${data.length} bytes)`);

      // CRITICAL FIX: Always read the current sessionId from ref at the time of input
      // This ensures we get the most up-to-date sessionId even after session switches
      const currentSessionId = sessionIdRef.current;

      // Additional validation: check if we have a valid current sendData function
      const currentSendData = sendDataRef.current;

      // Validate session ID
      if (!currentSessionId) {
        console.error('[Terminal] ❌ No session ID available - input cannot be routed!', {
          sessionIdRef: sessionIdRef.current,
          propSessionId: sessionId  // For debugging
        });
        return;
      }

      // Validate sendData function using ref to get current value
      if (!currentSendData || typeof currentSendData !== 'function') {
        console.error('[Terminal] ❌ sendData not available - input cannot be sent!', {
          hasSendData: !!currentSendData,
          sendDataType: typeof currentSendData,
          sessionId: currentSessionId,
          refValue: !!sendDataRef.current
        });
        return;
      }

      // DEFENSIVE FIX: Validate terminal is still focused and active
      if (!terminal.element || !document.activeElement) {
        console.warn('[Terminal] ⚠️ Terminal not focused, input may be misdirected');
      }

      // DEFENSIVE FIX: Check if WebSocket is still connected
      if (!isConnected) {
        console.error('[Terminal] ❌ WebSocket disconnected - cannot send input');
        return;
      }

      // Log routing information for debugging
      console.debug(`[Terminal] 🚀 Routing input to session: ${currentSessionId}`, {
        inputLength: data.length,
        timestamp: Date.now(),
        terminalFocused: document.activeElement === terminal.element?.querySelector('textarea'),
        isConnected
      });

      try {
        // Send raw keypress data to the correct session using current sendData function
        currentSendData(currentSessionId, data);
        console.debug(`[Terminal] ✅ Input successfully sent to session ${currentSessionId}`);
      } catch (error) {
        console.error('[Terminal] ❌ Failed to send input:', error, {
          sessionId: currentSessionId,
          dataLength: data.length,
          inputType: typeof data
        });
      }

      // Call optional onData callback with error handling
      const currentOnData = onDataRef.current;
      if (currentOnData && typeof currentOnData === 'function') {
        try {
          currentOnData(data);
        } catch (error) {
          console.error('[Terminal] ❌ Error in onData callback:', error);
        }
      }
    });

    // Handle cursor position reports from backend
    const handleCursorPosition = (data: string) => {
      const cursorMatch = data.match(/\x1b\[(\d+);(\d+)R/);
      if (cursorMatch) {
        const row = parseInt(cursorMatch[1], 10);
        const col = parseInt(cursorMatch[2], 10);
        console.debug(`[Terminal] 📍 Cursor position update: ${row},${col}`);
        setLastCursorPosition({ row, col });
      }
    };

    // Store cursor position handler for cleanup
    (terminal as any).cursorPositionHandler = handleCursorPosition;

    // No resize handling - terminal has fixed dimensions

    terminalRef.current = terminal;

    // Store disposable for cleanup - MUST be after terminalRef.current is set
    if (terminalRef.current) {
      (terminalRef.current as any)._onDataDisposable = onDataDisposable;

      // Mark that this terminal has valid sendData if we verified it
      if (sendData && typeof sendData === 'function') {
        (terminalRef.current as any)._hasValidSendData = true;
        console.debug('[Terminal] Terminal created with valid sendData function');
      }
    }

    // Process any pending data that arrived before terminal was ready
    if (pendingDataRef.current && pendingDataRef.current.length > 0) {
      console.debug(`[Terminal] 📦 Processing ${pendingDataRef.current.length} pending data packets`);
      const pendingData = [...pendingDataRef.current];
      pendingDataRef.current = [];

      // Process each pending data packet with a small delay
      setTimeout(() => {
        pendingData.forEach(data => {
          if (terminalRef.current && terminalRef.current.element) {
            console.debug(`[Terminal] ✏️ Writing pending data for session ${data.sessionId}`);
            terminalRef.current.write(data.data);
          }
        });
      }, 100); // Small delay to ensure terminal is fully ready
    }

    // Store cleanup function
    (terminal as any).scrollCleanup = () => {
      const viewport = terminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (viewport) {
        viewport.removeEventListener('scroll', checkScrollPosition);
      }
      
      // Clean up wheel event listener
      if ((terminal as any).wheelCleanup) {
        (terminal as any).wheelCleanup();
      }
    };

    return terminal;
  }, [sendData, onData, isConnected]); // Include critical functions needed for input

  const writeToTerminal = useCallback((data: string) => {
    if (terminalRef.current) {
      terminalRef.current.write(data);
    }
  }, []);

  const clearTerminal = useCallback(() => {
    if (terminalRef.current) {
      terminalRef.current.clear();
    }
  }, []);

  const focusTerminal = useCallback(() => {
    if (!terminalRef.current) {
      console.warn('[Terminal] 🎯 Cannot focus - terminal not ready');
      return false;
    }

    if (!terminalRef.current.element) {
      console.warn('[Terminal] 🎯 Cannot focus - terminal element not attached to DOM');
      return false;
    }

    try {
      // ENHANCED FOCUS: Multiple focus strategies for better reliability
      terminalRef.current.focus();

      // DEFENSIVE FIX: Also focus the textarea element if available
      const textarea = terminalRef.current.element.querySelector('textarea');
      if (textarea) {
        textarea.focus();
        console.debug('[Terminal] 🎯 Textarea focused for better input handling');
      }

      // DEFENSIVE FIX: Ensure terminal is in foreground
      if (terminalRef.current.element) {
        terminalRef.current.element.scrollIntoView({ block: 'nearest' });
      }

      console.debug('[Terminal] 🎯 Terminal focused successfully');
      return true;
    } catch (error) {
      console.error('[Terminal] ❌ Failed to focus terminal:', error);
      return false;
    }
  }, []);

  const fitTerminal = useCallback(() => {
    // No-op for fixed size terminal - removed console log to prevent error
  }, []);

  const destroyTerminal = useCallback(() => {
    if (terminalRef.current) {
      console.debug('[Terminal] 🛑 Destroying terminal with cleanup...');

      // Mark terminal as no longer ready
      setIsTerminalReady(false);

      try {
        // Dispose of onData handler to prevent multiple registrations
        if ((terminalRef.current as any)._onDataDisposable) {
          (terminalRef.current as any)._onDataDisposable.dispose();
          delete (terminalRef.current as any)._onDataDisposable;
          console.debug('[Terminal] ✅ onData handler disposed');
        }

        // Clean up scroll listeners
        if ((terminalRef.current as any).scrollCleanup) {
          (terminalRef.current as any).scrollCleanup();
          console.debug('[Terminal] ✅ Scroll listeners cleaned');
        }

        // Clean up wheel listeners
        if ((terminalRef.current as any).wheelCleanup) {
          (terminalRef.current as any).wheelCleanup();
          console.debug('[Terminal] ✅ Wheel listeners cleaned');
        }

        // Dispose terminal itself
        terminalRef.current.dispose();
        console.debug('[Terminal] ✅ Terminal disposed successfully');
      } catch (error) {
        console.error('[Terminal] ❌ Error during terminal cleanup:', error);
      } finally {
        terminalRef.current = null;
        // Reset initialization flags
        initializationAttempted.current = false;
        initializationInProgress.current = false;
      }
    }
    // Clear pending data
    pendingDataRef.current = [];
    console.debug('[Terminal] 🧹 Terminal cleanup completed');
  }, []);

  const scrollToBottom = useCallback(() => {
    if (terminalRef.current) {
      const viewport = terminalRef.current.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (viewport) {
        // Use requestAnimationFrame for smooth scrolling
        requestAnimationFrame(() => {
          viewport.scrollTop = viewport.scrollHeight;
          setIsAtBottom(true);
          setHasNewOutput(false);
        });
      }
    }
  }, []);

  const scrollToTop = useCallback(() => {
    if (terminalRef.current) {
      const viewport = terminalRef.current.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (viewport) {
        // Use requestAnimationFrame for smooth scrolling
        requestAnimationFrame(() => {
          viewport.scrollTop = 0;
          setIsAtBottom(false);
        });
      }
    }
  }, []);

  const refreshTerminal = useCallback(() => {
    console.debug('[Terminal] 🔄 Refreshing terminal and requesting full history...');

    // Send refresh command to backend via WebSocket message (not terminal input)
    if (sessionId && isConnected) {
      // Clear current terminal content first
      if (terminalRef.current) {
        terminalRef.current.clear();
      }

      // Send proper refresh message via WebSocket (not as terminal input)
      if (typeof sendMessage === 'function') {
        sendMessage({
          type: 'refresh-history',
          sessionId: sessionId,
          timestamp: Date.now()
        });
        console.debug('[Terminal] ✅ Refresh request sent via WebSocket message');
      } else {
        // Fallback: Send Ctrl+L (clear screen) followed by history request
        console.debug('[Terminal] 📤 Fallback: Sending Ctrl+L to clear and refresh display');
        sendData(sessionId, '\x0C'); // Ctrl+L clear screen control sequence

        // Request command history redisplay after a brief delay
        setTimeout(() => {
          sendData(sessionId, 'history\r'); // Request command history
        }, 100);
      }
    } else {
      console.warn('[Terminal] ⚠️ Cannot refresh - not connected or no session ID');
    }
  }, [sessionId, isConnected, sendData, sendMessage]);

  // ENHANCED FIX: Stable event handlers with improved session and streaming handling
  const handleTerminalData = useCallback((data: any) => {
      // Always check current value of terminalRef
      const currentTerminal = terminalRef.current;

      // Enhanced logging for debugging data flow issues
      console.debug(`[Terminal] 📡 terminal-data event received:`, {
        sessionId: data?.sessionId,
        currentSessionId: sessionIdRef.current,
        dataLength: data?.data?.length,
        hasTerminalRef: !!currentTerminal,
        terminalElement: currentTerminal?.element ? 'ready' : 'not-ready',
        isRefreshResponse: data?.isRefreshResponse,
        timestamp: Date.now(),
        env: process.env.NODE_ENV
      });

      // Check if we have a terminal instance
      if (!currentTerminal) {
        console.debug(`[Terminal] ⚠️ No terminal instance to receive data, queueing...`);
        // Queue the data for when terminal is ready
        if (!pendingDataRef.current) {
          pendingDataRef.current = [];
        }
        pendingDataRef.current.push(data);
        return;
      }

      // Use sessionIdRef for current session handling
      const currentSessionId = sessionIdRef.current || sessionId;

      // ENHANCED FIX: Better session validation with streaming persistence
      if (!data.sessionId) {
        console.warn('[Terminal] ⚠️ Received data without session ID - rejecting to prevent wrong terminal display');
        return;
      }

      if (data.sessionId !== currentSessionId) {
        console.debug(`[Terminal] 🔍 Session ID mismatch analysis:`, {
          expected: currentSessionId,
          received: data.sessionId,
          isRefreshResponse: data.isRefreshResponse,
          env: process.env.NODE_ENV
        });

        // ENHANCED FIX: Allow data if it's a refresh response or continuous stream
        const isRefreshResponse = data.isRefreshResponse;
        const isInitialTerminal = !currentSessionId || currentSessionId === data.sessionId;
        const isLikelyInitialData = data.sessionId && data.sessionId.startsWith('terminal-') &&
                                   (!currentSessionId || currentSessionId.startsWith('terminal-'));
        const isContinuousStream = data.sessionId && currentSessionId &&
                                  Math.abs(data.sessionId.localeCompare(currentSessionId)) < 5;

        if (isRefreshResponse || isInitialTerminal || isLikelyInitialData || isContinuousStream) {
          console.debug(`[Terminal] ✅ Accepting data (reason: ${isRefreshResponse ? 'refresh' : isInitialTerminal ? 'initial' : isContinuousStream ? 'stream' : 'initial-data'})`);
          // Update our session reference to match the actual session for streaming continuity
          sessionIdRef.current = data.sessionId;
        } else {
          console.debug(`[Terminal] 🚫 Rejecting data - strict session validation failed`);
          return;
        }
      }

      // PRODUCTION FIX: Always log data processing for essential debugging
      console.debug(`[Terminal] 📥 Processing data for session ${data.sessionId || 'default'} (current: ${currentSessionId})`);

      // Ensure terminal exists and is ready
      if (!currentTerminal || !currentTerminal.element) {
        console.warn(`[Terminal] ⚠️ Terminal not ready yet, queueing data for session ${data.sessionId}`);
        // Queue the data for later when terminal is ready
        if (!pendingDataRef.current) {
          pendingDataRef.current = [];
        }
        pendingDataRef.current.push(data);
        return;
      }

      const viewport = currentTerminal.element?.querySelector('.xterm-viewport') as HTMLElement;
        
        // Store current scroll position before writing
        const currentScrollTop = viewport?.scrollTop || 0;
        const wasAtBottom = isAtBottom;
        
        // Handle cursor position reports and echo state changes from metadata
        if (data.metadata) {
          if (data.metadata.hasCursorReport) {
            const cursorHandler = (currentTerminal as any).cursorPositionHandler;
            if (cursorHandler) {
              cursorHandler(data.data);
            }
          }
          
          if (data.metadata.hasEchoChange) {
            const newEchoState = data.metadata.echoState === 'on';
            console.debug(`[Terminal] 🔊 Echo state change detected: ${data.metadata.echoState}`);
            setEchoEnabled(newEchoState);
          }
        }

        // ENHANCED FIX: Robust terminal writing with streaming support
        try {
          // Ensure data is written atomically to prevent corruption
          if (data.data && typeof data.data === 'string') {
            currentTerminal.write(data.data);

            // Track successful data processing for streaming continuity
            (currentTerminal as any)._lastDataTimestamp = Date.now();
            (currentTerminal as any)._lastSessionId = data.sessionId;

            // PRODUCTION FIX: Force immediate display update
            if (process.env.NODE_ENV === 'production') {
              if (currentTerminal.element) {
                // Trigger reflow to ensure content is visible immediately
                currentTerminal.element.offsetHeight;
              }
            }
          } else {
            console.warn('[Terminal] ⚠️ Invalid data format received:', typeof data.data, data.data);
          }
        } catch (error) {
          console.error('[Terminal] ❌ Failed to write data to terminal:', error, {
            dataType: typeof data.data,
            dataLength: data.data?.length,
            sessionId: data.sessionId
          });
          return;
        }

        // Handle scrolling based on user position with improved logic
        if (viewport) {
          // Store current viewport metrics after writing
          const newScrollHeight = viewport.scrollHeight;
          const clientHeight = viewport.clientHeight;

          if (wasAtBottom) {
            // User was at bottom, so auto-scroll to show new content
            // PRODUCTION FIX: Use requestAnimationFrame in production for better reliability
            if (process.env.NODE_ENV === 'production') {
              requestAnimationFrame(() => {
                if (viewport) {
                  viewport.scrollTop = viewport.scrollHeight;
                  setIsAtBottom(true);
                }
              });
            } else {
              setTimeout(() => {
                if (viewport) {
                  viewport.scrollTop = viewport.scrollHeight;
                  setIsAtBottom(true);
                }
              }, 0);
            }
          } else {
            // User was reading above, preserve their relative position in the scrollback
            // Calculate the proportion of content that was above the current view
            const oldScrollHeight = currentScrollTop + clientHeight;
            const contentGrowth = newScrollHeight - oldScrollHeight;

            if (contentGrowth > 0) {
              // Content was added, adjust scroll position to maintain view
              if (process.env.NODE_ENV === 'production') {
                requestAnimationFrame(() => {
                  if (viewport) {
                    viewport.scrollTop = currentScrollTop + contentGrowth;
                  }
                });
              } else {
                setTimeout(() => {
                  if (viewport) {
                    viewport.scrollTop = currentScrollTop + contentGrowth;
                  }
                }, 0);
              }
            }

            // Show new output indicator if there's actual content
            if (data.data.trim()) {
              setHasNewOutput(true);
            }
          }
        }
  }, [setEchoEnabled, setIsAtBottom, setHasNewOutput, sessionId, isAtBottom]);

  const handleTerminalError = useCallback((data: any) => {
    const currentTerminal = terminalRef.current;
    const currentSessionId = sessionIdRef.current || sessionId;
    if (data.sessionId === currentSessionId && currentTerminal) {
      currentTerminal.write(`\x1b[31m${data.error}\x1b[0m\r\n`);
    }
  }, [sessionId]);

  const handleConnectionChange = useCallback((connected: boolean) => {
    const currentTerminal = terminalRef.current;
    if (currentTerminal) {
      const status = connected ? '\x1b[32mConnected' : '\x1b[31mDisconnected';
      currentTerminal.write(`\r\n\x1b[90m[${status}\x1b[90m]\x1b[0m\r\n`);
    }
  }, []);

  // Track terminal initialization state (moved to top for clarity)
  const [isTerminalReady, setIsTerminalReady] = useState(false);

  // Add initialization tracking to prevent recreation loops
  const initializationAttempted = useRef(false);
  const initializationInProgress = useRef(false);

  // Memoize expensive terminal configuration to prevent unnecessary recalculations
  const memoizedTerminalConfig = useMemo(() => terminalConfig, [terminalConfig]);

  // Track listener registration state per session to prevent duplicates
  const listenerKeyRef = useRef<string>('');
  const listenerCallbacksRef = useRef<{
    terminalData?: (data: any) => void;
    terminalError?: (data: any) => void;
    connectionChange?: (connected: boolean) => void;
  }>({});

  // Update refs to prevent stale closures in production
  useEffect(() => {
    handleTerminalDataRef.current = handleTerminalData;
    handleTerminalErrorRef.current = handleTerminalError;
    handleConnectionChangeRef.current = handleConnectionChange;
  }, [handleTerminalData, handleTerminalError, handleConnectionChange]);

  // FIXED: Stable WebSocket event registration with proper deduplication
  useEffect(() => {
    // Ensure we have WebSocket functions and connection
    if (!isConnected || !on || !off) {
      console.debug('[Terminal] ⏳ Waiting for WebSocket connection...', {
        isConnected,
        hasOn: !!on,
        hasOff: !!off,
        sessionId
      });
      return;
    }

    // Don't register if terminal is not ready
    if (!isTerminalReady) {
      console.debug('[Terminal] ⏳ Waiting for terminal to be ready before registering listeners...');
      return;
    }

    // Create unique key for this listener set
    const currentListenerKey = `${sessionId}-${hookInstanceId.current}`;

    // Check if we already have listeners registered for this exact configuration
    if (listenerKeyRef.current === currentListenerKey) {
      console.debug('[Terminal] ℹ️ Listeners already registered for this session/instance, skipping');
      return;
    }

    // Clean up any existing listeners before registering new ones
    const existingCallbacks = listenerCallbacksRef.current;
    if (existingCallbacks.terminalData || existingCallbacks.terminalError || existingCallbacks.connectionChange) {
      console.debug('[Terminal] 🧹 Cleaning up existing listeners before re-registration');
      try {
        if (existingCallbacks.terminalData) {
          off('terminal-data', existingCallbacks.terminalData);
          off('history-refreshed', existingCallbacks.terminalData);
        }
        if (existingCallbacks.terminalError) {
          off('terminal-error', existingCallbacks.terminalError);
        }
        if (existingCallbacks.connectionChange) {
          off('connection-change', existingCallbacks.connectionChange);
        }
      } catch (error) {
        console.debug('[Terminal] ⚠️ Error cleaning up old listeners:', error);
      }
    }

    console.debug('[Terminal] 🔗 Registering WebSocket listeners (instance:', hookInstanceId.current, ', session:', sessionId, ')');

    // Create stable callback references that use refs to avoid stale closures
    const stableHandleTerminalData = (data: any) => {
      // Use the ref to get the latest handler - critical for production
      if (handleTerminalDataRef.current) {
        handleTerminalDataRef.current(data);
      }
    };

    const stableHandleTerminalError = (data: any) => {
      // Use the ref to get the latest handler - critical for production
      if (handleTerminalErrorRef.current) {
        handleTerminalErrorRef.current(data);
      }
    };

    const stableHandleConnectionChange = (connected: boolean) => {
      // Use the ref to get the latest handler - critical for production
      if (handleConnectionChangeRef.current) {
        handleConnectionChangeRef.current(connected);
      }
    };

    // Store callbacks and key for cleanup
    listenerCallbacksRef.current = {
      terminalData: stableHandleTerminalData,
      terminalError: stableHandleTerminalError,
      connectionChange: stableHandleConnectionChange
    };
    listenerKeyRef.current = currentListenerKey;

    // Register event listeners
    try {
      on('terminal-data', stableHandleTerminalData);
      on('terminal-error', stableHandleTerminalError);
      on('connection-change', stableHandleConnectionChange);
      on('history-refreshed', stableHandleTerminalData);

      console.debug('[Terminal] ✅ WebSocket listeners registered successfully for session:', sessionId);
    } catch (error) {
      console.error('[Terminal] ❌ Failed to register WebSocket listeners:', error);
      listenerKeyRef.current = ''; // Reset on failure
      return;
    }

    // Cleanup function
    return () => {
      console.debug('[Terminal] 🧹 Cleaning up WebSocket listeners (instance:', hookInstanceId.current, ', session:', sessionId, ')');

      const callbacks = listenerCallbacksRef.current;

      try {
        if (callbacks.terminalData) {
          off('terminal-data', callbacks.terminalData);
          off('history-refreshed', callbacks.terminalData);
        }
        if (callbacks.terminalError) {
          off('terminal-error', callbacks.terminalError);
        }
        if (callbacks.connectionChange) {
          off('connection-change', callbacks.connectionChange);
        }

        listenerKeyRef.current = '';
        listenerCallbacksRef.current = {};
        console.debug('[Terminal] ✅ WebSocket listeners cleaned up successfully');
      } catch (error) {
        console.error('[Terminal] ❌ Error during listener cleanup:', error);
      }
    };
    // Remove handler functions from dependencies - they cause re-registration
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [on, off, isConnected, sessionId, isTerminalReady]); // Only track essential state changes

  // Fetch backend config via HTTP before terminal initialization
  // This happens completely out-of-band from the WebSocket connection
  useEffect(() => {
    console.debug('[Terminal] 🔧 Config fetch effect triggered - sessionId:', sessionId, 'backendTerminalConfig:', !!backendTerminalConfig);

    if (!sessionId) {
      console.debug('[Terminal] 🔧 No sessionId provided - skipping config fetch');
      return;
    }

    // Only fetch if we don't have config yet
    if (!backendTerminalConfig && !configRequestInProgress) {
      console.debug('[Terminal] 🔧 Fetching backend config via HTTP for session:', sessionId);
      setConfigRequestInProgress(true);
      setConfigError(null);

      // Fetch configuration from backend HTTP service
      terminalConfigService.fetchConfig(sessionId)
        .then((config) => {
          console.debug('[Terminal] 🔧 Backend config received via HTTP:', config);
          setBackendTerminalConfig(config);
          setConfigRequestInProgress(false);
          setConfigError(null);
        })
        .catch((error) => {
          console.error('[Terminal] 🔧 Failed to fetch backend config:', error);
          setConfigError(error.message || 'Failed to fetch terminal configuration');
          setConfigRequestInProgress(false);
        });
    } else {
      console.debug('[Terminal] 🔧 Config fetch skipped:', {
        hasConfig: !!backendTerminalConfig,
        inProgress: configRequestInProgress
      });
    }
  }, [sessionId, backendTerminalConfig, configRequestInProgress]); // Include all deps but check them inside

  // Handle session changes with improved cleanup
  useEffect(() => {
    console.debug('[Terminal] 🔄 Session changed to:', sessionId);

    // CRITICAL: Update sessionIdRef immediately and synchronously
    // This must happen before any other operations to prevent race conditions
    sessionIdRef.current = sessionId;
    console.debug('[Terminal] 🔧 SessionId ref immediately updated in session change effect');

    // CRITICAL: Destroy existing terminal when switching sessions
    // This ensures we don't have multiple terminals competing for input
    if (terminalRef.current) {
      console.debug('[Terminal] 🛑 Destroying previous terminal before session switch');
      destroyTerminal();
    }

    // Clear cached config for new sessions
    setConfigRequestInProgress(false);
    setConfigError(null);
    setBackendTerminalConfig(null);
    terminalConfigService.clearCache();

    // Reset initialization flags for new session
    initializationAttempted.current = false;
    initializationInProgress.current = false;
    setIsTerminalReady(false);

    // Clear any pending data from previous session
    pendingDataRef.current = [];

    // Reset container ready state to trigger re-initialization
    setContainerReady(false);

    console.debug('[Terminal] ✅ Session change handling completed for:', sessionId);
  }, [sessionId, destroyTerminal]);

  // Reset terminal when sendData changes to ensure input works
  useEffect(() => {
    if (!sendData || typeof sendData !== 'function') {
      return;
    }

    // If terminal was created before sendData was ready, we need to recreate it
    if (terminalRef.current && isConnected && !initializationInProgress.current) {
      const hasValidSendData = sendData && typeof sendData === 'function';

      if (hasValidSendData) {
        console.debug('[Terminal] sendData is now available, checking if terminal needs recreation');

        // Test if the terminal's onData handler has the correct sendData
        // If it was created when sendData wasn't ready, we need to recreate
        const needsRecreation = initializationAttempted.current && !(terminalRef.current as any)._hasValidSendData;

        if (needsRecreation) {
          console.debug('[Terminal] Recreating terminal with valid sendData function');

          // Destroy the old terminal
          if (terminalRef.current) {
            terminalRef.current.dispose();
            terminalRef.current = null;
          }

          // Reset initialization flags to allow recreation
          initializationAttempted.current = false;
          initializationInProgress.current = false;
          setIsTerminalReady(false);
        } else {
          // Mark that this terminal has valid sendData
          if (terminalRef.current) {
            (terminalRef.current as any)._hasValidSendData = true;
          }
        }
      }
    }
  }, [sendData, isConnected]);

  // OLD DEBUG EFFECT TEMPORARILY REMOVED TO ISOLATE DOM-BASED DETECTION

  // No window resize handling - terminal has fixed dimensions

  // Create a state to trigger re-initialization when needed
  const [containerReady, setContainerReady] = useState(false);

  // Persistent container tracking that survives React re-renders
  const persistentContainerState = useRef({
    hasSeenContainer: false,
    lastKnownElement: null as HTMLElement | null,
    isMonitoring: false
  });

  // Simplified container detection with better error handling
  useEffect(() => {
    let attempts = 0;
    const maxAttempts = 50; // Reduced from 200 for faster feedback
    let isActive = true;

    const checkContainer = () => {
      if (!isActive) return;
      attempts++;

      // Search for container in DOM
      const domContainer = document.querySelector('.xterm-wrapper') as HTMLDivElement | null;

      if (domContainer) {
        // Update ref to point to the DOM element
        containerRef.current = domContainer;
        persistentContainerState.current.hasSeenContainer = true;
        persistentContainerState.current.lastKnownElement = domContainer;

        // Attach any waiting terminal
        if (terminalRef.current && !terminalRef.current.element) {
          console.debug('[Terminal] 🔗 Attaching deferred terminal to container');
          try {
            terminalRef.current.open(domContainer);
            console.debug('[Terminal] ✅ Terminal successfully attached to DOM');
          } catch (err) {
            console.error('[Terminal] ❌ Failed to attach terminal:', err);
          }
        }

        if (!containerReady) {
          console.debug('[Terminal] ✅ Container ready after', attempts, 'attempts');
          setContainerReady(true);
        }
        return;
      }

      // Continue searching if not found yet
      if (attempts <= maxAttempts) {
        setTimeout(checkContainer, 50); // Increased interval for less spam
      } else {
        console.warn('[Terminal] ⚠️ Container not found after', maxAttempts, 'attempts');
        // Don't set ready state false here - allow terminal to work without container
      }
    };

    // Start monitoring with initial delay
    const timer = setTimeout(checkContainer, 10);

    return () => {
      isActive = false;
      clearTimeout(timer);
    };
  }, []); // Run once on mount
  
  // Initialize terminal when all conditions are met
  useEffect(() => {
    // Skip if terminal already exists
    if (terminalRef.current) {
      console.debug('[Terminal] Skipping initialization - terminal already exists');
      return;
    }

    // Skip if already in progress
    if (initializationInProgress.current) {
      console.debug('[Terminal] Skipping initialization - already in progress');
      return;
    }

    // CRITICAL: Check sessionId to ensure we're initializing for the correct session
    if (!sessionId) {
      console.debug('[Terminal] No sessionId - skipping initialization');
      return;
    }

    // Check if we have valid dimensions
    const cols = backendTerminalConfig?.cols;
    const rows = backendTerminalConfig?.rows;

    if (!cols || !rows || cols === 0 || rows === 0) {
      console.debug(`[Terminal] Waiting for backend terminal configuration... (cols: ${cols}, rows: ${rows})`);
      return; // Don't create terminal until we have both backend config and valid dimensions
    }

    // Check if we have WebSocket connection
    if (!isConnected) {
      console.debug('[Terminal] Waiting for WebSocket connection before creating terminal');
      return;
    }

    // CRITICAL: Verify sendData function is available before creating terminal
    if (!sendData || typeof sendData !== 'function') {
      console.warn('[Terminal] 🚨 sendData function not available - delaying terminal creation');
      return;
    }

    console.debug('[Terminal] Initialization check:', {
      cols,
      rows,
      containerReady,
      hasExistingTerminal: !!terminalRef.current,
      isTerminalReady,
      isConnected
    });

    // Mark that we're starting initialization BEFORE any async operations
    initializationInProgress.current = true;
    initializationAttempted.current = true;

    // REMOVED containerReady check - create terminal regardless of container
    // Terminal will be created in memory and attached to DOM when container is available
    console.debug('[Terminal] Creating terminal without waiting for container...');

    console.debug(`[Terminal] All conditions met, creating terminal with dimensions: ${cols}x${rows}`);
    console.debug('[Terminal] 🚀 CALLING initTerminal() - THIS IS WHERE XTERM GETS CREATED');

    // Call initTerminal directly to avoid dependency on the callback
    initTerminal();

    console.debug('[Terminal] 🚀 initTerminal() completed');

    // Signal that terminal is ready for data AND WebSocket listeners can be registered
    if (terminalRef.current) {
      console.debug('[Terminal] Terminal initialized and ready for data');
      // NOW set the flag that WebSocket listeners are waiting for
      // Use a small delay to ensure the terminal is fully rendered
      setTimeout(() => {
        setIsTerminalReady(true);
        initializationInProgress.current = false;
        console.debug('[Terminal] 🎯 Terminal marked as ready for WebSocket connection');
      }, 50);

      // Mark terminal as ready
      setIsTerminalReady(true);

      // ENHANCED FOCUS: Multiple focus attempts with validation
      setTimeout(() => {
        if (terminalRef.current && terminalRef.current.element) {
          console.debug('[Terminal] 🎯 Applying initial focus to terminal');
          focusTerminal();

          // Validate that input handlers are working
          setTimeout(() => {
            if (terminalRef.current && !(terminalRef.current as any)._onDataDisposable) {
              console.error('[Terminal] ❌ Terminal missing onData handler after initialization!');
            } else {
              console.debug('[Terminal] ✅ Terminal input handler verified');
            }
          }, 50);
        }
      }, 100);
    } else {
      // Reset if initialization failed
      setTimeout(() => {
        initializationAttempted.current = false;
        initializationInProgress.current = false;
      }, 100);
    }
  }, [backendTerminalConfig?.cols, backendTerminalConfig?.rows, isConnected, sendData, sessionId, initTerminal, focusTerminal]); // Critical deps including sendData and sessionId

  // Connect WebSocket first before terminal initialization
  useEffect(() => {
    if (backendTerminalConfig && connect && !isConnected && !terminalRef.current) {
      console.debug('[Terminal] 🔌 Config available, connecting WebSocket before terminal creation...');
      connect().then(() => {
        console.debug('[Terminal] ✅ WebSocket connected successfully, terminal can now be created');
      }).catch((err) => {
        console.error('[Terminal] ❌ Failed to connect WebSocket:', err);
      });
    }
  }, [backendTerminalConfig, connect, isConnected]);

  return {
    terminalRef: containerRef,
    terminal: terminalRef.current,
    backendTerminalConfig,
    writeToTerminal,
    clearTerminal,
    focusTerminal,
    fitTerminal,
    destroyTerminal,
    scrollToBottom,
    scrollToTop,
    refreshTerminal,
    isAtBottom,
    hasNewOutput,
    isConnected,
    echoEnabled,
    lastCursorPosition,
    configError,
    configRequestInProgress,
  };
};