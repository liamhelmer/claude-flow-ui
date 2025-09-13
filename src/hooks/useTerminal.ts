import { useEffect, useRef, useCallback, useMemo, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { SerializeAddon } from '@xterm/addon-serialize';
import { useWebSocket } from './useWebSocket';
import { useAppStore } from '@/lib/state/store';
import { terminalConfigService, type TerminalBackendConfig } from '@/services/terminal-config';
import type { TerminalConfig } from '@/types';

// Track if we've logged the waiting message to avoid spam
let hasLoggedWaiting = false;

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
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [hasNewOutput, setHasNewOutput] = useState(false);
  const [backendTerminalConfig, setBackendTerminalConfig] = useState<TerminalBackendConfig | null>(null);
  // Track echo state and cursor position for proper handling
  const [echoEnabled, setEchoEnabled] = useState(true);
  const [lastCursorPosition, setLastCursorPosition] = useState({ row: 1, col: 1 });
  // Track scroll position for better scrollback behavior - use refs to avoid re-renders
  const scrollHistoryRef = useRef<{position: number, timestamp: number}[]>([]);
  const scrollPositionRef = useRef<number>(0);
  const { sendData, resizeTerminal, on, off, isConnected } = useWebSocket();
  const [configRequestInProgress, setConfigRequestInProgress] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [configRequested, setConfigRequested] = useState(false);

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

  const initTerminal = useCallback(() => {
    console.debug('[Terminal] 🔧 initTerminal: Starting check...', {
      hasContainer: !!containerRef.current,
      containerElement: containerRef.current,
      hasTerminal: !!terminalRef.current,
      hasConfig: !!terminalConfig,
      cols: terminalConfig?.cols,
      rows: terminalConfig?.rows
    });
    
    if (!containerRef.current) {
      console.error('[Terminal] 🔧 initTerminal: Container ref is null - DOM element not available');
      return;
    }
    
    if (terminalRef.current) {
      console.debug('[Terminal] 🔧 initTerminal: Terminal already exists - skipping creation');
      return;
    }
    
    if (!terminalConfig || terminalConfig.cols === 0 || terminalConfig.rows === 0) {
      console.debug('[Terminal] 🔧 initTerminal: Invalid config', {
        hasConfig: !!terminalConfig,
        cols: terminalConfig?.cols,
        rows: terminalConfig?.rows
      });
      return;
    }
    
    console.debug('[Terminal] 🔧 initTerminal: Creating terminal with verified dimensions:', terminalConfig.cols, 'x', terminalConfig.rows);

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
      fontSize: terminalConfig.fontSize,
      fontFamily: terminalConfig.fontFamily,
      fontWeight: 'normal',
      fontWeightBold: 'bold',
      
      // Terminal dimensions
      cols: terminalConfig.cols,
      rows: terminalConfig.rows,
      
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
      terminal.open(containerRef.current!);
      console.debug('[Terminal] 🎨 Terminal opened with renderer');
    };
    
    // Dynamically load addons only on client side to avoid SSR issues
    if (typeof window !== 'undefined') {
      // Try to load WebGL addon first for best performance
      import('@xterm/addon-webgl').then(({ WebglAddon }) => {
        const webglAddon = new WebglAddon();
        
        // Check if WebGL is supported by opening terminal first
        terminal.open(containerRef.current!);
        
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
    
    // CRITICAL: Enhanced character echo and cursor handling
    let lastCursorX = 0;
    let lastCursorY = 0;
    
    // Override write method to fix echo issues
    const originalWrite = terminal.write.bind(terminal);
    terminal.write = (data: string | Uint8Array) => {
      // Store cursor position before write
      const beforeX = terminal.buffer.active.cursorX;
      const beforeY = terminal.buffer.active.cursorY;
      
      // Process the write
      const result = originalWrite(data);
      
      // Handle proper character echo for input
      if (typeof data === 'string') {
        // Fix linefeed-only echo by ensuring proper character display
        if (data === '\r' || data === '\n') {
          // Let terminal handle newlines normally
        } else if (data.length === 1 && data.charCodeAt(0) >= 32 && data.charCodeAt(0) <= 126) {
          // For printable characters, ensure they display properly
          lastCursorX = terminal.buffer.active.cursorX;
          lastCursorY = terminal.buffer.active.cursorY;
        }
      }
      
      return result;
    };
    
    // Don't load fit addon - we're using fixed dimensions
    // Note: terminal.open() is now handled by openTerminalWithAddons() after Canvas addon loads
    
    // Use backend-configured dimensions - do not resize the backend terminal
    const { cols, rows } = terminal;
    console.debug(`[Terminal] Frontend terminal created with dimensions: ${cols}x${rows} (backend controls actual PTY size)`);

    // Track scroll position for auto-scroll functionality and history
    const checkScrollPosition = () => {
      const viewport = terminal.element?.querySelector('.xterm-viewport') as HTMLElement;
      if (viewport) {
        const scrollTop = viewport.scrollTop;
        const scrollHeight = viewport.scrollHeight;
        const clientHeight = viewport.clientHeight;
        const threshold = 50; // pixels from bottom
        const atBottom = scrollHeight - scrollTop - clientHeight < threshold;
        
        // Only update refs (no re-render)
        scrollPositionRef.current = scrollTop;
        
        // Only update state if atBottom actually changed to avoid unnecessary re-renders
        if (atBottom !== isAtBottom) {
          setIsAtBottom(atBottom);
        }
        
        // Record scroll position in history less frequently to avoid performance issues
        const now = Date.now();
        const lastHistory = scrollHistoryRef.current[scrollHistoryRef.current.length - 1];
        if (!lastHistory || now - lastHistory.timestamp > 100) { // Only record every 100ms
          scrollHistoryRef.current = [
            ...scrollHistoryRef.current,
            { position: scrollTop, timestamp: now }
          ].slice(-10); // Keep only last 10 positions
        }
        
        // Clear new output indicator if at bottom (only if needed)
        if (atBottom && hasNewOutput) {
          setHasNewOutput(false);
        }
      }
    };

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
    
    // Enhanced terminal input handling with echo detection
    terminal.onData((data) => {
      console.debug(`[Terminal] 🎯 Input: ${JSON.stringify(data)} (${data.length} bytes)`);
      
      // Handle cursor position requests
      if (data === '\x1b[6n') {
        console.debug('[Terminal] 📍 Cursor position request detected');
      }
      
      // Send raw keypress data immediately to the PTY backend
      sendData(sessionId, data);
      onData?.(data);
      
      // Request cursor position after certain inputs for tracking
      const shouldTrackCursor = data.includes('\r') || data.includes('\n') || data === '\x1b[A' || data === '\x1b[B' || data === '\x1b[C' || data === '\x1b[D';
      if (shouldTrackCursor) {
        // Request cursor position report from terminal
        setTimeout(() => {
          sendData(sessionId, '\x1b[6n');
        }, 10);
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
  }, [sessionId, terminalConfig, sendData, onData, hasNewOutput, isAtBottom]);

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
    if (terminalRef.current) {
      terminalRef.current.focus();
    }
  }, []);

  const fitTerminal = useCallback(() => {
    // No-op for fixed size terminal - removed console log to prevent error
  }, []);

  const destroyTerminal = useCallback(() => {
    if (terminalRef.current) {
      // Clean up scroll listener and cursor position handler
      if ((terminalRef.current as any).scrollCleanup) {
        (terminalRef.current as any).scrollCleanup();
      }
      if ((terminalRef.current as any).cursorPositionHandler) {
        delete (terminalRef.current as any).cursorPositionHandler;
      }
      terminalRef.current.dispose();
      terminalRef.current = null;
    }
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
    
    // Send refresh command to backend
    if (sessionId && isConnected) {
      // Clear current terminal content
      if (terminalRef.current) {
        terminalRef.current.clear();
      }
      
      // Request refresh from backend with current session
      sendData(sessionId, JSON.stringify({
        type: 'refresh',
        sessionId: sessionId
      }));
    }
  }, [sessionId, isConnected, sendData]);

  // Define handleTerminalConfig outside useEffect to avoid circular dependency
  const handleTerminalConfig = useCallback((data: any) => {
    // In single-terminal UI, accept any terminal-config from backend
    // This prevents session ID mismatch issues during initialization
    console.debug(`[Terminal] 🔧 [HANDLER CALLED] *** EVENT HANDLER EXECUTING *** Received config from backend: ${data.cols}x${data.rows} (session: ${data.sessionId})`);
    console.debug(`[Terminal] 🔧 Previous backendTerminalConfig:`, backendTerminalConfig);
    
    // Reset config requested flag so it can be requested again if needed
    setConfigRequested(false);
    
    // Destroy existing terminal if dimensions have changed
    if (terminalRef.current && (terminalRef.current.cols !== data.cols || terminalRef.current.rows !== data.rows)) {
      console.debug(`[Terminal] Terminal dimensions changing from ${terminalRef.current.cols}x${terminalRef.current.rows} to ${data.cols}x${data.rows} - recreating terminal`);
      destroyTerminal();
    }
    
    console.debug(`[Terminal] 🔧 Updating backendTerminalConfig cols/rows:`, { cols: data.cols, rows: data.rows });
    setBackendTerminalConfig(prevConfig => {
      if (prevConfig) {
        return { ...prevConfig, cols: data.cols, rows: data.rows };
      }
      return prevConfig;
    });
  }, [backendTerminalConfig, destroyTerminal]);

  // Handle incoming terminal data
  useEffect(() => {
    console.debug('[Terminal] 🔧 DEBUG: useEffect for event handlers is running, registering terminal-config listener');
    
    const handleTerminalData = (data: any) => {
      // Accept data from any sessionId since we only have one terminal
      // This fixes the mismatch where backend sends with globalSessionId
      if (terminalRef.current) {
        console.debug(`[Terminal] 📥 Received data for session ${data.sessionId} (local: ${sessionId})`);
        const terminal = terminalRef.current;
        const viewport = terminal.element?.querySelector('.xterm-viewport') as HTMLElement;
        
        // Store current scroll position before writing
        const currentScrollTop = viewport?.scrollTop || 0;
        const wasAtBottom = isAtBottom;
        
        // Handle cursor position reports and echo state changes from metadata
        if (data.metadata) {
          if (data.metadata.hasCursorReport) {
            const cursorHandler = (terminal as any).cursorPositionHandler;
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
        
        // Write the raw output from PTY
        terminal.write(data.data);
        
        // Handle scrolling based on user position with improved logic
        if (viewport) {
          // Store current viewport metrics after writing
          const newScrollHeight = viewport.scrollHeight;
          const clientHeight = viewport.clientHeight;
          
          if (wasAtBottom) {
            // User was at bottom, so auto-scroll to show new content
            // Use a small delay to ensure content has been rendered
            setTimeout(() => {
              if (viewport) {
                viewport.scrollTop = viewport.scrollHeight;
                setIsAtBottom(true);
              }
            }, 0);
          } else {
            // User was reading above, preserve their relative position in the scrollback
            // Calculate the proportion of content that was above the current view
            const oldScrollHeight = currentScrollTop + clientHeight;
            const contentGrowth = newScrollHeight - oldScrollHeight;
            
            if (contentGrowth > 0) {
              // Content was added, adjust scroll position to maintain view
              setTimeout(() => {
                if (viewport) {
                  viewport.scrollTop = currentScrollTop + contentGrowth;
                }
              }, 0);
            }
            
            // Show new output indicator if there's actual content
            if (data.data.trim()) {
              setHasNewOutput(true);
            }
          }
        }
      }
    };
    
    const handleTerminalError = (data: any) => {
      if (data.sessionId === sessionId && terminalRef.current) {
        terminalRef.current.write(`\x1b[31m${data.error}\x1b[0m\r\n`);
      }
    };
    
    const handleConnectionChange = (connected: boolean) => {
      if (terminalRef.current) {
        const status = connected ? '\x1b[32mConnected' : '\x1b[31mDisconnected';
        terminalRef.current.write(`\r\n\x1b[90m[${status}\x1b[90m]\x1b[0m\r\n`);
      }
    };
    

    console.debug('[Terminal] 🔧 DEBUG: Registering event listeners with WebSocket client');
    on('terminal-data', handleTerminalData);
    on('terminal-error', handleTerminalError);
    on('connection-change', handleConnectionChange);
    console.debug('[Terminal] 🔧 DEBUG: About to register terminal-config listener');
    on('terminal-config', handleTerminalConfig);
    console.debug('[Terminal] 🔧 DEBUG: terminal-config listener registered');
    
    // Note: We no longer request config here as the main config request is now handled
    // by the async method in the connection change effect above. This fallback listener
    // is kept for compatibility with any configs that come through the old event system.

    return () => {
      off('terminal-data', handleTerminalData);
      off('terminal-error', handleTerminalError);
      off('connection-change', handleConnectionChange);
      off('terminal-config', handleTerminalConfig);
    };
  }, [sessionId, on, off, isAtBottom, handleTerminalConfig, isConnected]);

  // Fetch backend config via HTTP before terminal initialization
  // This happens completely out-of-band from the WebSocket connection
  useEffect(() => {
    console.debug('[Terminal] 🔧 Config fetch effect triggered - sessionId:', sessionId, 'backendTerminalConfig:', !!backendTerminalConfig);
    
    if (!sessionId) {
      console.debug('[Terminal] 🔧 No sessionId provided - skipping config fetch');
      return;
    }
    
    if (backendTerminalConfig) {
      console.debug('[Terminal] 🔧 Backend config already exists - skipping fetch');
      return;
    }

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
  }, [sessionId, backendTerminalConfig]);

  // Handle session changes - clear cached config for new sessions
  useEffect(() => {
    console.debug('[Terminal] 🔧 Session changed, clearing config cache');
    setConfigRequestInProgress(false);
    setConfigError(null);
    setBackendTerminalConfig(null);
    // Clear the cache for the old session
    terminalConfigService.clearCache();
  }, [sessionId]);

  // Debug: Monitor container ref changes
  useEffect(() => {
    console.debug('[Terminal] 🔧 Container ref changed:', {
      hasContainer: !!containerRef.current,
      containerElement: containerRef.current
    });
  }, []); // Run once on mount - containerRef.current is not a valid dependency

  // No window resize handling - terminal has fixed dimensions

  // Create a state to trigger re-initialization when needed
  const [containerReady, setContainerReady] = useState(false);
  
  // Monitor container ref and update containerReady state
  useEffect(() => {
    const checkContainer = () => {
      const isReady = !!containerRef.current;
      if (isReady !== containerReady) {
        console.debug('[Terminal] Container ready state changed:', isReady);
        setContainerReady(isReady);
      }
    };
    
    // Check immediately
    checkContainer();
    
    // Also check periodically until container is ready
    const interval = setInterval(() => {
      if (!containerReady && containerRef.current) {
        checkContainer();
      } else if (containerReady) {
        clearInterval(interval);
      }
    }, 100);
    
    return () => clearInterval(interval);
  }, [containerReady]);
  
  // Initialize terminal when all conditions are met
  useEffect(() => {
    console.debug('[Terminal] Initialization check:', {
      hasBackendConfig: !!backendTerminalConfig,
      hasTerminalConfig: !!terminalConfig && terminalConfig.cols > 0,
      containerReady,
      hasExistingTerminal: !!terminalRef.current
    });
    
    if (!backendTerminalConfig || !terminalConfig || terminalConfig.cols === 0 || terminalConfig.rows === 0) {
      console.debug(`[Terminal] Waiting for backend terminal configuration... (backend: ${backendTerminalConfig ? 'ready' : 'waiting'}, config: ${terminalConfig && terminalConfig.cols > 0 ? 'ready' : 'waiting'})`);
      return; // Don't create terminal until we have both backend config and valid dimensions
    }
    
    if (!containerReady) {
      console.debug('[Terminal] Waiting for container DOM element...');
      return; // Don't create terminal until container ref is available
    }
    
    if (terminalRef.current) {
      console.debug('[Terminal] Terminal already exists, skipping initialization');
      return; // Don't create if terminal already exists
    }
    
    console.debug('[Terminal] All conditions met, creating terminal with dimensions:', backendTerminalConfig);
    console.debug('[Terminal] 🚀 CALLING initTerminal() - THIS IS WHERE XTERM GETS CREATED');
    
    const terminal = initTerminal();
    
    console.debug('[Terminal] 🚀 initTerminal() returned:', !!terminal);
    
    // Signal that terminal is ready for data
    if (terminal) {
      console.debug('[Terminal] Terminal initialized and ready for data');
      // Focus after a short delay to ensure terminal is ready
      setTimeout(() => {
        focusTerminal();
      }, 100);
    }
    
    return () => {
      destroyTerminal();
    };
  }, [backendTerminalConfig, terminalConfig, containerReady, initTerminal, destroyTerminal, focusTerminal]);

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