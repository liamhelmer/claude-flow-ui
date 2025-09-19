'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { useAppStore, initializeSidebarForViewport } from '@/lib/state/store';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import TerminalSidebar from '@/components/sidebar/TerminalSidebar';
import Terminal from '@/components/terminal/Terminal';
import { cn } from '@/lib/utils';
import type { TerminalSession } from '@/types';

export default function HomePage() {
  const {
    terminalSessions,
    activeSessionId,
    sidebarOpen,
    loading,
    error,
    toggleSidebar,
    setActiveSession,
    addSession,
    removeSession,
    updateSession,
    setLoading,
    setError,
  } = useAppStore();

  const { connected, connecting, createSession, destroySession, switchSession, on, off } = useWebSocket();

  // REMOVED: Don't create a separate terminal instance here
  // The Terminal component will handle its own instance
  // This prevents duplicate terminal spawning and listener registration

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [initialSessionFetched, setInitialSessionFetched] = useState(false);
  const [pendingSessionId, setPendingSessionId] = useState<string | null>(null);
  const [connectionRetries, setConnectionRetries] = useState(0);
  const [hasEverConnected, setHasEverConnected] = useState(false);
  const maxRetries = 3;

  // REMOVED: Refresh is handled by the Terminal component
  // No need for duplicate refresh handling here

  // Track connection state and whether we've ever connected
  useEffect(() => {
    if (connected && !hasEverConnected) {
      setHasEverConnected(true);
    }
    if (process.env.NODE_ENV === 'development') {
      console.log('[HomePage] Connection state:', { connected, connecting, hasEverConnected });
    }
  }, [connected, connecting, hasEverConnected]);

  // Memoized fetch function to prevent recreation on every render
  const fetchInitialSession = useCallback(async () => {
    try {
      console.log('[HomePage] fetchInitialSession called - starting fetch from /api/terminals');
      setLoading(true);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

      const response = await fetch('/api/terminals', {
        signal: controller.signal,
        headers: {
          'Cache-Control': 'no-cache',
        },
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const terminals = await response.json();
        if (terminals && terminals.length > 0) {
          const mainTerminal = terminals[0];
          console.log('[HomePage] Found initial terminal:', mainTerminal.id);
          // Set pending session ID immediately for Terminal to use
          setPendingSessionId(mainTerminal.id);
          const mainSession: TerminalSession = {
            id: mainTerminal.id,
            name: mainTerminal.name || 'Claude Flow Terminal',
            isActive: true,
            lastActivity: new Date(mainTerminal.createdAt),
          };
          addSession(mainSession);
          setActiveSession(mainTerminal.id);
          setInitialSessionFetched(true);

          // INITIAL TERMINAL FIX: Ensure WebSocket connection before setting session
          // This prevents race conditions with terminal data handling
          // Only switch if not already on this session
          if (connected && activeSessionId !== mainTerminal.id) {
            console.debug('[HomePage] WebSocket already connected, switching to terminal session');
            switchSession(mainTerminal.id);
          } else if (!connected) {
            console.debug('[HomePage] WebSocket not ready, session will be switched on connection');
          }
          setConnectionRetries(0); // Reset retries on success
        } else {
          console.log('[HomePage] No terminals found, waiting for server to create one...');
          setInitialSessionFetched(true); // Don't keep retrying if no terminals
        }
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      console.error('[HomePage] Failed to fetch initial terminals:', error);

      if (connectionRetries < maxRetries) {
        setConnectionRetries(prev => prev + 1);
        console.log(`[HomePage] Retrying connection (${connectionRetries + 1}/${maxRetries})...`);
        // Exponential backoff: 1s, 2s, 4s
        setTimeout(() => {
          if (!initialSessionFetched) {
            fetchInitialSession();
          }
        }, Math.pow(2, connectionRetries) * 1000);
      } else {
        setError('Failed to connect to terminal server. Please refresh the page.');
        setInitialSessionFetched(true);
      }
    } finally {
      setLoading(false);
    }
  }, [initialSessionFetched, addSession, setActiveSession, connectionRetries, setLoading, setError, activeSessionId, connected, switchSession]);

  // Fetch initial terminal session from API immediately on mount
  useEffect(() => {
    console.log('[HomePage] useEffect for fetchInitialSession:', { initialSessionFetched });
    if (!initialSessionFetched) {
      console.log('[HomePage] Calling fetchInitialSession immediately...');
      // Call immediately without waiting
      fetchInitialSession();
    } else {
      console.log('[HomePage] Skipping fetchInitialSession - already fetched');
    }
    // Run only once on mount
  }, []); // Empty deps to run immediately on mount

  // Initialize sidebar state based on viewport size
  useEffect(() => {
    initializeSidebarForViewport();

    // Handle window resize
    const handleResize = () => {
      initializeSidebarForViewport();
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Handle WebSocket terminal events
  useEffect(() => {
    const handleSessionCreated = (data: { sessionId: string }) => {
      if (process.env.NODE_ENV === 'development') {
        console.log('[HomePage] Connected to terminal:', data.sessionId);
      }
      // Only maintain one session - the main terminal
      const mainSession: TerminalSession = {
        id: data.sessionId,
        name: 'Claude Flow Terminal',
        isActive: true,
        lastActivity: new Date(),
      };
      // Clear any existing sessions and set the main one
      if (terminalSessions.length === 0) {
        addSession(mainSession);
      }
      // INITIAL TERMINAL FIX: Synchronize session IDs to prevent race conditions
      console.debug('[HomePage] Session created, synchronizing with API session if needed');

      // If we already have a session from API, ensure they match
      if (terminalSessions.length > 0) {
        const existingSession = terminalSessions[0];
        if (existingSession.id !== data.sessionId) {
          console.debug('[HomePage] Updating session ID to match WebSocket:', data.sessionId);
          // Update the existing session to use the WebSocket session ID
          updateSession(existingSession.id, { id: data.sessionId });
        }
      }

      // Only switch if we're not already on this session
      if (activeSessionId !== data.sessionId) {
        // Notify backend about the session switch
        switchSession(data.sessionId);
        setActiveSession(data.sessionId);
      }
    };

    const handleSessionDestroyed = (data: { 
      sessionId: string; 
      reason?: string; 
      exitCode?: number;
      signal?: string;
    }) => {
      if (process.env.NODE_ENV === 'development') {
        console.log('[HomePage] Terminal disconnected:', data.sessionId, data.reason);
      }
      removeSession(data.sessionId);
      
      // If claude-flow exited, the whole UI will shut down
      if (data.reason === 'claude-flow-exited') {
        const exitMsg = data.exitCode !== undefined 
          ? `Claude Flow exited with code ${data.exitCode}` 
          : 'Claude Flow process terminated';
        if (process.env.NODE_ENV === 'development') {
          console.log(exitMsg);
        }
      }
    };

    // Handle terminal events
    const handleTerminalSpawned = (data: { id: string; name: string; command: string; createdAt: string }) => {
      const newSession: TerminalSession = {
        id: data.id,
        name: data.name,
        isActive: false,
        lastActivity: new Date(data.createdAt),
      };
      addSession(newSession);
      // Automatically switch to newly spawned terminal
      if (activeSessionId !== data.id) {
        switchSession(data.id);
        setActiveSession(data.id);
      }
      console.log('[HomePage] Terminal spawned and activated:', data.id);
    };

    const handleTerminalClosed = (data: { id: string }) => {
      removeSession(data.id);
      console.log('[HomePage] Terminal closed:', data.id);
    };

    on('session-created', handleSessionCreated);
    on('session-destroyed', handleSessionDestroyed);
    on('terminal-spawned', handleTerminalSpawned);
    on('terminal-closed', handleTerminalClosed);

    return () => {
      off('session-created', handleSessionCreated);
      off('session-destroyed', handleSessionDestroyed);
      off('terminal-spawned', handleTerminalSpawned);
      off('terminal-closed', handleTerminalClosed);
    };
    // Remove terminalSessions.length from dependencies to prevent re-registration
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [on, off, addSession, setActiveSession, removeSession, switchSession, activeSessionId, updateSession]);

  // The main session is created by the server on startup, no need to request it
  // We just wait for the session-created event which the server sends automatically

  // Handle terminal session selection with coordinated state updates
  const handleSessionSelect = useCallback(async (sessionId: string) => {
    console.debug('[HomePage] 🔄 Switching to session:', sessionId);

    try {
      // 1. Update local state first to prevent race conditions
      setActiveSession(sessionId);

      // 2. Notify backend about session switch
      switchSession(sessionId);

      console.debug('[HomePage] ✅ Session switch completed:', sessionId);
    } catch (error) {
      console.error('[HomePage] ❌ Failed to switch session:', error);
    }
  }, [switchSession, setActiveSession]);

  const handleSessionClose = async (sessionId: string) => {
    // Handle closing terminals (except the main one which is handled by the backend)
    try {
      const response = await fetch(`/api/terminals/${sessionId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        removeSession(sessionId);

        // If this was the active session, switch to another
        if (sessionId === activeSessionId) {
          const remaining = terminalSessions.filter(s => s.id !== sessionId);
          if (remaining.length > 0) {
            setActiveSession(remaining[0].id);
          }
        }
      } else {
        const error = await response.json();
        console.error('Failed to close terminal:', error);
      }
    } catch (error) {
      console.error('Error closing terminal:', error);
    }
  };

  const handleNewSession = () => {
    // This is now handled by the TerminalSidebar component
    if (process.env.NODE_ENV === 'development') {
      console.log('New terminal creation handled by sidebar');
    }
  };

  // Show loading state only while initially loading, not while connecting
  // WebSocket connection happens after terminal is ready
  if (loading) {
    return (
      <div className="h-full flex bg-background text-foreground">
        {/* Always show sidebar */}
        <TerminalSidebar
          isOpen={sidebarOpen}
          onToggle={toggleSidebar}
          activeSessionId={activeSessionId}
          onSessionSelect={handleSessionSelect}
          onSessionClose={handleSessionClose}
        />

        {/* Loading content */}
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-sm text-gray-400">Loading...</p>
          </div>
        </div>
      </div>
    );
  }

  // Show error state
  if (error) {
    return (
      <div className="h-full flex bg-background text-foreground">
        {/* Always show sidebar */}
        <TerminalSidebar
          isOpen={sidebarOpen}
          onToggle={toggleSidebar}
          activeSessionId={activeSessionId}
          onSessionSelect={handleSessionSelect}
          onSessionClose={handleSessionClose}
        />

        {/* Error content */}
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center max-w-md">
            <div className="text-red-500 mb-4">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.464 0L4.35 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h2 className="text-xl font-semibold mb-2">Connection Error</h2>
            <p className="text-sm text-gray-400 mb-4">{error}</p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Only show disconnected state if we HAD a connection and lost it
  // In production mode with command-line args, activeSessionId may be set before WebSocket connects
  if (!connected && hasEverConnected && activeSessionId) {
    return (
      <div className="h-full flex bg-background text-foreground">
        {/* Always show sidebar */}
        <TerminalSidebar
          isOpen={sidebarOpen}
          onToggle={toggleSidebar}
          activeSessionId={activeSessionId}
          onSessionSelect={handleSessionSelect}
          onSessionClose={handleSessionClose}
        />

        {/* Disconnected content */}
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="text-yellow-500 mb-4">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-xl font-semibold mb-2">Disconnected</h2>
            <p className="text-sm text-gray-400">
              Connection to terminal server was lost
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex bg-background text-foreground">
      {/* Left Sidebar - Terminal List */}
      <TerminalSidebar
        isOpen={sidebarOpen}
        onToggle={toggleSidebar}
        activeSessionId={activeSessionId}
        onSessionSelect={handleSessionSelect}
        onSessionClose={handleSessionClose}
      />

      {/* Main Content - Terminal Area directly adjacent to sidebar */}
      <div className="flex-1 flex min-w-0">
        {/* Terminal Area - no tabs needed for single terminal */}
        <div className="flex-1 relative">
          {/* Always render Terminal component to avoid unmounting */}
          {(() => {
            // Use pendingSessionId if activeSessionId not yet set
            const sessionToUse = activeSessionId || pendingSessionId || '';
            console.log('[HomePage] 🔧 Rendering Terminal with sessionId:', sessionToUse);
            return (
              <Terminal
                sessionId={sessionToUse}
                className="h-full"
              />
            );
          })()}
          {/* Show overlay when no session */}
          {!activeSessionId && (
            <div className="absolute inset-0 h-full flex items-center justify-center text-gray-400 bg-background z-10">
              <div className="text-center">
                <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <p className="text-lg mb-2">Connecting to Terminal...</p>
                <p className="text-sm">Waiting for claude-flow process</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}