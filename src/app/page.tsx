'use client';

import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import { useAppStore } from '@/lib/state/store';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import Sidebar from '@/components/sidebar/Sidebar';
import { cn } from '@/lib/utils';
import type { TerminalSession } from '@/types';

// Dynamically import Terminal to avoid SSR issues
const Terminal = dynamic(() => import('@/components/terminal/Terminal'), {
  ssr: false,
  loading: () => (
    <div className="h-full flex items-center justify-center">
      <div className="animate-pulse text-gray-400">Loading terminal...</div>
    </div>
  ),
});

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
  } = useAppStore();

  const { connected, connecting, createSession, destroySession, on, off } = useWebSocket();
  const [isCreatingSession, setIsCreatingSession] = useState(false);

  // Get terminal controls for the active session
  const {
    focusTerminal,
    fitTerminal,
    scrollToBottom,
    scrollToTop,
    refreshTerminal,
    isAtBottom,
    hasNewOutput,
    backendTerminalConfig,
  } = useTerminal({
    sessionId: activeSessionId || '',
  });

  const [isRefreshing, setIsRefreshing] = useState(false);

  // Handle refresh with loading state
  const handleRefresh = () => {
    setIsRefreshing(true);
    refreshTerminal();
    // Reset refreshing state after a delay
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  // Debug connection state
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      console.log('[HomePage] Connection state:', { connected, connecting });
    }
  }, [connected, connecting]);

  // Handle the single terminal session
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
      setActiveSession(data.sessionId);
      setIsCreatingSession(false);
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

    on('session-created', handleSessionCreated);
    on('session-destroyed', handleSessionDestroyed);
    
    return () => {
      off('session-created', handleSessionCreated);
      off('session-destroyed', handleSessionDestroyed);
    };
  }, [on, off, addSession, setActiveSession, removeSession, terminalSessions.length]);

  // Initialize with the main session when connected
  useEffect(() => {
    if (terminalSessions.length === 0 && connected && !isCreatingSession) {
      if (process.env.NODE_ENV === 'development') {
        console.log('[HomePage] Requesting main session...');
      }
      setIsCreatingSession(true);
      createSession();
    }
  }, [connected, terminalSessions.length, isCreatingSession, createSession]);

  // Single terminal - no need for session management
  const handleSessionSelect = (sessionId: string) => {
    // Only one session, always active
    setActiveSession(sessionId);
  };

  const handleSessionClose = (sessionId: string) => {
    // Cannot close the main terminal - it's managed by the process
    if (process.env.NODE_ENV === 'development') {
      console.log('Terminal lifecycle managed by claude-flow process');
    }
  };

  const handleNewSession = () => {
    // Only one terminal allowed
    if (process.env.NODE_ENV === 'development') {
      console.log('Only one terminal per claude-flow process');
    }
  };

  // Show loading state
  if (loading || connecting) {
    return (
      <div className="h-full flex items-center justify-center bg-background text-foreground">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-sm text-gray-400">
            {connecting ? 'Connecting to terminal server...' : 'Loading...'}
          </p>
        </div>
      </div>
    );
  }

  // Show error state
  if (error) {
    return (
      <div className="h-full flex items-center justify-center bg-background text-foreground">
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
    );
  }

  // Show disconnected state
  if (!connected) {
    return (
      <div className="h-full flex items-center justify-center bg-background text-foreground">
        <div className="text-center">
          <div className="text-yellow-500 mb-4">
            <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold mb-2">Disconnected</h2>
          <p className="text-sm text-gray-400">
            Unable to connect to terminal server
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex bg-background text-foreground">
      {/* Left Sidebar */}
      <Sidebar
        isOpen={sidebarOpen}
        onToggle={toggleSidebar}
        sessions={terminalSessions}
        activeSessionId={activeSessionId}
        onSessionSelect={handleSessionSelect}
        onSessionCreate={handleNewSession}
        onSessionClose={handleSessionClose}
        terminalControls={activeSessionId ? {
          onRefresh: handleRefresh,
          onScrollToTop: scrollToTop,
          onScrollToBottom: scrollToBottom,
          isAtBottom,
          hasNewOutput,
          isRefreshing,
          terminalConfig: backendTerminalConfig,
        } : undefined}
      />

      {/* Main Content */}
      <div className="flex-1 flex min-w-0">
        {/* Terminal Area - no tabs needed for single terminal */}
        <div className="flex-1 relative">
          {activeSessionId ? (
            <Terminal
              key={activeSessionId}
              sessionId={activeSessionId}
              className="h-full"
            />
          ) : (
            <div className="h-full flex items-center justify-center text-gray-400">
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