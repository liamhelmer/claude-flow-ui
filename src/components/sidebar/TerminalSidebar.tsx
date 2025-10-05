'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { cn } from '@/lib/utils';
import { Terminal, Plus, X, Menu, LogOut } from 'lucide-react';
import { useAuth } from '@/components/auth/AuthProvider';
import { getTerminals, spawnTerminal, type Terminal as TerminalType } from '@/lib/api';

interface TerminalSidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  activeSessionId: string | null;
  onSessionSelect: (sessionId: string) => void;
  onSessionClose: (sessionId: string) => void;
}

export default function TerminalSidebar({
  isOpen,
  onToggle,
  activeSessionId,
  onSessionSelect,
  onSessionClose
}: TerminalSidebarProps) {
  const [terminals, setTerminals] = useState<TerminalType[]>([]);
  const [loading, setLoading] = useState(false);
  const [initialFetchDone, setInitialFetchDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { isAuthRequired } = useAuth();

  // Fetch terminals using centralized API client with exponential backoff
  const fetchTerminals = useCallback(async () => {
    // Don't fetch if auth dialog is showing
    if (isAuthRequired) {
      console.debug('[TerminalSidebar] Skipping fetch - authentication required');
      return;
    }

    try {
      console.debug('[TerminalSidebar] Fetching terminals...');

      // Use centralized API client with built-in exponential backoff and deduplication
      const data = await getTerminals();

      console.debug('[TerminalSidebar] Fetched terminals:', data);
      setTerminals(data);
      setError(null);
      setInitialFetchDone(true);
    } catch (fetchError) {
      console.error('[TerminalSidebar] Failed to fetch terminals:', fetchError);

      // API client handles retries internally
      if (fetchError instanceof Error && fetchError.message === 'Authentication required') {
        console.debug('[TerminalSidebar] Authentication required, stopping fetch');
        setInitialFetchDone(true);
        return;
      }

      // Only show error if auth is not required
      if (!isAuthRequired) {
        setError('Failed to load terminals. Please check your connection.');
      }

      setInitialFetchDone(true);
    }
  }, [isAuthRequired]);

  // Fetch terminal list with optimized intervals
  useEffect(() => {
    // Only run on client side
    if (typeof window === 'undefined') {
      console.debug('[TerminalSidebar] Server-side render, skipping fetch');
      return;
    }

    // Don't start polling if auth is required
    if (isAuthRequired) {
      console.debug('[TerminalSidebar] Skipping polling - authentication required');
      return;
    }

    console.debug('[TerminalSidebar] Component mounted, starting terminal fetch...');

    // Fetch immediately on mount
    fetchTerminals();

    // Refresh terminal list every 5 seconds (max 1 request per second minimum)
    const interval = setInterval(fetchTerminals, 5000);
    return () => clearInterval(interval);
  }, [fetchTerminals, isAuthRequired]); // Include isAuthRequired to restart polling after auth

  // Spawn a new terminal using centralized API client
  const handleSpawnTerminal = useCallback(async () => {
    if (loading) return;

    setLoading(true);
    setError(null);

    try {
      console.debug('[TerminalSidebar] Spawning new terminal...');

      // Use centralized API client
      const newTerminal = await spawnTerminal();

      setTerminals(prev => [...prev, newTerminal]);
      // Auto-select the new terminal
      onSessionSelect(newTerminal.id);
      console.log('[TerminalSidebar] Successfully spawned new terminal:', newTerminal.id);
    } catch (spawnError: any) {
      console.error('[TerminalSidebar] Failed to spawn terminal:', spawnError);
      setError(`Failed to create new terminal: ${spawnError?.message || 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  }, [loading, terminals.length, onSessionSelect]);

  // Close a terminal with improved error handling
  const handleCloseTerminal = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent selection when closing

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

      const response = await fetch(`/api/terminals/${id}`, {
        method: 'DELETE',
        headers: {
          ...(typeof window !== 'undefined' && sessionStorage.getItem('backstage_jwt_token')
            ? { 'Authorization': `Bearer ${sessionStorage.getItem('backstage_jwt_token')}` }
            : {}),
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        setTerminals(prev => prev.filter(t => t.id !== id));

        // If this was the active terminal, select another one
        if (id === activeSessionId && terminals.length > 1) {
          const remaining = terminals.filter(t => t.id !== id);
          if (remaining.length > 0) {
            onSessionSelect(remaining[0].id);
          }
        }

        console.log('[TerminalSidebar] Successfully closed terminal:', id);
      } else {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }
    } catch (closeError: any) {
      console.error('Failed to close terminal:', closeError);
      setError(`Failed to close terminal: ${closeError?.message || 'Unknown error'}`);
    }
  }, [activeSessionId, terminals, onSessionSelect]);

  // Extract command name for display - memoized for performance
  const getCommandDisplay = useCallback((command: string): string => {
    if (!command) return 'Terminal';

    // Special case for Claude Flow
    if (command.includes('claude-flow')) {
      const match = command.match(/claude-flow\s+(.+)/);
      if (match) {
        return `Claude Flow: ${match[1]}`;
      }
      return 'Claude Flow';
    }

    // Extract the main command
    const parts = command.split(' ');
    const mainCommand = parts[0].split('/').pop();

    // Shorten common commands
    if (mainCommand === 'bash') return 'Bash';
    if (mainCommand === 'sh') return 'Shell';
    if (mainCommand === 'zsh') return 'Zsh';
    if (mainCommand === 'fish') return 'Fish';
    if (mainCommand === 'node') return 'Node.js';
    if (mainCommand === 'python') return 'Python';

    return mainCommand || 'Terminal';
  }, []);

  // Get auth context
  const { isAuthenticated, userInfo, logout } = useAuth();

  return (
    <div
      className={cn(
        'flex flex-col transition-all duration-300 ease-in-out',
        'bg-gray-900 border-r border-gray-700',
        'h-full overflow-hidden relative',
        isOpen ? 'w-72' : 'w-12' // Minimal width when collapsed
      )}
    >
      {/* Collapsed state - Just hamburger menu */}
      {!isOpen && (
        <div className="flex flex-col items-center py-4">
          <button
            onClick={onToggle}
            className="p-2 hover:bg-gray-800 rounded transition-colors"
            title="Open Sidebar"
          >
            <Menu className="w-5 h-5 text-gray-300" />
          </button>
        </div>
      )}

      {/* Expanded state - Full sidebar */}
      {isOpen && (
        <div className="flex flex-col h-full">
          {/* Header with X button */}
          <div className="flex items-center justify-between p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Terminal className="w-5 h-5" />
              Terminals
            </h2>
            <button
              onClick={onToggle}
              className="p-1 hover:bg-gray-800 rounded transition-colors"
              title="Close Sidebar"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          </div>

            {/* Terminal List */}
            <div className="flex-1 overflow-y-auto p-2">
              {error && (
                <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg">
                  <div className="flex items-center gap-2 text-red-400 text-sm">
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.464 0L4.35 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    <span>{error}</span>
                  </div>
                  <button
                    onClick={() => {
                      setError(null);
                      fetchTerminals();
                    }}
                    className="mt-2 px-2 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
                  >
                    Retry
                  </button>
                </div>
              )}
              {!initialFetchDone ? (
                <div className="text-center text-gray-400 py-4">
                  <div className="animate-pulse">Loading terminals...</div>
                </div>
              ) : terminals.length === 0 ? (
                <div className="text-center text-gray-400 py-4">
                  <Terminal className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <div className="text-sm">No terminals yet</div>
                  <div className="text-xs mt-1">Click "New Terminal" to create one</div>
                </div>
              ) : (
                <div className="space-y-1">
                  {terminals.map((terminal) => {
                  const isActive = terminal.id === activeSessionId;
                  const isMainTerminal = terminal.name === 'Claude Flow';

                  return (
                    <div
                      key={terminal.id}
                      onClick={() => onSessionSelect(terminal.id)}
                      className={cn(
                        'group flex items-center justify-between p-2 rounded-lg cursor-pointer',
                        'transition-colors',
                        isActive
                          ? 'bg-blue-600 text-white'
                          : 'hover:bg-gray-800 text-gray-300 hover:text-white'
                      )}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Terminal className="w-4 h-4 flex-shrink-0" />
                        <div className="min-w-0">
                          <div className="font-medium truncate">
                            {terminal.name}
                          </div>
                          <div className={cn(
                            'text-xs truncate',
                            isActive ? 'text-blue-200' : 'text-gray-500'
                          )}>
                            {getCommandDisplay(terminal.command)}
                          </div>
                        </div>
                      </div>

                      {!isMainTerminal && (
                        <button
                          onClick={(e) => handleCloseTerminal(terminal.id, e)}
                          className={cn(
                            'p-1 rounded opacity-0 group-hover:opacity-100 transition-opacity',
                            isActive
                              ? 'hover:bg-blue-700'
                              : 'hover:bg-gray-700'
                          )}
                          title="Close Terminal"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  );
                  })}
                </div>
              )}

              {/* New Terminal Button */}
              <button
                onClick={handleSpawnTerminal}
                disabled={loading}
                className={cn(
                  'mt-4 w-full flex items-center justify-center gap-2 p-2 rounded-lg',
                  'bg-green-600 hover:bg-green-700 transition-colors',
                  'text-white text-sm font-medium',
                  'border border-green-500',
                  loading && 'opacity-50 cursor-not-allowed'
                )}
              >
                <Plus className="w-4 h-4" />
                {loading ? 'Spawning...' : 'New Terminal'}
              </button>
            </div>

          {/* Footer Info and Auth */}
          <div className="border-t border-gray-700">
            {/* User info and logout button */}
            {isAuthenticated && (
              <div className="p-3 border-b border-gray-700">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 text-gray-400 min-w-0">
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                    <span className="truncate">
                      {userInfo?.name || userInfo?.email || 'Authenticated'}
                    </span>
                  </div>
                  <button
                    onClick={logout}
                    className="p-1.5 hover:bg-gray-800 rounded transition-colors text-gray-400 hover:text-red-400"
                    title="Logout"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* Terminal info */}
            <div className="p-4 text-xs text-gray-400">
              <div className="space-y-1">
                <div>• Click terminal to switch</div>
                <div>• Click × to close terminal</div>
                <div>• Main terminal cannot be closed</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}