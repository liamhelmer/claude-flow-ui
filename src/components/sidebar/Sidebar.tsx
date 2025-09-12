'use client';

import { cn } from '@/lib/utils';
import type { SidebarProps } from '@/types';
import { RefreshCw, ChevronUp, ChevronDown } from 'lucide-react';

export default function Sidebar({
  isOpen,
  onToggle,
  sessions,
  activeSessionId,
  onSessionSelect,
  onSessionCreate,
  onSessionClose,
  terminalControls,
}: SidebarProps) {
  return (
    <>
      {/* Sidebar */}
      <div
        className={cn(
          'sidebar-container flex flex-col transition-all duration-300 ease-in-out',
          'h-full overflow-hidden',
          isOpen ? 'w-64' : 'w-0'
        )}
      >
        {isOpen && (
          <div className="flex flex-col h-full">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
              <h2 className="text-lg font-semibold">Claude Flow Terminal</h2>
              <button
                onClick={onToggle}
                className="p-1 hover:bg-sidebar-hover rounded transition-colors"
                title="Toggle Sidebar"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Terminal Status */}
            <div className="flex-1 overflow-y-auto p-4">
              <div className="space-y-4">
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Status</h3>
                  {sessions.length > 0 ? (
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                      <span className="text-sm">Terminal Connected</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-gray-500 rounded-full"></div>
                      <span className="text-sm text-gray-400">Connecting...</span>
                    </div>
                  )}
                </div>

                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Keyboard Shortcuts</h3>
                  <div className="text-xs space-y-1 text-gray-300">
                    <div>Ctrl+C - Interrupt</div>
                    <div>Ctrl+D - Exit</div>
                    <div>Ctrl+L - Clear</div>
                    <div>↑/↓ - History</div>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Scroll</h3>
                  <div className="text-xs text-gray-300">
                    Use mouse wheel or touchpad to scroll through output history
                  </div>
                </div>

                {/* Terminal Controls Section */}
                {terminalControls && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-400 mb-2">Terminal Controls</h3>
                    <div className="space-y-2">
                      {/* Refresh Button */}
                      <button
                        onClick={terminalControls.onRefresh}
                        disabled={terminalControls.isRefreshing}
                        className={cn(
                          'w-full flex items-center justify-center gap-2 p-2 rounded-lg',
                          'bg-green-600 hover:bg-green-700 transition-colors',
                          'text-white text-sm',
                          'border border-green-500',
                          terminalControls.isRefreshing && 'opacity-70 cursor-not-allowed'
                        )}
                        title="Refresh terminal and reload history"
                      >
                        <RefreshCw className={cn('w-4 h-4', terminalControls.isRefreshing && 'animate-spin')} />
                        {terminalControls.isRefreshing ? 'Refreshing...' : 'Refresh'}
                      </button>

                      {/* Scroll Controls */}
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          onClick={terminalControls.onScrollToTop}
                          className={cn(
                            'flex items-center justify-center gap-1 p-2 rounded-lg',
                            'bg-blue-600 hover:bg-blue-700 transition-colors',
                            'text-white text-xs',
                            'border border-blue-500'
                          )}
                          title="Scroll to top"
                        >
                          <ChevronUp className="w-3 h-3" />
                          Top
                        </button>
                        
                        <button
                          onClick={terminalControls.onScrollToBottom}
                          disabled={terminalControls.isAtBottom}
                          className={cn(
                            'flex items-center justify-center gap-1 p-2 rounded-lg',
                            'bg-blue-600 hover:bg-blue-700 transition-colors',
                            'text-white text-xs',
                            'border border-blue-500',
                            terminalControls.isAtBottom && 'opacity-50 cursor-not-allowed'
                          )}
                          title="Scroll to bottom"
                        >
                          <ChevronDown className="w-3 h-3" />
                          Bottom
                        </button>
                      </div>

                      {/* Terminal Status */}
                      {terminalControls.terminalConfig && (
                        <div className="text-xs text-gray-400 border-t border-gray-700 pt-2">
                          <div>Size: {terminalControls.terminalConfig.cols}×{terminalControls.terminalConfig.rows}</div>
                          {terminalControls.hasNewOutput && (
                            <div className="text-yellow-400 flex items-center gap-1 mt-1">
                              <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
                              New output
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Toggle button when sidebar is closed */}
      {!isOpen && (
        <button
          onClick={onToggle}
          className={cn(
            'fixed top-4 left-4 z-50 p-2 bg-gray-800 hover:bg-gray-700',
            'rounded border border-gray-600 transition-colors'
          )}
          title="Open Sidebar"
        >
          <svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      )}
    </>
  );
}