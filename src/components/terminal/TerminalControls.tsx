'use client';

import { ChevronUp, ChevronDown, AlertCircle, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TerminalControlsProps {
  isAtBottom: boolean;
  hasNewOutput: boolean;
  onScrollToTop: () => void;
  onScrollToBottom: () => void;
  onRefresh: () => void;
  terminalConfig?: { cols: number; rows: number } | null;
  className?: string;
  isRefreshing?: boolean;
}

export default function TerminalControls({
  isAtBottom,
  hasNewOutput,
  onScrollToTop,
  onScrollToBottom,
  onRefresh,
  terminalConfig,
  className,
  isRefreshing = false,
}: TerminalControlsProps) {
  return (
    <div className={cn('flex flex-col gap-2 p-2', className)}>
      {/* Refresh button */}
      <button
        onClick={onRefresh}
        disabled={isRefreshing}
        className={cn(
          'flex items-center justify-center p-2 rounded-lg',
          'bg-green-600 hover:bg-green-700 transition-colors',
          'text-white',
          'border border-green-500',
          'group',
          isRefreshing && 'opacity-70 cursor-not-allowed'
        )}
        title="Refresh terminal and reload history"
      >
        <RefreshCw className={cn('w-5 h-5', isRefreshing && 'animate-spin')} />
      </button>

      {/* Scroll to top button */}
      <button
        onClick={onScrollToTop}
        className={cn(
          'flex items-center justify-center p-2 rounded-lg',
          'bg-gray-800 hover:bg-gray-700 transition-colors',
          'text-gray-400 hover:text-white',
          'border border-gray-700',
          'group'
        )}
        title="Scroll to top"
      >
        <ChevronUp className="w-5 h-5" />
      </button>

      {/* See latest button - only show when there's new output and not at bottom */}
      {hasNewOutput && !isAtBottom && (
        <button
          onClick={onScrollToBottom}
          className={cn(
            'flex items-center justify-center gap-2 px-3 py-2 rounded-lg',
            'bg-blue-600 hover:bg-blue-700 transition-all',
            'text-white font-medium text-sm',
            'border border-blue-500',
            'animate-pulse'
          )}
          title="Jump to latest output"
        >
          <AlertCircle className="w-4 h-4" />
          <span>See latest</span>
        </button>
      )}

      {/* Scroll to bottom button */}
      <button
        onClick={onScrollToBottom}
        className={cn(
          'flex items-center justify-center p-2 rounded-lg',
          'bg-gray-800 hover:bg-gray-700 transition-colors',
          'text-gray-400 hover:text-white',
          'border border-gray-700',
          'group',
          isAtBottom && 'opacity-50 cursor-default'
        )}
        title="Scroll to bottom"
        disabled={isAtBottom}
      >
        <ChevronDown className="w-5 h-5" />
      </button>

      {/* Visual indicator for scroll position */}
      <div className="mt-2 px-2">
        <div className="h-1 bg-gray-800 rounded-full overflow-hidden">
          <div 
            className={cn(
              'h-full transition-all duration-300',
              isAtBottom ? 'bg-green-500 w-full' : 'bg-gray-600 w-1/2'
            )}
          />
        </div>
      </div>

      {/* Terminal size display */}
      <div className="mt-4 px-2">
        <div className="text-xs text-gray-500 font-mono text-center">
          <div>Terminal Size</div>
          <div className="text-gray-400 font-semibold">
            {terminalConfig ? `${terminalConfig.cols}×${terminalConfig.rows}` : 'Waiting...'}
          </div>
          <div className="text-gray-600 mt-1">Backend</div>
        </div>
      </div>
    </div>
  );
}