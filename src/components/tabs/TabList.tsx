'use client';

import { cn } from '@/lib/utils';
import Tab from './Tab';
import type { TerminalSession } from '@/types';

interface TabListProps {
  sessions: TerminalSession[];
  activeSessionId: string | null;
  onSessionSelect: (sessionId: string) => void;
  onSessionClose: (sessionId: string) => void;
  onSessionCreate: () => void;
  onNewSession?: () => void; // Legacy support
  className?: string;
}

export default function TabList({
  sessions,
  activeSessionId,
  onSessionSelect,
  onSessionClose,
  onSessionCreate,
  onNewSession, // Legacy support
  className,
}: TabListProps) {
  return (
    <div className={cn('flex items-center bg-gray-800 border-b border-gray-700', className)}>
      {/* Tabs container */}
      <div className="flex flex-1 overflow-x-auto scrollbar-thin scrollbar-thumb-gray-600">
        {sessions.map((session) => (
          <Tab
            key={session.id}
            title={session.name}
            isActive={session.id === activeSessionId}
            onSelect={() => onSessionSelect(session.id)}
            onClose={() => onSessionClose(session.id)}
            closable={sessions.length > 1}
          />
        ))}
      </div>
      
      {/* New tab button */}
      <button
        onClick={onSessionCreate || onNewSession}
        className={cn(
          'flex-shrink-0 px-3 py-2 text-sm font-medium',
          'text-gray-400 hover:text-gray-200 hover:bg-gray-700',
          'border-l border-gray-700 transition-colors'
        )}
        aria-label="Create new terminal session"
      >
        +
      </button>
    </div>
  );
}