'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { cn } from '@/lib/utils';

// Dynamically import monitoring panels to avoid SSR issues
const MemoryPanel = dynamic(() => import('./MemoryPanel'), { 
  ssr: false,
  loading: () => <div className="p-4 text-gray-500">Loading...</div>
});
const AgentsPanel = dynamic(() => import('./AgentsPanel'), { 
  ssr: false,
  loading: () => <div className="p-4 text-gray-500">Loading...</div>
});
const PromptPanel = dynamic(() => import('./PromptPanel'), { 
  ssr: false,
  loading: () => <div className="p-4 text-gray-500">Loading...</div>
});
const CommandsPanel = dynamic(() => import('./CommandsPanel'), { 
  ssr: false,
  loading: () => <div className="p-4 text-gray-500">Loading...</div>
});

interface MonitoringSidebarProps {
  isOpen: boolean;
  onToggle: () => void;
}

export default function MonitoringSidebar({ isOpen, onToggle }: MonitoringSidebarProps) {
  const [activeTab, setActiveTab] = useState(0);

  const tabs = [
    { id: 'memory', label: 'Memory', icon: '💾' },
    { id: 'agents', label: 'Agents', icon: '🤖' },
    { id: 'prompt', label: 'Prompt', icon: '📝' },
    { id: 'commands', label: 'Commands', icon: '⚡' },
  ];

  return (
    <>
      {/* Monitoring Sidebar */}
      <div
        className={cn(
          'fixed right-0 top-0 h-full z-40',
          'bg-gray-900 border-l border-gray-700',
          'transition-transform duration-300 ease-in-out',
          'flex flex-col',
          isOpen ? 'translate-x-0 w-96' : 'translate-x-full w-0'
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700 bg-gray-800">
          <div className="flex items-center gap-2">
            <span className="text-xl">🐝</span>
            <h2 className="text-lg font-semibold text-white">Claude Flow UI Monitor</h2>
          </div>
          <button
            onClick={onToggle}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
            title="Close Monitor"
          >
            <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-gray-700 bg-gray-800">
          {tabs.map((tab, index) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(index)}
              className={cn(
                'flex-1 px-3 py-2 text-sm font-medium transition-colors',
                'border-b-2',
                activeTab === index
                  ? 'text-blue-400 border-blue-400 bg-gray-900'
                  : 'text-gray-400 border-transparent hover:text-white hover:bg-gray-700'
              )}
            >
              <span className="mr-1">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Panel Content */}
        <div className="flex-1 overflow-hidden bg-gray-900">
          {activeTab === 0 && <MemoryPanel />}
          {activeTab === 1 && <AgentsPanel />}
          {activeTab === 2 && <PromptPanel />}
          {activeTab === 3 && <CommandsPanel />}
        </div>
      </div>

      {/* Toggle Button when closed */}
      {!isOpen && (
        <button
          onClick={onToggle}
          className={cn(
            'fixed top-4 right-4 z-30',
            'p-2 bg-gray-800 hover:bg-gray-700',
            'rounded-lg border border-gray-600 transition-colors',
            'flex items-center gap-2'
          )}
          title="Open Monitor"
        >
          <span>🐝</span>
          <svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
        </button>
      )}
    </>
  );
}