'use client';

import { useEffect, useState } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';

interface Command {
  id: string;
  command: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  agentId?: string;
  output?: string;
  error?: string;
  startTime: number;
  endTime?: number;
  duration?: number;
}

const statusColors = {
  pending: 'text-yellow-400 bg-yellow-400/10',
  running: 'text-blue-400 bg-blue-400/10',
  completed: 'text-green-400 bg-green-400/10',
  failed: 'text-red-400 bg-red-400/10',
};

const statusIcons = {
  pending: '⏳',
  running: '🔄',
  completed: '✅',
  failed: '❌',
};

export default function CommandsPanel() {
  const { on, off, isConnected } = useWebSocket();
  const [commands, setCommands] = useState<Command[]>([]);
  const [selectedCommand, setSelectedCommand] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'running' | 'completed' | 'failed'>('all');

  useEffect(() => {
    const handleCommandCreated = (data: any) => {
      const command: Command = {
        id: data.id || Math.random().toString(36).slice(2),
        command: data.command,
        status: 'pending',
        agentId: data.agentId,
        startTime: Date.now(),
      };
      
      setCommands(prev => [command, ...prev].slice(0, 100)); // Keep last 100
    };

    const handleCommandUpdate = (data: any) => {
      setCommands(prev => prev.map(cmd => {
        if (cmd.id === data.id) {
          const updated = { ...cmd, ...data };
          if (data.status === 'completed' || data.status === 'failed') {
            updated.endTime = Date.now();
            updated.duration = updated.endTime - cmd.startTime;
          }
          return updated;
        }
        return cmd;
      }));
    };

    const handleCommandOutput = (data: any) => {
      setCommands(prev => prev.map(cmd => {
        if (cmd.id === data.id) {
          return {
            ...cmd,
            output: (cmd.output || '') + data.output,
          };
        }
        return cmd;
      }));
    };

    on('command-created', handleCommandCreated);
    on('command-update', handleCommandUpdate);
    on('command-output', handleCommandOutput);

    return () => {
      off('command-created', handleCommandCreated);
      off('command-update', handleCommandUpdate);
      off('command-output', handleCommandOutput);
    };
  }, [on, off]);

  if (!isConnected) {
    return (
      <div className="p-4 text-gray-500">
        <div className="text-sm">Disconnected</div>
      </div>
    );
  }

  const filteredCommands = commands.filter(cmd => 
    filter === 'all' || cmd.status === filter
  );

  const selected = selectedCommand 
    ? commands.find(cmd => cmd.id === selectedCommand)
    : null;

  const stats = {
    total: commands.length,
    running: commands.filter(c => c.status === 'running').length,
    completed: commands.filter(c => c.status === 'completed').length,
    failed: commands.filter(c => c.status === 'failed').length,
  };

  return (
    <div className="flex flex-col h-full">
      {/* Filter Tabs */}
      <div className="flex p-2 border-b border-gray-700 gap-1">
        {(['all', 'running', 'completed', 'failed'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`flex-1 px-2 py-1 text-xs rounded transition-colors ${
              filter === f 
                ? 'bg-blue-500 text-white' 
                : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
            {f === 'all' && ` (${stats.total})`}
            {f === 'running' && ` (${stats.running})`}
            {f === 'completed' && ` (${stats.completed})`}
            {f === 'failed' && ` (${stats.failed})`}
          </button>
        ))}
      </div>

      {/* Command List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {filteredCommands.length === 0 ? (
          <div className="text-sm text-gray-500">
            No {filter !== 'all' ? filter : ''} commands
          </div>
        ) : (
          filteredCommands.map(cmd => (
            <div
              key={cmd.id}
              onClick={() => setSelectedCommand(cmd.id)}
              tabIndex={0}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                selectedCommand === cmd.id
                  ? 'border-blue-500 bg-blue-500/10'
                  : 'border-gray-700 hover:border-gray-600 bg-gray-800/50'
              }`}
            >
              <div className="flex items-start justify-between mb-1">
                <div className="flex-1 min-w-0">
                  <code className="text-xs text-gray-300 font-mono block truncate">
                    {cmd.command}
                  </code>
                </div>
                <div className="flex items-center gap-2 ml-2">
                  <span className="text-sm">{statusIcons[cmd.status]}</span>
                  <span className={`px-2 py-0.5 rounded text-xs ${statusColors[cmd.status]}`}>
                    {cmd.status}
                  </span>
                </div>
              </div>
              
              <div className="flex items-center gap-3 text-xs text-gray-400">
                {cmd.agentId && (
                  <span>Agent: {cmd.agentId.slice(0, 8)}</span>
                )}
                {cmd.duration && (
                  <span>{(cmd.duration / 1000).toFixed(2)}s</span>
                )}
                <span>{new Date(cmd.startTime).toLocaleTimeString()}</span>
              </div>

              {cmd.status === 'running' && (
                <div className="mt-2">
                  <div className="h-1 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full bg-blue-500 animate-pulse" />
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Selected Command Details */}
      {selected && (
        <div className="border-t border-gray-700 p-4 bg-gray-800/50 max-h-64 overflow-y-auto">
          <h3 className="text-sm font-medium text-white mb-2">Command Output</h3>
          
          <div className="space-y-2">
            <div className="text-xs">
              <span className="text-gray-400">Command:</span>
              <code className="ml-2 text-gray-300 font-mono">{selected.command}</code>
            </div>
            
            {selected.output && (
              <div className="bg-black rounded p-2 max-h-32 overflow-y-auto">
                <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">
                  {selected.output}
                </pre>
              </div>
            )}
            
            {selected.error && (
              <div className="bg-red-900/20 rounded p-2">
                <pre className="text-xs text-red-400 font-mono whitespace-pre-wrap">
                  {selected.error}
                </pre>
              </div>
            )}
            
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-gray-400">Started:</span>
                <span className="ml-1 text-gray-300">
                  {new Date(selected.startTime).toLocaleTimeString()}
                </span>
              </div>
              {selected.endTime && (
                <div>
                  <span className="text-gray-400">Duration:</span>
                  <span className="ml-1 text-gray-300">
                    {((selected.endTime - selected.startTime) / 1000).toFixed(2)}s
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}