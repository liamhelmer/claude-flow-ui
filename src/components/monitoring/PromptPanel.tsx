'use client';

import { useEffect, useState } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';

interface PromptData {
  current: string;
  history: string[];
  context: {
    model?: string;
    temperature?: number;
    maxTokens?: number;
    systemPrompt?: string;
  };
  timestamp: number;
}

export default function PromptPanel() {
  const { on, off, isConnected } = useWebSocket();
  const [promptData, setPromptData] = useState<PromptData>({
    current: 'Welcome to Claude Flow Terminal',
    history: ['System initialized', 'Ready for input'],
    context: {
      model: 'claude-3',
      temperature: 0.7,
      maxTokens: 4096,
      systemPrompt: 'Claude Flow UI Terminal System',
    },
    timestamp: Date.now(),
  });
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    const handlePromptUpdate = (data: any) => {
      setPromptData(prev => ({
        current: data.prompt || prev.current,
        history: data.prompt ? [...prev.history, data.prompt] : prev.history,
        context: data.context || prev.context,
        timestamp: Date.now(),
      }));
    };

    const handleSystemPrompt = (data: any) => {
      setPromptData(prev => ({
        ...prev,
        context: {
          ...prev.context,
          systemPrompt: data.systemPrompt,
        },
      }));
    };

    on('prompt-update', handlePromptUpdate);
    on('system-prompt', handleSystemPrompt);

    return () => {
      off('prompt-update', handlePromptUpdate);
      off('system-prompt', handleSystemPrompt);
    };
  }, [on, off]);

  if (!isConnected) {
    return (
      <div className="p-4 text-gray-500">
        <div className="text-sm">Disconnected</div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Current Prompt */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium text-white">Current Prompt</h3>
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="text-xs text-gray-400 hover:text-white transition-colors"
          >
            {showHistory ? 'Hide' : 'Show'} History
          </button>
        </div>
        
        {promptData.current ? (
          <div className="bg-gray-800 rounded-lg p-3 max-h-32 overflow-y-auto">
            <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">
              {promptData.current}
            </pre>
          </div>
        ) : (
          <div className="text-sm text-gray-500">No active prompt</div>
        )}
      </div>

      {/* Context Information */}
      <div className="p-4 border-b border-gray-700">
        <h3 className="text-sm font-medium text-white mb-2">Context</h3>
        <div className="space-y-1 text-xs">
          {promptData.context.model && (
            <div className="flex justify-between">
              <span className="text-gray-400">Model:</span>
              <span className="text-gray-300">{promptData.context.model}</span>
            </div>
          )}
          {promptData.context.temperature !== undefined && (
            <div className="flex justify-between">
              <span className="text-gray-400">Temperature:</span>
              <span className="text-gray-300">{promptData.context.temperature}</span>
            </div>
          )}
          {promptData.context.maxTokens && (
            <div className="flex justify-between">
              <span className="text-gray-400">Max Tokens:</span>
              <span className="text-gray-300">{promptData.context.maxTokens}</span>
            </div>
          )}
        </div>
      </div>

      {/* System Prompt */}
      {promptData.context.systemPrompt && (
        <div className="p-4 border-b border-gray-700">
          <h3 className="text-sm font-medium text-white mb-2">System Prompt</h3>
          <div className="bg-gray-800 rounded-lg p-3 max-h-24 overflow-y-auto">
            <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono">
              {promptData.context.systemPrompt}
            </pre>
          </div>
        </div>
      )}

      {/* Prompt History */}
      {showHistory && (
        <div className="flex-1 overflow-y-auto p-4">
          <h3 className="text-sm font-medium text-white mb-2">
            History ({promptData.history.length} prompts)
          </h3>
          <div className="space-y-2">
            {promptData.history.length === 0 ? (
              <div className="text-xs text-gray-500">No prompt history</div>
            ) : (
              promptData.history.slice().reverse().map((prompt, index) => (
                <div
                  key={index}
                  className="bg-gray-800 rounded-lg p-2 hover:bg-gray-700 transition-colors"
                >
                  <div className="text-xs text-gray-500 mb-1">
                    #{promptData.history.length - index}
                  </div>
                  <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono truncate">
                    {prompt}
                  </pre>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="p-4 bg-gray-800/50 border-t border-gray-700">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <span className="text-gray-400">Total Prompts:</span>
            <span className="ml-1 text-gray-300">{promptData.history.length}</span>
          </div>
          <div>
            <span className="text-gray-400">Last Updated:</span>
            <span className="ml-1 text-gray-300">
              {new Date(promptData.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}