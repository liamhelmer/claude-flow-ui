'use client';

import { useEffect, useState } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';

interface Agent {
  id: string;
  type: string;
  name: string;
  state: 'initializing' | 'idle' | 'busy' | 'error' | 'terminated';
  health: {
    responsiveness: number;
    performance: number;
    reliability: number;
  };
  currentTask?: string;
  lastActivity?: string;
  metrics?: {
    tasksCompleted: number;
    avgResponseTime: number;
    errorRate: number;
  };
}

const stateColors = {
  initializing: 'text-blue-400 bg-blue-400/10',
  idle: 'text-gray-400 bg-gray-400/10',
  busy: 'text-green-400 bg-green-400/10',
  error: 'text-red-400 bg-red-400/10',
  terminated: 'text-gray-600 bg-gray-600/10',
};

const stateIcons = {
  initializing: '⚙️',
  idle: '💤',
  busy: '🔥',
  error: '❌',
  terminated: '⛔',
};

export default function AgentsPanel() {
  const { on, off, isConnected } = useWebSocket();
  const [agents, setAgents] = useState<Map<string, Agent>>(new Map());
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  useEffect(() => {
    const handleAgentUpdate = (data: any) => {
      if (data.agentId && data.agent) {
        setAgents(prev => {
          const updated = new Map(prev);
          updated.set(data.agentId, data.agent);
          return updated;
        });
      }
    };

    const handleAgentSpawned = (data: any) => {
      const agent: Agent = {
        id: data.agentId,
        type: data.type || 'worker',
        name: data.name || `Agent-${data.agentId.slice(0, 8)}`,
        state: 'initializing',
        health: {
          responsiveness: 100,
          performance: 100,
          reliability: 100,
        },
      };
      
      setAgents(prev => {
        const updated = new Map(prev);
        updated.set(agent.id, agent);
        return updated;
      });
    };

    const handleAgentStatus = (data: any) => {
      setAgents(prev => {
        const updated = new Map(prev);
        const agent = updated.get(data.agentId);
        if (agent) {
          updated.set(data.agentId, {
            ...agent,
            state: data.state || agent.state,
            currentTask: data.currentTask,
            lastActivity: new Date().toISOString(),
          });
        } else {
          // Create agent if it doesn't exist
          updated.set(data.agentId, {
            id: data.agentId,
            type: 'worker',
            name: `Agent-${data.agentId.slice(0, 8)}`,
            state: data.state || 'idle',
            currentTask: data.currentTask,
            health: {
              responsiveness: 100,
              performance: 95,
              reliability: 100,
            },
            metrics: {
              tasksCompleted: 0,
              avgResponseTime: 0,
              errorRate: 0,
            },
            lastActivity: new Date().toISOString(),
          });
        }
        return updated;
      });
    };

    on('agent-update', handleAgentUpdate);
    on('agent-spawned', handleAgentSpawned);
    on('agent-status', handleAgentStatus);

    return () => {
      off('agent-update', handleAgentUpdate);
      off('agent-spawned', handleAgentSpawned);
      off('agent-status', handleAgentStatus);
    };
  }, [on, off]);

  if (!isConnected) {
    return (
      <div className="p-4 text-gray-500">
        <div className="text-sm">Disconnected</div>
      </div>
    );
  }

  const agentList = Array.from(agents.values());
  const selected = selectedAgent ? agents.get(selectedAgent) : null;

  return (
    <div className="flex flex-col h-full">
      {/* Agent List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {agentList.length === 0 ? (
          <div className="text-sm text-gray-500">No active agents</div>
        ) : (
          agentList.map(agent => (
            <div
              key={agent.id}
              onClick={() => setSelectedAgent(agent.id)}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                selectedAgent === agent.id
                  ? 'border-blue-500 bg-blue-500/10'
                  : 'border-gray-700 hover:border-gray-600 bg-gray-800/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className="text-lg">{stateIcons[agent.state]}</span>
                  <span className="font-medium text-white">{agent.name}</span>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs ${stateColors[agent.state]}`}>
                  {agent.state}
                </span>
              </div>
              
              <div className="text-xs text-gray-400">
                Type: {agent.type}
              </div>
              
              {agent.currentTask && (
                <div className="text-xs text-gray-300 mt-1 truncate">
                  Task: {agent.currentTask}
                </div>
              )}

              {/* Health Indicators */}
              <div className="flex gap-1 mt-2">
                <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-green-500"
                    style={{ width: `${agent.health.responsiveness}%` }}
                  />
                </div>
                <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-blue-500"
                    style={{ width: `${agent.health.performance}%` }}
                  />
                </div>
                <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-purple-500"
                    style={{ width: `${agent.health.reliability}%` }}
                  />
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Selected Agent Details */}
      {selected && (
        <div className="border-t border-gray-700 p-4 bg-gray-800/50">
          <h3 className="text-sm font-medium text-white mb-2">Agent Details</h3>
          <div className="space-y-1 text-xs">
            <div className="flex justify-between">
              <span className="text-gray-400">ID:</span>
              <span className="font-mono text-gray-300">{selected.id.slice(0, 12)}...</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Responsiveness:</span>
              <span className="text-gray-300">{selected.health.responsiveness}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Performance:</span>
              <span className="text-gray-300">{selected.health.performance}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Reliability:</span>
              <span className="text-gray-300">{selected.health.reliability}%</span>
            </div>
            {selected.metrics && (
              <>
                <div className="flex justify-between">
                  <span className="text-gray-400">Tasks:</span>
                  <span className="text-gray-300">{selected.metrics.tasksCompleted}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Avg Response:</span>
                  <span className="text-gray-300">{selected.metrics.avgResponseTime}ms</span>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}