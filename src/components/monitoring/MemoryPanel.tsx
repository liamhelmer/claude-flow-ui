'use client';

import { useEffect, useState } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { formatBytes, formatPercentage } from '@/lib/utils';

interface MemoryData {
  total: number;
  used: number;
  free: number;
  percentage: number;
  efficiency: number;
  timestamp: number;
}

export default function MemoryPanel() {
  const { on, off, isConnected } = useWebSocket();
  const [memoryData, setMemoryData] = useState<MemoryData | null>(null);
  const [history, setHistory] = useState<number[]>([]);

  useEffect(() => {
    const handleMemoryUpdate = (data: any) => {
      // Handle null/undefined data
      if (!data) {
        return;
      }
      
      const memory: MemoryData = {
        total: data.memoryTotal || 0,
        used: data.memoryUsed || 0,
        free: data.memoryFree || 0,
        percentage: data.memoryUsagePercent || 0,
        efficiency: data.memoryEfficiency || 0,
        timestamp: data.timestamp || Date.now(),
      };
      
      setMemoryData(memory);
      setHistory(prev => [...prev.slice(-19), memory.percentage]);
    };

    on('system-metrics', handleMemoryUpdate);
    on('memory-update', handleMemoryUpdate);

    return () => {
      off('system-metrics', handleMemoryUpdate);
      off('memory-update', handleMemoryUpdate);
    };
  }, [on, off]);

  if (!isConnected) {
    return (
      <div className="p-4 text-gray-500">
        <div className="text-sm">Disconnected</div>
      </div>
    );
  }

  if (!memoryData) {
    return (
      <div className="p-4 text-gray-500">
        <div className="text-sm">Loading memory data...</div>
      </div>
    );
  }

  return (
    <div className="p-4 space-y-4">
      {/* Memory Usage Bar */}
      <div>
        <div className="flex justify-between text-sm mb-1">
          <span className="text-gray-400">Memory Usage</span>
          <span className="font-mono text-white">
            {formatPercentage(memoryData.percentage)}
          </span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div 
            className={`h-2 rounded-full transition-all duration-500 ${
              memoryData.percentage > 90 ? 'bg-red-500' :
              memoryData.percentage > 70 ? 'bg-yellow-500' :
              'bg-green-500'
            }`}
            style={{ width: `${memoryData.percentage}%` }}
          />
        </div>
      </div>

      {/* Memory Details */}
      <div className="space-y-2">
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Total</span>
          <span className="font-mono text-white">
            {formatBytes(memoryData.total)}
          </span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Used</span>
          <span className="font-mono text-white">
            {formatBytes(memoryData.used)}
          </span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Free</span>
          <span className="font-mono text-white">
            {formatBytes(memoryData.free)}
          </span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Efficiency</span>
          <span className="font-mono text-white">
            {formatPercentage(memoryData.efficiency)}
          </span>
        </div>
      </div>

      {/* Mini Chart */}
      <div className="pt-2 border-t border-gray-700">
        <div className="text-xs text-gray-400 mb-2">History (last 20)</div>
        <div className="flex items-end h-12 gap-0.5">
          {history.map((value, i) => (
            <div
              key={i}
              className={`flex-1 transition-all duration-300 ${
                value > 90 ? 'bg-red-500' :
                value > 70 ? 'bg-yellow-500' :
                'bg-green-500'
              }`}
              style={{ height: `${(value / 100) * 48}px` }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}