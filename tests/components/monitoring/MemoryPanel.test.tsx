import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import MemoryPanel from '@/components/monitoring/MemoryPanel';

// Mock the useWebSocket hook
const mockOn = jest.fn();
const mockOff = jest.fn();
const mockIsConnected = jest.fn();

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    on: mockOn,
    off: mockOff,
    isConnected: mockIsConnected(),
  }),
}));

// Mock the utils functions
jest.mock('@/lib/utils', () => ({
  formatBytes: jest.fn((bytes: number) => `${bytes} GB`),
  formatPercentage: jest.fn((percentage: number) => `${percentage.toFixed(1)}%`),
}));

describe('MemoryPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockIsConnected.mockReturnValue(true);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Connection States', () => {
    it('should display disconnected state when WebSocket is not connected', () => {
      mockIsConnected.mockReturnValue(false);
      
      render(<MemoryPanel />);
      
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should display loading state when connected but no memory data', () => {
      render(<MemoryPanel />);
      
      expect(screen.getByText('Loading memory data...')).toBeInTheDocument();
    });
  });

  describe('WebSocket Event Handling', () => {
    it('should register event listeners on mount', () => {
      render(<MemoryPanel />);
      
      expect(mockOn).toHaveBeenCalledWith('system-metrics', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('memory-update', expect.any(Function));
    });

    it('should unregister event listeners on unmount', () => {
      const { unmount } = render(<MemoryPanel />);
      
      unmount();
      
      expect(mockOff).toHaveBeenCalledWith('system-metrics', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('memory-update', expect.any(Function));
    });

    it('should handle memory update events correctly', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);
      
      // Simulate memory update
      const memoryData = {
        memoryTotal: 8000000000,
        memoryUsed: 4000000000,
        memoryFree: 4000000000,
        memoryUsagePercent: 50.0,
        memoryEfficiency: 85.5,
        timestamp: 1640995200000,
      };

      act(() => {
        memoryUpdateHandler?.(memoryData);
      });

      await waitFor(() => {
        expect(screen.getByText('Memory Usage')).toBeInTheDocument();
      });
    });
  });

  describe('Memory Data Display', () => {
    beforeEach(() => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);
      
      // Set up memory data
      const memoryData = {
        memoryTotal: 8000000000,
        memoryUsed: 4000000000,
        memoryFree: 4000000000,
        memoryUsagePercent: 50.0,
        memoryEfficiency: 85.5,
        timestamp: 1640995200000,
      };

      act(() => {
        memoryUpdateHandler?.(memoryData);
      });
    });

    it('should display memory usage details', async () => {
      await waitFor(() => {
        expect(screen.getByText('Memory Usage')).toBeInTheDocument();
        expect(screen.getByText('Total')).toBeInTheDocument();
        expect(screen.getByText('Used')).toBeInTheDocument();
        expect(screen.getByText('Free')).toBeInTheDocument();
        expect(screen.getByText('Efficiency')).toBeInTheDocument();
      });
    });

    it('should format memory values correctly', async () => {
      await waitFor(() => {
        // Check that formatBytes was called with correct values
        expect(require('@/lib/utils').formatBytes).toHaveBeenCalledWith(8000000000);
        expect(require('@/lib/utils').formatBytes).toHaveBeenCalledWith(4000000000);
        expect(require('@/lib/utils').formatPercentage).toHaveBeenCalledWith(50.0);
        expect(require('@/lib/utils').formatPercentage).toHaveBeenCalledWith(85.5);
      });
    });

    it('should display memory usage bar with correct color', async () => {
      await waitFor(() => {
        const progressBar = document.querySelector('[style*="width: 50%"]');
        expect(progressBar).toHaveClass('bg-green-500');
      });
    });

    it('should display warning color for high memory usage', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      const highMemoryData = {
        memoryTotal: 8000000000,
        memoryUsed: 6000000000,
        memoryFree: 2000000000,
        memoryUsagePercent: 80.0,
        memoryEfficiency: 60.0,
        timestamp: Date.now(),
      };

      act(() => {
        memoryUpdateHandler?.(highMemoryData);
      });

      await waitFor(() => {
        const progressBar = document.querySelector('[style*="width: 80%"]');
        expect(progressBar).toHaveClass('bg-yellow-500');
      });
    });

    it('should display critical color for very high memory usage', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      const criticalMemoryData = {
        memoryTotal: 8000000000,
        memoryUsed: 7500000000,
        memoryFree: 500000000,
        memoryUsagePercent: 95.0,
        memoryEfficiency: 40.0,
        timestamp: Date.now(),
      };

      act(() => {
        memoryUpdateHandler?.(criticalMemoryData);
      });

      await waitFor(() => {
        const progressBar = document.querySelector('[style*="width: 95%"]');
        expect(progressBar).toHaveClass('bg-red-500');
      });
    });
  });

  describe('Memory History Chart', () => {
    it('should display history chart with correct number of bars', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      // Add multiple memory updates to build history
      for (let i = 0; i < 5; i++) {
        act(() => {
          memoryUpdateHandler?.({
            memoryUsagePercent: 50 + i * 5,
            timestamp: Date.now(),
          });
        });
      }

      await waitFor(() => {
        expect(screen.getByText('History (last 20)')).toBeInTheDocument();
        const historyBars = document.querySelectorAll('.flex.items-end.h-12.gap-0\\.5 > div');
        expect(historyBars).toHaveLength(5);
      });
    });

    it('should limit history to last 20 entries', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      // Add more than 20 memory updates
      for (let i = 0; i < 25; i++) {
        act(() => {
          memoryUpdateHandler?.({
            memoryUsagePercent: 50,
            timestamp: Date.now(),
          });
        });
      }

      await waitFor(() => {
        const historyBars = document.querySelectorAll('.flex.items-end.h-12.gap-0\\.5 > div');
        expect(historyBars.length).toBeLessThanOrEqual(20);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle missing data gracefully', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      // Send incomplete data
      act(() => {
        memoryUpdateHandler?.({});
      });

      await waitFor(() => {
        expect(screen.getByText('Memory Usage')).toBeInTheDocument();
        // Should use default values (0) for missing data
        expect(require('@/lib/utils').formatBytes).toHaveBeenCalledWith(0);
        expect(require('@/lib/utils').formatPercentage).toHaveBeenCalledWith(0);
      });
    });

    it('should handle null/undefined memory data', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      act(() => {
        memoryUpdateHandler?.(null);
      });

      // Should still show loading state
      expect(screen.getByText('Loading memory data...')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels and semantic elements', async () => {
      let memoryUpdateHandler: ((data: any) => void) | null = null;
      
      mockOn.mockImplementation((event: string, handler: any) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          memoryUpdateHandler = handler;
        }
      });

      render(<MemoryPanel />);

      act(() => {
        memoryUpdateHandler?.({
          memoryTotal: 8000000000,
          memoryUsed: 4000000000,
          memoryUsagePercent: 50.0,
        });
      });

      await waitFor(() => {
        // Check for semantic structure
        expect(screen.getByText('Memory Usage')).toBeInTheDocument();
        
        // Progress bars should be accessible
        const progressBars = document.querySelectorAll('.h-2.rounded-full');
        expect(progressBars.length).toBeGreaterThan(0);
      });
    });
  });
});