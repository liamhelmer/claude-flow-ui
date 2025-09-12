import React from 'react';
import { render, screen, waitFor } from '../../../tests/test-utils';
import { useWebSocket } from '@/hooks/useWebSocket';
import MemoryPanel from '../MemoryPanel';

// Mock the useWebSocket hook
jest.mock('@/hooks/useWebSocket');
const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;

// Mock the utils functions
jest.mock('@/lib/utils', () => ({
  formatBytes: jest.fn((bytes: number) => `${bytes} MB`),
  formatPercentage: jest.fn((value: number) => `${value}%`),
}));

describe('MemoryPanel Component', () => {
  const defaultMockReturn = {
    on: jest.fn(),
    off: jest.fn(),
    send: jest.fn(),
    sendMessage: jest.fn(),
    connect: jest.fn(),
    disconnect: jest.fn(),
    isConnected: true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseWebSocket.mockReturnValue(defaultMockReturn);
  });

  describe('Rendering States', () => {
    it('should render disconnected state when not connected', () => {
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        isConnected: false,
      });

      render(<MemoryPanel />);
      
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should render loading state when connected but no data', () => {
      render(<MemoryPanel />);
      
      expect(screen.getByText('Loading memory data...')).toBeInTheDocument();
    });

    it('should render memory data when available', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          // Simulate receiving memory data
          setTimeout(() => {
            callback({
              memoryTotal: 8000000000,
              memoryUsed: 4000000000,
              memoryFree: 4000000000,
              memoryUsagePercent: 50,
              memoryEfficiency: 85,
              timestamp: Date.now(),
            });
          }, 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Memory Usage')).toBeInTheDocument();
      });
    });
  });

  describe('WebSocket Integration', () => {
    it('should listen for system-metrics and memory-update events', () => {
      const mockOn = jest.fn();
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      expect(mockOn).toHaveBeenCalledWith('system-metrics', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('memory-update', expect.any(Function));
    });

    it('should clean up event listeners on unmount', () => {
      const mockOff = jest.fn();
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        off: mockOff,
      });

      const { unmount } = render(<MemoryPanel />);
      unmount();
      
      expect(mockOff).toHaveBeenCalledWith('system-metrics', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('memory-update', expect.any(Function));
    });

    it('should handle null/undefined data gracefully', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics') {
          callback(null);
          callback(undefined);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      // Should still show loading state since no valid data was received
      expect(screen.getByText('Loading memory data...')).toBeInTheDocument();
    });
  });

  describe('Memory Data Display', () => {
    const mockMemoryData = {
      memoryTotal: 8000000000,
      memoryUsed: 4000000000,
      memoryFree: 4000000000,
      memoryUsagePercent: 50,
      memoryEfficiency: 85,
      timestamp: Date.now(),
    };

    beforeEach(() => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics' || event === 'memory-update') {
          setTimeout(() => callback(mockMemoryData), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });
    });

    it('should display memory usage percentage', async () => {
      render(<MemoryPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('50%')).toBeInTheDocument();
      });
    });

    it('should display memory details', async () => {
      render(<MemoryPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Total')).toBeInTheDocument();
        expect(screen.getByText('Used')).toBeInTheDocument();
        expect(screen.getByText('Free')).toBeInTheDocument();
        expect(screen.getByText('Efficiency')).toBeInTheDocument();
      });
    });

    it('should display history chart', async () => {
      render(<MemoryPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('History (last 20)')).toBeInTheDocument();
      });
    });
  });

  describe('Progress Bar Colors', () => {
    it('should use green color for low usage (<= 70%)', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics') {
          callback({ ...mockMemoryData, memoryUsagePercent: 50 });
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      await waitFor(() => {
        const progressBar = document.querySelector('.bg-green-500');
        expect(progressBar).toBeInTheDocument();
      });
    });

    it('should use yellow color for medium usage (70-90%)', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics') {
          callback({ ...mockMemoryData, memoryUsagePercent: 80 });
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      await waitFor(() => {
        const progressBar = document.querySelector('.bg-yellow-500');
        expect(progressBar).toBeInTheDocument();
      });
    });

    it('should use red color for high usage (> 90%)', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics') {
          callback({ ...mockMemoryData, memoryUsagePercent: 95 });
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      await waitFor(() => {
        const progressBar = document.querySelector('.bg-red-500');
        expect(progressBar).toBeInTheDocument();
      });
    });
  });

  describe('History Tracking', () => {
    it('should maintain history of memory usage', async () => {
      const mockOn = jest.fn();
      let callbackRef: any = null;

      mockOn.mockImplementation((event, callback) => {
        if (event === 'system-metrics') {
          callbackRef = callback;
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      // Simulate multiple memory updates
      if (callbackRef) {
        for (let i = 1; i <= 5; i++) {
          callbackRef({ ...mockMemoryData, memoryUsagePercent: i * 10 });
        }
      }

      await waitFor(() => {
        const historyBars = document.querySelectorAll('[style*="height"]');
        expect(historyBars.length).toBeGreaterThan(0);
      });
    });

    it('should limit history to 20 entries', async () => {
      const mockOn = jest.fn();
      let callbackRef: any = null;

      mockOn.mockImplementation((event, callback) => {
        if (event === 'system-metrics') {
          callbackRef = callback;
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      // Add more than 20 entries
      if (callbackRef) {
        for (let i = 1; i <= 25; i++) {
          callbackRef({ ...mockMemoryData, memoryUsagePercent: i });
        }
      }

      await waitFor(() => {
        const historyContainer = document.querySelector('.flex.items-end.h-12.gap-0\\.5');
        const historyBars = historyContainer?.children;
        expect(historyBars?.length).toBeLessThanOrEqual(20);
      });
    });
  });

  describe('Data Fallbacks', () => {
    it('should handle missing memory data properties', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics') {
          callback({}); // Empty object
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<MemoryPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('0%')).toBeInTheDocument();
      });
    });

    it('should use current timestamp when not provided', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'system-metrics') {
          callback({
            memoryTotal: 8000000000,
            // No timestamp provided
          });
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      const dateSpy = jest.spyOn(Date, 'now').mockReturnValue(1234567890);

      render(<MemoryPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Memory Usage')).toBeInTheDocument();
      });

      dateSpy.mockRestore();
    });
  });
});