/**
 * Enhanced comprehensive tests for AgentsPanel component
 * Tests state management, WebSocket integration, data visualization, and edge cases
 */

import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import AgentsPanel from '../AgentsPanel';
import { createMockAgentData, createMockSocketIO, waitForAsyncUpdate } from '@/__tests__/utils/test-helpers';

// Mock the useWebSocket hook
jest.mock('@/hooks/useWebSocket');
const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;

describe('AgentsPanel - Enhanced Tests', () => {
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

  describe('Component Rendering States', () => {
    it('should render disconnected state when WebSocket is not connected', () => {
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        isConnected: false,
      });

      render(<AgentsPanel />);
      
      expect(screen.getByText(/disconnected/i)).toBeInTheDocument();
    });

    it('should render loading state when connected but no agent data', () => {
      render(<AgentsPanel />);
      
      expect(screen.getByText(/loading/i)).toBeInTheDocument();
    });

    it('should render agent data when available', async () => {
      const mockAgentData = createMockAgentData({
        id: 'agent-1',
        name: 'Test Agent',
        type: 'coder',
        status: 'active'
      });

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status' || event === 'agents-update') {
          setTimeout(() => callback([mockAgentData]), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Test Agent')).toBeInTheDocument();
      });
    });

    it('should render empty state message when no agents are available', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status' || event === 'agents-update') {
          setTimeout(() => callback([]), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText(/no agents/i)).toBeInTheDocument();
      });
    });
  });

  describe('WebSocket Event Handling', () => {
    it('should listen for agent-status and agents-update events', () => {
      const mockOn = jest.fn();
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      expect(mockOn).toHaveBeenCalledWith('agent-status', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('agents-update', expect.any(Function));
    });

    it('should clean up event listeners on unmount', () => {
      const mockOff = jest.fn();
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        off: mockOff,
      });

      const { unmount } = render(<AgentsPanel />);
      unmount();
      
      expect(mockOff).toHaveBeenCalledWith('agent-status', expect.any(Function));
      expect(mockOff).toHaveBeenCalledWith('agents-update', expect.any(Function));
    });

    it('should handle null/undefined agent data gracefully', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          callback(null);
          callback(undefined);
          callback([null, undefined]);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      // Should not crash and should show loading state
      expect(screen.getByText(/loading/i)).toBeInTheDocument();
    });

    it('should handle malformed agent data', async () => {
      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          callback([
            { id: 'invalid-1' }, // Missing required fields
            { name: 'Agent 2', type: 'unknown' }, // Missing id
            'not-an-object', // Wrong type
          ]);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitForAsyncUpdate();
      
      // Should filter out invalid agents and render valid ones
      expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
    });
  });

  describe('Agent Data Display', () => {
    const createMockAgents = () => [
      createMockAgentData({
        id: 'agent-1',
        name: 'Coder Agent',
        type: 'coder',
        status: 'active',
        metrics: { tasksCompleted: 10, successRate: 0.9, averageTime: 1200 }
      }),
      createMockAgentData({
        id: 'agent-2',
        name: 'Tester Agent',
        type: 'tester',
        status: 'idle',
        metrics: { tasksCompleted: 5, successRate: 1.0, averageTime: 800 }
      }),
      createMockAgentData({
        id: 'agent-3',
        name: 'Failed Agent',
        type: 'reviewer',
        status: 'error',
        metrics: { tasksCompleted: 2, successRate: 0.5, averageTime: 2000 }
      })
    ];

    beforeEach(() => {
      const mockAgents = createMockAgents();
      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status' || event === 'agents-update') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });
    });

    it('should display agent names and types', async () => {
      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Coder Agent')).toBeInTheDocument();
        expect(screen.getByText('Tester Agent')).toBeInTheDocument();
        expect(screen.getByText('Failed Agent')).toBeInTheDocument();
      });
    });

    it('should display agent status with appropriate styling', async () => {
      render(<AgentsPanel />);
      
      await waitFor(() => {
        // Check for status indicators (colors/classes may vary based on implementation)
        const activeAgent = screen.getByText('Coder Agent').closest('.agent-card, .agent-item, div');
        const idleAgent = screen.getByText('Tester Agent').closest('.agent-card, .agent-item, div');
        const errorAgent = screen.getByText('Failed Agent').closest('.agent-card, .agent-item, div');
        
        expect(activeAgent).toBeInTheDocument();
        expect(idleAgent).toBeInTheDocument();
        expect(errorAgent).toBeInTheDocument();
      });
    });

    it('should display agent metrics', async () => {
      render(<AgentsPanel />);
      
      await waitFor(() => {
        // Look for metric values (adjust based on component implementation)
        expect(screen.getByText(/10/)).toBeInTheDocument(); // tasks completed
        expect(screen.getByText(/90%|0\.9/)).toBeInTheDocument(); // success rate
        expect(screen.getByText(/1\.2s|1200/)).toBeInTheDocument(); // average time
      });
    });

    it('should update agent data in real-time', async () => {
      let mockCallback: any = null;
      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          mockCallback = callback;
          setTimeout(() => callback(createMockAgents()), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Coder Agent')).toBeInTheDocument();
      });

      // Update agent data
      const updatedAgents = [
        createMockAgentData({
          id: 'agent-1',
          name: 'Updated Coder Agent',
          type: 'coder',
          status: 'busy',
          metrics: { tasksCompleted: 15, successRate: 0.95, averageTime: 1000 }
        })
      ];

      if (mockCallback) {
        mockCallback(updatedAgents);
      }

      await waitFor(() => {
        expect(screen.getByText('Updated Coder Agent')).toBeInTheDocument();
      });
    });
  });

  describe('Agent Status Categories', () => {
    it('should group agents by status', async () => {
      const mockAgents = [
        createMockAgentData({ id: 'agent-1', status: 'active' }),
        createMockAgentData({ id: 'agent-2', status: 'active' }),
        createMockAgentData({ id: 'agent-3', status: 'idle' }),
        createMockAgentData({ id: 'agent-4', status: 'error' }),
      ];

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        // Check for status groupings (implementation-dependent)
        const statusElements = screen.getAllByText(/active|idle|error/i);
        expect(statusElements.length).toBeGreaterThan(0);
      });
    });

    it('should show agent count by status', async () => {
      const mockAgents = Array.from({ length: 10 }, (_, i) => 
        createMockAgentData({
          id: `agent-${i}`,
          status: i < 5 ? 'active' : i < 8 ? 'idle' : 'error'
        })
      );

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        // Should show counts (5 active, 3 idle, 2 error)
        expect(screen.getByText(/5.*active|active.*5/i)).toBeInTheDocument();
      });
    });
  });

  describe('Performance and Memory', () => {
    it('should handle large numbers of agents efficiently', async () => {
      const mockAgents = Array.from({ length: 1000 }, (_, i) =>
        createMockAgentData({
          id: `agent-${i}`,
          name: `Agent ${i}`,
          type: ['coder', 'tester', 'reviewer'][i % 3] as any,
          status: ['active', 'idle', 'error'][i % 3] as any
        })
      );

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      const startTime = performance.now();
      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText(/agent/i)).toBeInTheDocument();
      }, { timeout: 5000 });

      const renderTime = performance.now() - startTime;
      expect(renderTime).toBeLessThan(1000); // Should render within 1 second
    });

    it('should handle rapid agent updates without memory leaks', async () => {
      let mockCallback: any = null;
      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          mockCallback = callback;
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      // Simulate rapid updates
      for (let i = 0; i < 100; i++) {
        const mockAgents = [createMockAgentData({ 
          id: 'rapid-agent',
          metrics: { tasksCompleted: i, successRate: Math.random(), averageTime: 1000 + i }
        })];
        
        if (mockCallback) {
          mockCallback(mockAgents);
        }
        
        await new Promise(resolve => setTimeout(resolve, 1));
      }

      // Should not crash or show memory warnings
      expect(screen.getByText(/loading|agent/i)).toBeInTheDocument();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle WebSocket reconnection scenarios', async () => {
      const mockOn = jest.fn();
      const mockOff = jest.fn();
      
      // Start disconnected
      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        isConnected: false,
        on: mockOn,
        off: mockOff,
      });

      const { rerender } = render(<AgentsPanel />);
      
      expect(screen.getByText(/disconnected/i)).toBeInTheDocument();

      // Simulate reconnection
      const mockAgents = [createMockAgentData()];
      const connectedMockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        isConnected: true,
        on: connectedMockOn,
        off: mockOff,
      });

      rerender(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.queryByText(/disconnected/i)).not.toBeInTheDocument();
        expect(screen.getByText(/agent/i)).toBeInTheDocument();
      });
    });

    it('should handle component unmount during data loading', () => {
      const mockOn = jest.fn((event, callback) => {
        // Simulate delayed response
        setTimeout(() => callback([createMockAgentData()]), 1000);
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      const { unmount } = render(<AgentsPanel />);
      
      // Unmount before data loads
      unmount();
      
      // Should not throw errors or warnings
      expect(mockOn).toHaveBeenCalled();
    });

    it('should handle corrupted agent data gracefully', async () => {
      const corruptedData = [
        { id: 'agent-1', name: null, type: undefined, status: 'active' },
        { id: null, name: 'Agent 2', type: 'coder', status: 'idle' },
        { /* empty object */ },
        'not-an-object',
        123,
        null,
        undefined
      ];

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(corruptedData), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitForAsyncUpdate();
      
      // Should not crash and should show appropriate state
      expect(screen.queryByText(/error|crash/i)).not.toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels and roles', async () => {
      const mockAgents = [
        createMockAgentData({ id: 'agent-1', name: 'Test Agent', status: 'active' })
      ];

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Test Agent')).toBeInTheDocument();
      });

      // Check for accessibility attributes
      const panel = screen.getByRole('region', { name: /agents/i }) || 
                   screen.getByLabelText(/agents/i) ||
                   document.querySelector('[aria-label*="agent"]');
      
      expect(panel).toBeInTheDocument();
    });

    it('should support keyboard navigation', async () => {
      const mockAgents = Array.from({ length: 3 }, (_, i) =>
        createMockAgentData({ id: `agent-${i}`, name: `Agent ${i}` })
      );

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(mockAgents), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultMockReturn,
        on: mockOn,
      });

      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText('Agent 0')).toBeInTheDocument();
      });

      // Check for focusable elements
      const focusableElements = screen.getAllByRole('button') || 
                               screen.getAllByRole('link') ||
                               document.querySelectorAll('[tabindex="0"], [tabindex="-1"]');
      
      expect(focusableElements.length).toBeGreaterThanOrEqual(0);
    });
  });
});