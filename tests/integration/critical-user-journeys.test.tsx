/**
 * Critical User Journey Integration Tests
 * 
 * Tests end-to-end user workflows that are business-critical.
 * These tests simulate real user interactions across multiple components.
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';
import { axe, toHaveNoViolations } from 'jest-axe';

// Import components and utilities
import '@testing-library/jest-dom';
import { createTestWrapper, mockWebSocket, createMockTerminal } from '../utils/test-helpers';

expect.extend(toHaveNoViolations);

// Mock dependencies
const mockSocket = mockWebSocket();
jest.mock('socket.io-client', () => ({
  io: jest.fn(() => mockSocket),
}));

jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => createMockTerminal()),
}));

describe('Critical User Journeys - Integration Tests', () => {
  let user: ReturnType<typeof userEvent.setup>;
  
  beforeEach(() => {
    user = userEvent.setup();
    jest.clearAllMocks();
    mockSocket.resetMocks();
  });

  describe('Terminal Session Management Flow', () => {
    it('should complete full terminal session lifecycle', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      const { container } = render(<TestApp />, { wrapper: createTestWrapper() });
      
      // 1. Application loads successfully
      expect(screen.getByRole('main')).toBeInTheDocument();
      
      // 2. User can create new terminal session
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);
      
      await waitFor(() => {
        expect(screen.getByText(/terminal/i)).toBeInTheDocument();
      });
      
      // 3. Terminal connects to WebSocket
      expect(mockSocket.emit).toHaveBeenCalledWith('create-session');
      
      // 4. User can execute commands
      const terminalContainer = screen.getByTestId('terminal-container');
      await user.click(terminalContainer);
      
      // Simulate command input
      mockSocket.triggerEvent('session-created', { sessionId: 'test-session-1' });
      mockSocket.triggerEvent('data', { data: 'test-output\n' });
      
      // 5. User can switch between tabs
      const tabList = screen.getByRole('tablist');
      const tabs = within(tabList).getAllByRole('tab');
      
      if (tabs.length > 1) {
        await user.click(tabs[1]);
        expect(tabs[1]).toHaveAttribute('aria-selected', 'true');
      }
      
      // 6. User can close terminal session
      const closeButton = screen.getByRole('button', { name: /close/i });
      await user.click(closeButton);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('close-session', expect.any(String));
    });

    it('should handle rapid tab creation and switching', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Rapidly create multiple tabs
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      
      for (let i = 0; i < 5; i++) {
        await user.click(newTabButton);
        mockSocket.triggerEvent('session-created', { sessionId: `test-session-${i}` });
      }
      
      await waitFor(() => {
        const tabs = screen.getAllByRole('tab');
        expect(tabs).toHaveLength(6); // 5 new + 1 default
      });
      
      // Rapidly switch between tabs
      const tabs = screen.getAllByRole('tab');
      for (let i = 0; i < tabs.length; i++) {
        await user.click(tabs[i]);
        expect(tabs[i]).toHaveAttribute('aria-selected', 'true');
      }
      
      // Performance validation - no memory leaks
      expect(mockSocket.listeners('data').length).toBeLessThan(10);
    });
  });

  describe('WebSocket Connection Management Flow', () => {
    it('should handle connection lifecycle with reconnection', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      const { rerender } = render(<TestApp />, { wrapper: createTestWrapper() });
      
      // 1. Initial connection established
      expect(mockSocket.connect).toHaveBeenCalled();
      
      // 2. Connection lost scenario
      mockSocket.triggerEvent('disconnect', 'transport close');
      
      await waitFor(() => {
        expect(screen.getByText(/connection lost/i)).toBeInTheDocument();
      });
      
      // 3. Automatic reconnection
      mockSocket.triggerEvent('connect');
      
      await waitFor(() => {
        expect(screen.queryByText(/connection lost/i)).not.toBeInTheDocument();
      }, { timeout: 5000 });
      
      // 4. Data integrity after reconnection
      mockSocket.triggerEvent('data', { data: 'reconnected-output\n' });
      
      expect(screen.getByText(/reconnected-output/i)).toBeInTheDocument();
    });

    it('should handle multiple connection failures gracefully', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Simulate multiple rapid disconnections/reconnections
      for (let i = 0; i < 3; i++) {
        mockSocket.triggerEvent('disconnect', 'transport error');
        mockSocket.triggerEvent('connect_error', new Error('Connection failed'));
        
        // Should show error state
        await waitFor(() => {
          expect(screen.getByText(/connection/i)).toBeInTheDocument();
        });
        
        // Reconnect
        mockSocket.triggerEvent('connect');
        
        await waitFor(() => {
          expect(mockSocket.connect).toHaveBeenCalled();
        });
      }
      
      // Final state should be connected
      expect(mockSocket.connected).toBe(true);
    });
  });

  describe('Monitoring and Performance Flow', () => {
    it('should display real-time performance metrics', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Open monitoring sidebar
      const monitoringToggle = screen.getByRole('button', { name: /monitoring/i });
      await user.click(monitoringToggle);
      
      await waitFor(() => {
        expect(screen.getByText(/performance/i)).toBeInTheDocument();
      });
      
      // Check for performance metrics display
      const metricsPanel = screen.getByTestId('performance-metrics');
      expect(metricsPanel).toBeInTheDocument();
      
      // Simulate performance data update
      const performanceData = {
        memory: { used: 50, total: 100 },
        cpu: 25,
        connections: 3
      };
      
      // Trigger performance update
      const event = new CustomEvent('performance-update', { detail: performanceData });
      window.dispatchEvent(event);
      
      await waitFor(() => {
        expect(screen.getByText(/50%/)).toBeInTheDocument(); // Memory usage
        expect(screen.getByText(/25%/)).toBeInTheDocument(); // CPU usage
      });
    });
  });

  describe('Error Recovery Flow', () => {
    it('should recover from terminal crashes gracefully', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Create terminal session
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);
      
      mockSocket.triggerEvent('session-created', { sessionId: 'test-session' });
      
      // Simulate terminal crash
      mockSocket.triggerEvent('session-error', { 
        sessionId: 'test-session', 
        error: 'Terminal process crashed' 
      });
      
      // Should show error state
      await waitFor(() => {
        expect(screen.getByText(/error/i)).toBeInTheDocument();
      });
      
      // User can restart session
      const restartButton = screen.getByRole('button', { name: /restart/i });
      await user.click(restartButton);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('restart-session', 'test-session');
      
      // Simulate successful restart
      mockSocket.triggerEvent('session-restarted', { sessionId: 'test-session' });
      
      await waitFor(() => {
        expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
      });
    });
  });

  describe('Accessibility Compliance', () => {
    it('should maintain accessibility throughout user journey', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      const { container } = render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Test initial accessibility
      const results = await axe(container);
      expect(results).toHaveNoViolations();
      
      // Create new tab and test
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);
      
      await waitFor(() => {
        expect(screen.getByRole('tabpanel')).toBeInTheDocument();
      });
      
      const resultsAfterTab = await axe(container);
      expect(resultsAfterTab).toHaveNoViolations();
      
      // Open monitoring and test
      const monitoringToggle = screen.getByRole('button', { name: /monitoring/i });
      await user.click(monitoringToggle);
      
      await waitFor(() => {
        expect(screen.getByRole('complementary')).toBeInTheDocument();
      });
      
      const resultsAfterMonitoring = await axe(container);
      expect(resultsAfterMonitoring).toHaveNoViolations();
    });

    it('should support keyboard navigation throughout journey', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Tab navigation
      await user.tab();
      expect(document.activeElement).toHaveAttribute('role', 'button');
      
      // Enter key activation
      await user.keyboard('{Enter}');
      
      // Continue tabbing through interface
      for (let i = 0; i < 5; i++) {
        await user.tab();
        expect(document.activeElement).toBeTruthy();
      }
      
      // Ensure all interactive elements are reachable
      const interactiveElements = screen.getAllByRole('button')
        .concat(screen.getAllByRole('tab'))
        .concat(screen.getAllByRole('textbox'));
      
      expect(interactiveElements.length).toBeGreaterThan(0);
      
      for (const element of interactiveElements) {
        expect(element).toHaveAttribute('tabindex', expect.stringMatching(/^(0|-1)$/));
      }
    });
  });

  describe('Data Persistence Flow', () => {
    it('should persist user preferences across sessions', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      const { rerender } = render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Modify user preferences
      const settingsButton = screen.getByRole('button', { name: /settings/i });
      await user.click(settingsButton);
      
      // Change theme or other settings
      const themeToggle = screen.getByRole('switch', { name: /dark mode/i });
      await user.click(themeToggle);
      
      // Simulate page refresh/reload
      rerender(<TestApp />);
      
      // Preferences should persist
      await waitFor(() => {
        const persistedThemeToggle = screen.getByRole('switch', { name: /dark mode/i });
        expect(persistedThemeToggle).toBeChecked();
      });
    });
  });
});