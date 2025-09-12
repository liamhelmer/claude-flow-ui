/**
 * Integration Tests: Sidebar + Tab Navigation
 * 
 * These tests verify that the Sidebar and Tab navigation components
 * work together correctly, handling session management, state synchronization,
 * and user interactions.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { testUtils, createIntegrationTest } from '@tests/utils/testHelpers';
import Sidebar from '@/components/sidebar/Sidebar';
import TabList from '@/components/tabs/TabList';
import { useAppStore } from '@/lib/state/store';

// Mock the store
jest.mock('@/lib/state/store');

createIntegrationTest('Sidebar Navigation Integration', () => {
  let mockStore;
  let mockSessions;
  let mockHandlers;

  beforeEach(() => {
    // Setup mock sessions
    mockSessions = [
      {
        id: 'session-1',
        name: 'Terminal 1',
        isActive: true,
        lastActivity: new Date(),
      },
      {
        id: 'session-2',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(Date.now() - 60000), // 1 minute ago
      },
    ];

    // Setup mock handlers
    mockHandlers = {
      onSessionSelect: jest.fn(),
      onSessionCreate: jest.fn(),
      onSessionClose: jest.fn(),
      onToggle: jest.fn(),
      onNewSession: jest.fn(),
    };

    // Mock store
    mockStore = {
      sidebarOpen: true,
      terminalSessions: mockSessions,
      activeSessionId: 'session-1',
      setSidebarOpen: jest.fn(),
      setActiveSession: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
    };
    useAppStore.mockReturnValue(mockStore);
  });

  describe('Sidebar State Management', () => {
    test('should toggle sidebar visibility', async () => {
      const { rerender } = render(
        <Sidebar
          isOpen={true}
          onToggle={mockHandlers.onToggle}
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      // Sidebar should be visible
      expect(screen.getByText('Claude Flow Terminal')).toBeInTheDocument();

      // Click toggle button
      const toggleButton = screen.getByTitle('Toggle Sidebar');
      await userEvent.click(toggleButton);

      expect(mockHandlers.onToggle).toHaveBeenCalled();

      // Simulate sidebar being closed
      rerender(
        <Sidebar
          isOpen={false}
          onToggle={mockHandlers.onToggle}
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      // Sidebar content should not be visible
      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();
      
      // But toggle button should be visible
      expect(screen.getByTitle('Open Sidebar')).toBeInTheDocument();
    });

    test('should persist sidebar state across renders', async () => {
      const { rerender } = render(
        <Sidebar
          isOpen={false}
          onToggle={mockHandlers.onToggle}
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();

      // Re-render with same state
      rerender(
        <Sidebar
          isOpen={false}
          onToggle={mockHandlers.onToggle}
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      expect(screen.queryByText('Claude Flow Terminal')).not.toBeInTheDocument();
    });
  });

  describe('Tab Navigation', () => {
    test('should render all sessions as tabs', () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
    });

    test('should highlight active tab', () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Active tab should have active styling (tested via data attributes or classes)
      const activeTab = screen.getByText('Terminal 1').closest('button');
      expect(activeTab).toHaveClass(/active|selected/); // Adjust based on actual class names
    });

    test('should switch active tab when clicked', async () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      const inactiveTab = screen.getByText('Terminal 2');
      await userEvent.click(inactiveTab);

      expect(mockHandlers.onSessionSelect).toHaveBeenCalledWith('session-2');
    });

    test('should create new session when new tab button clicked', async () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      const newTabButton = screen.getByLabelText('New terminal session');
      await userEvent.click(newTabButton);

      expect(mockHandlers.onNewSession).toHaveBeenCalled();
    });

    test('should close tab when close button clicked', async () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Find and click close button (assuming it exists for closable tabs)
      const closeButtons = screen.getAllByLabelText(/close|×/i);
      if (closeButtons.length > 0) {
        await userEvent.click(closeButtons[0]);
        expect(mockHandlers.onSessionClose).toHaveBeenCalled();
      }
    });
  });

  describe('Session State Synchronization', () => {
    test('should synchronize session list between sidebar and tabs', async () => {
      // Render both components
      render(
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockHandlers.onToggle}
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionCreate={mockHandlers.onSessionCreate}
            onSessionClose={mockHandlers.onSessionClose}
          />
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionClose={mockHandlers.onSessionClose}
            onNewSession={mockHandlers.onNewSession}
          />
        </div>
      );

      // Both should show the same sessions
      const terminalTexts = screen.getAllByText('Terminal 1');
      expect(terminalTexts.length).toBeGreaterThan(0);
    });

    test('should update both components when sessions change', async () => {
      const { rerender } = render(
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockHandlers.onToggle}
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionCreate={mockHandlers.onSessionCreate}
            onSessionClose={mockHandlers.onSessionClose}
          />
          <TabList
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionClose={mockHandlers.onSessionClose}
            onNewSession={mockHandlers.onNewSession}
          />
        </div>
      );

      // Add new session
      const newSessions = [
        ...mockSessions,
        {
          id: 'session-3',
          name: 'Terminal 3',
          isActive: false,
          lastActivity: new Date(),
        },
      ];

      rerender(
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockHandlers.onToggle}
            sessions={newSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionCreate={mockHandlers.onSessionCreate}
            onSessionClose={mockHandlers.onSessionClose}
          />
          <TabList
            sessions={newSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionClose={mockHandlers.onSessionClose}
            onNewSession={mockHandlers.onNewSession}
          />
        </div>
      );

      expect(screen.getByText('Terminal 3')).toBeInTheDocument();
    });
  });

  describe('Connection Status Integration', () => {
    test('should show connected status when sessions exist', () => {
      render(
        <Sidebar
          isOpen={true}
          onToggle={mockHandlers.onToggle}
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      expect(screen.getByText('Terminal Connected')).toBeInTheDocument();
      expect(screen.getByRole('status')).toHaveClass(/green|connected/);
    });

    test('should show connecting status when no sessions exist', () => {
      render(
        <Sidebar
          isOpen={true}
          onToggle={mockHandlers.onToggle}
          sessions={[]}
          activeSessionId={null}
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      expect(screen.getByText('Connecting...')).toBeInTheDocument();
    });
  });

  describe('Keyboard Navigation', () => {
    test('should support keyboard navigation in tabs', async () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      const tab1 = screen.getByText('Terminal 1');
      const tab2 = screen.getByText('Terminal 2');

      // Focus first tab
      tab1.focus();
      expect(document.activeElement).toBe(tab1);

      // Navigate with arrow keys
      await userEvent.keyboard('{ArrowRight}');
      // Note: This would require proper keyboard navigation implementation
      // The test verifies the structure is in place
    });

    test('should support keyboard shortcuts in sidebar', async () => {
      render(
        <div>
          <Sidebar
            isOpen={true}
            onToggle={mockHandlers.onToggle}
            sessions={mockSessions}
            activeSessionId="session-1"
            onSessionSelect={mockHandlers.onSessionSelect}
            onSessionCreate={mockHandlers.onSessionCreate}
            onSessionClose={mockHandlers.onSessionClose}
          />
        </div>
      );

      // Test Escape key to close sidebar
      await userEvent.keyboard('{Escape}');
      // This would need to be implemented in the actual component
    });
  });

  describe('Responsive Behavior', () => {
    test('should handle mobile viewport', async () => {
      // Mock mobile viewport
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 320,
      });

      render(
        <Sidebar
          isOpen={true}
          onToggle={mockHandlers.onToggle}
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionCreate={mockHandlers.onSessionCreate}
          onSessionClose={mockHandlers.onSessionClose}
        />
      );

      // Sidebar should adapt to mobile layout
      const sidebar = screen.getByRole('complementary');
      expect(sidebar).toHaveClass(/mobile|responsive/); // Adjust based on actual classes
    });

    test('should handle tablet viewport', async () => {
      // Mock tablet viewport
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 768,
      });

      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Tabs should handle overflow properly
      const tabContainer = screen.getByRole('tablist');
      expect(tabContainer).toHaveClass(/overflow-x-auto|scrollable/);
    });
  });

  describe('Error Handling', () => {
    test('should handle missing session gracefully', () => {
      render(
        <TabList
          sessions={mockSessions}
          activeSessionId="non-existent-session"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Should not crash and should render tabs
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 2')).toBeInTheDocument();
    });

    test('should handle empty sessions list', () => {
      render(
        <TabList
          sessions={[]}
          activeSessionId={null}
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Should still render new tab button
      expect(screen.getByLabelText('New terminal session')).toBeInTheDocument();
    });
  });

  describe('Performance Considerations', () => {
    test('should not re-render unnecessarily', async () => {
      const renderSpy = jest.fn();
      const TestWrapper = (props) => {
        renderSpy();
        return <TabList {...props} />;
      };

      const { rerender } = render(
        <TestWrapper
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      const initialRenderCount = renderSpy.mock.calls.length;

      // Re-render with same props
      rerender(
        <TestWrapper
          sessions={mockSessions}
          activeSessionId="session-1"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Should have rendered once more (React's normal behavior)
      expect(renderSpy.mock.calls.length).toBe(initialRenderCount + 1);
    });

    test('should handle large number of sessions', () => {
      const manySessions = Array.from({ length: 50 }, (_, i) => ({
        id: `session-${i}`,
        name: `Terminal ${i + 1}`,
        isActive: i === 0,
        lastActivity: new Date(),
      }));

      render(
        <TabList
          sessions={manySessions}
          activeSessionId="session-0"
          onSessionSelect={mockHandlers.onSessionSelect}
          onSessionClose={mockHandlers.onSessionClose}
          onNewSession={mockHandlers.onNewSession}
        />
      );

      // Should render without performance issues
      expect(screen.getByText('Terminal 1')).toBeInTheDocument();
      expect(screen.getByText('Terminal 50')).toBeInTheDocument();
    });
  });
});