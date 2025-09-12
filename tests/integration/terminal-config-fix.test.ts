/**
 * Terminal Configuration Fix Integration Tests
 * 
 * Tests to verify the terminal configuration display fix works correctly:
 * - TerminalControls shows actual backend config (e.g., "120×40", "80×24") 
 * - Shows "Waiting..." when no config is available
 * - Updates properly when backend sends terminal-config events
 * - Handles edge cases like null config, websocket disconnection
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import { testUtils, createIntegrationTest } from '../utils/testHelpers';
import TerminalControls from '@/components/terminal/TerminalControls';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

createIntegrationTest('Terminal Configuration Fix Integration', () => {
  let mockClient: any;
  let mockUseTerminal: any;
  let mockUseWebSocket: any;

  beforeEach(() => {
    // Mock useTerminal hook
    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      isAtBottom: false,
      hasNewOutput: false,
      terminal: null, // Start with no terminal config
    };
    (useTerminal as jest.Mock).mockReturnValue(mockUseTerminal);

    // Create mock WebSocket client
    mockClient = testUtils.createMockWebSocketClient();
    
    // Mock useWebSocket hook
    mockUseWebSocket = {
      connected: false,
      connecting: false,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: mockClient.on.bind(mockClient),
      off: mockClient.off.bind(mockClient),
    };
    (useWebSocket as jest.Mock).mockReturnValue(mockUseWebSocket);
  });

  describe('TerminalControls Configuration Display', () => {
    test('should show "Waiting..." when no terminal config available', () => {
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={null}
        />
      );

      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
    });

    test('should show "80×24" when backend sends standard config', () => {
      const config = { cols: 80, rows: 24 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={config}
        />
      );

      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('80×24')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
      expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
    });

    test('should show "120×40" when backend sends larger config', () => {
      const config = { cols: 120, rows: 40 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={config}
        />
      );

      expect(screen.getByText('Terminal Size')).toBeInTheDocument();
      expect(screen.getByText('120×40')).toBeInTheDocument();
      expect(screen.getByText('Backend')).toBeInTheDocument();
    });

    test('should show "132×50" when backend sends wide config', () => {
      const config = { cols: 132, rows: 50 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={config}
        />
      );

      expect(screen.getByText('132×50')).toBeInTheDocument();
    });

    test('should update display when config changes', () => {
      const initialConfig = { cols: 80, rows: 24 };
      
      const { rerender } = render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={initialConfig}
        />
      );

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Update config
      const newConfig = { cols: 120, rows: 40 };
      rerender(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={newConfig}
        />
      );

      expect(screen.getByText('120×40')).toBeInTheDocument();
      expect(screen.queryByText('80×24')).not.toBeInTheDocument();
    });

    test('should revert to "Waiting..." when config becomes null', () => {
      const config = { cols: 80, rows: 24 };
      
      const { rerender } = render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={config}
        />
      );

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Config becomes null (disconnection scenario)
      rerender(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={null}
        />
      );

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
      expect(screen.queryByText('80×24')).not.toBeInTheDocument();
    });
  });

  describe('Terminal Component Integration', () => {
    test('should pass terminal config from useTerminal to TerminalControls', () => {
      // Mock terminal with config
      mockUseTerminal.terminal = {
        cols: 100,
        rows: 30,
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('100×30')).toBeInTheDocument();
    });

    test('should show "Waiting..." when terminal is null', () => {
      // Mock no terminal
      mockUseTerminal.terminal = null;

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });

    test('should handle terminal without cols/rows properties', () => {
      // Mock terminal without size properties
      mockUseTerminal.terminal = {
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
        // cols and rows are undefined/null
      };

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });
  });

  describe('WebSocket Terminal Config Events', () => {
    test('should handle terminal-config WebSocket event', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Initially no config
      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Simulate WebSocket terminal-config event
      act(() => {
        // Update mock terminal with new config
        mockUseTerminal.terminal = {
          cols: 120,
          rows: 40,
          write: jest.fn(),
          onData: jest.fn(),
          onResize: jest.fn(),
        };

        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('120×40')).toBeInTheDocument();
        expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
      });
    });

    test('should ignore terminal-config from wrong session', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="current-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Send config for different session
      act(() => {
        mockClient.emit('terminal-config', {
          sessionId: 'other-session',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
        expect(screen.queryByText('120×40')).not.toBeInTheDocument();
      });
    });

    test('should handle multiple terminal-config updates', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // First config update
      act(() => {
        mockUseTerminal.terminal = { cols: 80, rows: 24, write: jest.fn(), onData: jest.fn(), onResize: jest.fn() };
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });

      // Second config update
      act(() => {
        mockUseTerminal.terminal = { cols: 120, rows: 40, write: jest.fn(), onData: jest.fn(), onResize: jest.fn() };
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 120,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('120×40')).toBeInTheDocument();
        expect(screen.queryByText('80×24')).not.toBeInTheDocument();
      });
    });
  });

  describe('WebSocket Connection States', () => {
    test('should maintain config when connected', async () => {
      mockUseTerminal.terminal = { cols: 80, rows: 24, write: jest.fn(), onData: jest.fn(), onResize: jest.fn() };
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Connection remains stable
      act(() => {
        mockClient.emit('connect');
      });

      await waitFor(() => {
        expect(screen.getByText('80×24')).toBeInTheDocument();
      });
    });

    test('should handle WebSocket disconnection', async () => {
      mockUseTerminal.terminal = { cols: 80, rows: 24, write: jest.fn(), onData: jest.fn(), onResize: jest.fn() };
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('80×24')).toBeInTheDocument();

      // Simulate disconnection - terminal config might be lost
      act(() => {
        mockUseWebSocket.connected = false;
        mockClient.connected = false;
        mockUseTerminal.terminal = null; // Terminal lost on disconnect
        mockClient.emit('disconnect');
      });

      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });
    });

    test('should restore config on WebSocket reconnection', async () => {
      mockUseWebSocket.connected = false;
      mockClient.connected = false;
      mockUseTerminal.terminal = null;

      render(<Terminal sessionId="test-session" />);

      expect(screen.getByText('Waiting...')).toBeInTheDocument();

      // Simulate reconnection with config restore
      act(() => {
        mockUseWebSocket.connected = true;
        mockClient.connected = true;
        mockUseTerminal.terminal = { cols: 100, rows: 30, write: jest.fn(), onData: jest.fn(), onResize: jest.fn() };
        mockClient.emit('connect');
        mockClient.emit('terminal-config', {
          sessionId: 'test-session',
          cols: 100,
          rows: 30,
        });
      });

      await waitFor(() => {
        expect(screen.getByText('100×30')).toBeInTheDocument();
        expect(screen.queryByText('Waiting...')).not.toBeInTheDocument();
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle malformed terminal-config events', async () => {
      mockUseWebSocket.connected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="test-session" />);

      // Send malformed config events
      act(() => {
        mockClient.emit('terminal-config', null);
        mockClient.emit('terminal-config', { sessionId: 'test-session' }); // missing cols/rows
        mockClient.emit('terminal-config', { cols: 80, rows: 24 }); // missing sessionId
      });

      // Should remain in waiting state
      await waitFor(() => {
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
      });
    });

    test('should handle invalid config values', async () => {
      const invalidConfigs = [
        { cols: 0, rows: 24 },
        { cols: 80, rows: 0 },
        { cols: -1, rows: 24 },
        { cols: 80, rows: -1 },
        { cols: null, rows: 24 },
        { cols: 80, rows: null },
        { cols: undefined, rows: 24 },
        { cols: 80, rows: undefined },
      ];

      for (const config of invalidConfigs) {
        const { unmount } = render(
          <TerminalControls
            isAtBottom={false}
            hasNewOutput={false}
            onScrollToTop={jest.fn()}
            onScrollToBottom={jest.fn()}
            terminalConfig={config}
          />
        );

        // Should show "Waiting..." for invalid configs
        expect(screen.getByText('Waiting...')).toBeInTheDocument();
        
        unmount();
      }
    });

    test('should handle very large config values', () => {
      const largeConfig = { cols: 9999, rows: 9999 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={largeConfig}
        />
      );

      expect(screen.getByText('9999×9999')).toBeInTheDocument();
    });

    test('should handle fractional config values', () => {
      const fractionalConfig = { cols: 80.5, rows: 24.7 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={fractionalConfig}
        />
      );

      // Should display the exact fractional values
      expect(screen.getByText('80.5×24.7')).toBeInTheDocument();
    });
  });

  describe('Visual Regression Prevention', () => {
    test('should maintain consistent styling with config display', () => {
      const config = { cols: 80, rows: 24 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={config}
        />
      );

      const sizeDisplay = screen.getByText('80×24');
      const container = sizeDisplay.closest('.mt-4');
      
      expect(container).toHaveClass('px-2');
      expect(sizeDisplay).toHaveClass('text-gray-400', 'font-semibold');
    });

    test('should maintain consistent styling with waiting state', () => {
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={false}
          onScrollToTop={jest.fn()}
          onScrollToBottom={jest.fn()}
          terminalConfig={null}
        />
      );

      const waitingDisplay = screen.getByText('Waiting...');
      expect(waitingDisplay).toHaveClass('text-gray-400', 'font-semibold');
    });

    test('should preserve all other control functionality', () => {
      const mockScrollToTop = jest.fn();
      const mockScrollToBottom = jest.fn();
      const config = { cols: 80, rows: 24 };
      
      render(
        <TerminalControls
          isAtBottom={false}
          hasNewOutput={true}
          onScrollToTop={mockScrollToTop}
          onScrollToBottom={mockScrollToBottom}
          terminalConfig={config}
        />
      );

      // All controls should still be present
      expect(screen.getByTitle('Scroll to top')).toBeInTheDocument();
      expect(screen.getByTitle('Scroll to bottom')).toBeInTheDocument();
      expect(screen.getByText('See latest')).toBeInTheDocument();
      
      // Config display should be present
      expect(screen.getByText('80×24')).toBeInTheDocument();
      
      // Visual indicator should be present
      expect(screen.container.querySelector('.h-1.bg-gray-800')).toBeInTheDocument();
    });
  });
});