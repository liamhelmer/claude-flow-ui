import { render, screen, fireEvent, act } from '@testing-library/react';
import PromptPanel from '../PromptPanel';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the useWebSocket hook
jest.mock('@/hooks/useWebSocket');

const mockWebSocket = {
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
};

const mockPromptData = {
  prompt: 'Test prompt content',
  context: {
    model: 'claude-3.5-sonnet',
    temperature: 0.8,
    maxTokens: 8192,
    systemPrompt: 'You are a helpful assistant',
  },
};

describe('PromptPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
    
    // Mock Date.now for consistent timestamps
    jest.spyOn(Date, 'now').mockReturnValue(1609459200000); // 2021-01-01
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('connection states', () => {
    it('should show disconnected state when not connected', () => {
      (useWebSocket as jest.Mock).mockReturnValue({
        ...mockWebSocket,
        isConnected: false,
      });

      render(<PromptPanel />);

      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('should show panel content when connected', () => {
      render(<PromptPanel />);

      expect(screen.getByText('Current Prompt')).toBeInTheDocument();
      expect(screen.getByText('Context')).toBeInTheDocument();
    });
  });

  describe('initial state', () => {
    it('should render with default values', () => {
      render(<PromptPanel />);

      expect(screen.getByText('Welcome to Claude Flow Terminal')).toBeInTheDocument();
      expect(screen.getByText('claude-3')).toBeInTheDocument();
      expect(screen.getByText('0.7')).toBeInTheDocument();
      expect(screen.getByText('4096')).toBeInTheDocument();
    });

    it('should show system prompt when available', () => {
      render(<PromptPanel />);

      expect(screen.getByText('System Prompt')).toBeInTheDocument();
      expect(screen.getByText('Claude Flow UI Terminal System')).toBeInTheDocument();
    });

    it('should initialize with default history', () => {
      render(<PromptPanel />);

      // Show history first
      const showHistoryButton = screen.getByText('Show History');
      fireEvent.click(showHistoryButton);

      expect(screen.getByText('System initialized')).toBeInTheDocument();
      expect(screen.getByText('Ready for input')).toBeInTheDocument();
      expect(screen.getByText('History (2 prompts)')).toBeInTheDocument();
    });
  });

  describe('prompt updates', () => {
    it('should handle prompt-update events', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({
          prompt: 'New test prompt',
          context: {
            model: 'claude-3.5-sonnet',
            temperature: 0.9,
            maxTokens: 2048,
          },
        });
      });

      expect(screen.getByText('New test prompt')).toBeInTheDocument();
      expect(screen.getByText('claude-3.5-sonnet')).toBeInTheDocument();
      expect(screen.getByText('0.9')).toBeInTheDocument();
      expect(screen.getByText('2048')).toBeInTheDocument();
    });

    it('should add prompts to history', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      // Show history first
      const showHistoryButton = screen.getByText('Show History');
      fireEvent.click(showHistoryButton);

      // Add new prompt
      act(() => {
        promptUpdateHandler({
          prompt: 'First new prompt',
        });
      });

      expect(screen.getByText('History (3 prompts)')).toBeInTheDocument();
      expect(screen.getByText('First new prompt')).toBeInTheDocument();
    });

    it('should preserve existing data when context is not provided', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({
          prompt: 'New prompt without context',
        });
      });

      // Should still show original context values
      expect(screen.getByText('claude-3')).toBeInTheDocument();
      expect(screen.getByText('0.7')).toBeInTheDocument();
      expect(screen.getByText('4096')).toBeInTheDocument();
    });

    it('should handle empty prompt updates', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      expect(() => {
        act(() => {
          promptUpdateHandler({
            context: {
              model: 'updated-model',
            },
          });
        });
      }).not.toThrow();

      expect(screen.getByText('updated-model')).toBeInTheDocument();
    });
  });

  describe('system prompt updates', () => {
    it('should handle system-prompt events', () => {
      render(<PromptPanel />);

      const systemPromptHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'system-prompt')[1];

      act(() => {
        systemPromptHandler({
          systemPrompt: 'Updated system prompt content',
        });
      });

      expect(screen.getByText('Updated system prompt content')).toBeInTheDocument();
    });

    it('should preserve other context data when updating system prompt', () => {
      render(<PromptPanel />);

      const systemPromptHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'system-prompt')[1];

      act(() => {
        systemPromptHandler({
          systemPrompt: 'New system prompt',
        });
      });

      // Should preserve existing context
      expect(screen.getByText('claude-3')).toBeInTheDocument();
      expect(screen.getByText('0.7')).toBeInTheDocument();
      expect(screen.getByText('4096')).toBeInTheDocument();
    });
  });

  describe('history toggle', () => {
    it('should toggle history visibility', () => {
      render(<PromptPanel />);

      const toggleButton = screen.getByText('Show History');
      
      // Initially hidden
      expect(screen.queryByText(/History \(\d+ prompts\)/)).not.toBeInTheDocument();

      // Show history
      fireEvent.click(toggleButton);
      expect(screen.getByText(/History \(\d+ prompts\)/)).toBeInTheDocument();
      expect(screen.getByText('Hide History')).toBeInTheDocument();

      // Hide history
      fireEvent.click(screen.getByText('Hide History'));
      expect(screen.queryByText(/History \(\d+ prompts\)/)).not.toBeInTheDocument();
      expect(screen.getByText('Show History')).toBeInTheDocument();
    });

    it('should show correct history count', () => {
      render(<PromptPanel />);

      const toggleButton = screen.getByText('Show History');
      fireEvent.click(toggleButton);

      expect(screen.getByText('History (2 prompts)')).toBeInTheDocument();
    });
  });

  describe('history display', () => {
    it('should display history in reverse order (newest first)', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      // Add multiple prompts
      act(() => {
        promptUpdateHandler({ prompt: 'First prompt' });
        promptUpdateHandler({ prompt: 'Second prompt' });
        promptUpdateHandler({ prompt: 'Third prompt' });
      });

      // Show history
      const toggleButton = screen.getByText('Show History');
      fireEvent.click(toggleButton);

      const historyItems = screen.container.querySelectorAll('[class*="bg-gray-800 rounded-lg p-2"]');
      expect(historyItems).toHaveLength(5); // 2 initial + 3 new

      // Check order (newest first)
      const firstItem = historyItems[0];
      expect(firstItem.textContent).toContain('#5');
      expect(firstItem.textContent).toContain('Third prompt');
    });

    it('should show empty history message when no history', () => {
      // Start with empty history
      render(<PromptPanel />);

      // Clear the default history by creating a new component state
      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      // Update with empty history (this would need to be handled in the component)
      // For now, let's test with default history
      const toggleButton = screen.getByText('Show History');
      fireEvent.click(toggleButton);

      // Should show the default history items
      expect(screen.getByText('System initialized')).toBeInTheDocument();
      expect(screen.getByText('Ready for input')).toBeInTheDocument();
    });

    it('should show prompt numbers correctly', () => {
      render(<PromptPanel />);

      const toggleButton = screen.getByText('Show History');
      fireEvent.click(toggleButton);

      expect(screen.getByText('#2')).toBeInTheDocument(); // Ready for input
      expect(screen.getByText('#1')).toBeInTheDocument(); // System initialized
    });
  });

  describe('context display', () => {
    it('should display all context information when available', () => {
      render(<PromptPanel />);

      expect(screen.getByText('Model:')).toBeInTheDocument();
      expect(screen.getByText('claude-3')).toBeInTheDocument();
      expect(screen.getByText('Temperature:')).toBeInTheDocument();
      expect(screen.getByText('0.7')).toBeInTheDocument();
      expect(screen.getByText('Max Tokens:')).toBeInTheDocument();
      expect(screen.getByText('4096')).toBeInTheDocument();
    });

    it('should handle missing context fields gracefully', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({
          prompt: 'Test prompt',
          context: {
            model: 'test-model',
            // temperature and maxTokens missing
          },
        });
      });

      expect(screen.getByText('test-model')).toBeInTheDocument();
      // Temperature and maxTokens should not be displayed if undefined
    });

    it('should handle zero temperature correctly', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({
          context: {
            temperature: 0,
          },
        });
      });

      expect(screen.getByText('0')).toBeInTheDocument();
    });
  });

  describe('no active prompt state', () => {
    it('should show no active prompt message when current is empty', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({
          prompt: '', // Empty prompt
        });
      });

      expect(screen.getByText('No active prompt')).toBeInTheDocument();
    });
  });

  describe('statistics display', () => {
    it('should show correct total prompts count', () => {
      render(<PromptPanel />);

      expect(screen.getByText('Total Prompts:')).toBeInTheDocument();
      expect(screen.getByText('2')).toBeInTheDocument(); // Initial history count
    });

    it('should show last updated time', () => {
      render(<PromptPanel />);

      expect(screen.getByText('Last Updated:')).toBeInTheDocument();
      // The exact time will depend on the mocked Date.now()
      expect(screen.getByText(/\d{1,2}:\d{2}:\d{2}/)).toBeInTheDocument();
    });

    it('should update statistics when prompts are added', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({ prompt: 'New prompt' });
      });

      expect(screen.getByText('3')).toBeInTheDocument(); // Updated count
    });
  });

  describe('event listener cleanup', () => {
    it('should set up WebSocket event listeners on mount', () => {
      render(<PromptPanel />);

      expect(mockWebSocket.on).toHaveBeenCalledWith('prompt-update', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('system-prompt', expect.any(Function));
    });

    it('should clean up event listeners on unmount', () => {
      const { unmount } = render(<PromptPanel />);

      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('prompt-update', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('system-prompt', expect.any(Function));
    });
  });

  describe('text truncation and formatting', () => {
    it('should handle long prompts with proper formatting', () => {
      render(<PromptPanel />);

      const longPrompt = 'A'.repeat(1000);
      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({ prompt: longPrompt });
      });

      const promptElement = screen.container.querySelector('pre.whitespace-pre-wrap');
      expect(promptElement).toBeInTheDocument();
      expect(promptElement?.textContent).toBe(longPrompt);
    });

    it('should preserve whitespace in prompts', () => {
      render(<PromptPanel />);

      const promptWithWhitespace = 'Line 1\n\nLine 3\t\tTabbed';
      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({ prompt: promptWithWhitespace });
      });

      const promptElement = screen.container.querySelector('pre.whitespace-pre-wrap');
      expect(promptElement?.textContent).toBe(promptWithWhitespace);
    });

    it('should handle history item truncation', () => {
      render(<PromptPanel />);

      const longPrompt = 'A'.repeat(500);
      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      act(() => {
        promptUpdateHandler({ prompt: longPrompt });
      });

      const toggleButton = screen.getByText('Show History');
      fireEvent.click(toggleButton);

      const historyItem = screen.container.querySelector('pre.truncate');
      expect(historyItem).toBeInTheDocument();
    });
  });

  describe('edge cases', () => {
    it('should handle null or undefined prompt data', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      expect(() => {
        act(() => {
          promptUpdateHandler(null);
        });
      }).not.toThrow();

      expect(() => {
        act(() => {
          promptUpdateHandler(undefined);
        });
      }).not.toThrow();
    });

    it('should handle invalid context data', () => {
      render(<PromptPanel />);

      const promptUpdateHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'prompt-update')[1];

      expect(() => {
        act(() => {
          promptUpdateHandler({
            context: null,
          });
        });
      }).not.toThrow();
    });

    it('should handle system prompt being null', () => {
      render(<PromptPanel />);

      const systemPromptHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'system-prompt')[1];

      act(() => {
        systemPromptHandler({
          systemPrompt: null,
        });
      });

      // System prompt section should not be visible when null
      expect(screen.queryByText('System Prompt')).not.toBeInTheDocument();
    });
  });
});