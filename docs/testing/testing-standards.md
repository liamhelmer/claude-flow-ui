# Testing Standards and Conventions

## Overview
This document establishes comprehensive testing standards for the Claude UI project to ensure consistent, maintainable, and high-quality tests across the codebase.

## Code Quality Standards

### Test Code Quality Principles
1. **Clarity Over Cleverness**: Write clear, readable tests
2. **Single Responsibility**: Each test should verify one behavior
3. **Descriptive Names**: Test names should explain what is being tested
4. **Arrange-Act-Assert**: Follow AAA pattern for test structure
5. **DRY Principle**: Avoid duplication through helpers and utilities

### Test Structure Standards
```typescript
describe('ComponentName/FeatureName', () => {
  // Group related tests logically
  describe('Primary Functionality', () => {
    beforeEach(() => {
      // Setup specific to this group
    });
    
    it('should perform expected behavior when given valid input', () => {
      // Arrange
      const input = createValidInput();
      const expectedOutput = createExpectedOutput();
      
      // Act
      const result = performAction(input);
      
      // Assert
      expect(result).toEqual(expectedOutput);
    });
  });
  
  describe('Error Handling', () => {
    // Error case tests
  });
  
  describe('Edge Cases', () => {
    // Edge case tests
  });
});
```

## Naming Conventions

### File Naming
```bash
# Unit tests
ComponentName.test.tsx
hookName.test.ts
utilityName.test.ts

# Integration tests
feature-integration.test.ts
component-interaction.test.tsx

# End-to-end tests
user-workflow.e2e.test.ts
critical-path.e2e.test.ts

# Performance tests
component-performance.test.ts
load-testing.test.ts

# Security tests
input-validation.security.test.ts
xss-prevention.security.test.ts
```

### Test Suite Naming
```typescript
// ✅ Good: Specific and descriptive
describe('TerminalComponent', () => {});
describe('WebSocket Integration', () => {});
describe('User Authentication Flow', () => {});

// ❌ Bad: Generic and unclear
describe('Component', () => {});
describe('Tests', () => {});
describe('Functionality', () => {});
```

### Test Case Naming
```typescript
// ✅ Good: Behavior-focused, readable
it('should display error message when login fails', () => {});
it('should call onSubmit with form data when form is valid', () => {});
it('should disable submit button while request is pending', () => {});

// ❌ Bad: Implementation-focused, unclear
it('renders correctly', () => {});
it('works as expected', () => {});
it('test component function', () => {});
```

## Testing Patterns and Best Practices

### Component Testing Standards

#### React Component Testing
```typescript
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TerminalComponent } from '../TerminalComponent';

describe('TerminalComponent', () => {
  const defaultProps = {
    sessionId: 'test-session',
    onCommand: jest.fn(),
    isConnected: true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render terminal container with proper attributes', () => {
      render(<TerminalComponent {...defaultProps} />);
      
      const terminal = screen.getByRole('application', { name: /terminal/i });
      expect(terminal).toBeInTheDocument();
      expect(terminal).toHaveAttribute('data-session-id', 'test-session');
    });

    it('should show connection status indicator', () => {
      render(<TerminalComponent {...defaultProps} />);
      
      expect(screen.getByLabelText(/connected/i)).toBeInTheDocument();
    });
  });

  describe('User Interactions', () => {
    it('should focus terminal when container is clicked', async () => {
      const user = userEvent.setup();
      render(<TerminalComponent {...defaultProps} />);
      
      const terminal = screen.getByRole('application');
      await user.click(terminal);
      
      expect(terminal).toHaveFocus();
    });

    it('should call onCommand when Enter key is pressed', async () => {
      const user = userEvent.setup();
      const mockOnCommand = jest.fn();
      
      render(<TerminalComponent {...defaultProps} onCommand={mockOnCommand} />);
      
      await user.type(screen.getByRole('textbox'), 'ls -la{enter}');
      
      expect(mockOnCommand).toHaveBeenCalledWith('ls -la');
    });
  });

  describe('Props and State Management', () => {
    it('should update when sessionId changes', () => {
      const { rerender } = render(<TerminalComponent {...defaultProps} />);
      
      rerender(<TerminalComponent {...defaultProps} sessionId="new-session" />);
      
      expect(screen.getByRole('application')).toHaveAttribute(
        'data-session-id', 
        'new-session'
      );
    });

    it('should handle loading state correctly', () => {
      render(<TerminalComponent {...defaultProps} isConnected={false} />);
      
      expect(screen.getByText(/connecting/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/disconnected/i)).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('should display error message when connection fails', () => {
      render(<TerminalComponent {...defaultProps} error="Connection failed" />);
      
      expect(screen.getByRole('alert')).toHaveTextContent('Connection failed');
    });

    it('should handle invalid session ID gracefully', () => {
      render(<TerminalComponent {...defaultProps} sessionId="" />);
      
      expect(screen.getByText(/invalid session/i)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<TerminalComponent {...defaultProps} />);
      
      expect(screen.getByRole('application')).toHaveAccessibleName(/terminal/i);
      expect(screen.getByRole('textbox')).toHaveAccessibleName(/command input/i);
    });

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      render(<TerminalComponent {...defaultProps} />);
      
      await user.tab();
      expect(screen.getByRole('textbox')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByRole('button', { name: /clear/i })).toHaveFocus();
    });
  });
});
```

#### Hook Testing Standards
```typescript
import { renderHook, act } from '@testing-library/react';
import { useTerminal } from '../useTerminal';

describe('useTerminal', () => {
  describe('Initial State', () => {
    it('should initialize with default values', () => {
      const { result } = renderHook(() => useTerminal());
      
      expect(result.current.isConnected).toBe(false);
      expect(result.current.currentSession).toBeNull();
      expect(result.current.history).toEqual([]);
    });
  });

  describe('Session Management', () => {
    it('should create new session with unique ID', () => {
      const { result } = renderHook(() => useTerminal());
      
      act(() => {
        result.current.createSession('test-session');
      });
      
      expect(result.current.currentSession).toEqual(
        expect.objectContaining({
          id: 'test-session',
          isActive: true,
        })
      );
    });

    it('should switch between sessions correctly', () => {
      const { result } = renderHook(() => useTerminal());
      
      act(() => {
        result.current.createSession('session-1');
        result.current.createSession('session-2');
      });
      
      act(() => {
        result.current.switchSession('session-1');
      });
      
      expect(result.current.currentSession?.id).toBe('session-1');
    });
  });

  describe('Command History', () => {
    it('should add commands to history', () => {
      const { result } = renderHook(() => useTerminal());
      
      act(() => {
        result.current.executeCommand('ls -la');
        result.current.executeCommand('pwd');
      });
      
      expect(result.current.history).toEqual(['ls -la', 'pwd']);
    });

    it('should limit history size to prevent memory leaks', () => {
      const { result } = renderHook(() => useTerminal());
      
      act(() => {
        // Add more than max history items
        for (let i = 0; i < 1500; i++) {
          result.current.executeCommand(`command-${i}`);
        }
      });
      
      expect(result.current.history.length).toBeLessThanOrEqual(1000);
    });
  });
});
```

### Integration Testing Standards

#### Component Integration Testing
```typescript
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createIntegrationTest } from '@tests/utils/test-helpers';
import { TerminalApp } from '../TerminalApp';

createIntegrationTest('Terminal Application Integration', () => {
  let mockWebSocket: MockWebSocket;
  let mockStore: MockStore;

  beforeEach(() => {
    mockWebSocket = createMockWebSocket();
    mockStore = createMockStore();
  });

  describe('Terminal and Sidebar Integration', () => {
    it('should synchronize session state between components', async () => {
      const user = userEvent.setup();
      render(<TerminalApp />, { 
        providers: { webSocket: mockWebSocket, store: mockStore }
      });
      
      // Create session via sidebar
      const createButton = screen.getByRole('button', { name: /new session/i });
      await user.click(createButton);
      
      // Verify terminal updates
      await waitFor(() => {
        expect(screen.getByRole('application')).toHaveAttribute(
          'data-session-id',
          expect.stringMatching(/session-\d+/)
        );
      });
      
      // Verify sidebar updates
      expect(screen.getByText(/session-\d+/)).toBeInTheDocument();
    });

    it('should handle session deletion across components', async () => {
      const user = userEvent.setup();
      render(<TerminalApp />);
      
      // Create and then delete session
      await user.click(screen.getByRole('button', { name: /new session/i }));
      await user.click(screen.getByRole('button', { name: /delete session/i }));
      
      // Verify both components update
      await waitFor(() => {
        expect(screen.queryByRole('application')).not.toBeInTheDocument();
        expect(screen.getByText(/no active session/i)).toBeInTheDocument();
      });
    });
  });

  describe('WebSocket Integration', () => {
    it('should establish connection and sync state', async () => {
      render(<TerminalApp />);
      
      // Simulate WebSocket connection
      act(() => {
        mockWebSocket.readyState = WebSocket.OPEN;
        mockWebSocket.onopen?.(new Event('open'));
      });
      
      await waitFor(() => {
        expect(screen.getByText(/connected/i)).toBeInTheDocument();
      });
    });

    it('should handle real-time message exchange', async () => {
      const user = userEvent.setup();
      render(<TerminalApp />);
      
      // Connect WebSocket
      act(() => {
        mockWebSocket.readyState = WebSocket.OPEN;
        mockWebSocket.onopen?.(new Event('open'));
      });
      
      // Send command
      await user.type(screen.getByRole('textbox'), 'echo "hello"{enter}');
      
      // Simulate server response
      act(() => {
        mockWebSocket.onmessage?.(new MessageEvent('message', {
          data: JSON.stringify({
            type: 'terminal-output',
            data: 'hello\n$',
          }),
        }));
      });
      
      await waitFor(() => {
        expect(screen.getByText('hello')).toBeInTheDocument();
      });
    });
  });
});
```

### Async Testing Patterns

#### Promise-based Testing
```typescript
describe('Async Operations', () => {
  it('should handle async data fetching', async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: 'test data' }),
    });
    global.fetch = mockFetch;
    
    render(<DataComponent />);
    
    await waitFor(() => {
      expect(screen.getByText('test data')).toBeInTheDocument();
    });
    
    expect(mockFetch).toHaveBeenCalledWith('/api/data');
  });

  it('should handle async errors gracefully', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'));
    global.fetch = mockFetch;
    
    render(<DataComponent />);
    
    await waitFor(() => {
      expect(screen.getByText(/error loading data/i)).toBeInTheDocument();
    });
  });
});
```

#### WebSocket Testing Patterns
```typescript
describe('WebSocket Communication', () => {
  it('should handle connection lifecycle', async () => {
    const { result } = renderHook(() => useWebSocket());
    
    expect(result.current.connected).toBe(false);
    
    act(() => {
      result.current.connect();
    });
    
    await waitFor(() => {
      expect(result.current.connected).toBe(true);
    });
    
    act(() => {
      result.current.disconnect();
    });
    
    await waitFor(() => {
      expect(result.current.connected).toBe(false);
    });
  });

  it('should handle message queuing during reconnection', async () => {
    const { result } = renderHook(() => useWebSocket());
    
    // Send messages while disconnected
    act(() => {
      result.current.send('message1');
      result.current.send('message2');
    });
    
    expect(result.current.messageQueue).toHaveLength(2);
    
    // Connect and verify messages are sent
    act(() => {
      result.current.connect();
    });
    
    await waitFor(() => {
      expect(result.current.messageQueue).toHaveLength(0);
    });
  });
});
```

## Error Handling Standards

### Error Testing Patterns
```typescript
describe('Error Handling', () => {
  it('should display user-friendly error messages', () => {
    render(<Component error="Network connection failed" />);
    
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Unable to connect. Please check your internet connection.'
    );
  });

  it('should recover from transient errors', async () => {
    const mockApi = jest.fn()
      .mockRejectedValueOnce(new Error('Temporary error'))
      .mockResolvedValue({ data: 'success' });
    
    render(<Component api={mockApi} />);
    
    // Wait for retry
    await waitFor(() => {
      expect(screen.getByText('success')).toBeInTheDocument();
    }, { timeout: 5000 });
    
    expect(mockApi).toHaveBeenCalledTimes(2);
  });

  it('should handle unexpected errors gracefully', () => {
    const ThrowingComponent = () => {
      throw new Error('Unexpected error');
    };
    
    render(
      <ErrorBoundary>
        <ThrowingComponent />
      </ErrorBoundary>
    );
    
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
  });
});
```

## Performance Testing Standards

### Performance Testing Patterns
```typescript
describe('Performance', () => {
  it('should render within performance budget', () => {
    const startTime = performance.now();
    
    render(<LargeComponent items={generateLargeDataset(1000)} />);
    
    const endTime = performance.now();
    const renderTime = endTime - startTime;
    
    expect(renderTime).toBeLessThan(100); // 100ms budget
  });

  it('should handle large datasets efficiently', () => {
    const largeDataset = generateLargeDataset(10000);
    
    render(<VirtualizedList items={largeDataset} />);
    
    // Only visible items should be rendered
    const renderedItems = screen.getAllByTestId('list-item');
    expect(renderedItems).toHaveLength(10); // Only 10 visible items
  });

  it('should not cause memory leaks', () => {
    const { unmount } = render(<Component />);
    
    const initialMemory = performance.memory?.usedJSHeapSize;
    
    unmount();
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    const finalMemory = performance.memory?.usedJSHeapSize;
    
    if (initialMemory && finalMemory) {
      expect(finalMemory).toBeLessThanOrEqual(initialMemory * 1.1);
    }
  });
});
```

## Accessibility Testing Standards

### A11y Testing Patterns
```typescript
import { axe, toHaveNoViolations } from 'jest-axe';

expect.extend(toHaveNoViolations);

describe('Accessibility', () => {
  it('should have no accessibility violations', async () => {
    const { container } = render(<Component />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('should support keyboard navigation', async () => {
    const user = userEvent.setup();
    render(<NavigationComponent />);
    
    // Test tab navigation
    await user.tab();
    expect(screen.getByRole('button', { name: /first/i })).toHaveFocus();
    
    await user.tab();
    expect(screen.getByRole('button', { name: /second/i })).toHaveFocus();
    
    // Test arrow key navigation
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('menuitem', { name: /option 1/i })).toHaveFocus();
  });

  it('should have proper ARIA attributes', () => {
    render(<Component />);
    
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-labelledby');
    expect(dialog).toHaveAttribute('aria-describedby');
    
    const closeButton = screen.getByRole('button', { name: /close/i });
    expect(closeButton).toHaveAttribute('aria-label', 'Close dialog');
  });

  it('should announce dynamic content changes', async () => {
    render(<LiveRegionComponent />);
    
    const liveRegion = screen.getByRole('status');
    expect(liveRegion).toHaveAttribute('aria-live', 'polite');
    
    fireEvent.click(screen.getByRole('button', { name: /update/i }));
    
    await waitFor(() => {
      expect(liveRegion).toHaveTextContent('Content updated');
    });
  });
});
```

## Security Testing Standards

### Security Testing Patterns
```typescript
describe('Security', () => {
  it('should sanitize user input', () => {
    const maliciousInput = '<script>alert("xss")</script>';
    
    render(<InputComponent value={maliciousInput} />);
    
    const input = screen.getByRole('textbox');
    expect(input).toHaveValue('alert("xss")'); // Script tags removed
  });

  it('should prevent XSS in dynamic content', () => {
    const maliciousContent = '<img src="x" onerror="alert(1)">';
    
    render(<DisplayComponent content={maliciousContent} />);
    
    // Check that content is escaped
    expect(screen.getByText(/img src/)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).not.toBeInTheDocument();
  });

  it('should validate CSRF tokens', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true });
    global.fetch = mockFetch;
    
    render(<FormComponent />);
    
    fireEvent.click(screen.getByRole('button', { name: /submit/i }));
    
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-CSRF-Token': expect.any(String),
          }),
        })
      );
    });
  });
});
```

## Test Maintenance Standards

### Regular Maintenance Tasks
1. **Weekly**: Review failing tests and flaky test reports
2. **Monthly**: Update test dependencies and review coverage
3. **Quarterly**: Audit test performance and refactor slow tests
4. **Annually**: Review testing architecture and update standards

### Code Review Checklist for Tests
- [ ] Test names clearly describe the behavior being tested
- [ ] Tests follow the AAA (Arrange-Act-Assert) pattern
- [ ] No hardcoded values; use factories or fixtures
- [ ] Proper cleanup in `afterEach` or `afterAll` hooks
- [ ] Accessibility testing included for UI components
- [ ] Error cases and edge cases covered
- [ ] Performance considerations addressed
- [ ] No test implementation details leaked into production code

### Refactoring Guidelines
- Extract common setup into helper functions
- Use data-driven tests for similar test cases
- Replace brittle selectors with semantic queries
- Consolidate duplicate mock setups
- Remove dead or obsolete tests

## Conclusion

These testing standards provide a comprehensive foundation for maintaining high-quality tests across the Claude UI project. Adherence to these standards will ensure:

- **Consistency**: All tests follow the same patterns and conventions
- **Maintainability**: Tests are easy to understand and modify
- **Reliability**: Tests accurately reflect application behavior
- **Completeness**: All important scenarios are covered
- **Performance**: Tests run efficiently in development and CI/CD

Regular review and updates of these standards will ensure they continue to serve the project's needs as it evolves.