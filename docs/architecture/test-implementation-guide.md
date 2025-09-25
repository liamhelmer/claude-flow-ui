# Test Architecture Implementation Guide

## Implementation Strategy

This guide provides step-by-step instructions for implementing the comprehensive test architecture for claude-flow-ui, following the modular design principles with each component under 500 lines.

## Phase 1: Foundation Setup (Week 1-2)

### 1.1 Core Testing Infrastructure

#### Enhanced Jest Configuration
```bash
# Install testing dependencies
npm install --save-dev jest @testing-library/react @testing-library/jest-dom
npm install --save-dev @testing-library/user-event jest-environment-jsdom
npm install --save-dev @types/jest jest-junit ts-jest
```

#### Test Setup Files Structure
```
tests/
├── unit/
│   ├── setup.ts                 # Unit test setup
│   ├── components/               # Component tests
│   ├── hooks/                    # Hook tests
│   ├── lib/                     # Library tests
│   └── utils/                   # Utility tests
├── integration/
│   ├── setup.ts                 # Integration test setup
│   ├── api/                     # API integration
│   ├── database/                # Database integration
│   └── websocket/               # WebSocket integration
├── e2e/
│   ├── playwright.config.ts     # E2E configuration
│   ├── fixtures/                # Test fixtures
│   ├── page-objects/            # Page objects
│   └── tests/                   # E2E test files
├── performance/
│   ├── k6/                      # K6 load tests
│   ├── lighthouse/              # Lighthouse tests
│   └── monitoring/              # Performance monitoring
├── security/
│   ├── owasp/                   # OWASP tests
│   ├── penetration/             # Penetration tests
│   └── compliance/              # Compliance tests
├── visual/
│   ├── screenshots/             # Visual baselines
│   ├── config/                  # Visual test config
│   └── comparisons/             # Comparison results
├── factories/
│   ├── user-factory.ts          # User data factory
│   ├── session-factory.ts       # Session data factory
│   └── event-factory.ts         # Event data factory
├── fixtures/
│   ├── api-responses.json       # API mock responses
│   ├── test-data.sql           # Database test data
│   └── websocket-events.json   # WebSocket events
└── utils/
    ├── test-helpers.ts          # Common test utilities
    ├── mock-services.ts         # Service mocks
    └── assertions.ts            # Custom assertions
```

### 1.2 Unit Testing Implementation

#### Component Test Template (< 500 lines)
```typescript
// tests/unit/components/component-test-template.ts
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';
import '@testing-library/jest-dom';

// Test utilities
export const renderWithProviders = (component: React.ReactElement, options = {}) => {
  const { theme = 'light', ...renderOptions } = options;

  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    <ThemeProvider theme={theme}>
      <MemoryRouter>
        <QueryClientProvider client={createTestQueryClient()}>
          {children}
        </QueryClientProvider>
      </MemoryRouter>
    </ThemeProvider>
  );

  return render(component, { wrapper: Wrapper, ...renderOptions });
};

// Standard test patterns
export const createComponentTestSuite = (Component: React.ComponentType<any>, defaultProps: any) => ({
  // Rendering tests
  async testBasicRendering() {
    renderWithProviders(<Component {...defaultProps} />);
    expect(screen.getByRole('main')).toBeInTheDocument();
  },

  async testPropsHandling() {
    const customProps = { ...defaultProps, customProp: 'test-value' };
    renderWithProviders(<Component {...customProps} />);
    expect(screen.getByTestId('component-container')).toHaveAttribute('data-custom', 'test-value');
  },

  // Interaction tests
  async testUserInteractions() {
    const user = userEvent.setup();
    const mockHandler = jest.fn();
    renderWithProviders(<Component {...defaultProps} onAction={mockHandler} />);

    const button = screen.getByRole('button', { name: /action/i });
    await user.click(button);

    expect(mockHandler).toHaveBeenCalledWith(expect.objectContaining({
      type: 'action',
      payload: expect.any(Object)
    }));
  },

  // Error boundary tests
  async testErrorHandling() {
    const ThrowError = () => { throw new Error('Test error'); };
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    renderWithProviders(
      <ErrorBoundary>
        <ThrowError />
      </ErrorBoundary>
    );

    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    consoleSpy.mockRestore();
  },

  // Accessibility tests
  async testAccessibility() {
    const { container } = renderWithProviders(<Component {...defaultProps} />);

    // Check for basic accessibility
    expect(container.firstChild).toHaveAttribute('role');
    expect(screen.getByRole('main')).toHaveAccessibleName();

    // Keyboard navigation
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    expect(focusableElements.length).toBeGreaterThan(0);
  }
});
```

#### Hook Testing Framework (< 500 lines)
```typescript
// tests/unit/hooks/hook-test-framework.ts
import { renderHook, act, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import React from 'react';

// Hook test wrapper
export const createHookWrapper = (initialProps = {}) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false }
    }
  });

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <TestContextProvider {...initialProps}>
        {children}
      </TestContextProvider>
    </QueryClientProvider>
  );
};

// Hook test utilities
export const createHookTestSuite = <T extends (...args: any[]) => any>(
  hook: T,
  initialProps?: Parameters<T>[0]
) => ({
  // State management tests
  async testInitialState() {
    const { result } = renderHook(() => hook(initialProps), {
      wrapper: createHookWrapper()
    });

    expect(result.current).toMatchSnapshot();
  },

  async testStateUpdates() {
    const { result } = renderHook(() => hook(initialProps), {
      wrapper: createHookWrapper()
    });

    act(() => {
      result.current.updateState({ newValue: 'test' });
    });

    await waitFor(() => {
      expect(result.current.state.newValue).toBe('test');
    });
  },

  // Side effect tests
  async testSideEffects() {
    const mockEffect = jest.fn();
    const { result } = renderHook(() => hook({ ...initialProps, onEffect: mockEffect }), {
      wrapper: createHookWrapper()
    });

    act(() => {
      result.current.triggerEffect();
    });

    await waitFor(() => {
      expect(mockEffect).toHaveBeenCalled();
    });
  },

  // Cleanup tests
  async testCleanup() {
    const mockCleanup = jest.fn();
    const { unmount } = renderHook(() => hook({ ...initialProps, onCleanup: mockCleanup }), {
      wrapper: createHookWrapper()
    });

    unmount();

    expect(mockCleanup).toHaveBeenCalled();
  },

  // Error handling tests
  async testErrorHandling() {
    const { result } = renderHook(() => hook(initialProps), {
      wrapper: createHookWrapper()
    });

    act(() => {
      result.current.triggerError();
    });

    await waitFor(() => {
      expect(result.current.error).toBeTruthy();
    });
  }
});
```

### 1.3 Integration Testing Setup

#### API Integration Test Framework (< 500 lines)
```typescript
// tests/integration/api/api-integration-framework.ts
import request from 'supertest';
import { Express } from 'express';
import { setupTestDatabase, cleanupTestDatabase } from '../utils/database-utils';
import { createMockServer } from '../utils/mock-server';

export class ApiIntegrationTestSuite {
  private app: Express;
  private mockServer: any;

  constructor(app: Express) {
    this.app = app;
  }

  async setup() {
    await setupTestDatabase();
    this.mockServer = await createMockServer();
  }

  async teardown() {
    await cleanupTestDatabase();
    if (this.mockServer) {
      await this.mockServer.stop();
    }
  }

  // Authentication tests
  async testAuthenticationFlow() {
    const loginResponse = await request(this.app)
      .post('/api/auth/login')
      .send({
        email: 'test@example.com',
        password: 'password123'
      })
      .expect(200);

    expect(loginResponse.body).toHaveProperty('accessToken');
    expect(loginResponse.body).toHaveProperty('refreshToken');

    return loginResponse.body.accessToken;
  }

  // CRUD operation tests
  async testCrudOperations(endpoint: string, resourceData: any) {
    const token = await this.testAuthenticationFlow();

    // Create
    const createResponse = await request(this.app)
      .post(`/api/${endpoint}`)
      .set('Authorization', `Bearer ${token}`)
      .send(resourceData)
      .expect(201);

    const resourceId = createResponse.body.id;

    // Read
    await request(this.app)
      .get(`/api/${endpoint}/${resourceId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    // Update
    const updatedData = { ...resourceData, name: 'Updated Name' };
    await request(this.app)
      .put(`/api/${endpoint}/${resourceId}`)
      .set('Authorization', `Bearer ${token}`)
      .send(updatedData)
      .expect(200);

    // Delete
    await request(this.app)
      .delete(`/api/${endpoint}/${resourceId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(204);
  }

  // Error handling tests
  async testErrorHandling() {
    // Test 401 Unauthorized
    await request(this.app)
      .get('/api/protected')
      .expect(401);

    // Test 404 Not Found
    await request(this.app)
      .get('/api/nonexistent')
      .expect(404);

    // Test 400 Bad Request
    await request(this.app)
      .post('/api/users')
      .send({ invalid: 'data' })
      .expect(400);
  }

  // Rate limiting tests
  async testRateLimiting() {
    const requests = Array.from({ length: 10 }, () =>
      request(this.app)
        .get('/api/health')
        .expect(200)
    );

    await Promise.all(requests);

    // The 11th request should be rate limited
    await request(this.app)
      .get('/api/health')
      .expect(429);
  }
}
```

#### WebSocket Integration Testing (< 500 lines)
```typescript
// tests/integration/websocket/websocket-integration.ts
import { io, Socket } from 'socket.io-client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';

export class WebSocketIntegrationTestSuite {
  private server: any;
  private io: SocketIOServer;
  private clientSocket: Socket;
  private port: number;

  constructor(port = 3001) {
    this.port = port;
  }

  async setup() {
    this.server = createServer();
    this.io = new SocketIOServer(this.server);

    await new Promise<void>((resolve) => {
      this.server.listen(this.port, resolve);
    });

    this.clientSocket = io(`http://localhost:${this.port}`);

    await new Promise<void>((resolve) => {
      this.clientSocket.on('connect', resolve);
    });
  }

  async teardown() {
    this.clientSocket.disconnect();
    this.io.close();
    this.server.close();
  }

  // Connection tests
  async testConnection() {
    expect(this.clientSocket.connected).toBe(true);

    return new Promise<void>((resolve) => {
      this.clientSocket.emit('test-event', 'test-data');
      this.io.on('connection', (socket) => {
        socket.on('test-event', (data) => {
          expect(data).toBe('test-data');
          resolve();
        });
      });
    });
  }

  // Message broadcasting tests
  async testBroadcasting() {
    const client2 = io(`http://localhost:${this.port}`);
    await new Promise<void>((resolve) => {
      client2.on('connect', resolve);
    });

    return new Promise<void>((resolve) => {
      client2.on('broadcast-event', (data) => {
        expect(data).toBe('broadcast-message');
        client2.disconnect();
        resolve();
      });

      this.clientSocket.emit('broadcast', 'broadcast-message');
    });
  }

  // Reconnection tests
  async testReconnection() {
    this.clientSocket.disconnect();
    expect(this.clientSocket.connected).toBe(false);

    this.clientSocket.connect();

    return new Promise<void>((resolve) => {
      this.clientSocket.on('connect', () => {
        expect(this.clientSocket.connected).toBe(true);
        resolve();
      });
    });
  }

  // Error handling tests
  async testErrorHandling() {
    return new Promise<void>((resolve) => {
      this.clientSocket.on('error', (error) => {
        expect(error).toBeDefined();
        resolve();
      });

      this.clientSocket.emit('trigger-error');
    });
  }

  // Performance tests
  async testMessageThroughput() {
    const messageCount = 1000;
    const messages: string[] = [];

    return new Promise<void>((resolve) => {
      this.clientSocket.on('throughput-response', (data) => {
        messages.push(data);
        if (messages.length === messageCount) {
          expect(messages).toHaveLength(messageCount);
          resolve();
        }
      });

      for (let i = 0; i < messageCount; i++) {
        this.clientSocket.emit('throughput-test', `message-${i}`);
      }
    });
  }
}
```

## Phase 2: Advanced Testing (Week 3-4)

### 2.1 End-to-End Testing Implementation

#### Terminal Page Object (< 500 lines)
```typescript
// tests/e2e/page-objects/terminal-page.ts
import { Page, Locator, expect } from '@playwright/test';

export class TerminalPage {
  readonly page: Page;
  readonly terminalContainer: Locator;
  readonly commandInput: Locator;
  readonly terminalOutput: Locator;
  readonly tabList: Locator;
  readonly newTabButton: Locator;
  readonly settingsButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.terminalContainer = page.locator('[data-testid="terminal-container"]');
    this.commandInput = page.locator('[data-testid="command-input"]');
    this.terminalOutput = page.locator('[data-testid="terminal-output"]');
    this.tabList = page.locator('[data-testid="tab-list"]');
    this.newTabButton = page.locator('[data-testid="new-tab-button"]');
    this.settingsButton = page.locator('[data-testid="settings-button"]');
  }

  async navigateToTerminal() {
    await this.page.goto('/');
    await expect(this.terminalContainer).toBeVisible();
  }

  async executeCommand(command: string) {
    await this.commandInput.fill(command);
    await this.commandInput.press('Enter');
    await this.waitForCommandCompletion();
  }

  async waitForCommandCompletion() {
    // Wait for command prompt to return
    await this.page.waitForSelector('[data-testid="command-prompt"]', { state: 'visible' });
  }

  async waitForOutput(expectedText: string, timeout = 5000) {
    await expect(this.terminalOutput).toContainText(expectedText, { timeout });
  }

  async createNewTab(name?: string) {
    await this.newTabButton.click();
    if (name) {
      const nameInput = this.page.locator('[data-testid="tab-name-input"]');
      await nameInput.fill(name);
      await nameInput.press('Enter');
    }
  }

  async switchToTab(index: number) {
    const tab = this.tabList.locator(`[data-testid="tab-${index}"]`);
    await tab.click();
    await expect(tab).toHaveAttribute('aria-selected', 'true');
  }

  async closeTab(index: number) {
    const closeButton = this.tabList.locator(`[data-testid="tab-${index}"] [data-testid="close-tab"]`);
    await closeButton.click();
  }

  async getTabCount() {
    return await this.tabList.locator('[role="tab"]').count();
  }

  async getTerminalContent() {
    return await this.terminalOutput.textContent();
  }

  async clearTerminal() {
    await this.executeCommand('clear');
  }

  async resizeTerminal(width: number, height: number) {
    await this.page.setViewportSize({ width, height });
    // Wait for terminal to adapt to new size
    await this.page.waitForTimeout(500);
  }

  // Accessibility helpers
  async checkAccessibility() {
    // Check for proper ARIA attributes
    await expect(this.terminalContainer).toHaveAttribute('role', 'main');
    await expect(this.commandInput).toHaveAttribute('aria-label');

    // Check keyboard navigation
    await this.commandInput.press('Tab');
    const focusedElement = this.page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  }

  // Performance helpers
  async measureCommandExecutionTime(command: string) {
    const startTime = Date.now();
    await this.executeCommand(command);
    const endTime = Date.now();
    return endTime - startTime;
  }

  async waitForWebSocketConnection() {
    await this.page.waitForFunction(() => {
      return (window as any).websocketConnected === true;
    });
  }
}
```

#### E2E Test Scenarios (< 500 lines)
```typescript
// tests/e2e/scenarios/terminal-workflows.spec.ts
import { test, expect } from '@playwright/test';
import { TerminalPage } from '../page-objects/terminal-page';
import { WebSocketMockServer } from '../fixtures/websocket-mock';

test.describe('Terminal Workflows', () => {
  let terminalPage: TerminalPage;
  let mockServer: WebSocketMockServer;

  test.beforeEach(async ({ page }) => {
    terminalPage = new TerminalPage(page);
    mockServer = new WebSocketMockServer();
    await mockServer.start();
    await terminalPage.navigateToTerminal();
  });

  test.afterEach(async () => {
    await mockServer.stop();
  });

  test('should execute basic commands', async () => {
    await test.step('Execute ls command', async () => {
      await terminalPage.executeCommand('ls');
      await terminalPage.waitForOutput('Desktop');
    });

    await test.step('Execute pwd command', async () => {
      await terminalPage.executeCommand('pwd');
      await terminalPage.waitForOutput('/home/user');
    });

    await test.step('Execute echo command', async () => {
      await terminalPage.executeCommand('echo "Hello World"');
      await terminalPage.waitForOutput('Hello World');
    });
  });

  test('should handle multi-tab sessions', async () => {
    await test.step('Create multiple tabs', async () => {
      await terminalPage.createNewTab('Tab 1');
      await terminalPage.createNewTab('Tab 2');

      const tabCount = await terminalPage.getTabCount();
      expect(tabCount).toBe(3); // Initial tab + 2 new tabs
    });

    await test.step('Execute commands in different tabs', async () => {
      await terminalPage.switchToTab(0);
      await terminalPage.executeCommand('echo "First tab"');

      await terminalPage.switchToTab(1);
      await terminalPage.executeCommand('echo "Second tab"');

      await terminalPage.switchToTab(2);
      await terminalPage.executeCommand('echo "Third tab"');
    });

    await test.step('Verify tab content isolation', async () => {
      await terminalPage.switchToTab(0);
      await terminalPage.waitForOutput('First tab');

      await terminalPage.switchToTab(1);
      await terminalPage.waitForOutput('Second tab');

      await terminalPage.switchToTab(2);
      await terminalPage.waitForOutput('Third tab');
    });
  });

  test('should handle WebSocket reconnection', async () => {
    await test.step('Establish connection', async () => {
      await terminalPage.waitForWebSocketConnection();
      await terminalPage.executeCommand('echo "Connected"');
      await terminalPage.waitForOutput('Connected');
    });

    await test.step('Simulate disconnection', async () => {
      await mockServer.simulateDisconnection();
      await terminalPage.executeCommand('echo "Disconnected"');
      // Command should queue while disconnected
    });

    await test.step('Reconnect and process queued commands', async () => {
      await mockServer.simulateReconnection();
      await terminalPage.waitForWebSocketConnection();
      await terminalPage.waitForOutput('Disconnected');
    });
  });

  test('should handle error scenarios gracefully', async () => {
    await test.step('Invalid command', async () => {
      await terminalPage.executeCommand('invalid-command-xyz');
      await terminalPage.waitForOutput('command not found');
    });

    await test.step('Permission denied', async () => {
      await terminalPage.executeCommand('sudo rm -rf /');
      await terminalPage.waitForOutput('Permission denied');
    });

    await test.step('Long running command interruption', async () => {
      await terminalPage.executeCommand('sleep 60');
      await terminalPage.page.keyboard.press('Control+C');
      await terminalPage.waitForOutput('Interrupted');
    });
  });

  test('should be accessible', async () => {
    await test.step('Check accessibility attributes', async () => {
      await terminalPage.checkAccessibility();
    });

    await test.step('Keyboard navigation', async () => {
      // Test tab navigation through interface
      await terminalPage.page.keyboard.press('Tab');
      await terminalPage.page.keyboard.press('Tab');
      await terminalPage.page.keyboard.press('Enter');

      // Should create new tab
      const tabCount = await terminalPage.getTabCount();
      expect(tabCount).toBe(2);
    });
  });

  test('should perform within performance budgets', async () => {
    await test.step('Command execution speed', async () => {
      const executionTime = await terminalPage.measureCommandExecutionTime('echo "performance test"');
      expect(executionTime).toBeLessThan(1000); // Should complete within 1 second
    });

    await test.step('Tab switching performance', async () => {
      // Create multiple tabs with content
      for (let i = 0; i < 5; i++) {
        await terminalPage.createNewTab(`Tab ${i}`);
        await terminalPage.executeCommand(`echo "Content for tab ${i}"`);
      }

      // Measure tab switching time
      const startTime = Date.now();
      await terminalPage.switchToTab(0);
      const switchTime = Date.now() - startTime;

      expect(switchTime).toBeLessThan(500); // Should switch within 500ms
    });
  });
});
```

This implementation guide provides concrete, executable code for implementing the test architecture. Each component is designed to be under 500 lines and follows modular principles for maintainability and scalability.