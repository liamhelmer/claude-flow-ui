/**
 * Backstage Plugin Integration Tests
 *
 * These tests validate the claude-flow UI integration with Backstage,
 * ensuring proper plugin registration, API compatibility, and session management.
 */

import {
  createApiFactory,
  createPlugin,
  createRouteRef,
  configApiRef,
  identityApiRef,
  ApiRegistry,
  ConfigApi,
  IdentityApi
} from '@backstage/core-plugin-api';
import { renderInTestApp, TestApiProvider } from '@backstage/test-utils';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ClaudeFlowApi, claudeFlowApiRef } from '@/lib/backstage/api';
import { ClaudeFlowPlugin } from '@/lib/backstage/plugin';
import { Terminal } from '@/components/terminal/Terminal';
import { WebSocketClient } from '@/lib/websocket/client';

// Mock Backstage APIs
const createMockConfigApi = (): jest.Mocked<ConfigApi> => ({
  getConfig: jest.fn(),
  getOptionalConfig: jest.fn(),
  getConfigArray: jest.fn(),
  getOptionalConfigArray: jest.fn(),
  getString: jest.fn(),
  getOptionalString: jest.fn(),
  getNumber: jest.fn(),
  getOptionalNumber: jest.fn(),
  getBoolean: jest.fn(),
  getOptionalBoolean: jest.fn(),
  getStringArray: jest.fn(),
  getOptionalStringArray: jest.fn(),
  has: jest.fn(),
  keys: jest.fn(),
  get: jest.fn(),
  getOptional: jest.fn(),
});

const createMockIdentityApi = (userId = 'test-user'): jest.Mocked<IdentityApi> => ({
  getUserId: jest.fn().mockResolvedValue(userId),
  getProfile: jest.fn().mockResolvedValue({
    email: 'test@example.com',
    displayName: 'Test User',
  }),
  getProfileInfo: jest.fn().mockResolvedValue({
    email: 'test@example.com',
    displayName: 'Test User',
  }),
  getBackstageIdentity: jest.fn().mockResolvedValue({
    type: 'user',
    userEntityRef: `user:default/${userId}`,
    ownershipEntityRefs: [`user:default/${userId}`],
  }),
  getCredentials: jest.fn().mockResolvedValue({
    token: 'mock-jwt-token',
  }),
  signOut: jest.fn(),
});

describe('Backstage Plugin Integration', () => {
  let mockConfigApi: jest.Mocked<ConfigApi>;
  let mockIdentityApi: jest.Mocked<IdentityApi>;
  let apiRegistry: ApiRegistry;

  beforeEach(() => {
    mockConfigApi = createMockConfigApi();
    mockIdentityApi = createMockIdentityApi();
    apiRegistry = new ApiRegistry();

    // Default config values
    mockConfigApi.getOptionalString.mockImplementation((key) => {
      switch (key) {
        case 'claudeFlow.websocketUrl':
          return 'ws://localhost:11236';
        case 'claudeFlow.apiUrl':
          return 'http://localhost:11235';
        case 'claudeFlow.terminalTheme':
          return 'backstage-dark';
        default:
          return undefined;
      }
    });

    mockConfigApi.getOptionalNumber.mockImplementation((key) => {
      switch (key) {
        case 'claudeFlow.maxSessions':
          return 10;
        case 'claudeFlow.sessionTimeout':
          return 3600000; // 1 hour
        default:
          return undefined;
      }
    });

    mockConfigApi.getOptionalBoolean.mockImplementation((key) => {
      switch (key) {
        case 'claudeFlow.enableAuth':
          return true;
        case 'claudeFlow.enableLogging':
          return true;
        default:
          return undefined;
      }
    });
  });

  describe('Plugin Registration', () => {
    test('should register Claude Flow plugin successfully', () => {
      const plugin = ClaudeFlowPlugin.create();

      expect(plugin).toBeDefined();
      expect(plugin.getId()).toBe('claude-flow');
      expect(plugin.getApis()).toHaveLength(1);
      expect(plugin.getRoutes()).toBeDefined();
    });

    test('should provide Claude Flow API factory', () => {
      const plugin = ClaudeFlowPlugin.create();
      const apiFactory = plugin.getApis()[0];

      expect(apiFactory.api).toBe(claudeFlowApiRef);

      const api = apiFactory.factory({
        configApi: mockConfigApi,
        identityApi: mockIdentityApi,
      });

      expect(api).toBeInstanceOf(ClaudeFlowApi);
    });

    test('should configure routes correctly', () => {
      const plugin = ClaudeFlowPlugin.create();
      const routes = plugin.getRoutes();

      expect(routes.root).toBeDefined();
      expect(routes.terminal).toBeDefined();
      expect(routes.sessions).toBeDefined();
    });
  });

  describe('API Integration', () => {
    let api: ClaudeFlowApi;

    beforeEach(() => {
      api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
    });

    test('should create session with Backstage identity', async () => {
      const session = await api.createSession();

      expect(session).toMatchObject({
        id: expect.stringMatching(/^session-\w+$/),
        userId: 'test-user',
        entityRef: 'user:default/test-user',
        createdAt: expect.any(Date),
        status: 'active',
      });

      expect(mockIdentityApi.getUserId).toHaveBeenCalled();
      expect(mockIdentityApi.getBackstageIdentity).toHaveBeenCalled();
    });

    test('should authenticate WebSocket connection', async () => {
      const session = await api.createSession();
      const connection = await api.connectSession(session.id);

      expect(connection).toMatchObject({
        sessionId: session.id,
        websocketUrl: 'ws://localhost:11236',
        authToken: 'mock-jwt-token',
        connected: true,
      });

      expect(mockIdentityApi.getCredentials).toHaveBeenCalled();
    });

    test('should handle session authorization', async () => {
      const user1Api = new ClaudeFlowApi(mockConfigApi, createMockIdentityApi('user1'));
      const user2Api = new ClaudeFlowApi(mockConfigApi, createMockIdentityApi('user2'));

      const session = await user1Api.createSession();

      // User2 should not be able to access user1's session
      await expect(
        user2Api.connectSession(session.id)
      ).rejects.toThrow('Access denied: Session belongs to another user');
    });

    test('should refresh auth tokens automatically', async () => {
      mockIdentityApi.getCredentials
        .mockResolvedValueOnce({ token: 'expired-token' })
        .mockResolvedValueOnce({ token: 'refreshed-token' });

      const session = await api.createSession();

      // Simulate token expiration
      jest.spyOn(api as any, 'isTokenExpired').mockReturnValue(true);

      const result = await api.sendData(session.id, 'test command');

      expect(result.tokenRefreshed).toBe(true);
      expect(mockIdentityApi.getCredentials).toHaveBeenCalledTimes(2);
    });
  });

  describe('Session Management', () => {
    let api: ClaudeFlowApi;

    beforeEach(() => {
      api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
    });

    test('should maintain session state across plugin reloads', async () => {
      const session1 = await api.createSession();

      // Simulate plugin reload by creating new API instance
      const newApi = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);

      const sessions = await newApi.getUserSessions();

      expect(sessions).toContainEqual(
        expect.objectContaining({ id: session1.id })
      );
    });

    test('should handle session cleanup on user logout', async () => {
      const session = await api.createSession();

      // Simulate logout
      await mockIdentityApi.signOut();

      const sessions = await api.getUserSessions();

      expect(sessions).toHaveLength(0);
    });

    test('should enforce session limits', async () => {
      mockConfigApi.getOptionalNumber.mockImplementation((key) => {
        if (key === 'claudeFlow.maxSessions') return 2;
        return undefined;
      });

      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);

      // Create maximum allowed sessions
      const session1 = await api.createSession();
      const session2 = await api.createSession();

      // Third session should be rejected
      await expect(api.createSession()).rejects.toThrow(
        'Maximum session limit reached (2)'
      );
    });

    test('should handle session timeout', async () => {
      mockConfigApi.getOptionalNumber.mockImplementation((key) => {
        if (key === 'claudeFlow.sessionTimeout') return 1000; // 1 second
        return undefined;
      });

      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
      const session = await api.createSession();

      // Wait for session timeout
      await new Promise(resolve => setTimeout(resolve, 1100));

      const sessions = await api.getUserSessions();
      const activeSession = sessions.find(s => s.id === session.id);

      expect(activeSession?.status).toBe('expired');
    });
  });

  describe('Component Integration', () => {
    test('should render Terminal component in Backstage context', async () => {
      const apis = [
        [configApiRef, mockConfigApi],
        [identityApiRef, mockIdentityApi],
        [claudeFlowApiRef, new ClaudeFlowApi(mockConfigApi, mockIdentityApi)],
      ];

      await renderInTestApp(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="test-session" />
        </TestApiProvider>
      );

      expect(screen.getByRole('group')).toBeInTheDocument();
      expect(screen.getByText(/terminal/i)).toBeInTheDocument();
    });

    test('should integrate with Backstage theming', async () => {
      mockConfigApi.getOptionalString.mockImplementation((key) => {
        if (key === 'claudeFlow.terminalTheme') return 'backstage-light';
        return undefined;
      });

      const apis = [
        [configApiRef, mockConfigApi],
        [identityApiRef, mockIdentityApi],
        [claudeFlowApiRef, new ClaudeFlowApi(mockConfigApi, mockIdentityApi)],
      ];

      const { container } = await renderInTestApp(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="test-session" />
        </TestApiProvider>
      );

      const terminalWrapper = container.querySelector('.xterm-wrapper');
      expect(terminalWrapper).toHaveClass('backstage-light-theme');
    });

    test('should handle Backstage route navigation', async () => {
      const apis = [
        [configApiRef, mockConfigApi],
        [identityApi, mockIdentityApi],
        [claudeFlowApiRef, new ClaudeFlowApi(mockConfigApi, mockIdentityApi)],
      ];

      const { rerender } = await renderInTestApp(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="session-1" />
        </TestApiProvider>
      );

      // Simulate navigation to different session
      await act(async () => {
        rerender(
          <TestApiProvider apis={apis}>
            <Terminal sessionId="session-2" />
          </TestApiProvider>
        );
      });

      await waitFor(() => {
        expect(screen.getByRole('group')).toBeInTheDocument();
      });
    });
  });

  describe('WebSocket Integration with Backstage', () => {
    test('should connect WebSocket with Backstage auth headers', async () => {
      const mockWebSocket = jest.fn();
      const originalWebSocket = global.WebSocket;
      global.WebSocket = mockWebSocket;

      const client = new WebSocketClient();
      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);

      await api.createSession();

      expect(mockWebSocket).toHaveBeenCalledWith(
        'ws://localhost:11236',
        expect.arrayContaining([
          expect.stringContaining('Authorization: Bearer mock-jwt-token')
        ])
      );

      global.WebSocket = originalWebSocket;
    });

    test('should handle WebSocket reconnection with fresh auth', async () => {
      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
      const session = await api.createSession();

      // Simulate connection drop
      const connection = await api.connectSession(session.id);
      connection.disconnect();

      // Reconnection should fetch fresh token
      mockIdentityApi.getCredentials.mockResolvedValueOnce({
        token: 'fresh-token',
      });

      await connection.reconnect();

      expect(mockIdentityApi.getCredentials).toHaveBeenCalledTimes(2);
    });
  });

  describe('Error Handling', () => {
    test('should handle Backstage API errors gracefully', async () => {
      mockIdentityApi.getUserId.mockRejectedValue(
        new Error('Identity service unavailable')
      );

      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);

      await expect(api.createSession()).rejects.toThrow(
        'Failed to create session: Identity service unavailable'
      );
    });

    test('should handle configuration errors', async () => {
      mockConfigApi.getOptionalString.mockImplementation((key) => {
        if (key === 'claudeFlow.websocketUrl') return undefined;
        return undefined;
      });

      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);

      await expect(api.createSession()).rejects.toThrow(
        'Claude Flow WebSocket URL not configured'
      );
    });

    test('should provide helpful error messages for common issues', async () => {
      // Test missing authentication
      mockIdentityApi.getCredentials.mockRejectedValue(
        new Error('User not authenticated')
      );

      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
      const session = await api.createSession();

      await expect(api.connectSession(session.id)).rejects.toThrow(
        'Authentication required. Please log in to Backstage.'
      );
    });
  });

  describe('Performance and Resource Management', () => {
    test('should not leak memory during session lifecycle', async () => {
      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
      const initialMemory = process.memoryUsage().heapUsed;

      // Create and destroy many sessions
      for (let i = 0; i < 50; i++) {
        const session = await api.createSession();
        await api.destroySession(session.id);
      }

      // Force garbage collection if available
      if (global.gc) global.gc();

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryGrowth = finalMemory - initialMemory;

      // Allow for reasonable memory growth but detect leaks
      expect(memoryGrowth).toBeLessThan(5 * 1024 * 1024); // < 5MB
    });

    test('should handle high session creation rate', async () => {
      const api = new ClaudeFlowApi(mockConfigApi, mockIdentityApi);
      const startTime = Date.now();

      // Create many sessions rapidly
      const promises = Array(20)
        .fill(0)
        .map(() => api.createSession());

      const sessions = await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(sessions).toHaveLength(20);
      expect(duration).toBeLessThan(2000); // All within 2 seconds
    });

    test('should cleanup resources on component unmount', async () => {
      const apis = [
        [configApiRef, mockConfigApi],
        [identityApiRef, mockIdentityApi],
        [claudeFlowApiRef, new ClaudeFlowApi(mockConfigApi, mockIdentityApi)],
      ];

      const { unmount } = await renderInTestApp(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="test-session" />
        </TestApiProvider>
      );

      const cleanupSpy = jest.spyOn(WebSocketClient.prototype, 'disconnect');

      unmount();

      expect(cleanupSpy).toHaveBeenCalled();
    });
  });

  describe('Accessibility Integration', () => {
    test('should maintain accessibility in Backstage context', async () => {
      const apis = [
        [configApiRef, mockConfigApi],
        [identityApiRef, mockIdentityApi],
        [claudeFlowApiRef, new ClaudeFlowApi(mockConfigApi, mockIdentityApi)],
      ];

      await renderInTestApp(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="test-session" />
        </TestApiProvider>
      );

      // Check for proper ARIA attributes
      const terminal = screen.getByRole('group');
      expect(terminal).toHaveAttribute('aria-label');
      expect(terminal).toHaveAttribute('role', 'group');

      // Check keyboard navigation
      await userEvent.tab();
      expect(terminal).toHaveFocus();
    });

    test('should support Backstage keyboard shortcuts', async () => {
      const apis = [
        [configApiRef, mockConfigApi],
        [identityApiRef, mockIdentityApi],
        [claudeFlowApiRef, new ClaudeFlowApi(mockConfigApi, mockIdentityApi)],
      ];

      await renderInTestApp(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="test-session" />
        </TestApiProvider>
      );

      const terminal = screen.getByRole('group');

      // Test Backstage-specific shortcuts don't interfere
      await userEvent.keyboard('{Control>}{/}{Control}'); // Backstage search

      // Terminal should still be focused and functional
      expect(terminal).toHaveFocus();
    });
  });
});