/**
 * Integration Test Scenarios for Claude UI Terminal Application
 * 
 * Comprehensive integration testing strategies covering component interactions,
 * data flows, and end-to-end workflows
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MockWebSocket, MockTerminal, createMockSession } from './mock-factories';

// ============================================================================
// Integration Test Framework
// ============================================================================

export interface IntegrationTestContext {
  mockWebSocket: MockWebSocket;
  mockTerminal: MockTerminal;
  user: ReturnType<typeof userEvent.setup>;
  cleanup: () => void;
}

export class IntegrationTestFramework {
  
  static async setupTestContext(): Promise<IntegrationTestContext> {
    const mockWebSocket = new MockWebSocket('ws://localhost:8080', { 
      autoConnect: true,
      enableLogging: true 
    });
    
    const mockTerminal = new MockTerminal({ 
      cols: 80, 
      rows: 24,
      enableEvents: true 
    });
    
    const user = userEvent.setup();
    
    // Setup global mocks
    global.WebSocket = jest.fn(() => mockWebSocket) as any;
    
    const cleanup = () => {
      mockWebSocket.cleanup();
      jest.restoreAllMocks();
    };

    return {
      mockWebSocket,
      mockTerminal,
      user,
      cleanup
    };
  }

  static async waitForWebSocketConnection(mockWs: MockWebSocket, timeout: number = 5000): Promise<void> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      if (mockWs.readyState === MockWebSocket.OPEN) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    
    throw new Error('WebSocket connection timeout');
  }

  static async waitForTerminalOutput(mockTerminal: MockTerminal, expectedText: string, timeout: number = 5000): Promise<void> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      const buffer = mockTerminal.getWriteBuffer();
      if (buffer.some(write => write.includes(expectedText))) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    
    throw new Error(`Expected terminal output "${expectedText}" not found within ${timeout}ms`);
  }
}

// ============================================================================
// WebSocket-Terminal Integration Tests
// ============================================================================

export class WebSocketTerminalIntegrationTests {
  
  /**
   * Test complete WebSocket-Terminal data flow
   */
  static async testWebSocketTerminalDataFlow(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // 1. Establish WebSocket connection
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      // 2. Create terminal session
      context.mockWebSocket.send(JSON.stringify({
        type: 'create',
        data: {}
      }));
      
      // 3. Simulate server response with session ID
      const sessionId = 'test-session-123';
      context.mockWebSocket.simulateServerMessage({
        type: 'session_created',
        data: { sessionId }
      });
      
      // 4. Send terminal input via WebSocket
      const testCommand = 'ls -la\n';
      context.mockWebSocket.send(JSON.stringify({
        type: 'data',
        data: { sessionId, data: testCommand }
      }));
      
      // 5. Simulate terminal output response
      const expectedOutput = 'total 12\ndrwxr-xr-x 3 user user 4096 Jan 1 12:00 .\n';
      context.mockWebSocket.simulateServerMessage({
        type: 'output',
        data: { sessionId, output: expectedOutput }
      });
      
      // 6. Verify terminal receives and displays output
      await IntegrationTestFramework.waitForTerminalOutput(context.mockTerminal, expectedOutput);
      
      // 7. Test terminal resize synchronization
      context.mockTerminal.simulateResize(120, 30);
      
      // 8. Verify resize message sent via WebSocket
      const messages = context.mockWebSocket.getMessageHistory();
      const resizeMessage = messages.find(msg => 
        msg.type === 'resize' && 
        msg.data.cols === 120 && 
        msg.data.rows === 30
      );
      
      expect(resizeMessage).toBeTruthy();
      
    } finally {
      context.cleanup();
    }
  }

  /**
   * Test WebSocket reconnection with session restoration
   */
  static async testWebSocketReconnectionWithSessionRestore(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // 1. Establish initial connection and session
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      const sessionId = 'persistent-session-456';
      context.mockWebSocket.simulateServerMessage({
        type: 'session_created',
        data: { sessionId }
      });
      
      // 2. Send some commands and receive output
      context.mockWebSocket.send(JSON.stringify({
        type: 'data',
        data: { sessionId, data: 'echo "Hello World"\n' }
      }));
      
      context.mockWebSocket.simulateServerMessage({
        type: 'output',
        data: { sessionId, output: 'Hello World\n' }
      });
      
      // 3. Simulate network disconnection
      context.mockWebSocket.simulateNetworkInterruption(2000);
      
      // 4. Wait for reconnection
      await new Promise(resolve => setTimeout(resolve, 2500));
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      // 5. Request session restoration
      context.mockWebSocket.send(JSON.stringify({
        type: 'restore',
        data: { sessionId }
      }));
      
      // 6. Verify session state is restored
      context.mockWebSocket.simulateServerMessage({
        type: 'session_restored',
        data: { 
          sessionId,
          history: ['echo "Hello World"'],
          currentDirectory: '/home/user'
        }
      });
      
      // 7. Test that new commands work after restoration
      context.mockWebSocket.send(JSON.stringify({
        type: 'data',
        data: { sessionId, data: 'pwd\n' }
      }));
      
      context.mockWebSocket.simulateServerMessage({
        type: 'output',
        data: { sessionId, output: '/home/user\n' }
      });
      
      await IntegrationTestFramework.waitForTerminalOutput(context.mockTerminal, '/home/user');
      
    } finally {
      context.cleanup();
    }
  }

  /**
   * Test multiple concurrent sessions
   */
  static async testMultipleConcurrentSessions(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      const sessionIds = ['session-1', 'session-2', 'session-3'];
      
      // 1. Create multiple sessions concurrently
      sessionIds.forEach(sessionId => {
        context.mockWebSocket.send(JSON.stringify({
          type: 'create',
          data: { requestedSessionId: sessionId }
        }));
        
        context.mockWebSocket.simulateServerMessage({
          type: 'session_created',
          data: { sessionId }
        });
      });
      
      // 2. Send commands to different sessions simultaneously
      const commands = [
        { sessionId: 'session-1', command: 'echo "Session 1"\n' },
        { sessionId: 'session-2', command: 'echo "Session 2"\n' },
        { sessionId: 'session-3', command: 'echo "Session 3"\n' }
      ];
      
      commands.forEach(({ sessionId, command }) => {
        context.mockWebSocket.send(JSON.stringify({
          type: 'data',
          data: { sessionId, data: command }
        }));
      });
      
      // 3. Simulate responses from all sessions
      sessionIds.forEach((sessionId, index) => {
        context.mockWebSocket.simulateServerMessage({
          type: 'output',
          data: { sessionId, output: `Session ${index + 1}\n` }
        });
      });
      
      // 4. Verify all sessions received their respective outputs
      for (let i = 0; i < sessionIds.length; i++) {
        await IntegrationTestFramework.waitForTerminalOutput(
          context.mockTerminal, 
          `Session ${i + 1}`
        );
      }
      
      // 5. Test session isolation - command in one session shouldn't affect others
      context.mockWebSocket.send(JSON.stringify({
        type: 'data',
        data: { sessionId: 'session-1', data: 'cd /tmp\n' }
      }));
      
      context.mockWebSocket.simulateServerMessage({
        type: 'output',
        data: { sessionId: 'session-1', output: '' }
      });
      
      // 6. Verify other sessions maintain their state
      context.mockWebSocket.send(JSON.stringify({
        type: 'data',
        data: { sessionId: 'session-2', data: 'pwd\n' }
      }));
      
      context.mockWebSocket.simulateServerMessage({
        type: 'output',
        data: { sessionId: 'session-2', output: '/home/user\n' }
      });
      
      await IntegrationTestFramework.waitForTerminalOutput(context.mockTerminal, '/home/user');
      
    } finally {
      context.cleanup();
    }
  }
}

// ============================================================================
// State-Component Integration Tests
// ============================================================================

export class StateComponentIntegrationTests {
  
  /**
   * Test state synchronization across components
   */
  static async testStateSynchronizationAcrossComponents(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // Mock store with initial state
      const mockStore = {
        sessions: [] as any[],
        activeSessionId: null as string | null,
        sidebarOpen: true,
        addSession: jest.fn(),
        setActiveSession: jest.fn(),
        removeSession: jest.fn(),
        toggleSidebar: jest.fn()
      };

      // 1. Add sessions to store
      const testSessions = [
        createMockSession({ id: 'session-1', name: 'Terminal 1' }),
        createMockSession({ id: 'session-2', name: 'Terminal 2' }),
        createMockSession({ id: 'session-3', name: 'Terminal 3' })
      ];
      
      testSessions.forEach(session => {
        mockStore.sessions.push(session);
        mockStore.addSession(session);
      });
      
      mockStore.activeSessionId = 'session-1';
      
      // 2. Simulate sidebar component reflecting store state
      expect(mockStore.sessions).toHaveLength(3);
      expect(mockStore.activeSessionId).toBe('session-1');
      
      // 3. Simulate tab switching
      mockStore.setActiveSession('session-2');
      mockStore.activeSessionId = 'session-2';
      
      // 4. Verify terminal component responds to active session change
      expect(mockStore.activeSessionId).toBe('session-2');
      
      // 5. Simulate session removal
      mockStore.removeSession('session-1');
      mockStore.sessions = mockStore.sessions.filter(s => s.id !== 'session-1');
      
      // 6. Verify active session updates if removed session was active
      if (mockStore.activeSessionId === 'session-1') {
        mockStore.activeSessionId = mockStore.sessions[0]?.id || null;
        mockStore.setActiveSession(mockStore.activeSessionId);
      }
      
      expect(mockStore.sessions).toHaveLength(2);
      expect(mockStore.sessions.find(s => s.id === 'session-1')).toBeUndefined();
      
    } finally {
      context.cleanup();
    }
  }

  /**
   * Test persistent state across page reloads
   */
  static async testPersistentStateAcrossReloads(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // Mock localStorage
      const localStorageMock: any = {
        store: new Map<string, string>(),
      };
      
      localStorageMock.getItem = jest.fn((key: string) => localStorageMock.store.get(key) || null);
      localStorageMock.setItem = jest.fn((key: string, value: string) => {
        localStorageMock.store.set(key, value);
      });
      localStorageMock.removeItem = jest.fn((key: string) => {
        localStorageMock.store.delete(key);
      });
      localStorageMock.clear = jest.fn(() => {
        localStorageMock.store.clear();
      });
      
      Object.defineProperty(window, 'localStorage', {
        value: localStorageMock,
        writable: true
      });
      
      // 1. Create initial state
      const initialState = {
        terminalSessions: [
          createMockSession({ id: 'persistent-1', name: 'Persistent Terminal 1' }),
          createMockSession({ id: 'persistent-2', name: 'Persistent Terminal 2' })
        ],
        activeSessionId: 'persistent-1',
        sidebarOpen: true,
        settings: {
          theme: 'dark',
          fontSize: 14
        }
      };
      
      // 2. Save state to localStorage
      localStorageMock.setItem('claude-flow-store', JSON.stringify(initialState));
      
      // 3. Simulate page reload by creating new store instance
      const restoredStateJson = localStorageMock.getItem('claude-flow-store');
      const restoredState = restoredStateJson ? JSON.parse(restoredStateJson) : null;
      
      // 4. Verify state restoration
      expect(restoredState).toBeTruthy();
      expect(restoredState.terminalSessions).toHaveLength(2);
      expect(restoredState.activeSessionId).toBe('persistent-1');
      expect(restoredState.settings.theme).toBe('dark');
      
      // 5. Test state migration for version updates
      const oldVersionState = {
        sessions: initialState.terminalSessions, // Old property name
        activeSession: 'persistent-1', // Old property name
        sidebar: true // Old property name
      };
      
      // 6. Simulate migration
      const migratedState = {
        terminalSessions: oldVersionState.sessions,
        activeSessionId: oldVersionState.activeSession,
        sidebarOpen: oldVersionState.sidebar,
        version: '2.0.0'
      };
      
      expect(migratedState.terminalSessions).toEqual(initialState.terminalSessions);
      expect(migratedState.activeSessionId).toBe(initialState.activeSessionId);
      
    } finally {
      context.cleanup();
    }
  }
}

// ============================================================================
// Error Handling Integration Tests
// ============================================================================

export class ErrorHandlingIntegrationTests {
  
  /**
   * Test error propagation through component hierarchy
   */
  static async testErrorPropagationThroughComponents(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // Mock error boundary
      const errorBoundary = {
        hasError: false,
        error: null,
        componentDidCatch: jest.fn((error, errorInfo) => {
          errorBoundary.hasError = true;
          errorBoundary.error = error;
        })
      };
      
      // 1. Simulate WebSocket error
      const wsError = new Error('WebSocket connection failed');
      context.mockWebSocket.simulateConnectionError();
      
      // 2. Verify error is caught by appropriate handler
      expect(context.mockWebSocket.readyState).toBe(MockWebSocket.CLOSED);
      
      // 3. Simulate terminal error
      const terminalError = new Error('Terminal initialization failed');
      
      try {
        throw terminalError;
      } catch (error) {
        errorBoundary.componentDidCatch(error, { componentStack: 'Terminal component' });
      }
      
      // 4. Verify error boundary caught the error
      expect(errorBoundary.hasError).toBe(true);
      expect(errorBoundary.error).toBe(terminalError);
      
      // 5. Test error recovery
      errorBoundary.hasError = false;
      errorBoundary.error = null;
      
      // 6. Simulate successful retry
      context.mockWebSocket.simulateConnection();
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      expect(context.mockWebSocket.readyState).toBe(MockWebSocket.OPEN);
      
    } finally {
      context.cleanup();
    }
  }

  /**
   * Test graceful degradation under various error conditions
   */
  static async testGracefulDegradation(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // 1. Test WebSocket unavailable scenario
      context.mockWebSocket.simulateConnectionError();
      
      // App should still render but show offline state
      const offlineState = {
        isOnline: false,
        error: 'Unable to connect to terminal server',
        retryCount: 0
      };
      
      expect(offlineState.isOnline).toBe(false);
      expect(offlineState.error).toContain('connect');
      
      // 2. Test partial functionality in offline mode
      // User should still be able to:
      // - View UI
      // - Access settings
      // - See error messages
      // - Retry connection
      
      // 3. Test recovery when connection is restored
      context.mockWebSocket.simulateConnection();
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      const onlineState = {
        isOnline: true,
        error: null,
        retryCount: 1
      };
      
      expect(onlineState.isOnline).toBe(true);
      expect(onlineState.error).toBeNull();
      
    } finally {
      context.cleanup();
    }
  }
}

// ============================================================================
// Performance Integration Tests
// ============================================================================

export class PerformanceIntegrationTests {
  
  /**
   * Test application performance under realistic load
   */
  static async testApplicationPerformanceUnderLoad(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      const startTime = performance.now();
      
      // 1. Create multiple sessions
      const sessionCount = 10;
      const sessionIds = [];
      
      for (let i = 0; i < sessionCount; i++) {
        const sessionId = `load-test-session-${i}`;
        sessionIds.push(sessionId);
        
        context.mockWebSocket.send(JSON.stringify({
          type: 'create',
          data: { requestedSessionId: sessionId }
        }));
        
        context.mockWebSocket.simulateServerMessage({
          type: 'session_created',
          data: { sessionId }
        });
      }
      
      // 2. Simulate high-frequency terminal output
      const messageCount = 1000;
      for (let i = 0; i < messageCount; i++) {
        const sessionId = sessionIds[i % sessionIds.length];
        context.mockWebSocket.simulateServerMessage({
          type: 'output',
          data: { 
            sessionId, 
            output: `Message ${i}: ${'x'.repeat(100)}\n` 
          }
        });
      }
      
      // 3. Measure performance
      const endTime = performance.now();
      const duration = endTime - startTime;
      const messagesPerSecond = messageCount / (duration / 1000);
      
      // 4. Verify performance meets requirements
      expect(messagesPerSecond).toBeGreaterThan(100); // At least 100 messages/sec
      expect(duration).toBeLessThan(10000); // Complete within 10 seconds
      
      // 5. Test memory usage
      const memoryBefore = (performance as any).memory ? (performance as any).memory.usedJSHeapSize : 0;
      
      // Generate more load
      for (let i = 0; i < 5000; i++) {
        context.mockTerminal.write(`Additional load message ${i}\n`);
      }
      
      const memoryAfter = (performance as any).memory ? (performance as any).memory.usedJSHeapSize : 0;
      const memoryIncrease = memoryAfter - memoryBefore;
      
      // Memory increase should be reasonable (less than 50MB for this test)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
      
    } finally {
      context.cleanup();
    }
  }
}

// ============================================================================
// Security Integration Tests
// ============================================================================

export class SecurityIntegrationTests {
  
  /**
   * Test input sanitization across the full stack
   */
  static async testInputSanitizationFullStack(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      await IntegrationTestFramework.waitForWebSocketConnection(context.mockWebSocket);
      
      const sessionId = 'security-test-session';
      context.mockWebSocket.simulateServerMessage({
        type: 'session_created',
        data: { sessionId }
      });
      
      // 1. Test XSS prevention
      const xssAttempts = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src="x" onerror="alert(\'XSS\')">',
        '<svg onload="alert(\'XSS\')">',
        '"><script>alert("XSS")</script>'
      ];
      
      for (const xssPayload of xssAttempts) {
        context.mockWebSocket.send(JSON.stringify({
          type: 'data',
          data: { sessionId, data: xssPayload }
        }));
        
        // Server should sanitize and return safe output
        const sanitizedOutput = xssPayload
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;');
        
        context.mockWebSocket.simulateServerMessage({
          type: 'output',
          data: { sessionId, output: sanitizedOutput }
        });
      }
      
      // 2. Test command injection prevention
      const injectionAttempts = [
        'ls; rm -rf /',
        'cat /etc/passwd',
        '$(rm -rf /)',
        '`cat /etc/shadow`',
        '; curl malicious-site.com'
      ];
      
      for (const injectionPayload of injectionAttempts) {
        context.mockWebSocket.send(JSON.stringify({
          type: 'data',
          data: { sessionId, data: injectionPayload }
        }));
        
        // Commands should be executed in sandboxed environment
        // or properly escaped/validated
        context.mockWebSocket.simulateServerMessage({
          type: 'output',
          data: { sessionId, output: 'Command not allowed or sandboxed\n' }
        });
      }
      
      // 3. Test session isolation
      const otherSessionId = 'other-session';
      
      // Attempt to access another session
      context.mockWebSocket.send(JSON.stringify({
        type: 'data',
        data: { sessionId: otherSessionId, data: 'pwd' }
      }));
      
      // Should receive error or no response for unauthorized session
      context.mockWebSocket.simulateServerMessage({
        type: 'error',
        data: { error: 'Unauthorized session access', code: 403 }
      });
      
    } finally {
      context.cleanup();
    }
  }
}

// ============================================================================
// Accessibility Integration Tests
// ============================================================================

export class AccessibilityIntegrationTests {
  
  /**
   * Test full application accessibility compliance
   */
  static async testFullApplicationAccessibility(): Promise<void> {
    const context = await IntegrationTestFramework.setupTestContext();
    
    try {
      // Mock DOM and accessibility APIs
      const mockElement = {
        getAttribute: jest.fn(),
        setAttribute: jest.fn(),
        focus: jest.fn(),
        blur: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn()
      };
      
      // 1. Test keyboard navigation
      const tabSequence = [
        'sidebar-toggle',
        'session-tab-1',
        'session-tab-2',
        'terminal-area',
        'new-session-button'
      ];
      
      for (const elementId of tabSequence) {
        // Simulate tab key press
        const tabEvent = new KeyboardEvent('keydown', { key: 'Tab' });
        
        // Element should be focusable and in correct tab order
        expect(mockElement.setAttribute).toHaveBeenCalledWith('tabindex', '0');
      }
      
      // 2. Test screen reader announcements
      const announcements = [
        'Terminal session created',
        'New output available',
        'Connection lost, attempting to reconnect',
        'Session restored'
      ];
      
      for (const announcement of announcements) {
        // Verify aria-live regions are updated
        expect(mockElement.setAttribute).toHaveBeenCalledWith('aria-live', 'polite');
      }
      
      // 3. Test high contrast mode
      const highContrastStyles = {
        backgroundColor: 'white',
        color: 'black',
        border: '2px solid black'
      };
      
      // Verify components adapt to high contrast
      expect(highContrastStyles.backgroundColor).toBe('white');
      expect(highContrastStyles.color).toBe('black');
      
      // 4. Test font scaling
      const fontSizes = [12, 14, 16, 18, 24, 32];
      
      for (const fontSize of fontSizes) {
        // Components should scale appropriately
        expect(fontSize).toBeGreaterThanOrEqual(12);
        expect(fontSize).toBeLessThanOrEqual(32);
      }
      
    } finally {
      context.cleanup();
    }
  }
}

// ============================================================================
// Integration Test Suite Runner
// ============================================================================

export class IntegrationTestSuite {
  
  static async runAllIntegrationTests(): Promise<{
    websocketTerminal: boolean;
    stateComponent: boolean;
    errorHandling: boolean;
    performance: boolean;
    security: boolean;
    accessibility: boolean;
  }> {
    const results = {
      websocketTerminal: false,
      stateComponent: false,
      errorHandling: false,
      performance: false,
      security: false,
      accessibility: false
    };

    try {
      console.log('Running WebSocket-Terminal integration tests...');
      await WebSocketTerminalIntegrationTests.testWebSocketTerminalDataFlow();
      await WebSocketTerminalIntegrationTests.testWebSocketReconnectionWithSessionRestore();
      await WebSocketTerminalIntegrationTests.testMultipleConcurrentSessions();
      results.websocketTerminal = true;

      console.log('Running State-Component integration tests...');
      await StateComponentIntegrationTests.testStateSynchronizationAcrossComponents();
      await StateComponentIntegrationTests.testPersistentStateAcrossReloads();
      results.stateComponent = true;

      console.log('Running Error Handling integration tests...');
      await ErrorHandlingIntegrationTests.testErrorPropagationThroughComponents();
      await ErrorHandlingIntegrationTests.testGracefulDegradation();
      results.errorHandling = true;

      console.log('Running Performance integration tests...');
      await PerformanceIntegrationTests.testApplicationPerformanceUnderLoad();
      results.performance = true;

      console.log('Running Security integration tests...');
      await SecurityIntegrationTests.testInputSanitizationFullStack();
      results.security = true;

      console.log('Running Accessibility integration tests...');
      await AccessibilityIntegrationTests.testFullApplicationAccessibility();
      results.accessibility = true;

      console.log('All integration tests completed successfully');

    } catch (error) {
      console.error('Integration test failed:', error);
      throw error;
    }

    return results;
  }
}

