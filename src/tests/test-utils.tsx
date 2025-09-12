/**
 * Test Utilities
 * Provides common testing utilities and helpers for all tests
 */
import React from 'react';
import { render, RenderOptions, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Re-export everything from testing library
export * from '@testing-library/react';
import '@testing-library/jest-dom';
export { userEvent };

// Mock data creators
export const createMockSession = (id: string = 'test-session') => ({
  id,
  title: `Session ${id}`,
  isActive: false,
  createdAt: new Date().toISOString(),
  status: 'connected' as const,
});

export const createMockTerminalSession = (overrides = {}) => ({
  id: 'terminal-1',
  title: 'Terminal Session',
  status: 'connected',
  createdAt: new Date().toISOString(),
  lastActivity: new Date().toISOString(),
  ...overrides,
});

export const createMockWebSocketMessage = (type: string = 'test', data: any = {}) => ({
  type,
  data,
  timestamp: new Date().toISOString(),
});

export const mockSystemMetrics = {
  cpu: 45.2,
  memory: 67.8,
  disk: 23.4,
  network: {
    upload: 1024,
    download: 2048,
  },
};

export const mockAgentStatus = {
  id: 'agent-1',
  name: 'Test Agent',
  status: 'active',
  lastSeen: new Date().toISOString(),
  tasks: 3,
};

// Utility functions
export const wait = (ms: number = 0) => new Promise(resolve => setTimeout(resolve, ms));

export const mockLocalStorage = () => {
  const storage: Record<string, string> = {};
  
  return {
    getItem: jest.fn((key: string) => storage[key] || null),
    setItem: jest.fn((key: string, value: string) => {
      storage[key] = value;
    }),
    removeItem: jest.fn((key: string) => {
      delete storage[key];
    }),
    clear: jest.fn(() => {
      Object.keys(storage).forEach(key => delete storage[key]);
    }),
  };
};

export const mockSessionStorage = () => {
  const storage: Record<string, string> = {};
  
  return {
    getItem: jest.fn((key: string) => storage[key] || null),
    setItem: jest.fn((key: string, value: string) => {
      storage[key] = value;
    }),
    removeItem: jest.fn((key: string) => {
      delete storage[key];
    }),
    clear: jest.fn(() => {
      Object.keys(storage).forEach(key => delete storage[key]);
    }),
  };
};

// Mock providers for testing components
const MockProviders: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <div data-testid="mock-provider">{children}</div>;
};

// Custom render function with providers
const customRender = (
  ui: React.ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) => render(ui, { wrapper: MockProviders, ...options });

// Re-export custom render
export { customRender as render };

// WebSocket mock utilities
export const createMockWebSocket = () => ({
  connect: jest.fn(),
  disconnect: jest.fn(),
  send: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  connected: false,
  connecting: false,
});

// DOM testing utilities
export const getByDataTestId = (testId: string) => screen.getByTestId(testId);
export const queryByDataTestId = (testId: string) => screen.queryByTestId(testId);

// Async utilities
export const waitForElement = async (callback: () => HTMLElement) => {
  return waitFor(callback);
};

export const triggerResize = (width: number = 1024, height: number = 768) => {
  Object.defineProperty(window, 'innerWidth', { value: width, writable: true });
  Object.defineProperty(window, 'innerHeight', { value: height, writable: true });
  window.dispatchEvent(new Event('resize'));
};

// Form testing utilities
export const fillForm = async (fields: Record<string, string>) => {
  const user = userEvent.setup();
  
  for (const [fieldName, value] of Object.entries(fields)) {
    const field = screen.getByLabelText(new RegExp(fieldName, 'i')) || 
                  screen.getByPlaceholderText(new RegExp(fieldName, 'i')) ||
                  screen.getByDisplayValue('');
    
    if (field) {
      await user.clear(field);
      await user.type(field, value);
    }
  }
};

// Component testing utilities
export const expectElementToBeVisible = (element: HTMLElement) => {
  expect(element).toBeInTheDocument();
  expect(element).toBeVisible();
};

export const expectElementToHaveClasses = (element: HTMLElement, classes: string[]) => {
  classes.forEach(className => {
    expect(element).toHaveClass(className);
  });
};