/**
 * Test Utilities
 * Provides common testing utilities and helpers
 */
import React from 'react';
import { render, RenderOptions } from '@testing-library/react';

// Re-export everything from testing library
export * from '@testing-library/react';
export * from '@testing-library/jest-dom';

// Mock providers for testing
const MockProviders: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <>{children}</>;
};

// Custom render function with providers
const customRender = (
  ui: React.ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) => render(ui, { wrapper: MockProviders, ...options });

// Re-export custom render
export { customRender as render };

// Test utilities from global setup
export const {
  createMockTerminalSession,
  createMockWebSocketMessage,
  mockSystemMetrics,
  mockAgentStatus,
  wait,
  mockLocalStorage,
  mockSessionStorage,
} = global.testUtils;