/**
 * Performance Benchmark Test Suite
 * 
 * Tests application performance under various load conditions.
 * Includes rendering performance, memory usage, and WebSocket throughput tests.
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';
import '@testing-library/jest-dom';

import { createTestWrapper, mockWebSocket, createMockTerminal } from '../utils/test-helpers';

// Performance testing utilities
class PerformanceTracker {
  private metrics: { [key: string]: number[] } = {};

  startTiming(label: string): () => number {
    const start = performance.now();
    return () => {
      const duration = performance.now() - start;
      if (!this.metrics[label]) {
        this.metrics[label] = [];
      }
      this.metrics[label].push(duration);
      return duration;
    };
  }

  getAverageTime(label: string): number {
    const times = this.metrics[label] || [];
    return times.reduce((sum, time) => sum + time, 0) / times.length;
  }

  getPercentile(label: string, percentile: number): number {
    const times = (this.metrics[label] || []).sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * times.length) - 1;
    return times[index] || 0;
  }

  reset(): void {
    this.metrics = {};
  }
}

// Mock dependencies
const mockSocket = mockWebSocket();
jest.mock('socket.io-client', () => ({
  io: jest.fn(() => mockSocket),
}));

jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => createMockTerminal()),
}));

describe('Performance Benchmark Tests', () => {
  let performanceTracker: PerformanceTracker;
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    performanceTracker = new PerformanceTracker();
    user = userEvent.setup();
    jest.clearAllMocks();
    mockSocket.resetMocks();
  });

  describe('Component Rendering Performance', () => {
    it('should render main application under 100ms', async () => {
      const endTiming = performanceTracker.startTiming('initial-render');
      
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      await waitFor(() => {
        expect(screen.getByRole('main')).toBeInTheDocument();
      });
      
      const renderTime = endTiming();
      expect(renderTime).toBeLessThan(100);
    });

    it('should handle rapid tab creation efficiently', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      
      // Benchmark tab creation
      const tabCreationTimes: number[] = [];
      
      for (let i = 0; i < 10; i++) {
        const endTiming = performanceTracker.startTiming(`tab-creation-${i}`);
        
        await user.click(newTabButton);
        mockSocket.triggerEvent('session-created', { sessionId: `test-session-${i}` });
        
        await waitFor(() => {
          const tabs = screen.getAllByRole('tab');
          expect(tabs).toHaveLength(i + 2); // +1 for initial tab, +1 for new tab
        });
        
        tabCreationTimes.push(endTiming());
      }
      
      // Each tab creation should be under 50ms
      tabCreationTimes.forEach((time, index) => {
        expect(time).toBeLessThan(50);
      });
      
      // Performance shouldn't degrade significantly with more tabs
      const firstTabTime = tabCreationTimes[0];
      const lastTabTime = tabCreationTimes[tabCreationTimes.length - 1];
      expect(lastTabTime).toBeLessThan(firstTabTime * 2);
    });

    it('should maintain 60fps during animations', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Monitor frame rate during sidebar animation
      const frameRates: number[] = [];
      let frameCount = 0;
      let lastFrameTime = performance.now();
      
      const trackFrameRate = () => {
        frameCount++;
        const currentTime = performance.now();
        const deltaTime = currentTime - lastFrameTime;
        
        if (deltaTime >= 1000) {
          frameRates.push(frameCount);
          frameCount = 0;
          lastFrameTime = currentTime;
        }
        
        if (frameRates.length < 3) {
          requestAnimationFrame(trackFrameRate);
        }
      };
      
      requestAnimationFrame(trackFrameRate);
      
      // Trigger sidebar animation
      const monitoringToggle = screen.getByRole('button', { name: /monitoring/i });
      await user.click(monitoringToggle);
      
      // Wait for animation to complete and frame rate measurement
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      // Should maintain close to 60fps (allowing some variance)
      frameRates.forEach(fps => {
        expect(fps).toBeGreaterThan(50);
      });
    });
  });

  describe('Memory Performance', () => {
    beforeEach(() => {
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
    });

    it('should not leak memory with repeated tab operations', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
      
      // Perform many tab operations
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      
      for (let i = 0; i < 20; i++) {
        // Create tab
        await user.click(newTabButton);
        mockSocket.triggerEvent('session-created', { sessionId: `session-${i}` });
        
        // Close tab
        const closeButton = screen.getAllByRole('button', { name: /close/i })[0];
        await user.click(closeButton);
        mockSocket.triggerEvent('session-closed', { sessionId: `session-${i}` });
        
        // Wait for cleanup
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      
      // Force garbage collection
      if (global.gc) {
        global.gc();
      }
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be minimal (< 5MB)
      expect(memoryIncrease).toBeLessThan(5 * 1024 * 1024);
    });

    it('should handle large data streams efficiently', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
      
      // Create terminal
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);
      mockSocket.triggerEvent('session-created', { sessionId: 'memory-test' });
      
      // Stream large amounts of data
      const chunkSize = 1024; // 1KB chunks
      const totalChunks = 1000; // 1MB total
      
      const endTiming = performanceTracker.startTiming('large-data-stream');
      
      for (let i = 0; i < totalChunks; i++) {
        const chunk = 'A'.repeat(chunkSize);
        mockSocket.triggerEvent('data', { data: chunk });
        
        // Yield control occasionally
        if (i % 100 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }
      
      const streamTime = endTiming();
      
      // Should process 1MB in reasonable time (< 2 seconds)
      expect(streamTime).toBeLessThan(2000);
      
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable (< 10MB for 1MB data)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });

  describe('WebSocket Performance', () => {
    it('should handle high-frequency WebSocket messages', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const messagesPerSecond = 100;
      const testDuration = 2000; // 2 seconds
      const expectedMessages = (messagesPerSecond * testDuration) / 1000;
      
      let processedMessages = 0;
      const messageProcessingTimes: number[] = [];
      
      // Create terminal for message processing
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);
      mockSocket.triggerEvent('session-created', { sessionId: 'perf-test' });
      
      const startTest = performance.now();
      
      // Send high-frequency messages
      const sendMessage = () => {
        const messageStart = performance.now();
        
        mockSocket.triggerEvent('data', { 
          data: `Message ${processedMessages}\n`,
          timestamp: Date.now()
        });
        
        const messageEnd = performance.now();
        messageProcessingTimes.push(messageEnd - messageStart);
        processedMessages++;
        
        if (performance.now() - startTest < testDuration) {
          setTimeout(sendMessage, 1000 / messagesPerSecond);
        }
      };
      
      sendMessage();
      
      // Wait for test completion
      await waitFor(() => {
        expect(processedMessages).toBeGreaterThan(expectedMessages * 0.9);
      }, { timeout: testDuration + 1000 });
      
      // Calculate performance metrics
      const avgProcessingTime = messageProcessingTimes.reduce((sum, time) => sum + time, 0) / messageProcessingTimes.length;
      const p95ProcessingTime = performanceTracker.getPercentile('message-processing', 95);
      
      // Each message should process quickly (< 5ms average)
      expect(avgProcessingTime).toBeLessThan(5);
      
      // 95th percentile should be under 10ms
      expect(p95ProcessingTime).toBeLessThan(10);
      
      // Should process most messages (> 90% success rate)
      expect(processedMessages).toBeGreaterThan(expectedMessages * 0.9);
    });

    it('should maintain responsiveness under message bursts', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      // Create terminal
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      await user.click(newTabButton);
      mockSocket.triggerEvent('session-created', { sessionId: 'burst-test' });
      
      // Send burst of messages
      const burstSize = 50;
      const burstStart = performance.now();
      
      for (let i = 0; i < burstSize; i++) {
        mockSocket.triggerEvent('data', { data: `Burst message ${i}\n` });
      }
      
      const burstEnd = performance.now();
      const burstProcessingTime = burstEnd - burstStart;
      
      // Burst should be processed quickly (< 100ms for 50 messages)
      expect(burstProcessingTime).toBeLessThan(100);
      
      // UI should remain responsive - test by clicking button
      const responseStart = performance.now();
      const settingsButton = screen.getByRole('button', { name: /settings/i });
      await user.click(settingsButton);
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument();
      });
      
      const responseTime = performance.now() - responseStart;
      
      // UI response should be fast even after message burst (< 50ms)
      expect(responseTime).toBeLessThan(50);
    });
  });

  describe('Interaction Performance', () => {
    it('should respond to user input within 16ms (60fps)', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const inputResponseTimes: number[] = [];
      
      // Test various user interactions
      const interactions = [
        () => user.click(screen.getByRole('button', { name: /new tab/i })),
        () => user.click(screen.getByRole('button', { name: /monitoring/i })),
        () => user.keyboard('{Tab}'),
        () => user.keyboard('{Escape}'),
      ];
      
      for (const interaction of interactions) {
        const startTime = performance.now();
        
        await interaction();
        
        // Wait for DOM update
        await new Promise(resolve => requestAnimationFrame(resolve));
        
        const responseTime = performance.now() - startTime;
        inputResponseTimes.push(responseTime);
      }
      
      // All interactions should respond within 16ms (60fps budget)
      inputResponseTimes.forEach((time, index) => {
        expect(time).toBeLessThan(16);
      });
      
      const avgResponseTime = inputResponseTimes.reduce((sum, time) => sum + time, 0) / inputResponseTimes.length;
      expect(avgResponseTime).toBeLessThan(10);
    });

    it('should maintain performance with many concurrent terminals', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const terminalCount = 10;
      const newTabButton = screen.getByRole('button', { name: /new tab/i });
      
      // Create multiple terminals
      const createStart = performance.now();
      
      for (let i = 0; i < terminalCount; i++) {
        await user.click(newTabButton);
        mockSocket.triggerEvent('session-created', { sessionId: `perf-terminal-${i}` });
      }
      
      const createTime = performance.now() - createStart;
      
      // Should create all terminals in reasonable time (< 500ms)
      expect(createTime).toBeLessThan(500);
      
      // Test interaction with multiple terminals active
      const tabs = screen.getAllByRole('tab');
      const switchingStart = performance.now();
      
      // Switch between terminals
      for (let i = 0; i < Math.min(5, tabs.length); i++) {
        await user.click(tabs[i]);
        await new Promise(resolve => requestAnimationFrame(resolve));
      }
      
      const switchingTime = performance.now() - switchingStart;
      
      // Tab switching should remain fast (< 100ms for 5 switches)
      expect(switchingTime).toBeLessThan(100);
    });
  });

  describe('Long-running Performance', () => {
    it('should maintain performance over extended usage', async () => {
      const TestApp = await import('../../src/app/page').then(m => m.default);
      render(<TestApp />, { wrapper: createTestWrapper() });
      
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const performanceResults: number[] = [];
      
      // Simulate extended usage pattern
      for (let cycle = 0; cycle < 10; cycle++) {
        const cycleStart = performance.now();
        
        // Create terminal
        const newTabButton = screen.getByRole('button', { name: /new tab/i });
        await user.click(newTabButton);
        mockSocket.triggerEvent('session-created', { sessionId: `cycle-${cycle}` });
        
        // Send some data
        for (let i = 0; i < 10; i++) {
          mockSocket.triggerEvent('data', { data: `Cycle ${cycle} message ${i}\n` });
        }
        
        // Switch tabs
        const tabs = screen.getAllByRole('tab');
        if (tabs.length > 1) {
          await user.click(tabs[Math.floor(Math.random() * tabs.length)]);
        }
        
        // Close random tab
        const closeTabs = screen.getAllByRole('button', { name: /close/i });
        if (closeTabs.length > 1) {
          await user.click(closeTabs[0]);
        }
        
        const cycleTime = performance.now() - cycleStart;
        performanceResults.push(cycleTime);
        
        // Brief pause between cycles
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      // Performance should remain consistent (no significant degradation)
      const firstCycle = performanceResults[0];
      const lastCycle = performanceResults[performanceResults.length - 1];
      
      // Last cycle shouldn't be more than 2x slower than first cycle
      expect(lastCycle).toBeLessThan(firstCycle * 2);
      
      // Average performance should be reasonable
      const avgCycleTime = performanceResults.reduce((sum, time) => sum + time, 0) / performanceResults.length;
      expect(avgCycleTime).toBeLessThan(200);
      
      // Memory shouldn't grow excessively
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryGrowth = finalMemory - initialMemory;
      expect(memoryGrowth).toBeLessThan(20 * 1024 * 1024); // < 20MB growth
    });
  });
});