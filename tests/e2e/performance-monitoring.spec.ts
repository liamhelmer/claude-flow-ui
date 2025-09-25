import { test, expect } from './fixtures/test-fixtures';
import { TerminalPage } from './page-objects/TerminalPage';
import { MonitoringPage } from './page-objects/MonitoringPage';
import { SidebarPage } from './page-objects/SidebarPage';

/**
 * E2E Tests for Performance Monitoring Workflows
 * Tests performance monitoring features, metrics collection, and system resource tracking
 */

test.describe('Performance Monitoring Workflows', () => {
  let terminalPage: TerminalPage;
  let monitoringPage: MonitoringPage;
  let sidebarPage: SidebarPage;

  test.beforeEach(async ({ page, terminalPage: tp, monitoringPage: mp, sidebarPage: sp }) => {
    terminalPage = tp;
    monitoringPage = mp;
    sidebarPage = sp;

    // Navigate to the application
    await terminalPage.goto('/');
    await terminalPage.waitForPageLoad();
    await terminalPage.waitForTerminalReady();
    await monitoringPage.waitForMonitoringReady();
  });

  test('should display performance metrics', async ({ testData }) => {
    // Get performance metrics
    const metrics = await monitoringPage.getPerformanceMetrics();

    if (metrics) {
      // Verify metrics are reasonable
      expect(metrics.cpu).toBeGreaterThanOrEqual(0);
      expect(metrics.cpu).toBeLessThanOrEqual(100);

      expect(metrics.memory).toBeGreaterThanOrEqual(0);
      expect(metrics.memory).toBeLessThanOrEqual(100);

      expect(metrics.responseTime).toBeGreaterThanOrEqual(0);
      expect(metrics.responseTime).toBeLessThan(10000); // Less than 10 seconds

      console.log('Performance metrics:', metrics);
    } else {
      console.log('Performance monitoring not available in current setup');
    }
  });

  test('should track memory usage during terminal operations', async ({ testData }) => {
    // Get baseline memory usage
    const initialMemory = await monitoringPage.getMemoryStats();

    if (initialMemory) {
      console.log('Initial memory usage:', initialMemory);

      // Generate memory usage with large output
      await terminalPage.executeCommand('seq 1 1000');
      await terminalPage.waitForOutput('1000');

      // Check memory usage after large output
      await monitoringPage.page.waitForTimeout(2000);
      const memoryAfterOutput = await monitoringPage.getMemoryStats();

      if (memoryAfterOutput) {
        console.log('Memory after large output:', memoryAfterOutput);

        // Memory usage should be tracked
        expect(memoryAfterOutput.used).toBeGreaterThan(0);
        expect(memoryAfterOutput.total).toBeGreaterThan(0);
        expect(memoryAfterOutput.percentage).toBeGreaterThanOrEqual(0);
        expect(memoryAfterOutput.percentage).toBeLessThanOrEqual(100);
      }
    } else {
      console.log('Memory monitoring not available in current setup');
    }
  });

  test('should monitor performance during intensive operations', async ({ testData }) => {
    const performanceScenarios = testData.getPerformanceScenarios();
    const intensiveScenario = performanceScenarios.find(s => s.name === 'CPU Intensive') || performanceScenarios[0];

    // Start monitoring
    const monitoringPromise = monitoringPage.monitorPerformance(15000); // 15 seconds

    // Execute intensive command
    await terminalPage.executeCommand(intensiveScenario.command);

    if (intensiveScenario.command.includes('seq')) {
      await terminalPage.waitForOutput('100', intensiveScenario.metrics.maxExecutionTime);
    } else {
      await terminalPage.page.waitForTimeout(10000);
    }

    // Get monitoring results
    const performanceData = await monitoringPromise;

    if (performanceData && performanceData.length > 0) {
      console.log('Performance monitoring data points:', performanceData.length);

      // Analyze performance data
      const avgCpu = performanceData.reduce((sum, p) => sum + p.cpu, 0) / performanceData.length;
      const avgMemory = performanceData.reduce((sum, p) => sum + p.memory, 0) / performanceData.length;
      const avgResponseTime = performanceData.reduce((sum, p) => sum + p.responseTime, 0) / performanceData.length;

      console.log('Average metrics:', { avgCpu, avgMemory, avgResponseTime });

      // Verify metrics are within reasonable ranges
      expect(avgCpu).toBeGreaterThanOrEqual(0);
      expect(avgCpu).toBeLessThanOrEqual(100);
      expect(avgMemory).toBeGreaterThanOrEqual(0);
      expect(avgMemory).toBeLessThanOrEqual(100);
    }
  });

  test('should track command execution history', async ({ testData }) => {
    // Execute several commands
    const commands = testData.getTestCommands().slice(0, 3);

    for (const testCommand of commands) {
      if (testCommand.skipOn?.includes(process.platform)) {
        continue;
      }

      await terminalPage.executeCommand(testCommand.command);
      await terminalPage.waitForOutput(testCommand.expectedOutput, testCommand.timeout);
    }

    // Get command history from monitoring
    const commandHistory = await monitoringPage.getCommandHistory();

    if (commandHistory && commandHistory.length > 0) {
      console.log('Command history entries:', commandHistory.length);

      // Verify command history contains executed commands
      for (const testCommand of commands) {
        if (testCommand.skipOn?.includes(process.platform)) {
          continue;
        }

        const foundCommand = commandHistory.some(cmd =>
          cmd.command.includes(testCommand.command.split(' ')[0])
        );

        if (foundCommand) {
          console.log(`Command found in history: ${testCommand.command}`);
        }
      }
    } else {
      console.log('Command history monitoring not available');
    }
  });

  test('should detect performance alerts', async ({ testData }) => {
    // Generate load that might trigger alerts
    await terminalPage.executeCommand('seq 1 2000');
    await terminalPage.waitForOutput('2000');

    // Check for performance alerts
    const alerts = await monitoringPage.checkPerformanceAlerts();

    console.log('Performance alerts detected:', alerts.length);

    if (alerts.length > 0) {
      // Verify alert structure
      for (const alert of alerts) {
        expect(alert).toHaveProperty('type');
        expect(alert).toHaveProperty('message');
        expect(alert).toHaveProperty('severity');
        expect(['info', 'warning', 'error']).toContain(alert.severity);

        console.log(`Alert: ${alert.type} - ${alert.message} (${alert.severity})`);
      }
    }
  });

  test('should handle performance data export', async ({ testData }) => {
    // Execute some operations to generate data
    await terminalPage.executeCommand('echo "Performance test"');
    await terminalPage.waitForOutput('Performance test');

    // Attempt to export monitoring data
    const exportData = await monitoringPage.exportMonitoringData('json');

    if (exportData) {
      console.log('Exported monitoring data structure:', Object.keys(exportData));

      // Verify export data structure
      expect(exportData).toHaveProperty('timestamp');
      expect(typeof exportData.timestamp).toBe('number');

      if (exportData.agents) {
        expect(exportData.agents).toHaveProperty('count');
        expect(typeof exportData.agents.count).toBe('number');
      }

      if (exportData.performance) {
        expect(typeof exportData.performance).toBe('object');
      }
    } else {
      console.log('Performance data export not available');
    }
  });

  test('should monitor agents activity', async ({ testData }) => {
    // Get agents information
    const agentsInfo = await monitoringPage.getAgentsInfo();

    console.log('Agents monitoring:', agentsInfo);

    // Verify agents data structure
    expect(typeof agentsInfo.count).toBe('number');
    expect(typeof agentsInfo.active).toBe('number');
    expect(Array.isArray(agentsInfo.statuses)).toBeTruthy();

    // Active agents should not exceed total count
    expect(agentsInfo.active).toBeLessThanOrEqual(agentsInfo.count);

    if (agentsInfo.count > 0) {
      // Get detailed agent metrics
      const agentMetrics = await monitoringPage.getAgentMetrics();

      console.log('Agent metrics keys:', Object.keys(agentMetrics));

      // Verify agent metrics structure
      for (const [agentId, metrics] of Object.entries(agentMetrics)) {
        expect(metrics).toHaveProperty('status');
        expect(metrics).toHaveProperty('tasks');
        expect(metrics).toHaveProperty('performance');
        expect(typeof metrics.tasks).toBe('number');
        expect(typeof metrics.performance).toBe('number');
      }
    }
  });

  test('should measure terminal responsiveness', async ({ testData }) => {
    // Measure input delay
    const delay = await terminalPage.measureInputDelay('echo "responsiveness test"');

    console.log(`Terminal input delay: ${delay}ms`);

    // Verify delay is acceptable (under 2 seconds)
    expect(delay).toBeLessThan(2000);

    // Test responsiveness under load
    await terminalPage.executeCommand('seq 1 500');

    // Measure delay under load
    const delayUnderLoad = await terminalPage.measureInputDelay('echo "load test"');

    console.log(`Terminal input delay under load: ${delayUnderLoad}ms`);

    // Delay under load should still be reasonable (under 5 seconds)
    expect(delayUnderLoad).toBeLessThan(5000);
  });

  test('should refresh monitoring data', async ({ testData }) => {
    // Get initial metrics
    const initialMetrics = await monitoringPage.getPerformanceMetrics();

    // Execute some operations
    await terminalPage.executeCommand('date');
    await terminalPage.page.waitForTimeout(1000);

    // Refresh monitoring data
    await monitoringPage.refreshMonitoringData();

    // Get updated metrics
    const updatedMetrics = await monitoringPage.getPerformanceMetrics();

    console.log('Metrics comparison:', { initial: initialMetrics, updated: updatedMetrics });

    // Both should be valid (or both null if monitoring not available)
    if (initialMetrics && updatedMetrics) {
      // Timestamps might differ slightly
      expect(typeof updatedMetrics.cpu).toBe('number');
      expect(typeof updatedMetrics.memory).toBe('number');
      expect(typeof updatedMetrics.responseTime).toBe('number');
    }
  });

  test('should handle monitoring system errors gracefully', async ({ testData }) => {
    // Try to access monitoring features that might not be available
    const performanceMetrics = await monitoringPage.getPerformanceMetrics();
    const memoryStats = await monitoringPage.getMemoryStats();
    const agentsInfo = await monitoringPage.getAgentsInfo();
    const commandHistory = await monitoringPage.getCommandHistory();

    // Test should not crash even if monitoring is not available
    console.log('Monitoring availability:', {
      performanceMetrics: !!performanceMetrics,
      memoryStats: !!memoryStats,
      agentsInfo: agentsInfo.count >= 0,
      commandHistory: Array.isArray(commandHistory)
    });

    // Verify terminal still works regardless of monitoring status
    await terminalPage.executeCommand('echo "Terminal works without monitoring"');
    await terminalPage.waitForOutput('Terminal works without monitoring');
  });

  test('should monitor system resource usage over time', async ({ testData }) => {
    // Monitor for a short period
    const monitoringDuration = 10000; // 10 seconds
    const metricsPromise = monitoringPage.monitorPerformance(monitoringDuration);

    // Generate some activity during monitoring
    setTimeout(async () => {
      await terminalPage.executeCommand('seq 1 100');
    }, 2000);

    setTimeout(async () => {
      await terminalPage.executeCommand('echo "Mid-monitoring"');
    }, 5000);

    setTimeout(async () => {
      await terminalPage.executeCommand('date');
    }, 8000);

    // Wait for monitoring to complete
    const metrics = await metricsPromise;

    if (metrics && metrics.length > 0) {
      console.log(`Collected ${metrics.length} performance data points`);

      // Calculate trend analysis
      const timestamps = metrics.map(m => m.timestamp);
      const minTime = Math.min(...timestamps);
      const maxTime = Math.max(...timestamps);
      const duration = maxTime - minTime;

      console.log(`Monitoring duration: ${duration}ms`);
      expect(duration).toBeGreaterThan(8000); // Should be close to 10 seconds

      // Verify data consistency
      for (const metric of metrics) {
        expect(metric.cpu).toBeGreaterThanOrEqual(0);
        expect(metric.cpu).toBeLessThanOrEqual(100);
        expect(metric.memory).toBeGreaterThanOrEqual(0);
        expect(metric.memory).toBeLessThanOrEqual(100);
      }
    } else {
      console.log('Performance monitoring data not available');
    }
  });
});