import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for Monitoring components and panels
 * Handles performance monitoring, agents panel, memory usage, and commands tracking
 */
export class MonitoringPage extends BasePage {
  readonly monitoringSidebar: Locator;
  readonly agentsPanel: Locator;
  readonly memoryPanel: Locator;
  readonly commandsPanel: Locator;
  readonly promptPanel: Locator;
  readonly performanceMonitor: Locator;

  // Agent-related elements
  readonly agentsList: Locator;
  readonly agentStatus: Locator;
  readonly agentMetrics: Locator;

  // Memory monitoring
  readonly memoryUsage: Locator;
  readonly memoryChart: Locator;
  readonly memoryStats: Locator;

  // Commands monitoring
  readonly commandHistory: Locator;
  readonly commandMetrics: Locator;
  readonly commandFilters: Locator;

  // Performance metrics
  readonly cpuUsage: Locator;
  readonly networkStats: Locator;
  readonly responseTime: Locator;

  constructor(page: Page) {
    super(page);

    // Main monitoring components
    this.monitoringSidebar = page.locator('[data-testid="monitoring-sidebar"], .monitoring-sidebar');
    this.agentsPanel = page.locator('[data-testid="agents-panel"], .agents-panel');
    this.memoryPanel = page.locator('[data-testid="memory-panel"], .memory-panel');
    this.commandsPanel = page.locator('[data-testid="commands-panel"], .commands-panel');
    this.promptPanel = page.locator('[data-testid="prompt-panel"], .prompt-panel');
    this.performanceMonitor = page.locator('[data-testid="performance-monitor"], .performance-monitor');

    // Agent monitoring
    this.agentsList = page.locator('[data-testid="agents-list"] .agent-item, .agents-list .agent');
    this.agentStatus = page.locator('.agent-status, [data-testid="agent-status"]');
    this.agentMetrics = page.locator('.agent-metrics, [data-testid="agent-metrics"]');

    // Memory monitoring
    this.memoryUsage = page.locator('[data-testid="memory-usage"], .memory-usage');
    this.memoryChart = page.locator('[data-testid="memory-chart"], .memory-chart');
    this.memoryStats = page.locator('[data-testid="memory-stats"], .memory-stats');

    // Commands monitoring
    this.commandHistory = page.locator('[data-testid="command-history"], .command-history');
    this.commandMetrics = page.locator('[data-testid="command-metrics"], .command-metrics');
    this.commandFilters = page.locator('[data-testid="command-filters"], .command-filters');

    // Performance metrics
    this.cpuUsage = page.locator('[data-testid="cpu-usage"], .cpu-usage');
    this.networkStats = page.locator('[data-testid="network-stats"], .network-stats');
    this.responseTime = page.locator('[data-testid="response-time"], .response-time');
  }

  /**
   * Wait for monitoring components to load
   */
  async waitForMonitoringReady(): Promise<void> {
    try {
      await this.performanceMonitor.waitFor({ state: 'visible', timeout: 10000 });
      console.log('✅ Performance monitor ready');
    } catch (error) {
      console.warn('Performance monitor not found, continuing...');
    }

    await this.waitForNetworkIdle();
  }

  /**
   * Get agents panel information
   */
  async getAgentsInfo(): Promise<{ count: number; active: number; statuses: string[] }> {
    await this.waitForMonitoringReady();

    try {
      const agentElements = await this.agentsList.all();
      const count = agentElements.length;

      let active = 0;
      const statuses: string[] = [];

      for (const agent of agentElements) {
        const status = await agent.locator('.status, [data-testid="status"]').textContent();
        if (status) {
          statuses.push(status.trim());
          if (status.toLowerCase().includes('active') || status.toLowerCase().includes('running')) {
            active++;
          }
        }
      }

      return { count, active, statuses };
    } catch (error) {
      console.warn('Could not get agents info:', error);
      return { count: 0, active: 0, statuses: [] };
    }
  }

  /**
   * Get memory usage statistics
   */
  async getMemoryStats(): Promise<{ used: number; total: number; percentage: number } | null> {
    await this.waitForMonitoringReady();

    try {
      const memoryText = await this.memoryUsage.textContent();
      if (!memoryText) return null;

      // Parse memory text (format: "Used: 123 MB / Total: 456 MB (27%)")
      const usedMatch = memoryText.match(/Used:\s*(\d+(?:\.\d+)?)\s*MB/i);
      const totalMatch = memoryText.match(/Total:\s*(\d+(?:\.\d+)?)\s*MB/i);
      const percentMatch = memoryText.match(/\((\d+(?:\.\d+)?)%\)/);

      if (usedMatch && totalMatch && percentMatch) {
        return {
          used: parseFloat(usedMatch[1]),
          total: parseFloat(totalMatch[1]),
          percentage: parseFloat(percentMatch[1])
        };
      }
    } catch (error) {
      console.warn('Could not parse memory stats:', error);
    }

    return null;
  }

  /**
   * Get command history
   */
  async getCommandHistory(): Promise<Array<{ command: string; timestamp: string; status: string }>> {
    await this.waitForMonitoringReady();

    try {
      const commandElements = await this.commandHistory.locator('.command-item, [data-testid="command-item"]').all();
      const commands: Array<{ command: string; timestamp: string; status: string }> = [];

      for (const element of commandElements) {
        const command = await element.locator('.command-text, [data-testid="command-text"]').textContent() || '';
        const timestamp = await element.locator('.timestamp, [data-testid="timestamp"]').textContent() || '';
        const status = await element.locator('.status, [data-testid="status"]').textContent() || '';

        commands.push({
          command: command.trim(),
          timestamp: timestamp.trim(),
          status: status.trim()
        });
      }

      return commands;
    } catch (error) {
      console.warn('Could not get command history:', error);
      return [];
    }
  }

  /**
   * Get performance metrics
   */
  async getPerformanceMetrics(): Promise<{
    cpu: number;
    memory: number;
    network: { sent: number; received: number };
    responseTime: number;
  } | null> {
    await this.waitForMonitoringReady();

    try {
      // Get CPU usage
      const cpuText = await this.cpuUsage.textContent();
      const cpuMatch = cpuText?.match(/(\d+(?:\.\d+)?)%/);
      const cpu = cpuMatch ? parseFloat(cpuMatch[1]) : 0;

      // Get memory percentage
      const memoryStats = await this.getMemoryStats();
      const memory = memoryStats?.percentage || 0;

      // Get network stats
      const networkText = await this.networkStats.textContent();
      const sentMatch = networkText?.match(/Sent:\s*(\d+(?:\.\d+)?)/);
      const receivedMatch = networkText?.match(/Received:\s*(\d+(?:\.\d+)?)/);
      const network = {
        sent: sentMatch ? parseFloat(sentMatch[1]) : 0,
        received: receivedMatch ? parseFloat(receivedMatch[1]) : 0
      };

      // Get response time
      const responseText = await this.responseTime.textContent();
      const responseMatch = responseText?.match(/(\d+(?:\.\d+)?)\s*ms/);
      const responseTime = responseMatch ? parseFloat(responseMatch[1]) : 0;

      return { cpu, memory, network, responseTime };
    } catch (error) {
      console.warn('Could not get performance metrics:', error);
      return null;
    }
  }

  /**
   * Filter command history
   */
  async filterCommands(filter: 'all' | 'success' | 'error' | 'running'): Promise<void> {
    await this.waitForMonitoringReady();

    try {
      const filterButton = this.commandFilters.locator(`button[data-filter="${filter}"]`);
      await filterButton.click();

      // Wait for filter to apply
      await this.page.waitForTimeout(1000);

      console.log(`✅ Commands filtered by: ${filter}`);
    } catch (error) {
      console.warn(`Could not apply filter ${filter}:`, error);
    }
  }

  /**
   * Clear command history
   */
  async clearCommandHistory(): Promise<void> {
    try {
      const clearButton = this.commandsPanel.locator('button', { hasText: 'Clear' });
      await clearButton.click();

      // Wait for confirmation or immediate clear
      await this.page.waitForTimeout(1000);

      console.log('✅ Command history cleared');
    } catch (error) {
      console.warn('Could not clear command history:', error);
    }
  }

  /**
   * Monitor performance for a duration
   */
  async monitorPerformance(durationMs: number): Promise<Array<{
    timestamp: number;
    cpu: number;
    memory: number;
    responseTime: number;
  }>> {
    const metrics: Array<any> = [];
    const interval = 1000; // Sample every second
    const samples = Math.floor(durationMs / interval);

    console.log(`📊 Monitoring performance for ${durationMs}ms (${samples} samples)`);

    for (let i = 0; i < samples; i++) {
      const timestamp = Date.now();
      const perfMetrics = await this.getPerformanceMetrics();

      if (perfMetrics) {
        metrics.push({
          timestamp,
          cpu: perfMetrics.cpu,
          memory: perfMetrics.memory,
          responseTime: perfMetrics.responseTime
        });
      }

      // Wait for next sample
      if (i < samples - 1) {
        await this.page.waitForTimeout(interval);
      }
    }

    console.log(`✅ Performance monitoring complete. Collected ${metrics.length} samples`);
    return metrics;
  }

  /**
   * Check for performance alerts or warnings
   */
  async checkPerformanceAlerts(): Promise<Array<{ type: string; message: string; severity: string }>> {
    const alerts: Array<{ type: string; message: string; severity: string }> = [];

    try {
      const alertElements = await this.performanceMonitor.locator('.alert, .warning, .error').all();

      for (const element of alertElements) {
        const message = await element.textContent() || '';
        const classList = await element.getAttribute('class') || '';

        let severity = 'info';
        let type = 'general';

        if (classList.includes('error') || classList.includes('text-red')) {
          severity = 'error';
        } else if (classList.includes('warning') || classList.includes('text-yellow')) {
          severity = 'warning';
        }

        if (message.toLowerCase().includes('memory')) {
          type = 'memory';
        } else if (message.toLowerCase().includes('cpu')) {
          type = 'cpu';
        } else if (message.toLowerCase().includes('network')) {
          type = 'network';
        }

        alerts.push({
          type,
          message: message.trim(),
          severity
        });
      }
    } catch (error) {
      console.warn('Could not check performance alerts:', error);
    }

    return alerts;
  }

  /**
   * Get agent-specific metrics
   */
  async getAgentMetrics(agentId?: string): Promise<{
    [agentId: string]: {
      status: string;
      tasks: number;
      performance: number;
      lastActivity: string;
    }
  }> {
    const agentMetrics: any = {};

    try {
      const agentElements = await this.agentsList.all();

      for (const agent of agentElements) {
        const id = await agent.getAttribute('data-agent-id') || `agent-${Math.random()}`;
        const status = await agent.locator('.status').textContent() || 'unknown';
        const tasksText = await agent.locator('.tasks-count').textContent() || '0';
        const tasks = parseInt(tasksText.match(/\d+/)?.[0] || '0');
        const perfText = await agent.locator('.performance').textContent() || '0%';
        const performance = parseFloat(perfText.match(/\d+/)?.[0] || '0');
        const lastActivity = await agent.locator('.last-activity').textContent() || '';

        agentMetrics[id] = {
          status: status.trim(),
          tasks,
          performance,
          lastActivity: lastActivity.trim()
        };

        // If specific agent requested, return only that one
        if (agentId && id === agentId) {
          return { [id]: agentMetrics[id] };
        }
      }
    } catch (error) {
      console.warn('Could not get agent metrics:', error);
    }

    return agentMetrics;
  }

  /**
   * Export monitoring data
   */
  async exportMonitoringData(format: 'json' | 'csv' = 'json'): Promise<any> {
    try {
      const exportButton = this.performanceMonitor.locator(`button[data-export="${format}"]`);
      await exportButton.click();

      // Wait for download or data to be available
      await this.page.waitForTimeout(2000);

      console.log(`✅ Monitoring data exported in ${format} format`);

      // Return the monitoring data object
      return {
        timestamp: Date.now(),
        agents: await this.getAgentsInfo(),
        memory: await this.getMemoryStats(),
        performance: await this.getPerformanceMetrics(),
        commands: await this.getCommandHistory(),
        alerts: await this.checkPerformanceAlerts()
      };
    } catch (error) {
      console.warn(`Could not export monitoring data as ${format}:`, error);
      return null;
    }
  }

  /**
   * Refresh monitoring data
   */
  async refreshMonitoringData(): Promise<void> {
    try {
      const refreshButton = this.performanceMonitor.locator('button[title="Refresh"], button', { hasText: 'Refresh' });
      await refreshButton.click();

      // Wait for refresh to complete
      await this.page.waitForTimeout(2000);
      await this.waitForNetworkIdle();

      console.log('✅ Monitoring data refreshed');
    } catch (error) {
      console.warn('Could not refresh monitoring data:', error);
    }
  }
}