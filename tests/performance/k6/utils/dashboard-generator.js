#!/usr/bin/env node

/**
 * Performance Dashboard Generator
 *
 * Generates real-time performance monitoring dashboards from k6 test results:
 * - HTML performance dashboards with live metrics
 * - Historical trend analysis
 * - SLA compliance reporting
 * - Performance alerts and recommendations
 */

const fs = require('fs');
const path = require('path');

class PerformanceDashboardGenerator {
  constructor(options = {}) {
    this.options = {
      outputDir: options.outputDir || path.join(__dirname, '..', 'reports', 'dashboards'),
      templateDir: options.templateDir || path.join(__dirname, '..', 'templates'),
      refreshInterval: options.refreshInterval || 30000, // 30 seconds
      retentionDays: options.retentionDays || 30,
      ...options,
    };

    // Ensure output directory exists
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }
  }

  /**
   * Generate comprehensive performance dashboard
   */
  generateDashboard(testResults, options = {}) {
    const dashboardData = this.processTestResults(testResults);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    const dashboard = {
      metadata: {
        title: options.title || 'Claude Flow UI Performance Dashboard',
        generated: new Date().toISOString(),
        version: '1.0.0',
        refreshInterval: this.options.refreshInterval,
      },
      summary: this.generateSummary(dashboardData),
      metrics: this.generateMetricsSection(dashboardData),
      trends: this.generateTrendsSection(dashboardData),
      sla: this.generateSLASection(dashboardData),
      alerts: this.generateAlertsSection(dashboardData),
      recommendations: this.generateRecommendations(dashboardData),
    };

    // Generate HTML dashboard
    const htmlDashboard = this.generateHTMLDashboard(dashboard);
    const htmlPath = path.join(this.options.outputDir, `performance-dashboard-${timestamp}.html`);
    fs.writeFileSync(htmlPath, htmlDashboard);

    // Generate JSON data for API consumption
    const jsonPath = path.join(this.options.outputDir, `dashboard-data-${timestamp}.json`);
    fs.writeFileSync(jsonPath, JSON.stringify(dashboard, null, 2));

    // Generate latest symlinks for easy access
    const latestHtmlPath = path.join(this.options.outputDir, 'latest-dashboard.html');
    const latestJsonPath = path.join(this.options.outputDir, 'latest-dashboard.json');

    try {
      if (fs.existsSync(latestHtmlPath)) fs.unlinkSync(latestHtmlPath);
      if (fs.existsSync(latestJsonPath)) fs.unlinkSync(latestJsonPath);
      fs.symlinkSync(path.basename(htmlPath), latestHtmlPath);
      fs.symlinkSync(path.basename(jsonPath), latestJsonPath);
    } catch (error) {
      // Fallback to copy if symlink fails (Windows)
      fs.copyFileSync(htmlPath, latestHtmlPath);
      fs.copyFileSync(jsonPath, latestJsonPath);
    }

    console.log(`📊 Performance dashboard generated:`);
    console.log(`   HTML: ${htmlPath}`);
    console.log(`   JSON: ${jsonPath}`);
    console.log(`   Latest: ${latestHtmlPath}`);

    return {
      htmlPath,
      jsonPath,
      dashboard,
    };
  }

  /**
   * Process raw test results into dashboard format
   */
  processTestResults(testResults) {
    const data = {
      testRuns: [],
      metrics: {
        api: {},
        websocket: {},
        terminal: {},
        memory: {},
      },
      trends: {},
      slaViolations: [],
      performance: {
        overallScore: 0,
        categoryScores: {},
      },
    };

    // Process multiple test results if array provided
    const results = Array.isArray(testResults) ? testResults : [testResults];

    results.forEach(result => {
      if (result && result.metrics) {
        data.testRuns.push({
          timestamp: result.timestamp || Date.now(),
          duration: result.duration || 0,
          success: result.success !== false,
          testName: result.testName || 'unknown',
          metrics: result.metrics,
        });

        // Aggregate metrics
        this.aggregateMetrics(data.metrics, result.metrics);
      }
    });

    // Calculate performance scores
    data.performance.overallScore = this.calculateOverallScore(data.metrics);
    data.performance.categoryScores = this.calculateCategoryScores(data.metrics);

    // Generate trends
    data.trends = this.generateTrendData(data.testRuns);

    // Check SLA violations
    data.slaViolations = this.checkSLAViolations(data.metrics);

    return data;
  }

  /**
   * Aggregate metrics from multiple test runs
   */
  aggregateMetrics(target, source) {
    Object.keys(source).forEach(category => {
      if (!target[category]) target[category] = {};

      Object.keys(source[category]).forEach(metric => {
        const value = source[category][metric];

        if (typeof value === 'number') {
          if (!target[category][metric]) {
            target[category][metric] = { values: [], avg: 0, min: 0, max: 0 };
          }

          target[category][metric].values.push(value);
          const values = target[category][metric].values;

          target[category][metric].avg = values.reduce((sum, v) => sum + v, 0) / values.length;
          target[category][metric].min = Math.min(...values);
          target[category][metric].max = Math.max(...values);
        } else {
          target[category][metric] = value;
        }
      });
    });
  }

  /**
   * Generate dashboard summary section
   */
  generateSummary(data) {
    const totalRuns = data.testRuns.length;
    const successfulRuns = data.testRuns.filter(run => run.success).length;
    const successRate = totalRuns > 0 ? (successfulRuns / totalRuns) * 100 : 0;

    return {
      testRuns: totalRuns,
      successRate: successRate.toFixed(1),
      overallScore: data.performance.overallScore.toFixed(1),
      lastRun: totalRuns > 0 ? new Date(data.testRuns[data.testRuns.length - 1].timestamp).toISOString() : null,
      status: this.getOverallStatus(data.performance.overallScore, successRate),
    };
  }

  /**
   * Generate metrics section for dashboard
   */
  generateMetricsSection(data) {
    const metrics = {};

    Object.keys(data.metrics).forEach(category => {
      metrics[category] = {};

      Object.keys(data.metrics[category]).forEach(metric => {
        const metricData = data.metrics[category][metric];

        if (metricData && typeof metricData === 'object' && metricData.avg !== undefined) {
          metrics[category][metric] = {
            current: metricData.avg.toFixed(2),
            min: metricData.min.toFixed(2),
            max: metricData.max.toFixed(2),
            trend: this.calculateMetricTrend(metricData.values),
            status: this.getMetricStatus(category, metric, metricData.avg),
          };
        }
      });
    });

    return metrics;
  }

  /**
   * Generate trends section
   */
  generateTrendsSection(data) {
    if (data.testRuns.length < 2) {
      return { available: false, message: 'Insufficient data for trend analysis' };
    }

    const trends = {};
    const sortedRuns = data.testRuns.sort((a, b) => a.timestamp - b.timestamp);

    // Calculate response time trends
    const responseTimes = sortedRuns.map(run => ({
      timestamp: run.timestamp,
      apiLatency: run.metrics?.api?.avgLatency || 0,
      wsLatency: run.metrics?.websocket?.avgLatency || 0,
      terminalLatency: run.metrics?.terminal?.avgLatency || 0,
    }));

    trends.responseTime = this.calculateTrend(responseTimes);

    // Calculate memory trends
    const memoryUsage = sortedRuns.map(run => ({
      timestamp: run.timestamp,
      usage: run.metrics?.memory?.currentUsage || 0,
    }));

    trends.memory = this.calculateTrend(memoryUsage);

    return trends;
  }

  /**
   * Generate SLA compliance section
   */
  generateSLASection(data) {
    const slaTargets = {
      api: {
        healthCheck: { target: 50, current: data.metrics.api?.healthCheckLatency?.avg || 0 },
        terminalConfig: { target: 200, current: data.metrics.api?.terminalConfigLatency?.avg || 0 },
        terminalOps: { target: 300, current: data.metrics.api?.terminalOpsLatency?.avg || 0 },
      },
      websocket: {
        connectionTime: { target: 2000, current: data.metrics.websocket?.connectionTime?.avg || 0 },
        messageLatency: { target: 100, current: data.metrics.websocket?.messageLatency?.avg || 0 },
      },
      terminal: {
        ioLatency: { target: 500, current: data.metrics.terminal?.ioLatency?.avg || 0 },
        commandLatency: { target: 200, current: data.metrics.terminal?.commandLatency?.avg || 0 },
      },
      memory: {
        usage: { target: 512, current: data.metrics.memory?.currentUsage?.avg || 0 },
      },
    };

    const slaResults = {};
    let totalChecks = 0;
    let passedChecks = 0;

    Object.keys(slaTargets).forEach(category => {
      slaResults[category] = {};

      Object.keys(slaTargets[category]).forEach(metric => {
        const sla = slaTargets[category][metric];
        const compliance = sla.current <= sla.target;

        slaResults[category][metric] = {
          target: sla.target,
          current: sla.current.toFixed(2),
          compliance: compliance,
          deviation: ((sla.current - sla.target) / sla.target * 100).toFixed(1),
        };

        totalChecks++;
        if (compliance) passedChecks++;
      });
    });

    return {
      overallCompliance: totalChecks > 0 ? ((passedChecks / totalChecks) * 100).toFixed(1) : '0.0',
      details: slaResults,
      violations: data.slaViolations,
    };
  }

  /**
   * Generate alerts section
   */
  generateAlertsSection(data) {
    const alerts = [];

    // Check for performance degradation
    if (data.performance.overallScore < 70) {
      alerts.push({
        level: 'critical',
        category: 'performance',
        message: `Overall performance score is ${data.performance.overallScore.toFixed(1)}/100`,
        recommendation: 'Investigate performance bottlenecks and optimize critical paths',
      });
    }

    // Check for SLA violations
    data.slaViolations.forEach(violation => {
      alerts.push({
        level: 'warning',
        category: 'sla',
        message: violation.message,
        recommendation: violation.recommendation,
      });
    });

    // Check for memory issues
    const memoryUsage = data.metrics.memory?.currentUsage?.avg || 0;
    if (memoryUsage > 400) {
      alerts.push({
        level: 'warning',
        category: 'memory',
        message: `High memory usage detected: ${memoryUsage.toFixed(2)}MB`,
        recommendation: 'Monitor for memory leaks and optimize memory-intensive operations',
      });
    }

    // Check for error rates
    const errorRate = data.metrics.api?.errorRate?.avg || 0;
    if (errorRate > 5) {
      alerts.push({
        level: 'critical',
        category: 'reliability',
        message: `High error rate detected: ${errorRate.toFixed(1)}%`,
        recommendation: 'Investigate and fix error conditions causing request failures',
      });
    }

    return alerts;
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(data) {
    const recommendations = [];

    // Performance recommendations
    if (data.metrics.api?.avgLatency?.avg > 200) {
      recommendations.push({
        category: 'API Performance',
        priority: 'high',
        title: 'Optimize API Response Times',
        description: 'API response times are above optimal thresholds',
        actions: [
          'Add response caching for frequently accessed endpoints',
          'Optimize database queries and add appropriate indexes',
          'Consider implementing request batching',
          'Review and optimize serialization/deserialization logic',
        ],
      });
    }

    // WebSocket recommendations
    if (data.metrics.websocket?.messageLatency?.avg > 50) {
      recommendations.push({
        category: 'WebSocket Performance',
        priority: 'medium',
        title: 'Improve WebSocket Message Latency',
        description: 'WebSocket message latency is higher than expected',
        actions: [
          'Implement message batching for high-frequency updates',
          'Use binary frames for large data transfers',
          'Add message compression for text-heavy data',
          'Optimize message routing and processing logic',
        ],
      });
    }

    // Memory recommendations
    const memoryGrowth = data.metrics.memory?.growthRate?.avg || 0;
    if (memoryGrowth > 10) {
      recommendations.push({
        category: 'Memory Management',
        priority: 'high',
        title: 'Address Memory Growth',
        description: 'Memory usage is growing faster than expected',
        actions: [
          'Implement proper cleanup in event handlers',
          'Remove unused event listeners on component unmount',
          'Use object pooling for frequently created objects',
          'Monitor and fix circular references',
        ],
      });
    }

    // Terminal performance recommendations
    if (data.metrics.terminal?.ioLatency?.avg > 300) {
      recommendations.push({
        category: 'Terminal Performance',
        priority: 'medium',
        title: 'Optimize Terminal I/O',
        description: 'Terminal I/O operations are slower than expected',
        actions: [
          'Implement virtual scrolling for large buffers',
          'Use WebGL renderer when available',
          'Batch DOM updates to minimize reflows',
          'Optimize terminal data processing pipeline',
        ],
      });
    }

    return recommendations;
  }

  /**
   * Generate HTML dashboard
   */
  generateHTMLDashboard(dashboard) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${dashboard.metadata.title}</title>
    <style>
        ${this.getDashboardCSS()}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard">
        <header class="dashboard-header">
            <h1>${dashboard.metadata.title}</h1>
            <div class="header-info">
                <span>Generated: ${new Date(dashboard.metadata.generated).toLocaleString()}</span>
                <span class="status-badge ${dashboard.summary.status}">${dashboard.summary.status.toUpperCase()}</span>
            </div>
        </header>

        <div class="summary-cards">
            <div class="summary-card">
                <h3>Overall Score</h3>
                <div class="metric-value ${this.getScoreClass(parseFloat(dashboard.summary.overallScore))}">${dashboard.summary.overallScore}/100</div>
            </div>
            <div class="summary-card">
                <h3>Success Rate</h3>
                <div class="metric-value">${dashboard.summary.successRate}%</div>
            </div>
            <div class="summary-card">
                <h3>Test Runs</h3>
                <div class="metric-value">${dashboard.summary.testRuns}</div>
            </div>
            <div class="summary-card">
                <h3>Last Run</h3>
                <div class="metric-value">${dashboard.summary.lastRun ? new Date(dashboard.summary.lastRun).toLocaleString() : 'N/A'}</div>
            </div>
        </div>

        <div class="dashboard-grid">
            <section class="metrics-section">
                <h2>Performance Metrics</h2>
                ${this.generateMetricsHTML(dashboard.metrics)}
            </section>

            <section class="sla-section">
                <h2>SLA Compliance</h2>
                ${this.generateSLAHTML(dashboard.sla)}
            </section>

            <section class="alerts-section">
                <h2>Alerts & Issues</h2>
                ${this.generateAlertsHTML(dashboard.alerts)}
            </section>

            <section class="recommendations-section">
                <h2>Recommendations</h2>
                ${this.generateRecommendationsHTML(dashboard.recommendations)}
            </section>
        </div>

        <footer class="dashboard-footer">
            <p>Auto-refresh enabled (${dashboard.metadata.refreshInterval / 1000}s interval)</p>
            <p>Claude Flow UI Performance Dashboard v${dashboard.metadata.version}</p>
        </footer>
    </div>

    <script>
        ${this.getDashboardJS(dashboard)}
    </script>
</body>
</html>`;
  }

  /**
   * Get CSS styles for dashboard
   */
  getDashboardCSS() {
    return `
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }

        .dashboard {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .dashboard-header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .dashboard-header h1 {
            color: #2563eb;
            margin: 0;
        }

        .header-info {
            display: flex;
            gap: 15px;
            align-items: center;
        }

        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
        }

        .status-badge.excellent { background: #10b981; }
        .status-badge.good { background: #3b82f6; }
        .status-badge.warning { background: #f59e0b; }
        .status-badge.critical { background: #ef4444; }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }

        .summary-card h3 {
            color: #6b7280;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }

        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #1f2937;
        }

        .metric-value.excellent { color: #10b981; }
        .metric-value.good { color: #3b82f6; }
        .metric-value.warning { color: #f59e0b; }
        .metric-value.poor { color: #ef4444; }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        section h2 {
            color: #1f2937;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e5e7eb;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }

        .metric-item {
            text-align: center;
            padding: 15px;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
        }

        .metric-item h4 {
            color: #6b7280;
            font-size: 0.8em;
            margin-bottom: 5px;
        }

        .sla-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #f3f4f6;
        }

        .sla-compliance {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .sla-compliance.pass {
            background: #d1fae5;
            color: #065f46;
        }

        .sla-compliance.fail {
            background: #fee2e2;
            color: #991b1b;
        }

        .alert-item {
            margin: 10px 0;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid;
        }

        .alert-item.critical {
            background: #fef2f2;
            border-color: #ef4444;
        }

        .alert-item.warning {
            background: #fffbeb;
            border-color: #f59e0b;
        }

        .alert-item.info {
            background: #eff6ff;
            border-color: #3b82f6;
        }

        .recommendation-item {
            margin: 15px 0;
            padding: 15px;
            background: #f9fafb;
            border-radius: 6px;
            border-left: 4px solid #10b981;
        }

        .recommendation-item h4 {
            color: #1f2937;
            margin-bottom: 8px;
        }

        .recommendation-actions {
            margin-top: 10px;
        }

        .recommendation-actions ul {
            margin-left: 20px;
        }

        .recommendation-actions li {
            margin: 5px 0;
            color: #4b5563;
        }

        .dashboard-footer {
            margin-top: 30px;
            padding: 20px;
            text-align: center;
            color: #6b7280;
            font-size: 0.85em;
        }

        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            .dashboard-header {
                flex-direction: column;
                gap: 15px;
            }
        }
    `;
  }

  /**
   * Generate JavaScript for dashboard interactivity
   */
  getDashboardJS(dashboard) {
    return `
        // Auto-refresh dashboard
        setInterval(() => {
            window.location.reload();
        }, ${dashboard.metadata.refreshInterval});

        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Performance Dashboard Loaded');
            console.log('Dashboard Data:', ${JSON.stringify(dashboard, null, 2)});
        });
    `;
  }

  /**
   * Generate HTML for metrics section
   */
  generateMetricsHTML(metrics) {
    let html = '<div class="metrics-grid">';

    Object.keys(metrics).forEach(category => {
      Object.keys(metrics[category]).forEach(metric => {
        const metricData = metrics[category][metric];
        html += `
          <div class="metric-item">
            <h4>${this.formatMetricName(metric)}</h4>
            <div class="metric-value ${metricData.status}">${metricData.current}</div>
            <small>Min: ${metricData.min} | Max: ${metricData.max}</small>
          </div>
        `;
      });
    });

    html += '</div>';
    return html;
  }

  /**
   * Generate HTML for SLA section
   */
  generateSLAHTML(sla) {
    let html = `<div class="sla-overview">Overall Compliance: <strong>${sla.overallCompliance}%</strong></div>`;

    Object.keys(sla.details).forEach(category => {
      html += `<h3>${this.formatCategoryName(category)}</h3>`;

      Object.keys(sla.details[category]).forEach(metric => {
        const slaData = sla.details[category][metric];
        html += `
          <div class="sla-item">
            <span>${this.formatMetricName(metric)}</span>
            <span class="sla-compliance ${slaData.compliance ? 'pass' : 'fail'}">
              ${slaData.compliance ? 'PASS' : 'FAIL'}
            </span>
          </div>
        `;
      });
    });

    return html;
  }

  /**
   * Generate HTML for alerts section
   */
  generateAlertsHTML(alerts) {
    if (alerts.length === 0) {
      return '<div class="alert-item info"><strong>No alerts</strong> - All systems performing within expected parameters</div>';
    }

    let html = '';
    alerts.forEach(alert => {
      html += `
        <div class="alert-item ${alert.level}">
          <strong>${alert.category.toUpperCase()}:</strong> ${alert.message}
          <br><small><strong>Recommendation:</strong> ${alert.recommendation}</small>
        </div>
      `;
    });

    return html;
  }

  /**
   * Generate HTML for recommendations section
   */
  generateRecommendationsHTML(recommendations) {
    if (recommendations.length === 0) {
      return '<div class="recommendation-item"><strong>No recommendations</strong> - Performance is within acceptable parameters</div>';
    }

    let html = '';
    recommendations.forEach(rec => {
      html += `
        <div class="recommendation-item">
          <h4>${rec.title} (${rec.priority} priority)</h4>
          <p>${rec.description}</p>
          <div class="recommendation-actions">
            <strong>Recommended Actions:</strong>
            <ul>
              ${rec.actions.map(action => `<li>${action}</li>`).join('')}
            </ul>
          </div>
        </div>
      `;
    });

    return html;
  }

  /**
   * Helper methods
   */
  calculateOverallScore(metrics) {
    // Simplified scoring algorithm
    let score = 100;
    let penalties = 0;

    // API performance penalties
    const apiLatency = metrics.api?.avgLatency?.avg || 0;
    if (apiLatency > 200) penalties += Math.min(20, (apiLatency - 200) / 50);

    // WebSocket performance penalties
    const wsLatency = metrics.websocket?.messageLatency?.avg || 0;
    if (wsLatency > 100) penalties += Math.min(15, (wsLatency - 100) / 20);

    // Memory usage penalties
    const memoryUsage = metrics.memory?.currentUsage?.avg || 0;
    if (memoryUsage > 400) penalties += Math.min(25, (memoryUsage - 400) / 50);

    return Math.max(0, score - penalties);
  }

  calculateCategoryScores(metrics) {
    return {
      api: Math.max(0, 100 - Math.min(50, (metrics.api?.avgLatency?.avg || 0) / 10)),
      websocket: Math.max(0, 100 - Math.min(50, (metrics.websocket?.messageLatency?.avg || 0) / 5)),
      terminal: Math.max(0, 100 - Math.min(50, (metrics.terminal?.ioLatency?.avg || 0) / 20)),
      memory: Math.max(0, 100 - Math.min(50, (metrics.memory?.currentUsage?.avg || 0) / 20)),
    };
  }

  generateTrendData(testRuns) {
    if (testRuns.length < 2) return { available: false };

    const sorted = testRuns.sort((a, b) => a.timestamp - b.timestamp);
    return {
      available: true,
      dataPoints: sorted.length,
      timeSpan: sorted[sorted.length - 1].timestamp - sorted[0].timestamp,
    };
  }

  checkSLAViolations(metrics) {
    const violations = [];

    if (metrics.api?.healthCheckLatency?.avg > 50) {
      violations.push({
        category: 'API',
        metric: 'Health Check Latency',
        message: `Health check latency (${metrics.api.healthCheckLatency.avg.toFixed(2)}ms) exceeds SLA (50ms)`,
        recommendation: 'Optimize health check endpoint and database queries',
      });
    }

    return violations;
  }

  getOverallStatus(score, successRate) {
    if (score >= 85 && successRate >= 95) return 'excellent';
    if (score >= 70 && successRate >= 90) return 'good';
    if (score >= 50 && successRate >= 80) return 'warning';
    return 'critical';
  }

  getMetricStatus(category, metric, value) {
    // Define thresholds by category and metric
    const thresholds = {
      api: { healthCheckLatency: [25, 50, 100], terminalConfigLatency: [100, 200, 400] },
      websocket: { messageLatency: [25, 50, 100], connectionTime: [500, 1000, 2000] },
      terminal: { ioLatency: [100, 200, 500], commandLatency: [50, 100, 200] },
      memory: { currentUsage: [200, 350, 500] },
    };

    const threshold = thresholds[category]?.[metric];
    if (!threshold) return 'good';

    if (value <= threshold[0]) return 'excellent';
    if (value <= threshold[1]) return 'good';
    if (value <= threshold[2]) return 'warning';
    return 'poor';
  }

  getScoreClass(score) {
    if (score >= 85) return 'excellent';
    if (score >= 70) return 'good';
    if (score >= 50) return 'warning';
    return 'poor';
  }

  calculateMetricTrend(values) {
    if (values.length < 2) return 'stable';
    const recent = values.slice(-Math.min(5, values.length));
    const avg = recent.reduce((sum, v) => sum + v, 0) / recent.length;
    const first = recent[0];
    const change = ((avg - first) / first) * 100;

    if (change > 10) return 'increasing';
    if (change < -10) return 'decreasing';
    return 'stable';
  }

  formatMetricName(metric) {
    return metric.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
  }

  formatCategoryName(category) {
    return category.charAt(0).toUpperCase() + category.slice(1);
  }
}

module.exports = PerformanceDashboardGenerator;

// CLI usage
if (require.main === module) {
  const generator = new PerformanceDashboardGenerator();

  // Example usage with mock data
  const mockTestResults = {
    timestamp: Date.now(),
    duration: 300000,
    success: true,
    testName: 'load-test',
    metrics: {
      api: {
        healthCheckLatency: { avg: 25, min: 15, max: 45 },
        terminalConfigLatency: { avg: 85, min: 60, max: 120 },
        avgLatency: { avg: 65, min: 45, max: 95 },
      },
      websocket: {
        messageLatency: { avg: 35, min: 20, max: 75 },
        connectionTime: { avg: 850, min: 600, max: 1200 },
      },
      terminal: {
        ioLatency: { avg: 150, min: 100, max: 250 },
        commandLatency: { avg: 75, min: 50, max: 120 },
      },
      memory: {
        currentUsage: { avg: 280, min: 250, max: 320 },
        growthRate: { avg: 5, min: 2, max: 12 },
      },
    },
  };

  try {
    const result = generator.generateDashboard(mockTestResults, {
      title: 'Claude Flow UI Performance Dashboard - Demo',
    });
    console.log('✅ Demo dashboard generated successfully');
    console.log(`   Open: ${result.htmlPath}`);
  } catch (error) {
    console.error('❌ Failed to generate dashboard:', error.message);
    process.exit(1);
  }
}