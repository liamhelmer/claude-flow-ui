#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const readline = require('readline');
const { createReadStream, createWriteStream } = require('fs');

/**
 * Log File Analyzer - Batch Processing Example
 *
 * This example demonstrates batch processing of web server logs:
 * - Access log parsing and analysis
 * - Traffic pattern detection
 * - Error rate analysis
 * - Geographic distribution
 * - Performance metrics
 * - Security threat detection
 * - Report generation
 */

class LogAnalyzer {
  constructor(config = {}) {
    this.config = {
      batchSize: 10000,
      outputDir: './analysis',
      reportFormats: ['json', 'csv', 'html'],
      timeWindow: '1h', // 1h, 1d, 1w
      logFormat: 'combined', // combined, common, json
      analysis: {
        traffic: true,
        errors: true,
        performance: true,
        security: true,
        geography: true
      },
      thresholds: {
        errorRate: 0.05, // 5%
        avgResponseTime: 1000, // 1s
        suspiciousRequests: 100
      },
      ...config
    };

    this.stats = {
      totalRequests: 0,
      uniqueIPs: new Set(),
      statusCodes: {},
      methods: {},
      userAgents: {},
      referrers: {},
      errors: [],
      responseTimeSum: 0,
      responseTimes: [],
      hourlyTraffic: {},
      topPages: {},
      suspiciousIPs: {},
      startTime: null,
      endTime: null
    };

    // Common log format regex
    this.logRegex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"/;

    // Security patterns
    this.securityPatterns = [
      /[<>'"]/,  // XSS attempts
      /union.*select/i, // SQL injection
      /\.\.\//, // Directory traversal
      /eval\(/, // Code injection
      /script/i // Script injection
    ];
  }

  /**
   * Process a single log file
   */
  async processFile(inputFile) {
    console.log(`Analyzing log file: ${inputFile}`);
    this.stats.startTime = new Date();

    const fileStream = createReadStream(inputFile);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    let lineCount = 0;
    const batchLines = [];

    for await (const line of rl) {
      lineCount++;
      batchLines.push(line);

      if (batchLines.length >= this.config.batchSize) {
        await this.processBatch(batchLines);
        batchLines.length = 0; // Clear array

        if (lineCount % (this.config.batchSize * 10) === 0) {
          console.log(`Processed ${lineCount} lines...`);
        }
      }
    }

    // Process remaining lines
    if (batchLines.length > 0) {
      await this.processBatch(batchLines);
    }

    this.stats.endTime = new Date();
    console.log(`Completed analysis: ${lineCount} lines processed`);

    await this.generateReports();
    return this.getAnalysisResults();
  }

  /**
   * Process a batch of log lines
   */
  async processBatch(lines) {
    for (const line of lines) {
      if (line.trim()) {
        this.analyzeLine(line);
      }
    }
  }

  /**
   * Analyze a single log line
   */
  analyzeLine(line) {
    try {
      let logData;

      if (this.config.logFormat === 'json') {
        logData = this.parseJsonLog(line);
      } else {
        logData = this.parseCommonLog(line);
      }

      if (!logData) return;

      this.stats.totalRequests++;

      // Track unique IPs
      this.stats.uniqueIPs.add(logData.ip);

      // Status code analysis
      this.stats.statusCodes[logData.status] =
        (this.stats.statusCodes[logData.status] || 0) + 1;

      // HTTP method analysis
      this.stats.methods[logData.method] =
        (this.stats.methods[logData.method] || 0) + 1;

      // User agent analysis
      const ua = logData.userAgent || 'Unknown';
      this.stats.userAgents[ua] = (this.stats.userAgents[ua] || 0) + 1;

      // Referrer analysis
      const ref = logData.referrer || 'Direct';
      this.stats.referrers[ref] = (this.stats.referrers[ref] || 0) + 1;

      // Page popularity
      this.stats.topPages[logData.path] =
        (this.stats.topPages[logData.path] || 0) + 1;

      // Time-based analysis
      this.analyzeTime(logData.timestamp);

      // Performance analysis
      this.analyzePerformance(logData);

      // Security analysis
      this.analyzeSecurity(logData);

      // Error analysis
      if (logData.status >= 400) {
        this.stats.errors.push({
          timestamp: logData.timestamp,
          ip: logData.ip,
          status: logData.status,
          path: logData.path,
          userAgent: logData.userAgent
        });
      }

    } catch (error) {
      console.warn(`Failed to parse log line: ${line.substring(0, 100)}...`);
    }
  }

  /**
   * Parse common/combined log format
   */
  parseCommonLog(line) {
    const match = line.match(this.logRegex);
    if (!match) return null;

    return {
      ip: match[1],
      timestamp: this.parseTimestamp(match[2]),
      method: match[3],
      path: match[4],
      protocol: match[5],
      status: parseInt(match[6]),
      size: match[7] === '-' ? 0 : parseInt(match[7]),
      referrer: match[8],
      userAgent: match[9]
    };
  }

  /**
   * Parse JSON log format
   */
  parseJsonLog(line) {
    try {
      const data = JSON.parse(line);
      return {
        ip: data.remote_addr || data.ip,
        timestamp: new Date(data.timestamp || data.time),
        method: data.method,
        path: data.path || data.uri,
        status: parseInt(data.status),
        size: parseInt(data.size || data.bytes || 0),
        responseTime: parseFloat(data.response_time || data.duration || 0),
        referrer: data.referrer || data.referer,
        userAgent: data.user_agent || data.userAgent
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Parse timestamp from log format
   */
  parseTimestamp(timestamp) {
    // Convert Apache log timestamp: [10/Oct/2000:13:55:36 -0700]
    const cleaned = timestamp.replace(/[\[\]]/g, '');
    return new Date(cleaned);
  }

  /**
   * Analyze time-based patterns
   */
  analyzeTime(timestamp) {
    if (!timestamp || isNaN(timestamp.getTime())) return;

    const hour = timestamp.getHours();
    this.stats.hourlyTraffic[hour] = (this.stats.hourlyTraffic[hour] || 0) + 1;
  }

  /**
   * Analyze performance metrics
   */
  analyzePerformance(logData) {
    if (logData.responseTime) {
      this.stats.responseTimeSum += logData.responseTime;
      this.stats.responseTimes.push(logData.responseTime);
    }

    // Estimate response time from other factors if not available
    if (!logData.responseTime && logData.size) {
      const estimatedTime = Math.log(logData.size) * 10; // Rough estimate
      this.stats.responseTimeSum += estimatedTime;
      this.stats.responseTimes.push(estimatedTime);
    }
  }

  /**
   * Analyze security threats
   */
  analyzeSecurity(logData) {
    const path = logData.path || '';
    const userAgent = logData.userAgent || '';
    const ip = logData.ip;

    let suspicious = false;

    // Check for suspicious patterns
    for (const pattern of this.securityPatterns) {
      if (pattern.test(path) || pattern.test(userAgent)) {
        suspicious = true;
        break;
      }
    }

    // Check for too many requests from same IP
    if (!this.stats.suspiciousIPs[ip]) {
      this.stats.suspiciousIPs[ip] = { count: 0, suspicious: false };
    }

    this.stats.suspiciousIPs[ip].count++;

    if (suspicious || this.stats.suspiciousIPs[ip].count > this.config.thresholds.suspiciousRequests) {
      this.stats.suspiciousIPs[ip].suspicious = true;
    }
  }

  /**
   * Generate comprehensive analysis reports
   */
  async generateReports() {
    await fs.mkdir(this.config.outputDir, { recursive: true });

    const analysis = this.getAnalysisResults();

    // JSON Report
    if (this.config.reportFormats.includes('json')) {
      await this.generateJsonReport(analysis);
    }

    // CSV Report
    if (this.config.reportFormats.includes('csv')) {
      await this.generateCsvReport(analysis);
    }

    // HTML Report
    if (this.config.reportFormats.includes('html')) {
      await this.generateHtmlReport(analysis);
    }
  }

  /**
   * Generate JSON report
   */
  async generateJsonReport(analysis) {
    const reportFile = path.join(this.config.outputDir, 'log-analysis.json');
    await fs.writeFile(reportFile, JSON.stringify(analysis, null, 2));
    console.log(`JSON report saved to: ${reportFile}`);
  }

  /**
   * Generate CSV report
   */
  async generateCsvReport(analysis) {
    const reportFile = path.join(this.config.outputDir, 'log-analysis.csv');
    const csvStream = createWriteStream(reportFile);

    // Write summary data
    csvStream.write('Metric,Value\n');
    csvStream.write(`Total Requests,${analysis.summary.totalRequests}\n`);
    csvStream.write(`Unique Visitors,${analysis.summary.uniqueVisitors}\n`);
    csvStream.write(`Error Rate,${analysis.summary.errorRate}%\n`);
    csvStream.write(`Avg Response Time,${analysis.summary.avgResponseTime}ms\n`);

    csvStream.write('\nHour,Requests\n');
    for (let hour = 0; hour < 24; hour++) {
      const count = analysis.traffic.hourlyDistribution[hour] || 0;
      csvStream.write(`${hour},${count}\n`);
    }

    csvStream.end();
    console.log(`CSV report saved to: ${reportFile}`);
  }

  /**
   * Generate HTML report
   */
  async generateHtmlReport(analysis) {
    const reportFile = path.join(this.config.outputDir, 'log-analysis.html');

    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Log Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px 20px; }
        .chart { margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .warning { color: red; font-weight: bold; }
        .good { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Web Server Log Analysis Report</h1>
    <p>Generated: ${new Date().toLocaleString()}</p>

    <div class="summary">
        <h2>Summary</h2>
        <div class="metric">
            <strong>Total Requests:</strong> ${analysis.summary.totalRequests.toLocaleString()}
        </div>
        <div class="metric">
            <strong>Unique Visitors:</strong> ${analysis.summary.uniqueVisitors.toLocaleString()}
        </div>
        <div class="metric">
            <strong>Error Rate:</strong>
            <span class="${analysis.summary.errorRate > 5 ? 'warning' : 'good'}">
                ${analysis.summary.errorRate}%
            </span>
        </div>
        <div class="metric">
            <strong>Avg Response Time:</strong>
            <span class="${analysis.summary.avgResponseTime > 1000 ? 'warning' : 'good'}">
                ${analysis.summary.avgResponseTime}ms
            </span>
        </div>
    </div>

    <h2>Top Pages</h2>
    <table>
        <tr><th>Page</th><th>Requests</th><th>Percentage</th></tr>
        ${analysis.traffic.topPages.slice(0, 10).map(page =>
          `<tr><td>${page.path}</td><td>${page.count}</td><td>${page.percentage}%</td></tr>`
        ).join('')}
    </table>

    <h2>Status Code Distribution</h2>
    <table>
        <tr><th>Status Code</th><th>Count</th><th>Percentage</th></tr>
        ${analysis.errors.statusDistribution.map(status =>
          `<tr><td>${status.code}</td><td>${status.count}</td><td>${status.percentage}%</td></tr>`
        ).join('')}
    </table>

    <h2>Security Analysis</h2>
    <p><strong>Suspicious IPs:</strong> ${analysis.security.suspiciousIPs.length}</p>
    <p><strong>Threat Level:</strong>
        <span class="${analysis.security.threatLevel === 'HIGH' ? 'warning' : 'good'}">
            ${analysis.security.threatLevel}
        </span>
    </p>

</body>
</html>`;

    await fs.writeFile(reportFile, html);
    console.log(`HTML report saved to: ${reportFile}`);
  }

  /**
   * Get comprehensive analysis results
   */
  getAnalysisResults() {
    const processingTime = this.stats.endTime - this.stats.startTime;
    const avgResponseTime = this.stats.responseTimes.length > 0
      ? Math.round(this.stats.responseTimeSum / this.stats.responseTimes.length)
      : 0;

    const errorRate = ((this.stats.errors.length / this.stats.totalRequests) * 100).toFixed(2);

    // Sort top pages
    const topPages = Object.entries(this.stats.topPages)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 20)
      .map(([path, count]) => ({
        path,
        count,
        percentage: ((count / this.stats.totalRequests) * 100).toFixed(2)
      }));

    // Status code distribution
    const statusDistribution = Object.entries(this.stats.statusCodes)
      .sort(([,a], [,b]) => b - a)
      .map(([code, count]) => ({
        code: parseInt(code),
        count,
        percentage: ((count / this.stats.totalRequests) * 100).toFixed(2)
      }));

    // Security analysis
    const suspiciousIPs = Object.entries(this.stats.suspiciousIPs)
      .filter(([, data]) => data.suspicious)
      .map(([ip, data]) => ({ ip, requestCount: data.count }));

    return {
      summary: {
        totalRequests: this.stats.totalRequests,
        uniqueVisitors: this.stats.uniqueIPs.size,
        errorRate: parseFloat(errorRate),
        avgResponseTime,
        processingTime,
        analysisDate: new Date().toISOString()
      },
      traffic: {
        topPages,
        hourlyDistribution: this.stats.hourlyTraffic,
        methodDistribution: this.stats.methods,
        userAgents: Object.entries(this.stats.userAgents)
          .sort(([,a], [,b]) => b - a)
          .slice(0, 10)
      },
      errors: {
        totalErrors: this.stats.errors.length,
        errorRate: parseFloat(errorRate),
        statusDistribution,
        recentErrors: this.stats.errors.slice(-10)
      },
      performance: {
        avgResponseTime,
        responseTimeP95: this.calculatePercentile(this.stats.responseTimes, 95),
        responseTimeP99: this.calculatePercentile(this.stats.responseTimes, 99),
        slowestRequests: this.stats.responseTimes
          .map((time, index) => ({ time, index }))
          .sort((a, b) => b.time - a.time)
          .slice(0, 10)
      },
      security: {
        suspiciousIPs,
        threatLevel: suspiciousIPs.length > 10 ? 'HIGH' :
                    suspiciousIPs.length > 5 ? 'MEDIUM' : 'LOW',
        securityEvents: this.stats.errors.filter(error => error.status === 403 || error.status === 401)
      }
    };
  }

  /**
   * Calculate percentile for response times
   */
  calculatePercentile(arr, percentile) {
    if (arr.length === 0) return 0;

    const sorted = [...arr].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return Math.round(sorted[index] || 0);
  }

  /**
   * Process multiple log files
   */
  async processBatch(inputFiles) {
    console.log(`Processing ${inputFiles.length} log files...`);

    for (const file of inputFiles) {
      console.log(`\n--- Processing: ${path.basename(file)} ---`);
      await this.processFile(file);

      // Reset stats for next file (except for cumulative analysis)
      this.resetFileStats();
    }
  }

  /**
   * Reset per-file statistics
   */
  resetFileStats() {
    // Keep cumulative data, reset per-file counters
    this.stats.totalRequests = 0;
    this.stats.errors = [];
    this.stats.responseTimes = [];
    this.stats.responseTimeSum = 0;
  }
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node log-analyzer.js <log-file-or-directory> [config-file]');
    console.log('Example: node log-analyzer.js ./logs/access.log');
    console.log('Example: node log-analyzer.js ./logs/ ./config/analyzer-config.json');
    process.exit(1);
  }

  const inputPath = args[0];
  const configPath = args[1];

  let config = {};
  if (configPath) {
    try {
      const configData = await fs.readFile(configPath, 'utf8');
      config = JSON.parse(configData);
    } catch (error) {
      console.error(`Error loading config: ${error.message}`);
      process.exit(1);
    }
  }

  const analyzer = new LogAnalyzer(config);

  try {
    const stat = await fs.stat(inputPath);

    if (stat.isFile()) {
      await analyzer.processFile(inputPath);
    } else if (stat.isDirectory()) {
      const files = await fs.readdir(inputPath);
      const logFiles = files
        .filter(file => file.match(/\.(log|txt)$/i))
        .map(file => path.join(inputPath, file));

      if (logFiles.length === 0) {
        console.log('No log files found in directory');
        process.exit(1);
      }

      await analyzer.processBatch(logFiles);
    }
  } catch (error) {
    console.error(`Error processing files: ${error.message}`);
    process.exit(1);
  }
}

// Export for testing
module.exports = LogAnalyzer;

// Run CLI if called directly
if (require.main === module) {
  main().catch(console.error);
}