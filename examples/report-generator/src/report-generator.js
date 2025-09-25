#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const { Transform } = require('stream');
const { createReadStream, createWriteStream } = require('fs');

/**
 * Report Generator - Batch Processing Example
 *
 * This example demonstrates batch processing for business report generation:
 * - Sales report generation
 * - Financial analysis reports
 * - Customer analytics
 * - Performance dashboards
 * - Multi-format output (HTML, PDF, Excel, JSON)
 * - Template-based reporting
 * - Scheduled report generation
 */

class ReportGenerator {
  constructor(config = {}) {
    this.config = {
      batchSize: 2000,
      outputDir: './reports',
      templateDir: './templates',
      dataDir: './data',
      formats: ['html', 'json', 'csv'],
      reportTypes: ['sales', 'financial', 'customer', 'performance'],
      dateRange: {
        start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
        end: new Date()
      },
      aggregations: ['sum', 'avg', 'count', 'min', 'max'],
      groupBy: ['day', 'week', 'month', 'quarter', 'year'],
      ...config
    };

    this.data = {
      sales: [],
      customers: [],
      products: [],
      transactions: []
    };

    this.metrics = {
      totalSales: 0,
      totalRevenue: 0,
      averageOrderValue: 0,
      customerCount: 0,
      productsSold: 0,
      topProducts: [],
      topCustomers: [],
      salesTrends: {},
      performanceMetrics: {}
    };

    this.reports = new Map();
    this.templates = new Map();
  }

  /**
   * Generate comprehensive business reports
   */
  async generateReports(dataSource, reportTypes = null) {
    console.log('Starting report generation...');

    // Load data
    await this.loadData(dataSource);

    // Load templates
    await this.loadTemplates();

    // Generate specified reports or all types
    const types = reportTypes || this.config.reportTypes;

    for (const type of types) {
      console.log(`Generating ${type} report...`);
      await this.generateReport(type);
    }

    // Generate summary dashboard
    await this.generateDashboard();

    console.log('Report generation completed!');
    return this.getReportSummary();
  }

  /**
   * Load data from various sources
   */
  async loadData(dataSource) {
    console.log('Loading data...');

    if (typeof dataSource === 'string') {
      // Load from file or directory
      await this.loadDataFromFiles(dataSource);
    } else if (typeof dataSource === 'object') {
      // Use provided data object
      this.data = { ...this.data, ...dataSource };
    }

    // Process and clean data
    await this.processData();

    console.log(`Loaded ${this.getTotalRecords()} records`);
  }

  /**
   * Load data from files
   */
  async loadDataFromFiles(sourcePath) {
    const stat = await fs.stat(sourcePath);

    if (stat.isFile()) {
      await this.loadSingleFile(sourcePath);
    } else if (stat.isDirectory()) {
      await this.loadFromDirectory(sourcePath);
    }
  }

  /**
   * Load data from directory of files
   */
  async loadFromDirectory(dirPath) {
    const files = await fs.readdir(dirPath);

    for (const file of files) {
      const filePath = path.join(dirPath, file);
      const fileName = path.parse(file).name.toLowerCase();

      // Determine data type from filename
      if (fileName.includes('sales') || fileName.includes('orders')) {
        this.data.sales = await this.loadJsonFile(filePath);
      } else if (fileName.includes('customer')) {
        this.data.customers = await this.loadJsonFile(filePath);
      } else if (fileName.includes('product')) {
        this.data.products = await this.loadJsonFile(filePath);
      } else if (fileName.includes('transaction')) {
        this.data.transactions = await this.loadJsonFile(filePath);
      }
    }
  }

  /**
   * Load JSON file
   */
  async loadJsonFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      console.warn(`Failed to load ${filePath}:`, error.message);
      return [];
    }
  }

  /**
   * Process and clean loaded data
   */
  async processData() {
    // Process sales data
    if (this.data.sales && this.data.sales.length > 0) {
      this.data.sales = this.data.sales.map(sale => ({
        ...sale,
        date: new Date(sale.date || sale.orderDate),
        amount: parseFloat(sale.amount || sale.total || 0),
        quantity: parseInt(sale.quantity || 1)
      })).filter(sale =>
        sale.date >= this.config.dateRange.start &&
        sale.date <= this.config.dateRange.end
      );
    }

    // Process customer data
    if (this.data.customers && this.data.customers.length > 0) {
      this.data.customers = this.data.customers.map(customer => ({
        ...customer,
        registrationDate: new Date(customer.registrationDate || customer.createdAt),
        lifetimeValue: parseFloat(customer.lifetimeValue || 0)
      }));
    }

    // Calculate basic metrics
    await this.calculateMetrics();
  }

  /**
   * Calculate key business metrics
   */
  async calculateMetrics() {
    const sales = this.data.sales || [];
    const customers = this.data.customers || [];

    // Sales metrics
    this.metrics.totalSales = sales.length;
    this.metrics.totalRevenue = sales.reduce((sum, sale) => sum + sale.amount, 0);
    this.metrics.averageOrderValue = this.metrics.totalSales > 0
      ? this.metrics.totalRevenue / this.metrics.totalSales : 0;

    // Customer metrics
    this.metrics.customerCount = customers.length;

    // Product analysis
    const productSales = {};
    sales.forEach(sale => {
      const product = sale.productId || sale.product;
      if (product) {
        if (!productSales[product]) {
          productSales[product] = { count: 0, revenue: 0 };
        }
        productSales[product].count += sale.quantity || 1;
        productSales[product].revenue += sale.amount;
      }
    });

    this.metrics.topProducts = Object.entries(productSales)
      .sort(([,a], [,b]) => b.revenue - a.revenue)
      .slice(0, 10)
      .map(([product, data]) => ({ product, ...data }));

    // Customer analysis
    const customerSales = {};
    sales.forEach(sale => {
      const customer = sale.customerId || sale.customer;
      if (customer) {
        if (!customerSales[customer]) {
          customerSales[customer] = { orders: 0, revenue: 0 };
        }
        customerSales[customer].orders += 1;
        customerSales[customer].revenue += sale.amount;
      }
    });

    this.metrics.topCustomers = Object.entries(customerSales)
      .sort(([,a], [,b]) => b.revenue - a.revenue)
      .slice(0, 10)
      .map(([customer, data]) => ({ customer, ...data }));

    // Time-based trends
    this.metrics.salesTrends = this.calculateTrends(sales);
  }

  /**
   * Calculate sales trends over time
   */
  calculateTrends(sales) {
    const trends = {
      daily: {},
      weekly: {},
      monthly: {}
    };

    sales.forEach(sale => {
      const date = sale.date;
      const day = date.toISOString().split('T')[0];
      const week = this.getWeekString(date);
      const month = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;

      // Daily trends
      if (!trends.daily[day]) {
        trends.daily[day] = { sales: 0, revenue: 0 };
      }
      trends.daily[day].sales += 1;
      trends.daily[day].revenue += sale.amount;

      // Weekly trends
      if (!trends.weekly[week]) {
        trends.weekly[week] = { sales: 0, revenue: 0 };
      }
      trends.weekly[week].sales += 1;
      trends.weekly[week].revenue += sale.amount;

      // Monthly trends
      if (!trends.monthly[month]) {
        trends.monthly[month] = { sales: 0, revenue: 0 };
      }
      trends.monthly[month].sales += 1;
      trends.monthly[month].revenue += sale.amount;
    });

    return trends;
  }

  /**
   * Get week string for date
   */
  getWeekString(date) {
    const year = date.getFullYear();
    const start = new Date(year, 0, 1);
    const days = Math.floor((date - start) / (24 * 60 * 60 * 1000));
    const week = Math.ceil((days + start.getDay() + 1) / 7);
    return `${year}-W${String(week).padStart(2, '0')}`;
  }

  /**
   * Generate specific report type
   */
  async generateReport(reportType) {
    const reportData = await this.prepareReportData(reportType);

    for (const format of this.config.formats) {
      await this.generateReportFormat(reportType, format, reportData);
    }

    this.reports.set(reportType, reportData);
  }

  /**
   * Prepare data for specific report type
   */
  async prepareReportData(reportType) {
    switch (reportType) {
      case 'sales':
        return this.prepareSalesReport();
      case 'financial':
        return this.prepareFinancialReport();
      case 'customer':
        return this.prepareCustomerReport();
      case 'performance':
        return this.preparePerformanceReport();
      default:
        throw new Error(`Unknown report type: ${reportType}`);
    }
  }

  /**
   * Prepare sales report data
   */
  async prepareSalesReport() {
    return {
      title: 'Sales Report',
      period: `${this.config.dateRange.start.toDateString()} - ${this.config.dateRange.end.toDateString()}`,
      summary: {
        totalSales: this.metrics.totalSales,
        totalRevenue: this.metrics.totalRevenue,
        averageOrderValue: this.metrics.averageOrderValue,
        growthRate: this.calculateGrowthRate('sales')
      },
      trends: this.metrics.salesTrends,
      topProducts: this.metrics.topProducts,
      topCustomers: this.metrics.topCustomers,
      breakdown: {
        byDay: Object.entries(this.metrics.salesTrends.daily)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([date, data]) => ({ date, ...data })),
        byMonth: Object.entries(this.metrics.salesTrends.monthly)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([month, data]) => ({ month, ...data }))
      },
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * Prepare financial report data
   */
  async prepareFinancialReport() {
    const revenue = this.metrics.totalRevenue;
    const costs = revenue * 0.7; // Simplified cost calculation
    const profit = revenue - costs;
    const margin = revenue > 0 ? (profit / revenue) * 100 : 0;

    return {
      title: 'Financial Report',
      period: `${this.config.dateRange.start.toDateString()} - ${this.config.dateRange.end.toDateString()}`,
      summary: {
        totalRevenue: revenue,
        totalCosts: costs,
        grossProfit: profit,
        profitMargin: margin,
        revenueGrowth: this.calculateGrowthRate('revenue')
      },
      breakdown: {
        revenueByProduct: this.metrics.topProducts.map(p => ({
          product: p.product,
          revenue: p.revenue,
          percentage: (p.revenue / revenue) * 100
        })),
        monthlyPerformance: Object.entries(this.metrics.salesTrends.monthly)
          .map(([month, data]) => ({
            month,
            revenue: data.revenue,
            estimatedProfit: data.revenue * 0.3,
            orders: data.sales
          }))
      },
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * Prepare customer report data
   */
  async prepareCustomerReport() {
    const avgCustomerValue = this.metrics.customerCount > 0
      ? this.metrics.totalRevenue / this.metrics.customerCount : 0;

    return {
      title: 'Customer Analytics Report',
      period: `${this.config.dateRange.start.toDateString()} - ${this.config.dateRange.end.toDateString()}`,
      summary: {
        totalCustomers: this.metrics.customerCount,
        averageCustomerValue: avgCustomerValue,
        customerGrowth: this.calculateGrowthRate('customers'),
        retentionRate: this.calculateRetentionRate()
      },
      topCustomers: this.metrics.topCustomers,
      segments: this.analyzeCustomerSegments(),
      acquisition: this.analyzeCustomerAcquisition(),
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * Prepare performance report data
   */
  async preparePerformanceReport() {
    return {
      title: 'Performance Dashboard',
      period: `${this.config.dateRange.start.toDateString()} - ${this.config.dateRange.end.toDateString()}`,
      kpis: {
        salesGrowth: this.calculateGrowthRate('sales'),
        revenueGrowth: this.calculateGrowthRate('revenue'),
        customerGrowth: this.calculateGrowthRate('customers'),
        averageOrderValue: this.metrics.averageOrderValue,
        customerLifetimeValue: this.calculateCustomerLifetimeValue()
      },
      trends: {
        salesTrend: this.calculateTrendDirection('sales'),
        revenueTrend: this.calculateTrendDirection('revenue'),
        customerTrend: this.calculateTrendDirection('customers')
      },
      alerts: this.generatePerformanceAlerts(),
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * Calculate growth rate for metric
   */
  calculateGrowthRate(metric) {
    // Simplified growth calculation - in practice, you'd compare with previous period
    return Math.round((Math.random() * 20 - 10) * 100) / 100; // Random for demo
  }

  /**
   * Calculate customer retention rate
   */
  calculateRetentionRate() {
    // Simplified calculation - in practice, track repeat customers
    return Math.round((75 + Math.random() * 20) * 100) / 100; // Random for demo
  }

  /**
   * Analyze customer segments
   */
  analyzeCustomerSegments() {
    const segments = {
      high_value: { count: 0, revenue: 0, threshold: 1000 },
      medium_value: { count: 0, revenue: 0, threshold: 500 },
      low_value: { count: 0, revenue: 0, threshold: 0 }
    };

    this.metrics.topCustomers.forEach(customer => {
      if (customer.revenue >= segments.high_value.threshold) {
        segments.high_value.count++;
        segments.high_value.revenue += customer.revenue;
      } else if (customer.revenue >= segments.medium_value.threshold) {
        segments.medium_value.count++;
        segments.medium_value.revenue += customer.revenue;
      } else {
        segments.low_value.count++;
        segments.low_value.revenue += customer.revenue;
      }
    });

    return segments;
  }

  /**
   * Analyze customer acquisition
   */
  analyzeCustomerAcquisition() {
    // Simplified analysis
    return {
      newCustomers: Math.floor(this.metrics.customerCount * 0.2),
      acquisitionCost: 25.50,
      acquisitionChannels: {
        organic: 45,
        paid_ads: 30,
        referral: 15,
        social: 10
      }
    };
  }

  /**
   * Calculate customer lifetime value
   */
  calculateCustomerLifetimeValue() {
    return this.metrics.averageOrderValue * 3.5; // Simplified calculation
  }

  /**
   * Calculate trend direction
   */
  calculateTrendDirection(metric) {
    const growth = this.calculateGrowthRate(metric);
    return growth > 5 ? 'up' : growth < -5 ? 'down' : 'stable';
  }

  /**
   * Generate performance alerts
   */
  generatePerformanceAlerts() {
    const alerts = [];

    if (this.calculateGrowthRate('revenue') < -10) {
      alerts.push({
        type: 'warning',
        message: 'Revenue decline detected',
        severity: 'high'
      });
    }

    if (this.metrics.averageOrderValue < 50) {
      alerts.push({
        type: 'info',
        message: 'Average order value below target',
        severity: 'medium'
      });
    }

    return alerts;
  }

  /**
   * Generate report in specific format
   */
  async generateReportFormat(reportType, format, reportData) {
    const fileName = `${reportType}-report-${Date.now()}.${format}`;
    const filePath = path.join(this.config.outputDir, fileName);

    await fs.mkdir(this.config.outputDir, { recursive: true });

    switch (format) {
      case 'json':
        await this.generateJsonReport(filePath, reportData);
        break;
      case 'html':
        await this.generateHtmlReport(filePath, reportData);
        break;
      case 'csv':
        await this.generateCsvReport(filePath, reportData);
        break;
      default:
        console.warn(`Unsupported format: ${format}`);
    }
  }

  /**
   * Generate JSON report
   */
  async generateJsonReport(filePath, reportData) {
    await fs.writeFile(filePath, JSON.stringify(reportData, null, 2));
    console.log(`JSON report generated: ${filePath}`);
  }

  /**
   * Generate HTML report
   */
  async generateHtmlReport(filePath, reportData) {
    const template = this.templates.get('html') || this.getDefaultHtmlTemplate();
    const html = this.renderTemplate(template, reportData);

    await fs.writeFile(filePath, html);
    console.log(`HTML report generated: ${filePath}`);
  }

  /**
   * Generate CSV report
   */
  async generateCsvReport(filePath, reportData) {
    const csvStream = createWriteStream(filePath);

    // Write summary data
    csvStream.write('Summary Information\n');
    csvStream.write('Metric,Value\n');

    if (reportData.summary) {
      for (const [key, value] of Object.entries(reportData.summary)) {
        csvStream.write(`${key},${value}\n`);
      }
    }

    csvStream.write('\n');

    // Write breakdown data if available
    if (reportData.breakdown && reportData.breakdown.byMonth) {
      csvStream.write('Monthly Breakdown\n');
      csvStream.write('Month,Sales,Revenue\n');

      reportData.breakdown.byMonth.forEach(month => {
        csvStream.write(`${month.month},${month.sales || 0},${month.revenue || 0}\n`);
      });
    }

    csvStream.end();
    console.log(`CSV report generated: ${filePath}`);
  }

  /**
   * Load report templates
   */
  async loadTemplates() {
    try {
      const templateFiles = await fs.readdir(this.config.templateDir);

      for (const file of templateFiles) {
        const filePath = path.join(this.config.templateDir, file);
        const content = await fs.readFile(filePath, 'utf8');
        const format = path.extname(file).slice(1);
        this.templates.set(format, content);
      }
    } catch (error) {
      console.log('No templates directory found, using defaults');
    }
  }

  /**
   * Get default HTML template
   */
  getDefaultHtmlTemplate() {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>{{title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .metric { background: white; border: 1px solid #ddd; padding: 15px; border-radius: 5px; min-width: 200px; }
        .metric h3 { margin: 0; color: #333; }
        .metric .value { font-size: 24px; font-weight: bold; color: #0066cc; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { margin: 20px 0; height: 300px; background: #f9f9f9; display: flex; align-items: center; justify-content: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{title}}</h1>
        <p>Period: {{period}}</p>
        <p>Generated: {{generatedAt}}</p>
    </div>

    <div class="summary">
        {{#summary}}
        <div class="metric">
            <h3>{{@key}}</h3>
            <div class="value">{{this}}</div>
        </div>
        {{/summary}}
    </div>

    <div class="chart">
        <p>Chart visualization would appear here</p>
    </div>

    <h2>Detailed Analysis</h2>
    <p>Additional report content and analysis would appear here...</p>
</body>
</html>`;
  }

  /**
   * Render template with data
   */
  renderTemplate(template, data) {
    let rendered = template;

    // Simple template rendering (in practice, use a proper template engine)
    rendered = rendered.replace(/\{\{title\}\}/g, data.title || 'Report');
    rendered = rendered.replace(/\{\{period\}\}/g, data.period || '');
    rendered = rendered.replace(/\{\{generatedAt\}\}/g, new Date(data.generatedAt).toLocaleString());

    // Replace summary metrics
    if (data.summary) {
      let summaryHtml = '';
      for (const [key, value] of Object.entries(data.summary)) {
        summaryHtml += `
          <div class="metric">
            <h3>${key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}</h3>
            <div class="value">${typeof value === 'number' ? value.toLocaleString() : value}</div>
          </div>`;
      }
      rendered = rendered.replace(/\{\{#summary\}\}.*\{\{\/summary\}\}/s, summaryHtml);
    }

    return rendered;
  }

  /**
   * Generate comprehensive dashboard
   */
  async generateDashboard() {
    console.log('Generating comprehensive dashboard...');

    const dashboardData = {
      title: 'Business Intelligence Dashboard',
      period: `${this.config.dateRange.start.toDateString()} - ${this.config.dateRange.end.toDateString()}`,
      overview: {
        totalRevenue: this.metrics.totalRevenue,
        totalSales: this.metrics.totalSales,
        customerCount: this.metrics.customerCount,
        averageOrderValue: this.metrics.averageOrderValue
      },
      reports: Array.from(this.reports.keys()),
      trends: this.metrics.salesTrends,
      alerts: this.generatePerformanceAlerts(),
      generatedAt: new Date().toISOString()
    };

    // Generate dashboard in multiple formats
    for (const format of this.config.formats) {
      const fileName = `dashboard.${format}`;
      const filePath = path.join(this.config.outputDir, fileName);

      switch (format) {
        case 'json':
          await fs.writeFile(filePath, JSON.stringify(dashboardData, null, 2));
          break;
        case 'html':
          const html = this.renderTemplate(this.getDashboardTemplate(), dashboardData);
          await fs.writeFile(filePath, html);
          break;
      }
    }

    console.log('Dashboard generated successfully');
  }

  /**
   * Get dashboard HTML template
   */
  getDashboardTemplate() {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>{{title}}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: white; border-radius: 10px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric-card h3 { margin: 0 0 10px 0; color: #555; font-size: 14px; text-transform: uppercase; }
        .metric-card .value { font-size: 32px; font-weight: bold; color: #333; }
        .chart-container { background: white; border-radius: 10px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert.warning { background: #fff3cd; border-left: 4px solid #ffc107; }
        .alert.info { background: #d1ecf1; border-left: 4px solid #17a2b8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{title}}</h1>
        <p>{{period}}</p>
    </div>

    <div class="container">
        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Total Revenue</h3>
                <div class="value">${{overview.totalRevenue}}</div>
            </div>
            <div class="metric-card">
                <h3>Total Sales</h3>
                <div class="value">{{overview.totalSales}}</div>
            </div>
            <div class="metric-card">
                <h3>Customers</h3>
                <div class="value">{{overview.customerCount}}</div>
            </div>
            <div class="metric-card">
                <h3>Avg Order Value</h3>
                <div class="value">${{overview.averageOrderValue}}</div>
            </div>
        </div>

        <div class="chart-container">
            <h2>Sales Trends</h2>
            <p>Interactive charts would be displayed here using a charting library like Chart.js or D3.js</p>
        </div>
    </div>
</body>
</html>`;
  }

  /**
   * Get total records count
   */
  getTotalRecords() {
    return Object.values(this.data).reduce((total, arr) =>
      total + (Array.isArray(arr) ? arr.length : 0), 0);
  }

  /**
   * Get report generation summary
   */
  getReportSummary() {
    return {
      reportsGenerated: this.reports.size,
      totalRecords: this.getTotalRecords(),
      formats: this.config.formats,
      outputDirectory: this.config.outputDir,
      generatedAt: new Date().toISOString()
    };
  }
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node report-generator.js <data-source> [report-types] [config-file]');
    console.log('Examples:');
    console.log('  node report-generator.js ./data/');
    console.log('  node report-generator.js ./data/ sales,financial');
    console.log('  node report-generator.js ./data/ sales ./config/reports.json');
    process.exit(1);
  }

  const [dataSource, reportTypes, configFile] = args;

  let config = {};
  if (configFile) {
    try {
      const configData = await fs.readFile(configFile, 'utf8');
      config = JSON.parse(configData);
    } catch (error) {
      console.error(`Error loading config: ${error.message}`);
      process.exit(1);
    }
  }

  const generator = new ReportGenerator(config);

  try {
    const types = reportTypes ? reportTypes.split(',') : null;
    const summary = await generator.generateReports(dataSource, types);

    console.log('\n=== REPORT GENERATION SUMMARY ===');
    console.log(`Reports generated: ${summary.reportsGenerated}`);
    console.log(`Total records processed: ${summary.totalRecords}`);
    console.log(`Output formats: ${summary.formats.join(', ')}`);
    console.log(`Output directory: ${summary.outputDirectory}`);

  } catch (error) {
    console.error(`Report generation failed: ${error.message}`);
    process.exit(1);
  }
}

// Export for testing
module.exports = ReportGenerator;

// Run CLI if called directly
if (require.main === module) {
  main().catch(console.error);
}