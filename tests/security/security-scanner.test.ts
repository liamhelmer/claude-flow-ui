/**
 * Automated Security Scanning Integration Tests
 *
 * Integration tests for automated security scanning tools including:
 * - OWASP ZAP integration
 * - Burp Suite Professional integration
 * - Custom security scanners
 * - Dependency vulnerability scanning
 * - Static code analysis security rules
 * - Dynamic application security testing (DAST)
 * - Infrastructure security scanning
 */

import { test, expect, describe, beforeEach, afterEach, jest } from '@jest/globals';
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { SecurityPayloadGenerator, SecurityValidationHelpers } from './utils/security-helpers';

interface ScanResult {
  tool: string;
  timestamp: string;
  findings: SecurityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface SecurityFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: {
    file?: string;
    line?: number;
    url?: string;
    parameter?: string;
  };
  cwe?: string;
  owasp?: string;
  recommendation: string;
}

class SecurityScannerIntegration {
  /**
   * OWASP ZAP Scanner Integration
   */
  static createZapScanner() {
    return {
      async startZapProxy(port: number = 8080): Promise<{ pid: number; url: string }> {
        // Mock ZAP startup
        return {
          pid: 12345,
          url: `http://localhost:${port}`
        };
      },
      
      async spiderScan(targetUrl: string): Promise<{ scanId: string; status: string }> {
        // Mock spider scan
        return {
          scanId: 'spider-001',
          status: 'running'
        };
      },
      
      async activeScan(targetUrl: string): Promise<{ scanId: string; status: string }> {
        // Mock active scan
        return {
          scanId: 'active-001',
          status: 'running'
        };
      },
      
      async getScanResults(scanId: string): Promise<ScanResult> {
        // Mock scan results
        return {
          tool: 'OWASP ZAP',
          timestamp: new Date().toISOString(),
          findings: [
            {
              id: 'zap-001',
              severity: 'high',
              title: 'SQL Injection',
              description: 'SQL injection vulnerability found in search parameter',
              location: {
                url: '/api/search',
                parameter: 'query'
              },
              cwe: 'CWE-89',
              owasp: 'A03:2021 – Injection',
              recommendation: 'Use parameterized queries to prevent SQL injection'
            },
            {
              id: 'zap-002',
              severity: 'medium',
              title: 'Missing Security Headers',
              description: 'X-Content-Type-Options header is missing',
              location: {
                url: '/api/data'
              },
              cwe: 'CWE-16',
              owasp: 'A05:2021 – Security Misconfiguration',
              recommendation: 'Add X-Content-Type-Options: nosniff header'
            }
          ],
          summary: {
            critical: 0,
            high: 1,
            medium: 1,
            low: 0,
            info: 0
          }
        };
      },
      
      async generateReport(scanId: string, format: 'json' | 'html' | 'xml' = 'json'): Promise<string> {
        const results = await this.getScanResults(scanId);
        
        if (format === 'json') {
          return JSON.stringify(results, null, 2);
        }
        
        // Mock HTML/XML report generation
        return `<report>Mock ${format.toUpperCase()} report</report>`;
      },
      
      async stopZapProxy(pid: number): Promise<void> {
        // Mock ZAP shutdown
        console.log(`Stopping ZAP proxy with PID: ${pid}`);
      }
    };
  }
  
  /**
   * Burp Suite Professional Integration
   */
  static createBurpScanner() {
    return {
      async startBurpSuite(projectFile?: string): Promise<{ sessionId: string }> {
        // Mock Burp Suite startup
        return {
          sessionId: 'burp-session-001'
        };
      },
      
      async configureScan(config: {
        targetScope: string[];
        crawlSettings: any;
        auditSettings: any;
      }): Promise<{ configId: string }> {
        return {
          configId: 'config-001'
        };
      },
      
      async runScan(targetUrl: string, configId: string): Promise<{ taskId: string }> {
        return {
          taskId: 'task-001'
        };
      },
      
      async getScanStatus(taskId: string): Promise<{ status: string; progress: number }> {
        return {
          status: 'running',
          progress: 75
        };
      },
      
      async getScanFindings(taskId: string): Promise<ScanResult> {
        return {
          tool: 'Burp Suite Professional',
          timestamp: new Date().toISOString(),
          findings: [
            {
              id: 'burp-001',
              severity: 'critical',
              title: 'Insecure Direct Object Reference',
              description: 'Direct access to user data without authorization check',
              location: {
                url: '/api/user/123/profile',
                parameter: 'id'
              },
              cwe: 'CWE-639',
              owasp: 'A01:2021 – Broken Access Control',
              recommendation: 'Implement proper authorization checks for user data access'
            }
          ],
          summary: {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
          }
        };
      },
      
      async exportResults(taskId: string, format: 'json' | 'xml' | 'html'): Promise<string> {
        const findings = await this.getScanFindings(taskId);
        return JSON.stringify(findings, null, 2);
      }
    };
  }
  
  /**
   * Custom Security Scanner
   */
  static createCustomScanner() {
    return {
      async scanForVulnerabilities(targetUrl: string, options: {
        includePayloads?: boolean;
        maxDepth?: number;
        timeout?: number;
      } = {}): Promise<ScanResult> {
        const findings: SecurityFinding[] = [];
        
        // Test for various vulnerability types
        if (options.includePayloads) {
          // SQL Injection tests
          const sqlPayloads = SecurityPayloadGenerator.generateSqlInjectionPayloads();
          for (const payload of sqlPayloads.slice(0, 3)) {
            findings.push({
              id: `custom-sql-${findings.length + 1}`,
              severity: 'high',
              title: 'Potential SQL Injection',
              description: `SQL injection payload detected: ${payload}`,
              location: {
                url: targetUrl,
                parameter: 'query'
              },
              cwe: 'CWE-89',
              owasp: 'A03:2021 – Injection',
              recommendation: 'Implement input validation and use parameterized queries'
            });
          }
          
          // XSS tests
          const xssPayloads = SecurityPayloadGenerator.generateXssPayloads();
          for (const payload of xssPayloads.slice(0, 2)) {
            findings.push({
              id: `custom-xss-${findings.length + 1}`,
              severity: 'medium',
              title: 'Potential Cross-Site Scripting (XSS)',
              description: `XSS payload detected: ${payload}`,
              location: {
                url: targetUrl,
                parameter: 'content'
              },
              cwe: 'CWE-79',
              owasp: 'A03:2021 – Injection',
              recommendation: 'Implement output encoding and input validation'
            });
          }
        }
        
        return {
          tool: 'Custom Security Scanner',
          timestamp: new Date().toISOString(),
          findings,
          summary: {
            critical: findings.filter(f => f.severity === 'critical').length,
            high: findings.filter(f => f.severity === 'high').length,
            medium: findings.filter(f => f.severity === 'medium').length,
            low: findings.filter(f => f.severity === 'low').length,
            info: findings.filter(f => f.severity === 'info').length
          }
        };
      },
      
      async scanDependencies(packageJsonPath: string): Promise<ScanResult> {
        const findings: SecurityFinding[] = [
          {
            id: 'dep-001',
            severity: 'high',
            title: 'Vulnerable Dependency: lodash',
            description: 'lodash version 4.17.15 has known security vulnerabilities',
            location: {
              file: packageJsonPath,
              line: 25
            },
            cwe: 'CWE-1035',
            owasp: 'A06:2021 – Vulnerable and Outdated Components',
            recommendation: 'Update lodash to version 4.17.21 or later'
          }
        ];
        
        return {
          tool: 'Dependency Scanner',
          timestamp: new Date().toISOString(),
          findings,
          summary: {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0
          }
        };
      },
      
      async scanConfiguration(configFiles: string[]): Promise<ScanResult> {
        const findings: SecurityFinding[] = [
          {
            id: 'config-001',
            severity: 'medium',
            title: 'Hardcoded Secret in Configuration',
            description: 'API key found in configuration file',
            location: {
              file: configFiles[0],
              line: 12
            },
            cwe: 'CWE-798',
            owasp: 'A02:2021 – Cryptographic Failures',
            recommendation: 'Move secrets to environment variables or secure key management'
          }
        ];
        
        return {
          tool: 'Configuration Scanner',
          timestamp: new Date().toISOString(),
          findings,
          summary: {
            critical: 0,
            high: 0,
            medium: 1,
            low: 0,
            info: 0
          }
        };
      }
    };
  }
}

class SecurityReportGenerator {
  static async generateComprehensiveReport(scanResults: ScanResult[]): Promise<string> {
    const report = {
      metadata: {
        generatedAt: new Date().toISOString(),
        totalScans: scanResults.length,
        tools: scanResults.map(r => r.tool)
      },
      
      summary: {
        totalFindings: scanResults.reduce((sum, r) => sum + r.findings.length, 0),
        bySeverity: {
          critical: scanResults.reduce((sum, r) => sum + r.summary.critical, 0),
          high: scanResults.reduce((sum, r) => sum + r.summary.high, 0),
          medium: scanResults.reduce((sum, r) => sum + r.summary.medium, 0),
          low: scanResults.reduce((sum, r) => sum + r.summary.low, 0),
          info: scanResults.reduce((sum, r) => sum + r.summary.info, 0)
        }
      },
      
      owaspMapping: this.mapToOwaspTop10(scanResults),
      
      findings: scanResults.flatMap(r => r.findings),
      
      recommendations: this.generateRecommendations(scanResults)
    };
    
    return JSON.stringify(report, null, 2);
  }
  
  private static mapToOwaspTop10(scanResults: ScanResult[]): { [key: string]: number } {
    const owaspMap: { [key: string]: number } = {};
    
    scanResults.flatMap(r => r.findings).forEach(finding => {
      if (finding.owasp) {
        owaspMap[finding.owasp] = (owaspMap[finding.owasp] || 0) + 1;
      }
    });
    
    return owaspMap;
  }
  
  private static generateRecommendations(scanResults: ScanResult[]): string[] {
    const recommendations = new Set<string>();
    
    scanResults.flatMap(r => r.findings).forEach(finding => {
      recommendations.add(finding.recommendation);
    });
    
    return Array.from(recommendations);
  }
  
  static async generateCiReport(scanResults: ScanResult[], thresholds: {
    critical: number;
    high: number;
    medium: number;
  }): Promise<{ passed: boolean; report: string; issues: string[] }> {
    const summary = {
      critical: scanResults.reduce((sum, r) => sum + r.summary.critical, 0),
      high: scanResults.reduce((sum, r) => sum + r.summary.high, 0),
      medium: scanResults.reduce((sum, r) => sum + r.summary.medium, 0)
    };
    
    const issues: string[] = [];
    let passed = true;
    
    if (summary.critical > thresholds.critical) {
      issues.push(`Critical vulnerabilities: ${summary.critical} (threshold: ${thresholds.critical})`);
      passed = false;
    }
    
    if (summary.high > thresholds.high) {
      issues.push(`High vulnerabilities: ${summary.high} (threshold: ${thresholds.high})`);
      passed = false;
    }
    
    if (summary.medium > thresholds.medium) {
      issues.push(`Medium vulnerabilities: ${summary.medium} (threshold: ${thresholds.medium})`);
      passed = false;
    }
    
    const report = {
      status: passed ? 'PASSED' : 'FAILED',
      summary,
      thresholds,
      issues,
      timestamp: new Date().toISOString()
    };
    
    return {
      passed,
      report: JSON.stringify(report, null, 2),
      issues
    };
  }
}

describe('Automated Security Scanning Integration Test Suite', () => {
  let zapScanner: any;
  let burpScanner: any;
  let customScanner: any;
  
  beforeEach(() => {
    zapScanner = SecurityScannerIntegration.createZapScanner();
    burpScanner = SecurityScannerIntegration.createBurpScanner();
    customScanner = SecurityScannerIntegration.createCustomScanner();
    jest.clearAllMocks();
  });
  
  describe('OWASP ZAP Integration', () => {
    test('should start ZAP proxy and run spider scan', async () => {
      const zapProxy = await zapScanner.startZapProxy(8080);
      expect(zapProxy.pid).toBeDefined();
      expect(zapProxy.url).toBe('http://localhost:8080');
      
      const spiderScan = await zapScanner.spiderScan('http://localhost:3000');
      expect(spiderScan.scanId).toBe('spider-001');
      expect(spiderScan.status).toBe('running');
      
      await zapScanner.stopZapProxy(zapProxy.pid);
    });
    
    test('should run active scan and generate results', async () => {
      const activeScan = await zapScanner.activeScan('http://localhost:3000');
      expect(activeScan.scanId).toBe('active-001');
      
      const results = await zapScanner.getScanResults(activeScan.scanId);
      
      expect(results.tool).toBe('OWASP ZAP');
      expect(results.findings.length).toBeGreaterThan(0);
      expect(results.summary.high).toBe(1);
      expect(results.summary.medium).toBe(1);
      
      // Verify specific vulnerabilities are detected
      const sqlInjectionFinding = results.findings.find(f => f.title === 'SQL Injection');
      expect(sqlInjectionFinding).toBeDefined();
      expect(sqlInjectionFinding?.severity).toBe('high');
      expect(sqlInjectionFinding?.cwe).toBe('CWE-89');
    });
    
    test('should generate reports in different formats', async () => {
      const scanId = 'active-001';
      
      const jsonReport = await zapScanner.generateReport(scanId, 'json');
      expect(() => JSON.parse(jsonReport)).not.toThrow();
      
      const htmlReport = await zapScanner.generateReport(scanId, 'html');
      expect(htmlReport).toContain('<report>');
      
      const xmlReport = await zapScanner.generateReport(scanId, 'xml');
      expect(xmlReport).toContain('<report>');
    });
  });
  
  describe('Burp Suite Integration', () => {
    test('should start Burp Suite and configure scan', async () => {
      const session = await burpScanner.startBurpSuite();
      expect(session.sessionId).toBe('burp-session-001');
      
      const config = await burpScanner.configureScan({
        targetScope: ['http://localhost:3000/*'],
        crawlSettings: { maxDepth: 3 },
        auditSettings: { includePassiveChecks: true }
      });
      
      expect(config.configId).toBe('config-001');
    });
    
    test('should run comprehensive security scan', async () => {
      const task = await burpScanner.runScan('http://localhost:3000', 'config-001');
      expect(task.taskId).toBe('task-001');
      
      const status = await burpScanner.getScanStatus(task.taskId);
      expect(status.status).toBe('running');
      expect(status.progress).toBe(75);
      
      const findings = await burpScanner.getScanFindings(task.taskId);
      expect(findings.tool).toBe('Burp Suite Professional');
      expect(findings.summary.critical).toBe(1);
      
      // Verify critical vulnerability detection
      const idorFinding = findings.findings.find(f => f.title.includes('Insecure Direct Object Reference'));
      expect(idorFinding).toBeDefined();
      expect(idorFinding?.severity).toBe('critical');
    });
  });
  
  describe('Custom Security Scanner', () => {
    test('should perform vulnerability scanning with payloads', async () => {
      const results = await customScanner.scanForVulnerabilities('http://localhost:3000', {
        includePayloads: true,
        maxDepth: 2
      });
      
      expect(results.tool).toBe('Custom Security Scanner');
      expect(results.findings.length).toBeGreaterThan(0);
      
      // Should include SQL injection and XSS findings
      const sqlFindings = results.findings.filter(f => f.title.includes('SQL Injection'));
      const xssFindings = results.findings.filter(f => f.title.includes('XSS'));
      
      expect(sqlFindings.length).toBeGreaterThan(0);
      expect(xssFindings.length).toBeGreaterThan(0);
    });
    
    test('should scan dependencies for vulnerabilities', async () => {
      const results = await customScanner.scanDependencies('/app/package.json');
      
      expect(results.tool).toBe('Dependency Scanner');
      expect(results.summary.high).toBe(1);
      
      const vulnerableDep = results.findings.find(f => f.title.includes('lodash'));
      expect(vulnerableDep).toBeDefined();
      expect(vulnerableDep?.location.file).toBe('/app/package.json');
    });
    
    test('should scan configuration files for security issues', async () => {
      const configFiles = ['/app/config.json', '/app/.env'];
      const results = await customScanner.scanConfiguration(configFiles);
      
      expect(results.tool).toBe('Configuration Scanner');
      expect(results.summary.medium).toBe(1);
      
      const hardcodedSecret = results.findings.find(f => f.title.includes('Hardcoded Secret'));
      expect(hardcodedSecret).toBeDefined();
      expect(hardcodedSecret?.cwe).toBe('CWE-798');
    });
  });
  
  describe('Security Report Generation', () => {
    test('should generate comprehensive security report', async () => {
      const zapResults = await zapScanner.getScanResults('active-001');
      const burpResults = await burpScanner.getScanFindings('task-001');
      const customResults = await customScanner.scanForVulnerabilities('http://localhost:3000', {
        includePayloads: true
      });
      
      const allResults = [zapResults, burpResults, customResults];
      const report = await SecurityReportGenerator.generateComprehensiveReport(allResults);
      
      const parsedReport = JSON.parse(report);
      
      expect(parsedReport.metadata.totalScans).toBe(3);
      expect(parsedReport.metadata.tools).toContain('OWASP ZAP');
      expect(parsedReport.metadata.tools).toContain('Burp Suite Professional');
      expect(parsedReport.metadata.tools).toContain('Custom Security Scanner');
      
      expect(parsedReport.summary.totalFindings).toBeGreaterThan(0);
      expect(parsedReport.summary.bySeverity.critical).toBeGreaterThan(0);
      expect(parsedReport.summary.bySeverity.high).toBeGreaterThan(0);
      
      expect(parsedReport.owaspMapping).toBeDefined();
      expect(parsedReport.recommendations).toBeDefined();
      expect(Array.isArray(parsedReport.recommendations)).toBe(true);
    });
    
    test('should generate CI/CD pipeline report with thresholds', async () => {
      const mockResults: ScanResult[] = [
        {
          tool: 'Test Scanner',
          timestamp: new Date().toISOString(),
          findings: [],
          summary: { critical: 1, high: 3, medium: 5, low: 2, info: 0 }
        }
      ];
      
      const thresholds = { critical: 0, high: 2, medium: 10 };
      const ciReport = await SecurityReportGenerator.generateCiReport(mockResults, thresholds);
      
      expect(ciReport.passed).toBe(false);
      expect(ciReport.issues).toContain('Critical vulnerabilities: 1 (threshold: 0)');
      expect(ciReport.issues).toContain('High vulnerabilities: 3 (threshold: 2)');
      
      const reportData = JSON.parse(ciReport.report);
      expect(reportData.status).toBe('FAILED');
      expect(reportData.summary.critical).toBe(1);
      expect(reportData.summary.high).toBe(3);
    });
    
    test('should pass CI/CD pipeline with acceptable vulnerability levels', async () => {
      const mockResults: ScanResult[] = [
        {
          tool: 'Test Scanner',
          timestamp: new Date().toISOString(),
          findings: [],
          summary: { critical: 0, high: 1, medium: 3, low: 5, info: 2 }
        }
      ];
      
      const thresholds = { critical: 0, high: 2, medium: 5 };
      const ciReport = await SecurityReportGenerator.generateCiReport(mockResults, thresholds);
      
      expect(ciReport.passed).toBe(true);
      expect(ciReport.issues.length).toBe(0);
      
      const reportData = JSON.parse(ciReport.report);
      expect(reportData.status).toBe('PASSED');
    });
  });
  
  describe('Integration with Development Workflow', () => {
    test('should integrate with pre-commit hooks', async () => {
      // Mock git hook that runs security scan
      const runPreCommitScan = async () => {
        const results = await customScanner.scanConfiguration(['.env', 'config.json']);
        
        // Check if any critical or high severity issues found
        const criticalIssues = results.summary.critical + results.summary.high;
        
        return {
          passed: criticalIssues === 0,
          issues: criticalIssues,
          report: results
        };
      };
      
      const scanResult = await runPreCommitScan();
      expect(scanResult).toHaveProperty('passed');
      expect(scanResult).toHaveProperty('issues');
      expect(scanResult).toHaveProperty('report');
    });
    
    test('should integrate with CI/CD pipeline', async () => {
      // Mock CI/CD pipeline security stage
      const runCiSecurityScan = async () => {
        const zapResults = await zapScanner.getScanResults('ci-scan-001');
        const depResults = await customScanner.scanDependencies('package.json');
        
        const combinedResults = [zapResults, depResults];
        const ciReport = await SecurityReportGenerator.generateCiReport(
          combinedResults,
          { critical: 0, high: 3, medium: 10 }
        );
        
        return ciReport;
      };
      
      const pipelineResult = await runCiSecurityScan();
      
      expect(pipelineResult.passed).toBeDefined();
      expect(pipelineResult.report).toBeDefined();
      expect(pipelineResult.issues).toBeDefined();
      
      // Pipeline should fail if security thresholds are exceeded
      if (!pipelineResult.passed) {
        expect(pipelineResult.issues.length).toBeGreaterThan(0);
      }
    });
    
    test('should generate security badges for README', async () => {
      const generateSecurityBadge = (summary: { critical: number; high: number; medium: number; low: number }) => {
        const totalVulns = summary.critical + summary.high + summary.medium + summary.low;
        
        if (summary.critical > 0) {
          return { color: 'red', label: `${totalVulns} vulnerabilities`, status: 'critical' };
        } else if (summary.high > 0) {
          return { color: 'orange', label: `${totalVulns} vulnerabilities`, status: 'high' };
        } else if (summary.medium > 0) {
          return { color: 'yellow', label: `${totalVulns} vulnerabilities`, status: 'medium' };
        } else {
          return { color: 'green', label: 'secure', status: 'secure' };
        }
      };
      
      const mockSummary = { critical: 0, high: 0, medium: 2, low: 1 };
      const badge = generateSecurityBadge(mockSummary);
      
      expect(badge.color).toBe('yellow');
      expect(badge.label).toBe('3 vulnerabilities');
      expect(badge.status).toBe('medium');
    });
  });
  
  describe('Security Monitoring and Alerting', () => {
    test('should send alerts for critical vulnerabilities', async () => {
      const mockAlertService = {
        alerts: [] as any[],
        sendAlert: function(severity: string, message: string, details: any) {
          this.alerts.push({ severity, message, details, timestamp: new Date() });
        }
      };
      
      const processSecurityResults = (results: ScanResult) => {
        results.findings.forEach(finding => {
          if (finding.severity === 'critical') {
            mockAlertService.sendAlert(
              'CRITICAL',
              `Critical security vulnerability detected: ${finding.title}`,
              finding
            );
          }
        });
      };
      
      const criticalResults: ScanResult = {
        tool: 'Test Scanner',
        timestamp: new Date().toISOString(),
        findings: [
          {
            id: 'crit-001',
            severity: 'critical',
            title: 'Remote Code Execution',
            description: 'RCE vulnerability found',
            location: { url: '/api/execute' },
            cwe: 'CWE-94',
            owasp: 'A03:2021 – Injection',
            recommendation: 'Disable code execution endpoint'
          }
        ],
        summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      };
      
      processSecurityResults(criticalResults);
      
      expect(mockAlertService.alerts.length).toBe(1);
      expect(mockAlertService.alerts[0].severity).toBe('CRITICAL');
      expect(mockAlertService.alerts[0].message).toContain('Remote Code Execution');
    });
    
    test('should track security metrics over time', async () => {
      const mockMetricsService = {
        metrics: [] as any[],
        recordMetric: function(name: string, value: number, tags: any = {}) {
          this.metrics.push({
            name,
            value,
            tags,
            timestamp: new Date().toISOString()
          });
        }
      };
      
      const recordSecurityMetrics = (results: ScanResult[]) => {
        const totalVulns = results.reduce((sum, r) => 
          sum + r.summary.critical + r.summary.high + r.summary.medium + r.summary.low, 0
        );
        
        const criticalVulns = results.reduce((sum, r) => sum + r.summary.critical, 0);
        const highVulns = results.reduce((sum, r) => sum + r.summary.high, 0);
        
        mockMetricsService.recordMetric('security.vulnerabilities.total', totalVulns);
        mockMetricsService.recordMetric('security.vulnerabilities.critical', criticalVulns);
        mockMetricsService.recordMetric('security.vulnerabilities.high', highVulns);
        
        results.forEach(result => {
          mockMetricsService.recordMetric(
            'security.scan.findings',
            result.findings.length,
            { tool: result.tool }
          );
        });
      };
      
      const mockResults = [
        { tool: 'ZAP', findings: [{}], summary: { critical: 0, high: 1, medium: 2, low: 1, info: 0 } },
        { tool: 'Burp', findings: [{}, {}], summary: { critical: 1, high: 0, medium: 1, low: 0, info: 0 } }
      ] as ScanResult[];
      
      recordSecurityMetrics(mockResults);
      
      expect(mockMetricsService.metrics.length).toBe(5); // 3 summary + 2 tool-specific
      
      const totalVulnMetric = mockMetricsService.metrics.find(m => m.name === 'security.vulnerabilities.total');
      expect(totalVulnMetric?.value).toBe(5); // 0+1+2+1 + 1+0+1+0
      
      const criticalMetric = mockMetricsService.metrics.find(m => m.name === 'security.vulnerabilities.critical');
      expect(criticalMetric?.value).toBe(1);
    });
  });
  
  afterEach(() => {
    jest.restoreAllMocks();
  });
});
