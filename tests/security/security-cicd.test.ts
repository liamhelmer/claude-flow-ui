/**
 * Security CI/CD Pipeline Integration Tests
 *
 * Comprehensive tests for integrating security into CI/CD pipelines including:
 * - Pre-commit security hooks
 * - Continuous security scanning
 * - Security gate enforcement
 * - Vulnerability management workflow
 * - Security metrics and reporting
 * - Automated security remediation
 * - Compliance validation
 */

import { test, expect, describe, beforeEach, afterEach, jest } from '@jest/globals';
import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';

interface SecurityGate {
  name: string;
  enabled: boolean;
  thresholds: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  blockOnFailure: boolean;
  notifyOnFailure: boolean;
}

interface PipelineStage {
  name: string;
  order: number;
  parallel: boolean;
  dependencies: string[];
  securityChecks: SecurityCheck[];
}

interface SecurityCheck {
  name: string;
  tool: string;
  command: string;
  timeout: number;
  retryOnFailure: boolean;
  outputFormat: 'json' | 'xml' | 'sarif';
}

interface SecurityMetrics {
  timestamp: string;
  buildId: string;
  branch: string;
  commit: string;
  vulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  coverage: {
    sast: number;
    dast: number;
    dependency: number;
    container: number;
  };
  scanDuration: number;
  fixedVulnerabilities: number;
  newVulnerabilities: number;
}

class SecurityPipelineManager {
  private securityGates: SecurityGate[] = [];
  private pipelineStages: PipelineStage[] = [];
  private metrics: SecurityMetrics[] = [];
  
  /**
   * Configure security gates for the pipeline
   */
  configureSecurityGates(): SecurityGate[] {
    this.securityGates = [
      {
        name: 'pre-commit',
        enabled: true,
        thresholds: { critical: 0, high: 0, medium: 5, low: 20 },
        blockOnFailure: true,
        notifyOnFailure: true
      },
      {
        name: 'build',
        enabled: true,
        thresholds: { critical: 0, high: 2, medium: 10, low: 50 },
        blockOnFailure: true,
        notifyOnFailure: true
      },
      {
        name: 'staging',
        enabled: true,
        thresholds: { critical: 0, high: 1, medium: 5, low: 20 },
        blockOnFailure: true,
        notifyOnFailure: true
      },
      {
        name: 'production',
        enabled: true,
        thresholds: { critical: 0, high: 0, medium: 2, low: 10 },
        blockOnFailure: true,
        notifyOnFailure: true
      }
    ];
    
    return this.securityGates;
  }
  
  /**
   * Define security pipeline stages
   */
  definePipelineStages(): PipelineStage[] {
    this.pipelineStages = [
      {
        name: 'static-analysis',
        order: 1,
        parallel: false,
        dependencies: [],
        securityChecks: [
          {
            name: 'SAST Scan',
            tool: 'semgrep',
            command: 'semgrep --config=security --json --output=sast-results.json',
            timeout: 300000,
            retryOnFailure: false,
            outputFormat: 'json'
          },
          {
            name: 'Secret Detection',
            tool: 'truffleHog',
            command: 'trufflehog --json --output=secrets-results.json',
            timeout: 180000,
            retryOnFailure: false,
            outputFormat: 'json'
          },
          {
            name: 'License Compliance',
            tool: 'license-checker',
            command: 'license-checker --json --output=license-results.json',
            timeout: 120000,
            retryOnFailure: false,
            outputFormat: 'json'
          }
        ]
      },
      {
        name: 'dependency-analysis',
        order: 2,
        parallel: true,
        dependencies: [],
        securityChecks: [
          {
            name: 'NPM Audit',
            tool: 'npm-audit',
            command: 'npm audit --json --output=npm-audit-results.json',
            timeout: 180000,
            retryOnFailure: true,
            outputFormat: 'json'
          },
          {
            name: 'Snyk Scan',
            tool: 'snyk',
            command: 'snyk test --json --output=snyk-results.json',
            timeout: 300000,
            retryOnFailure: true,
            outputFormat: 'json'
          },
          {
            name: 'OWASP Dependency Check',
            tool: 'dependency-check',
            command: 'dependency-check --scan . --format JSON --out dependency-check-report.json',
            timeout: 600000,
            retryOnFailure: false,
            outputFormat: 'json'
          }
        ]
      },
      {
        name: 'container-security',
        order: 3,
        parallel: true,
        dependencies: ['build'],
        securityChecks: [
          {
            name: 'Container Image Scan',
            tool: 'trivy',
            command: 'trivy image --format json --output trivy-results.json myapp:latest',
            timeout: 300000,
            retryOnFailure: false,
            outputFormat: 'json'
          },
          {
            name: 'Dockerfile Security',
            tool: 'hadolint',
            command: 'hadolint --format json Dockerfile > hadolint-results.json',
            timeout: 60000,
            retryOnFailure: false,
            outputFormat: 'json'
          }
        ]
      },
      {
        name: 'dynamic-analysis',
        order: 4,
        parallel: false,
        dependencies: ['deploy-staging'],
        securityChecks: [
          {
            name: 'DAST Scan',
            tool: 'zap',
            command: 'zap-baseline.py -t https://staging.app.com -J zap-results.json',
            timeout: 1800000,
            retryOnFailure: false,
            outputFormat: 'json'
          },
          {
            name: 'API Security Test',
            tool: 'postman',
            command: 'newman run security-tests.json --reporters json --reporter-json-export api-security-results.json',
            timeout: 300000,
            retryOnFailure: true,
            outputFormat: 'json'
          }
        ]
      }
    ];
    
    return this.pipelineStages;
  }
  
  /**
   * Evaluate security gate
   */
  async evaluateSecurityGate(
    gateName: string,
    vulnerabilities: { critical: number; high: number; medium: number; low: number }
  ): Promise<{ passed: boolean; reasons: string[]; recommendations: string[] }> {
    const gate = this.securityGates.find(g => g.name === gateName);
    
    if (!gate || !gate.enabled) {
      return { passed: true, reasons: [], recommendations: [] };
    }
    
    const reasons: string[] = [];
    const recommendations: string[] = [];
    let passed = true;
    
    if (vulnerabilities.critical > gate.thresholds.critical) {
      passed = false;
      reasons.push(`Critical vulnerabilities: ${vulnerabilities.critical} (limit: ${gate.thresholds.critical})`);
      recommendations.push('Address all critical vulnerabilities before proceeding');
    }
    
    if (vulnerabilities.high > gate.thresholds.high) {
      passed = false;
      reasons.push(`High vulnerabilities: ${vulnerabilities.high} (limit: ${gate.thresholds.high})`);
      recommendations.push('Reduce high-severity vulnerabilities');
    }
    
    if (vulnerabilities.medium > gate.thresholds.medium) {
      passed = false;
      reasons.push(`Medium vulnerabilities: ${vulnerabilities.medium} (limit: ${gate.thresholds.medium})`);
      recommendations.push('Consider addressing medium-severity vulnerabilities');
    }
    
    if (vulnerabilities.low > gate.thresholds.low) {
      passed = false;
      reasons.push(`Low vulnerabilities: ${vulnerabilities.low} (limit: ${gate.thresholds.low})`);
      recommendations.push('Review and address low-severity vulnerabilities');
    }
    
    return { passed, reasons, recommendations };
  }
  
  /**
   * Execute security checks for a pipeline stage
   */
  async executeSecurityChecks(stageName: string): Promise<{
    success: boolean;
    results: { [checkName: string]: any };
    metrics: SecurityMetrics;
  }> {
    const stage = this.pipelineStages.find(s => s.name === stageName);
    
    if (!stage) {
      throw new Error(`Stage ${stageName} not found`);
    }
    
    const startTime = Date.now();
    const results: { [checkName: string]: any } = {};
    let totalVulnerabilities = { critical: 0, high: 0, medium: 0, low: 0 };
    
    // Execute security checks (mocked for testing)
    for (const check of stage.securityChecks) {
      try {
        // Mock security check execution
        const mockResult = this.mockSecurityCheckResult(check.name);
        results[check.name] = mockResult;
        
        // Aggregate vulnerabilities
        if (mockResult.vulnerabilities) {
          totalVulnerabilities.critical += mockResult.vulnerabilities.critical || 0;
          totalVulnerabilities.high += mockResult.vulnerabilities.high || 0;
          totalVulnerabilities.medium += mockResult.vulnerabilities.medium || 0;
          totalVulnerabilities.low += mockResult.vulnerabilities.low || 0;
        }
      } catch (error) {
        results[check.name] = {
          success: false,
          error: error.message,
          vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }
        };
      }
    }
    
    const endTime = Date.now();
    const scanDuration = endTime - startTime;
    
    const metrics: SecurityMetrics = {
      timestamp: new Date().toISOString(),
      buildId: 'build-123',
      branch: 'main',
      commit: 'abc123',
      vulnerabilities: {
        total: totalVulnerabilities.critical + totalVulnerabilities.high + totalVulnerabilities.medium + totalVulnerabilities.low,
        ...totalVulnerabilities
      },
      coverage: {
        sast: stageName.includes('static') ? 85 : 0,
        dast: stageName.includes('dynamic') ? 75 : 0,
        dependency: stageName.includes('dependency') ? 95 : 0,
        container: stageName.includes('container') ? 80 : 0
      },
      scanDuration,
      fixedVulnerabilities: Math.floor(Math.random() * 5),
      newVulnerabilities: totalVulnerabilities.critical + totalVulnerabilities.high
    };
    
    this.metrics.push(metrics);
    
    return {
      success: Object.values(results).every(r => r.success !== false),
      results,
      metrics
    };
  }
  
  /**
   * Mock security check result for testing
   */
  private mockSecurityCheckResult(checkName: string): any {
    const mockResults: { [key: string]: any } = {
      'SAST Scan': {
        success: true,
        vulnerabilities: { critical: 0, high: 1, medium: 3, low: 5 },
        findings: [
          {
            rule: 'javascript.lang.security.audit.xss.template-string-concatenation.template-string-concatenation',
            severity: 'high',
            message: 'Potential XSS vulnerability',
            file: 'src/components/UserProfile.tsx',
            line: 45
          }
        ]
      },
      'Secret Detection': {
        success: true,
        vulnerabilities: { critical: 1, high: 0, medium: 0, low: 0 },
        findings: [
          {
            type: 'AWS Access Key',
            severity: 'critical',
            file: '.env.example',
            line: 3,
            entropy: 4.5
          }
        ]
      },
      'NPM Audit': {
        success: true,
        vulnerabilities: { critical: 0, high: 2, medium: 4, low: 8 },
        advisories: [
          {
            id: 1096735,
            title: 'Regular Expression Denial of Service in lodash',
            severity: 'high',
            module_name: 'lodash',
            vulnerable_versions: '<4.17.21'
          }
        ]
      },
      'Container Image Scan': {
        success: true,
        vulnerabilities: { critical: 0, high: 1, medium: 2, low: 3 },
        findings: [
          {
            vulnerability_id: 'CVE-2023-12345',
            severity: 'high',
            package: 'openssl',
            installed_version: '1.1.1k',
            fixed_version: '1.1.1m'
          }
        ]
      },
      'DAST Scan': {
        success: true,
        vulnerabilities: { critical: 0, high: 0, medium: 1, low: 2 },
        alerts: [
          {
            alert: 'Missing X-Content-Type-Options Header',
            risk: 'medium',
            confidence: 'medium',
            url: 'https://staging.app.com/api/data'
          }
        ]
      }
    };
    
    return mockResults[checkName] || {
      success: true,
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      findings: []
    };
  }
  
  /**
   * Generate security compliance report
   */
  generateComplianceReport(): {
    overallScore: number;
    compliance: { [standard: string]: { score: number; requirements: any[] } };
    recommendations: string[];
  } {
    const compliance = {
      'OWASP Top 10': {
        score: 85,
        requirements: [
          { id: 'A01', name: 'Broken Access Control', status: 'compliant', score: 90 },
          { id: 'A02', name: 'Cryptographic Failures', status: 'compliant', score: 95 },
          { id: 'A03', name: 'Injection', status: 'partial', score: 75 },
          { id: 'A04', name: 'Insecure Design', status: 'compliant', score: 85 },
          { id: 'A05', name: 'Security Misconfiguration', status: 'non-compliant', score: 60 }
        ]
      },
      'PCI DSS': {
        score: 78,
        requirements: [
          { id: '1', name: 'Install and maintain firewalls', status: 'compliant', score: 95 },
          { id: '2', name: 'Change default passwords', status: 'compliant', score: 100 },
          { id: '3', name: 'Protect stored cardholder data', status: 'partial', score: 70 },
          { id: '4', name: 'Encrypt transmission of data', status: 'compliant', score: 90 }
        ]
      },
      'SOC 2': {
        score: 82,
        requirements: [
          { id: 'CC1', name: 'Control Environment', status: 'compliant', score: 85 },
          { id: 'CC2', name: 'Communication and Information', status: 'compliant', score: 80 },
          { id: 'CC3', name: 'Risk Assessment', status: 'partial', score: 75 }
        ]
      }
    };
    
    const overallScore = Object.values(compliance).reduce((sum, c) => sum + c.score, 0) / Object.keys(compliance).length;
    
    const recommendations = [
      'Address injection vulnerabilities to improve OWASP A03 compliance',
      'Review security configuration to meet OWASP A05 requirements',
      'Implement additional data protection measures for PCI DSS requirement 3',
      'Enhance risk assessment processes for SOC 2 CC3 compliance'
    ];
    
    return { overallScore, compliance, recommendations };
  }
  
  /**
   * Generate security metrics dashboard data
   */
  generateSecurityDashboard(): any {
    const latestMetrics = this.metrics[this.metrics.length - 1] || {
      vulnerabilities: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      coverage: { sast: 0, dast: 0, dependency: 0, container: 0 }
    };
    
    return {
      summary: {
        totalVulnerabilities: latestMetrics.vulnerabilities.total,
        criticalVulnerabilities: latestMetrics.vulnerabilities.critical,
        highVulnerabilities: latestMetrics.vulnerabilities.high,
        securityScore: this.calculateSecurityScore(latestMetrics.vulnerabilities),
        trend: this.calculateTrend()
      },
      coverage: latestMetrics.coverage,
      recentScans: this.metrics.slice(-10),
      topVulnerabilities: this.getTopVulnerabilities(),
      remediationQueue: this.getRemediationQueue()
    };
  }
  
  private calculateSecurityScore(vulns: { critical: number; high: number; medium: number; low: number }): number {
    const baseScore = 100;
    const penalties = {
      critical: 20,
      high: 10,
      medium: 5,
      low: 1
    };
    
    const penalty = vulns.critical * penalties.critical +
                   vulns.high * penalties.high +
                   vulns.medium * penalties.medium +
                   vulns.low * penalties.low;
    
    return Math.max(0, baseScore - penalty);
  }
  
  private calculateTrend(): 'improving' | 'stable' | 'degrading' {
    if (this.metrics.length < 2) return 'stable';
    
    const recent = this.metrics.slice(-2);
    const oldScore = this.calculateSecurityScore(recent[0].vulnerabilities);
    const newScore = this.calculateSecurityScore(recent[1].vulnerabilities);
    
    if (newScore > oldScore) return 'improving';
    if (newScore < oldScore) return 'degrading';
    return 'stable';
  }
  
  private getTopVulnerabilities(): any[] {
    return [
      {
        id: 'VULN-001',
        title: 'SQL Injection in User Search',
        severity: 'high',
        component: 'API',
        age: 7,
        occurrences: 3
      },
      {
        id: 'VULN-002',
        title: 'XSS in Comment System',
        severity: 'medium',
        component: 'Frontend',
        age: 14,
        occurrences: 2
      }
    ];
  }
  
  private getRemediationQueue(): any[] {
    return [
      {
        id: 'REM-001',
        vulnerability: 'VULN-001',
        priority: 'high',
        assignee: 'security-team',
        estimatedEffort: '2 days',
        status: 'in-progress'
      },
      {
        id: 'REM-002',
        vulnerability: 'VULN-002',
        priority: 'medium',
        assignee: 'frontend-team',
        estimatedEffort: '4 hours',
        status: 'planned'
      }
    ];
  }
}

class SecurityNotificationManager {
  private notifications: any[] = [];
  
  async sendSecurityAlert(alert: {
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    buildId: string;
    branch: string;
    recipients: string[];
  }): Promise<void> {
    // Mock notification sending
    this.notifications.push({
      ...alert,
      timestamp: new Date().toISOString(),
      sent: true
    });
  }
  
  getNotifications(): any[] {
    return this.notifications;
  }
  
  clearNotifications(): void {
    this.notifications = [];
  }
}

describe('Security CI/CD Pipeline Integration Test Suite', () => {
  let pipelineManager: SecurityPipelineManager;
  let notificationManager: SecurityNotificationManager;
  
  beforeEach(() => {
    pipelineManager = new SecurityPipelineManager();
    notificationManager = new SecurityNotificationManager();
    jest.clearAllMocks();
  });
  
  describe('Security Gate Configuration', () => {
    test('should configure security gates for different pipeline stages', () => {
      const gates = pipelineManager.configureSecurityGates();
      
      expect(gates.length).toBe(4);
      expect(gates.map(g => g.name)).toEqual(['pre-commit', 'build', 'staging', 'production']);
      
      // Production gate should have strictest thresholds
      const prodGate = gates.find(g => g.name === 'production');
      expect(prodGate?.thresholds.critical).toBe(0);
      expect(prodGate?.thresholds.high).toBe(0);
      expect(prodGate?.blockOnFailure).toBe(true);
      
      // Pre-commit gate should allow more medium/low vulnerabilities
      const preCommitGate = gates.find(g => g.name === 'pre-commit');
      expect(preCommitGate?.thresholds.medium).toBe(5);
      expect(preCommitGate?.thresholds.low).toBe(20);
    });
    
    test('should evaluate security gates correctly', async () => {
      pipelineManager.configureSecurityGates();
      
      // Test passing gate
      const passingResult = await pipelineManager.evaluateSecurityGate('build', {
        critical: 0,
        high: 1,
        medium: 5,
        low: 25
      });
      
      expect(passingResult.passed).toBe(true);
      expect(passingResult.reasons).toHaveLength(0);
      
      // Test failing gate
      const failingResult = await pipelineManager.evaluateSecurityGate('production', {
        critical: 1,
        high: 2,
        medium: 10,
        low: 50
      });
      
      expect(failingResult.passed).toBe(false);
      expect(failingResult.reasons).toContain('Critical vulnerabilities: 1 (limit: 0)');
      expect(failingResult.reasons).toContain('High vulnerabilities: 2 (limit: 0)');
      expect(failingResult.recommendations).toContain('Address all critical vulnerabilities before proceeding');
    });
  });
  
  describe('Pipeline Stage Execution', () => {
    test('should define comprehensive security pipeline stages', () => {
      const stages = pipelineManager.definePipelineStages();
      
      expect(stages.length).toBe(4);
      expect(stages.map(s => s.name)).toEqual([
        'static-analysis',
        'dependency-analysis',
        'container-security',
        'dynamic-analysis'
      ]);
      
      // Static analysis should run first
      const staticStage = stages.find(s => s.name === 'static-analysis');
      expect(staticStage?.order).toBe(1);
      expect(staticStage?.securityChecks.length).toBe(3);
      expect(staticStage?.securityChecks.map(c => c.name)).toContain('SAST Scan');
      
      // Dynamic analysis should depend on staging deployment
      const dynamicStage = stages.find(s => s.name === 'dynamic-analysis');
      expect(dynamicStage?.dependencies).toContain('deploy-staging');
      expect(dynamicStage?.securityChecks.map(c => c.name)).toContain('DAST Scan');
    });
    
    test('should execute security checks for static analysis stage', async () => {
      pipelineManager.definePipelineStages();
      
      const result = await pipelineManager.executeSecurityChecks('static-analysis');
      
      expect(result.success).toBe(true);
      expect(result.results).toHaveProperty('SAST Scan');
      expect(result.results).toHaveProperty('Secret Detection');
      expect(result.results).toHaveProperty('License Compliance');
      
      // Should detect critical secret
      expect(result.results['Secret Detection'].vulnerabilities.critical).toBe(1);
      
      // Should have scan metrics
      expect(result.metrics.timestamp).toBeDefined();
      expect(result.metrics.vulnerabilities.total).toBeGreaterThan(0);
      expect(result.metrics.coverage.sast).toBeGreaterThan(0);
    });
    
    test('should execute dependency analysis with multiple tools', async () => {
      pipelineManager.definePipelineStages();
      
      const result = await pipelineManager.executeSecurityChecks('dependency-analysis');
      
      expect(result.success).toBe(true);
      expect(result.results).toHaveProperty('NPM Audit');
      expect(result.results).toHaveProperty('Snyk Scan');
      expect(result.results).toHaveProperty('OWASP Dependency Check');
      
      // NPM Audit should find vulnerabilities
      const npmResult = result.results['NPM Audit'];
      expect(npmResult.vulnerabilities.high).toBe(2);
      expect(npmResult.advisories).toBeDefined();
      expect(Array.isArray(npmResult.advisories)).toBe(true);
    });
    
    test('should execute container security scanning', async () => {
      pipelineManager.definePipelineStages();
      
      const result = await pipelineManager.executeSecurityChecks('container-security');
      
      expect(result.success).toBe(true);
      expect(result.results).toHaveProperty('Container Image Scan');
      expect(result.results).toHaveProperty('Dockerfile Security');
      
      // Container scan should find vulnerabilities
      const containerResult = result.results['Container Image Scan'];
      expect(containerResult.vulnerabilities.high).toBe(1);
      expect(containerResult.findings).toBeDefined();
    });
    
    test('should execute dynamic analysis after deployment', async () => {
      pipelineManager.definePipelineStages();
      
      const result = await pipelineManager.executeSecurityChecks('dynamic-analysis');
      
      expect(result.success).toBe(true);
      expect(result.results).toHaveProperty('DAST Scan');
      expect(result.results).toHaveProperty('API Security Test');
      
      // DAST should find medium severity issues
      const dastResult = result.results['DAST Scan'];
      expect(dastResult.vulnerabilities.medium).toBe(1);
      expect(dastResult.alerts).toBeDefined();
      expect(result.metrics.coverage.dast).toBeGreaterThan(0);
    });
  });
  
  describe('Security Notifications and Alerting', () => {
    test('should send alerts for critical vulnerabilities', async () => {
      await notificationManager.sendSecurityAlert({
        severity: 'critical',
        title: 'Critical Security Vulnerability Detected',
        description: 'SQL injection vulnerability found in user authentication',
        buildId: 'build-123',
        branch: 'main',
        recipients: ['security-team@company.com', 'dev-team@company.com']
      });
      
      const notifications = notificationManager.getNotifications();
      expect(notifications.length).toBe(1);
      expect(notifications[0].severity).toBe('critical');
      expect(notifications[0].sent).toBe(true);
      expect(notifications[0].recipients).toContain('security-team@company.com');
    });
    
    test('should integrate with security gate failures', async () => {
      pipelineManager.configureSecurityGates();
      
      const gateResult = await pipelineManager.evaluateSecurityGate('production', {
        critical: 2,
        high: 1,
        medium: 3,
        low: 5
      });
      
      if (!gateResult.passed) {
        await notificationManager.sendSecurityAlert({
          severity: 'critical',
          title: 'Production Security Gate Failed',
          description: `Security gate failed: ${gateResult.reasons.join(', ')}`,
          buildId: 'build-456',
          branch: 'release/v1.2.0',
          recipients: ['security-team@company.com', 'release-manager@company.com']
        });
      }
      
      const notifications = notificationManager.getNotifications();
      expect(notifications.length).toBe(1);
      expect(notifications[0].title).toContain('Production Security Gate Failed');
    });
  });
  
  describe('Security Metrics and Reporting', () => {
    test('should generate comprehensive security dashboard', async () => {
      // Execute multiple security checks to generate metrics
      pipelineManager.definePipelineStages();
      await pipelineManager.executeSecurityChecks('static-analysis');
      await pipelineManager.executeSecurityChecks('dependency-analysis');
      
      const dashboard = pipelineManager.generateSecurityDashboard();
      
      expect(dashboard.summary).toBeDefined();
      expect(dashboard.summary.totalVulnerabilities).toBeGreaterThan(0);
      expect(dashboard.summary.securityScore).toBeLessThan(100);
      expect(['improving', 'stable', 'degrading']).toContain(dashboard.summary.trend);
      
      expect(dashboard.coverage).toBeDefined();
      expect(dashboard.coverage.sast).toBeGreaterThan(0);
      expect(dashboard.coverage.dependency).toBeGreaterThan(0);
      
      expect(dashboard.topVulnerabilities).toBeDefined();
      expect(Array.isArray(dashboard.topVulnerabilities)).toBe(true);
      
      expect(dashboard.remediationQueue).toBeDefined();
      expect(Array.isArray(dashboard.remediationQueue)).toBe(true);
    });
    
    test('should generate security compliance report', () => {
      const complianceReport = pipelineManager.generateComplianceReport();
      
      expect(complianceReport.overallScore).toBeGreaterThan(0);
      expect(complianceReport.overallScore).toBeLessThanOrEqual(100);
      
      expect(complianceReport.compliance).toHaveProperty('OWASP Top 10');
      expect(complianceReport.compliance).toHaveProperty('PCI DSS');
      expect(complianceReport.compliance).toHaveProperty('SOC 2');
      
      // Check OWASP compliance details
      const owaspCompliance = complianceReport.compliance['OWASP Top 10'];
      expect(owaspCompliance.score).toBeGreaterThan(0);
      expect(owaspCompliance.requirements.length).toBe(5);
      
      const injectionReq = owaspCompliance.requirements.find(r => r.id === 'A03');
      expect(injectionReq?.name).toBe('Injection');
      expect(injectionReq?.status).toBe('partial');
      
      expect(complianceReport.recommendations).toBeDefined();
      expect(Array.isArray(complianceReport.recommendations)).toBe(true);
      expect(complianceReport.recommendations.length).toBeGreaterThan(0);
    });
    
    test('should track security metrics over time', async () => {
      pipelineManager.definePipelineStages();
      
      // Execute multiple security checks to generate time-series data
      const results = [];
      for (let i = 0; i < 3; i++) {
        const result = await pipelineManager.executeSecurityChecks('static-analysis');
        results.push(result.metrics);
      }
      
      expect(results.length).toBe(3);
      
      results.forEach((metrics, index) => {
        expect(metrics.timestamp).toBeDefined();
        expect(metrics.buildId).toBeDefined();
        expect(metrics.vulnerabilities.total).toBeGreaterThan(0);
        expect(metrics.scanDuration).toBeGreaterThan(0);
        expect(typeof metrics.newVulnerabilities).toBe('number');
        expect(typeof metrics.fixedVulnerabilities).toBe('number');
      });
    });
  });
  
  describe('Integration with Development Workflow', () => {
    test('should integrate with pre-commit hooks', async () => {
      pipelineManager.configureSecurityGates();
      
      const runPreCommitSecurityCheck = async () => {
        // Mock pre-commit security check
        const vulnerabilities = { critical: 0, high: 0, medium: 2, low: 3 };
        const gateResult = await pipelineManager.evaluateSecurityGate('pre-commit', vulnerabilities);
        
        if (!gateResult.passed) {
          throw new Error(`Pre-commit security check failed: ${gateResult.reasons.join(', ')}`);
        }
        
        return { passed: true, vulnerabilities };
      };
      
      const result = await runPreCommitSecurityCheck();
      expect(result.passed).toBe(true);
      expect(result.vulnerabilities.medium).toBe(2);
    });
    
    test('should fail pre-commit on critical vulnerabilities', async () => {
      pipelineManager.configureSecurityGates();
      
      const runPreCommitWithCritical = async () => {
        const vulnerabilities = { critical: 1, high: 0, medium: 0, low: 0 };
        const gateResult = await pipelineManager.evaluateSecurityGate('pre-commit', vulnerabilities);
        
        if (!gateResult.passed) {
          throw new Error(`Pre-commit blocked: ${gateResult.reasons.join(', ')}`);
        }
        
        return gateResult;
      };
      
      await expect(runPreCommitWithCritical()).rejects.toThrow('Pre-commit blocked');
    });
    
    test('should integrate with pull request checks', async () => {
      const runPrSecurityCheck = async (prBranch: string) => {
        pipelineManager.definePipelineStages();
        
        // Run security checks for PR
        const staticResult = await pipelineManager.executeSecurityChecks('static-analysis');
        const depResult = await pipelineManager.executeSecurityChecks('dependency-analysis');
        
        const totalVulns = {
          critical: staticResult.metrics.vulnerabilities.critical + depResult.metrics.vulnerabilities.critical,
          high: staticResult.metrics.vulnerabilities.high + depResult.metrics.vulnerabilities.high,
          medium: staticResult.metrics.vulnerabilities.medium + depResult.metrics.vulnerabilities.medium,
          low: staticResult.metrics.vulnerabilities.low + depResult.metrics.vulnerabilities.low
        };
        
        const buildGateResult = await pipelineManager.evaluateSecurityGate('build', totalVulns);
        
        return {
          branch: prBranch,
          securityChecksPassed: buildGateResult.passed,
          vulnerabilities: totalVulns,
          recommendations: buildGateResult.recommendations
        };
      };
      
      const prResult = await runPrSecurityCheck('feature/user-authentication');
      
      expect(prResult.branch).toBe('feature/user-authentication');
      expect(typeof prResult.securityChecksPassed).toBe('boolean');
      expect(prResult.vulnerabilities).toBeDefined();
      expect(prResult.vulnerabilities.critical).toBeDefined();
    });
  });
  
  describe('Automated Remediation', () => {
    test('should generate automated fix suggestions', () => {
      const generateFixSuggestions = (vulnerability: any) => {
        const fixes: { [key: string]: any } = {
          'SQL Injection': {
            type: 'code_fix',
            description: 'Use parameterized queries',
            automatedFix: {
              pattern: /query\s*=\s*['"].*?\$\{.*?\}.*?['"]/g,
              replacement: 'Use prepared statements with parameter binding',
              confidence: 'high'
            },
            examples: [
              'Before: query = `SELECT * FROM users WHERE id = ${userId}`',
              'After: query = "SELECT * FROM users WHERE id = ?"; db.query(query, [userId])'
            ]
          },
          'Missing Security Headers': {
            type: 'config_fix',
            description: 'Add security headers middleware',
            automatedFix: {
              file: 'middleware/security.js',
              content: `
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});
`,
              confidence: 'medium'
            }
          },
          'Vulnerable Dependency': {
            type: 'dependency_update',
            description: 'Update vulnerable package',
            automatedFix: {
              package: 'lodash',
              currentVersion: '4.17.15',
              fixedVersion: '4.17.21',
              updateCommand: 'npm install lodash@4.17.21',
              confidence: 'high'
            }
          }
        };
        
        return fixes[vulnerability.type] || {
          type: 'manual_review',
          description: 'Manual review required',
          confidence: 'low'
        };
      };
      
      const sqlVuln = { type: 'SQL Injection', severity: 'high' };
      const headerVuln = { type: 'Missing Security Headers', severity: 'medium' };
      const depVuln = { type: 'Vulnerable Dependency', severity: 'high' };
      
      const sqlFix = generateFixSuggestions(sqlVuln);
      const headerFix = generateFixSuggestions(headerVuln);
      const depFix = generateFixSuggestions(depVuln);
      
      expect(sqlFix.type).toBe('code_fix');
      expect(sqlFix.automatedFix.confidence).toBe('high');
      
      expect(headerFix.type).toBe('config_fix');
      expect(headerFix.automatedFix.file).toBe('middleware/security.js');
      
      expect(depFix.type).toBe('dependency_update');
      expect(depFix.automatedFix.updateCommand).toBe('npm install lodash@4.17.21');
    });
    
    test('should create automated pull requests for fixes', async () => {
      const createAutomatedPR = async (vulnerabilities: any[]) => {
        const autoFixableVulns = vulnerabilities.filter(v => 
          ['Vulnerable Dependency', 'Missing Security Headers'].includes(v.type)
        );
        
        if (autoFixableVulns.length === 0) {
          return null;
        }
        
        const prData = {
          title: `Security: Automated fixes for ${autoFixableVulns.length} vulnerabilities`,
          description: `This PR contains automated fixes for the following security issues:\n\n${autoFixableVulns.map(v => `- ${v.type}: ${v.description}`).join('\n')}`,
          branch: `security/automated-fixes-${Date.now()}`,
          files: autoFixableVulns.map(v => ({
            path: v.file || 'package.json',
            content: v.fixContent || 'automated fix content'
          })),
          labels: ['security', 'automated-fix'],
          reviewers: ['security-team']
        };
        
        return prData;
      };
      
      const vulnerabilities = [
        {
          type: 'Vulnerable Dependency',
          description: 'Update lodash to fix ReDOS vulnerability',
          file: 'package.json',
          fixContent: '"lodash": "^4.17.21"'
        },
        {
          type: 'Missing Security Headers',
          description: 'Add X-Content-Type-Options header',
          file: 'middleware/security.js',
          fixContent: 'res.setHeader(\'X-Content-Type-Options\', \'nosniff\');'
        },
        {
          type: 'SQL Injection',
          description: 'Manual review required for SQL injection',
          file: 'api/users.js'
        }
      ];
      
      const pr = await createAutomatedPR(vulnerabilities);
      
      expect(pr).toBeDefined();
      expect(pr?.title).toContain('Automated fixes for 2 vulnerabilities');
      expect(pr?.files.length).toBe(2);
      expect(pr?.labels).toContain('security');
      expect(pr?.reviewers).toContain('security-team');
    });
  });
  
  afterEach(() => {
    jest.restoreAllMocks();
    notificationManager.clearNotifications();
  });
});
