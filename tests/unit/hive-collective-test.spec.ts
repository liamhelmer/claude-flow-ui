/**
 * Hive Mind Collective Unit Tests
 * Testing Agent Integration Tests for Swarm Coordination
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { hiveTest } from '../utils/hive-testing-framework';

describe('Hive Mind Collective Testing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  hiveTest.createCoordinatedSuite('Agent Output Validation', (hooks) => {
    it('should validate researcher agent output structure', async () => {
      const mockResearcherOutput = {
        analysis: 'Comprehensive market research completed',
        findings: ['Finding 1', 'Finding 2'],
        recommendations: ['Rec 1', 'Rec 2'],
        confidence: 0.85,
        sources: ['source1.com', 'source2.org']
      };

      const criteria = {
        requiredFields: ['analysis', 'findings', 'recommendations', 'confidence'],
        typeValidation: {
          analysis: 'string',
          findings: 'object',
          recommendations: 'object',
          confidence: 'number'
        },
        contentRules: [
          {
            validator: (output) => output.confidence >= 0 && output.confidence <= 1,
            message: 'Confidence should be between 0 and 1',
            severity: 10
          },
          {
            validator: (output) => Array.isArray(output.findings) && output.findings.length > 0,
            message: 'Findings should be a non-empty array',
            severity: 15
          }
        ]
      };

      const result = hiveTest.validateAgentOutput(mockResearcherOutput, criteria);
      
      expect(result.passed).toBe(true);
      expect(result.score).toBe(100);
      expect(result.issues).toHaveLength(0);

      await hooks.storeResult('validation/researcher-output', result);
    });

    it('should validate coder agent output structure', async () => {
      const mockCoderOutput = {
        implementation: 'function calculate() { return 42; }',
        tests: ['test1.spec.js', 'test2.spec.js'],
        documentation: 'Function calculates the answer to everything',
        complexity: 'low',
        coverage: 95
      };

      const criteria = {
        requiredFields: ['implementation', 'tests', 'documentation'],
        typeValidation: {
          implementation: 'string',
          tests: 'object',
          documentation: 'string',
          coverage: 'number'
        },
        contentRules: [
          {
            validator: (output) => output.coverage >= 80,
            message: 'Code coverage should be at least 80%',
            severity: 20
          },
          {
            validator: (output) => output.implementation.length > 0,
            message: 'Implementation cannot be empty',
            severity: 25
          }
        ]
      };

      const result = hiveTest.validateAgentOutput(mockCoderOutput, criteria);
      
      expect(result.passed).toBe(true);
      expect(result.score).toBe(100);

      await hooks.storeResult('validation/coder-output', result);
    });

    it('should detect and fail invalid agent outputs', async () => {
      const invalidOutput = {
        // Missing required fields
        partialData: 'incomplete'
      };

      const criteria = {
        requiredFields: ['analysis', 'findings', 'confidence'],
        typeValidation: {
          confidence: 'number'
        }
      };

      const result = hiveTest.validateAgentOutput(invalidOutput, criteria);
      
      expect(result.passed).toBe(false);
      expect(result.score).toBeLessThan(100);
      expect(result.issues).toContain('Missing required field: analysis');
      expect(result.issues).toContain('Missing required field: findings');
      expect(result.issues).toContain('Missing required field: confidence');

      await hooks.storeResult('validation/invalid-output', result);
    });
  });

  hiveTest.createCoordinatedSuite('Performance Testing', (hooks) => {
    it('should benchmark agent response time', async () => {
      const mockAgentOperation = async () => {
        // Simulate agent processing time
        await new Promise(resolve => setTimeout(resolve, 50));
        return { result: 'processed', timestamp: Date.now() };
      };

      const thresholds = {
        maxAverageMs: 100,
        iterations: 5
      };

      const result = await hiveTest.benchmarkPerformance(mockAgentOperation, thresholds);
      
      expect(result.passed).toBe(true);
      expect(result.average).toBeLessThan(100);
      expect(result.iterations).toBe(5);

      await hooks.storeResult('performance/agent-response-time', result);
    });

    it('should fail slow operations', async () => {
      const slowOperation = async () => {
        await new Promise(resolve => setTimeout(resolve, 150));
        return { result: 'slow' };
      };

      const thresholds = {
        maxAverageMs: 100,
        iterations: 3
      };

      const result = await hiveTest.benchmarkPerformance(slowOperation, thresholds);
      
      expect(result.passed).toBe(false);
      expect(result.average).toBeGreaterThan(100);

      await hooks.storeResult('performance/slow-operation', result);
    });
  });

  hiveTest.createCoordinatedSuite('Security Validation', (hooks) => {
    it('should detect XSS vulnerabilities', async () => {
      const maliciousInput = { query: '<script>alert("xss")</script>' };
      const unsafeOutput = '<div><script>alert("xss")</script></div>';

      const result = hiveTest.validateSecurity(maliciousInput, unsafeOutput);
      
      expect(result.passed).toBe(false);
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].type).toBe('XSS');
      expect(result.vulnerabilities[0].severity).toBe('HIGH');

      await hooks.storeResult('security/xss-detection', result);
    });

    it('should detect SQL injection patterns', async () => {
      const maliciousInput = { 
        username: "admin'; DROP TABLE users; --",
        query: "SELECT * FROM data WHERE id = 1 UNION SELECT * FROM secrets"
      };
      const output = 'Query processed successfully';

      const result = hiveTest.validateSecurity(maliciousInput, output);
      
      expect(result.passed).toBe(false);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities.some(v => v.type === 'SQL_INJECTION')).toBe(true);

      await hooks.storeResult('security/sql-injection-detection', result);
    });

    it('should detect sensitive data exposure', async () => {
      const input = { user: 'test' };
      const exposedOutput = {
        user: 'test',
        debug: 'api_key="secret123", password="admin123"'
      };

      const result = hiveTest.validateSecurity(input, exposedOutput);
      
      expect(result.passed).toBe(false);
      expect(result.vulnerabilities.some(v => v.type === 'DATA_EXPOSURE')).toBe(true);

      await hooks.storeResult('security/data-exposure-detection', result);
    });

    it('should pass clean secure outputs', async () => {
      const input = { query: 'normal search term' };
      const output = { results: ['item1', 'item2'], count: 2 };

      const result = hiveTest.validateSecurity(input, output);
      
      expect(result.passed).toBe(true);
      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.securityScore).toBe(100);

      await hooks.storeResult('security/clean-output', result);
    });
  });

  hiveTest.createCoordinatedSuite('Integration Testing', (hooks) => {
    it('should test hive memory coordination', async () => {
      const testData = {
        agentId: 'test-agent',
        operation: 'memory-test',
        data: { key: 'value', timestamp: Date.now() }
      };

      // Store and retrieve from hive memory
      await hooks.storeResult('integration/memory-test', testData);
      
      // Verify the operation completed
      expect(testData.agentId).toBe('test-agent');
      expect(testData.operation).toBe('memory-test');
    });

    it('should test cross-agent communication patterns', async () => {
      const communicationLog = {
        from: 'researcher',
        to: 'coder',
        message: 'Requirements analysis complete',
        payload: { specs: ['spec1', 'spec2'], priority: 'high' },
        timestamp: new Date().toISOString()
      };

      await hooks.storeResult('integration/cross-agent-comm', communicationLog);

      expect(communicationLog.from).toBe('researcher');
      expect(communicationLog.to).toBe('coder');
      expect(communicationLog.payload.specs).toHaveLength(2);
    });
  });

  hiveTest.createCoordinatedSuite('Edge Case Testing', (hooks) => {
    it('should handle empty agent outputs gracefully', async () => {
      const emptyOutput = {};
      const criteria = {
        requiredFields: [],
        typeValidation: {},
        contentRules: []
      };

      const result = hiveTest.validateAgentOutput(emptyOutput, criteria);
      
      expect(result.passed).toBe(true);
      expect(result.score).toBe(100);

      await hooks.storeResult('edge-cases/empty-output', result);
    });

    it('should handle malformed data structures', async () => {
      const malformedData = null;
      const criteria = {
        requiredFields: ['data']
      };

      const result = hiveTest.validateAgentOutput(malformedData, criteria);
      
      expect(result.passed).toBe(false);
      expect(result.issues.length).toBeGreaterThan(0);

      await hooks.storeResult('edge-cases/malformed-data', result);
    });

    it('should handle very large data sets', async () => {
      const largeDataset = {
        data: new Array(10000).fill(0).map((_, i) => ({ id: i, value: `item${i}` })),
        metadata: { size: 10000, type: 'large-dataset' }
      };

      const result = hiveTest.validateAgentOutput(largeDataset, {
        requiredFields: ['data', 'metadata'],
        contentRules: [
          {
            validator: (output) => Array.isArray(output.data) && output.data.length > 0,
            message: 'Data should be a non-empty array'
          }
        ]
      });

      expect(result.passed).toBe(true);
      expect(result.score).toBe(100);

      await hooks.storeResult('edge-cases/large-dataset', { 
        passed: result.passed, 
        dataSize: largeDataset.data.length 
      });
    });
  });
});