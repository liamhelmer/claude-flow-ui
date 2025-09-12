#!/usr/bin/env node
/**
 * Edge Case Testing for Gitignore Patterns
 * Tests complex scenarios and edge cases
 */

const fs = require('fs');
const path = require('path');

class EdgeCaseValidator {
  constructor(gitignorePath) {
    this.gitignorePath = gitignorePath;
    this.patterns = this.loadPatterns();
  }

  loadPatterns() {
    try {
      const content = fs.readFileSync(this.gitignorePath, 'utf8');
      return content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    } catch (error) {
      console.error(`Error reading .gitignore: ${error.message}`);
      return [];
    }
  }

  // Advanced pattern matching with negation support
  shouldIgnore(filePath) {
    const normalizedPath = filePath.startsWith('./') ? filePath.substring(2) : filePath;
    let ignored = false;
    
    for (const pattern of this.patterns) {
      if (pattern.startsWith('!')) {
        // Negation pattern
        const negPattern = pattern.substring(1);
        if (this.matchesPattern(normalizedPath, negPattern)) {
          ignored = false; // Un-ignore this file
        }
      } else {
        if (this.matchesPattern(normalizedPath, pattern)) {
          ignored = true;
        }
      }
    }
    
    return ignored;
  }

  matchesPattern(filePath, pattern) {
    // Handle directory patterns ending with /
    if (pattern.endsWith('/')) {
      const dirPattern = pattern.slice(0, -1);
      // Match if the file is inside this directory
      return filePath.startsWith(dirPattern + '/') || filePath === dirPattern;
    }

    // Handle absolute patterns starting with /
    if (pattern.startsWith('/')) {
      const absolutePattern = pattern.substring(1);
      return this.globMatch(filePath, absolutePattern);
    }

    // Handle relative patterns - can match at any level
    const segments = filePath.split('/');
    for (let i = 0; i < segments.length; i++) {
      const subPath = segments.slice(i).join('/');
      if (this.globMatch(subPath, pattern)) {
        return true;
      }
    }

    return this.globMatch(filePath, pattern);
  }

  globMatch(str, pattern) {
    // Convert glob pattern to regex
    let regex = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '[^/]*')
      .replace(/\*\*/g, '.*');
    
    return new RegExp(`^${regex}$`).test(str);
  }

  testEdgeCases() {
    const edgeCases = [
      // Test negation patterns
      { 
        path: 'memory/sessions/README.md', 
        shouldIgnore: false, 
        description: 'README.md should be un-ignored by !memory/sessions/README.md'
      },
      { 
        path: 'memory/agents/README.md', 
        shouldIgnore: false, 
        description: 'README.md should be un-ignored by !memory/agents/README.md'
      },
      
      // Test nested directories
      { 
        path: 'deep/nested/memory/sessions/data.json', 
        shouldIgnore: true, 
        description: 'Nested memory/sessions should still be ignored'
      },
      { 
        path: 'coordination/memory_bank/deep/nested/file.json', 
        shouldIgnore: true, 
        description: 'Deep nested files in coordination should be ignored'
      },
      
      // Test database files in various locations
      { 
        path: 'src/data.db', 
        shouldIgnore: true, 
        description: 'Database files anywhere should be ignored'
      },
      { 
        path: 'tests/fixtures/test.sqlite', 
        shouldIgnore: true, 
        description: 'SQLite files anywhere should be ignored'
      },
      
      // Test executables
      { 
        path: 'bin/claude-flow', 
        shouldIgnore: true, 
        description: 'claude-flow executable anywhere should be ignored'
      },
      { 
        path: 'scripts/claude-flow.bat', 
        shouldIgnore: true, 
        description: 'claude-flow.bat anywhere should be ignored'
      },
      
      // Test hive-mind prompts
      { 
        path: 'temp/hive-mind-prompt-abc123.txt', 
        shouldIgnore: true, 
        description: 'Hive-mind prompts anywhere should be ignored'
      },
      
      // Test files that should NOT be ignored
      { 
        path: 'src/claude-integration.js', 
        shouldIgnore: false, 
        description: 'Source files mentioning claude should not be ignored'
      },
      { 
        path: 'docs/claude-flow-guide.md', 
        shouldIgnore: false, 
        description: 'Documentation should not be ignored'
      },
      { 
        path: 'tests/claude-flow-unit.test.js', 
        shouldIgnore: false, 
        description: 'Test files should not be ignored'
      },
      
      // Test similar but different patterns
      { 
        path: 'claude-flow-config.json', 
        shouldIgnore: false, 
        description: 'Different from claude-flow.config.json should not be ignored'
      },
      { 
        path: 'my-claude-flow', 
        shouldIgnore: false, 
        description: 'Files containing claude-flow but not exact match'
      },
      
      // Test case sensitivity
      { 
        path: 'CLAUDE-FLOW.CONFIG.JSON', 
        shouldIgnore: false, 
        description: 'Case sensitivity test - should not be ignored'
      },
    ];

    const results = {
      passed: 0,
      failed: 0,
      details: []
    };

    console.log('🔬 Testing Edge Cases\n');
    console.log('='.repeat(60));

    edgeCases.forEach(testCase => {
      const actualIgnore = this.shouldIgnore(testCase.path);
      const passed = actualIgnore === testCase.shouldIgnore;
      
      results.details.push({
        path: testCase.path,
        expected: testCase.shouldIgnore,
        actual: actualIgnore,
        passed,
        description: testCase.description
      });

      const status = passed ? '✅' : '❌';
      const action = testCase.shouldIgnore ? 'ignored' : 'tracked';
      const actualAction = actualIgnore ? 'ignored' : 'tracked';
      
      console.log(`${status} ${testCase.path}`);
      console.log(`   Expected: ${action}, Got: ${actualAction}`);
      console.log(`   Test: ${testCase.description}`);
      
      if (!passed) {
        console.log(`   ❌ FAILED: Pattern mismatch detected`);
      }
      console.log('');

      if (passed) results.passed++;
      else results.failed++;
    });

    return results;
  }

  analyzePatternCoverage() {
    console.log('\n📋 Pattern Coverage Analysis');
    console.log('='.repeat(50));
    
    const patternAnalysis = {
      claudeFlow: [],
      databases: [],
      directories: [],
      executables: [],
      negations: []
    };

    this.patterns.forEach(pattern => {
      if (pattern.includes('claude-flow') || pattern.includes('hive-mind')) {
        patternAnalysis.claudeFlow.push(pattern);
      }
      if (pattern.includes('.db') || pattern.includes('.sqlite')) {
        patternAnalysis.databases.push(pattern);
      }
      if (pattern.endsWith('/')) {
        patternAnalysis.directories.push(pattern);
      }
      if (pattern === 'claude-flow' || pattern.endsWith('.bat') || pattern.endsWith('.ps1')) {
        patternAnalysis.executables.push(pattern);
      }
      if (pattern.startsWith('!')) {
        patternAnalysis.negations.push(pattern);
      }
    });

    console.log(`📁 Directory Patterns (${patternAnalysis.directories.length}):`);
    patternAnalysis.directories.forEach(p => console.log(`   - ${p}`));
    
    console.log(`\n🔧 Claude-Flow Patterns (${patternAnalysis.claudeFlow.length}):`);
    patternAnalysis.claudeFlow.forEach(p => console.log(`   - ${p}`));
    
    console.log(`\n💾 Database Patterns (${patternAnalysis.databases.length}):`);
    patternAnalysis.databases.forEach(p => console.log(`   - ${p}`));
    
    console.log(`\n⚡ Executable Patterns (${patternAnalysis.executables.length}):`);
    patternAnalysis.executables.forEach(p => console.log(`   - ${p}`));
    
    console.log(`\n↩️  Negation Patterns (${patternAnalysis.negations.length}):`);
    patternAnalysis.negations.forEach(p => console.log(`   - ${p}`));

    return patternAnalysis;
  }

  generateDetailedReport() {
    console.log('\n🔬 DETAILED EDGE CASE VALIDATION REPORT');
    console.log('='.repeat(60));
    
    const edgeResults = this.testEdgeCases();
    const coverage = this.analyzePatternCoverage();
    
    console.log(`\n📊 Edge Case Test Results:`);
    console.log(`   ✅ Passed: ${edgeResults.passed}`);
    console.log(`   ❌ Failed: ${edgeResults.failed}`);
    console.log(`   📈 Success Rate: ${((edgeResults.passed / (edgeResults.passed + edgeResults.failed)) * 100).toFixed(1)}%`);
    
    if (edgeResults.failed > 0) {
      console.log(`\n❌ Failed Edge Cases:`);
      edgeResults.details
        .filter(detail => !detail.passed)
        .forEach(detail => {
          console.log(`   - ${detail.path}`);
          console.log(`     Expected: ${detail.expected ? 'ignored' : 'tracked'}`);
          console.log(`     Actual: ${detail.actual ? 'ignored' : 'tracked'}`);
          console.log(`     Issue: ${detail.description}`);
        });
    }

    console.log(`\n🎯 Critical Recommendations:`);
    
    if (edgeResults.failed === 0) {
      console.log(`   ✨ All edge cases passed! Patterns are robust.`);
    } else {
      console.log(`   🔧 ${edgeResults.failed} edge cases failed - review pattern logic`);
      
      // Specific recommendations based on failures
      const negationFailures = edgeResults.details.filter(d => 
        !d.passed && d.path.includes('README.md') && d.expected === false
      );
      
      if (negationFailures.length > 0) {
        console.log(`   📝 Negation patterns may need adjustment for README files`);
      }
    }

    return {
      edgeResults,
      coverage,
      overallHealth: edgeResults.failed === 0
    };
  }
}

// Run edge case validation
const validator = new EdgeCaseValidator('.gitignore');
const report = validator.generateDetailedReport();

process.exit(report.overallHealth ? 0 : 1);