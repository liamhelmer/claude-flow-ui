#!/usr/bin/env node
/**
 * Gitignore Pattern Validation Script
 * Tests gitignore patterns against actual file patterns
 */

const fs = require('fs');
const path = require('path');

class GitignoreValidator {
  constructor(gitignorePath) {
    this.gitignorePath = gitignorePath;
    this.patterns = [];
    this.loadPatterns();
  }

  loadPatterns() {
    try {
      const content = fs.readFileSync(this.gitignorePath, 'utf8');
      this.patterns = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    } catch (error) {
      console.error(`Error reading .gitignore: ${error.message}`);
      process.exit(1);
    }
  }

  // Convert gitignore pattern to regex
  patternToRegex(pattern) {
    let regex = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    
    if (pattern.startsWith('/')) {
      regex = '^' + regex.substring(1);
    } else {
      regex = '(^|.*/|^.*/?)' + regex;
    }
    
    if (pattern.endsWith('/')) {
      regex += '.*';
    } else {
      regex += '(/.*)?$';
    }
    
    return new RegExp(regex);
  }

  // Test if a file path should be ignored
  shouldIgnore(filePath) {
    const normalizedPath = filePath.startsWith('./') ? filePath.substring(2) : filePath;
    
    for (const pattern of this.patterns) {
      if (pattern.startsWith('!')) {
        // Negation pattern - if it matches, don't ignore
        const negPattern = pattern.substring(1);
        const negRegex = this.patternToRegex(negPattern);
        if (negRegex.test(normalizedPath)) {
          return false;
        }
      } else {
        const regex = this.patternToRegex(pattern);
        if (regex.test(normalizedPath)) {
          return true;
        }
      }
    }
    return false;
  }

  // Test specific patterns
  testPatterns() {
    const testCases = [
      // Claude Flow files that SHOULD be ignored
      { path: 'claude-flow.config.json', shouldIgnore: true },
      { path: '.swarm/memory.db', shouldIgnore: true },
      { path: '.hive-mind/sessions/test.json', shouldIgnore: true },
      { path: 'memory/claude-flow-data.json', shouldIgnore: true },
      { path: 'memory/sessions/session-123.json', shouldIgnore: true },
      { path: 'memory/agents/agent-456.json', shouldIgnore: true },
      { path: 'coordination/memory_bank/data.json', shouldIgnore: true },
      { path: 'coordination/subtasks/task.json', shouldIgnore: true },
      { path: 'coordination/orchestration/orch.json', shouldIgnore: true },
      { path: 'test.db', shouldIgnore: true },
      { path: 'data.sqlite', shouldIgnore: true },
      { path: 'claude-flow', shouldIgnore: true },
      { path: 'claude-flow.bat', shouldIgnore: true },
      { path: 'claude-flow.ps1', shouldIgnore: true },
      { path: 'hive-mind-prompt-123.txt', shouldIgnore: true },
      { path: '.claude/settings.local.json', shouldIgnore: true },
      { path: '.mcp.json', shouldIgnore: true },

      // Files that should NOT be ignored
      { path: 'memory/sessions/README.md', shouldIgnore: false },
      { path: 'memory/agents/README.md', shouldIgnore: false },
      { path: 'src/components/test.js', shouldIgnore: false },
      { path: 'package.json', shouldIgnore: false },
      { path: 'README.md', shouldIgnore: false },
      { path: 'tests/claude-flow-tests.js', shouldIgnore: false },
      { path: 'docs/claude-integration.md', shouldIgnore: false },
    ];

    const results = {
      passed: 0,
      failed: 0,
      details: []
    };

    console.log('🧪 Testing Gitignore Patterns\n');
    console.log('='.repeat(50));

    testCases.forEach(testCase => {
      const actualIgnore = this.shouldIgnore(testCase.path);
      const passed = actualIgnore === testCase.shouldIgnore;
      
      results.details.push({
        path: testCase.path,
        expected: testCase.shouldIgnore,
        actual: actualIgnore,
        passed
      });

      if (passed) {
        results.passed++;
        console.log(`✅ ${testCase.path} - ${testCase.shouldIgnore ? 'ignored' : 'tracked'} correctly`);
      } else {
        results.failed++;
        console.log(`❌ ${testCase.path} - expected ${testCase.shouldIgnore ? 'ignored' : 'tracked'}, got ${actualIgnore ? 'ignored' : 'tracked'}`);
      }
    });

    return results;
  }

  // Validate gitignore syntax
  validateSyntax() {
    const issues = [];
    
    this.patterns.forEach((pattern, index) => {
      const lineNum = index + 1;
      
      // Check for common syntax issues
      if (pattern.includes('//')) {
        issues.push(`Line ${lineNum}: Double slashes in pattern "${pattern}"`);
      }
      
      if (pattern.startsWith('**/') && pattern.length === 3) {
        issues.push(`Line ${lineNum}: Incomplete glob pattern "${pattern}"`);
      }
      
      if (pattern.includes(' ') && !pattern.includes('\\ ')) {
        issues.push(`Line ${lineNum}: Unescaped space in pattern "${pattern}"`);
      }
    });

    return issues;
  }

  // Generate validation report
  generateReport() {
    console.log('\n📊 GITIGNORE VALIDATION REPORT');
    console.log('='.repeat(50));
    
    const testResults = this.testPatterns();
    const syntaxIssues = this.validateSyntax();
    
    console.log(`\n📈 Test Results:`);
    console.log(`  ✅ Passed: ${testResults.passed}`);
    console.log(`  ❌ Failed: ${testResults.failed}`);
    console.log(`  📊 Total: ${testResults.passed + testResults.failed}`);
    console.log(`  🎯 Success Rate: ${((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)}%`);
    
    if (syntaxIssues.length > 0) {
      console.log(`\n⚠️  Syntax Issues Found:`);
      syntaxIssues.forEach(issue => console.log(`  - ${issue}`));
    } else {
      console.log(`\n✅ No syntax issues detected`);
    }
    
    if (testResults.failed > 0) {
      console.log(`\n❌ Failed Test Cases:`);
      testResults.details
        .filter(detail => !detail.passed)
        .forEach(detail => {
          console.log(`  - ${detail.path}: expected ${detail.expected ? 'ignored' : 'tracked'}, got ${detail.actual ? 'ignored' : 'tracked'}`);
        });
    }

    // Recommendations
    console.log(`\n💡 Recommendations:`);
    if (testResults.failed === 0 && syntaxIssues.length === 0) {
      console.log(`  ✨ Gitignore patterns are working perfectly!`);
    } else {
      if (testResults.failed > 0) {
        console.log(`  🔧 Review failed pattern matches and adjust rules`);
      }
      if (syntaxIssues.length > 0) {
        console.log(`  📝 Fix syntax issues for better pattern matching`);
      }
    }

    return {
      testResults,
      syntaxIssues,
      overallSuccess: testResults.failed === 0 && syntaxIssues.length === 0
    };
  }
}

// Run validation
const validator = new GitignoreValidator('.gitignore');
const report = validator.generateReport();

// Exit with appropriate code
process.exit(report.overallSuccess ? 0 : 1);