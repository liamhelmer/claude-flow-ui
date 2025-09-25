#!/usr/bin/env node

/**
 * Test suite for Claude Flow UI environment variable support
 * Tests the environment variable configuration for claude-flow command line options
 */

const { spawn } = require('child_process');
const path = require('path');

const serverPath = path.join(__dirname, '..', 'unified-server.js');

// Color codes for output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  gray: '\x1b[90m'
};

// Test cases
const tests = [
  {
    name: 'PORT environment variable',
    env: { PORT: '3456' },
    expectedInOutput: 'Using PORT from environment: 3456',
    timeout: 3000
  },
  {
    name: 'TERMINAL_SIZE environment variable',
    env: { TERMINAL_SIZE: '140x50' },
    expectedInOutput: 'Using TERMINAL_SIZE from environment: 140x50',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_MODE environment variable',
    env: { CLAUDE_FLOW_MODE: 'sparc' },
    expectedInOutput: 'npx claude-flow sparc',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_PROMPT environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'chat',
      CLAUDE_FLOW_PROMPT: 'Tell me about neural networks'
    },
    expectedInOutput: 'npx claude-flow chat "Tell me about neural networks"',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_NEURAL environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'dev',
      CLAUDE_FLOW_NEURAL: 'true'
    },
    expectedInOutput: 'npx claude-flow dev --neural-enhanced',
    timeout: 5000  // Increased timeout for neural flag test
  },
  {
    name: 'CLAUDE_SPAWN=true environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'dev',
      CLAUDE_SPAWN: 'true'
    },
    expectedInOutput: 'npx claude-flow dev --claude',
    timeout: 3000
  },
  {
    name: 'CLAUDE_SPAWN=auto environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'sparc',
      CLAUDE_SPAWN: 'auto'
    },
    expectedInOutput: 'npx claude-flow sparc --auto-spawn',
    timeout: 3000
  },
  {
    name: 'CLAUDE_SPAWN=false environment variable (no flag)',
    env: {
      CLAUDE_FLOW_MODE: 'chat',
      CLAUDE_SPAWN: 'false'
    },
    expectedInOutput: 'npx claude-flow chat',
    notExpectedInOutput: '--claude',
    alsoNotExpectedInOutput: '--auto-spawn',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_SUBCOMMAND environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'sparc',
      CLAUDE_FLOW_SUBCOMMAND: 'tdd',
      CLAUDE_FLOW_PROMPT: 'Build API'
    },
    expectedInOutput: 'npx claude-flow sparc tdd "Build API"',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_ARGUMENTS environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'dev',
      CLAUDE_FLOW_PROMPT: 'Create service',
      CLAUDE_FLOW_ARGUMENTS: '--max-agents 5 --timeout 300'
    },
    expectedInOutput: 'npx claude-flow dev "Create service" --max-agents 5 --timeout 300',
    timeout: 3000
  },
  {
    name: 'Combined SUBCOMMAND and ARGUMENTS',
    env: {
      CLAUDE_FLOW_MODE: 'sparc',
      CLAUDE_FLOW_SUBCOMMAND: 'batch',
      CLAUDE_FLOW_PROMPT: 'Process data',
      CLAUDE_FLOW_ARGUMENTS: '--workers 4 --parallel',
      CLAUDE_FLOW_NEURAL: 'true'
    },
    expectedInOutput: 'npx claude-flow sparc batch "Process data" --workers 4 --parallel --neural-enhanced',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_TIMEOUT environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'dev',
      CLAUDE_FLOW_TIMEOUT: '600'
    },
    expectedInOutput: 'npx claude-flow dev --timeout 600',
    timeout: 3000
  },
  {
    name: 'HIVE_CONSENSUS_TYPE environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'hive-mind',
      HIVE_CONSENSUS_TYPE: 'majority'
    },
    expectedInOutput: 'npx claude-flow hive-mind --consensus majority',
    timeout: 3000
  },
  {
    name: 'HIVE_QUEEN_TYPE environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'hive-mind',
      HIVE_QUEEN_TYPE: 'strategic'
    },
    expectedInOutput: 'npx claude-flow hive-mind --queen-type strategic',
    timeout: 3000
  },
  {
    name: 'AUTO_SCALE_AGENTS environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'swarm',
      AUTO_SCALE_AGENTS: 'true'
    },
    expectedInOutput: 'npx claude-flow swarm --auto-scale',
    timeout: 3000
  },
  {
    name: 'HIVE_LOG_LEVEL debug with verbose',
    env: {
      CLAUDE_FLOW_MODE: 'hive-mind',
      HIVE_LOG_LEVEL: 'debug'
    },
    expectedInOutput: 'npx claude-flow hive-mind --log-level debug --verbose',
    timeout: 3000
  },
  {
    name: 'HIVE_LOG_LEVEL info without verbose',
    env: {
      CLAUDE_FLOW_MODE: 'hive-mind',
      HIVE_LOG_LEVEL: 'info'
    },
    expectedInOutput: 'npx claude-flow hive-mind --log-level info',
    notExpectedInOutput: '--verbose',
    timeout: 3000
  },
  {
    name: 'HIVE_MEMORY_SIZE environment variable',
    env: {
      CLAUDE_FLOW_MODE: 'hive-mind',
      HIVE_MEMORY_SIZE: '2048'
    },
    expectedInOutput: 'npx claude-flow hive-mind --memory-size 2048',
    timeout: 3000
  },
  {
    name: 'Complete hive-mind configuration',
    env: {
      CLAUDE_FLOW_MODE: 'hive-mind',
      CLAUDE_FLOW_SUBCOMMAND: 'coordinate',
      CLAUDE_FLOW_PROMPT: 'Build API',
      CLAUDE_FLOW_TIMEOUT: '1800',
      HIVE_CONSENSUS_TYPE: 'byzantine',
      HIVE_QUEEN_TYPE: 'adaptive',
      AUTO_SCALE_AGENTS: 'true',
      HIVE_LOG_LEVEL: 'debug',
      HIVE_MEMORY_SIZE: '4096',
      CLAUDE_FLOW_NEURAL: 'true'
    },
    expectedInOutput: 'npx claude-flow hive-mind coordinate "Build API" --timeout 1800 --consensus byzantine --queen-type adaptive --auto-scale --log-level debug --verbose --memory-size 4096 --neural-enhanced',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_INIT=true environment variable',
    env: {
      CLAUDE_FLOW_INIT: 'true',
      CLAUDE_FLOW_MODE: 'chat'
    },
    expectedInOutput: 'npx claude-flow init',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_INIT=force environment variable',
    env: {
      CLAUDE_FLOW_INIT: 'force',
      CLAUDE_FLOW_MODE: 'chat'
    },
    expectedInOutput: 'npx claude-flow init --force',
    timeout: 3000
  },
  {
    name: 'CLAUDE_FLOW_INIT=github environment variable',
    env: {
      CLAUDE_FLOW_INIT: 'github',
      CLAUDE_FLOW_MODE: 'chat'
    },
    expectedInOutput: 'npx claude-flow github init',
    timeout: 3000
  },
  {
    name: 'Combined environment variables',
    env: {
      CLAUDE_FLOW_MODE: 'sparc',
      CLAUDE_FLOW_PROMPT: 'Build a REST API',
      CLAUDE_FLOW_NEURAL: 'true'
    },
    expectedInOutput: 'npx claude-flow sparc "Build a REST API" --neural-enhanced',
    timeout: 3000
  },
  {
    name: 'Command line args override environment variables',
    env: {
      CLAUDE_FLOW_MODE: 'chat',
      CLAUDE_FLOW_PROMPT: 'env prompt'
    },
    args: ['--', 'dev', 'cli prompt'],
    expectedInOutput: 'npx claude-flow dev cli prompt',
    timeout: 3000
  },
  {
    name: 'PORT command line overrides environment',
    env: { PORT: '4000' },
    args: ['--port', '5000'],
    expectedInOutput: 'http://localhost:5000',
    notExpectedInOutput: 'Using PORT from environment',
    timeout: 3000
  },
  {
    name: 'TERMINAL_SIZE command line overrides environment',
    env: { TERMINAL_SIZE: '100x30' },
    args: ['--terminal-size', '180x60'],
    notExpectedInOutput: 'Using TERMINAL_SIZE from environment',
    timeout: 3000
  },
  {
    name: 'All server and claude-flow env variables combined',
    env: {
      PORT: '9090',
      TERMINAL_SIZE: '200x80',
      CLAUDE_FLOW_MODE: 'sparc',
      CLAUDE_FLOW_SUBCOMMAND: 'pipeline',
      CLAUDE_FLOW_PROMPT: 'Full test',
      CLAUDE_FLOW_ARGUMENTS: '--verbose --output json',
      CLAUDE_FLOW_NEURAL: 'true',
      CLAUDE_SPAWN: 'auto'
    },
    expectedInOutput: 'Using PORT from environment: 9090',
    alsoExpectedInOutput: 'Using TERMINAL_SIZE from environment: 200x80',
    timeout: 3000
  }
];

// Test runner
async function runTest(test) {
  return new Promise((resolve) => {
    console.log(`\n${colors.blue}Testing: ${test.name}${colors.reset}`);
    console.log(`${colors.gray}Environment: ${JSON.stringify(test.env)}${colors.reset}`);
    if (test.args) {
      console.log(`${colors.gray}Arguments: ${test.args.join(' ')}${colors.reset}`);
    }
    console.log(`${colors.gray}Expected: ${test.expectedInOutput}${colors.reset}`);

    const child = spawn('node', [serverPath, ...(test.args || [])], {
      env: { ...process.env, ...test.env },
      stdio: 'pipe'
    });

    let output = '';
    let initOutput = '';

    child.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;

      // Check for init commands
      if (text.includes('Running initialization commands') ||
          text.includes('Executing:') ||
          text.includes('Init Commands:')) {
        initOutput += text;
      }
    });

    child.stderr.on('data', (data) => {
      output += data.toString();
    });

    setTimeout(() => {
      child.kill();

      // Check for expected output
      let passed = true;

      // Check main expected output
      if (test.expectedInOutput) {
        if (!output.includes(test.expectedInOutput) &&
            !(test.expectedInOutput.includes('init') && initOutput.length > 0)) {
          passed = false;
        }
      }

      // Check additional expected output
      if (test.alsoExpectedInOutput && passed) {
        if (!output.includes(test.alsoExpectedInOutput)) {
          passed = false;
        }
      }

      // Check for output that should NOT be present
      if (test.notExpectedInOutput && passed) {
        if (output.includes(test.notExpectedInOutput)) {
          passed = false;
          console.log(`${colors.yellow}Found unexpected text: ${test.notExpectedInOutput}${colors.reset}`);
        }
      }

      // Check for additional output that should NOT be present
      if (test.alsoNotExpectedInOutput && passed) {
        if (output.includes(test.alsoNotExpectedInOutput)) {
          passed = false;
          console.log(`${colors.yellow}Found unexpected text: ${test.alsoNotExpectedInOutput}${colors.reset}`);
        }
      }

      if (passed) {
        console.log(`${colors.green}✓ PASSED${colors.reset}`);
        if (initOutput) {
          console.log(`${colors.gray}Init commands detected: Yes${colors.reset}`);
        }
      } else {
        console.log(`${colors.red}✗ FAILED${colors.reset}`);
        console.log(`${colors.yellow}Output did not contain expected text${colors.reset}`);
        console.log(`${colors.gray}Relevant output:\n${output.substring(0, 500)}${colors.reset}`);
      }

      resolve(passed);
    }, test.timeout);
  });
}

// Main test execution
async function runAllTests() {
  console.log(`${colors.blue}========================================${colors.reset}`);
  console.log(`${colors.blue}Claude Flow UI Environment Variable Tests${colors.reset}`);
  console.log(`${colors.blue}========================================${colors.reset}`);

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    const result = await runTest(test);
    if (result) {
      passed++;
    } else {
      failed++;
    }
  }

  console.log(`\n${colors.blue}========================================${colors.reset}`);
  console.log(`${colors.blue}Test Results${colors.reset}`);
  console.log(`${colors.blue}========================================${colors.reset}`);
  console.log(`${colors.green}Passed: ${passed}${colors.reset}`);
  console.log(`${colors.red}Failed: ${failed}${colors.reset}`);
  console.log(`${colors.gray}Total: ${tests.length}${colors.reset}`);

  if (failed === 0) {
    console.log(`\n${colors.green}All tests passed! 🎉${colors.reset}`);
    process.exit(0);
  } else {
    console.log(`\n${colors.red}Some tests failed. Please review the output above.${colors.reset}`);
    process.exit(1);
  }
}

// Run tests
runAllTests().catch(console.error);