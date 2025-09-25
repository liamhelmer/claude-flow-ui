/**
 * Utility functions for claude-flow command construction
 * Handles environment variable configuration and command building
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

/**
 * Get the appropriate claude-flow command based on environment variables
 * @returns {string} The claude-flow command to use
 */
function getClaudeFlowCommand() {
  // Check CLAUDE_FLOW_ALPHA environment variable
  const useAlpha = process.env.CLAUDE_FLOW_ALPHA;

  if (useAlpha && (useAlpha.toLowerCase() === 'true' || useAlpha === '1' || useAlpha.toLowerCase() === 'yes')) {
    return 'npx claude-flow@alpha';
  }

  // Default to stable version
  return 'npx claude-flow';
}

/**
 * Build a complete claude-flow command with arguments
 * @param {string[]} args - Arguments to pass to claude-flow
 * @returns {string} Complete command string
 */
function buildClaudeFlowCommand(args = []) {
  const baseCommand = getClaudeFlowCommand();

  if (args.length === 0) {
    return baseCommand;
  }

  const allArgs = args.join(' ');
  return `${baseCommand} ${allArgs}`;
}

/**
 * Build an array of command parts for spawn/exec functions
 * @param {string[]} args - Arguments to pass to claude-flow
 * @returns {object} Object with command and args array
 */
function buildClaudeFlowCommandArray(args = []) {
  const baseCommand = getClaudeFlowCommand();

  if (baseCommand.startsWith('npx ')) {
    // For npx commands, split into npx and the package
    const packageName = baseCommand.substring(4); // Remove 'npx '
    return {
      command: 'npx',
      args: [packageName, ...args]
    };
  }

  // For direct commands
  return {
    command: baseCommand,
    args: args
  };
}

/**
 * Check if claude-flow initialization is needed
 * Looks for .claude-flow directory, .claude directory, and CLAUDE.md file
 * @param {string} workingDir - Directory to check (defaults to current working directory)
 * @returns {boolean} true if initialization is needed
 */
function needsClaudeFlowInit(workingDir = process.cwd()) {
  const claudeFlowDir = path.join(workingDir, '.claude-flow');
  const claudeDir = path.join(workingDir, '.claude');
  const claudeMdFile = path.join(workingDir, 'CLAUDE.md');

  // Check if any of the expected files/directories exist
  const hasClaudeFlowDir = fs.existsSync(claudeFlowDir) && fs.statSync(claudeFlowDir).isDirectory();
  const hasClaudeDir = fs.existsSync(claudeDir) && fs.statSync(claudeDir).isDirectory();
  const hasClaudeMd = fs.existsSync(claudeMdFile) && fs.statSync(claudeMdFile).isFile();

  // If none exist, initialization is needed
  return !hasClaudeFlowDir && !hasClaudeDir && !hasClaudeMd;
}

/**
 * Run claude-flow init automatically
 * @param {string} workingDir - Directory to run init in (defaults to current working directory)
 * @returns {Promise<boolean>} true if initialization succeeded
 */
async function runClaudeFlowInit(workingDir = process.cwd()) {
  return new Promise((resolve, reject) => {
    const baseCommand = getClaudeFlowCommand();
    const { command, args } = buildClaudeFlowCommandArray(['init']);

    console.log(`[AutoInit] 🚀 Running claude-flow init in ${workingDir}...`);
    console.log(`[AutoInit] Command: ${command} ${args.join(' ')}`);

    const initProcess = spawn(command, args, {
      cwd: workingDir,
      stdio: 'pipe',
      env: process.env
    });

    let stdout = '';
    let stderr = '';

    initProcess.stdout.on('data', (data) => {
      const output = data.toString();
      stdout += output;
      console.log(`[AutoInit] ${output.trim()}`);
    });

    initProcess.stderr.on('data', (data) => {
      const output = data.toString();
      stderr += output;
      // Only log non-warning stderr
      if (!output.includes('ExperimentalWarning')) {
        console.log(`[AutoInit] ${output.trim()}`);
      }
    });

    initProcess.on('close', (code) => {
      if (code === 0) {
        console.log(`[AutoInit] ✅ claude-flow init completed successfully`);
        resolve(true);
      } else {
        console.error(`[AutoInit] ❌ claude-flow init failed with exit code ${code}`);
        if (stderr) {
          console.error(`[AutoInit] Error output: ${stderr}`);
        }
        resolve(false); // Don't reject, just return false
      }
    });

    initProcess.on('error', (error) => {
      console.error(`[AutoInit] ❌ Failed to spawn claude-flow init: ${error.message}`);
      resolve(false); // Don't reject, just return false
    });

    // Set a timeout for init process
    setTimeout(() => {
      if (!initProcess.killed) {
        console.log(`[AutoInit] ⏰ Init process timed out, killing...`);
        initProcess.kill('SIGTERM');
        resolve(false);
      }
    }, 30000); // 30 second timeout
  });
}

/**
 * Handle auto-initialization if needed
 * @param {string} workingDir - Directory to check and init (defaults to current working directory)
 * @returns {Promise<boolean>} true if auto-init ran successfully or wasn't needed
 */
async function handleAutoInit(workingDir = process.cwd()) {
  if (needsClaudeFlowInit(workingDir)) {
    console.log(`[AutoInit] 🔍 Claude-flow initialization files not found in ${workingDir}`);
    console.log(`[AutoInit] 📋 Checking for: .claude-flow/, .claude/, CLAUDE.md`);
    return await runClaudeFlowInit(workingDir);
  } else {
    console.log(`[AutoInit] ✅ Claude-flow already initialized (found existing files)`);
    return true;
  }
}

/**
 * Get init commands with proper claude-flow version
 * @param {string} initType - Type of init command
 * @param {string} workingDir - Directory to check for auto init (defaults to current working directory)
 * @returns {Promise<string[]>} Array of init command strings (async for auto mode)
 */
async function getInitCommands(initType, workingDir = process.cwd()) {
  const baseCommand = getClaudeFlowCommand();
  const commands = [];

  switch (initType?.toLowerCase()) {
    case 'true':
      commands.push(`${baseCommand} init`);
      break;
    case 'force':
      commands.push(`${baseCommand} init --force`);
      break;
    case 'github':
      commands.push(`${baseCommand} init`);
      commands.push(`${baseCommand} github init`);
      break;
    case 'auto':
      // Handle auto initialization
      const autoInitSuccess = await handleAutoInit(workingDir);
      if (autoInitSuccess) {
        console.log(`[AutoInit] 🎉 Auto-initialization completed successfully`);
      } else {
        console.log(`[AutoInit] ⚠️ Auto-initialization failed or was skipped`);
      }
      // Don't return commands for auto mode since we handle it directly
      break;
    default:
      // No init commands
      break;
  }

  return commands;
}

/**
 * Log the claude-flow version being used
 */
function logClaudeFlowVersion() {
  const command = getClaudeFlowCommand();
  const isAlpha = command.includes('@alpha');

  if (isAlpha) {
    console.log('🔬 Using claude-flow@alpha (CLAUDE_FLOW_ALPHA=true)');
  } else {
    console.log('✅ Using claude-flow stable version');
  }
}

module.exports = {
  getClaudeFlowCommand,
  buildClaudeFlowCommand,
  buildClaudeFlowCommandArray,
  getInitCommands,
  logClaudeFlowVersion,
  needsClaudeFlowInit,
  runClaudeFlowInit,
  handleAutoInit
};