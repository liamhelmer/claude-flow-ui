#!/usr/bin/env node

/**
 * Diagnostic script for tmux issues
 * Run this to check tmux configuration and permissions
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('🔍 Claude Flow UI - Tmux Diagnostics\n');
console.log('='.repeat(50));

// Check tmux installation
function checkTmux() {
  return new Promise((resolve) => {
    const tmux = spawn('tmux', ['-V'], { stdio: 'pipe' });
    let output = '';
    
    tmux.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    tmux.on('exit', (code) => {
      if (code === 0) {
        console.log(`✅ Tmux installed: ${output.trim()}`);
        resolve(true);
      } else {
        console.error('❌ Tmux not found or not accessible');
        resolve(false);
      }
    });
    
    tmux.on('error', () => {
      console.error('❌ Failed to run tmux command');
      resolve(false);
    });
  });
}

// Check socket directories
function checkSocketDirs() {
  console.log('\n📁 Socket Directories:');
  
  const dirs = [
    path.join(os.tmpdir(), '.claude-flow-tmux'),
    path.join(os.tmpdir(), '.claude-flow-sockets'),
    path.join('/tmp', '.claude-flow-tmux'),
    path.join('/tmp', '.claude-flow-sockets')
  ];
  
  dirs.forEach(dir => {
    if (fs.existsSync(dir)) {
      const stats = fs.statSync(dir);
      const files = fs.readdirSync(dir);
      console.log(`  ✅ ${dir}`);
      console.log(`     Permissions: ${(stats.mode & parseInt('777', 8)).toString(8)}`);
      console.log(`     Files: ${files.length} socket(s)`);
      if (files.length > 0) {
        files.slice(0, 3).forEach(file => {
          console.log(`       - ${file}`);
        });
        if (files.length > 3) {
          console.log(`       ... and ${files.length - 3} more`);
        }
      }
    } else {
      console.log(`  ⚠️  ${dir} (does not exist)`);
    }
  });
}

// Check temp directory permissions
function checkTempDir() {
  console.log('\n🔐 Temp Directory Permissions:');
  
  const tmpDir = os.tmpdir();
  const stats = fs.statSync(tmpDir);
  console.log(`  Directory: ${tmpDir}`);
  console.log(`  Permissions: ${(stats.mode & parseInt('777', 8)).toString(8)}`);
  console.log(`  Writable: ${fs.accessSync(tmpDir, fs.constants.W_OK) === undefined ? 'Yes' : 'No'}`);
}

// List active tmux sessions
async function listTmuxSessions() {
  console.log('\n📺 Active Tmux Sessions:');
  
  return new Promise((resolve) => {
    const tmux = spawn('tmux', ['list-sessions'], { stdio: 'pipe' });
    let output = '';
    let error = '';
    
    tmux.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    tmux.stderr.on('data', (data) => {
      error += data.toString();
    });
    
    tmux.on('exit', (code) => {
      if (code === 0 && output) {
        console.log('  Sessions found:');
        output.trim().split('\n').forEach(line => {
          console.log(`    - ${line}`);
        });
      } else if (error.includes('no server running')) {
        console.log('  No tmux server running (this is normal if no sessions active)');
      } else if (error) {
        console.log(`  Error: ${error.trim()}`);
      } else {
        console.log('  No sessions found');
      }
      resolve();
    });
    
    tmux.on('error', () => {
      console.log('  Failed to list sessions');
      resolve();
    });
  });
}

// Test creating a session
async function testSessionCreation() {
  console.log('\n🧪 Testing Session Creation:');
  
  const testSessionName = `test-${Date.now()}`;
  const socketDir = path.join(os.tmpdir(), '.claude-flow-tmux');
  
  // Ensure directory exists
  if (!fs.existsSync(socketDir)) {
    fs.mkdirSync(socketDir, { recursive: true, mode: 0o755 });
    console.log(`  Created socket directory: ${socketDir}`);
  }
  
  const socketPath = path.join(socketDir, `${testSessionName}.sock`);
  
  return new Promise((resolve) => {
    console.log(`  Creating test session: ${testSessionName}`);
    console.log(`  Socket path: ${socketPath}`);
    
    const tmux = spawn('tmux', [
      '-S', socketPath,
      'new-session',
      '-d',
      '-s', testSessionName,
      '-x', '80',
      '-y', '24'
    ], { stdio: 'pipe' });
    
    let error = '';
    tmux.stderr.on('data', (data) => {
      error += data.toString();
    });
    
    tmux.on('exit', (code) => {
      if (code === 0) {
        console.log('  ✅ Session created successfully');
        
        // Try to capture from it
        const capture = spawn('tmux', [
          '-S', socketPath,
          'capture-pane',
          '-t', testSessionName,
          '-p'
        ], { stdio: 'pipe' });
        
        let captureOutput = '';
        let captureError = '';
        
        capture.stdout.on('data', (data) => {
          captureOutput += data.toString();
        });
        
        capture.stderr.on('data', (data) => {
          captureError += data.toString();
        });
        
        capture.on('exit', (captureCode) => {
          if (captureCode === 0) {
            console.log(`  ✅ Capture successful (${captureOutput.length} bytes)`);
          } else {
            console.log(`  ❌ Capture failed with code ${captureCode}`);
            if (captureError) {
              console.log(`     Error: ${captureError.trim()}`);
            }
          }
          
          // Clean up test session
          const kill = spawn('tmux', [
            '-S', socketPath,
            'kill-session',
            '-t', testSessionName
          ], { stdio: 'ignore' });
          
          kill.on('exit', () => {
            try {
              fs.unlinkSync(socketPath);
              console.log('  🧹 Test session cleaned up');
            } catch (e) {
              // Ignore cleanup errors
            }
            resolve();
          });
        });
      } else {
        console.log(`  ❌ Failed to create session (exit code ${code})`);
        if (error) {
          console.log(`     Error: ${error.trim()}`);
        }
        resolve();
      }
    });
    
    tmux.on('error', (err) => {
      console.log(`  ❌ Failed to spawn tmux: ${err.message}`);
      resolve();
    });
  });
}

// Check environment variables
function checkEnvironment() {
  console.log('\n🌍 Environment:');
  console.log(`  Platform: ${os.platform()}`);
  console.log(`  Node version: ${process.version}`);
  console.log(`  User: ${os.userInfo().username}`);
  console.log(`  Home: ${os.homedir()}`);
  console.log(`  Temp: ${os.tmpdir()}`);
  console.log(`  TERM: ${process.env.TERM || '(not set)'}`);
  console.log(`  SHELL: ${process.env.SHELL || '(not set)'}`);
  console.log(`  PATH includes tmux: ${process.env.PATH?.includes('/usr/bin') || process.env.PATH?.includes('/usr/local/bin') ? 'Yes' : 'Check PATH'}`);
}

// Run diagnostics
async function runDiagnostics() {
  checkEnvironment();
  
  const tmuxOk = await checkTmux();
  if (!tmuxOk) {
    console.log('\n⚠️  Tmux is not installed or not accessible.');
    console.log('Please install tmux:');
    console.log('  macOS: brew install tmux');
    console.log('  Ubuntu/Debian: sudo apt-get install tmux');
    console.log('  RHEL/CentOS: sudo yum install tmux');
    return;
  }
  
  checkSocketDirs();
  checkTempDir();
  await listTmuxSessions();
  await testSessionCreation();
  
  console.log('\n' + '='.repeat(50));
  console.log('Diagnostics complete!');
  console.log('\nIf you see any ❌ errors above, they indicate potential issues.');
  console.log('If tmux capture is failing, check:');
  console.log('  1. Socket directory permissions');
  console.log('  2. Tmux version compatibility');
  console.log('  3. Any error messages in the test session creation');
}

// Run
runDiagnostics().catch(err => {
  console.error('Diagnostic script failed:', err);
  process.exit(1);
});