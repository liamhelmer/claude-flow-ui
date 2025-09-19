#!/usr/bin/env node

// Simple terminal input test
const { spawn } = require('child_process');
const path = require('path');

console.log('🧪 Simple Terminal Input Test');
console.log('=============================');

// Start the server
const serverPath = path.resolve(__dirname, '../');
console.log('Starting server in development mode...');

const serverProcess = spawn('npm', ['run', 'dev'], {
  cwd: serverPath,
  env: { ...process.env, PORT: 3002 },
  stdio: 'inherit'
});

// Give server time to start
setTimeout(() => {
  console.log('\n✅ Server should be running on http://localhost:3002');
  console.log('\nManual test steps:');
  console.log('1. Open http://localhost:3002 in a browser');
  console.log('2. Click on the terminal to focus it');
  console.log('3. Type "hello world"');
  console.log('4. Verify the text appears in the terminal');
  console.log('\nPress Ctrl+C to stop the server when done testing.\n');
}, 5000);

// Handle cleanup
process.on('SIGINT', () => {
  console.log('\nStopping server...');
  serverProcess.kill('SIGTERM');
  process.exit(0);
});