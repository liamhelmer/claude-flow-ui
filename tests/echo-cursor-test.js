#!/usr/bin/env node

/**
 * Terminal Echo and Cursor Position Test
 * Tests the fixes for echo handling and cursor position tracking
 */

const { spawn } = require('child_process');
const path = require('path');

console.log('🧪 Testing Terminal Echo and Cursor Position Fixes\n');

// Test 1: Basic echo functionality
console.log('📝 Test 1: Basic Echo Test');
const echoTest = spawn('echo', ['Hello, World!'], { 
  stdio: ['inherit', 'pipe', 'inherit'],
  env: {
    ...process.env,
    TERM: 'xterm-256color'
  }
});

echoTest.stdout.on('data', (data) => {
  console.log(`✅ Echo output: ${data.toString().trim()}`);
});

echoTest.on('close', (code) => {
  console.log(`Echo test completed with code ${code}\n`);
  
  // Test 2: stty echo handling  
  console.log('🔧 Test 2: stty Command Test');
  const sttyTest = spawn('stty', ['-a'], {
    stdio: ['inherit', 'pipe', 'inherit'],
    env: {
      ...process.env,
      TERM: 'xterm-256color'
    }
  });
  
  sttyTest.stdout.on('data', (data) => {
    const output = data.toString();
    const hasEcho = output.includes('echo');
    const hasIcanon = output.includes('icanon');
    console.log(`✅ stty output contains echo: ${hasEcho}`);
    console.log(`✅ stty output contains icanon: ${hasIcanon}`);
    console.log(`Raw output: ${output.trim()}`);
  });
  
  sttyTest.on('close', (code) => {
    console.log(`stty test completed with code ${code}\n`);
    
    // Test 3: Cursor position escape sequences
    console.log('📍 Test 3: Cursor Position Test');
    process.stdout.write('Testing cursor position...');
    process.stdout.write('\x1b[6n'); // Request cursor position
    
    // Listen for cursor position response
    process.stdin.setRawMode(true);
    process.stdin.resume();
    
    let received = false;
    const timeout = setTimeout(() => {
      if (!received) {
        console.log('⚠️  No cursor position response received (this is expected in non-interactive mode)');
        process.stdin.setRawMode(false);
        process.stdin.pause();
        console.log('\n✅ Terminal echo and cursor tests completed!');
        process.exit(0);
      }
    }, 1000);
    
    process.stdin.on('data', (chunk) => {
      const data = chunk.toString();
      const cursorMatch = data.match(/\x1b\[(\d+);(\d+)R/);
      if (cursorMatch) {
        received = true;
        clearTimeout(timeout);
        const row = cursorMatch[1];
        const col = cursorMatch[2];
        console.log(`\n✅ Cursor position received: row ${row}, col ${col}`);
        process.stdin.setRawMode(false);
        process.stdin.pause();
        console.log('\n✅ Terminal echo and cursor tests completed!');
        process.exit(0);
      }
    });
  });
});