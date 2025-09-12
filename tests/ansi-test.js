#!/usr/bin/env node

/**
 * ANSI Codes Test Script
 * Tests various ANSI escape sequences to ensure proper interpretation
 */

const io = require('socket.io-client');

const socket = io('http://localhost:8080', {
  path: '/api/ws',
  transports: ['websocket']
});

console.log('🔌 Connecting to WebSocket server...');

socket.on('connect', () => {
  console.log('✅ Connected to WebSocket server');
  console.log('📡 Socket ID:', socket.id);
  
  // Connect to current terminal session
  const sessionId = 'claude-flow-ui-1757663635653';
  
  console.log(`\n🧪 Connecting to terminal session: ${sessionId}`);
  socket.emit('terminal-connect', { sessionId });
  
  // After connecting, send various ANSI test sequences
  setTimeout(() => {
    console.log('\n🎨 Testing ANSI color codes...');
    
    // Test 1: Basic color test
    socket.emit('data', {
      sessionId: sessionId,
      data: 'echo -e "\\033[31mRed text\\033[0m \\033[32mGreen text\\033[0m \\033[33mYellow text\\033[0m"\r'
    });
    
    setTimeout(() => {
      // Test 2: 256-color test (this is what the user reported)
      console.log('\n🎨 Testing 256-color ANSI codes...');
      socket.emit('data', {
        sessionId: sessionId,
        data: 'echo -e "\\033[38;5;246mGray text using 256 colors\\033[0m"\r'
      });
    }, 1000);
    
    setTimeout(() => {
      // Test 3: Cursor positioning
      console.log('\n📍 Testing cursor positioning...');
      socket.emit('data', {
        sessionId: sessionId,
        data: 'echo -e "\\033[10;5HCursor at row 10, col 5\\033[0m"\r'
      });
    }, 2000);
    
    setTimeout(() => {
      // Test 4: Mixed formatting
      console.log('\n✨ Testing mixed formatting...');
      socket.emit('data', {
        sessionId: sessionId,
        data: 'echo -e "\\033[1;31;44mBold Red on Blue\\033[0m \\033[4;32mUnderlined Green\\033[0m"\r'
      });
    }, 3000);
    
    setTimeout(() => {
      // Test 5: Clear screen and reset
      console.log('\n🧹 Testing clear and reset...');
      socket.emit('data', {
        sessionId: sessionId,
        data: 'clear\r'
      });
    }, 4000);
    
  }, 1000);
});

socket.on('terminal-data', (data) => {
  console.log('\n📊 Terminal Data Received:');
  console.log('Session ID:', data.sessionId);
  console.log('Data Length:', data.data.length, 'bytes');
  console.log('Raw Data (first 500 chars):');
  console.log(JSON.stringify(data.data.substring(0, 500)));
  
  // Check for uninterpreted ANSI codes
  const ansiPattern = /\033\[[0-9;]*[a-zA-Z]/g;
  const foundCodes = data.data.match(ansiPattern);
  if (foundCodes) {
    console.log('🚨 Found uninterpreted ANSI codes:', foundCodes);
  } else {
    console.log('✅ No raw ANSI codes visible (good - they should be interpreted)');
  }
});

socket.on('terminal-config', (config) => {
  console.log('\n⚙️ Terminal Config Received:');
  console.log('Session ID:', config.sessionId);
  console.log('Terminal Size:', `${config.cols}x${config.rows}`);
});

socket.on('terminal-error', (error) => {
  console.error('\n❌ Terminal Error:', error);
});

socket.on('disconnect', (reason) => {
  console.log('\n🔌 Disconnected:', reason);
});

socket.on('connect_error', (error) => {
  console.error('\n❌ Connection Error:', error.message);
});

// Auto-disconnect after 15 seconds
setTimeout(() => {
  console.log('\n🏁 ANSI test completed, disconnecting...');
  socket.disconnect();
  process.exit(0);
}, 15000);

console.log('🕐 ANSI test will run for 15 seconds...');