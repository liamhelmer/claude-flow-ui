#!/usr/bin/env node

/**
 * WebSocket Test Script for Terminal Full History Capture
 * Tests the refresh functionality and full screen capture
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
  
  // Test 1: Connect to existing terminal session
  const sessionId = 'claude-flow-ui-1757662388064'; // Updated to current session
  
  console.log(`\n🧪 Test 1: Connecting to terminal session: ${sessionId}`);
  socket.emit('terminal-connect', { sessionId });
});

socket.on('terminal-data', (data) => {
  console.log('\n📊 Terminal Data Received:');
  console.log('Session ID:', data.sessionId);
  console.log('Data Length:', data.data.length, 'bytes');
  console.log('Sample Data (first 200 chars):');
  console.log(data.data.substring(0, 200));
  
  // Test 2: Test typing and echo after receiving initial data
  setTimeout(() => {
    console.log('\n🔄 Test 2: Testing input and echo...');
    
    // Send some test input to see if it echoes properly
    socket.emit('data', {
      sessionId: data.sessionId,
      data: 'h'
    });
    
    setTimeout(() => {
      socket.emit('data', {
        sessionId: data.sessionId, 
        data: 'e'
      });
    }, 200);
    
    setTimeout(() => {
      socket.emit('data', {
        sessionId: data.sessionId,
        data: 'l'
      });
    }, 400);
    
    setTimeout(() => {
      socket.emit('data', {
        sessionId: data.sessionId,
        data: 'l'
      });
    }, 600);
    
    setTimeout(() => {
      socket.emit('data', {
        sessionId: data.sessionId,
        data: 'o'
      });
    }, 800);
    
    setTimeout(() => {
      socket.emit('data', {
        sessionId: data.sessionId,
        data: '\r'
      });
    }, 1000);

    // Test 3: Test refresh functionality after commands
    setTimeout(() => {
      console.log('\n🔄 Test 3: Testing refresh functionality...');
      socket.emit('data', {
        sessionId: data.sessionId,
        data: JSON.stringify({
          type: 'refresh',
          sessionId: data.sessionId
        })
      });
    }, 2000);
  }, 2000);
});

socket.on('terminal-config', (config) => {
  console.log('\n⚙️ Terminal Config Received:');
  console.log('Session ID:', config.sessionId);
  console.log('Terminal Size:', `${config.cols}x${config.rows}`);
  console.log('Font:', config.fontFamily, config.fontSize + 'px');
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

// Auto-disconnect after 10 seconds
setTimeout(() => {
  console.log('\n🏁 Test completed, disconnecting...');
  socket.disconnect();
  process.exit(0);
}, 10000);

console.log('🕐 Test will run for 10 seconds...');