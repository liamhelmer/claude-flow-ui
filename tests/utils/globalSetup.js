const { spawn } = require('child_process');
const path = require('path');

// Global test setup - start mock servers if needed
module.exports = async () => {
  console.log('🧪 Global test setup started');
  
  // Set test environment
  process.env.NODE_ENV = 'test';
  process.env.NEXT_PUBLIC_WS_PORT = '11237'; // Different port for tests
  process.env.NEXT_PUBLIC_WS_URL = 'ws://localhost:11237';
  
  // Increase EventEmitter listener limits for tests
  process.setMaxListeners(0);
  require('events').EventEmitter.defaultMaxListeners = 20;
  
  // Store configuration in global for cleanup
  global.__TESTCONFIG__ = {
    wsPort: '11237',
    startTime: Date.now(),
    originalDateNow: Date.now,
  };
  
  console.log('✅ Global test setup completed');
};