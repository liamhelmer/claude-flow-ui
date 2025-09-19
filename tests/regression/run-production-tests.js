#!/usr/bin/env node

/**
 * Production Terminal Testing Runner
 *
 * This script runs the production-specific terminal regression tests
 * with proper environment setup to reproduce the reported issues.
 */

const { execSync } = require('child_process');
const path = require('path');

// Force production environment
process.env.NODE_ENV = 'production';
process.env.FAST_REFRESH = 'false';
process.env.REACT_STRICT_MODE = 'false';

console.log('🏭 Starting Production Terminal Regression Tests...');
console.log(`📍 NODE_ENV: ${process.env.NODE_ENV}`);
console.log('🔍 Testing production-specific terminal issues:');
console.log('   1. Terminal input display delay');
console.log('   2. Terminal switching problems');
console.log('   3. WebSocket disconnection effects');
console.log('');

const testCommand = [
  'npx jest',
  '--config', path.join(__dirname, 'jest.production.config.js'),
  '--runInBand', // Run tests serially for more reliable WebSocket testing
  '--verbose',
  '--no-cache', // Ensure fresh environment for each run
  '--detectOpenHandles', // Detect WebSocket handle leaks
  '--forceExit', // Force exit after tests complete
  '--maxWorkers=1' // Single worker for WebSocket testing stability
].join(' ');

try {
  console.log(`🚀 Running: ${testCommand}`);
  console.log('');

  execSync(testCommand, {
    stdio: 'inherit',
    cwd: path.resolve(__dirname, '../..'),
    env: {
      ...process.env,
      NODE_ENV: 'production',
      FAST_REFRESH: 'false',
      REACT_STRICT_MODE: 'false'
    }
  });

  console.log('');
  console.log('✅ Production terminal regression tests completed successfully!');

} catch (error) {
  console.error('');
  console.error('❌ Production terminal tests failed:');
  console.error(error.message);

  console.log('');
  console.log('🔧 Troubleshooting tips:');
  console.log('   - Ensure NODE_ENV=production is set');
  console.log('   - Check WebSocket connection handling in production mode');
  console.log('   - Verify event listener timing in production builds');
  console.log('   - Test input display logic with production optimizations');

  process.exit(1);
}

// Instructions for running specific test scenarios
console.log('');
console.log('📋 Available test scenarios:');
console.log('   npm run test:production-input   # Test input display delay');
console.log('   npm run test:production-switch  # Test terminal switching');
console.log('   npm run test:production-ws      # Test WebSocket behavior');
console.log('   npm run test:production-all     # Run all production tests');
console.log('');
console.log('🔍 To debug specific issues:');
console.log('   1. Set DEBUG=terminal:* environment variable');
console.log('   2. Check browser console for production-specific errors');
console.log('   3. Monitor WebSocket connection status in Network tab');
console.log('   4. Verify terminal input timing with performance tools');