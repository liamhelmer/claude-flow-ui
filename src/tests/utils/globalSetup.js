/**
 * Global Jest Setup
 * Runs once before all tests start
 */

module.exports = async () => {
  console.log('🧪 Global test setup started');
  
  // Set up global test environment
  process.env.NODE_ENV = 'test';
  process.env.TZ = 'UTC';
  
  // Suppress verbose logging during tests
  process.env.SUPPRESS_LOGS = 'true';
  
  // Configure test timeouts
  jest.setTimeout(30000);
  
  console.log('✅ Global test setup completed');
};