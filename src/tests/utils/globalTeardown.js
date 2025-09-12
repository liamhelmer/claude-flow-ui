/**
 * Global Jest Teardown
 * Runs once after all tests complete
 */

module.exports = async () => {
  console.log('🧹 Global test teardown started');
  
  // Calculate test duration
  const testDuration = Date.now() - global.__TEST_START_TIME__;
  console.log(`🕒 Total test duration: ${testDuration}ms`);
  
  // Cleanup any global resources
  if (global.testCleanup) {
    await global.testCleanup();
  }
  
  console.log('✅ Global test teardown completed');
};