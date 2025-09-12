// Global test teardown
module.exports = async () => {
  console.log('🧹 Global test teardown started');
  
  // Clean up any global test resources
  if (global.__TESTCONFIG__) {
    const duration = Date.now() - global.__TESTCONFIG__.startTime;
    console.log(`🕒 Total test duration: ${duration}ms`);
    
    // Clean up global references
    delete global.__TESTCONFIG__;
  }
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
  
  console.log('✅ Global test teardown completed');
};