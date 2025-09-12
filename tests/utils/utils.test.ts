/**
 * Test Utilities Validation Tests
 */

describe('Test Infrastructure', () => {
  describe('Environment Validation', () => {
    it('should have all required test globals', () => {
      expect(typeof jest).toBe('object');
      expect(typeof expect).toBe('function');
      expect(typeof window).toBe('object');
      expect(typeof document).toBe('object');
      expect(typeof global.testUtils).toBe('object');
    });
  });

  describe('Test Utils', () => {
    it('should provide all required utilities', () => {
      expect(global.testUtils).toBeDefined();
      expect(typeof global.testUtils.flushPromises).toBe('function');
      expect(typeof global.testUtils.waitForNextTick).toBe('function');
      expect(typeof global.testUtils.wait).toBe('function');
    });

    it('should create mock sessions with unique IDs', () => {
      const session1 = global.testUtils.createMockTerminalSession();
      const session2 = global.testUtils.createMockTerminalSession();
      
      expect(session1.id).toBeDefined();
      expect(session2.id).toBeDefined();
      expect(session1.id).not.toBe(session2.id);
    });
  });

  describe('Promise Utilities', () => {
    it('should flush promises', async () => {
      let resolved = false;
      Promise.resolve().then(() => { resolved = true; });
      
      await global.testUtils.flushPromises();
      expect(resolved).toBe(true);
    });

    it('should wait for next tick', async () => {
      let executed = false;
      setImmediate(() => { executed = true; });
      
      await global.testUtils.waitForNextTick();
      expect(executed).toBe(true);
    });
  });

  describe('Mock Isolation', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    it('should isolate mocks between tests', () => {
      const mockFn = jest.fn();
      mockFn('test1');
      expect(mockFn).toHaveBeenCalledWith('test1');
    });

    it('should not see calls from previous test', () => {
      const mockFn = jest.fn();
      expect(mockFn).not.toHaveBeenCalled();
    });
  });
});
