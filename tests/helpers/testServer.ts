import { Application } from 'express';
import App from '../../rest-api/src/app';
import { setupTestDatabase, cleanupTestDatabase } from './testDatabase';

let appInstance: App;
let server: Application;

export const startTestServer = async (): Promise<Application> => {
  if (!appInstance) {
    // Setup test environment
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
    process.env.JWT_EXPIRES_IN = '1h';
    process.env.REDIS_HOST = 'localhost';
    process.env.REDIS_PORT = '6379';
    process.env.DB_HOST = 'localhost';
    process.env.DB_PORT = '5432';
    process.env.DB_NAME = 'claude_flow_test';

    // Initialize test database
    await setupTestDatabase();

    // Create app instance
    appInstance = new App();
    server = appInstance.app;
  }

  return server;
};

export const stopTestServer = async (): Promise<void> => {
  if (appInstance) {
    await appInstance.shutdown();
    await cleanupTestDatabase();
  }
};

export const getTestApp = (): Application => {
  if (!server) {
    throw new Error('Test server not started. Call startTestServer() first.');
  }
  return server;
};

// Helper function to reset test state between tests
export const resetTestState = async (): Promise<void> => {
  await cleanupTestDatabase();
  await setupTestDatabase();
};