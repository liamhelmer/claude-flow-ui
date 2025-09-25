import { Sequelize } from 'sequelize';
import { config } from '../../rest-api/src/config/environment';

let testDb: Sequelize;

export const setupTestDatabase = async (): Promise<void> => {
  if (!testDb) {
    testDb = new Sequelize({
      dialect: 'postgres',
      host: process.env.TEST_DB_HOST || 'localhost',
      port: parseInt(process.env.TEST_DB_PORT || '5432'),
      database: process.env.TEST_DB_NAME || 'claude_flow_test',
      username: process.env.TEST_DB_USER || 'test_user',
      password: process.env.TEST_DB_PASS || 'test_pass',
      logging: false, // Disable logging in tests
      define: {
        timestamps: true,
        underscored: false,
      },
    });

    try {
      await testDb.authenticate();
      console.log('Test database connection established.');
    } catch (error) {
      console.error('Unable to connect to test database:', error);
      throw error;
    }
  }

  // Sync database schema (recreate tables)
  await testDb.sync({ force: true });
};

export const cleanupTestDatabase = async (): Promise<void> => {
  if (testDb) {
    // Clean all tables
    const queryInterface = testDb.getQueryInterface();
    const tableNames = await queryInterface.showAllTables();

    await testDb.transaction(async (transaction) => {
      // Disable foreign key checks temporarily
      await testDb.query('SET FOREIGN_KEY_CHECKS = 0', { transaction });

      // Truncate all tables
      for (const tableName of tableNames) {
        await queryInterface.bulkDelete(tableName, {}, { transaction });
      }

      // Re-enable foreign key checks
      await testDb.query('SET FOREIGN_KEY_CHECKS = 1', { transaction });
    });
  }
};

export const closeTestDatabase = async (): Promise<void> => {
  if (testDb) {
    await testDb.close();
  }
};

export const getTestDatabase = (): Sequelize => {
  if (!testDb) {
    throw new Error('Test database not initialized. Call setupTestDatabase() first.');
  }
  return testDb;
};

// Helper function to create test data
export const createTestUser = async (userData = {}): Promise<any> => {
  const testDb = getTestDatabase();
  const User = testDb.models.User;

  const defaultUser = {
    email: `test-${Date.now()}@example.com`,
    password: '$2b$10$hashedpassword', // Pre-hashed for tests
    firstName: 'Test',
    lastName: 'User',
    role: 'user',
    isActive: true,
    emailVerified: true,
    ...userData
  };

  return await User.create(defaultUser);
};

// Helper function to count records
export const countRecords = async (modelName: string): Promise<number> => {
  const testDb = getTestDatabase();
  const Model = testDb.models[modelName];
  return await Model.count();
};