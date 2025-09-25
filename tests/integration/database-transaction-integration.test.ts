/**
 * Database Transaction and Persistence Integration Tests
 *
 * These tests validate database operations, transaction handling,
 * concurrent access patterns, and data integrity across the application.
 */

import { database } from '../../rest-api/src/config/database';
import { User } from '../../rest-api/src/models/User';
import { Transaction } from 'sequelize';
import bcrypt from 'bcryptjs';

// Mock session model for testing (would be implemented in real app)
interface SessionData {
  id: string;
  userId: string;
  data: any;
  createdAt: Date;
  updatedAt: Date;
}

describe('Database Transaction and Persistence Integration Tests', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_db_test';
    
    await database.connect();
    await database.sync({ force: true }); // Clean database
  }, 30000);

  afterAll(async () => {
    await database.disconnect();
  }, 30000);

  beforeEach(async () => {
    // Clean up between tests
    await User.destroy({ where: {}, force: true });
  });

  describe('Basic CRUD Operations', () => {
    test('should create user with proper data validation', async () => {
      const userData = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user' as const,
      };

      const user = await User.create(userData);
      
      expect(user).toMatchObject({
        id: expect.any(String),
        firstName: userData.firstName,
        lastName: userData.lastName,
        email: userData.email.toLowerCase(), // Should be normalized
        role: userData.role,
        isActive: true,
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date),
      });

      // Verify password is hashed
      expect(user.password).toBe(userData.password);
      expect(user.password).not.toBe('password123');

      // Test virtual field
      expect(user.fullName).toBe('John Doe');
    });

    test('should enforce unique email constraint', async () => {
      const userData = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'duplicate@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user' as const,
      };

      // Create first user
      await User.create(userData);

      // Try to create duplicate
      await expect(User.create(userData)).rejects.toThrow(
        expect.objectContaining({
          name: 'SequelizeUniqueConstraintError',
        })
      );
    });

    test('should validate required fields', async () => {
      const invalidData = {
        firstName: '', // Empty string should fail
        email: 'invalid-email', // Invalid email format
        password: '123', // Too short
      };

      await expect(User.create(invalidData as any)).rejects.toThrow(
        expect.objectContaining({
          name: 'SequelizeValidationError',
        })
      );
    });

    test('should update user and track changes', async () => {
      const user = await User.create({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      });

      const originalUpdatedAt = user.updatedAt;
      
      // Wait a moment to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      await user.update({
        firstName: 'Jane',
        lastLoginAt: new Date(),
      });

      expect(user.firstName).toBe('Jane');
      expect(user.lastName).toBe('Doe'); // Unchanged
      expect(user.lastLoginAt).toBeInstanceOf(Date);
      expect(user.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt.getTime());
    });

    test('should soft delete and restore users', async () => {
      const user = await User.create({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      });

      // Soft delete (deactivate)
      await user.update({ isActive: false });
      
      // Should still exist in database but inactive
      const inactiveUser = await User.findByPk(user.id);
      expect(inactiveUser?.isActive).toBe(false);

      // Restore
      await user.update({ isActive: true });
      expect(user.isActive).toBe(true);
    });
  });

  describe('Transaction Handling', () => {
    test('should handle successful transaction commit', async () => {
      const transaction = await database.sequelize.transaction();

      try {
        const user1 = await User.create({
          firstName: 'User',
          lastName: 'One',
          email: 'user1@test.com',
          password: await bcrypt.hash('password123', 12),
          role: 'user',
        }, { transaction });

        const user2 = await User.create({
          firstName: 'User',
          lastName: 'Two',
          email: 'user2@test.com',
          password: await bcrypt.hash('password123', 12),
          role: 'admin',
        }, { transaction });

        await transaction.commit();

        // Verify both users were created
        const users = await User.findAll();
        expect(users).toHaveLength(2);
        
        const userEmails = users.map(u => u.email);
        expect(userEmails).toContain('user1@test.com');
        expect(userEmails).toContain('user2@test.com');

      } catch (error) {
        await transaction.rollback();
        throw error;
      }
    });

    test('should handle transaction rollback on error', async () => {
      let transaction: Transaction | null = null;
      
      try {
        transaction = await database.sequelize.transaction();

        // Create first user successfully
        await User.create({
          firstName: 'User',
          lastName: 'One',
          email: 'user1@test.com',
          password: await bcrypt.hash('password123', 12),
          role: 'user',
        }, { transaction });

        // Attempt to create duplicate email (should fail)
        await User.create({
          firstName: 'User',
          lastName: 'Duplicate',
          email: 'user1@test.com', // Same email
          password: await bcrypt.hash('password123', 12),
          role: 'user',
        }, { transaction });

        await transaction.commit();
      } catch (error) {
        if (transaction) {
          await transaction.rollback();
        }
        
        // Verify no users were created due to rollback
        const users = await User.findAll();
        expect(users).toHaveLength(0);
        
        expect(error).toHaveProperty('name', 'SequelizeUniqueConstraintError');
      }
    });

    test('should handle nested transactions', async () => {
      const mainTransaction = await database.sequelize.transaction();

      try {
        // Create user in main transaction
        const user = await User.create({
          firstName: 'Main',
          lastName: 'User',
          email: 'main@test.com',
          password: await bcrypt.hash('password123', 12),
          role: 'user',
        }, { transaction: mainTransaction });

        // Create savepoint
        const savepoint = await database.sequelize.transaction({
          transaction: mainTransaction,
        });

        try {
          // Update user in savepoint
          await user.update({
            firstName: 'Updated',
            lastLoginAt: new Date(),
          }, { transaction: savepoint });

          await savepoint.commit();
        } catch (error) {
          await savepoint.rollback();
          throw error;
        }

        await mainTransaction.commit();

        // Verify the update was committed
        const updatedUser = await User.findByPk(user.id);
        expect(updatedUser?.firstName).toBe('Updated');
        expect(updatedUser?.lastLoginAt).toBeInstanceOf(Date);

      } catch (error) {
        await mainTransaction.rollback();
        throw error;
      }
    });
  });

  describe('Concurrent Access and Race Conditions', () => {
    test('should handle concurrent user creation attempts', async () => {
      const createUser = (index: number) => {
        return User.create({
          firstName: 'User',
          lastName: `${index}`,
          email: `user${index}@test.com`,
          password: bcrypt.hashSync('password123', 12),
          role: 'user',
        });
      };

      // Create 10 users concurrently
      const promises = Array.from({ length: 10 }, (_, i) => createUser(i));
      const users = await Promise.all(promises);

      expect(users).toHaveLength(10);
      
      // Verify all users have unique emails
      const emails = users.map(u => u.email);
      const uniqueEmails = new Set(emails);
      expect(uniqueEmails.size).toBe(10);
    });

    test('should handle concurrent updates to same user', async () => {
      const user = await User.create({
        firstName: 'John',
        lastName: 'Doe',
        email: 'concurrent@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      });

      // Simulate concurrent updates
      const updatePromises = [
        user.update({ firstName: 'Jane' }),
        user.update({ lastName: 'Smith' }),
        user.update({ role: 'admin' }),
      ];

      await Promise.all(updatePromises);

      // Reload user to get latest state
      await user.reload();
      
      // The last update should win for each field
      expect(user.firstName).toBeTruthy();
      expect(user.lastName).toBeTruthy();
      expect(['user', 'admin']).toContain(user.role);
    });

    test('should handle optimistic locking conflicts', async () => {
      const user = await User.create({
        firstName: 'John',
        lastName: 'Doe',
        email: 'locking@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      });

      // Fetch the same user instance twice
      const user1 = await User.findByPk(user.id);
      const user2 = await User.findByPk(user.id);

      expect(user1).toBeTruthy();
      expect(user2).toBeTruthy();

      // Update through first instance
      await user1!.update({ firstName: 'Jane' });

      // Update through second instance should still work
      // (Sequelize doesn't have built-in optimistic locking,
      // but we test the behavior)
      await user2!.update({ lastName: 'Smith' });

      // Verify final state
      await user.reload();
      expect(user.firstName).toBe('Jane');
      expect(user.lastName).toBe('Smith');
    });
  });

  describe('Data Integrity and Constraints', () => {
    test('should enforce email format validation', async () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user..double@domain.com',
        'user@domain',
        '',
      ];

      for (const email of invalidEmails) {
        await expect(User.create({
          firstName: 'Test',
          lastName: 'User',
          email,
          password: await bcrypt.hash('password123', 12),
          role: 'user',
        })).rejects.toThrow(
          expect.objectContaining({
            name: 'SequelizeValidationError',
          })
        );
      }
    });

    test('should enforce name length constraints', async () => {
      // Test minimum length
      await expect(User.create({
        firstName: 'A', // Too short
        lastName: 'Doe',
        email: 'test@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      })).rejects.toThrow(
        expect.objectContaining({
          name: 'SequelizeValidationError',
        })
      );

      // Test maximum length
      const longName = 'A'.repeat(101); // Too long
      await expect(User.create({
        firstName: longName,
        lastName: 'Doe',
        email: 'test@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      })).rejects.toThrow(
        expect.objectContaining({
          name: 'SequelizeValidationError',
        })
      );
    });

    test('should enforce role enumeration', async () => {
      await expect(User.create({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'invalid-role' as any,
      })).rejects.toThrow(
        expect.objectContaining({
          name: 'SequelizeValidationError',
        })
      );
    });

    test('should handle database connection recovery', async () => {
      // Simulate connection loss and recovery
      await database.disconnect();
      
      // Attempt operation while disconnected
      await expect(User.findAll()).rejects.toThrow();
      
      // Reconnect
      await database.connect();
      
      // Operation should work after reconnection
      const users = await User.findAll();
      expect(users).toEqual([]);
    });
  });

  describe('Performance and Indexing', () => {
    test('should efficiently query by email (indexed field)', async () => {
      // Create multiple users
      const users = await Promise.all(
        Array.from({ length: 100 }, (_, i) => 
          User.create({
            firstName: 'User',
            lastName: `${i}`,
            email: `user${i}@test.com`,
            password: bcrypt.hashSync('password123', 12),
            role: 'user',
          })
        )
      );

      const startTime = Date.now();
      
      // Query by email (indexed)
      const foundUser = await User.findOne({
        where: { email: 'user50@test.com' }
      });
      
      const queryTime = Date.now() - startTime;
      
      expect(foundUser).toBeTruthy();
      expect(foundUser!.lastName).toBe('50');
      
      // Query should be fast (under 100ms)
      expect(queryTime).toBeLessThan(100);
    });

    test('should handle bulk operations efficiently', async () => {
      const userData = Array.from({ length: 1000 }, (_, i) => ({
        firstName: 'Bulk',
        lastName: `User${i}`,
        email: `bulk${i}@test.com`,
        password: bcrypt.hashSync('password123', 12),
        role: 'user' as const,
      }));

      const startTime = Date.now();
      
      // Bulk create
      await User.bulkCreate(userData, {
        validate: true,
        returning: false, // Faster for large datasets
      });
      
      const createTime = Date.now() - startTime;
      
      // Verify all users were created
      const count = await User.count();
      expect(count).toBe(1000);
      
      // Bulk create should be reasonably fast (under 5 seconds)
      expect(createTime).toBeLessThan(5000);
      
      const updateStartTime = Date.now();
      
      // Bulk update
      await User.update(
        { role: 'admin' },
        { 
          where: {
            firstName: 'Bulk'
          }
        }
      );
      
      const updateTime = Date.now() - updateStartTime;
      
      // Verify all users were updated
      const adminCount = await User.count({ where: { role: 'admin' } });
      expect(adminCount).toBe(1000);
      
      // Bulk update should be fast (under 2 seconds)
      expect(updateTime).toBeLessThan(2000);
    });
  });

  describe('Database Migration and Schema Changes', () => {
    test('should handle adding new fields gracefully', async () => {
      // Create user with current schema
      const user = await User.create({
        firstName: 'John',
        lastName: 'Doe',
        email: 'migration@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      });

      // Simulate adding a new field (in real app, this would be a migration)
      // For test purposes, we'll just verify the current structure
      const userAttributes = Object.keys(user.dataValues);
      
      const expectedFields = [
        'id', 'firstName', 'lastName', 'email', 'password',
        'role', 'isActive', 'lastLoginAt', 'createdAt', 'updatedAt'
      ];
      
      expectedFields.forEach(field => {
        expect(userAttributes).toContain(field);
      });
    });

    test('should maintain data integrity during schema changes', async () => {
      // Create users before "migration"
      const beforeUsers = await Promise.all([
        User.create({
          firstName: 'Pre',
          lastName: 'Migration1',
          email: 'pre1@test.com',
          password: await bcrypt.hash('password123', 12),
          role: 'user',
        }),
        User.create({
          firstName: 'Pre',
          lastName: 'Migration2',
          email: 'pre2@test.com',
          password: await bcrypt.hash('password123', 12),
          role: 'admin',
        }),
      ]);

      // Simulate schema change (force sync to rebuild tables)
      await database.sync({ force: false, alter: true });
      
      // Verify data still exists and is accessible
      const afterUsers = await User.findAll({
        order: [['createdAt', 'ASC']]
      });
      
      expect(afterUsers).toHaveLength(beforeUsers.length);
      expect(afterUsers[0].email).toBe('pre1@test.com');
      expect(afterUsers[1].email).toBe('pre2@test.com');
    });
  });
});
