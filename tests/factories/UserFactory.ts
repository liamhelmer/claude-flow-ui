import { v4 as uuid } from 'uuid';

export interface UserData {
  id?: string;
  email?: string;
  password?: string;
  firstName?: string;
  lastName?: string;
  role?: string;
  isActive?: boolean;
  emailVerified?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

export const UserFactory = {
  create: (overrides: UserData = {}): UserData => ({
    id: uuid(),
    email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
    password: 'Test123!@#',
    firstName: 'Test',
    lastName: 'User',
    role: 'user',
    isActive: true,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),

  createMany: (count: number, overrides: UserData = {}): UserData[] =>
    Array.from({ length: count }, () => UserFactory.create(overrides)),

  createAdmin: (overrides: UserData = {}): UserData =>
    UserFactory.create({
      role: 'admin',
      email: `admin-${Date.now()}@example.com`,
      firstName: 'Admin',
      lastName: 'User',
      ...overrides
    }),

  createUnverified: (overrides: UserData = {}): UserData =>
    UserFactory.create({
      emailVerified: false,
      ...overrides
    }),

  createInactive: (overrides: UserData = {}): UserData =>
    UserFactory.create({
      isActive: false,
      ...overrides
    }),

  // For registration tests
  createRegistrationData: (overrides: Partial<UserData> = {}) => ({
    email: `test-${Date.now()}@example.com`,
    password: 'Test123!@#',
    firstName: 'Test',
    lastName: 'User',
    ...overrides
  }),

  // For login tests
  createLoginData: (overrides = {}) => ({
    email: 'test@example.com',
    password: 'Test123!@#',
    ...overrides
  }),

  // For update tests
  createUpdateData: (overrides = {}) => ({
    firstName: 'Updated',
    lastName: 'User',
    ...overrides
  })
};

export default UserFactory;