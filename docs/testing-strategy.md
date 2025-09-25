# REST API Testing Strategy

## 1. Testing Pyramid Structure

```
         /\
        /E2E\      <- Few, high-value workflow tests
       /------\
      /Integr. \   <- API endpoint integration tests
     /----------\
    /   Unit     \ <- Many, fast, focused unit tests
   /--------------\
```

## 2. Test Types and Structure

### Unit Tests (70% of tests)
- **Location**: `tests/unit/`
- **Purpose**: Test individual functions, classes, and modules in isolation
- **Scope**: Services, utilities, middleware, controllers (business logic only)
- **Mocking**: Heavy use of mocks for external dependencies

### Integration Tests (25% of tests)
- **Location**: `tests/integration/`
- **Purpose**: Test API endpoints with real database and Redis
- **Scope**: Full HTTP request/response cycles
- **Mocking**: Minimal mocking, real database connections

### E2E Tests (5% of tests)
- **Location**: `tests/e2e/`
- **Purpose**: Test complete user workflows
- **Scope**: Authentication flows, user journeys
- **Mocking**: No mocking, real services

## 3. Test Patterns and Conventions

### Unit Test Pattern (AAA Pattern)
```typescript
describe('ServiceName', () => {
  let service: ServiceName;
  let mockDependency: jest.Mocked<DependencyType>;

  beforeEach(() => {
    // Arrange
    mockDependency = createMockDependency();
    service = new ServiceName(mockDependency);
  });

  describe('methodName', () => {
    it('should handle valid input correctly', async () => {
      // Arrange
      const input = createValidInput();
      mockDependency.method.mockResolvedValue(expectedResult);

      // Act
      const result = await service.methodName(input);

      // Assert
      expect(result).toEqual(expectedOutput);
      expect(mockDependency.method).toHaveBeenCalledWith(expectedArgs);
    });
  });
});
```

### Integration Test Pattern
```typescript
describe('POST /api/v1/endpoint', () => {
  beforeEach(async () => {
    await setupTestDatabase();
  });

  afterEach(async () => {
    await cleanupTestDatabase();
  });

  it('should create resource with valid data', async () => {
    const response = await request(app)
      .post('/api/v1/endpoint')
      .send(validData)
      .expect(201);

    expect(response.body.success).toBe(true);
    // Verify database state
    const created = await Repository.findById(response.body.data.id);
    expect(created).toBeTruthy();
  });
});
```

## 4. Test Data Management

### Test Database Strategy
- **Separate test database**: `claude_flow_test`
- **Database per test**: Each integration test gets fresh DB state
- **Factories**: Use factory functions for consistent test data
- **Fixtures**: Predefined data sets for complex scenarios

### Data Factories
```typescript
export const UserFactory = {
  create: (overrides = {}) => ({
    id: uuid(),
    email: `test-${Date.now()}@example.com`,
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

  createMany: (count: number, overrides = {}) =>
    Array.from({ length: count }, () => UserFactory.create(overrides))
};
```

## 5. Mocking Strategies

### Mock Hierarchy
1. **External APIs**: Always mocked in unit/integration tests
2. **Database**: Mocked in unit tests, real in integration tests
3. **Redis**: Mocked in unit tests, real in integration tests
4. **File System**: Always mocked
5. **Time**: Mocked when needed with `jest.useFakeTimers()`

### Mock Implementation
```typescript
// Service mocks
jest.mock('../services/EmailService', () => ({
  EmailService: jest.fn().mockImplementation(() => ({
    sendWelcomeEmail: jest.fn().mockResolvedValue(true),
    sendPasswordResetEmail: jest.fn().mockResolvedValue(true)
  }))
}));

// Database mocks
const mockUserRepository = {
  findById: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  findByEmail: jest.fn()
};
```

## 6. Coverage Requirements

### Global Coverage Targets
- **Statements**: ≥80%
- **Branches**: ≥75%
- **Functions**: ≥80%
- **Lines**: ≥80%

### Component-Specific Targets
- **Utils**: ≥90% (critical shared code)
- **Middleware**: ≥85% (security critical)
- **Services**: ≥80% (business logic)
- **Controllers**: ≥75% (mainly integration tested)

### Coverage Exclusions
- Type definition files (*.d.ts)
- Configuration files
- Server startup file
- Index/barrel files

## 7. Authentication & Authorization Testing

### Test Scenarios
1. **Valid token authentication**
2. **Invalid/malformed tokens**
3. **Expired tokens**
4. **Missing authorization headers**
5. **Role-based access control**
6. **Token refresh flows**

### Security Test Cases
- SQL injection attempts
- XSS payload sanitization
- Rate limiting enforcement
- CORS policy validation
- Input validation bypass attempts

## 8. Performance Testing Strategy

### Load Testing
- **Tools**: Artillery.js, Jest with supertest
- **Metrics**: Response time, throughput, error rate
- **Thresholds**: <200ms for simple operations, <500ms for complex operations

### Memory Testing
- **Heap usage monitoring**
- **Memory leak detection**
- **Garbage collection impact**

### Stress Testing
- **Concurrent user simulation**
- **Resource exhaustion scenarios**
- **Recovery testing**

## 9. Error Scenario Testing

### Error Categories
1. **Validation Errors**: Invalid input data
2. **Authentication Errors**: Auth failures
3. **Authorization Errors**: Permission denied
4. **Business Logic Errors**: Domain rule violations
5. **System Errors**: Database/Redis failures
6. **Network Errors**: Timeout scenarios

### Error Response Format Testing
```typescript
expect(response.body).toEqual({
  success: false,
  error: {
    message: 'Validation failed',
    code: 'VALIDATION_ERROR',
    details: expect.any(Array)
  }
});
```

## 10. CI/CD Pipeline Integration

### Pipeline Stages
1. **Lint & Type Check**
2. **Unit Tests** (parallel execution)
3. **Integration Tests** (with test DB)
4. **E2E Tests** (full stack)
5. **Performance Tests** (on staging)
6. **Coverage Report & Quality Gate**

### Quality Gates
- All tests must pass
- Coverage thresholds must be met
- No high-severity security vulnerabilities
- Performance benchmarks must pass

### Test Environment Setup
```yaml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: claude_flow_test
      POSTGRES_USER: test_user
      POSTGRES_PASSWORD: test_pass
  redis:
    image: redis:7-alpine
```

## 11. Test Organization

### Directory Structure
```
tests/
├── unit/
│   ├── services/
│   ├── middleware/
│   ├── utils/
│   └── controllers/
├── integration/
│   ├── auth/
│   ├── users/
│   └── health/
├── e2e/
│   ├── auth-flows/
│   └── user-journeys/
├── performance/
├── fixtures/
├── factories/
├── mocks/
└── helpers/
```

### Test File Naming
- Unit tests: `*.test.ts`
- Integration tests: `*.integration.test.ts`
- E2E tests: `*.e2e.test.ts`
- Performance tests: `*.perf.test.ts`

## 12. Testing Best Practices

### General Rules
1. **One assertion per test** (when possible)
2. **Descriptive test names** (should read like specifications)
3. **Independent tests** (no test dependencies)
4. **Fast feedback** (unit tests <100ms, integration <1s)
5. **Reliable tests** (no flaky tests allowed)

### Code Quality
- Use TypeScript for all test files
- Maintain consistent test structure
- Regular test refactoring
- Comprehensive error testing
- Performance regression prevention

### Documentation
- Test scenarios in README
- Complex test explanations
- Mock rationale documentation
- Performance benchmark baselines