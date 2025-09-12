# Testing Quality Standards - Claude UI Project

**Established by**: Hive Mind Tester Agent  
**Purpose**: Ensure consistent, high-quality testing practices across the codebase  
**Compliance Level**: MANDATORY for all code contributions

---

## 📋 Quality Standards Overview

### Core Testing Principles

1. **Test-Driven Development (TDD)**
   - Write tests before implementation
   - Red-Green-Refactor cycle
   - Minimum viable test coverage

2. **Comprehensive Coverage**
   - Unit tests for all functions and components
   - Integration tests for workflows
   - End-to-end tests for critical paths

3. **Quality over Quantity**
   - Meaningful assertions
   - Clear test intentions
   - Maintainable test code

---

## 🎯 Coverage Requirements

### Minimum Thresholds (Enforced by Jest)
```javascript
coverageThreshold: {
  global: {
    branches: 70,
    functions: 70,
    lines: 70,
    statements: 70,
  },
}
```

### Component-Specific Standards
```
React Components:     85% coverage minimum
Custom Hooks:         90% coverage minimum
Utility Functions:    95% coverage minimum
Business Logic:       85% coverage minimum
API Clients:          80% coverage minimum
Type Definitions:     100% type coverage
```

### Coverage Quality Metrics
- **Line Coverage**: Measures executed code lines
- **Branch Coverage**: Tests all conditional paths
- **Function Coverage**: Validates all function calls
- **Statement Coverage**: Covers all executable statements

---

## 🧪 Test Categories & Standards

### 1. Unit Tests

#### Purpose
Test individual components, functions, and modules in isolation.

#### Standards
```typescript
describe('ComponentName', () => {
  // Group related tests
  describe('when prop X is provided', () => {
    // Specific scenario testing
    it('should render expected output', () => {
      // Arrange
      const props = { x: 'value' };
      
      // Act
      render(<Component {...props} />);
      
      // Assert
      expect(screen.getByText('expected')).toBeInTheDocument();
    });
  });
});
```

#### Requirements
- ✅ Test all component props and states
- ✅ Mock external dependencies
- ✅ Test error conditions
- ✅ Validate accessibility attributes
- ✅ Use meaningful test descriptions

### 2. Integration Tests

#### Purpose
Test component interactions and data flow between modules.

#### Standards
```typescript
describe('Feature Integration', () => {
  it('should complete end-to-end workflow', async () => {
    // Setup with providers
    renderWithProviders(<App />);
    
    // User interaction simulation
    await userEvent.click(screen.getByRole('button', { name: 'Start' }));
    
    // Async operation validation
    await waitFor(() => {
      expect(screen.getByText('Success')).toBeInTheDocument();
    });
  });
});
```

#### Requirements
- ✅ Test critical user workflows
- ✅ Validate state management
- ✅ Test API integration
- ✅ Verify error handling
- ✅ Include loading states

### 3. Accessibility Tests

#### Purpose
Ensure WCAG 2.1 AA compliance and screen reader compatibility.

#### Standards
```typescript
describe('Accessibility', () => {
  it('should have no accessibility violations', async () => {
    const { container } = render(<Component />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
  
  it('should support keyboard navigation', () => {
    render(<Component />);
    const element = screen.getByRole('button');
    
    element.focus();
    expect(element).toHaveFocus();
    
    fireEvent.keyDown(element, { key: 'Enter' });
    // Validate keyboard interaction
  });
});
```

#### Requirements
- ✅ Run jest-axe on all components
- ✅ Test keyboard navigation
- ✅ Validate ARIA attributes
- ✅ Test screen reader compatibility
- ✅ Check color contrast compliance

### 4. Performance Tests

#### Purpose
Validate performance requirements and detect regressions.

#### Standards
```typescript
describe('Performance', () => {
  it('should render within performance budget', async () => {
    const start = performance.now();
    render(<ExpensiveComponent />);
    const renderTime = performance.now() - start;
    
    expect(renderTime).toBeLessThan(100); // 100ms budget
  });
  
  it('should not create memory leaks', () => {
    const { unmount } = render(<Component />);
    const initialMemory = performance.memory?.usedJSHeapSize || 0;
    
    unmount();
    
    // Force garbage collection if available
    if (global.gc) global.gc();
    
    const finalMemory = performance.memory?.usedJSHeapSize || 0;
    expect(finalMemory).toBeLessThanOrEqual(initialMemory + 1024 * 1024); // 1MB tolerance
  });
});
```

#### Requirements
- ✅ Validate render performance
- ✅ Test memory usage
- ✅ Monitor bundle size impact
- ✅ Check async operation timing
- ✅ Validate resource cleanup

### 5. Security Tests

#### Purpose
Validate security measures and prevent vulnerabilities.

#### Standards
```typescript
describe('Security', () => {
  it('should sanitize user input', () => {
    const maliciousInput = '<script>alert("xss")</script>';
    render(<Component userInput={maliciousInput} />);
    
    expect(screen.queryByText(maliciousInput)).not.toBeInTheDocument();
    expect(screen.getByText('&lt;script&gt;')).toBeInTheDocument();
  });
  
  it('should validate API inputs', async () => {
    const invalidData = { id: '../../../etc/passwd' };
    
    await expect(apiClient.getData(invalidData))
      .rejects.toThrow('Invalid input');
  });
});
```

#### Requirements
- ✅ Test input sanitization
- ✅ Validate authentication flows
- ✅ Check authorization logic
- ✅ Test CSRF protection
- ✅ Validate data encryption

---

## 🎨 Test Writing Guidelines

### File Naming Conventions
```
Component Tests:     ComponentName.test.tsx
Hook Tests:          useHookName.test.ts
Utility Tests:       utilityName.test.ts
Integration Tests:   featureName.integration.test.tsx
E2E Tests:          workflow.e2e.test.ts
```

### Test Structure (AAA Pattern)
```typescript
describe('Feature Description', () => {
  // Setup
  beforeEach(() => {
    // Common test setup
  });
  
  // Teardown
  afterEach(() => {
    // Cleanup
  });
  
  describe('specific scenario', () => {
    it('should do something specific', () => {
      // Arrange - Setup test data and conditions
      const testData = createTestData();
      
      // Act - Execute the action being tested
      const result = performAction(testData);
      
      // Assert - Verify the expected outcome
      expect(result).toEqual(expectedResult);
    });
  });
});
```

### Test Descriptions
```typescript
// ✅ GOOD - Descriptive and specific
it('should display loading spinner when data is being fetched')
it('should show error message when API call fails')
it('should update user profile when form is submitted successfully')

// ❌ BAD - Vague and unclear
it('should work')
it('handles data')
it('tests the component')
```

### Mock Usage Guidelines
```typescript
// ✅ GOOD - Minimal, focused mocking
jest.mock('@/lib/api', () => ({
  fetchUserData: jest.fn(),
}));

// ✅ GOOD - Mock with realistic data
const mockUser = {
  id: '123',
  name: 'Test User',
  email: 'test@example.com',
};
mockFetchUserData.mockResolvedValue(mockUser);

// ❌ BAD - Over-mocking
jest.mock('entire-module-unnecessarily');
```

---

## 🔧 Testing Tools & Utilities

### Required Dependencies
```json
{
  "@testing-library/react": "^16.3.0",
  "@testing-library/jest-dom": "^6.8.0",
  "@testing-library/user-event": "^14.6.1",
  "jest": "^30.0.5",
  "jest-environment-jsdom": "^30.0.5",
  "jest-axe": "^10.0.0"
}
```

### Custom Test Utilities
```typescript
// renderWithProviders - Wrap with necessary providers
export const renderWithProviders = (
  ui: React.ReactElement,
  options?: RenderOptions
) => {
  return render(ui, {
    wrapper: ({ children }) => (
      <TestProviders>
        {children}
      </TestProviders>
    ),
    ...options,
  });
};

// waitForLoadingToFinish - Common async pattern
export const waitForLoadingToFinish = () =>
  waitFor(() => {
    expect(screen.queryByText('Loading...')).not.toBeInTheDocument();
  });
```

### Global Test Setup
```typescript
// tests/setup.ts
import '@testing-library/jest-dom';

// Mock common browser APIs
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Suppress console warnings in tests
beforeAll(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});
```

---

## 📊 Quality Metrics & Monitoring

### Automated Quality Gates
```yaml
# CI/CD Pipeline Checks
test_quality:
  coverage_threshold: 70%
  test_execution_time: <30s
  flaky_test_rate: <5%
  accessibility_violations: 0
  security_vulnerabilities: 0
```

### Code Review Checklist
```
□ All new code has corresponding tests
□ Tests follow naming conventions
□ Test descriptions are clear and specific
□ Accessibility tests are included for UI components
□ Mock usage is appropriate and minimal
□ Test execution time is reasonable
□ No flaky or intermittent test failures
□ Coverage thresholds are met
```

### Performance Monitoring
```typescript
// Test execution time monitoring
beforeEach(() => {
  global.testStartTime = performance.now();
});

afterEach(() => {
  const duration = performance.now() - global.testStartTime;
  if (duration > 1000) { // 1 second threshold
    console.warn(`Slow test detected: ${duration.toFixed(2)}ms`);
  }
});
```

---

## 🚨 Anti-Patterns to Avoid

### Common Testing Mistakes
```typescript
// ❌ BAD - Testing implementation details
expect(component.state.isLoading).toBe(true);

// ✅ GOOD - Testing user-visible behavior
expect(screen.getByText('Loading...')).toBeInTheDocument();

// ❌ BAD - Brittle selectors
expect(container.querySelector('.css-123abc')).toBeInTheDocument();

// ✅ GOOD - Semantic queries
expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument();

// ❌ BAD - Large, unfocused tests
it('should handle everything', () => {
  // Tests 10 different scenarios
});

// ✅ GOOD - Focused, single-purpose tests
it('should show error when username is empty');
it('should disable submit button when form is invalid');
```

### Flaky Test Prevention
```typescript
// ✅ Use waitFor for async operations
await waitFor(() => {
  expect(screen.getByText('Success')).toBeInTheDocument();
});

// ✅ Use fake timers for time-dependent code
jest.useFakeTimers();
// ... test code ...
jest.runAllTimers();
jest.useRealTimers();

// ✅ Clean up after tests
afterEach(() => {
  jest.clearAllMocks();
  cleanup();
});
```

---

## 📚 Resources & Documentation

### Testing Library Resources
- [React Testing Library Docs](https://testing-library.com/docs/react-testing-library/intro/)
- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [jest-axe for Accessibility](https://github.com/nickcolley/jest-axe)

### Best Practices References
- [Kent C. Dodds Testing Blog](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)
- [Testing Trophy](https://kentcdodds.com/blog/the-testing-trophy-and-testing-classifications)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)

### Internal Documentation
- `tests/README.md` - Project-specific testing guidelines
- `tests/examples/` - Test implementation examples
- `tests/utils/` - Shared testing utilities

---

## 🎯 Enforcement & Compliance

### Required for All PRs
1. ✅ Tests pass in CI/CD pipeline
2. ✅ Coverage thresholds are met
3. ✅ No accessibility violations
4. ✅ Code review approval
5. ✅ Quality gate checks pass

### Monitoring & Reporting
- Daily coverage reports
- Weekly quality metrics review
- Monthly testing standard updates
- Quarterly testing strategy review

---

**Quality Standards Maintained by Hive Mind Tester Agent**  
*Ensuring excellence through systematic validation*