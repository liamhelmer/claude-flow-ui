# Regression Test Status Report

## Summary
Date: 2025-09-19
Total Test Files: 20 (Mixed Jest and Playwright tests)

## Test File Categories

### 1. ❌ **Non-Working Tests (Jest Tests Incompatible with Playwright)**
These files use Jest syntax and cannot be run with Playwright:

- `initial-terminal-input.test.js` - ReferenceError: expect is not defined
- `production-initial-terminal.test.js` - ReferenceError: describe is not defined
- `production-terminal-issues.test.js` - Error: Do not import @jest/globals
- `simple-initial-terminal-regression.test.js` - ReferenceError: describe is not defined
- `terminal-refresh-regression.test.js` - Jest test file
- `terminal-switching-regression.test.js` - Jest test file
- `terminal-workaround-validation.test.js` - Jest test file

### 2. ❌ **Non-Working Tests (TypeScript/JSX Syntax Issues)**
These files have syntax errors when run with Playwright:

- `terminal-config-regression.test.ts` - Unexpected JSX syntax in test
- `tmux-regression.test.ts` - ReferenceError: describe is not defined

### 3. ⚠️ **Partially Working Playwright Tests**
These Playwright tests run but have failures:

#### **listener-leak.spec.ts**
- ✘ Test 1: Listener Registration Count - Single Terminal
- ✘ Test 2: Listener Leak on Component Re-render
- ✘ Test 3: Listener Cleanup on Terminal Switch
- ✘ Test 4: Memory Leak Detection Over Time
- ✘ Test 5: Validate Proper Listener Deduplication
- ✘ Test 6: Verify useEffect Cleanup Functions
- **Issue**: Multiple listener registrations detected (4 listeners registered instead of expected 1)

#### **production-terminal-working.spec.ts**
- ✘ Terminal launches with claude-flow and processes input correctly
- **Issue**: Terminal UI not fully rendered in production mode

#### **production-terminal-input.spec.ts**
- ✘ Terminal receives and displays typed input in terminal-data
- **Issue**: Terminal UI not visible in production mode

#### **terminal-server-data-flow.spec.ts**
- ✘ Input typed into terminal is received by server
- **Issue**: Terminal UI not rendering properly, preventing input/output verification

### 4. ✅ **Potentially Working Playwright Tests**
These tests are properly formatted for Playwright and may work with fixes:

- `main-terminal-working.spec.ts`
- `production-terminal-data-flow.spec.ts`
- `sidebar-persistence.spec.ts`
- `sidebar-visibility.spec.ts`
- `single-terminal-instance.spec.ts`
- `terminal-data-flow.spec.ts`
- `terminal-input.spec.js`
- `terminal-switching.spec.ts`
- `working-terminal-data-flow.spec.ts`

## Key Issues Found

### 1. **Mixed Test Framework Problem**
- Many tests use Jest syntax (`describe`, `test`, `expect`) which is incompatible with Playwright
- Need to either:
  - Convert Jest tests to Playwright format
  - Set up separate test runners for Jest and Playwright tests

### 2. **Frontend Rendering Issues in Production**
- Terminal component not rendering properly in production builds
- Sidebar renders but terminal canvas is missing
- This affects all tests that require terminal interaction

### 3. **WebSocket Listener Duplication**
- Multiple listener registrations occurring (4x instead of 1x)
- Indicates potential memory leak in WebSocket event handling
- Each re-render adds listeners without proper cleanup

### 4. **Test Infrastructure Issues**
- No clear separation between unit tests (Jest) and E2E tests (Playwright)
- Missing test configuration files for different test types
- Some tests reference non-existent setup files

## Recommendations

### Immediate Actions:
1. **Fix Production Build Terminal Rendering** - Critical for all terminal-related tests
2. **Fix WebSocket Listener Cleanup** - Prevents memory leaks and test failures
3. **Separate Test Runners** - Configure Jest for unit tests, Playwright for E2E

### Test Organization:
1. Move Jest tests to `tests/unit/` directory
2. Keep Playwright tests in `tests/regression/`
3. Create separate npm scripts:
   - `npm run test:unit` - Run Jest tests
   - `npm run test:e2e` - Run Playwright tests
   - `npm run test:regression` - Run regression suite

### Priority Fixes:
1. **High**: Fix terminal rendering in production mode
2. **High**: Fix WebSocket listener duplication
3. **Medium**: Convert critical Jest tests to Playwright
4. **Low**: Clean up obsolete test files

## Test Commands

### Run Only Playwright Tests:
```bash
npx playwright test tests/regression/*.spec.ts tests/regression/*.spec.js
```

### Run Specific Test:
```bash
npx playwright test tests/regression/terminal-server-data-flow.spec.ts
```

### Run with Debug Output:
```bash
DEBUG_TMUX=1 npx playwright test --headed
```