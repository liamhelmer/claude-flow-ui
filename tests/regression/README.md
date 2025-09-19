# Terminal Regression Test Suite

## Overview

This comprehensive regression test suite is designed to reproduce, validate, and document specific terminal refresh and switching issues. The tests are automated using Playwright for browser automation and provide detailed reports for developers to understand and fix the issues.

## Test Suite Components

### 🔴 Terminal Refresh Regression Test
**File:** `terminal-refresh-regression.test.js`

**Objective:** Reproduce the terminal refresh issue where:
- Input reaches backend successfully (confirmed in logs)
- New data does NOT appear in terminal display
- Display remains stale/unupdated despite backend processing

**Key Features:**
- Automated reproduction of the exact issue
- Backend reception confirmation via console log monitoring
- Display update detection and validation
- Multiple refresh operation attempts
- Detailed event tracking and analysis

### 🔄 Terminal Switching Regression Test
**File:** `terminal-switching-regression.test.js`

**Objective:** Reproduce terminal switching issues where:
- Multiple terminals are created successfully
- Clicking to switch between terminals shows wrong terminal content
- Session routing gets confused between terminals
- Expected terminal content doesn't appear when switching

**Key Features:**
- Creates 4 terminals with unique identifiers
- Tests switching between terminals using multiple methods
- Validates session isolation between terminals
- Detects wrong terminal content display
- Comprehensive session routing analysis

### 🔧 Terminal Workaround Validation Test
**File:** `terminal-workaround-validation.test.js`

**Objective:** Validate the documented workaround:
1. Reproduce the refresh issue (input not appearing)
2. Apply the workaround (create new terminal + switch back)
3. Confirm that input now appears (workaround effectiveness)
4. Test workaround reliability with multiple attempts

**Key Features:**
- 4-step workaround validation process
- Reliability testing (multiple attempts)
- Effectiveness measurement
- Alternative workaround method testing
- User-friendly workaround documentation

### 🏃 Regression Test Runner
**File:** `run-regression-tests.js`

**Objective:** Orchestrate execution of all regression tests with unified reporting.

**Key Features:**
- Sequential execution of all tests
- Comprehensive reporting and analysis
- Command-line options for targeted testing
- JSON report generation
- Exit codes for CI/CD integration

### 🔍 Validation Script
**File:** `validate-regression-tests.js`

**Objective:** Validate that the test infrastructure is properly set up and ready to run.

**Key Features:**
- File existence and structure validation
- Module import testing
- Method availability verification
- Smoke testing of all components
- Usage examples and documentation

## Quick Start

### 1. Validate Test Infrastructure
```bash
node tests/regression/validate-regression-tests.js
```

### 2. Run All Regression Tests
```bash
node tests/regression/run-regression-tests.js
```

### 3. Run Individual Tests
```bash
# Terminal refresh issue
node tests/regression/terminal-refresh-regression.test.js

# Terminal switching issue
node tests/regression/terminal-switching-regression.test.js

# Workaround validation
node tests/regression/terminal-workaround-validation.test.js
```

## Command Line Options

### Full Test Suite Options
```bash
# Run all tests (default)
node tests/regression/run-regression-tests.js

# Run specific test only
node tests/regression/run-regression-tests.js --refresh-only
node tests/regression/run-regression-tests.js --switching-only
node tests/regression/run-regression-tests.js --workaround-only

# Exit on first failure (useful for CI/CD)
node tests/regression/run-regression-tests.js --exit-on-failure

# Skip report generation
node tests/regression/run-regression-tests.js --no-report

# Show help
node tests/regression/run-regression-tests.js --help
```

## Test Results and Exit Codes

### Exit Codes
- `0`: All tests passed, no regressions detected
- `1`: Test failures or regressions detected

### Result Types
- **SUCCESS**: Test passed, no regression detected
- **REGRESSION DETECTED**: Issue reproduced successfully
- **TEST FAILURE**: Technical failure preventing test completion

## Reports and Output

### Console Output
Each test provides real-time progress updates:
- 🚀 Initialization steps
- ⌨️ Input events
- 📤 Backend responses
- 📊 Results analysis
- ✅/❌ Success/failure indicators

### JSON Reports
Comprehensive reports are saved as:
```
tests/regression/regression-report-{timestamp}.json
```

Report structure:
```json
{
  "summary": {
    "testSuite": "Terminal Regression Tests",
    "timestamp": "ISO date",
    "regressionIssuesFound": 0,
    "criticalIssues": []
  },
  "testResults": {
    "refresh": { "status": "PASSED|FAILED", "regressionDetected": false },
    "switching": { "status": "PASSED|FAILED", "regressionDetected": false },
    "workaround": { "status": "PASSED|FAILED", "workaroundValidated": false }
  },
  "analysis": ["Key findings and insights"],
  "recommendations": ["Actionable developer recommendations"]
}
```

## Technical Details

### Test Architecture
- **Browser Automation**: Playwright (Chromium)
- **Server Management**: Node.js child_process spawn
- **Event Tracking**: Console log monitoring + network interception
- **Assertion Strategy**: Display content comparison + backend confirmation
- **Cleanup**: Automatic browser and server cleanup

### Port Usage
Tests use different ports to avoid conflicts:
- Refresh Test: Port 11250
- Switching Test: Port 11251
- Workaround Test: Port 11252

### Dependencies
- `playwright` - Browser automation
- `Node.js` - Test execution environment
- Terminal server running via `npm run claude-flow-ui`

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```
   Error: Server timeout
   ```
   - Solution: Ensure no other processes are using the test ports
   - Check: `lsof -i :11250`, `lsof -i :11251`, `lsof -i :11252`

2. **Browser Launch Issues**
   ```
   Error: Failed to launch browser
   ```
   - Solution: Install Playwright browsers: `npx playwright install`

3. **Server Startup Failures**
   ```
   Error: Server startup timeout
   ```
   - Solution: Check if `npm run claude-flow-ui` works manually
   - Verify: Dependencies are installed (`npm install`)

### Debug Mode
For verbose output, check the console logs during test execution. Each test provides detailed step-by-step progress.

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Run Terminal Regression Tests
  run: |
    npm install
    npx playwright install
    node tests/regression/validate-regression-tests.js
    node tests/regression/run-regression-tests.js --exit-on-failure
```

### Test Results
- Exit code 0: All tests passed
- Exit code 1: Regressions detected or test failures
- JSON reports available for parsing and analysis

## Developer Guide

### Understanding Regression Results

#### 🔴 Refresh Regression Confirmed
**Symptoms:**
- Backend receives input correctly (confirmed in logs)
- Terminal display does not update
- Manual refresh operations are ineffective

**Investigation Areas:**
- WebSocket event handling
- Terminal DOM manipulation
- Display update mechanisms
- Viewport rendering logic

#### 🔄 Switching Regression Confirmed
**Symptoms:**
- Wrong terminal content displayed when switching
- Session isolation compromised
- Terminal routing logic issues

**Investigation Areas:**
- Session management logic
- Terminal routing mechanisms
- Multiple terminal handling
- Session ID validation

#### 🔧 Workaround Validated
**Implications:**
- Temporary solution available for users
- Issue is in terminal initialization/refresh logic
- Creating new terminal + switching back fixes the problem

**Investigation Focus:**
- Terminal lifecycle management
- Session initialization logic
- Why workaround resolves the issue

### Adding New Regression Tests

1. Create new test file in `/tests/regression/`
2. Follow the class structure pattern:
   ```javascript
   class NewRegressionTest {
     async initialize() { /* Setup */ }
     async performTest() { /* Main test logic */ }
     async cleanup() { /* Cleanup */ }
     async run() { /* Orchestration */ }
   }
   ```
3. Add to `run-regression-tests.js`
4. Update this README

## Support and Maintenance

### Regular Testing
- Run regression tests before releases
- Include in CI/CD pipeline
- Monitor for new edge cases

### Test Maintenance
- Update browser dependencies regularly
- Adjust timeouts based on system performance
- Monitor for UI changes that affect selectors

### Issue Reporting
When regression tests detect issues:
1. Check the detailed JSON report
2. Review console logs from test execution
3. Run individual tests for focused debugging
4. Include report data in bug reports

---

**Last Updated:** September 2025
**Test Suite Version:** 1.0
**Maintainer:** Claude Code (Automated Testing Specialist)