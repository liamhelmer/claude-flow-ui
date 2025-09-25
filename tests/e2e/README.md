# E2E Testing Framework for Claude Flow UI

A comprehensive end-to-end testing framework built with Playwright, designed to ensure the reliability, performance, and accessibility of Claude Flow UI across multiple browsers and scenarios.

## 🎯 Overview

This E2E testing framework provides:

- **Multi-browser support**: Chrome, Firefox, Safari, and mobile browsers
- **Page Object Model**: Maintainable and reusable test structure
- **Visual regression testing**: Automated screenshot comparison
- **Performance monitoring**: Core Web Vitals and loading metrics
- **Accessibility validation**: WCAG compliance testing
- **Real-time WebSocket testing**: Connection reliability and data flow
- **API testing**: REST endpoints and authentication
- **Backstage integration**: Plugin compatibility testing

## 🏗️ Architecture

```
tests/e2e/
├── config/                     # Global setup and teardown
│   ├── global-setup.ts
│   └── global-teardown.ts
├── fixtures/                   # Test fixtures and data factories
│   └── test-fixtures.ts
├── page-objects/              # Page Object Model classes
│   ├── BasePage.ts
│   ├── TerminalPage.ts
│   └── BackstagePage.ts
├── utils/                     # Test utilities and helpers
│   ├── custom-matchers.ts
│   └── test-utilities.ts
├── terminal/                  # Terminal functionality tests
├── websocket/                # WebSocket communication tests
├── scrollback/               # Scrollback functionality tests
├── api/                      # REST API tests
├── performance/              # Performance and accessibility tests
├── visual/                   # Visual regression tests (auto-generated)
├── reports/                  # Test reports and artifacts
├── screenshots/              # Screenshots on failure
├── videos/                   # Video recordings
└── playwright.config.ts      # Main configuration
```

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- Claude Flow UI application running

### Installation

```bash
# Install dependencies (if not already done)
npm install

# Install Playwright browsers
npm run test:e2e:install

# Or install specific browsers
npx playwright install chromium firefox webkit
```

### Basic Usage

```bash
# Run all E2E tests
npm run test:e2e

# Run tests with browser UI (headed mode)
npm run test:e2e:headed

# Run tests in interactive UI mode
npm run test:e2e:ui

# Run specific test suites
npm run test:e2e:terminal      # Terminal functionality
npm run test:e2e:websocket     # WebSocket communication
npm run test:e2e:scrollback    # Scrollback features
npm run test:e2e:api           # REST API tests
npm run test:e2e:backstage     # Backstage integration

# Run browser-specific tests
npm run test:e2e:chromium
npm run test:e2e:firefox
npm run test:e2e:webkit

# Run mobile and responsive tests
npm run test:e2e:mobile

# Run performance and accessibility tests
npm run test:e2e:performance
npm run test:e2e:accessibility

# Visual regression testing
npm run test:e2e:visual
```

## 🧪 Test Categories

### 1. Terminal Functionality (`tests/e2e/terminal/`)

Tests core terminal operations:
- Command execution and output validation
- Command history and navigation
- Terminal controls (clear, scroll, resize)
- Error handling and recovery
- Keyboard shortcuts and accessibility
- Performance with large outputs

### 2. WebSocket Communication (`tests/e2e/websocket/`)

Tests real-time communication:
- Connection establishment and management
- Message exchange and streaming
- Reconnection after network issues
- High-frequency message handling
- Connection stability under load
- Error scenarios and graceful degradation

### 3. Scrollback Functionality (`tests/e2e/scrollback/`)

Tests terminal scrollback features:
- Scroll navigation and controls
- Buffer management and limits
- Scroll position persistence
- Performance with large content
- New output indicators
- Keyboard and mouse interaction

### 4. API Testing (`tests/e2e/api/`)

Tests REST API endpoints:
- Authentication and authorization
- Terminal session management
- Error handling and validation
- Rate limiting and security
- Performance and reliability
- CORS and headers

### 5. Performance & Accessibility (`tests/e2e/performance/`)

Tests performance and accessibility:
- Core Web Vitals (FCP, LCP, CLS, TBT)
- Loading performance and caching
- Memory usage and resource management
- WCAG accessibility compliance
- Screen reader support
- High contrast mode

### 6. Backstage Integration (`backstage-integration-workflows.spec.ts`)

Tests Backstage plugin integration:
- Plugin loading and navigation
- Theme integration and consistency
- Authentication flow
- Layout and responsive behavior
- State persistence across navigation
- Error recovery and stability

## 🎛️ Configuration

### Environment Variables

```bash
# Test environment configuration
BASE_URL=http://localhost:11235     # Application URL
BACKSTAGE_URL=http://localhost:3000 # Backstage URL (for integration tests)
API_BASE_URL=http://localhost:11235/api # API endpoint
TEST_API_KEY=your-test-key          # Test API key

# Test behavior configuration
CI=true                             # Enable CI mode
HEADED=false                        # Run in headless mode
SLOW_MO=0                           # Add delay between actions (ms)
```

### Browser Configuration

The framework supports multiple browser configurations:

- **Desktop**: Chrome, Firefox, Safari
- **Mobile**: Mobile Chrome, Mobile Safari, Tablet
- **High DPI**: High resolution displays
- **Specialized**: Performance testing, Visual regression

### Test Data Configuration

Test data is managed through factories in `fixtures/test-fixtures.ts`:

```typescript
// Example test data usage
test('should execute test commands', async ({ testData, terminalPage }) => {
  const commands = testData.getTestCommands();

  for (const command of commands) {
    await terminalPage.executeCommand(command.command);
    await terminalPage.waitForOutput(command.expectedOutput);
  }
});
```

## 📋 Page Object Model

### Base Page Object

All page objects extend `BasePage` for common functionality:

```typescript
import { BasePage } from '../page-objects/BasePage';

export class CustomPage extends BasePage {
  async customAction() {
    await this.clickElement('.custom-button');
    await this.waitForElement('.result');
  }
}
```

### Terminal Page Object

Specialized for terminal interactions:

```typescript
// Example usage
const terminalPage = new TerminalPage(page);
await terminalPage.waitForTerminalReady();
await terminalPage.executeCommand('echo "Hello World"');
await terminalPage.waitForOutput('Hello World');
```

### Backstage Page Object

Handles Backstage-specific functionality:

```typescript
const backstagePage = new BackstagePage(page);
await backstagePage.navigateToBackstage();
await backstagePage.navigateToClaudeFlowPlugin();
```

## 🔧 Custom Matchers

Extended assertions for domain-specific testing:

```typescript
// Terminal-specific matchers
await expect(terminalPage.terminalContainer).toBeConnectedTerminal();
await expect(terminalPage.terminalContainer).toHaveTerminalOutput('expected text');
await expect(terminalPage.terminalContainer).toHaveResponsiveTerminal(2000);

// Performance matchers
await expect(page).toLoadWithinBudget(3000);
await expect(page).toHaveGoodCoreWebVitals();

// Accessibility matchers
await expect(page).toPassA11yAudit();
await expect(terminalPage.terminalContainer).toHaveAccessibleTerminal();

// WebSocket matchers
await expect(page).toHaveActiveWebSocket();
await expect(page).toReceiveWebSocketMessage('terminal-data');
```

## 📊 Reporting and Artifacts

### Test Reports

- **HTML Report**: Interactive test results with screenshots and videos
- **JSON Report**: Machine-readable results for CI/CD integration
- **JUnit XML**: Compatible with various CI systems

### Artifacts

- **Screenshots**: Captured on test failures
- **Videos**: Recording of failed test runs
- **Traces**: Detailed execution traces for debugging
- **Visual Snapshots**: Baseline images for visual regression

### Accessing Reports

```bash
# View HTML report
npm run test:e2e:report

# Reports are saved to:
# - tests/e2e/reports/html/
# - tests/e2e/reports/test-results.json
# - tests/e2e/reports/junit.xml
```

## 🚨 Debugging Tests

### Debug Mode

```bash
# Run tests in debug mode (step through execution)
npm run test:e2e:debug

# Generate test code interactively
npm run test:e2e:codegen
```

### Browser Developer Tools

```bash
# Run with browser developer tools
npm run test:e2e:headed
```

### Verbose Output

Add `console.log` statements in tests or use Playwright's built-in logging:

```typescript
test('debug example', async ({ page }) => {
  await page.goto('/');

  // Take screenshot for debugging
  await page.screenshot({ path: 'debug-screenshot.png' });

  // Log page title
  console.log('Page title:', await page.title());
});
```

## ⚡ Performance Optimization

### Parallel Execution

Tests run in parallel by default. Configure in `playwright.config.ts`:

```typescript
workers: process.env.CI ? 2 : undefined, // Limit workers in CI
fullyParallel: true, // Enable parallel execution
```

### Test Isolation

Each test runs in a fresh browser context:
- Clean state between tests
- No test interference
- Reliable and consistent results

### Resource Management

- Automatic browser cleanup
- Memory leak detection
- Resource usage monitoring

## 🔄 CI/CD Integration

### GitHub Actions

The framework includes comprehensive GitHub Actions workflows:

- **Multi-browser testing**: Chrome, Firefox, Safari
- **Mobile and responsive testing**: Various device sizes
- **Visual regression testing**: Automated screenshot comparison
- **Performance testing**: Core Web Vitals monitoring
- **Accessibility testing**: WCAG compliance validation
- **Backstage integration**: Plugin compatibility testing

### Workflow Triggers

- **Push to main/develop**: Full test suite
- **Pull requests**: Focused testing
- **Nightly schedule**: Comprehensive testing
- **Manual dispatch**: On-demand testing

## 📝 Writing Tests

### Basic Test Structure

```typescript
import { test, expect } from '../fixtures/test-fixtures';

test.describe('Feature Tests', () => {
  test.beforeEach(async ({ terminalPage }) => {
    await terminalPage.goto();
    await terminalPage.waitForTerminalReady();
  });

  test('should perform basic operation', async ({ terminalPage }) => {
    await terminalPage.executeCommand('echo "test"');
    await expect(terminalPage.terminalContainer).toHaveTerminalOutput('test');
  });

  test.afterEach(async ({ page }) => {
    // Cleanup if needed
  });
});
```

### Best Practices

1. **Use Page Objects**: Encapsulate page interactions
2. **Wait for Elements**: Use explicit waits instead of timeouts
3. **Unique Selectors**: Use data-testid attributes
4. **Test Independence**: Each test should be independent
5. **Descriptive Names**: Test names should explain what they verify
6. **Error Scenarios**: Test both success and failure cases

### Test Data Management

Use the test data factory for consistent test data:

```typescript
test('should handle various commands', async ({ testData, terminalPage }) => {
  const commands = testData.getTestCommands();
  const errorScenarios = testData.getErrorScenarios();

  // Test successful commands
  for (const cmd of commands) {
    await terminalPage.executeCommand(cmd.command);
    await terminalPage.waitForOutput(cmd.expectedOutput);
  }

  // Test error scenarios
  for (const scenario of errorScenarios) {
    await terminalPage.executeCommand(scenario.command);
    await terminalPage.waitForOutput(scenario.expectedErrorText);
  }
});
```

## 🛠️ Maintenance

### Updating Baselines

Visual regression tests may need baseline updates:

```bash
# Update visual baselines
npm run test:e2e:visual -- --update-snapshots
```

### Browser Updates

Keep Playwright browsers updated:

```bash
# Update browsers
npx playwright install

# Update specific browser
npx playwright install chromium
```

### Configuration Updates

Review and update configuration regularly:
- Browser versions and settings
- Timeout values and retries
- Test data and fixtures
- CI/CD pipeline settings

## 🤝 Contributing

When adding new E2E tests:

1. Follow the existing Page Object Model structure
2. Use appropriate test data factories
3. Include proper error handling and cleanup
4. Add tests to relevant CI/CD workflows
5. Update documentation as needed

## 📚 Resources

- [Playwright Documentation](https://playwright.dev/)
- [Page Object Model Pattern](https://playwright.dev/docs/test-pom)
- [Visual Comparisons](https://playwright.dev/docs/test-screenshots)
- [Accessibility Testing](https://playwright.dev/docs/accessibility-testing)
- [Performance Testing](https://playwright.dev/docs/test-runners)

---

This E2E testing framework ensures Claude Flow UI delivers a reliable, performant, and accessible experience across all supported browsers and scenarios.