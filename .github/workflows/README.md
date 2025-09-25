# GitHub Actions CI/CD Workflows

This directory contains comprehensive GitHub Actions workflows for automated testing, deployment, and monitoring of the claude-flow-ui project.

## Workflow Overview

### 🔄 Core Workflows

1. **[pr-validation.yml](./pr-validation.yml)** - Fast feedback for pull requests
2. **[main-integration.yml](./main-integration.yml)** - Comprehensive testing on main branch
3. **[release-pipeline.yml](./release-pipeline.yml)** - Production deployment pipeline
4. **[scheduled-testing.yml](./scheduled-testing.yml)** - Nightly regression and monitoring

### 🚀 PR Validation Workflow

**Triggers:** Pull requests to `main` or `develop`
**Duration:** ~8-12 minutes
**Purpose:** Fast feedback with critical tests only

**Test Matrix:**
- **Node.js Versions:** 18.x, 20.x, 22.x
- **Code Quality:** Linting, type checking, formatting
- **Security:** npm audit, vulnerability scanning
- **Unit Tests:** Core functionality with 80% coverage threshold
- **Integration Tests:** Database and Redis connectivity
- **Smoke Tests:** Critical E2E flows (Chromium only)
- **Build Verification:** Production build validation

**Key Features:**
- ✅ Skips draft PRs unless labeled `run-tests`
- ✅ Parallel execution for fast feedback
- ✅ Coverage threshold enforcement (80%)
- ✅ Security vulnerability blocking
- ✅ Optional preview deployment with `deploy-preview` label
- ✅ Comprehensive status reporting

### 🏗️ Main Branch Integration

**Triggers:** Pushes to `main`, manual dispatch
**Duration:** ~25-35 minutes
**Purpose:** Full validation before staging deployment

**Test Matrix:**
- **Node.js Versions:** 18.x, 20.x, 22.x
- **Browsers:** Chromium, Firefox, WebKit
- **Services:** PostgreSQL, Redis, Elasticsearch
- **Environments:** Full service stack testing

**Test Suites:**
1. **Quality & Security** - Comprehensive code analysis
2. **Unit Tests** - 90% coverage requirement for main
3. **Integration Tests** - Full service integration
4. **E2E Tests** - Cross-browser validation
5. **Performance Tests** - Lighthouse, load testing
6. **Regression Tests** - Accessibility, visual, mobile
7. **Build Verification** - Multi-Node production builds

**Deployment:**
- ✅ Automatic staging deployment on success
- ✅ Post-deployment validation
- ✅ Performance benchmarking
- ✅ Comprehensive reporting

### 🎯 Release Pipeline

**Triggers:** Git tags (`v*.*.*`), releases, manual dispatch
**Duration:** ~45-60 minutes
**Purpose:** Production-ready release deployment

**Validation Stages:**
1. **Release Preparation** - Version validation, release notes
2. **Comprehensive Regression** - Full test matrix across Node versions
3. **Security Compliance** - OWASP, license, container scanning
4. **Production Build** - Multi-arch optimized builds
5. **Staging Validation** - Pre-production testing
6. **Production Deployment** - Blue-green deployment with rollback
7. **NPM Publishing** - Package registry updates

**Test Coverage:**
- **Security Audit** - Critical/high vulnerability blocking
- **Cross-browser E2E** - All major browsers
- **Performance Validation** - Regression detection
- **Accessibility Compliance** - WCAG validation
- **Mobile Compatibility** - Responsive design testing
- **API Contract Validation** - Backward compatibility

**Deployment Features:**
- ✅ Pre-deployment backup
- ✅ Health checks and validation
- ✅ Automatic rollback on failure
- ✅ GitHub release creation
- ✅ NPM package publishing

### 📅 Scheduled Testing

**Schedules:**
- **Nightly** (2 AM UTC) - Regression testing
- **Weekly** (Sunday 4 AM UTC) - Comprehensive testing
- **Monthly** (1st at 6 AM UTC) - Dependency updates

**Test Types:**

#### Nightly Regression
- Unit and integration tests
- E2E smoke tests
- API health checks
- Environment monitoring

#### Weekly Comprehensive
- Full cross-browser E2E testing
- Accessibility compliance
- Visual regression testing
- Performance monitoring

#### Monthly Maintenance
- Dependency updates (automated PRs)
- Security vulnerability scanning
- License compliance checking
- Performance trend analysis

**Monitoring Features:**
- ✅ Environment health checks
- ✅ Performance regression detection
- ✅ Security vulnerability tracking
- ✅ Automated dependency PRs
- ✅ Trend analysis and reporting

## Configuration

### Environment Variables

Required secrets in GitHub repository settings:

```bash
# Code coverage
CODECOV_TOKEN=your_codecov_token

# NPM publishing
NPM_TOKEN=your_npm_token

# Optional: Slack/Discord notifications
SLACK_WEBHOOK_URL=your_slack_webhook
DISCORD_WEBHOOK_URL=your_discord_webhook
```

### Environment Configuration

**Staging Environment:**
- URL: `https://staging.claude-flow-ui.com`
- Purpose: Pre-production testing
- Features: Full functionality, test data

**Production Environment:**
- URL: `https://claude-flow-ui.com`
- Purpose: Live application
- Features: Production data, monitoring

### Branch Protection

Recommended branch protection rules for `main`:

```yaml
required_status_checks:
  strict: true
  contexts:
    - "Code Quality"
    - "Unit Tests"
    - "Security Scan"
    - "Build Verification"
    - "PR Validation Summary"

required_pull_request_reviews:
  required_approving_review_count: 1
  dismiss_stale_reviews: true
  require_code_owner_reviews: true

enforce_admins: false
allow_deletions: false
allow_force_pushes: false
```

## Test Organization

### Test File Structure
```
tests/
├── unit/                    # Jest unit tests
├── integration/             # Service integration tests
├── e2e/                     # Playwright E2E tests
│   ├── accessibility/       # WCAG compliance tests
│   ├── visual/              # Visual regression tests
│   ├── mobile/              # Mobile responsive tests
│   ├── performance/         # Performance E2E tests
│   └── api/                 # API contract tests
├── performance/             # Load and performance tests
└── security/                # Security validation tests
```

### Test Tagging

Use test tags for selective execution:

```typescript
// Smoke tests for PR validation
test.describe('Login Flow @smoke', () => {
  // Critical user flows
});

// Full regression for releases
test.describe('User Management @regression', () => {
  // Comprehensive functionality
});

// Performance tests
test.describe('Page Load Performance @performance', () => {
  // Load time validation
});
```

## Performance Thresholds

### Coverage Requirements
- **Pull Requests:** 80% line coverage minimum
- **Main Branch:** 85% line coverage minimum
- **Releases:** 90% line coverage minimum

### Performance Benchmarks
- **Lighthouse Performance:** ≥80 (production), ≥75 (staging)
- **First Contentful Paint:** <2s
- **Largest Contentful Paint:** <4s
- **Total Blocking Time:** <300ms

### Load Testing Thresholds
- **Requests/second:** ≥100 (staging), ≥50 (production)
- **Average Latency:** <500ms
- **P99 Latency:** <2000ms
- **Error Rate:** <1%

## Troubleshooting

### Common Issues

1. **Flaky E2E Tests**
   ```bash
   # Re-run with debug
   npx playwright test --debug --headed
   ```

2. **Coverage Threshold Failures**
   ```bash
   # Generate detailed coverage report
   npm run test:coverage
   open coverage/lcov-report/index.html
   ```

3. **Performance Regression**
   ```bash
   # Run local performance audit
   npm run lighthouse:desktop
   npm run test:performance:benchmarks
   ```

4. **Dependency Conflicts**
   ```bash
   # Clean install
   rm -rf node_modules package-lock.json
   npm install
   ```

### Workflow Debugging

Enable debug logging by setting repository secrets:
```bash
ACTIONS_STEP_DEBUG=true
ACTIONS_RUNNER_DEBUG=true
```

View detailed logs in workflow runs for debugging failures.

## Customization

### Adding New Test Suites

1. Create test files in appropriate directory
2. Update workflow matrix if needed
3. Add new test commands to package.json
4. Update coverage thresholds if necessary

### Modifying Deployment Targets

1. Update environment URLs in workflows
2. Add new environment secrets
3. Configure branch protection rules
4. Update deployment scripts

### Performance Monitoring

1. Add new Lighthouse audits
2. Configure performance budgets
3. Set up trend tracking
4. Add alerting thresholds

## Monitoring & Alerts

### GitHub Checks
- All workflows report status to PR checks
- Failed workflows block merging
- Detailed reports in workflow summaries

### External Monitoring
- Codecov for coverage tracking
- Lighthouse CI for performance
- Security advisories for vulnerabilities

### Notifications
Configure webhook notifications for:
- Failed releases
- Security vulnerabilities
- Performance regressions
- Coverage drops

---

*This CI/CD pipeline ensures high-quality, secure, and performant releases while providing fast feedback to developers.*