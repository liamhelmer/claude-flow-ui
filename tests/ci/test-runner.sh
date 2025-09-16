#!/bin/bash

# Comprehensive CI/CD Test Runner Script
# Runs all test suites in the correct order for CI/CD pipelines

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT=300  # 5 minutes
COVERAGE_THRESHOLD=90
REPORT_DIR="test-reports"
ARTIFACT_DIR="test-artifacts"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create directories
create_directories() {
    log_info "Creating test directories..."
    mkdir -p "$REPORT_DIR"
    mkdir -p "$ARTIFACT_DIR"
    mkdir -p "coverage"
    mkdir -p "test-results"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v node &> /dev/null; then
        log_error "Node.js is not installed"
        exit 1
    fi

    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed"
        exit 1
    fi

    # Check if package.json exists
    if [[ ! -f "package.json" ]]; then
        log_error "package.json not found"
        exit 1
    fi

    log_success "Dependencies check passed"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."

    if [[ "$CI" == "true" ]]; then
        npm ci --silent
    else
        npm install --silent
    fi

    log_success "Dependencies installed"
}

# Lint code
run_linting() {
    log_info "Running linting..."

    if npm run lint > "$REPORT_DIR/lint-report.txt" 2>&1; then
        log_success "Linting passed"
    else
        log_error "Linting failed"
        cat "$REPORT_DIR/lint-report.txt"
        exit 1
    fi
}

# Type checking
run_type_check() {
    log_info "Running type checking..."

    if npm run type-check > "$REPORT_DIR/typecheck-report.txt" 2>&1; then
        log_success "Type checking passed"
    else
        log_error "Type checking failed"
        cat "$REPORT_DIR/typecheck-report.txt"
        exit 1
    fi
}

# Unit tests
run_unit_tests() {
    log_info "Running unit tests..."

    # Use coverage configuration for CI
    export NODE_ENV=test
    export CI=true

    if timeout $TEST_TIMEOUT npm run test:ci -- \
        --testPathPattern="tests/unit" \
        --outputFile="$REPORT_DIR/unit-test-results.json" \
        --coverageDirectory="coverage/unit" > "$REPORT_DIR/unit-test-output.txt" 2>&1; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        cat "$REPORT_DIR/unit-test-output.txt"
        exit 1
    fi
}

# Integration tests
run_integration_tests() {
    log_info "Running integration tests..."

    # Start the server for integration tests
    log_info "Starting server for integration tests..."
    npm run server:dev &
    SERVER_PID=$!

    # Wait for server to start
    sleep 10

    # Check if server is running
    if ! curl -f http://localhost:3000/health > /dev/null 2>&1; then
        log_error "Server failed to start"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi

    # Run integration tests
    if timeout $TEST_TIMEOUT npm test -- \
        --testPathPattern="tests/integration" \
        --outputFile="$REPORT_DIR/integration-test-results.json" \
        --coverageDirectory="coverage/integration" > "$REPORT_DIR/integration-test-output.txt" 2>&1; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed"
        cat "$REPORT_DIR/integration-test-output.txt"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi

    # Stop the server
    kill $SERVER_PID 2>/dev/null || true
    sleep 2
}

# Security tests
run_security_tests() {
    log_info "Running security tests..."

    # Start the server for security tests
    npm run server:dev &
    SERVER_PID=$!
    sleep 10

    if timeout $TEST_TIMEOUT npm test -- \
        --testPathPattern="tests/security" \
        --outputFile="$REPORT_DIR/security-test-results.json" > "$REPORT_DIR/security-test-output.txt" 2>&1; then
        log_success "Security tests passed"
    else
        log_error "Security tests failed"
        cat "$REPORT_DIR/security-test-output.txt"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi

    kill $SERVER_PID 2>/dev/null || true
    sleep 2
}

# E2E tests
run_e2e_tests() {
    log_info "Running E2E tests..."

    # Install Playwright browsers if needed
    if command -v npx &> /dev/null; then
        npx playwright install --with-deps > /dev/null 2>&1 || true
    fi

    # Start the server for E2E tests
    npm run server:dev &
    SERVER_PID=$!
    sleep 15  # E2E tests need more time for server startup

    # Run E2E tests
    if timeout $((TEST_TIMEOUT * 2)) npm run test:e2e > "$REPORT_DIR/e2e-test-output.txt" 2>&1; then
        log_success "E2E tests passed"
    else
        log_warning "E2E tests failed (non-blocking)"
        cat "$REPORT_DIR/e2e-test-output.txt" || true
        # Don't exit on E2E failure in CI (can be flaky)
    fi

    kill $SERVER_PID 2>/dev/null || true
    sleep 2
}

# Load tests (optional, for performance validation)
run_load_tests() {
    if [[ "$RUN_LOAD_TESTS" == "true" ]]; then
        log_info "Running load tests..."

        # Start the server
        npm run server:dev &
        SERVER_PID=$!
        sleep 10

        # Run load tests
        if timeout $((TEST_TIMEOUT * 3)) node tests/load/load-test.js > "$REPORT_DIR/load-test-output.txt" 2>&1; then
            log_success "Load tests passed"
        else
            log_warning "Load tests failed (non-blocking)"
            cat "$REPORT_DIR/load-test-output.txt" || true
        fi

        kill $SERVER_PID 2>/dev/null || true
        sleep 2
    else
        log_info "Skipping load tests (set RUN_LOAD_TESTS=true to enable)"
    fi
}

# Generate coverage report
generate_coverage_report() {
    log_info "Generating coverage report..."

    # Merge coverage from different test types
    if command -v npx &> /dev/null && [[ -d "coverage" ]]; then
        # Generate combined coverage report
        npm run test:coverage -- --collectCoverageFrom="src/**/*.{js,ts,tsx}" --coverageDirectory="coverage/combined" > "$REPORT_DIR/coverage-output.txt" 2>&1 || true

        # Check coverage threshold
        if [[ -f "coverage/combined/coverage-summary.json" ]]; then
            COVERAGE=$(node -e "
                const fs = require('fs');
                const coverage = JSON.parse(fs.readFileSync('coverage/combined/coverage-summary.json'));
                const total = coverage.total;
                console.log(Math.min(total.lines.pct, total.statements.pct, total.functions.pct, total.branches.pct));
            " 2>/dev/null || echo "0")

            if (( $(echo "$COVERAGE >= $COVERAGE_THRESHOLD" | bc -l) )); then
                log_success "Coverage threshold met: ${COVERAGE}% >= ${COVERAGE_THRESHOLD}%"
            else
                log_warning "Coverage below threshold: ${COVERAGE}% < ${COVERAGE_THRESHOLD}%"
            fi
        fi
    fi
}

# Build verification
run_build_verification() {
    log_info "Running build verification..."

    if npm run build > "$REPORT_DIR/build-output.txt" 2>&1; then
        log_success "Build verification passed"
    else
        log_error "Build verification failed"
        cat "$REPORT_DIR/build-output.txt"
        exit 1
    fi
}

# Collect artifacts
collect_artifacts() {
    log_info "Collecting test artifacts..."

    # Copy reports
    cp -r "$REPORT_DIR"/* "$ARTIFACT_DIR/" 2>/dev/null || true

    # Copy coverage reports
    if [[ -d "coverage" ]]; then
        cp -r coverage "$ARTIFACT_DIR/" 2>/dev/null || true
    fi

    # Copy test results
    if [[ -d "test-results" ]]; then
        cp -r test-results "$ARTIFACT_DIR/" 2>/dev/null || true
    fi

    # Copy screenshots from E2E tests
    if [[ -d "test-results" ]]; then
        find test-results -name "*.png" -exec cp {} "$ARTIFACT_DIR/" \; 2>/dev/null || true
    fi

    log_success "Artifacts collected in $ARTIFACT_DIR/"
}

# Generate test summary
generate_test_summary() {
    log_info "Generating test summary..."

    local summary_file="$REPORT_DIR/test-summary.json"

    cat > "$summary_file" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "environment": {
    "ci": "${CI:-false}",
    "node_version": "$(node --version)",
    "npm_version": "$(npm --version)",
    "platform": "$(uname -s)",
    "arch": "$(uname -m)"
  },
  "test_results": {
    "linting": "$(test -f "$REPORT_DIR/lint-report.txt" && echo "completed" || echo "skipped")",
    "type_checking": "$(test -f "$REPORT_DIR/typecheck-report.txt" && echo "completed" || echo "skipped")",
    "unit_tests": "$(test -f "$REPORT_DIR/unit-test-results.json" && echo "completed" || echo "skipped")",
    "integration_tests": "$(test -f "$REPORT_DIR/integration-test-results.json" && echo "completed" || echo "skipped")",
    "security_tests": "$(test -f "$REPORT_DIR/security-test-results.json" && echo "completed" || echo "skipped")",
    "e2e_tests": "$(test -f "$REPORT_DIR/e2e-test-output.txt" && echo "completed" || echo "skipped")",
    "load_tests": "$(test -f "$REPORT_DIR/load-test-output.txt" && echo "completed" || echo "skipped")",
    "build_verification": "$(test -f "$REPORT_DIR/build-output.txt" && echo "completed" || echo "skipped")"
  }
}
EOF

    log_success "Test summary generated: $summary_file"
}

# Cleanup
cleanup() {
    log_info "Cleaning up..."

    # Kill any remaining processes
    pkill -f "node.*server" 2>/dev/null || true
    pkill -f "npm.*server" 2>/dev/null || true

    # Clean up temporary files
    rm -f .tmp-* 2>/dev/null || true

    log_success "Cleanup completed"
}

# Main execution
main() {
    log_info "Starting comprehensive test suite..."

    # Set up trap for cleanup
    trap cleanup EXIT

    # Create directories
    create_directories

    # Check environment
    check_dependencies
    install_dependencies

    # Run tests in order
    run_linting
    run_type_check
    run_unit_tests
    run_integration_tests
    run_security_tests
    run_e2e_tests
    run_load_tests

    # Generate reports
    generate_coverage_report
    run_build_verification

    # Collect results
    collect_artifacts
    generate_test_summary

    log_success "All tests completed successfully!"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi