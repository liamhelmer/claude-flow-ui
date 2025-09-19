#!/bin/bash
# Terminal Input Regression Test Runner
#
# This script runs the comprehensive terminal input regression tests
# and provides detailed output about the terminal input issue.

set -e

echo "🧪 Terminal Input Regression Test Runner"
echo "========================================"
echo ""

# Check if Playwright is installed
if ! command -v npx playwright &> /dev/null; then
    echo "❌ Playwright not found. Installing..."
    npm install @playwright/test
    npx playwright install
fi

# Create results directory
mkdir -p tests/results

echo "📋 Running Tests:"
echo "  1. Simple demonstration test (visual)"
echo "  2. Comprehensive Playwright regression test"
echo ""

# Run the simple demo test first
echo "🎯 Step 1: Running simple demonstration test..."
echo "This test will show the browser and demonstrate the input issue visually."
echo "The browser will stay open for 30 seconds for manual inspection."
echo ""

if node tests/simple-terminal-input-demo.js; then
    echo "✅ Simple demo test: INPUT WORKING"
else
    echo "❌ Simple demo test: INPUT ISSUE CONFIRMED"
fi

echo ""
echo "🎯 Step 2: Running comprehensive Playwright tests..."
echo "These tests are designed to FAIL until the terminal input bug is fixed."
echo ""

# Run Playwright tests with custom config
if npx playwright test --config=tests/playwright.config.regression.js; then
    echo "✅ All regression tests passed - Terminal input is working!"
    exit 0
else
    echo "❌ Regression tests failed - Terminal input bug confirmed"
    echo ""
    echo "📊 Test Results:"
    echo "  - HTML Report: tests/results/regression-html/index.html"
    echo "  - JSON Results: tests/results/regression-results.json"
    echo "  - Videos: tests/results/artifacts/"
    echo ""
    echo "🔍 Debugging Information:"
    echo "  - Check console logs for WebSocket connection issues"
    echo "  - Verify terminal initialization sequence"
    echo "  - Check input event routing and session ID handling"
    echo "  - Look for 'sendData' function availability"
    exit 1
fi