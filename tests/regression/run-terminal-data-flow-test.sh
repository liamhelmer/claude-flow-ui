#!/bin/bash

# Terminal Data Flow Regression Test Runner
# This script runs the comprehensive terminal data flow regression test

set -e

echo "🧪 Terminal Data Flow Regression Test Runner"
echo "==========================================="

# Check if the application is running
echo "📡 Checking if application is running on localhost:3000..."
if ! curl -s http://localhost:3000 > /dev/null; then
    echo "❌ Application is not running on localhost:3000"
    echo "   Please start the application with: npm run dev"
    exit 1
fi

echo "✅ Application is running"

# Check if Playwright is installed
echo "🎭 Checking Playwright installation..."
if ! npx playwright --version > /dev/null 2>&1; then
    echo "❌ Playwright is not installed"
    echo "   Installing Playwright..."
    npx playwright install
fi

echo "✅ Playwright is ready"

# Run the terminal data flow regression test
echo "🚀 Running terminal data flow regression test..."
echo ""

npx playwright test tests/regression/terminal-data-flow.spec.ts \
    --headed \
    --timeout=30000 \
    --workers=1 \
    --reporter=line,html:tests/regression/reports/terminal-data-flow-report.html

TEST_EXIT_CODE=$?

echo ""
echo "📊 Test Results:"
echo "==============="

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All terminal data flow tests passed!"
    echo "📄 Detailed report: tests/regression/reports/terminal-data-flow-report.html"
else
    echo "❌ Some terminal data flow tests failed"
    echo "📄 Check detailed report: tests/regression/reports/terminal-data-flow-report.html"
    echo "📋 Debug logs are available in the test output above"
fi

echo ""
echo "🔍 Quick Debug Commands:"
echo "----------------------"
echo "View browser console: Open test in headed mode (already enabled)"
echo "Check WebSocket: Open browser dev tools > Network > WS tab"
echo "Inspect terminal: Right-click terminal > Inspect Element"

exit $TEST_EXIT_CODE