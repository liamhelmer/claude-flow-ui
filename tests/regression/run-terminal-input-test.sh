#!/bin/bash

# Terminal Input Regression Test Runner
echo "🧪 Running Terminal Input Regression Tests..."
echo "================================================"

# Check if dependencies are installed
if ! command -v npx &> /dev/null; then
    echo "❌ npx not found. Please install Node.js and npm."
    exit 1
fi

# Install Playwright if not already installed
if [ ! -d "node_modules/@playwright" ]; then
    echo "📦 Installing Playwright..."
    npm install --save-dev @playwright/test
    npx playwright install chromium
fi

# Build the project first
echo "🔨 Building production bundle..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Please fix build errors first."
    exit 1
fi

# Run the regression test
echo "🎭 Starting Playwright tests..."
npx playwright test tests/regression/terminal-input.spec.js --reporter=list

# Capture test result
TEST_RESULT=$?

if [ $TEST_RESULT -eq 0 ]; then
    echo "✅ All terminal input tests passed!"
    echo "The terminal input functionality is working correctly."
else
    echo "❌ Terminal input tests failed!"
    echo "The bug is reproduced. Terminal input is not displaying characters."
    echo ""
    echo "To debug further:"
    echo "1. Run: npx playwright test tests/regression/terminal-input.spec.js --debug"
    echo "2. Check screenshots in tests/regression/debug-*.png"
    echo "3. Review console logs above for specific failures"
fi

echo "================================================"
exit $TEST_RESULT