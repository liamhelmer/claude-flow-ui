#!/bin/bash
# Test script to verify Backstage authentication startup

echo "🧪 Testing Backstage Authentication Startup..."
echo ""

# Set environment variables
export BACKSTAGE_URL="https://backstage.example.com"
export BACKSTAGE_REQUIRE_AUTH="true"
export BACKSTAGE_ALLOWED_GROUPS="group:default/test-group"
export PORT="8081"

echo "Environment Configuration:"
echo "  BACKSTAGE_URL=$BACKSTAGE_URL"
echo "  BACKSTAGE_REQUIRE_AUTH=$BACKSTAGE_REQUIRE_AUTH"
echo "  BACKSTAGE_ALLOWED_GROUPS=$BACKSTAGE_ALLOWED_GROUPS"
echo ""

echo "Starting server (will run for 5 seconds)..."
timeout 5s node unified-server.js 2>&1 | tee /tmp/auth-startup-test.log &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if authentication middleware was loaded
if grep -q "✅ Backstage authentication middleware enabled" /tmp/auth-startup-test.log; then
  echo "✅ SUCCESS: Authentication middleware loaded"
else
  echo "❌ FAILED: Authentication middleware not loaded"
  cat /tmp/auth-startup-test.log
  kill $SERVER_PID 2>/dev/null
  exit 1
fi

# Check if configuration was logged
if grep -q "🔐 Backstage Authentication Configuration:" /tmp/auth-startup-test.log; then
  echo "✅ SUCCESS: Configuration logged"
else
  echo "❌ FAILED: Configuration not logged"
  kill $SERVER_PID 2>/dev/null
  exit 1
fi

# Test unauthenticated request (should fail with 401)
echo ""
echo "Testing unauthenticated API request..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/api/health 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "401" ]; then
  echo "✅ SUCCESS: Unauthenticated request rejected with 401"
else
  echo "❌ FAILED: Expected 401, got $HTTP_CODE"
  kill $SERVER_PID 2>/dev/null
  exit 1
fi

# Cleanup
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "🎉 All tests passed!"
echo ""
echo "Authentication is properly configured and enforced."
