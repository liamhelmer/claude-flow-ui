#!/bin/bash

# Test the unified server with claude-flow command

echo "Testing unified-server with claude-flow --version"
echo "================================================"

# Start the server with claude-flow --version argument
echo "Starting server with: node unified-server.js -- --version"

# Run in background and capture output
timeout 10 node unified-server.js -- --version 2>&1 | tee test-output.log &

# Wait a moment for server to start
sleep 2

# Connect with curl to trigger session creation
echo "Attempting to connect to WebSocket endpoint..."
curl -s http://localhost:5173/health || echo "Server not responding"

# Wait for command to complete
sleep 5

# Check what happened
echo ""
echo "Server output:"
echo "--------------"
cat test-output.log | grep -E "\[SERVER\]|exit|Exit|tmux|socket"

# Kill any remaining processes
pkill -f "node unified-server.js" 2>/dev/null

echo ""
echo "Test complete"