#!/bin/bash

# Create a test tmux session and check what's actually happening

echo "Creating test tmux session..."

# Create session with claude-flow command
tmux new-session -d -s test-manual "npx claude-flow@alpha --help"

echo "Waiting for command to complete..."
sleep 10

echo "Capturing pane content..."
tmux capture-pane -t test-manual -p

echo ""
echo "Checking pane status..."
tmux list-panes -t test-manual -F "Pane dead: #{pane_dead}, Exit code: #{pane_dead_status}"

echo ""
echo "Checking what's in the pane with -S and -E flags..."
tmux capture-pane -t test-manual -S - -E - -p

echo ""
echo "Killing session..."
tmux kill-session -t test-manual

echo "Done!"