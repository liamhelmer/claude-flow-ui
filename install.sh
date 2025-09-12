#!/bin/bash

# Claude Flow UI Installation Script

echo "🐝 Claude Flow UI Installer"
echo "═══════════════════════════════════════════"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18 or higher."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18 or higher is required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "✅ Dependencies installed successfully"
echo ""

# Build the project
echo "🔨 Building the project..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo ""
echo "✅ Build completed successfully"
echo ""

# Make server.js executable
chmod +x server.js

# Create a global link (optional)
echo "🔗 Creating global command link..."
npm link

echo ""
echo "═══════════════════════════════════════════"
echo "✅ Claude Flow UI installed successfully!"
echo "═══════════════════════════════════════════"
echo ""
echo "Default Ports:"
echo "  UI:        http://localhost:11235"
echo "  WebSocket: ws://localhost:11236"
echo ""
echo "Usage:"
echo "  npm run claude-flow-ui                    # Start with default ports"
echo "  npm run claude-flow-ui -- --port 8080     # UI on 8080, WebSocket on 8081"
echo "  npx claude-flow-ui --port 3000            # UI on 3000, WebSocket on 3001"
echo ""
echo "With claude-flow:"
echo "  npm run claude-flow-ui -- swarm --objective \"Your task\""
echo "  npm run claude-flow-ui -- --port 8080 hive-mind --queen strategic"
echo ""
echo "The WebSocket port is automatically set to UI port + 1"
echo ""