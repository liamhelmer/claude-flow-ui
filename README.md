# Claude Flow UI - Frontend for Claude Flow

A modern web-based terminal and monitoring interface for Claude Flow with real-time system monitoring.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start UI with WebSocket server on default ports (11235/11236)
npm run claude-flow-ui

# The server automatically:
# 1. Starts the UI on port 11235
# 2. Starts WebSocket server on port 11236
# 3. Optionally launches claude-flow with your arguments

# Start UI on specific port
npm run claude-flow-ui -- --port 8080

# Start UI with claude-flow (pass arguments after port)
npm run claude-flow-ui -- --port 8080 swarm --objective "your task here"

# Or use directly with npx after install
npx claude-flow-ui --port 3000 hive-mind --name "my-hive"
```

## 📋 Features

### Terminal Console
- **Full Keyboard Support**: Arrow keys, history, Ctrl+C, Ctrl+L, etc.
- **Command History**: Navigate with up/down arrows
- **Multi-Session**: Multiple terminal tabs
- **Real-time I/O**: Live streaming of input/output

### Monitoring Dashboard
- **💾 Memory Panel**: Real-time memory usage, efficiency metrics, visual history
- **🤖 Agents Panel**: Live agent status, health indicators, task monitoring
- **📝 Prompt Panel**: Current/historical prompts, context information
- **⚡ Commands Panel**: Active command tracking, execution status, output logs

## 🎯 Usage

### CLI Options

```bash
claude-flow-ui [--port <number>] [claude-flow-args...]
```

- `--port <number>`: Specify port (default: 11235)
- `claude-flow-args`: Any arguments to pass to claude-flow

### Environment Variables (NEW!)

Configure both server and claude-flow options using environment variables:

```bash
# Server configuration
export PORT=3000
export TERMINAL_SIZE=140x50

# Claude Flow configuration
export CLAUDE_FLOW_ALPHA=true        # Use alpha version
export CLAUDE_FLOW_MODE=sparc
export CLAUDE_FLOW_PROMPT="Build a REST API"
export CLAUDE_FLOW_NEURAL=true
export CLAUDE_FLOW_INIT=github

# Run UI - automatically uses env vars
npm run claude-flow-ui
```

Available environment variables:

**Server Configuration:**
- `PORT`: UI server port (default: 8080)
- `TERMINAL_SIZE`: Terminal dimensions as `{cols}x{rows}` (default: 120x40)

**Claude Flow Configuration:**
- `CLAUDE_FLOW_ALPHA`: Use alpha version (`true`/`false`, default: `false`)
- `CLAUDE_FLOW_MODE`: First argument/mode for claude-flow
- `CLAUDE_FLOW_SUBCOMMAND`: Subcommand after mode (e.g., `tdd`, `run`, `batch`)
- `CLAUDE_FLOW_PROMPT`: Task description (automatically quoted)
- `CLAUDE_FLOW_ARGUMENTS`: Additional arguments after prompt
- `CLAUDE_FLOW_TIMEOUT`: Timeout in seconds for operations
- `CLAUDE_FLOW_NEURAL`: Set to `true` to enable neural mode
- `CLAUDE_SPAWN`: Agent spawning (`true` for --claude, `auto` for --auto-spawn)
- `CLAUDE_FLOW_INIT`: Run init commands (`true`, `force`, `github`, or `auto` - NEW!)

**Hive Mind Configuration:**
- `HIVE_CONSENSUS_TYPE`: Consensus algorithm (`majority`, `unanimous`, `byzantine`, etc.)
- `HIVE_QUEEN_TYPE`: Queen coordinator type (`strategic`, `tactical`, `adaptive`, `democratic`)
- `AUTO_SCALE_AGENTS`: Enable auto-scaling (`true` to enable)
- `HIVE_LOG_LEVEL`: Log level (`error`, `warn`, `info`, `debug` - debug also adds --verbose)
- `HIVE_MEMORY_SIZE`: Memory allocation for hive system

See [docs/ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md) for full documentation.

### Examples

```bash
# Run UI only (no claude-flow)
npm run claude-flow-ui

# Run UI with claude-flow in swarm mode
npm run claude-flow-ui -- swarm --objective "Build a React app"

# Run UI on port 8080 with hive-mind mode
npm run claude-flow-ui -- --port 8080 hive-mind --queen strategic

# Run with all claude-flow options
npm run claude-flow-ui -- --port 3000 swarm \
  --objective "Create API" \
  --model claude-3-opus \
  --max-agents 10

# NEW: Auto-initialize claude-flow in new projects
CLAUDE_FLOW_INIT=auto npm run claude-flow-ui

# Auto-init with alpha version
CLAUDE_FLOW_INIT=auto CLAUDE_FLOW_ALPHA=true npm run claude-flow-ui
```

### Port Selection Logic

1. Default UI port is **11235**
2. Default WebSocket port is **11236** (UI port + 1)
3. If `--port` is specified, that port is used for UI
4. WebSocket automatically uses UI port + 1
5. If the requested port is occupied, automatically finds next available port
6. Both servers start automatically - no separate setup needed
7. Displays both UI and WebSocket ports on startup

### 🌐 What Starts Automatically

When you run `npm run claude-flow-ui`:

1. **UI Server**: Next.js application on port 11235
2. **WebSocket Server**: Real-time communication on port 11236
3. **Claude Flow** (optional): If you provide arguments

The WebSocket server provides:
- Terminal session management
- Real-time system metrics
- Agent status updates
- Command execution monitoring

## 🏗️ Architecture

### Tech Stack

- **Framework**: Next.js 15 with App Router
- **UI Library**: React 18
- **Styling**: Tailwind CSS 3.4
- **Terminal**: xterm.js 5.5
- **WebSocket**: Socket.IO Client 4.8
- **State Management**: Zustand 5.0
- **Language**: TypeScript 5.6

### Project Structure

```
src/
├── app/                    # Next.js app directory
├── components/             # React components
│   ├── terminal/          # Interactive terminal
│   ├── monitoring/        # Monitoring panels
│   │   ├── MemoryPanel.tsx
│   │   ├── AgentsPanel.tsx
│   │   ├── PromptPanel.tsx
│   │   └── CommandsPanel.tsx
│   ├── sidebar/           # Session sidebar
│   └── tabs/              # Tab components
├── hooks/                 # Custom React hooks
│   ├── useTerminal.ts     # Terminal logic
│   └── useWebSocket.ts    # WebSocket connection
├── lib/                   # Utility libraries
│   ├── state/            # Zustand store
│   └── websocket/        # WebSocket client
└── types/                # TypeScript definitions
```

## 🛠️ Development

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/claude-flow-ui.git
cd claude-flow-ui

# Install dependencies
npm install
```

### Development Mode

```bash
# Start development server
npm run dev

# Run with custom port
PORT=8080 npm run dev
```

### Production Build

```bash
# Build for production
npm run build

# Start production server
npm start

# Or use the custom server
node server.js --port 8080
```

## 📡 WebSocket Configuration

The UI connects to claude-flow's WebSocket server for real-time communication.

Default connection: `ws://localhost:11236` (UI port + 1)

The WebSocket port is automatically set to UI port + 1:
- UI on port 11235 → WebSocket on port 11236
- UI on port 8080 → WebSocket on port 8081

To override, set environment variables:

```bash
# .env.local
NEXT_PUBLIC_WS_PORT=11236
NEXT_PUBLIC_WS_URL=ws://localhost:11236
```

## 🔧 Configuration

### Environment Variables

```bash
# .env.local
NEXT_PUBLIC_WS_PORT=11236        # WebSocket port (default: UI port + 1)
NEXT_PUBLIC_WS_URL=ws://localhost:11236  # Full WebSocket URL
NEXT_PUBLIC_API_URL=http://localhost:11235  # API URL
```

### Terminal Customization

Edit `src/hooks/useTerminal.ts` to customize:
- Terminal colors and theme
- Font size and family
- Cursor style
- Scrollback buffer size

## 📦 Scripts

- `npm run dev` - Development server
- `npm run build` - Production build
- `npm start` - Production server (Next.js)
- `npm run serve` - Custom server with port selection
- `npm run claude-flow-ui` - Start UI with CLI options
- `npm run lint` - Run ESLint
- `npm run type-check` - TypeScript checking

## 🐛 Troubleshooting

### Port Already in Use

The server automatically finds the next available port if the requested port is occupied.

### WebSocket Connection Failed

The WebSocket server starts automatically with the UI. If you see connection errors:

1. Check that both servers started successfully (look for the startup messages)
2. Verify the WebSocket port in the console output
3. Ensure no firewall is blocking the WebSocket port
4. Try restarting with `npm run claude-flow-ui`

### Testing WebSocket Connection

```bash
# Test the WebSocket connection
node test-connection.js
```

This will verify that the WebSocket server is running and responding.

### Terminal Not Responding

1. Refresh the browser
2. Check browser console for errors
3. Ensure WebSocket connection is established

## 📄 License

MIT

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐝 Hive Mind

Built with collective intelligence by the Claude Flow Hive Mind system.