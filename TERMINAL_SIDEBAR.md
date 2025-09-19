# Terminal Sidebar - Multi-Terminal Support

The claude-flow-ui now supports multiple terminal sessions through a terminal sidebar. This feature allows you to spawn multiple bash shells alongside the main Claude Flow terminal.

## Features

✅ **Multiple Terminals** - Run multiple terminal sessions simultaneously
✅ **Terminal List** - See all active terminals in the sidebar
✅ **Easy Switching** - Click any terminal to switch to it
✅ **Spawn Terminals** - Create new bash shells with one click
✅ **Close Terminals** - Close any terminal except the main Claude Flow session
✅ **Same Configuration** - All terminals use the same size and tmux configuration

## How It Works

### Starting the Server

```bash
npm run claude-flow-ui
# or
PORT=8080 npm run claude-flow-ui
```

### Using the Terminal Sidebar

1. **View the Sidebar** - The left sidebar shows "Terminals" with a list of all active sessions
2. **Create New Terminal** - Click the green "New Terminal" button
3. **Switch Terminals** - Click on any terminal in the list to switch to it
4. **Close Terminals** - Click the X button next to any terminal (except main)
5. **Toggle Sidebar** - Click the chevron icon to hide/show the sidebar

### API Endpoints

The following API endpoints are available in `unified-server.js`:

- `GET /api/terminals` - List all active terminals
- `POST /api/terminals/spawn` - Create a new terminal
  ```json
  {
    "name": "My Terminal",
    "command": "/bin/bash --login"
  }
  ```
- `DELETE /api/terminals/:id` - Close a terminal

### Testing the Functionality

#### Quick Test
```bash
# Start the server
npm run claude-flow-ui

# In another terminal, test the API
curl http://localhost:5173/api/terminals

# Spawn a new terminal
curl -X POST http://localhost:5173/api/terminals/spawn \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Terminal"}'
```

#### Interactive Demo
```bash
# Start the server
npm run claude-flow-ui

# In another terminal, run the demo
node demo-terminals.js
```

This will give you an interactive menu to:
- List all terminals
- Spawn new terminals
- Close terminals
- Create multiple demo terminals

### Technical Details

- All terminals use `tmux-stream-manager.js` for consistent management
- Terminal size: 120 columns × 40 rows
- New terminals start with `/bin/bash --login`
- The main Claude Flow terminal is protected and cannot be closed
- WebSocket connections automatically route to the selected terminal
- Terminal list refreshes every 2 seconds

### Troubleshooting

**Sidebar not showing?**
- Clear browser cache (Cmd+Shift+R on Mac, Ctrl+Shift+F5 on PC)
- Check browser console for errors
- Verify the server is running

**New terminals not working?**
- Ensure tmux is installed: `which tmux`
- Check server logs for errors
- Verify API is responding: `curl http://localhost:5173/api/terminals`

**Can't close terminals?**
- The main Claude Flow terminal cannot be closed (by design)
- Only additional bash terminals can be closed

### Architecture

```
unified-server.js
├── Terminal Management (Map)
│   ├── Main Terminal (Claude Flow)
│   └── Additional Terminals (Bash)
├── API Endpoints
│   ├── GET /api/terminals
│   ├── POST /api/terminals/spawn
│   └── DELETE /api/terminals/:id
└── WebSocket Handler
    └── Routes data to active terminal

TerminalSidebar.tsx (UI)
├── Terminal List
├── New Terminal Button
├── Terminal Selection
└── Close Terminal Buttons
```

## Example Use Cases

1. **Development Setup** - Main terminal for Claude Flow, additional terminals for git, builds, tests
2. **Multi-Task Workflow** - Separate terminals for different projects or tasks
3. **Monitoring** - Keep logs in one terminal while working in another
4. **Testing** - Run tests in separate terminal while developing

## Notes

- The terminal sidebar is fully integrated into the production build
- Works with both `npm run dev` and `npm run claude-flow-ui`
- All terminals share the same tmux socket directory for consistency
- Terminal sessions persist until explicitly closed or server shutdown