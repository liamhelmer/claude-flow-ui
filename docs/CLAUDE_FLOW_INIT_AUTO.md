# CLAUDE_FLOW_INIT=auto Feature

The `CLAUDE_FLOW_INIT=auto` environment variable provides automatic initialization of claude-flow in projects that don't already have it set up.

## How It Works

When `CLAUDE_FLOW_INIT=auto` is set, the system will:

1. **Auto-detect** if claude-flow is already initialized by checking for:
   - `.claude-flow/` directory
   - `.claude/` directory
   - `CLAUDE.md` file

2. **Automatically run `claude-flow init`** if none of these files/directories exist

3. **Skip initialization** if any of the expected files/directories are found

## Usage

### Basic Usage

```bash
export CLAUDE_FLOW_INIT=auto
npm start
```

### With Other Environment Variables

```bash
export CLAUDE_FLOW_INIT=auto
export CLAUDE_FLOW_ALPHA=true
npm start
```

This will use `npx claude-flow@alpha init` if initialization is needed.

### One-time Usage

```bash
CLAUDE_FLOW_INIT=auto npm start
```

## Detection Logic

The auto-detection checks for these files/directories in the current working directory:

| File/Directory | Description |
|----------------|-------------|
| `.claude-flow/` | Primary claude-flow configuration directory |
| `.claude/` | Alternative claude configuration directory |
| `CLAUDE.md` | Claude configuration file |

If **any** of these exist, initialization is skipped.
If **none** exist, `claude-flow init` is automatically executed.

## Available CLAUDE_FLOW_INIT Options

| Value | Behavior |
|-------|----------|
| `auto` | **NEW** - Auto-detect and initialize if needed |
| `true` | Always run `claude-flow init` |
| `force` | Always run `claude-flow init --force` |
| `github` | Run `claude-flow init` and `claude-flow github init` |
| (unset) | No initialization |

## Examples

### New Project Setup

```bash
# In a fresh project directory
export CLAUDE_FLOW_INIT=auto
npm start
```

Output:
```
[AutoInit] 🔍 Claude-flow initialization files not found in /path/to/project
[AutoInit] 📋 Checking for: .claude-flow/, .claude/, CLAUDE.md
[AutoInit] 🚀 Running claude-flow init in /path/to/project...
[AutoInit] ✅ claude-flow init completed successfully
[AutoInit] 🎉 Auto-initialization completed successfully
```

### Existing Project

```bash
# In a project that already has .claude-flow/
export CLAUDE_FLOW_INIT=auto
npm start
```

Output:
```
[AutoInit] ✅ Claude-flow already initialized (found existing files)
```

## Implementation Details

The auto-initialization feature:

- **Runs asynchronously** during server startup
- **Has a 30-second timeout** to prevent hanging
- **Handles errors gracefully** without crashing the server
- **Uses the correct claude-flow version** (respects `CLAUDE_FLOW_ALPHA`)
- **Provides detailed logging** for troubleshooting

## Error Handling

If auto-initialization fails:
- The error is logged but **doesn't stop the server**
- A warning message is displayed
- The server continues to start normally

Example:
```
[AutoInit] ❌ claude-flow init failed with exit code 1
[AutoInit] ⚠️ Auto-initialization failed or was skipped
```

## Troubleshooting

### Auto-init not triggering

Check that your directory is truly empty of claude-flow files:
```bash
ls -la | grep -E '(\.claude|CLAUDE\.md)'
```

### Init command failing

Run manually to see detailed error:
```bash
npx claude-flow init
```

### Check what version is being used

The server logs will show:
```
✅ Using claude-flow stable version
# or
🔬 Using claude-flow@alpha (CLAUDE_FLOW_ALPHA=true)
```

## Testing

Run the test suite to verify auto-init functionality:

```bash
node tests/auto-init-test.js
```

This tests:
- Auto-detection logic
- File/directory checking
- Integration with environment variables