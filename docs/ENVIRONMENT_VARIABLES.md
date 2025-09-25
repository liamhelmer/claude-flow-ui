# Claude Flow UI Environment Variables

Claude Flow UI now supports environment variables to configure both the UI server settings and command-line options for the `claude-flow` CLI. This allows you to set default configurations without needing to pass command-line arguments every time.

## Supported Environment Variables

### Server Configuration

#### PORT

Sets the port for the UI server.

```bash
# Example: Run on port 3000
export PORT=3000
claude-flow-ui

# Equivalent to: claude-flow-ui --port 3000
```

- Default: 8080
- Range: 1-65535
- Command-line `--port` argument overrides this environment variable

#### TERMINAL_SIZE

Sets the terminal dimensions (columns x rows).

```bash
# Example: Set terminal to 140 columns by 50 rows
export TERMINAL_SIZE=140x50
claude-flow-ui

# Equivalent to: claude-flow-ui --terminal-size 140x50
```

- Default: 120x40
- Format: `{columns}x{rows}`
- Command-line `--terminal-size` argument overrides this environment variable

### Claude Flow Configuration

#### CLAUDE_FLOW_ALPHA

Controls which version of claude-flow to use. When set to `true`, uses the alpha version (`@alpha`) instead of the stable version.

```bash
# Example: Use claude-flow@alpha
export CLAUDE_FLOW_ALPHA=true
claude-flow-ui

# Runs: npx claude-flow@alpha [arguments]
```

- Default: `false` (uses stable `npx claude-flow`)
- Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`
- When `true`: Uses `npx claude-flow@alpha`
- When `false`: Uses `npx claude-flow`

### CLAUDE_FLOW_MODE

Sets the first argument (mode) for the claude-flow CLI.

```bash
# Example: Run in SPARC mode
export CLAUDE_FLOW_MODE=sparc
claude-flow-ui

# Equivalent to: npx claude-flow sparc
```

Available modes include:
- `chat` - Interactive chat mode
- `sparc` - SPARC development methodology
- `dev` - Development mode
- `api` - API development mode
- `ui` - UI development mode
- And many more (see claude-flow documentation)

### CLAUDE_FLOW_SUBCOMMAND

Sets the subcommand that comes after the mode.

```bash
# Example: Use a specific subcommand
export CLAUDE_FLOW_MODE=sparc
export CLAUDE_FLOW_SUBCOMMAND=tdd
export CLAUDE_FLOW_PROMPT="Implement user authentication"
claude-flow-ui

# Equivalent to: npx claude-flow sparc tdd "Implement user authentication"
```

Common subcommands include:
- `tdd` - Test-driven development workflow
- `run` - Run a specific mode
- `batch` - Batch processing
- `pipeline` - Pipeline execution

### CLAUDE_FLOW_PROMPT

Provides the prompt/task description for claude-flow, properly escaped in quotes.

```bash
# Example: Set a development task
export CLAUDE_FLOW_MODE=dev
export CLAUDE_FLOW_PROMPT="Build a REST API with authentication"
claude-flow-ui

# Equivalent to: npx claude-flow dev "Build a REST API with authentication"
```

### CLAUDE_FLOW_ARGUMENTS

Provides additional arguments that come after the prompt.

```bash
# Example: Add custom arguments
export CLAUDE_FLOW_MODE=sparc
export CLAUDE_FLOW_PROMPT="Build microservices"
export CLAUDE_FLOW_ARGUMENTS="--max-agents 10 --timeout 300"
claude-flow-ui

# Equivalent to: npx claude-flow sparc "Build microservices" --max-agents 10 --timeout 300
```

Arguments are split by spaces. For arguments containing spaces, the entire CLAUDE_FLOW_ARGUMENTS should be quoted:
```bash
export CLAUDE_FLOW_ARGUMENTS='--config "custom config.json" --output-dir "./build"'
```

### CLAUDE_FLOW_NEURAL

Enables neural-enhanced mode by appending the `--neural-enhanced` flag.

```bash
# Example: Enable neural enhancements
export CLAUDE_FLOW_MODE=chat
export CLAUDE_FLOW_NEURAL=true
claude-flow-ui

# Equivalent to: npx claude-flow chat --neural-enhanced
```

Accepted values:
- `true` or `1` or `yes` - Enables neural mode
- Any other value - Neural mode disabled

### CLAUDE_SPAWN

Controls agent spawning behavior.

```bash
# Example 1: Enable Claude spawning
export CLAUDE_FLOW_MODE=dev
export CLAUDE_SPAWN=true
claude-flow-ui

# Equivalent to: npx claude-flow dev --claude

# Example 2: Enable auto-spawning
export CLAUDE_FLOW_MODE=sparc
export CLAUDE_SPAWN=auto
claude-flow-ui

# Equivalent to: npx claude-flow sparc --auto-spawn
```

Accepted values:
- `true` - Appends `--claude` flag
- `auto` - Appends `--auto-spawn` flag
- `false` or absent - No spawn flags added

### CLAUDE_FLOW_TIMEOUT

Sets the timeout value in seconds for claude-flow operations.

```bash
# Example: Set 10 minute timeout
export CLAUDE_FLOW_MODE=dev
export CLAUDE_FLOW_TIMEOUT=600
claude-flow-ui

# Equivalent to: npx claude-flow dev --timeout 600
```

- Value must be a positive integer (seconds)
- Default timeout depends on the claude-flow operation

### CLAUDE_FLOW_INIT

Runs initialization commands before starting claude-flow.

```bash
# Example 1: Basic initialization
export CLAUDE_FLOW_INIT=true
export CLAUDE_FLOW_MODE=chat
claude-flow-ui

# Runs: npx claude-flow init
# Then: npx claude-flow chat
```

```bash
# Example 2: Force initialization
export CLAUDE_FLOW_INIT=force
export CLAUDE_FLOW_MODE=dev
claude-flow-ui

# Runs: npx claude-flow init --force
# Then: npx claude-flow dev
```

```bash
# Example 3: Initialize with GitHub integration
export CLAUDE_FLOW_INIT=github
export CLAUDE_FLOW_MODE=chat
claude-flow-ui

# Runs: npx claude-flow init
# Runs: npx claude-flow github init
# Then: npx claude-flow chat
```

Available options:
- `true` - Run basic initialization
- `force` - Force initialization (overwrites existing config)
- `github` - Initialize with GitHub integration

## Hive Mind Configuration

### HIVE_CONSENSUS_TYPE

Sets the consensus algorithm for hive mind coordination.

```bash
# Example: Use majority consensus
export CLAUDE_FLOW_MODE=hive-mind
export HIVE_CONSENSUS_TYPE=majority
claude-flow-ui

# Equivalent to: npx claude-flow hive-mind --consensus majority
```

Available consensus types:
- `majority` - Simple majority voting
- `unanimous` - Requires all agents to agree
- `weighted` - Weighted voting based on agent performance
- `byzantine` - Byzantine fault-tolerant consensus
- `raft` - Raft consensus algorithm

### HIVE_QUEEN_TYPE

Sets the type of queen coordinator for the hive.

```bash
# Example: Use strategic queen
export CLAUDE_FLOW_MODE=hive-mind
export HIVE_QUEEN_TYPE=strategic
claude-flow-ui

# Equivalent to: npx claude-flow hive-mind --queen-type strategic
```

Available queen types:
- `strategic` - Strategic planning and high-level coordination
- `tactical` - Tactical execution and task management
- `adaptive` - Adaptive learning and optimization
- `democratic` - Democratic coordination with distributed decision making

### AUTO_SCALE_AGENTS

Enables automatic scaling of agents based on workload.

```bash
# Example: Enable auto-scaling
export CLAUDE_FLOW_MODE=swarm
export AUTO_SCALE_AGENTS=true
claude-flow-ui

# Equivalent to: npx claude-flow swarm --auto-scale
```

Accepted values:
- `true` or `1` or `yes` - Enables auto-scaling
- Any other value - Auto-scaling disabled

### HIVE_LOG_LEVEL

Sets the logging level for hive operations. When set to `debug`, also enables verbose output.

```bash
# Example: Enable debug logging with verbose output
export CLAUDE_FLOW_MODE=hive-mind
export HIVE_LOG_LEVEL=debug
claude-flow-ui

# Equivalent to: npx claude-flow hive-mind --log-level debug --verbose
```

Available log levels:
- `error` - Error messages only
- `warn` - Warning and error messages
- `info` - Informational, warning, and error messages
- `debug` - All messages including debug (also adds --verbose flag)

### HIVE_MEMORY_SIZE

Sets the memory size allocation for the hive mind system.

```bash
# Example: Set 2GB memory allocation
export CLAUDE_FLOW_MODE=hive-mind
export HIVE_MEMORY_SIZE=2048
claude-flow-ui

# Equivalent to: npx claude-flow hive-mind --memory-size 2048
```

- Value can be in MB (e.g., `1024`) or with units (e.g., `1GB`, `512MB`)
- Determines the memory pool available for hive coordination and agent communication

## Combining Environment Variables

You can combine multiple environment variables for complex configurations:

```bash
# Full example with all variables
export PORT=3000
export TERMINAL_SIZE=140x50
export CLAUDE_FLOW_INIT=github
export CLAUDE_FLOW_MODE=hive-mind
export CLAUDE_FLOW_SUBCOMMAND=coordinate
export CLAUDE_FLOW_PROMPT="Create a microservices architecture"
export CLAUDE_FLOW_ARGUMENTS="--max-agents 8"
export CLAUDE_FLOW_TIMEOUT=1800
export HIVE_CONSENSUS_TYPE=majority
export HIVE_QUEEN_TYPE=strategic
export AUTO_SCALE_AGENTS=true
export HIVE_LOG_LEVEL=debug
export HIVE_MEMORY_SIZE=4096
export CLAUDE_FLOW_NEURAL=true
export CLAUDE_SPAWN=auto

claude-flow-ui

# This will:
# 1. Start UI server on port 3000
# 2. Set terminal to 140x50 dimensions
# 3. Run: npx claude-flow init
# 4. Run: npx claude-flow github init
# 5. Run: npx claude-flow hive-mind coordinate "Create a microservices architecture" --max-agents 8 --timeout 1800 --consensus majority --queen-type strategic --auto-scale --log-level debug --verbose --memory-size 4096 --neural-enhanced --auto-spawn
```

## Command-Line Override

Command-line arguments still take precedence over environment variables when using the `--` separator:

```bash
# Environment variables set
export CLAUDE_FLOW_MODE=chat
export CLAUDE_FLOW_PROMPT="Environment prompt"

# Command-line override
claude-flow-ui -- dev "Command-line prompt"

# Will run: npx claude-flow dev "Command-line prompt"
# (ignores environment variables)
```

## Display on Startup

When environment variables are configured, the full claude-flow command will be displayed in the startup banner:

```
╔════════════════════════════════════════════════════╗
║           UNIFIED TERMINAL SERVER                  ║
╠════════════════════════════════════════════════════╣
║   ...                                              ║
║   Claude Flow Command:                            ║
║   npx claude-flow sparc "Build API" --neural-...  ║
║                                                    ║
║   Init Commands:                                  ║
║   • npx claude-flow init                          ║
║   • npx claude-flow github init                   ║
╚════════════════════════════════════════════════════╝
```

## Docker Support

These environment variables work seamlessly with Docker:

```dockerfile
# Dockerfile example
FROM node:18
ENV PORT=8080
ENV TERMINAL_SIZE=140x50
ENV CLAUDE_FLOW_MODE=dev
ENV CLAUDE_FLOW_NEURAL=true
ENV CLAUDE_FLOW_INIT=true
# ... rest of Dockerfile
```

```yaml
# docker-compose.yml example
version: '3'
services:
  claude-flow-ui:
    image: claude-flow-ui
    environment:
      - PORT=8080
      - TERMINAL_SIZE=160x60
      - CLAUDE_FLOW_MODE=sparc
      - CLAUDE_FLOW_PROMPT=Develop microservices
      - CLAUDE_FLOW_NEURAL=true
      - CLAUDE_FLOW_INIT=github
    ports:
      - "8080:8080"
```

## CI/CD Integration

Perfect for CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run Claude Flow UI
  env:
    CLAUDE_FLOW_MODE: test
    CLAUDE_FLOW_PROMPT: "Run comprehensive tests"
    CLAUDE_FLOW_NEURAL: true
  run: npx claude-flow-ui
```

## Testing

Run the environment variable tests:

```bash
node tests/env-variables.test.js
```

## Troubleshooting

1. **Variables not working?**
   - Ensure variables are exported: `export CLAUDE_FLOW_MODE=chat`
   - Check for typos in variable names
   - Verify values are valid for each variable

2. **Command-line override not working?**
   - Use the `--` separator: `claude-flow-ui -- dev prompt`
   - Everything after `--` is passed to claude-flow

3. **Init commands failing?**
   - Check that claude-flow is installed: `npm list claude-flow`
   - Verify network connectivity for npm commands
   - Init commands continue even if one fails

## Examples

### Development Workflow

```bash
# Set up for development
export CLAUDE_FLOW_INIT=github
export CLAUDE_FLOW_MODE=dev
export CLAUDE_FLOW_NEURAL=true
export CLAUDE_FLOW_PROMPT="Build authentication system"

# Start the UI
claude-flow-ui
```

### SPARC Methodology

```bash
# SPARC mode with neural enhancements
export CLAUDE_FLOW_MODE=sparc
export CLAUDE_FLOW_PROMPT="Design e-commerce platform"
export CLAUDE_FLOW_NEURAL=true

claude-flow-ui
```

### Testing Environment

```bash
# Set up for testing
export CLAUDE_FLOW_MODE=test
export CLAUDE_FLOW_PROMPT="Run unit tests"

claude-flow-ui
```

### Production Deployment

```bash
# Production configuration
export CLAUDE_FLOW_INIT=force
export CLAUDE_FLOW_MODE=deploy
export CLAUDE_FLOW_PROMPT="Deploy to production"

claude-flow-ui
```