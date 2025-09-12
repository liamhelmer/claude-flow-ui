# Config Prefetch Solution Design

## Problem Statement
The terminal initialization currently has a race condition where the terminal may attempt to initialize before receiving configuration from the backend, causing initialization failures or incorrect terminal dimensions.

## Root Causes
1. Terminal config is sent asynchronously after WebSocket connection
2. Terminal initialization hook runs immediately when component mounts
3. No guaranteed ordering between config reception and terminal initialization
4. The current "pending config" mechanism is reactive, not proactive

## Solution Design

### Architecture Overview
```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   WebSocket     │────►│  Config Manager  │────►│    Terminal     │
│    Client       │     │  (New Component) │     │   Component     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                        │                         │
        │  1. Connect           │                         │
        │  2. Request Config    │                         │
        └──────────────────────►│                         │
                                │  3. Store Config        │
                                │                         │
                                │  4. Config Ready ──────►│
                                │                         │
                                │                    5. Initialize
```

### Implementation Approach

#### 1. Config Prefetch Function
Create a dedicated config prefetch mechanism that:
- Requests terminal configuration immediately upon WebSocket connection
- Returns a Promise that resolves when config is received
- Handles timeouts and retries gracefully

```typescript
// src/lib/terminal/config-prefetcher.ts
interface TerminalConfigPrefetcher {
  prefetchConfig(sessionId: string): Promise<TerminalConfig>;
  getConfig(sessionId: string): TerminalConfig | null;
  clearConfig(sessionId: string): void;
}
```

#### 2. Promise-Based Initialization Sequence
Modify the terminal initialization to wait for config:

```typescript
// Modified useTerminal hook
const initializeWithConfig = async () => {
  try {
    // Wait for config before initializing
    const config = await configPrefetcher.prefetchConfig(sessionId);
    setBackendTerminalConfig(config);
    
    // Now safe to initialize terminal
    initTerminal();
  } catch (error) {
    console.error('Failed to prefetch config:', error);
    // Handle gracefully with fallback
  }
};
```

#### 3. Error Handling Strategy
- **Timeout**: 5-second timeout for config fetch
- **Retry**: Up to 3 retries with exponential backoff
- **Fallback**: Use reasonable default dimensions if all else fails
- **User Feedback**: Show loading state during config fetch

#### 4. Backward Compatibility
- Keep existing config event handlers as backup
- Support both push (event) and pull (request) config models
- Gracefully handle servers that don't support config requests

### Key Components

#### ConfigPrefetcher Service
```typescript
class ConfigPrefetcher {
  private configCache = new Map<string, TerminalConfig>();
  private pendingRequests = new Map<string, Promise<TerminalConfig>>();
  
  async prefetchConfig(sessionId: string): Promise<TerminalConfig> {
    // Check cache first
    if (this.configCache.has(sessionId)) {
      return this.configCache.get(sessionId)!;
    }
    
    // Check if already fetching
    if (this.pendingRequests.has(sessionId)) {
      return this.pendingRequests.get(sessionId)!;
    }
    
    // Create new request
    const request = this.createConfigRequest(sessionId);
    this.pendingRequests.set(sessionId, request);
    
    try {
      const config = await request;
      this.configCache.set(sessionId, config);
      return config;
    } finally {
      this.pendingRequests.delete(sessionId);
    }
  }
}
```

#### Modified WebSocket Protocol
Add explicit config request/response:
```typescript
// Client sends
{ type: 'request-config', sessionId: 'xxx' }

// Server responds
{ type: 'config-response', sessionId: 'xxx', cols: 120, rows: 40 }
```

### Benefits
1. **Deterministic Initialization**: Terminal only initializes after config is available
2. **Better Error Handling**: Clear timeout and retry logic
3. **Improved Performance**: Config cached for subsequent uses
4. **Backward Compatible**: Works with existing event-based system
5. **User Experience**: Loading state instead of broken terminal

### Migration Path
1. Implement ConfigPrefetcher service
2. Add request-config handler to WebSocket server
3. Modify useTerminal to use prefetch
4. Add loading state to Terminal component
5. Test with both new and old server versions
6. Remove legacy pending config mechanism

### Testing Strategy
- Unit tests for ConfigPrefetcher
- Integration tests for config fetch flow
- E2E tests for terminal initialization
- Stress tests for concurrent config requests
- Compatibility tests with old server versions