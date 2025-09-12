# WebSocket Mocking Solution

## Problem Summary
The WebSocket client tests were failing due to improper Socket.IO mocking in Jest environment, specifically:
- `Cannot read properties of undefined (reading 'on')` errors
- Mock socket not being returned properly from `io()` function
- Inconsistent mock setup between different test files

## Root Cause
1. **Mock Conflict**: The test file was declaring its own `jest.mock('socket.io-client')` which conflicted with the global mock in `jest.setup.js`
2. **Incomplete Mock Object**: The mock socket wasn't implementing all required Socket.IO client methods
3. **State Management**: Mock socket state wasn't being properly reset between tests

## Solution

### 1. Fixed Global Mock in jest.setup.js
```javascript
// Mock Socket.IO client with proper implementation
jest.mock('socket.io-client', () => {
  // Create a fresh mock socket for each test
  const createMockSocket = () => ({
    id: 'mock-socket-id',
    connected: false,
    disconnected: true,
    on: jest.fn(),
    off: jest.fn(),
    emit: jest.fn(),
    disconnect: jest.fn(),
    connect: jest.fn(),
    // Add other Socket.IO methods as needed
    removeAllListeners: jest.fn(),
    listeners: jest.fn(() => []),
    listenerCount: jest.fn(() => 0),
  });
  
  const mockIo = jest.fn(() => createMockSocket());
  
  return {
    io: mockIo,
    Socket: createMockSocket,
  };
});
```

### 2. Updated Test File Pattern
```typescript
// Remove conflicting mock declaration
// OLD: jest.mock('socket.io-client');

// Use the global mock from jest.setup.js
const mockIo = io as jest.MockedFunction<typeof io>;
let mockSocket: any;

// Helper to create a fresh mock socket
const createMockSocket = () => ({
  connected: false,
  disconnected: true,
  id: 'mock-socket-id',
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  removeAllListeners: jest.fn(),
  listeners: jest.fn(() => []),
  listenerCount: jest.fn(() => 0),
});

// In beforeEach:
beforeEach(() => {
  jest.clearAllMocks();
  
  // Create a fresh mock socket for each test
  mockSocket = createMockSocket();
  mockIo.mockReturnValue(mockSocket);
  
  client = new WebSocketClient('ws://test:8080');
});
```

### 3. Updated Event List
Added new events that were added to the WebSocket client:
- `terminal-config`
- `terminal-error` 
- `connection-change`

### 4. Fixed Test Patterns
- Removed duplicate mock declarations
- Ensured consistent mock socket creation
- Fixed connection state management in tests
- Updated test assertions to work with new events

## Key Files Modified
1. `/jest.setup.js` - Fixed global Socket.IO mock
2. `/src/lib/websocket/__tests__/client.test.ts` - Updated test patterns
3. Updated event handling tests for new WebSocket events

## Testing Pattern
```typescript
// Pattern for testing WebSocket connection
it('should connect successfully', async () => {
  const connectPromise = client.connect();

  // Simulate successful connection
  const connectHandler = mockSocket.on.mock.calls.find(
    ([event]) => event === 'connect'
  )?.[1];
  mockSocket.connected = true;
  connectHandler?.();

  await connectPromise;

  expect(mockIo).toHaveBeenCalledWith('ws://test:8080', {
    transports: ['websocket', 'polling'],
    autoConnect: true,
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 1000,
  });
  expect(client.connected).toBe(true);
});
```

## Result
- Fixed `Cannot read properties of undefined (reading 'on')` error
- Proper Socket.IO client mocking in Jest/jsdom environment  
- All WebSocket client tests now pass
- Consistent mock behavior across all test scenarios
- Solution stored in collective memory for hive coordination