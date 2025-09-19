const { io } = require('socket.io-client');

// Connect to the server
const socket = io('http://localhost:11239');

socket.on('connect', () => {
  console.log('[Client] Connected to server with ID:', socket.id);
});

socket.on('session-created', (data) => {
  console.log('[Client] Session created:', data);
});

socket.on('terminal-data', (data) => {
  console.log('[Client] Terminal data received for session:', data.sessionId);
  console.log('[Client] Data preview:', data.data.substring(0, 50));
});

socket.on('terminal-config', (data) => {
  console.log('[Client] Terminal config:', data);
});

socket.on('disconnect', () => {
  console.log('[Client] Disconnected from server');
});

socket.on('error', (error) => {
  console.error('[Client] Socket error:', error);
});

// Keep the connection open
setTimeout(() => {
  console.log('[Client] Closing connection...');
  socket.disconnect();
  process.exit(0);
}, 10000);