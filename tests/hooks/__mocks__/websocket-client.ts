// Mock implementation for WebSocket client
export class MockWebSocketClient {
  public connected = false;
  public connecting = false;
  private listeners = new Map<string, Function[]>();
  private mockSocket: any = null;

  async connect(): Promise<void> {
    this.connecting = true;
    // Simulate connection delay
    await new Promise(resolve => setTimeout(resolve, 10));
    this.connected = true;
    this.connecting = false;
    this.emit('connect');
  }

  disconnect(): void {
    this.connected = false;
    this.connecting = false;
    this.listeners.clear();
    this.emit('disconnect');
  }

  send(event: string, data: any): void {
    if (!this.connected) {
      throw new Error('WebSocket not connected');
    }
    // Mock sending data
  }

  sendMessage(message: any): void {
    this.send('message', message);
  }

  on(event: string, callback: Function): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  off(event: string, callback: Function): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      const index = eventListeners.indexOf(callback);
      if (index > -1) {
        eventListeners.splice(index, 1);
      }
    }
  }

  private emit(event: string, data?: any): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.forEach(callback => callback(data));
    }
  }

  // Mock method to simulate receiving messages
  simulateMessage(event: string, data: any): void {
    this.emit(event, data);
  }

  // Mock method to simulate connection errors
  simulateError(error: Error): void {
    this.connected = false;
    this.connecting = false;
    this.emit('error', error);
  }
}

export const wsClient = new MockWebSocketClient();