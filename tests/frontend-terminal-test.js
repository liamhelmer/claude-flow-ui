#!/usr/bin/env node

/**
 * End-to-end test to verify ANSI escape codes and color information
 * pass through the entire stack: tmux → WebSocket server → frontend
 */

const WebSocket = require('ws');
const TmuxManager = require('../src/lib/tmux-manager');

class FrontendTerminalTest {
  constructor() {
    this.tmuxManager = new TmuxManager();
    this.ws = null;
    this.sessionInfo = null;
    this.receivedMessages = [];
  }

  async runTest() {
    try {
      console.log('🧪 Testing full stack terminal data flow with ANSI preservation...\n');
      
      // 1. Start WebSocket server connection
      await this.connectToWebSocket();
      
      // 2. Create terminal session through WebSocket
      await this.createTerminalSession();
      
      // 3. Send ANSI test commands
      await this.sendAnsiTestCommands();
      
      // 4. Wait for responses and analyze
      await this.analyzeResponses();
      
      // 5. Cleanup
      await this.cleanup();
      
      console.log('✅ Frontend terminal test completed successfully');
      
    } catch (error) {
      console.error('❌ Frontend terminal test failed:', error.message);
      await this.cleanup();
      process.exit(1);
    }
  }

  async connectToWebSocket() {
    console.log('🔌 Connecting to WebSocket server...');
    
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket('ws://localhost:11236');
      
      this.ws.on('open', () => {
        console.log('✅ Connected to WebSocket server');
        resolve();
      });
      
      this.ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          this.receivedMessages.push(message);
          console.log(`📥 Received: ${message.type}`, message.data ? `(${JSON.stringify(message.data).substring(0, 100)}...)` : '');
        } catch (error) {
          console.log(`📥 Received raw: ${data.toString().substring(0, 100)}...`);
        }
      });
      
      this.ws.on('error', (error) => {
        console.error('❌ WebSocket error:', error.message);
        reject(error);
      });
      
      this.ws.on('close', () => {
        console.log('🔌 WebSocket connection closed');
      });
      
      // Timeout after 5 seconds
      setTimeout(() => {
        if (this.ws.readyState !== WebSocket.OPEN) {
          reject(new Error('WebSocket connection timeout'));
        }
      }, 5000);
    });
  }

  async createTerminalSession() {
    console.log('📝 Creating terminal session through WebSocket...');
    
    return new Promise((resolve, reject) => {
      // Listen for session creation response
      const messageHandler = (message) => {
        if (message.type === 'session_created') {
          console.log(`✅ Session created: ${message.data.sessionId}`);
          this.sessionId = message.data.sessionId;
          resolve();
        } else if (message.type === 'error') {
          reject(new Error(`Session creation failed: ${message.data.error}`));
        }
      };

      // Add temporary message handler
      const originalMessages = [...this.receivedMessages];
      const checkForResponse = () => {
        const newMessages = this.receivedMessages.slice(originalMessages.length);
        for (const message of newMessages) {
          messageHandler(message);
        }
        if (!this.sessionId) {
          setTimeout(checkForResponse, 100);
        }
      };

      // Send create session request
      this.ws.send(JSON.stringify({
        type: 'create',
        data: {
          command: 'bash',
          args: [],
          cols: 80,
          rows: 24
        }
      }));

      setTimeout(checkForResponse, 100);
      
      // Timeout after 10 seconds
      setTimeout(() => {
        if (!this.sessionId) {
          reject(new Error('Session creation timeout'));
        }
      }, 10000);
    });
  }

  async sendAnsiTestCommands() {
    console.log('🎨 Sending ANSI test commands...');
    
    const testCommands = [
      'echo "=== ANSI Color Test ==="',
      'echo -e "\\e[31mRED TEXT\\e[0m"',
      'echo -e "\\e[32mGREEN TEXT\\e[0m"', 
      'echo -e "\\e[34mBLUE TEXT\\e[0m"',
      'echo -e "\\e[1mBOLD TEXT\\e[0m"',
      'echo -e "\\e[4mUNDERLINE\\e[0m"',
      'echo -e "\\e[7mREVERSE\\e[0m"',
      'echo -e "\\e[33;1mYELLOW BOLD\\e[0m"',
      'echo "=== Terminal Info ==="',
      'echo "TERM=$TERM"',
      'echo "COLORTERM=$COLORTERM"',
      'tput colors'
    ];

    for (const command of testCommands) {
      console.log(`📤 Sending: ${command}`);
      
      this.ws.send(JSON.stringify({
        type: 'data',
        data: {
          sessionId: this.sessionId,
          data: command + '\r'
        }
      }));
      
      // Wait between commands
      await new Promise(resolve => setTimeout(resolve, 300));
    }
    
    // Wait for all output to settle
    console.log('⏳ Waiting for output to settle...');
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  async analyzeResponses() {
    console.log('\n📊 Analyzing received messages...');
    console.log('='.repeat(60));
    
    // Filter output messages
    const outputMessages = this.receivedMessages.filter(msg => msg.type === 'output');
    console.log(`📈 Total output messages received: ${outputMessages.length}`);
    
    if (outputMessages.length === 0) {
      throw new Error('No output messages received from WebSocket');
    }
    
    // Combine all output
    const allOutput = outputMessages.map(msg => msg.data.output || msg.data.data || '').join('');
    console.log(`📏 Total output length: ${allOutput.length} characters`);
    
    // Analyze ANSI escape codes
    const ansiEscapeRegex = /\x1b\[[0-9;]*[a-zA-Z]/g;
    const ansiCodes = allOutput.match(ansiEscapeRegex) || [];
    
    console.log(`🎨 ANSI escape codes found: ${ansiCodes.length}`);
    
    if (ansiCodes.length > 0) {
      console.log('✅ ANSI escape codes are being preserved through the full stack!');
      
      // Show sample of preserved codes
      console.log('\n🔍 Sample preserved ANSI codes:');
      ansiCodes.slice(0, 10).forEach((code, index) => {
        console.log(`   ${index + 1}. ${JSON.stringify(code)}`);
      });
      
      // Analyze color codes specifically
      const colorCodes = ansiCodes.filter(code => /\x1b\[3[0-7]m|\x1b\[9[0-7]m/.test(code));
      console.log(`🌈 Color codes found: ${colorCodes.length}`);
      
      // Analyze formatting codes
      const formatCodes = ansiCodes.filter(code => /\x1b\[[0147]m/.test(code));
      console.log(`📝 Formatting codes found: ${formatCodes.length}`);
      
    } else {
      console.log('⚠️  No ANSI escape codes found in output');
      console.log('   This could indicate that escape codes are being stripped somewhere in the pipeline');
    }
    
    // Check terminal configuration info
    const termMatch = allOutput.match(/TERM=([^\s\n\r]+)/);
    const colorTermMatch = allOutput.match(/COLORTERM=([^\s\n\r]+)/);
    const colorsMatch = allOutput.match(/(\d+)\s*(?:\n|$)/);
    
    console.log('\n🖥️  Terminal Configuration in Output:');
    console.log(`   TERM: ${termMatch ? termMatch[1] : 'not found'}`);
    console.log(`   COLORTERM: ${colorTermMatch ? colorTermMatch[1] : 'not found'}`);
    console.log(`   Colors: ${colorsMatch ? colorsMatch[1] : 'not found'}`);
    
    // Verify expected values
    if (termMatch && termMatch[1] === 'xterm-256color') {
      console.log('✅ TERM is correctly set to xterm-256color');
    } else {
      console.log('⚠️  TERM may not be optimally configured');
    }
    
    if (colorTermMatch && colorTermMatch[1] === 'truecolor') {
      console.log('✅ COLORTERM is correctly set to truecolor');
    } else {
      console.log('⚠️  COLORTERM may not be optimally configured');
    }
    
    // Show sample output
    console.log('\n📄 Sample output (first 800 characters):');
    console.log('─'.repeat(60));
    console.log(allOutput.substring(0, 800));
    if (allOutput.length > 800) {
      console.log('...');
    }
    console.log('─'.repeat(60));
    
    // Verify specific test patterns
    const testPatterns = [
      { name: 'Red text', pattern: /RED TEXT/ },
      { name: 'Green text', pattern: /GREEN TEXT/ },
      { name: 'Blue text', pattern: /BLUE TEXT/ },
      { name: 'Bold text', pattern: /BOLD TEXT/ },
      { name: 'Underline', pattern: /UNDERLINE/ },
      { name: 'Yellow bold', pattern: /YELLOW BOLD/ }
    ];
    
    console.log('\n🎯 Test Pattern Verification:');
    testPatterns.forEach(({ name, pattern }) => {
      const found = pattern.test(allOutput);
      console.log(`   ${found ? '✅' : '❌'} ${name}: ${found ? 'found' : 'not found'}`);
    });
    
    // Overall assessment
    const hasAnsiCodes = ansiCodes.length > 0;
    const hasTestText = testPatterns.some(({ pattern }) => pattern.test(allOutput));
    const hasTermConfig = termMatch && colorTermMatch;
    
    console.log('\n🏆 Overall Assessment:');
    if (hasAnsiCodes && hasTestText && hasTermConfig) {
      console.log('✅ EXCELLENT: Full ANSI preservation and terminal configuration working correctly');
    } else if (hasAnsiCodes && hasTestText) {
      console.log('✅ GOOD: ANSI codes preserved and test text found');
    } else if (hasTestText) {
      console.log('⚠️  PARTIAL: Test text found but ANSI codes may be stripped');
    } else {
      console.log('❌ POOR: Missing test output or ANSI preservation issues');
    }
  }

  async cleanup() {
    console.log('\n🧹 Cleaning up...');
    
    if (this.sessionId && this.ws && this.ws.readyState === WebSocket.OPEN) {
      // Send kill session request
      this.ws.send(JSON.stringify({
        type: 'kill',
        data: { sessionId: this.sessionId }
      }));
      
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    if (this.ws) {
      this.ws.close();
    }
    
    // Cleanup any remaining tmux sessions
    await this.tmuxManager.cleanup();
  }
}

// Run the test
const test = new FrontendTerminalTest();
test.runTest().catch(console.error);