#!/usr/bin/env node

/**
 * Test script to verify ANSI escape code preservation through tmux
 */

const TmuxManager = require('../src/lib/tmux-manager');
const path = require('path');

async function testAnsiPreservation() {
  const tmuxManager = new TmuxManager();
  
  try {
    console.log('🧪 Testing ANSI escape code preservation through tmux...\n');
    
    // Check if tmux is available
    const tmuxAvailable = await tmuxManager.isTmuxAvailable();
    if (!tmuxAvailable) {
      console.error('❌ Tmux is not available on this system');
      process.exit(1);
    }
    
    // Create a test session
    console.log('📝 Creating test tmux session...');
    const sessionInfo = await tmuxManager.createSession('ansi-test-session', null, [], 80, 24);
    console.log(`✅ Created session: ${sessionInfo.name}`);
    
    // Test ANSI color codes
    const colorTests = [
      '\\e[31mRED TEXT\\e[0m',      // Red text
      '\\e[32mGREEN TEXT\\e[0m',    // Green text  
      '\\e[34mBLUE TEXT\\e[0m',     // Blue text
      '\\e[1mBOLD TEXT\\e[0m',      // Bold text
      '\\e[4mUNDERLINE\\e[0m',      // Underline
      '\\e[7mREVERSE\\e[0m',        // Reverse video
      '\\e[33;1mYELLOW BOLD\\e[0m'  // Yellow bold
    ];
    
    console.log('\n🎨 Testing ANSI color codes...');
    
    // Send test commands
    await tmuxManager.sendCommand(sessionInfo.name, `echo "=== ANSI Color Test ==="`);
    await new Promise(resolve => setTimeout(resolve, 500));
    
    for (const colorTest of colorTests) {
      await tmuxManager.sendCommand(sessionInfo.name, `echo -e "${colorTest}"`);
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    
    // Test terminal capabilities
    await tmuxManager.sendCommand(sessionInfo.name, 'echo "=== Terminal Capabilities ==="');
    await tmuxManager.sendCommand(sessionInfo.name, 'tput colors');
    await tmuxManager.sendCommand(sessionInfo.name, 'echo "TERM=$TERM"');
    await tmuxManager.sendCommand(sessionInfo.name, 'echo "COLORTERM=$COLORTERM"');
    
    // Wait for output to settle
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Capture output with ANSI preservation
    console.log('\n📸 Capturing tmux output with ANSI preservation...');
    const outputWithAnsi = await tmuxManager.capturePane(sessionInfo.name, sessionInfo.socketPath);
    
    // Capture output without ANSI preservation (for comparison)
    console.log('📸 Capturing tmux output without ANSI preservation...');
    const { spawn } = require('child_process');
    const outputWithoutAnsi = await new Promise((resolve, reject) => {
      const tmux = spawn('tmux', [
        '-S', sessionInfo.socketPath,
        'capture-pane',
        '-t', sessionInfo.name,
        '-p'  // No -e flag
      ], { stdio: 'pipe' });

      let output = '';
      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          resolve(output);
        } else {
          reject(new Error(`Failed to capture pane without ANSI`));
        }
      });
    });
    
    // Analysis
    console.log('\n📊 Analysis Results:');
    console.log('='.repeat(60));
    
    const ansiEscapeRegex = /\x1b\[[0-9;]*[a-zA-Z]/g;
    const ansiCodesWithAnsi = outputWithAnsi.match(ansiEscapeRegex) || [];
    const ansiCodesWithoutAnsi = outputWithoutAnsi.match(ansiEscapeRegex) || [];
    
    console.log(`📈 ANSI codes found (with -e flag): ${ansiCodesWithAnsi.length}`);
    console.log(`📉 ANSI codes found (without -e flag): ${ansiCodesWithoutAnsi.length}`);
    
    if (ansiCodesWithAnsi.length > ansiCodesWithoutAnsi.length) {
      console.log('✅ ANSI escape code preservation is working correctly!');
      console.log(`   → ${ansiCodesWithAnsi.length - ansiCodesWithoutAnsi.length} additional ANSI codes preserved`);
    } else {
      console.log('⚠️  ANSI escape code preservation may not be working as expected');
    }
    
    // Show sample of preserved escape codes
    if (ansiCodesWithAnsi.length > 0) {
      console.log('\n🔍 Sample preserved ANSI codes:');
      ansiCodesWithAnsi.slice(0, 5).forEach((code, index) => {
        console.log(`   ${index + 1}. ${JSON.stringify(code)}`);
      });
    }
    
    // Terminal capabilities check
    const termInfo = outputWithAnsi.match(/TERM=([^\n]+)/)?.[1] || 'unknown';
    const colorTermInfo = outputWithAnsi.match(/COLORTERM=([^\n]+)/)?.[1] || 'unknown';
    const colorsSupported = outputWithAnsi.match(/(\d+)\s*$/m)?.[1] || 'unknown';
    
    console.log('\n🖥️  Terminal Configuration:');
    console.log(`   TERM: ${termInfo}`);
    console.log(`   COLORTERM: ${colorTermInfo}`);
    console.log(`   Colors supported: ${colorsSupported}`);
    
    // Verify expected configuration
    if (termInfo === 'xterm-256color' && colorTermInfo === 'truecolor') {
      console.log('✅ Terminal environment is correctly configured for color support');
    } else {
      console.log('⚠️  Terminal environment may not be optimally configured');
    }
    
    console.log('\n📄 Raw output sample (first 500 chars):');
    console.log('─'.repeat(60));
    console.log(outputWithAnsi.substring(0, 500) + '...');
    console.log('─'.repeat(60));
    
    // Cleanup
    console.log('\n🧹 Cleaning up test session...');
    await tmuxManager.killSession(sessionInfo.name);
    console.log('✅ Test completed successfully');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  }
}

// Run the test
testAnsiPreservation().catch(console.error);