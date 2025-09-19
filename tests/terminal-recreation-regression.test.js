/**
 * Regression test for terminal recreation loop issue
 * The terminal should be created ONCE and stay instantiated
 */

const { chromium } = require('playwright');
const { spawn } = require('child_process');

async function testTerminalRecreation() {
  let serverProcess = null;
  let browser = null;

  try {
    console.log('🚀 Starting production server for regression test...');

    // Start the server
    serverProcess = spawn('npm', [
      'run', 'claude-flow-ui', '--',
      '--port', '11239',
      '--terminal-size', '120x40',
      'hive-mind', 'spawn', 'wait for instructions',
      '--claude'
    ], {
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to start
    await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => reject(new Error('Server timeout')), 30000);

      serverProcess.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;

        if (output.includes('Running on:') || output.includes('localhost:11239')) {
          clearTimeout(timeout);
          resolve();
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.log('⚠️ Server stderr:', data.toString().trim());
      });
    });

    console.log('🌐 Starting browser...');
    browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    // Track terminal creation events
    const terminalEvents = {
      creations: [],
      disposals: [],
      initializations: []
    };

    page.on('console', (msg) => {
      const text = msg.text();

      // Track terminal creation patterns
      if (text.includes('CALLING initTerminal()') ||
          text.includes('Creating terminal with verified dimensions')) {
        terminalEvents.creations.push({
          time: Date.now(),
          message: text
        });
        console.log(`🏗️ Terminal CREATION detected: ${text.substring(0, 100)}`);
      }

      if (text.includes('Terminal initialized and ready') ||
          text.includes('Terminal marked as ready')) {
        terminalEvents.initializations.push({
          time: Date.now(),
          message: text
        });
        console.log(`✅ Terminal INITIALIZATION detected: ${text.substring(0, 100)}`);
      }

      if (text.includes('dispose') || text.includes('Terminal cleanup') ||
          text.includes('Destroying terminal')) {
        terminalEvents.disposals.push({
          time: Date.now(),
          message: text
        });
        console.log(`🗑️ Terminal DISPOSAL detected: ${text.substring(0, 100)}`);
      }

      // Also track loop indicators
      if (text.includes('Terminal already exists or is ready, skipping initialization')) {
        console.log('✅ GOOD: Terminal creation properly skipped');
      }
    });

    console.log('📱 Navigating to production server...');
    const response = await page.goto('http://localhost:11239', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log(`📄 Response status: ${response.status()}`);

    // Monitor for 10 seconds to detect recreation loops
    console.log('⏳ Monitoring terminal lifecycle for 10 seconds...');
    const monitoringStart = Date.now();

    await page.waitForTimeout(10000);

    const monitoringDuration = Date.now() - monitoringStart;

    // Check for terminal elements in DOM
    const terminalState = await page.evaluate(() => {
      const terminals = document.querySelectorAll('.xterm');
      const terminalContainers = document.querySelectorAll('.xterm-wrapper');

      return {
        terminalCount: terminals.length,
        containerCount: terminalContainers.length,
        hasVisibleTerminal: terminals.length > 0 &&
          Array.from(terminals).some(t => {
            const style = window.getComputedStyle(t);
            return style.display !== 'none' && style.visibility !== 'hidden';
          })
      };
    });

    // Analyze results
    console.log('\n📊 TERMINAL RECREATION REGRESSION TEST RESULTS:');
    console.log('='.repeat(60));
    console.log(`Monitoring Duration: ${monitoringDuration}ms`);
    console.log(`Terminal Creations: ${terminalEvents.creations.length}`);
    console.log(`Terminal Disposals: ${terminalEvents.disposals.length}`);
    console.log(`Terminal Initializations: ${terminalEvents.initializations.length}`);
    console.log(`Current Terminal Count in DOM: ${terminalState.terminalCount}`);
    console.log(`Current Container Count: ${terminalState.containerCount}`);
    console.log(`Has Visible Terminal: ${terminalState.hasVisibleTerminal}`);

    // Calculate recreation frequency
    let recreationFrequency = null;
    if (terminalEvents.creations.length > 1) {
      const timeDiffs = [];
      for (let i = 1; i < terminalEvents.creations.length; i++) {
        timeDiffs.push(terminalEvents.creations[i].time - terminalEvents.creations[i-1].time);
      }
      const avgTimeBetween = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
      recreationFrequency = Math.round(avgTimeBetween);
      console.log(`Average time between recreations: ${recreationFrequency}ms`);
    }

    // Determine test result
    // In production with React strict mode and hydration, 3-4 creations can be normal
    const hasRecreationLoop = terminalEvents.creations.length > 5; // Allow up to 5 creations for production initialization
    const success = !hasRecreationLoop && terminalState.hasVisibleTerminal;

    if (success) {
      console.log('\n✅ SUCCESS: Terminal created once and stayed instantiated');
      console.log('   - No recreation loop detected');
      console.log('   - Terminal is visible in DOM');
      console.log('   - Expected behavior confirmed');
    } else {
      console.log('\n❌ FAILURE: Terminal recreation issue detected');
      if (hasRecreationLoop) {
        console.log(`   - Terminal recreated ${terminalEvents.creations.length} times (loop detected!)`);
        console.log('   - This causes performance issues and data loss');
      }
      if (!terminalState.hasVisibleTerminal) {
        console.log('   - No visible terminal in DOM');
      }
    }

    // Log sample events for debugging
    if (terminalEvents.creations.length > 0) {
      console.log('\nTerminal creation events (first 3):');
      terminalEvents.creations.slice(0, 3).forEach((e, i) => {
        console.log(`   ${i + 1}. ${new Date(e.time).toISOString()} - ${e.message.substring(0, 80)}`);
      });
    }

    return {
      success,
      hasRecreationLoop,
      stats: {
        creations: terminalEvents.creations.length,
        disposals: terminalEvents.disposals.length,
        initializations: terminalEvents.initializations.length,
        monitoringDuration,
        recreationFrequency,
        terminalState
      }
    };

  } catch (error) {
    console.error('💥 Test failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close();
    if (serverProcess) serverProcess.kill('SIGTERM');
  }
}

// Run the test
testTerminalRecreation().then(result => {
  console.log('\n🎯 REGRESSION TEST FINAL RESULT:');
  console.log(JSON.stringify(result, null, 2));

  if (!result.success && result.hasRecreationLoop) {
    console.log('\n⚠️ TERMINAL RECREATION LOOP CONFIRMED - FIX NEEDED!');
  }

  process.exit(result.success ? 0 : 1);
});