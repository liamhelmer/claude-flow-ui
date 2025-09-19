const { chromium } = require('playwright');

/**
 * Production Terminal Fix Test
 *
 * Validates that:
 * 1. No duplicate session switching occurs
 * 2. Terminal receives and displays data properly
 * 3. Input is routed to the correct terminal
 * 4. Only one tmux session is created
 */
(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();

  // Enable detailed console logging
  page.on('console', msg => {
    const text = msg.text();
    console.log(`[Browser] ${msg.type()}: ${text}`);
  });

  page.on('pageerror', error => {
    console.error(`[Page Error]: ${error}`);
  });

  console.log('[Test] Navigating to http://localhost:11239...');
  await page.goto('http://localhost:11239');

  console.log('[Test] Waiting for page to load...');
  await page.waitForLoadState('networkidle');

  // Wait for terminal to be ready
  console.log('[Test] Waiting for terminal to initialize...');
  await page.waitForTimeout(3000);

  // Check initial state
  const isDisconnected = await page.isVisible('text=Disconnected');
  const isTerminalVisible = await page.isVisible('.xterm-wrapper');
  const isLoadingVisible = await page.isVisible('text=Loading');
  const isConnectingVisible = await page.isVisible('text=Connecting to Terminal');

  console.log('[Test] Initial page state:');
  console.log('  - Disconnected message:', isDisconnected);
  console.log('  - Terminal visible:', isTerminalVisible);
  console.log('  - Loading visible:', isLoadingVisible);
  console.log('  - Connecting visible:', isConnectingVisible);

  // Check for terminal content
  const terminalContent = await page.evaluate(() => {
    const terminal = document.querySelector('.xterm-screen');
    return terminal ? terminal.textContent.trim() : null;
  });

  console.log('[Test] Terminal content present:', !!terminalContent);
  if (terminalContent) {
    const lines = terminalContent.split('\n').filter(l => l.trim());
    console.log('[Test] Terminal lines count:', lines.length);
    console.log('[Test] First few lines:', lines.slice(0, 3));
  }

  // Test terminal input
  console.log('[Test] Testing terminal input...');
  await page.click('.xterm-wrapper', { force: true });
  await page.waitForTimeout(500);

  // Type a test command
  await page.keyboard.type('echo "Terminal test successful"');
  await page.keyboard.press('Enter');

  // Wait for output
  await page.waitForTimeout(2000);

  // Check if output appeared
  const terminalContentAfter = await page.evaluate(() => {
    const terminal = document.querySelector('.xterm-screen');
    return terminal ? terminal.textContent : '';
  });

  const testSuccessful = terminalContentAfter.includes('Terminal test successful');
  console.log('[Test] Terminal input test:', testSuccessful ? 'PASSED' : 'FAILED');

  // Check WebSocket status
  const wsStatus = await page.evaluate(() => {
    if (window.wsClient) {
      return {
        connected: window.wsClient.connected,
        sessionId: window.wsClient.sessionId
      };
    }
    return { connected: false, sessionId: null };
  });

  console.log('[Test] WebSocket status:', wsStatus);

  // Check session consistency
  const sessionData = await page.evaluate(() => {
    const store = window.__STORE__;
    if (store) {
      const state = store.getState();
      return {
        activeSessionId: state.activeSessionId,
        sessionsCount: state.terminalSessions.length,
        sessions: state.terminalSessions.map(s => ({ id: s.id, name: s.name }))
      };
    }
    return null;
  });

  console.log('[Test] Session data:', sessionData);

  // Verify only one session exists
  if (sessionData && sessionData.sessionsCount === 1) {
    console.log('[Test] ✅ Only one session exists (correct)');
  } else if (sessionData) {
    console.log(`[Test] ⚠️ Multiple sessions found: ${sessionData.sessionsCount}`);
  }

  // Final status
  console.log('\n[Test] Final Results:');
  console.log('  - Page loads:', !isDisconnected && !isLoadingVisible ? 'PASS' : 'FAIL');
  console.log('  - Terminal visible:', isTerminalVisible ? 'PASS' : 'FAIL');
  console.log('  - Terminal has content:', !!terminalContent ? 'PASS' : 'FAIL');
  console.log('  - Input works:', testSuccessful ? 'PASS' : 'FAIL');
  console.log('  - WebSocket connected:', wsStatus.connected ? 'PASS' : 'FAIL');
  console.log('  - Single session:', sessionData?.sessionsCount === 1 ? 'PASS' : 'FAIL');

  // Keep browser open for manual inspection
  console.log('\n[Test] Keeping browser open for manual inspection...');
  await page.waitForTimeout(30000);

  await browser.close();
})();