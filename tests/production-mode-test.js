const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();

  // Enable console logging
  page.on('console', msg => {
    console.log(`[Browser] ${msg.type()}: ${msg.text()}`);
  });

  page.on('pageerror', error => {
    console.error(`[Page Error]: ${error}`);
  });

  console.log('[Test] Navigating to http://localhost:11238...');
  await page.goto('http://localhost:11238');

  console.log('[Test] Waiting for page to load...');
  await page.waitForLoadState('networkidle');

  // Check what's visible
  const isDisconnected = await page.isVisible('text=Disconnected');
  const isTerminalVisible = await page.isVisible('.xterm-wrapper');
  const isLoadingVisible = await page.isVisible('text=Loading');

  console.log('[Test] Page state:');
  console.log('  - Disconnected message:', isDisconnected);
  console.log('  - Terminal visible:', isTerminalVisible);
  console.log('  - Loading visible:', isLoadingVisible);

  // Wait a bit longer to see if it connects
  console.log('[Test] Waiting 5 seconds for WebSocket connection...');
  await page.waitForTimeout(5000);

  // Check again
  const isDisconnectedAfter = await page.isVisible('text=Disconnected');
  const isTerminalVisibleAfter = await page.isVisible('.xterm-wrapper');

  console.log('[Test] Page state after waiting:');
  console.log('  - Disconnected message:', isDisconnectedAfter);
  console.log('  - Terminal visible:', isTerminalVisibleAfter);

  // Get page content for debugging
  const bodyText = await page.evaluate(() => document.body.innerText);
  console.log('[Test] Page content preview:', bodyText.substring(0, 200));

  // Check for WebSocket connection
  const wsConnected = await page.evaluate(() => {
    return window.wsClient && window.wsClient.connected;
  });
  console.log('[Test] WebSocket connected:', wsConnected);

  // Keep browser open for manual inspection
  console.log('[Test] Keeping browser open for manual inspection...');
  await page.waitForTimeout(30000);

  await browser.close();
})();