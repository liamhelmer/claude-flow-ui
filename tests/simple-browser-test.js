const { chromium } = require('playwright');

(async () => {
  console.log('[Test] Starting simple browser test...');
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();

  // Enable console logging
  page.on('console', msg => {
    console.log(`[Browser] ${msg.type()}: ${msg.text()}`);
  });

  page.on('pageerror', error => {
    console.error(`[Page Error]: ${error}`);
  });

  console.log('[Test] Navigating to http://localhost:11239...');

  try {
    await page.goto('http://localhost:11239', { waitUntil: 'domcontentloaded' });
    console.log('[Test] Page loaded successfully');

    // Wait a moment
    await page.waitForTimeout(5000);

    // Check what's on the page
    const title = await page.title();
    console.log('[Test] Page title:', title);

    const bodyText = await page.evaluate(() => document.body.innerText);
    console.log('[Test] Page content preview:', bodyText.substring(0, 200));

    // Check for specific elements
    const hasTerminal = await page.locator('.xterm-wrapper').count();
    const hasLoading = await page.locator('text=Loading').count();
    const hasConnecting = await page.locator('text=Connecting').count();

    console.log('[Test] Terminal elements:', hasTerminal);
    console.log('[Test] Loading elements:', hasLoading);
    console.log('[Test] Connecting elements:', hasConnecting);

    // Check WebSocket connection
    const wsState = await page.evaluate(() => {
      if (window.wsClient) {
        return {
          exists: true,
          connected: window.wsClient.connected,
          connecting: window.wsClient.connecting
        };
      }
      return { exists: false };
    });

    console.log('[Test] WebSocket state:', wsState);

    console.log('[Test] Keeping browser open for inspection...');
    await page.waitForTimeout(20000);

  } catch (error) {
    console.error('[Test] Error:', error.message);
  }

  await browser.close();
  console.log('[Test] Test complete');
})();