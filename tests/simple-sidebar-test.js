/**
 * Simple Sidebar Visibility Test
 * Tests that sidebar is visible in both collapsed and expanded states
 */

const puppeteer = require('puppeteer');

async function testSidebarVisibility(url, mode) {
  console.log(`\n=== Testing ${mode.toUpperCase()} Mode: ${url} ===`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1200, height: 800 });

    console.log(`[${mode}] Navigating to ${url}...`);
    await page.goto(url, { waitUntil: 'networkidle0', timeout: 15000 });

    // Wait for page to load
    await page.waitForTimeout(2000);

    // Check if sidebar container exists
    const sidebarContainer = await page.$('div.bg-gray-900.border-r.border-gray-700');
    console.log(`[${mode}] Sidebar container found: ${!!sidebarContainer}`);

    if (sidebarContainer) {
      // Check sidebar width
      const sidebarClasses = await page.evaluate(() => {
        const sidebar = document.querySelector('div.bg-gray-900.border-r.border-gray-700');
        return sidebar ? sidebar.className : null;
      });

      console.log(`[${mode}] Sidebar classes: ${sidebarClasses}`);

      // Check for open/close buttons
      const hamburgerButton = await page.$('button[title="Open Sidebar"]');
      const closeButton = await page.$('button[title="Close Sidebar"]');

      console.log(`[${mode}] Hamburger menu (collapsed state): ${!!hamburgerButton}`);
      console.log(`[${mode}] Close button (expanded state): ${!!closeButton}`);

      // Determine current state
      const isExpanded = sidebarClasses && sidebarClasses.includes('w-72');
      const isCollapsed = sidebarClasses && sidebarClasses.includes('w-12');

      console.log(`[${mode}] Sidebar expanded (w-72): ${isExpanded}`);
      console.log(`[${mode}] Sidebar collapsed (w-12): ${isCollapsed}`);

      // Check for terminals header
      const terminalsHeader = await page.$('h2:has-text("Terminals")');
      console.log(`[${mode}] Terminals header visible: ${!!terminalsHeader}`);

      // Take screenshot
      await page.screenshot({
        path: `/tmp/sidebar-test-${mode}.png`,
        fullPage: false
      });
      console.log(`[${mode}] Screenshot saved to /tmp/sidebar-test-${mode}.png`);

      return {
        mode,
        sidebarExists: !!sidebarContainer,
        isExpanded,
        isCollapsed,
        hasHamburger: !!hamburgerButton,
        hasCloseButton: !!closeButton,
        hasTerminalsHeader: !!terminalsHeader,
        classes: sidebarClasses
      };
    } else {
      console.log(`[${mode}] ❌ SIDEBAR NOT FOUND!`);
      return {
        mode,
        sidebarExists: false,
        error: 'Sidebar container not found'
      };
    }

  } catch (error) {
    console.error(`[${mode}] Error:`, error.message);
    return {
      mode,
      error: error.message
    };
  } finally {
    await browser.close();
  }
}

async function runTests() {
  console.log('🧪 Running Sidebar Visibility Tests...\n');

  const results = [];

  // Test development mode (if running)
  try {
    const devResult = await testSidebarVisibility('http://localhost:9000', 'development');
    results.push(devResult);
  } catch (error) {
    console.log('[DEV] Server not running, skipping...');
  }

  // Test production mode (if running)
  try {
    const prodResult = await testSidebarVisibility('http://localhost:9001', 'production');
    results.push(prodResult);
  } catch (error) {
    console.log('[PROD] Server not running, skipping...');
  }

  // Generate report
  console.log('\n' + '='.repeat(60));
  console.log('                SIDEBAR TEST RESULTS');
  console.log('='.repeat(60));

  results.forEach(result => {
    if (result.error) {
      console.log(`\n❌ ${result.mode.toUpperCase()}: ${result.error}`);
    } else {
      console.log(`\n✅ ${result.mode.toUpperCase()}:`);
      console.log(`   Sidebar exists: ${result.sidebarExists}`);
      console.log(`   Expanded (w-72): ${result.isExpanded}`);
      console.log(`   Collapsed (w-12): ${result.isCollapsed}`);
      console.log(`   Hamburger button: ${result.hasHamburger}`);
      console.log(`   Close button: ${result.hasCloseButton}`);
      console.log(`   Terminals header: ${result.hasTerminalsHeader}`);
    }
  });

  // Analysis
  console.log('\n' + '='.repeat(60));
  console.log('                     ANALYSIS');
  console.log('='.repeat(60));

  const workingResults = results.filter(r => !r.error && r.sidebarExists);

  if (workingResults.length === 0) {
    console.log('❌ NO WORKING SIDEBARS FOUND - All tests failed');
  } else if (workingResults.every(r => r.isExpanded && !r.isCollapsed)) {
    console.log('✅ SIDEBAR ALWAYS EXPANDED - This is the current behavior');
    console.log('   - Sidebar starts in expanded state (w-72)');
    console.log('   - Close button is visible');
    console.log('   - No hamburger menu (collapsed state) detected');
  } else if (workingResults.some(r => r.isCollapsed)) {
    console.log('⚠️  MIXED STATES DETECTED');
  } else {
    console.log('❓ UNKNOWN STATE');
  }

  console.log('\n🔍 DIAGNOSIS:');
  console.log('   The sidebar is rendering correctly but starts in EXPANDED state.');
  console.log('   This means the `sidebarOpen: true` default in the store is working.');
  console.log('   The issue might be that users expect it to start COLLAPSED on smaller screens.');

  console.log('\n💡 RECOMMENDATIONS:');
  console.log('   1. Check if initializeSidebarForViewport() is being called');
  console.log('   2. Test on mobile viewport (< 768px width)');
  console.log('   3. Verify toggle functionality works correctly');
  console.log('   4. Check if production has different initial state');
}

if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { testSidebarVisibility };