/**
 * Regression test for scrollback functionality
 * Ensures scrollback continues working after changes
 */

const puppeteer = require('puppeteer');
const { spawn } = require('child_process');

describe('Scrollback Regression Tests', () => {
  let browser;
  let page;
  let serverProcess;
  const TEST_PORT = 18090;

  beforeAll(async () => {
    // Start server
    serverProcess = spawn('node', ['unified-server.js'], {
      env: {
        ...process.env,
        PORT: TEST_PORT,
        NODE_ENV: 'test',
        DEBUG_TMUX: '1'
      },
      stdio: 'pipe'
    });

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Launch browser
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
  });

  afterAll(async () => {
    if (browser) await browser.close();
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise(resolve => {
        serverProcess.once('exit', resolve);
        setTimeout(() => {
          serverProcess.kill('SIGKILL');
          resolve();
        }, 5000);
      });
    }
  });

  beforeEach(async () => {
    page = await browser.newPage();
    await page.goto(`http://localhost:${TEST_PORT}`, {
      waitUntil: 'networkidle2',
      timeout: 10000
    });

    // Wait for terminal to be ready
    await page.waitForSelector('.xterm-wrapper', { timeout: 10000 });
    await page.waitForTimeout(1000);
  });

  afterEach(async () => {
    if (page) await page.close();
  });

  test('scrollback configuration should be 10000 lines', async () => {
    const config = await page.evaluate(() => {
      // Access terminal through window or find it
      const terminal = window.__terminal || window.terminal;
      if (terminal && terminal.options) {
        return {
          scrollback: terminal.options.scrollback
        };
      }

      // Try to find terminal in React components
      const terminalElements = document.querySelectorAll('[data-terminal-instance]');
      if (terminalElements.length > 0) {
        // Terminal might be stored in element data
        const instance = terminalElements[0]._terminal;
        if (instance) {
          return {
            scrollback: instance.options.scrollback
          };
        }
      }

      return { scrollback: null };
    });

    expect(config.scrollback).toBe(10000);
  });

  test('scrollback should preserve content when scrolling', async () => {
    // Generate test content
    for (let i = 1; i <= 50; i++) {
      await page.keyboard.type(`echo "Regression Test Line ${i}"`);
      await page.keyboard.press('Enter');
      if (i % 10 === 0) {
        await page.waitForTimeout(200);
      }
    }

    await page.waitForTimeout(1000);

    // Get buffer content before scrolling
    const beforeScroll = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return { lines: 0, content: '' };

      const buffer = terminal.buffer.active;
      let content = [];
      let lineCount = 0;

      for (let i = 0; i < buffer.length; i++) {
        const line = buffer.getLine(i);
        if (line) {
          const text = line.translateToString(true).trim();
          if (text) {
            content.push(text);
            lineCount++;
          }
        }
      }

      return {
        lines: lineCount,
        content: content.join('\n'),
        hasContent: content.length > 0
      };
    });

    expect(beforeScroll.hasContent).toBe(true);
    expect(beforeScroll.content).toContain('Regression Test Line');

    // Scroll up
    await page.keyboard.down('Shift');
    await page.keyboard.press('PageUp');
    await page.keyboard.press('PageUp');
    await page.keyboard.up('Shift');
    await page.waitForTimeout(500);

    // Check if we can still see earlier content
    const afterScroll = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return { scrolled: false };

      const viewport = terminal._core ? terminal._core.viewport : terminal.viewport;
      const buffer = terminal.buffer.active;

      const currentScroll = viewport ? viewport.scrollTop : 0;
      const maxScroll = buffer.length - terminal.rows;

      return {
        scrolled: currentScroll < maxScroll,
        scrollPosition: currentScroll,
        bufferLength: buffer.length,
        terminalRows: terminal.rows
      };
    });

    expect(afterScroll.scrolled).toBe(true);
  });

  test('scrollback should update with new content', async () => {
    // Generate initial content
    for (let i = 1; i <= 20; i++) {
      await page.keyboard.type(`echo "Initial ${i}"`);
      await page.keyboard.press('Enter');
    }

    await page.waitForTimeout(1000);

    // Clear screen
    await page.keyboard.type('clear');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);

    // Add new content
    for (let i = 1; i <= 20; i++) {
      await page.keyboard.type(`echo "Updated ${i}"`);
      await page.keyboard.press('Enter');
    }

    await page.waitForTimeout(1000);

    // Check buffer contains both old and new
    const bufferContent = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return { hasOld: false, hasNew: false };

      const buffer = terminal.buffer.active;
      let fullContent = '';

      for (let i = 0; i < buffer.length; i++) {
        const line = buffer.getLine(i);
        if (line) {
          fullContent += line.translateToString(true) + '\n';
        }
      }

      return {
        hasOld: fullContent.includes('Initial'),
        hasNew: fullContent.includes('Updated'),
        totalLength: fullContent.length
      };
    });

    expect(bufferContent.hasOld).toBe(true);
    expect(bufferContent.hasNew).toBe(true);
    expect(bufferContent.totalLength).toBeGreaterThan(0);
  });

  test('mouse wheel scrolling should work', async () => {
    // Generate content
    for (let i = 1; i <= 100; i++) {
      await page.keyboard.type(`echo "${i}"`);
      await page.keyboard.press('Enter');
    }

    await page.waitForTimeout(2000);

    // Get initial position
    const initialPos = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return -1;
      const viewport = terminal._core ? terminal._core.viewport : terminal.viewport;
      return viewport ? viewport.scrollTop : -1;
    });

    // Find terminal element and scroll
    const terminalElement = await page.$('.xterm-wrapper');
    if (terminalElement) {
      const box = await terminalElement.boundingBox();

      // Move mouse to terminal
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);

      // Scroll up
      await page.mouse.wheel({ deltaY: -300 });
      await page.waitForTimeout(500);
    }

    // Get new position
    const newPos = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return -1;
      const viewport = terminal._core ? terminal._core.viewport : terminal.viewport;
      return viewport ? viewport.scrollTop : -1;
    });

    // Position should have changed (scrolled up = lower value)
    expect(newPos).not.toBe(initialPos);
  });

  test('tmux configuration should have correct history limit', async () => {
    // Send tmux command to check configuration
    await page.keyboard.type('tmux show-options history-limit');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);

    // Get output
    const output = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return '';

      const buffer = terminal.buffer.active;
      let text = '';

      // Get last 10 lines
      const startLine = Math.max(0, buffer.length - 10);
      for (let i = startLine; i < buffer.length; i++) {
        const line = buffer.getLine(i);
        if (line) {
          text += line.translateToString(true) + '\n';
        }
      }

      return text;
    });

    // Should show history-limit of 10000
    expect(output).toMatch(/history-limit\s+10000/);
  });

  test('large scrollback should not cause performance issues', async () => {
    const startTime = Date.now();

    // Generate 1000 lines quickly
    await page.keyboard.type('for i in {1..1000}; do echo "Performance test line $i"; done');
    await page.keyboard.press('Enter');

    // Wait for command to complete
    await page.waitForTimeout(5000);

    const endTime = Date.now();
    const duration = endTime - startTime;

    // Should complete in reasonable time (less than 10 seconds)
    expect(duration).toBeLessThan(10000);

    // Check buffer is populated
    const bufferInfo = await page.evaluate(() => {
      const terminal = window.__terminal || window.terminal;
      if (!terminal) return { lines: 0 };

      const buffer = terminal.buffer.active;
      let nonEmptyLines = 0;

      for (let i = 0; i < buffer.length; i++) {
        const line = buffer.getLine(i);
        if (line && line.translateToString(true).trim()) {
          nonEmptyLines++;
        }
      }

      return {
        lines: nonEmptyLines,
        totalBuffer: buffer.length
      };
    });

    expect(bufferInfo.lines).toBeGreaterThan(900); // Should have most lines
    expect(bufferInfo.totalBuffer).toBeLessThanOrEqual(10000); // Should respect limit
  });
});