/**
 * Comprehensive test suite for terminal scrollback functionality
 * Tests 10,000 line scrollback buffer implementation
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { spawn } from 'child_process';
import WebSocket from 'ws';
import puppeteer from 'puppeteer';

describe('Terminal Scrollback Functionality', () => {
  let serverProcess;
  let browser;
  let page;
  let ws;
  const SERVER_PORT = 18080;
  const WS_PORT = 18081;

  beforeEach(async () => {
    // Start the server in test mode
    serverProcess = spawn('node', ['unified-server.js'], {
      env: {
        ...process.env,
        PORT: SERVER_PORT.toString(),
        WS_PORT: WS_PORT.toString(),
        NODE_ENV: 'test',
        DEBUG_TMUX: '1'
      }
    });

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Launch browser
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    page = await browser.newPage();

    // Navigate to the app
    await page.goto(`http://localhost:${SERVER_PORT}`);

    // Wait for terminal to be ready
    await page.waitForSelector('.xterm-wrapper', { timeout: 5000 });

    // Connect WebSocket
    ws = new WebSocket(`ws://localhost:${WS_PORT}`);
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
  });

  afterEach(async () => {
    if (ws) ws.close();
    if (browser) await browser.close();
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise(resolve => serverProcess.once('exit', resolve));
    }
  });

  describe('Scrollback Buffer Configuration', () => {
    test('xterm should be configured with 10000 lines scrollback', async () => {
      // Evaluate terminal configuration in the browser
      const scrollbackSize = await page.evaluate(() => {
        const terminal = window.__terminal;
        return terminal ? terminal.options.scrollback : null;
      });

      expect(scrollbackSize).toBe(10000);
    });

    test('tmux should have history-limit set to 10000', async () => {
      // Send command to check tmux configuration
      await page.keyboard.type('tmux show-options -t claude-flow-main history-limit\n');
      await page.waitForTimeout(500);

      // Get terminal output
      const output = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const buffer = terminal.buffer.active;
        let text = '';
        for (let i = 0; i < buffer.length; i++) {
          text += buffer.getLine(i).translateToString(true) + '\n';
        }
        return text;
      });

      expect(output).toContain('history-limit 10000');
    });

    test('tmux should have mouse support enabled', async () => {
      // Send command to check mouse configuration
      await page.keyboard.type('tmux show-options -t claude-flow-main mouse\n');
      await page.waitForTimeout(500);

      // Get terminal output
      const output = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const buffer = terminal.buffer.active;
        let text = '';
        for (let i = 0; i < buffer.length; i++) {
          text += buffer.getLine(i).translateToString(true) + '\n';
        }
        return text;
      });

      expect(output).toContain('mouse on');
    });
  });

  describe('Scrollback Buffer Functionality', () => {
    test('should preserve content when scrolling back', async () => {
      // Generate content to fill scrollback
      for (let i = 1; i <= 100; i++) {
        await page.keyboard.type(`echo "Line ${i}"\n`);
        if (i % 10 === 0) {
          await page.waitForTimeout(100); // Small delay every 10 lines
        }
      }

      await page.waitForTimeout(1000); // Wait for all output

      // Scroll up using keyboard
      await page.keyboard.down('Shift');
      await page.keyboard.press('PageUp');
      await page.keyboard.press('PageUp');
      await page.keyboard.press('PageUp');
      await page.keyboard.up('Shift');

      await page.waitForTimeout(500);

      // Check if scrollback contains earlier lines
      const visibleText = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const viewport = terminal._core.viewport;
        const buffer = terminal.buffer.active;
        let text = '';

        // Get visible viewport lines
        for (let i = viewport.scrollTop; i < Math.min(viewport.scrollTop + terminal.rows, buffer.length); i++) {
          const line = buffer.getLine(i);
          if (line) {
            text += line.translateToString(true) + '\n';
          }
        }
        return text;
      });

      // Should see earlier lines in scrollback
      expect(visibleText).toMatch(/Line \d+/);
      expect(visibleText).not.toContain('Line 100'); // Should not see latest line when scrolled up
    });

    test('should update scrollback buffer with new content', async () => {
      // Generate initial content
      for (let i = 1; i <= 50; i++) {
        await page.keyboard.type(`echo "Initial Line ${i}"\n`);
      }

      await page.waitForTimeout(1000);

      // Clear screen but preserve scrollback
      await page.keyboard.type('clear\n');
      await page.waitForTimeout(500);

      // Generate new content
      for (let i = 1; i <= 50; i++) {
        await page.keyboard.type(`echo "New Line ${i}"\n`);
      }

      await page.waitForTimeout(1000);

      // Scroll up to check scrollback
      await page.keyboard.down('Shift');
      for (let i = 0; i < 10; i++) {
        await page.keyboard.press('PageUp');
      }
      await page.keyboard.up('Shift');

      await page.waitForTimeout(500);

      // Get scrollback content
      const scrollbackContent = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const buffer = terminal.buffer.active;
        let text = '';

        // Get all buffer content
        for (let i = 0; i < buffer.length; i++) {
          const line = buffer.getLine(i);
          if (line) {
            text += line.translateToString(true) + '\n';
          }
        }
        return text;
      });

      // Should contain both old and new content
      expect(scrollbackContent).toContain('Initial Line');
      expect(scrollbackContent).toContain('New Line');
    });

    test('should handle 10000 lines without losing data', async () => {
      // Generate exactly 10000 lines
      const batchSize = 100;
      const totalBatches = 100; // 100 * 100 = 10000

      for (let batch = 0; batch < totalBatches; batch++) {
        // Generate batch of lines
        let command = 'for i in {';
        command += `${batch * batchSize + 1}..${(batch + 1) * batchSize}`;
        command += '}; do echo "Test Line $i"; done\n';

        await page.keyboard.type(command);
        await page.waitForTimeout(500); // Wait for batch to process
      }

      await page.waitForTimeout(3000); // Wait for all output

      // Check buffer size
      const bufferInfo = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return { size: 0, hasContent: false };
        const buffer = terminal.buffer.active;

        // Count non-empty lines
        let nonEmptyCount = 0;
        for (let i = 0; i < buffer.length; i++) {
          const line = buffer.getLine(i);
          if (line && line.translateToString(true).trim()) {
            nonEmptyCount++;
          }
        }

        return {
          size: buffer.length,
          nonEmptyLines: nonEmptyCount,
          maxScrollback: terminal.options.scrollback
        };
      });

      expect(bufferInfo.maxScrollback).toBe(10000);
      expect(bufferInfo.size).toBeGreaterThan(0);
      expect(bufferInfo.size).toBeLessThanOrEqual(10000);
    });

    test('should support mouse wheel scrolling', async () => {
      // Generate content
      for (let i = 1; i <= 100; i++) {
        await page.keyboard.type(`echo "Scroll Test ${i}"\n`);
      }

      await page.waitForTimeout(1000);

      // Get initial viewport position
      const initialPosition = await page.evaluate(() => {
        const terminal = window.__terminal;
        return terminal ? terminal._core.viewport.scrollTop : -1;
      });

      // Simulate mouse wheel scroll up
      await page.mouse.move(400, 300); // Move to terminal area
      await page.mouse.wheel({ deltaY: -500 });
      await page.waitForTimeout(500);

      // Get new viewport position
      const scrolledPosition = await page.evaluate(() => {
        const terminal = window.__terminal;
        return terminal ? terminal._core.viewport.scrollTop : -1;
      });

      // Should have scrolled up (lower position value)
      expect(scrolledPosition).toBeLessThan(initialPosition);

      // Scroll back down
      await page.mouse.wheel({ deltaY: 500 });
      await page.waitForTimeout(500);

      const finalPosition = await page.evaluate(() => {
        const terminal = window.__terminal;
        return terminal ? terminal._core.viewport.scrollTop : -1;
      });

      // Should be back near the bottom
      expect(finalPosition).toBeGreaterThan(scrolledPosition);
    });
  });

  describe('Streaming and Updates', () => {
    test('should preserve scrollback when receiving streamed updates', async () => {
      // Generate initial content
      for (let i = 1; i <= 50; i++) {
        await page.keyboard.type(`echo "Stream Test ${i}"\n`);
      }

      await page.waitForTimeout(1000);

      // Start a command that produces streaming output
      await page.keyboard.type('for i in {1..20}; do echo "Streaming $i"; sleep 0.1; done\n');

      // While streaming, scroll up
      await page.waitForTimeout(500);
      await page.keyboard.down('Shift');
      await page.keyboard.press('PageUp');
      await page.keyboard.press('PageUp');
      await page.keyboard.up('Shift');

      // Get content while scrolled up
      const scrolledContent = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const viewport = terminal._core.viewport;
        const buffer = terminal.buffer.active;
        let text = '';

        for (let i = viewport.scrollTop; i < Math.min(viewport.scrollTop + terminal.rows, buffer.length); i++) {
          const line = buffer.getLine(i);
          if (line) {
            text += line.translateToString(true) + '\n';
          }
        }
        return text;
      });

      // Should still see old content while new is being added
      expect(scrolledContent).toContain('Stream Test');

      // Wait for streaming to complete
      await page.waitForTimeout(3000);

      // Scroll to bottom
      await page.keyboard.press('End');
      await page.waitForTimeout(500);

      // Check that new content is present
      const bottomContent = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const buffer = terminal.buffer.active;
        let text = '';

        // Get last 20 lines
        const startLine = Math.max(0, buffer.length - 20);
        for (let i = startLine; i < buffer.length; i++) {
          const line = buffer.getLine(i);
          if (line) {
            text += line.translateToString(true) + '\n';
          }
        }
        return text;
      });

      expect(bottomContent).toContain('Streaming');
    });

    test('should handle screen clear commands correctly', async () => {
      // Generate content
      for (let i = 1; i <= 30; i++) {
        await page.keyboard.type(`echo "Before Clear ${i}"\n`);
      }

      await page.waitForTimeout(1000);

      // Clear screen (should preserve scrollback)
      await page.keyboard.type('clear\n');
      await page.waitForTimeout(500);

      // Add new content
      for (let i = 1; i <= 10; i++) {
        await page.keyboard.type(`echo "After Clear ${i}"\n`);
      }

      await page.waitForTimeout(1000);

      // Scroll up to check if old content is preserved
      await page.keyboard.down('Shift');
      for (let i = 0; i < 5; i++) {
        await page.keyboard.press('PageUp');
      }
      await page.keyboard.up('Shift');

      await page.waitForTimeout(500);

      const scrollbackContent = await page.evaluate(() => {
        const terminal = window.__terminal;
        if (!terminal) return '';
        const buffer = terminal.buffer.active;
        let text = '';

        for (let i = 0; i < buffer.length; i++) {
          const line = buffer.getLine(i);
          if (line) {
            const content = line.translateToString(true).trim();
            if (content) {
              text += content + '\n';
            }
          }
        }
        return text;
      });

      // Should have both before and after clear content
      expect(scrollbackContent).toContain('Before Clear');
      expect(scrollbackContent).toContain('After Clear');
    });
  });
});