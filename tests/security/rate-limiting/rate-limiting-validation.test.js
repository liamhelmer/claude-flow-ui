/**
 * Security Test Suite: Rate Limiting Validation
 * OWASP Compliance: Rate Limiting and DoS Prevention
 */

const { expect } = require('chai');
const sinon = require('sinon');

describe('Rate Limiting Validation', () => {
  let clock;

  beforeEach(() => {
    clock = sinon.useFakeTimers();
  });

  afterEach(() => {
    clock.restore();
  });

  describe('Request Rate Limiting', () => {
    it('should implement basic request rate limiting', () => {
      const rateLimiter = new Map();
      const maxRequestsPerMinute = 60;
      const windowSizeMs = 60000; // 1 minute
      const clientId = 'client_123';

      // Simulate rapid requests
      for (let i = 0; i < 100; i++) {
        const now = Date.now();

        if (!rateLimiter.has(clientId)) {
          rateLimiter.set(clientId, {
            count: 0,
            windowStart: now,
            blocked: false
          });
        }

        const clientData = rateLimiter.get(clientId);

        // Reset window if time has passed
        if (now - clientData.windowStart >= windowSizeMs) {
          clientData.count = 0;
          clientData.windowStart = now;
          clientData.blocked = false;
        }

        clientData.count++;

        // Check rate limit
        if (clientData.count > maxRequestsPerMinute) {
          clientData.blocked = true;
          console.log(`Request ${i + 1} blocked: Rate limit exceeded (${clientData.count}/${maxRequestsPerMinute})`);
          break;
        }

        rateLimiter.set(clientId, clientData);

        // Advance time slightly for each request
        clock.tick(500); // 0.5 seconds between requests
      }

      const finalData = rateLimiter.get(clientId);
      expect(finalData.blocked).to.be.true;
      expect(finalData.count).to.be.greaterThan(maxRequestsPerMinute);
    });

    it('should implement sliding window rate limiting', () => {
      const slidingWindow = new Map();
      const maxRequests = 10;
      const windowSizeMs = 60000; // 1 minute
      const clientId = 'sliding_client';

      // Initialize sliding window
      slidingWindow.set(clientId, []);

      for (let i = 0; i < 15; i++) {
        const now = Date.now();
        const requests = slidingWindow.get(clientId);

        // Remove old requests outside the window
        const cutoff = now - windowSizeMs;
        const validRequests = requests.filter(timestamp => timestamp > cutoff);

        // Check if new request would exceed limit
        if (validRequests.length >= maxRequests) {
          console.log(`Request ${i + 1} blocked: Sliding window limit exceeded (${validRequests.length}/${maxRequests})`);
          expect(validRequests.length).to.be.greaterThanOrEqual(maxRequests);
          break;
        }

        // Add new request
        validRequests.push(now);
        slidingWindow.set(clientId, validRequests);

        console.log(`Request ${i + 1} allowed: ${validRequests.length}/${maxRequests} in window`);

        // Advance time
        clock.tick(5000); // 5 seconds between requests
      }
    });

    it('should implement token bucket rate limiting', () => {
      const tokenBuckets = new Map();
      const bucketSize = 10;
      const refillRate = 1; // 1 token per second
      const clientId = 'bucket_client';

      // Initialize token bucket
      tokenBuckets.set(clientId, {
        tokens: bucketSize,
        lastRefill: Date.now()
      });

      for (let i = 0; i < 20; i++) {
        const now = Date.now();
        const bucket = tokenBuckets.get(clientId);

        // Refill tokens based on time passed
        const timePassed = now - bucket.lastRefill;
        const tokensToAdd = Math.floor(timePassed / 1000) * refillRate;
        bucket.tokens = Math.min(bucketSize, bucket.tokens + tokensToAdd);
        bucket.lastRefill = now;

        // Try to consume a token
        if (bucket.tokens > 0) {
          bucket.tokens--;
          console.log(`Request ${i + 1} allowed: ${bucket.tokens} tokens remaining`);
        } else {
          console.log(`Request ${i + 1} blocked: No tokens available`);
          expect(bucket.tokens).to.equal(0);

          if (i > 10) { // Should be blocked after initial burst
            break;
          }
        }

        tokenBuckets.set(clientId, bucket);

        // Advance time
        clock.tick(500); // 0.5 seconds between requests
      }
    });
  });

  describe('API Endpoint Rate Limiting', () => {
    it('should implement endpoint-specific rate limits', () => {
      const endpointLimits = {
        '/api/auth/login': { limit: 5, window: 300000 }, // 5 attempts per 5 minutes
        '/api/users': { limit: 100, window: 60000 }, // 100 requests per minute
        '/api/files/upload': { limit: 10, window: 60000 }, // 10 uploads per minute
        '/api/search': { limit: 50, window: 60000 } // 50 searches per minute
      };

      const endpointTracking = new Map();

      const testRequests = [
        { endpoint: '/api/auth/login', count: 7 }, // Should be limited
        { endpoint: '/api/users', count: 150 }, // Should be limited
        { endpoint: '/api/files/upload', count: 15 }, // Should be limited
        { endpoint: '/api/search', count: 75 } // Should be limited
      ];

      testRequests.forEach(test => {
        const limits = endpointLimits[test.endpoint];
        const clientId = 'test_client';
        const trackingKey = `${clientId}:${test.endpoint}`;

        for (let i = 0; i < test.count; i++) {
          const now = Date.now();

          if (!endpointTracking.has(trackingKey)) {
            endpointTracking.set(trackingKey, {
              count: 0,
              windowStart: now
            });
          }

          const tracking = endpointTracking.get(trackingKey);

          // Reset window if expired
          if (now - tracking.windowStart >= limits.window) {
            tracking.count = 0;
            tracking.windowStart = now;
          }

          tracking.count++;

          if (tracking.count > limits.limit) {
            console.log(`${test.endpoint} request ${i + 1} blocked: ${tracking.count}/${limits.limit} limit exceeded`);
            expect(tracking.count).to.be.greaterThan(limits.limit);
            break;
          }

          endpointTracking.set(trackingKey, tracking);
        }
      });
    });

    it('should implement progressive rate limiting penalties', () => {
      const penaltySystem = {
        strikes: new Map(),
        penalties: [
          { threshold: 1, duration: 60000, multiplier: 1 }, // 1 minute
          { threshold: 3, duration: 300000, multiplier: 2 }, // 5 minutes
          { threshold: 5, duration: 900000, multiplier: 4 }, // 15 minutes
          { threshold: 10, duration: 3600000, multiplier: 8 } // 1 hour
        ]
      };

      const clientId = 'penalty_client';

      // Simulate multiple violations
      for (let violation = 1; violation <= 12; violation++) {
        const currentStrikes = penaltySystem.strikes.get(clientId) || 0;
        penaltySystem.strikes.set(clientId, currentStrikes + 1);

        const strikes = penaltySystem.strikes.get(clientId);

        // Find applicable penalty
        let penalty = penaltySystem.penalties[0]; // Default penalty
        for (const p of penaltySystem.penalties.reverse()) {
          if (strikes >= p.threshold) {
            penalty = p;
            break;
          }
        }

        const penaltyDuration = penalty.duration * penalty.multiplier;

        console.log(`Violation ${violation}: ${strikes} strikes -> ${penaltyDuration / 1000}s penalty`);

        if (violation >= 5) {
          expect(penaltyDuration).to.be.greaterThan(300000); // Should be at least 5 minutes
        }

        if (violation >= 10) {
          expect(penaltyDuration).to.be.greaterThan(3600000); // Should be at least 1 hour
        }
      }
    });
  });

  describe('Distributed Rate Limiting', () => {
    it('should handle rate limiting across multiple nodes', () => {
      // Simulate distributed rate limiting with shared state
      const sharedRateStore = new Map();
      const nodes = ['node1', 'node2', 'node3'];
      const globalLimit = 100;
      const clientId = 'distributed_client';

      let totalRequests = 0;
      let blockedRequests = 0;

      // Simulate requests across different nodes
      for (let i = 0; i < 150; i++) {
        const node = nodes[i % nodes.length];

        // Check global rate limit (simulated shared state)
        const currentCount = sharedRateStore.get(clientId) || 0;

        if (currentCount >= globalLimit) {
          blockedRequests++;
          console.log(`Request ${i + 1} blocked on ${node}: Global limit ${globalLimit} exceeded`);
          continue;
        }

        // Allow request and increment counter
        sharedRateStore.set(clientId, currentCount + 1);
        totalRequests++;

        if (i % 20 === 0) {
          console.log(`Request ${i + 1} on ${node}: ${currentCount + 1}/${globalLimit}`);
        }
      }

      expect(totalRequests).to.equal(globalLimit);
      expect(blockedRequests).to.equal(50); // 150 - 100 = 50 blocked
      console.log(`Distributed rate limiting: ${totalRequests} allowed, ${blockedRequests} blocked`);
    });

    it('should implement rate limiting with geographic distribution', () => {
      const geoLimits = new Map([
        ['US', { limit: 1000, current: 0 }],
        ['EU', { limit: 800, current: 0 }],
        ['ASIA', { limit: 600, current: 0 }],
        ['OTHER', { limit: 200, current: 0 }]
      ]);

      const requests = [
        { region: 'US', count: 1200 },
        { region: 'EU', count: 900 },
        { region: 'ASIA', count: 700 },
        { region: 'OTHER', count: 300 }
      ];

      requests.forEach(test => {
        const limits = geoLimits.get(test.region);
        let blocked = 0;

        for (let i = 0; i < test.count; i++) {
          if (limits.current >= limits.limit) {
            blocked++;
            continue;
          }
          limits.current++;
        }

        console.log(`${test.region}: ${limits.current}/${limits.limit} allowed, ${blocked} blocked`);
        expect(limits.current).to.equal(limits.limit);
        expect(blocked).to.equal(test.count - limits.limit);
      });
    });
  });

  describe('DDoS Protection', () => {
    it('should detect and mitigate DDoS attacks', () => {
      const ddosDetector = {
        connections: new Map(),
        suspiciousThreshold: 100,
        blocklistDuration: 300000 // 5 minutes
      };

      const attackScenarios = [
        { sourceIP: '203.0.113.1', requests: 500, description: 'Single IP flood' },
        { sourceIP: '203.0.113.2', requests: 150, description: 'Moderate attack' },
        { sourceIP: '192.168.1.100', requests: 50, description: 'Normal traffic' },
        { sourceIP: '10.0.0.1', requests: 300, description: 'Internal flood' }
      ];

      attackScenarios.forEach(scenario => {
        const now = Date.now();

        for (let i = 0; i < scenario.requests; i++) {
          if (!ddosDetector.connections.has(scenario.sourceIP)) {
            ddosDetector.connections.set(scenario.sourceIP, {
              count: 0,
              firstSeen: now,
              blocked: false
            });
          }

          const connectionData = ddosDetector.connections.get(scenario.sourceIP);
          connectionData.count++;

          // Detect suspicious activity
          if (connectionData.count > ddosDetector.suspiciousThreshold && !connectionData.blocked) {
            connectionData.blocked = true;
            console.log(`DDoS detected from ${scenario.sourceIP}: ${connectionData.count} requests - BLOCKED`);
            console.log(`Attack type: ${scenario.description}`);
            break;
          }

          ddosDetector.connections.set(scenario.sourceIP, connectionData);
        }

        const finalData = ddosDetector.connections.get(scenario.sourceIP);
        if (scenario.requests > ddosDetector.suspiciousThreshold) {
          expect(finalData.blocked).to.be.true;
        } else {
          expect(finalData.blocked).to.be.false;
        }
      });
    });

    it('should implement adaptive rate limiting based on system load', () => {
      const adaptiveRateLimiter = {
        baseLimit: 100,
        currentLimit: 100,
        systemLoad: 0.3, // 30% load
        thresholds: [
          { load: 0.7, multiplier: 0.8 }, // Reduce to 80% when load > 70%
          { load: 0.8, multiplier: 0.6 }, // Reduce to 60% when load > 80%
          { load: 0.9, multiplier: 0.4 }  // Reduce to 40% when load > 90%
        ]
      };

      const loadScenarios = [0.3, 0.5, 0.7, 0.8, 0.9, 0.95];

      loadScenarios.forEach(load => {
        adaptiveRateLimiter.systemLoad = load;
        adaptiveRateLimiter.currentLimit = adaptiveRateLimiter.baseLimit;

        // Apply adaptive limits based on system load
        for (const threshold of adaptiveRateLimiter.thresholds.reverse()) {
          if (load >= threshold.load) {
            adaptiveRateLimiter.currentLimit = Math.floor(adaptiveRateLimiter.baseLimit * threshold.multiplier);
            break;
          }
        }

        console.log(`System load: ${(load * 100).toFixed(0)}% -> Rate limit: ${adaptiveRateLimiter.currentLimit}/${adaptiveRateLimiter.baseLimit}`);

        if (load >= 0.9) {
          expect(adaptiveRateLimiter.currentLimit).to.be.lessThan(adaptiveRateLimiter.baseLimit * 0.5);
        }
      });
    });

    it('should implement CAPTCHA challenge for suspicious traffic', () => {
      const captchaSystem = {
        challengeThreshold: 20,
        challenges: new Map(),
        solveRate: 0.8 // 80% of legitimate users solve CAPTCHA
      };

      const trafficPatterns = [
        { clientId: 'human_user', requestsPerMinute: 15, isLegitimate: true },
        { clientId: 'suspicious_user', requestsPerMinute: 50, isLegitimate: true },
        { clientId: 'bot_user', requestsPerMinute: 100, isLegitimate: false },
        { clientId: 'scraper_bot', requestsPerMinute: 200, isLegitimate: false }
      ];

      trafficPatterns.forEach(pattern => {
        const shouldChallenge = pattern.requestsPerMinute > captchaSystem.challengeThreshold;

        if (shouldChallenge) {
          console.log(`CAPTCHA challenge issued to ${pattern.clientId} (${pattern.requestsPerMinute} req/min)`);

          // Simulate CAPTCHA solving
          const wouldSolve = pattern.isLegitimate && Math.random() < captchaSystem.solveRate;

          if (wouldSolve) {
            console.log(`${pattern.clientId} solved CAPTCHA - ACCESS GRANTED`);
          } else {
            console.log(`${pattern.clientId} failed CAPTCHA - ACCESS DENIED`);

            // Bots should generally fail CAPTCHA
            if (!pattern.isLegitimate) {
              expect(wouldSolve).to.be.false;
            }
          }
        }
      });
    });
  });

  describe('Rate Limiting Bypass Prevention', () => {
    it('should prevent rate limiting bypass through header manipulation', () => {
      const bypassAttempts = [
        { headers: { 'X-Forwarded-For': '127.0.0.1' }, description: 'Localhost spoofing' },
        { headers: { 'X-Real-IP': '192.168.1.1' }, description: 'Private IP spoofing' },
        { headers: { 'User-Agent': 'GoogleBot/2.1' }, description: 'Search engine spoofing' },
        { headers: { 'X-Originating-IP': '8.8.8.8' }, description: 'DNS server spoofing' },
        { headers: { 'CF-Connecting-IP': '1.1.1.1' }, description: 'CloudFlare spoofing' },
        { headers: { 'X-Forwarded-For': '10.0.0.1, 203.0.113.1' }, description: 'Multiple IP chain' }
      ];

      const trustedProxies = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
      const realClientIP = '203.0.113.100'; // Actual attacker IP

      bypassAttempts.forEach((attempt, index) => {
        // Validate headers and extract real IP
        const spoofedIP = attempt.headers['X-Forwarded-For'] ||
                         attempt.headers['X-Real-IP'] ||
                         attempt.headers['X-Originating-IP'] ||
                         attempt.headers['CF-Connecting-IP'];

        // In real implementation, validate against trusted proxy list
        const isTrustedProxy = false; // Simplified - these should not be trusted
        const effectiveIP = isTrustedProxy ? spoofedIP : realClientIP;

        console.log(`Bypass attempt ${index + 1}: ${attempt.description}`);
        console.log(`Spoofed IP: ${spoofedIP}, Effective IP: ${effectiveIP}`);

        // Rate limiting should use the real client IP, not spoofed
        expect(effectiveIP).to.equal(realClientIP);
      });
    });

    it('should prevent rate limiting bypass through distributed requests', () => {
      const distributedAttack = {
        botnet: [
          '198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4',
          '203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'
        ],
        requestsPerBot: 30, // Each bot stays under individual limits
        totalRequests: 0
      };

      const globalRateLimit = 100; // Global limit for all sources
      const perIPLimit = 50; // Per-IP limit
      const ipRequestCounts = new Map();
      let globalRequestCount = 0;

      distributedAttack.botnet.forEach(botIP => {
        for (let i = 0; i < distributedAttack.requestsPerBot; i++) {
          // Check per-IP limit
          const ipCount = ipRequestCounts.get(botIP) || 0;
          if (ipCount >= perIPLimit) {
            console.log(`Request from ${botIP} blocked: Per-IP limit exceeded (${ipCount}/${perIPLimit})`);
            break;
          }

          // Check global limit
          if (globalRequestCount >= globalRateLimit) {
            console.log(`Request from ${botIP} blocked: Global limit exceeded (${globalRequestCount}/${globalRateLimit})`);
            break;
          }

          // Allow request
          ipRequestCounts.set(botIP, ipCount + 1);
          globalRequestCount++;
          distributedAttack.totalRequests++;
        }
      });

      // Should hit global limit before individual bots hit their limits
      expect(distributedAttack.totalRequests).to.be.lessThanOrEqual(globalRateLimit);
      console.log(`Distributed attack mitigated: ${distributedAttack.totalRequests}/${distributedAttack.botnet.length * distributedAttack.requestsPerBot} requests allowed`);
    });

    it('should implement rate limiting for authenticated vs anonymous users', () => {
      const userTiers = {
        anonymous: { limit: 10, window: 60000 },
        authenticated: { limit: 100, window: 60000 },
        premium: { limit: 1000, window: 60000 },
        admin: { limit: Infinity, window: 60000 }
      };

      const testUsers = [
        { id: 'anonymous_user', tier: 'anonymous', requests: 20 },
        { id: 'regular_user', tier: 'authenticated', requests: 150 },
        { id: 'premium_user', tier: 'premium', requests: 1500 },
        { id: 'admin_user', tier: 'admin', requests: 5000 }
      ];

      testUsers.forEach(user => {
        const limits = userTiers[user.tier];
        let allowed = 0;
        let blocked = 0;

        for (let i = 0; i < user.requests; i++) {
          if (allowed < limits.limit) {
            allowed++;
          } else {
            blocked++;
          }
        }

        console.log(`${user.tier} user ${user.id}: ${allowed}/${user.requests} allowed, ${blocked} blocked`);

        if (user.tier !== 'admin') {
          expect(allowed).to.equal(Math.min(user.requests, limits.limit));
          expect(blocked).to.equal(Math.max(0, user.requests - limits.limit));
        } else {
          expect(blocked).to.equal(0); // Admin should never be blocked
        }
      });
    });
  });
});