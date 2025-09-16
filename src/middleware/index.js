const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const requestIdMiddleware = require('./requestId');
const { errorHandler, notFoundHandler } = require('./errorHandler');
const config = require('../config/environment');
const logger = require('../config/logger');

/**
 * Configure and setup all middleware
 */
const setupMiddleware = (app) => {
  // Trust proxy for accurate IP addresses (when behind load balancer/proxy)
  app.set('trust proxy', 1);

  // Request ID middleware (should be first)
  app.use(requestIdMiddleware);

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }));

  // CORS middleware
  app.use(cors({
    origin: config.corsOrigin,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    credentials: true
  }));

  // Compression middleware
  app.use(compression({
    filter: (req, res) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
    threshold: 1024 // Only compress responses larger than 1KB
  }));

  // Rate limiting middleware
  const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    max: config.rateLimitMax,
    message: {
      error: {
        message: 'Too many requests from this IP, please try again later.',
        timestamp: new Date().toISOString()
      }
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.requestId
      });
      res.status(429).json({
        error: {
          message: 'Too many requests from this IP, please try again later.',
          requestId: req.requestId,
          timestamp: new Date().toISOString()
        }
      });
    }
  });
  app.use(limiter);

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logging middleware
  app.use((req, res, next) => {
    const start = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info('HTTP Request', {
        request: {
          id: req.requestId,
          method: req.method,
          url: req.url,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        },
        response: {
          statusCode: res.statusCode,
          duration: `${duration}ms`
        }
      });
    });

    next();
  });

  logger.info('Middleware setup completed');
};

/**
 * Setup error handling middleware (should be called after routes)
 */
const setupErrorHandling = (app) => {
  // 404 handler
  app.use(notFoundHandler);

  // Global error handler
  app.use(errorHandler);

  logger.info('Error handling middleware setup completed');
};

module.exports = {
  setupMiddleware,
  setupErrorHandling
};