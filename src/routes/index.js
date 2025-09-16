const express = require('express');
const logger = require('../config/logger');
const config = require('../config/environment');

const router = express.Router();

/**
 * Main hello world endpoint
 * Returns a welcome message with server information
 */
router.get('/', (req, res) => {
  const welcomeMessage = {
    message: 'Hello, World!',
    application: config.appName,
    version: config.appVersion,
    environment: config.nodeEnv,
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
    server: {
      uptime: process.uptime(),
      platform: process.platform,
      nodeVersion: process.version
    }
  };

  logger.info('Hello world endpoint accessed', {
    requestId: req.requestId,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(200).json(welcomeMessage);
});

/**
 * API information endpoint
 * Returns information about available endpoints
 */
router.get('/info', (req, res) => {
  const apiInfo = {
    name: config.appName,
    version: config.appVersion,
    description: 'Production-ready Node.js hello world server with Express.js',
    endpoints: [
      {
        path: '/',
        method: 'GET',
        description: 'Main hello world endpoint'
      },
      {
        path: '/info',
        method: 'GET',
        description: 'API information endpoint'
      },
      {
        path: '/health',
        method: 'GET',
        description: 'Basic health check endpoint'
      },
      {
        path: '/health/detailed',
        method: 'GET',
        description: 'Detailed health check endpoint'
      }
    ],
    timestamp: new Date().toISOString(),
    requestId: req.requestId
  };

  logger.info('API info endpoint accessed', {
    requestId: req.requestId,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(200).json(apiInfo);
});

module.exports = router;