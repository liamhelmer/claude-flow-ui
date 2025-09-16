const express = require('express');
const logger = require('../config/logger');
const config = require('../config/environment');

const router = express.Router();

/**
 * Health check endpoint
 * Returns the current status of the application
 */
router.get('/', async (req, res) => {
  try {
    const healthCheck = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.nodeEnv,
      version: config.appVersion,
      requestId: req.requestId,
      checks: {
        memory: getMemoryUsage(),
        cpu: getCpuUsage()
      }
    };

    logger.info('Health check performed', {
      requestId: req.requestId,
      healthCheck
    });

    res.status(200).json(healthCheck);
  } catch (error) {
    logger.error('Health check failed', {
      error: error.message,
      requestId: req.requestId
    });

    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      error: 'Health check failed'
    });
  }
});

/**
 * Detailed health check endpoint
 * Returns more detailed information about the application
 */
router.get('/detailed', async (req, res) => {
  try {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    const detailedHealthCheck = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.nodeEnv,
      version: config.appVersion,
      requestId: req.requestId,
      system: {
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        pid: process.pid
      },
      memory: {
        rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
        external: `${Math.round(memoryUsage.external / 1024 / 1024)}MB`
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system
      }
    };

    logger.info('Detailed health check performed', {
      requestId: req.requestId,
      detailedHealthCheck
    });

    res.status(200).json(detailedHealthCheck);
  } catch (error) {
    logger.error('Detailed health check failed', {
      error: error.message,
      requestId: req.requestId
    });

    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      error: 'Detailed health check failed'
    });
  }
});

/**
 * Get memory usage information
 */
function getMemoryUsage() {
  const memoryUsage = process.memoryUsage();
  return {
    heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
    heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
    rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`
  };
}

/**
 * Get CPU usage information
 */
function getCpuUsage() {
  const cpuUsage = process.cpuUsage();
  return {
    user: cpuUsage.user,
    system: cpuUsage.system
  };
}

module.exports = router;