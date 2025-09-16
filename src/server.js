const express = require('express');
const config = require('./config/environment');
const logger = require('./config/logger');
const { setupMiddleware, setupErrorHandling } = require('./middleware');
const gracefulShutdown = require('./utils/gracefulShutdown');

// Import routes
const healthRoutes = require('./routes/health');
const indexRoutes = require('./routes/index');

/**
 * Create and configure Express application
 */
function createApp() {
  const app = express();

  // Setup middleware
  setupMiddleware(app);

  // Setup routes
  app.use('/health', healthRoutes);
  app.use('/', indexRoutes);

  // Setup error handling (must be last)
  setupErrorHandling(app);

  return app;
}

/**
 * Start the server
 */
async function startServer() {
  try {
    // Create Express app
    const app = createApp();

    // Start HTTP server
    const server = app.listen(config.port, config.host, () => {
      logger.info('Server started successfully', {
        name: config.appName,
        version: config.appVersion,
        environment: config.nodeEnv,
        host: config.host,
        port: config.port,
        pid: process.pid,
        nodeVersion: process.version
      });

      logger.info('Available endpoints:', {
        endpoints: [
          `http://${config.host}:${config.port}/`,
          `http://${config.host}:${config.port}/info`,
          `http://${config.host}:${config.port}/health`,
          `http://${config.host}:${config.port}/health/detailed`
        ]
      });
    });

    // Initialize graceful shutdown
    gracefulShutdown.init(server);

    // Example: Register tmux managers for automatic cleanup
    // Uncomment the lines below if your application uses tmux sessions:
    //
    // const tmuxManager = gracefulShutdown.createTmuxManager(process.cwd(), 'MainTmuxManager');
    // const tmuxStreamManager = gracefulShutdown.createTmuxStreamManager('StreamManager');
    //
    // Or register existing instances:
    // gracefulShutdown.registerTmuxManager(existingTmuxManager, 'ExistingManager');

    // Handle server errors
    server.on('error', (error) => {
      if (error.syscall !== 'listen') {
        throw error;
      }

      const bind = typeof config.port === 'string'
        ? 'Pipe ' + config.port
        : 'Port ' + config.port;

      switch (error.code) {
        case 'EACCES':
          logger.error(`${bind} requires elevated privileges`);
          process.exit(1);
          break;
        case 'EADDRINUSE':
          logger.error(`${bind} is already in use`);
          process.exit(1);
          break;
        default:
          logger.error('Server error occurred', { error: error.message, stack: error.stack });
          throw error;
      }
    });

    return server;
  } catch (error) {
    logger.error('Failed to start server', { error: error.message, stack: error.stack });
    process.exit(1);
  }
}

// Start the server if this file is run directly
if (require.main === module) {
  startServer();
}

module.exports = { createApp, startServer };