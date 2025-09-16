const logger = require('../config/logger');
const config = require('../config/environment');

/**
 * Error handling middleware
 * Logs errors and sends appropriate responses to clients
 */
const errorHandler = (err, req, res, next) => {
  // Log error with request context
  logger.error('Unhandled error occurred', {
    error: {
      message: err.message,
      stack: err.stack,
      name: err.name
    },
    request: {
      id: req.requestId,
      method: req.method,
      url: req.url,
      headers: req.headers,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  });

  // Default error response
  let status = 500;
  let message = 'Internal Server Error';
  let details = null;

  // Handle specific error types
  if (err.name === 'ValidationError') {
    status = 400;
    message = 'Validation Error';
    details = err.message;
  } else if (err.name === 'UnauthorizedError') {
    status = 401;
    message = 'Unauthorized';
  } else if (err.name === 'ForbiddenError') {
    status = 403;
    message = 'Forbidden';
  } else if (err.name === 'NotFoundError') {
    status = 404;
    message = 'Not Found';
  } else if (err.status) {
    status = err.status;
    message = err.message || message;
  }

  // Prepare error response
  const errorResponse = {
    error: {
      message,
      requestId: req.requestId,
      timestamp: new Date().toISOString()
    }
  };

  // Include error details in development mode
  if (config.nodeEnv === 'development') {
    errorResponse.error.details = details || err.message;
    errorResponse.error.stack = err.stack;
  }

  // Send error response
  res.status(status).json(errorResponse);
};

/**
 * 404 Not Found handler
 */
const notFoundHandler = (req, res) => {
  logger.warn('Route not found', {
    request: {
      id: req.requestId,
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  });

  res.status(404).json({
    error: {
      message: 'Route not found',
      requestId: req.requestId,
      timestamp: new Date().toISOString()
    }
  });
};

module.exports = {
  errorHandler,
  notFoundHandler
};