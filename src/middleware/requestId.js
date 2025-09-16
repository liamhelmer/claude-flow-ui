const { v4: uuidv4 } = require('uuid');

/**
 * Middleware to add a unique request ID to each request
 * The request ID is used for tracing and logging purposes
 */
const requestIdMiddleware = (req, res, next) => {
  // Generate a unique request ID
  const requestId = req.headers['x-request-id'] || uuidv4();

  // Add request ID to request object
  req.requestId = requestId;

  // Add request ID to response headers
  res.setHeader('X-Request-ID', requestId);

  // Continue to next middleware
  next();
};

module.exports = requestIdMiddleware;