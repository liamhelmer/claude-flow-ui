/**
 * Utilities Index
 *
 * Central export for all utility modules in claude-flow-ui
 */

// Wait utilities
const wait = require('./wait');
const waitHelpers = require('./waitHelpers');
const WaitManager = require('../lib/enhanced-wait-manager');

// Core utilities
const gracefulShutdown = require('./gracefulShutdown');

module.exports = {
  // Wait utilities
  ...wait,
  ...waitHelpers,
  WaitManager,

  // Core utilities
  gracefulShutdown,

  // Convenience exports
  createWaitManager: (options) => new WaitManager(options)
};