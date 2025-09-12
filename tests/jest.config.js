// This configuration file is deprecated.
// All Jest configuration has been consolidated to the root jest.config.js
// This file is kept for backward compatibility but should not be used.

const rootConfig = require('../jest.config.js');

console.warn('⚠️  Using deprecated tests/jest.config.js. Please use root jest.config.js instead.');

module.exports = rootConfig;