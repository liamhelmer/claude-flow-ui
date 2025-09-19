/** @type {import('next').NextConfig} */
const nextConfig = {
  // Regular build for embedding in CLI package
  // No static export to avoid Html import issues

  // Configure for production deployment
  images: {
    unoptimized: true,
  },

  // Fix production build issues
  productionBrowserSourceMaps: true, // Enable source maps for debugging

  webpack: (config, { isServer }) => {
    // Handle node modules for xterm
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      path: false,
      os: false,
    };

    // Fix "Cannot read properties of undefined (reading 'call')" error
    if (!isServer) {
      config.optimization = {
        ...config.optimization,
        minimize: true,
        minimizer: config.optimization.minimizer ?
          config.optimization.minimizer.filter(minimizer => {
            // Keep only safe minimizers
            return !minimizer.constructor.name.includes('Terser');
          }) : [],
      };
    }

    return config;
  },
}

module.exports = nextConfig