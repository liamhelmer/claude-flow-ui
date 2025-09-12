/** @type {import('next').NextConfig} */
const nextConfig = {
  // Regular build for embedding in CLI package
  // No static export to avoid Html import issues
  
  // Configure for production deployment
  images: {
    unoptimized: true,
  },
  
  webpack: (config) => {
    // Handle node modules for xterm
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      path: false,
      os: false,
    };
    return config;
  },
}

module.exports = nextConfig