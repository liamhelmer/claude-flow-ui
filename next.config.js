/** @type {import('next').NextConfig} */
const nextConfig = {
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