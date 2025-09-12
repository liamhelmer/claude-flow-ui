# Static Build Implementation for Claude Flow UI

## Overview

This document describes the implementation of static file serving for the Claude Flow UI npm package, enabling it to work correctly when installed globally without requiring a development environment.

## Problem Statement

The original package failed when globally installed because it relied on Next.js dev server and expected `.next` directory to be present. Global npm packages need to bundle all required assets.

## Solution Architecture

### 1. Next.js Static Export Configuration

**File: `next.config.js`**
- Enabled `output: 'export'` for static file generation
- Disabled image optimization (`images.unoptimized: true`)
- Configured proper asset prefix handling
- Set up static export optimizations

### 2. Enhanced Unified Server

**File: `unified-server.js`**
- **Detection Logic**: Automatically detects if running in static mode by checking for `out/` directory
- **Dual Mode Operation**: 
  - Development: Uses Next.js dev server
  - Production: Serves static files from `out/` directory
- **Static File Serving**: Proper MIME type handling and SPA routing support
- **API Preservation**: All WebSocket and API endpoints remain functional

### 3. Build Process

**Scripts Added:**
- `build:static`: Generates static files for production
- `build:verify`: Comprehensive verification of build output
- `test:integration`: Tests package functionality in production mode

**Package Configuration:**
- Updated `files` array to include `out/` directory
- Modified build hooks to automatically generate static files before packaging
- Preserved all necessary server files (`unified-server.js`, `src/lib/tmux-stream-manager.js`)

## Implementation Details

### Static File Detection

```javascript
const staticOutDir = path.join(__dirname, 'out');
const useStaticFiles = !dev && existsSync(staticOutDir);
```

### Conditional Server Setup

```javascript
if (useStaticFiles) {
  // Serve static files from 'out' directory
  app.use('/', express.static(staticOutDir, { /* options */ }));
  // Handle SPA routing
} else {
  // Use Next.js server
  nextApp = next({ dev });
  handle = nextApp.getRequestHandler();
}
```

### Asset Management

- All CSS, JS, and HTML files are properly bundled in the `out/` directory
- Static assets maintain correct relative paths
- MIME types are properly set for different file types
- SPA routing is preserved for client-side navigation

## Key Features

### ✅ Development Mode
- Uses Next.js dev server with hot reloading
- Full development experience preserved
- Source maps and debugging available

### ✅ Production Mode (Static)
- Serves pre-built static files
- No dependency on Next.js runtime
- Works in global npm installations
- Maintains all WebSocket and API functionality

### ✅ Automatic Detection
- Server automatically detects which mode to use
- No configuration required from users
- Graceful fallback if static files not available

## File Structure After Build

```
claude-flow-ui/
├── unified-server.js              # Main server (handles both modes)
├── out/                          # Static build output
│   ├── index.html               # Main app HTML
│   ├── 404.html                 # Error page
│   └── _next/                   # Next.js assets
│       ├── static/              # Static assets
│       └── [build-id]/          # Versioned assets
├── src/lib/tmux-stream-manager.js # Required server dependencies
└── package.json                  # Updated configuration
```

## Verification Process

### Build Verification Script (`scripts/build-verify.js`)

1. **Build Output Check**: Verifies `out/` directory exists with required files
2. **Server Files Check**: Ensures all server dependencies are present
3. **Package Configuration**: Validates `package.json` settings
4. **Static Mode Test**: Tests server detection logic

### Integration Test (`scripts/test-package-integration.js`)

1. **Production Startup**: Tests server startup in production mode
2. **Static Detection**: Verifies automatic static file detection
3. **Functionality Test**: Ensures WebSocket and API endpoints work

## Usage Instructions

### For Development
```bash
npm run dev          # Next.js development server
npm run server:dev   # Backend server for development
```

### For Production Build
```bash
npm run build:static  # Generate static files
npm run build:verify  # Verify build output
npm run test:integration # Test production functionality
```

### For Package Distribution
```bash
npm run build:static  # Builds static files automatically
npm pack             # Creates package tarball
```

### For Global Installation
```bash
npm install -g @liamhelmer/claude-flow-ui
claude-flow-ui       # Runs in static mode automatically
```

## WebSocket and API Compatibility

All backend functionality is preserved:
- **WebSocket Connections**: `/api/ws` endpoint
- **Terminal API**: `/api/terminal-config` 
- **Health Checks**: `/api/health`
- **Tmux Integration**: Full tmux streaming support
- **File Upload**: All file handling APIs

## Performance Benefits

- **Faster Startup**: No Next.js compilation in production
- **Smaller Memory Footprint**: Static file serving vs full Next.js runtime
- **Better Caching**: Static assets can be cached effectively
- **Global Install Ready**: Works in restricted npm global environments

## Testing

### Automated Tests
- ✅ Build verification passes
- ✅ Integration test passes  
- ✅ Static mode detection works
- ✅ Server startup in production mode
- ✅ WebSocket functionality preserved

### Manual Testing
- ✅ Global installation works
- ✅ Frontend loads correctly
- ✅ Terminal functionality intact
- ✅ API endpoints responsive
- ✅ File serving works properly

## Future Considerations

### Potential Enhancements
1. **Asset Compression**: Gzip compression for static files
2. **CDN Support**: Asset prefix configuration for CDN deployment
3. **Progressive Web App**: Service worker for offline functionality
4. **Build Optimization**: Further size reduction techniques

### Compatibility
- **Node.js**: >=18.0.0 (as specified in package.json)
- **npm**: >=8.0.0
- **Operating Systems**: Cross-platform (Windows, macOS, Linux)
- **Terminal Emulators**: All major terminal emulators supported

## Implementation Status

- [x] Next.js static export configuration
- [x] Server dual-mode operation
- [x] Static file detection logic
- [x] Build process automation
- [x] Package configuration updates
- [x] Verification and testing scripts
- [x] Integration testing
- [x] Documentation

**Status: ✅ COMPLETE**

The Claude Flow UI package now successfully embeds static web content and works correctly when installed globally via npm.