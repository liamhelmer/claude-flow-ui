#!/usr/bin/env node

/**
 * Platform Compatibility Checker for Claude Flow UI
 * Handles platform-specific tmux and terminal compatibility issues
 */

const os = require('os');
const { spawn } = require('child_process');
const fs = require('fs');

class PlatformCompatibility {
  constructor() {
    this.platform = os.platform();
    this.arch = os.arch();
    this.version = os.version();
    this.nodeVersion = process.version;
  }

  /**
   * Get platform-specific information
   */
  getPlatformInfo() {
    return {
      platform: this.platform,
      arch: this.arch,
      version: this.version,
      nodeVersion: this.nodeVersion,
      isMac: this.platform === 'darwin',
      isLinux: this.platform === 'linux',
      isWindows: this.platform === 'win32',
      tmuxCompatible: this.isTmuxCompatible()
    };
  }

  /**
   * Check if tmux is compatible with this platform
   */
  isTmuxCompatible() {
    // Tmux is not natively available on Windows
    if (this.platform === 'win32') {
      return false;
    }
    return true;
  }

  /**
   * Check tmux version and capabilities
   */
  async checkTmuxVersion() {
    if (!this.isTmuxCompatible()) {
      return { available: false, reason: 'Platform not supported' };
    }

    return new Promise((resolve) => {
      const tmux = spawn('tmux', ['-V'], { stdio: 'pipe' });
      let output = '';
      let errorOutput = '';

      tmux.stdout.on('data', (data) => {
        output += data.toString();
      });

      tmux.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      tmux.on('exit', (code) => {
        if (code === 0) {
          const versionMatch = output.match(/tmux (\d+\.\d+)/);
          const version = versionMatch ? versionMatch[1] : 'unknown';
          const versionNumber = parseFloat(version);
          
          resolve({
            available: true,
            version: version,
            versionNumber: versionNumber,
            supportsCapturePaneHistory: versionNumber >= 1.8,
            supportsColorEscapes: versionNumber >= 2.0,
            raw: output.trim()
          });
        } else {
          resolve({
            available: false,
            reason: 'Not installed or not accessible',
            error: errorOutput || 'Unknown error'
          });
        }
      });

      tmux.on('error', (err) => {
        resolve({
          available: false,
          reason: 'Not installed',
          error: err.message
        });
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        tmux.kill('SIGKILL');
        resolve({
          available: false,
          reason: 'Version check timed out',
          error: 'Timeout'
        });
      }, 5000);
    });
  }

  /**
   * Get platform-specific tmux command adjustments
   */
  getTmuxCommandAdjustments() {
    const adjustments = {
      socketPathPrefix: '/tmp/.claude-flow-sockets',
      maxSocketPathLength: 100, // Default safe length
      useShortSessionNames: false,
      captureTimeout: 5000,
      fallbackStrategies: ['basic-capture', 'limited-history', 'current-screen']
    };

    // macOS specific adjustments
    if (this.platform === 'darwin') {
      // macOS has stricter socket path length limits
      adjustments.maxSocketPathLength = 80;
      adjustments.useShortSessionNames = true;
      adjustments.socketPathPrefix = '/tmp/.cf-sockets';
    }

    // Linux specific adjustments
    if (this.platform === 'linux') {
      // Linux generally more permissive but check for snap/flatpak restrictions
      adjustments.maxSocketPathLength = 108; // Unix domain socket path limit
      adjustments.captureTimeout = 3000; // Faster timeout for better responsiveness
    }

    return adjustments;
  }

  /**
   * Validate socket directory accessibility
   */
  async validateSocketDirectory(socketDir) {
    try {
      // Check if directory exists
      if (!fs.existsSync(socketDir)) {
        fs.mkdirSync(socketDir, { recursive: true, mode: 0o755 });
      }

      // Check write permissions
      const testFile = `${socketDir}/.write-test-${Date.now()}`;
      fs.writeFileSync(testFile, 'test', { mode: 0o644 });
      fs.unlinkSync(testFile);

      // Check socket path length
      const testSocketPath = `${socketDir}/test-session-${Date.now()}.sock`;
      const adjustments = this.getTmuxCommandAdjustments();
      
      if (testSocketPath.length > adjustments.maxSocketPathLength) {
        return {
          valid: false,
          reason: `Socket path too long (${testSocketPath.length} > ${adjustments.maxSocketPathLength})`,
          suggestion: 'Use shorter socket directory path or session names'
        };
      }

      return {
        valid: true,
        socketDir: socketDir,
        maxPathLength: adjustments.maxSocketPathLength
      };

    } catch (error) {
      return {
        valid: false,
        reason: `Socket directory validation failed: ${error.message}`,
        suggestion: 'Check directory permissions and disk space'
      };
    }
  }

  /**
   * Get recommended tmux capture strategy for this platform
   */
  getRecommendedCaptureStrategy() {
    const strategies = [];

    // Base strategy that works on all platforms
    strategies.push({
      name: 'standard-capture',
      args: ['-S', '{socketPath}', 'capture-pane', '-t', '{sessionName}', '-S', '-', '-E', '-', '-e', '-p'],
      timeout: 5000,
      description: 'Standard full history capture'
    });

    // Platform-specific optimizations
    if (this.platform === 'darwin') {
      // macOS sometimes has issues with full history capture
      strategies.unshift({
        name: 'macos-optimized',
        args: ['-S', '{socketPath}', 'capture-pane', '-t', '{sessionName}', '-S', '-50', '-e', '-p'],
        timeout: 3000,
        description: 'macOS optimized capture with limited history'
      });
    }

    if (this.platform === 'linux') {
      // Linux can handle more aggressive capturing
      strategies.unshift({
        name: 'linux-optimized',
        args: ['-S', '{socketPath}', 'capture-pane', '-t', '{sessionName}', '-S', '-', '-E', '-', '-e', '-p'],
        timeout: 3000,
        description: 'Linux optimized full capture'
      });
    }

    // Fallback strategies
    strategies.push(
      {
        name: 'basic-fallback',
        args: ['-S', '{socketPath}', 'capture-pane', '-t', '{sessionName}', '-p'],
        timeout: 2000,
        description: 'Basic capture without escape sequences'
      },
      {
        name: 'minimal-fallback',
        args: ['-S', '{socketPath}', 'list-windows', '-t', '{sessionName}'],
        timeout: 1000,
        description: 'Minimal fallback showing session info'
      }
    );

    return strategies;
  }

  /**
   * Generate a comprehensive compatibility report
   */
  async generateCompatibilityReport() {
    const platformInfo = this.getPlatformInfo();
    const tmuxInfo = await this.checkTmuxVersion();
    const adjustments = this.getTmuxCommandAdjustments();
    const strategies = this.getRecommendedCaptureStrategy();
    
    const socketValidation = await this.validateSocketDirectory(adjustments.socketPathPrefix);

    return {
      timestamp: new Date().toISOString(),
      platform: platformInfo,
      tmux: tmuxInfo,
      compatibility: {
        tmuxSupported: tmuxInfo.available,
        socketDirectoryValid: socketValidation.valid,
        recommendedStrategies: strategies.map(s => s.name),
        issues: this.getKnownIssues(),
        recommendations: this.getRecommendations()
      },
      adjustments: adjustments,
      socketValidation: socketValidation,
      strategies: strategies
    };
  }

  /**
   * Get known platform-specific issues
   */
  getKnownIssues() {
    const issues = [];

    if (this.platform === 'darwin') {
      issues.push({
        severity: 'medium',
        description: 'macOS has strict socket path length limits',
        workaround: 'Use shorter session names and socket paths'
      });
      
      if (this.version.includes('arm64')) {
        issues.push({
          severity: 'low',
          description: 'Apple Silicon may have different tmux behavior',
          workaround: 'Use Rosetta compatibility if issues persist'
        });
      }
    }

    if (this.platform === 'linux') {
      issues.push({
        severity: 'low',
        description: 'Some Linux distributions may have restricted /tmp access',
        workaround: 'Use user-specific socket directory if needed'
      });
    }

    if (this.platform === 'win32') {
      issues.push({
        severity: 'high',
        description: 'Windows does not natively support tmux',
        workaround: 'Use WSL2 or alternative terminal solutions'
      });
    }

    return issues;
  }

  /**
   * Get platform-specific recommendations
   */
  getRecommendations() {
    const recommendations = [];

    if (this.platform === 'darwin') {
      recommendations.push(
        'Install tmux via Homebrew for best compatibility',
        'Use short session names to avoid socket path issues',
        'Consider using iTerm2 for enhanced terminal features'
      );
    }

    if (this.platform === 'linux') {
      recommendations.push(
        'Ensure tmux is installed via package manager',
        'Check systemd user session limits if experiencing issues',
        'Use modern terminal emulators for better color support'
      );
    }

    if (this.platform === 'win32') {
      recommendations.push(
        'Use Windows Subsystem for Linux (WSL2) for tmux support',
        'Consider Windows Terminal for better terminal experience',
        'Alternative: Use PowerShell or Command Prompt without tmux'
      );
    }

    return recommendations;
  }
}

module.exports = PlatformCompatibility;