/**
 * Bundle Size Analysis and Code Splitting Analyzer
 *
 * Analyzes webpack bundle sizes, code splitting effectiveness,
 * and provides recommendations for optimization.
 */

import { performance } from 'perf_hooks';
import * as fs from 'fs';
import * as path from 'path';

interface BundleAnalysis {
  totalSize: number;
  gzippedSize: number;
  chunks: ChunkAnalysis[];
  dependencies: DependencyAnalysis[];
  treeshaking: TreeshakingAnalysis;
  codeSplitting: CodeSplittingAnalysis;
  recommendations: string[];
}

interface ChunkAnalysis {
  name: string;
  size: number;
  gzippedSize: number;
  type: 'entry' | 'vendor' | 'async' | 'runtime';
  modules: ModuleAnalysis[];
}

interface ModuleAnalysis {
  name: string;
  size: number;
  reasons: string[];
  optimizable: boolean;
}

interface DependencyAnalysis {
  name: string;
  size: number;
  version: string;
  used: boolean;
  alternatives: string[];
}

interface TreeshakingAnalysis {
  effectiveModules: number;
  unusedExports: number;
  savings: number;
}

interface CodeSplittingAnalysis {
  effectiveness: number;
  asyncChunks: number;
  routeBasedSplits: number;
  componentBasedSplits: number;
  recommendations: string[];
}

export class BundleAnalyzer {
  private buildDir: string;
  private packageJsonPath: string;

  constructor(projectRoot: string = '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui') {
    this.buildDir = path.join(projectRoot, '.next');
    this.packageJsonPath = path.join(projectRoot, 'package.json');
  }

  async analyzeBundles(): Promise<BundleAnalysis> {
    console.log('📦 Starting bundle analysis...');

    const analysis: BundleAnalysis = {
      totalSize: 0,
      gzippedSize: 0,
      chunks: [],
      dependencies: [],
      treeshaking: {
        effectiveModules: 0,
        unusedExports: 0,
        savings: 0
      },
      codeSplitting: {
        effectiveness: 0,
        asyncChunks: 0,
        routeBasedSplits: 0,
        componentBasedSplits: 0,
        recommendations: []
      },
      recommendations: []
    };

    try {
      // Analyze build output
      if (fs.existsSync(this.buildDir)) {
        await this.analyzeNextjsBuild(analysis);
      } else {
        console.warn('Build directory not found. Run npm run build first.');
        await this.simulateBundleAnalysis(analysis);
      }

      // Analyze dependencies
      await this.analyzeDependencies(analysis);

      // Generate recommendations
      this.generateRecommendations(analysis);

      console.log(`✅ Bundle analysis complete. Total size: ${this.formatBytes(analysis.totalSize)}`);
      return analysis;

    } catch (error) {
      console.error('❌ Bundle analysis failed:', error);
      throw error;
    }
  }

  private async analyzeNextjsBuild(analysis: BundleAnalysis): Promise<void> {
    const staticDir = path.join(this.buildDir, 'static');

    if (!fs.existsSync(staticDir)) {
      console.warn('Static directory not found in build output');
      return;
    }

    // Find all JS and CSS files
    const files = this.findBundleFiles(staticDir);

    for (const file of files) {
      const stat = fs.statSync(file.path);
      const chunk: ChunkAnalysis = {
        name: file.name,
        size: stat.size,
        gzippedSize: this.estimateGzipSize(stat.size),
        type: this.determineChunkType(file.name),
        modules: []
      };

      // Analyze individual modules if possible
      if (file.ext === '.js') {
        chunk.modules = await this.analyzeJavaScriptModules(file.path);
      }

      analysis.chunks.push(chunk);
      analysis.totalSize += stat.size;
      analysis.gzippedSize += chunk.gzippedSize;
    }

    // Analyze code splitting effectiveness
    analysis.codeSplitting = this.analyzeCodeSplitting(analysis.chunks);
  }

  private findBundleFiles(dir: string): Array<{path: string, name: string, ext: string}> {
    const files: Array<{path: string, name: string, ext: string}> = [];

    const scanDirectory = (currentDir: string) => {
      const items = fs.readdirSync(currentDir);

      for (const item of items) {
        const itemPath = path.join(currentDir, item);
        const stat = fs.statSync(itemPath);

        if (stat.isDirectory()) {
          scanDirectory(itemPath);
        } else {
          const ext = path.extname(item);
          if (ext === '.js' || ext === '.css') {
            files.push({
              path: itemPath,
              name: item,
              ext
            });
          }
        }
      }
    };

    scanDirectory(dir);
    return files;
  }

  private determineChunkType(filename: string): ChunkAnalysis['type'] {
    if (filename.includes('runtime')) return 'runtime';
    if (filename.includes('vendor') || filename.includes('node_modules')) return 'vendor';
    if (filename.includes('pages/') || filename.includes('chunks/')) return 'async';
    return 'entry';
  }

  private async analyzeJavaScriptModules(filePath: string): Promise<ModuleAnalysis[]> {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const modules: ModuleAnalysis[] = [];

      // Simple heuristic analysis of modules
      // In a real implementation, this would parse the webpack module map
      const modulePatterns = [
        { name: 'react', pattern: /react/gi },
        { name: 'react-dom', pattern: /react-dom/gi },
        { name: 'next', pattern: /next/gi },
        { name: '@xterm', pattern: /@xterm/gi },
        { name: 'socket.io', pattern: /socket\.io/gi },
        { name: 'lucide-react', pattern: /lucide-react/gi },
        { name: 'tailwindcss', pattern: /tailwind/gi }
      ];

      for (const pattern of modulePatterns) {
        const matches = content.match(pattern.pattern);
        if (matches && matches.length > 0) {
          modules.push({
            name: pattern.name,
            size: matches.length * 100, // Rough estimation
            reasons: ['imported'],
            optimizable: this.isModuleOptimizable(pattern.name)
          });
        }
      }

      return modules;

    } catch (error) {
      console.warn(`Could not analyze modules in ${filePath}:`, error);
      return [];
    }
  }

  private isModuleOptimizable(moduleName: string): boolean {
    // Modules that are commonly over-imported or have alternatives
    const optimizableModules = ['lodash', 'moment', 'rxjs', 'antd', 'material-ui'];
    return optimizableModules.some(opt => moduleName.includes(opt));
  }

  private analyzeCodeSplitting(chunks: ChunkAnalysis[]): CodeSplittingAnalysis {
    const asyncChunks = chunks.filter(chunk => chunk.type === 'async').length;
    const totalChunks = chunks.length;

    const routeBasedChunks = chunks.filter(chunk =>
      chunk.name.includes('pages/') || chunk.name.includes('route')
    ).length;

    const componentBasedChunks = chunks.filter(chunk =>
      chunk.name.includes('components/') || chunk.name.includes('lazy')
    ).length;

    const effectiveness = totalChunks > 1 ? asyncChunks / totalChunks : 0;

    const recommendations: string[] = [];

    if (effectiveness < 0.3) {
      recommendations.push('Implement more code splitting with React.lazy() and Suspense');
    }

    if (routeBasedChunks === 0) {
      recommendations.push('Consider implementing route-based code splitting');
    }

    if (componentBasedChunks < 3) {
      recommendations.push('Split large components into separate chunks');
    }

    return {
      effectiveness,
      asyncChunks,
      routeBasedSplits: routeBasedChunks,
      componentBasedSplits: componentBasedChunks,
      recommendations
    };
  }

  private async analyzeDependencies(analysis: BundleAnalysis): Promise<void> {
    try {
      if (!fs.existsSync(this.packageJsonPath)) {
        console.warn('package.json not found');
        return;
      }

      const packageJson = JSON.parse(fs.readFileSync(this.packageJsonPath, 'utf8'));
      const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

      const heavyDependencies = [
        { name: 'react', threshold: 50000, alternatives: [] },
        { name: 'react-dom', threshold: 100000, alternatives: [] },
        { name: '@xterm/xterm', threshold: 200000, alternatives: ['term.js', 'hterm'] },
        { name: 'socket.io-client', threshold: 80000, alternatives: ['ws', 'native WebSocket'] },
        { name: 'next', threshold: 300000, alternatives: ['vite + react', 'webpack + react'] },
        { name: 'lucide-react', threshold: 100000, alternatives: ['react-icons', 'heroicons'] }
      ];

      for (const [name, version] of Object.entries(dependencies)) {
        const depInfo = heavyDependencies.find(d => name.startsWith(d.name));

        if (depInfo) {
          analysis.dependencies.push({
            name,
            size: depInfo.threshold, // Estimated size
            version: version as string,
            used: true, // Would need more sophisticated analysis
            alternatives: depInfo.alternatives
          });
        }
      }

      // Sort by size
      analysis.dependencies.sort((a, b) => b.size - a.size);

    } catch (error) {
      console.error('Error analyzing dependencies:', error);
    }
  }

  private async simulateBundleAnalysis(analysis: BundleAnalysis): Promise<void> {
    console.log('📝 Simulating bundle analysis (no build found)...');

    // Simulate typical Next.js bundle structure
    const simulatedChunks: ChunkAnalysis[] = [
      {
        name: 'main.js',
        size: 150000,
        gzippedSize: 45000,
        type: 'entry',
        modules: [
          { name: 'react', size: 40000, reasons: ['entry'], optimizable: false },
          { name: 'next', size: 60000, reasons: ['framework'], optimizable: false },
          { name: 'app', size: 50000, reasons: ['application'], optimizable: true }
        ]
      },
      {
        name: 'vendor.js',
        size: 300000,
        gzippedSize: 90000,
        type: 'vendor',
        modules: [
          { name: '@xterm/xterm', size: 180000, reasons: ['terminal'], optimizable: true },
          { name: 'socket.io-client', size: 80000, reasons: ['websocket'], optimizable: true },
          { name: 'lucide-react', size: 40000, reasons: ['icons'], optimizable: true }
        ]
      },
      {
        name: 'runtime.js',
        size: 25000,
        gzippedSize: 8000,
        type: 'runtime',
        modules: []
      }
    ];

    analysis.chunks = simulatedChunks;
    analysis.totalSize = simulatedChunks.reduce((sum, chunk) => sum + chunk.size, 0);
    analysis.gzippedSize = simulatedChunks.reduce((sum, chunk) => sum + chunk.gzippedSize, 0);
  }

  private estimateGzipSize(originalSize: number): number {
    // Typical gzip compression ratio for JavaScript is ~70%
    return Math.floor(originalSize * 0.3);
  }

  private generateRecommendations(analysis: BundleAnalysis): void {
    const recommendations: string[] = [];

    // Bundle size recommendations
    if (analysis.totalSize > 1000000) { // 1MB
      recommendations.push('Consider reducing bundle size - currently over 1MB');
    }

    // Chunk analysis recommendations
    const entryChunks = analysis.chunks.filter(c => c.type === 'entry');
    const largestEntry = entryChunks.reduce((largest, chunk) =>
      chunk.size > largest.size ? chunk : largest,
      { size: 0 } as any
    );

    if (largestEntry.size > 200000) { // 200KB
      recommendations.push('Entry chunk is too large - consider code splitting');
    }

    // Vendor chunk recommendations
    const vendorChunks = analysis.chunks.filter(c => c.type === 'vendor');
    if (vendorChunks.length === 0) {
      recommendations.push('Consider separating vendor dependencies into a vendor chunk');
    } else if (vendorChunks[0]?.size > 400000) { // 400KB
      recommendations.push('Vendor chunk is large - consider splitting into multiple vendor chunks');
    }

    // Dependency recommendations
    const largeDependencies = analysis.dependencies.filter(d => d.size > 100000);
    for (const dep of largeDependencies) {
      if (dep.alternatives.length > 0) {
        recommendations.push(
          `Consider alternatives to ${dep.name}: ${dep.alternatives.join(', ')}`
        );
      }
    }

    // Code splitting recommendations
    recommendations.push(...analysis.codeSplitting.recommendations);

    // Performance recommendations
    if (analysis.gzippedSize / analysis.totalSize > 0.4) {
      recommendations.push('Poor compression ratio - check for duplicate code or large assets');
    }

    analysis.recommendations = recommendations;
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Generate a detailed bundle report
   */
  generateReport(analysis: BundleAnalysis): string {
    let report = '# Bundle Analysis Report\n\n';

    // Overview
    report += '## Overview\n';
    report += `- **Total Size:** ${this.formatBytes(analysis.totalSize)}\n`;
    report += `- **Gzipped Size:** ${this.formatBytes(analysis.gzippedSize)}\n`;
    report += `- **Compression Ratio:** ${((analysis.gzippedSize / analysis.totalSize) * 100).toFixed(1)}%\n`;
    report += `- **Chunks:** ${analysis.chunks.length}\n\n`;

    // Chunks breakdown
    report += '## Chunks Breakdown\n';
    const sortedChunks = analysis.chunks.sort((a, b) => b.size - a.size);

    for (const chunk of sortedChunks) {
      report += `### ${chunk.name} (${chunk.type})\n`;
      report += `- **Size:** ${this.formatBytes(chunk.size)}\n`;
      report += `- **Gzipped:** ${this.formatBytes(chunk.gzippedSize)}\n`;

      if (chunk.modules.length > 0) {
        report += '- **Top Modules:**\n';
        const topModules = chunk.modules
          .sort((a, b) => b.size - a.size)
          .slice(0, 5);

        for (const module of topModules) {
          const optimizable = module.optimizable ? ' (optimizable)' : '';
          report += `  - ${module.name}: ${this.formatBytes(module.size)}${optimizable}\n`;
        }
      }
      report += '\n';
    }

    // Dependencies
    if (analysis.dependencies.length > 0) {
      report += '## Large Dependencies\n';
      for (const dep of analysis.dependencies.slice(0, 10)) {
        report += `- **${dep.name}:** ${this.formatBytes(dep.size)}`;
        if (dep.alternatives.length > 0) {
          report += ` (alternatives: ${dep.alternatives.join(', ')})`;
        }
        report += '\n';
      }
      report += '\n';
    }

    // Code Splitting Analysis
    report += '## Code Splitting Analysis\n';
    report += `- **Effectiveness:** ${(analysis.codeSplitting.effectiveness * 100).toFixed(1)}%\n`;
    report += `- **Async Chunks:** ${analysis.codeSplitting.asyncChunks}\n`;
    report += `- **Route-based Splits:** ${analysis.codeSplitting.routeBasedSplits}\n`;
    report += `- **Component-based Splits:** ${analysis.codeSplitting.componentBasedSplits}\n\n`;

    // Recommendations
    if (analysis.recommendations.length > 0) {
      report += '## Recommendations\n';
      for (const rec of analysis.recommendations) {
        report += `- ${rec}\n`;
      }
      report += '\n';
    }

    return report;
  }

  /**
   * Save bundle analysis to file
   */
  async saveAnalysis(analysis: BundleAnalysis): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportPath = `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/analysis/bundle-analysis-${timestamp}.json`;

    const fullReport = {
      ...analysis,
      timestamp: Date.now(),
      textReport: this.generateReport(analysis)
    };

    fs.writeFileSync(reportPath, JSON.stringify(fullReport, null, 2));
    console.log(`📄 Bundle analysis saved to: ${reportPath}`);

    return reportPath;
  }
}