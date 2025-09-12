# Quality Metrics Framework

## Overview
This document defines a comprehensive quality metrics framework for the Claude UI project, establishing measurable standards for code quality, testing effectiveness, and overall project health.

## Quality Metrics Categories

### 1. Code Coverage Metrics

#### Coverage Thresholds
```javascript
// jest.config.js - Enhanced coverage configuration
coverageThreshold: {
  global: {
    branches: 85,      // ⬆️ Target: 85% branch coverage
    functions: 90,     // ⬆️ Target: 90% function coverage  
    lines: 90,         // ⬆️ Target: 90% line coverage
    statements: 90,    // ⬆️ Target: 90% statement coverage
  },
  
  // Component-specific thresholds
  'src/components/': {
    branches: 90,
    functions: 95,
    lines: 95,
    statements: 95,
  },
  
  'src/hooks/': {
    branches: 95,
    functions: 100,
    lines: 100,
    statements: 100,
  },
  
  'src/lib/': {
    branches: 90,
    functions: 95,
    lines: 95,
    statements: 95,
  },
  
  // Lower thresholds for integration files
  'src/pages/': {
    branches: 70,
    functions: 80,
    lines: 80,
    statements: 80,
  },
}
```

#### Coverage Quality Indicators
- **Excellent (90%+)**: Comprehensive test coverage
- **Good (80-89%)**: Adequate coverage with minor gaps
- **Fair (70-79%)**: Acceptable coverage, improvement needed
- **Poor (<70%)**: Insufficient coverage, immediate attention required

#### Coverage Reporting Script
```bash
#!/bin/bash
# scripts/coverage-report.sh

echo "🧪 Running comprehensive coverage analysis..."

# Generate coverage report
npm run test:coverage

# Generate detailed HTML report
npm run test:coverage -- --coverageReporters=html

# Extract coverage percentages
COVERAGE_LINES=$(grep -o 'Lines.*: [0-9.]*%' coverage/lcov-report/index.html | head -1 | grep -o '[0-9.]*')
COVERAGE_FUNCTIONS=$(grep -o 'Functions.*: [0-9.]*%' coverage/lcov-report/index.html | head -1 | grep -o '[0-9.]*')
COVERAGE_BRANCHES=$(grep -o 'Branches.*: [0-9.]*%' coverage/lcov-report/index.html | head -1 | grep -o '[0-9.]*')

echo "📊 Coverage Summary:"
echo "Lines: ${COVERAGE_LINES}%"
echo "Functions: ${COVERAGE_FUNCTIONS}%"
echo "Branches: ${COVERAGE_BRANCHES}%"

# Check if coverage meets thresholds
if (( $(echo "$COVERAGE_LINES >= 90" | bc -l) )); then
  echo "✅ Line coverage meets target"
else
  echo "❌ Line coverage below target (90%)"
fi

if (( $(echo "$COVERAGE_FUNCTIONS >= 90" | bc -l) )); then
  echo "✅ Function coverage meets target"
else
  echo "❌ Function coverage below target (90%)"
fi

if (( $(echo "$COVERAGE_BRANCHES >= 85" | bc -l) )); then
  echo "✅ Branch coverage meets target"
else
  echo "❌ Branch coverage below target (85%)"
fi
```

### 2. Test Quality Metrics

#### Test Suite Health Indicators
```typescript
// tests/utils/testMetrics.ts
export interface TestSuiteMetrics {
  totalTests: number;
  passingTests: number;
  failingTests: number;
  skippedTests: number;
  flakyTests: number;
  averageTestDuration: number;
  slowestTests: Array<{ name: string; duration: number }>;
  testDistribution: {
    unit: number;
    integration: number;
    e2e: number;
  };
  coverageGaps: Array<{
    file: string;
    uncoveredLines: number[];
    coveragePercentage: number;
  }>;
}

export const calculateTestMetrics = (testResults: any): TestSuiteMetrics => {
  const totalTests = testResults.numTotalTests;
  const passingTests = testResults.numPassedTests;
  const failingTests = testResults.numFailedTests;
  const skippedTests = testResults.numPendingTests;
  
  // Calculate average test duration
  const testDurations = testResults.testResults
    .flatMap((result: any) => result.perfStats?.duration || 0);
  const averageTestDuration = testDurations.reduce((a: number, b: number) => a + b, 0) / testDurations.length;
  
  // Identify slowest tests (>1 second)
  const slowestTests = testResults.testResults
    .filter((result: any) => (result.perfStats?.duration || 0) > 1000)
    .map((result: any) => ({
      name: result.testFilePath,
      duration: result.perfStats?.duration,
    }))
    .sort((a: any, b: any) => b.duration - a.duration)
    .slice(0, 10);
  
  // Categorize tests by type
  const testDistribution = {
    unit: testResults.testResults.filter((r: any) => r.testFilePath.includes('__tests__')).length,
    integration: testResults.testResults.filter((r: any) => r.testFilePath.includes('integration')).length,
    e2e: testResults.testResults.filter((r: any) => r.testFilePath.includes('e2e')).length,
  };
  
  return {
    totalTests,
    passingTests,
    failingTests,
    skippedTests,
    flakyTests: 0, // To be calculated from historical data
    averageTestDuration,
    slowestTests,
    testDistribution,
    coverageGaps: [], // To be populated from coverage reports
  };
};
```

#### Test Performance Benchmarks
```typescript
// tests/utils/performanceBenchmarks.ts
export const PERFORMANCE_BENCHMARKS = {
  testExecution: {
    unit: {
      max: 50,      // Unit tests should complete in <50ms
      target: 25,   // Target: <25ms
    },
    integration: {
      max: 500,     // Integration tests should complete in <500ms
      target: 200,  // Target: <200ms
    },
    e2e: {
      max: 5000,    // E2E tests should complete in <5s
      target: 2000, // Target: <2s
    },
  },
  
  suiteExecution: {
    total: {
      max: 300000,  // Total suite should complete in <5 minutes
      target: 120000, // Target: <2 minutes
    },
    parallel: {
      workers: '50%', // Use 50% of available CPU cores
      maxWorkers: 8,  // Maximum 8 parallel workers
    },
  },
  
  memoryUsage: {
    maxHeapSize: 512 * 1024 * 1024, // 512MB max heap
    leakThreshold: 50 * 1024 * 1024, // 50MB memory leak threshold
  },
};

export const validateTestPerformance = (metrics: TestSuiteMetrics): boolean => {
  const issues = [];
  
  // Check average test duration
  if (metrics.averageTestDuration > PERFORMANCE_BENCHMARKS.testExecution.unit.max) {
    issues.push(`Average test duration (${metrics.averageTestDuration}ms) exceeds maximum (${PERFORMANCE_BENCHMARKS.testExecution.unit.max}ms)`);
  }
  
  // Check for slow tests
  if (metrics.slowestTests.length > 0) {
    issues.push(`Found ${metrics.slowestTests.length} slow tests`);
  }
  
  // Check test distribution
  const totalTests = metrics.totalTests;
  const unitPercentage = (metrics.testDistribution.unit / totalTests) * 100;
  
  if (unitPercentage < 70) {
    issues.push(`Unit test percentage (${unitPercentage.toFixed(1)}%) below target (70%)`);
  }
  
  if (issues.length > 0) {
    console.warn('⚠️  Test Performance Issues:');
    issues.forEach(issue => console.warn(`   - ${issue}`));
    return false;
  }
  
  return true;
};
```

### 3. Code Quality Metrics

#### Complexity Analysis
```typescript
// scripts/complexity-analysis.ts
export interface ComplexityMetrics {
  cyclomaticComplexity: number;
  linesOfCode: number;
  maintainabilityIndex: number;
  codeSmells: CodeSmell[];
  duplication: DuplicationReport;
  dependencies: DependencyAnalysis;
}

export interface CodeSmell {
  type: 'long-method' | 'large-class' | 'duplicate-code' | 'dead-code' | 'complex-conditional';
  file: string;
  line: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  suggestion: string;
}

export const analyzeCodeComplexity = async (filePath: string): Promise<ComplexityMetrics> => {
  const sourceCode = await fs.readFile(filePath, 'utf-8');
  const ast = parse(sourceCode, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
  
  let cyclomaticComplexity = 1; // Base complexity
  let linesOfCode = sourceCode.split('\n').length;
  const codeSmells: CodeSmell[] = [];
  
  // Traverse AST to calculate complexity
  traverse(ast, {
    // Control flow statements increase complexity
    IfStatement: () => cyclomaticComplexity++,
    SwitchCase: () => cyclomaticComplexity++,
    WhileStatement: () => cyclomaticComplexity++,
    ForStatement: () => cyclomaticComplexity++,
    ConditionalExpression: () => cyclomaticComplexity++,
    LogicalExpression: (path) => {
      if (path.node.operator === '&&' || path.node.operator === '||') {
        cyclomaticComplexity++;
      }
    },
    
    // Detect code smells
    FunctionDeclaration: (path) => {
      const functionLines = path.node.loc?.end.line! - path.node.loc?.start.line!;
      if (functionLines > 50) {
        codeSmells.push({
          type: 'long-method',
          file: filePath,
          line: path.node.loc?.start.line || 0,
          severity: functionLines > 100 ? 'critical' : 'high',
          description: `Function has ${functionLines} lines (limit: 50)`,
          suggestion: 'Consider breaking this function into smaller, more focused functions',
        });
      }
    },
    
    ClassDeclaration: (path) => {
      // Count methods and properties
      const members = path.node.body.body.length;
      if (members > 20) {
        codeSmells.push({
          type: 'large-class',
          file: filePath,
          line: path.node.loc?.start.line || 0,
          severity: members > 30 ? 'critical' : 'high',
          description: `Class has ${members} members (limit: 20)`,
          suggestion: 'Consider splitting this class into smaller, more cohesive classes',
        });
      }
    },
  });
  
  // Calculate maintainability index (simplified)
  const maintainabilityIndex = Math.max(
    0,
    (171 - 5.2 * Math.log(linesOfCode) - 0.23 * cyclomaticComplexity - 16.2 * Math.log(linesOfCode)) * 100 / 171
  );
  
  return {
    cyclomaticComplexity,
    linesOfCode,
    maintainabilityIndex,
    codeSmells,
    duplication: await analyzeDuplication(filePath),
    dependencies: await analyzeDependencies(filePath),
  };
};

export const CODE_QUALITY_THRESHOLDS = {
  cyclomaticComplexity: {
    excellent: 5,
    good: 10,
    fair: 15,
    poor: 20,
  },
  maintainabilityIndex: {
    excellent: 85,
    good: 70,
    fair: 50,
    poor: 25,
  },
  linesOfCode: {
    function: 50,
    class: 500,
    file: 1000,
  },
};
```

#### Dependency Analysis
```typescript
// scripts/dependency-analysis.ts
export interface DependencyAnalysis {
  totalDependencies: number;
  outdatedDependencies: OutdatedDependency[];
  vulnerabilities: SecurityVulnerability[];
  bundleSize: BundleSizeReport;
  circularDependencies: CircularDependency[];
}

export interface OutdatedDependency {
  name: string;
  current: string;
  latest: string;
  severity: 'patch' | 'minor' | 'major';
  updatePath: string;
}

export const analyzeDependencies = async (): Promise<DependencyAnalysis> => {
  const packageJson = JSON.parse(await fs.readFile('package.json', 'utf-8'));
  const dependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };
  
  // Check for outdated dependencies
  const outdatedCheck = await exec('npm outdated --json').catch(() => ({ stdout: '{}' }));
  const outdatedData = JSON.parse(outdatedCheck.stdout || '{}');
  
  const outdatedDependencies: OutdatedDependency[] = Object.entries(outdatedData).map(
    ([name, info]: [string, any]) => ({
      name,
      current: info.current,
      latest: info.latest,
      severity: determineSeverity(info.current, info.latest),
      updatePath: `npm install ${name}@${info.latest}`,
    })
  );
  
  // Check for security vulnerabilities
  const auditResult = await exec('npm audit --json').catch(() => ({ stdout: '{}' }));
  const auditData = JSON.parse(auditResult.stdout || '{}');
  
  const vulnerabilities: SecurityVulnerability[] = Object.values(auditData.vulnerabilities || {}).map(
    (vuln: any) => ({
      name: vuln.name,
      severity: vuln.severity,
      description: vuln.via?.[0]?.title || 'Unknown vulnerability',
      fixPath: vuln.fixAvailable ? `npm audit fix` : 'Manual fix required',
    })
  );
  
  return {
    totalDependencies: Object.keys(dependencies).length,
    outdatedDependencies,
    vulnerabilities,
    bundleSize: await analyzeBundleSize(),
    circularDependencies: await detectCircularDependencies(),
  };
};
```

### 4. Performance Metrics

#### Runtime Performance Tracking
```typescript
// tests/utils/performanceTracker.ts
export interface PerformanceMetrics {
  renderTime: number;
  firstContentfulPaint: number;
  timeToInteractive: number;
  memoryUsage: MemoryUsage;
  bundleSize: BundleSize;
  networkRequests: NetworkMetrics;
}

export class PerformanceTracker {
  private metrics: Map<string, number[]> = new Map();
  
  startMeasurement(name: string): void {
    performance.mark(`${name}-start`);
  }
  
  endMeasurement(name: string): number {
    performance.mark(`${name}-end`);
    performance.measure(name, `${name}-start`, `${name}-end`);
    
    const measure = performance.getEntriesByName(name)[0];
    const duration = measure.duration;
    
    // Store measurement
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    this.metrics.get(name)!.push(duration);
    
    return duration;
  }
  
  getAverageTime(name: string): number {
    const measurements = this.metrics.get(name) || [];
    return measurements.reduce((sum, time) => sum + time, 0) / measurements.length;
  }
  
  getPerformanceReport(): PerformanceReport {
    const report: PerformanceReport = {
      measurements: {},
      summary: {
        totalMeasurements: 0,
        averageTime: 0,
        slowestOperation: '',
        fastestOperation: '',
      },
    };
    
    this.metrics.forEach((times, name) => {
      const average = this.getAverageTime(name);
      report.measurements[name] = {
        count: times.length,
        average,
        min: Math.min(...times),
        max: Math.max(...times),
        total: times.reduce((sum, time) => sum + time, 0),
      };
      
      report.summary.totalMeasurements += times.length;
    });
    
    // Calculate overall statistics
    const averages = Object.values(report.measurements).map(m => m.average);
    report.summary.averageTime = averages.reduce((sum, avg) => sum + avg, 0) / averages.length;
    
    const sortedByAverage = Object.entries(report.measurements)
      .sort(([, a], [, b]) => b.average - a.average);
    
    report.summary.slowestOperation = sortedByAverage[0]?.[0] || '';
    report.summary.fastestOperation = sortedByAverage[sortedByAverage.length - 1]?.[0] || '';
    
    return report;
  }
}

// Global performance tracker instance
export const performanceTracker = new PerformanceTracker();
```

#### Component Performance Benchmarks
```typescript
// tests/performance/componentBenchmarks.test.ts
import { performanceTracker } from '../utils/performanceTracker';

describe('Component Performance Benchmarks', () => {
  const PERFORMANCE_BUDGETS = {
    componentRender: 16, // 16ms for 60fps
    stateUpdate: 5,      // 5ms for state updates
    initialMount: 100,   // 100ms for initial mount
    dataLoading: 200,    // 200ms for data loading
  };
  
  it('should render Terminal component within performance budget', () => {
    performanceTracker.startMeasurement('terminal-render');
    
    renderWithProviders(<Terminal sessionId="test" />);
    
    const renderTime = performanceTracker.endMeasurement('terminal-render');
    expect(renderTime).toBeLessThan(PERFORMANCE_BUDGETS.componentRender);
  });
  
  it('should handle state updates efficiently', async () => {
    const { result } = renderHook(() => useTerminal());
    
    performanceTracker.startMeasurement('state-update');
    
    act(() => {
      result.current.createSession('test-session');
    });
    
    const updateTime = performanceTracker.endMeasurement('state-update');
    expect(updateTime).toBeLessThan(PERFORMANCE_BUDGETS.stateUpdate);
  });
  
  it('should load large datasets efficiently', async () => {
    const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
      id: i,
      data: `Item ${i}`,
    }));
    
    performanceTracker.startMeasurement('large-dataset-render');
    
    renderWithProviders(<DataTable data={largeDataset} />);
    
    const renderTime = performanceTracker.endMeasurement('large-dataset-render');
    expect(renderTime).toBeLessThan(PERFORMANCE_BUDGETS.dataLoading);
  });
});
```

### 5. User Experience Metrics

#### Accessibility Metrics
```typescript
// tests/utils/accessibilityMetrics.ts
export interface AccessibilityMetrics {
  violations: AxeViolation[];
  wcagLevel: 'A' | 'AA' | 'AAA';
  keyboardNavigation: KeyboardNavigationTest[];
  screenReaderSupport: ScreenReaderTest[];
  colorContrast: ColorContrastReport;
}

export const generateAccessibilityReport = async (
  component: React.ReactElement
): Promise<AccessibilityMetrics> => {
  const { container } = renderWithProviders(component);
  
  // Run axe-core accessibility tests
  const axeResults = await axe(container);
  const violations = axeResults.violations;
  
  // Determine WCAG compliance level
  const wcagLevel = determineWcagLevel(violations);
  
  // Test keyboard navigation
  const keyboardNavigation = await testKeyboardNavigation(container);
  
  // Test screen reader support
  const screenReaderSupport = testScreenReaderSupport(container);
  
  // Test color contrast
  const colorContrast = analyzeColorContrast(container);
  
  return {
    violations,
    wcagLevel,
    keyboardNavigation,
    screenReaderSupport,
    colorContrast,
  };
};

const ACCESSIBILITY_THRESHOLDS = {
  maxViolations: {
    critical: 0,
    serious: 2,
    moderate: 5,
    minor: 10,
  },
  minColorContrast: {
    normal: 4.5,
    large: 3.0,
  },
  keyboardNavigation: {
    minTabStops: 3,
    maxTabTime: 500, // ms
  },
};
```

#### User Journey Metrics
```typescript
// tests/e2e/userJourneyMetrics.ts
export interface UserJourneyMetrics {
  taskCompletionRate: number;
  averageTaskTime: number;
  errorRate: number;
  userSatisfactionScore: number;
  criticalPathPerformance: CriticalPathMetric[];
}

export const measureUserJourney = async (
  journey: UserJourneyStep[]
): Promise<UserJourneyMetrics> => {
  const startTime = performance.now();
  let errorCount = 0;
  let completedSteps = 0;
  
  const criticalPathPerformance: CriticalPathMetric[] = [];
  
  for (const step of journey) {
    const stepStartTime = performance.now();
    
    try {
      await executeStep(step);
      completedSteps++;
      
      const stepDuration = performance.now() - stepStartTime;
      criticalPathPerformance.push({
        stepName: step.name,
        duration: stepDuration,
        success: true,
      });
    } catch (error) {
      errorCount++;
      criticalPathPerformance.push({
        stepName: step.name,
        duration: performance.now() - stepStartTime,
        success: false,
        error: error.message,
      });
    }
  }
  
  const totalTime = performance.now() - startTime;
  const taskCompletionRate = (completedSteps / journey.length) * 100;
  const errorRate = (errorCount / journey.length) * 100;
  
  return {
    taskCompletionRate,
    averageTaskTime: totalTime / journey.length,
    errorRate,
    userSatisfactionScore: calculateSatisfactionScore(taskCompletionRate, errorRate),
    criticalPathPerformance,
  };
};
```

### 6. Continuous Monitoring

#### Metrics Dashboard
```typescript
// scripts/metrics-dashboard.ts
export class MetricsDashboard {
  private metrics: Map<string, MetricValue[]> = new Map();
  
  async generateDashboard(): Promise<DashboardReport> {
    const testMetrics = await this.collectTestMetrics();
    const codeQualityMetrics = await this.collectCodeQualityMetrics();
    const performanceMetrics = await this.collectPerformanceMetrics();
    const accessibilityMetrics = await this.collectAccessibilityMetrics();
    
    return {
      timestamp: new Date().toISOString(),
      summary: this.generateSummary(),
      testSuite: testMetrics,
      codeQuality: codeQualityMetrics,
      performance: performanceMetrics,
      accessibility: accessibilityMetrics,
      trends: this.calculateTrends(),
      recommendations: this.generateRecommendations(),
    };
  }
  
  private async collectTestMetrics(): Promise<TestSuiteMetrics> {
    const testResults = await runTests();
    return calculateTestMetrics(testResults);
  }
  
  private async collectCodeQualityMetrics(): Promise<CodeQualityReport> {
    const sourceFiles = await glob('src/**/*.{ts,tsx}');
    const complexityReports = await Promise.all(
      sourceFiles.map(file => analyzeCodeComplexity(file))
    );
    
    return aggregateComplexityReports(complexityReports);
  }
  
  private generateRecommendations(): Recommendation[] {
    const recommendations: Recommendation[] = [];
    
    // Analyze trends and current metrics to generate actionable recommendations
    const currentMetrics = this.getCurrentMetrics();
    
    if (currentMetrics.testCoverage < 85) {
      recommendations.push({
        priority: 'high',
        category: 'testing',
        title: 'Improve Test Coverage',
        description: `Current coverage is ${currentMetrics.testCoverage}%. Target is 85%+`,
        actionItems: [
          'Add unit tests for uncovered functions',
          'Implement integration tests for critical paths',
          'Review and update existing tests',
        ],
      });
    }
    
    if (currentMetrics.averageComplexity > 10) {
      recommendations.push({
        priority: 'medium',
        category: 'code-quality',
        title: 'Reduce Code Complexity',
        description: `Average complexity is ${currentMetrics.averageComplexity}. Target is <10`,
        actionItems: [
          'Refactor complex functions into smaller units',
          'Simplify conditional logic',
          'Extract reusable components',
        ],
      });
    }
    
    return recommendations;
  }
}
```

#### Automated Quality Gates
```typescript
// scripts/quality-gates.ts
export interface QualityGate {
  name: string;
  threshold: number;
  operator: 'gte' | 'lte' | 'eq';
  metric: string;
  blocking: boolean;
}

export const QUALITY_GATES: QualityGate[] = [
  {
    name: 'Test Coverage',
    threshold: 85,
    operator: 'gte',
    metric: 'coverage.total',
    blocking: true,
  },
  {
    name: 'Test Pass Rate',
    threshold: 100,
    operator: 'eq',
    metric: 'tests.passRate',
    blocking: true,
  },
  {
    name: 'Build Performance',
    threshold: 120000, // 2 minutes
    operator: 'lte',
    metric: 'build.duration',
    blocking: false,
  },
  {
    name: 'Bundle Size',
    threshold: 2048, // 2MB
    operator: 'lte',
    metric: 'bundle.size',
    blocking: true,
  },
  {
    name: 'Security Vulnerabilities',
    threshold: 0,
    operator: 'eq',
    metric: 'security.highSeverityCount',
    blocking: true,
  },
  {
    name: 'Accessibility Violations',
    threshold: 0,
    operator: 'eq',
    metric: 'accessibility.criticalViolations',
    blocking: true,
  },
];

export const evaluateQualityGates = async (): Promise<QualityGateResult[]> => {
  const metrics = await collectAllMetrics();
  const results: QualityGateResult[] = [];
  
  for (const gate of QUALITY_GATES) {
    const metricValue = getMetricValue(metrics, gate.metric);
    const passed = evaluateCondition(metricValue, gate.threshold, gate.operator);
    
    results.push({
      gateName: gate.name,
      passed,
      actualValue: metricValue,
      threshold: gate.threshold,
      blocking: gate.blocking,
      impact: passed ? 'none' : gate.blocking ? 'blocking' : 'warning',
    });
  }
  
  return results;
};
```

### 7. Reporting and Visualization

#### Metrics Export
```typescript
// scripts/metrics-export.ts
export const exportMetrics = async (format: 'json' | 'csv' | 'html' = 'json') => {
  const dashboard = new MetricsDashboard();
  const report = await dashboard.generateDashboard();
  
  switch (format) {
    case 'json':
      await fs.writeFile('metrics/quality-report.json', JSON.stringify(report, null, 2));
      break;
      
    case 'csv':
      const csv = convertToCsv(report);
      await fs.writeFile('metrics/quality-report.csv', csv);
      break;
      
    case 'html':
      const html = generateHtmlReport(report);
      await fs.writeFile('metrics/quality-report.html', html);
      break;
  }
  
  console.log(`📊 Quality metrics exported to metrics/quality-report.${format}`);
};

const generateHtmlReport = (report: DashboardReport): string => {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Quality Metrics Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    .metric-card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 10px 0; }
    .metric-value { font-size: 2em; font-weight: bold; color: #2196F3; }
    .metric-label { color: #666; }
    .status-good { color: #4CAF50; }
    .status-warning { color: #FF9800; }
    .status-error { color: #F44336; }
    .chart { width: 100%; height: 300px; margin: 20px 0; }
  </style>
</head>
<body>
  <h1>Quality Metrics Report</h1>
  <p>Generated: ${report.timestamp}</p>
  
  <div class="metric-card">
    <h2>Test Coverage</h2>
    <div class="metric-value ${report.testSuite.coveragePercentage >= 85 ? 'status-good' : 'status-warning'}">
      ${report.testSuite.coveragePercentage}%
    </div>
    <div class="metric-label">Target: 85%</div>
  </div>
  
  <div class="metric-card">
    <h2>Test Results</h2>
    <div class="metric-value ${report.testSuite.failingTests === 0 ? 'status-good' : 'status-error'}">
      ${report.testSuite.passingTests}/${report.testSuite.totalTests}
    </div>
    <div class="metric-label">Passing Tests</div>
  </div>
  
  <!-- Add more metrics sections -->
  
  <div class="metric-card">
    <h2>Recommendations</h2>
    <ul>
      ${report.recommendations.map(rec => `
        <li class="status-${rec.priority}">
          <strong>${rec.title}</strong>: ${rec.description}
        </li>
      `).join('')}
    </ul>
  </div>
</body>
</html>
  `;
};
```

### 8. CI/CD Integration

#### GitHub Actions Workflow
```yaml
# .github/workflows/quality-metrics.yml
name: Quality Metrics

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  quality-metrics:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests with coverage
        run: npm run test:coverage
      
      - name: Generate quality metrics
        run: npm run metrics:generate
      
      - name: Evaluate quality gates
        run: npm run quality:gates
        
      - name: Upload coverage reports
        uses: codecov/codecov-action@v3
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          
      - name: Comment PR with metrics
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('metrics/quality-report.json', 'utf8'));
            
            const comment = `
            ## 📊 Quality Metrics Report
            
            | Metric | Value | Status |
            |--------|-------|--------|
            | Test Coverage | ${report.testSuite.coveragePercentage}% | ${report.testSuite.coveragePercentage >= 85 ? '✅' : '⚠️'} |
            | Tests Passing | ${report.testSuite.passingTests}/${report.testSuite.totalTests} | ${report.testSuite.failingTests === 0 ? '✅' : '❌'} |
            | Code Quality | ${report.codeQuality.maintainabilityIndex}/100 | ${report.codeQuality.maintainabilityIndex >= 70 ? '✅' : '⚠️'} |
            | Bundle Size | ${report.performance.bundleSize}KB | ${report.performance.bundleSize <= 2048 ? '✅' : '⚠️'} |
            
            ${report.recommendations.length > 0 ? `
            ### 🎯 Recommendations
            ${report.recommendations.map(rec => `- **${rec.title}**: ${rec.description}`).join('\n')}
            ` : ''}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

## Usage and Implementation

### 1. Setup Commands
```bash
# Install metrics dependencies
npm install --save-dev @complexity/analyzer jest-axe puppeteer

# Add npm scripts to package.json
npm run metrics:generate    # Generate comprehensive metrics report
npm run metrics:export      # Export metrics in various formats
npm run quality:gates       # Evaluate quality gates
npm run coverage:detailed   # Generate detailed coverage report
```

### 2. Daily Monitoring
```bash
#!/bin/bash
# scripts/daily-metrics.sh

echo "🔍 Running daily quality metrics..."

# Generate metrics
npm run metrics:generate

# Evaluate quality gates
npm run quality:gates

# Export reports
npm run metrics:export -- --format html
npm run metrics:export -- --format csv

# Send notifications if quality gates fail
if [ $? -ne 0 ]; then
  echo "❌ Quality gates failed. Sending notifications..."
  # Add notification logic (Slack, email, etc.)
fi

echo "✅ Daily metrics completed"
```

### 3. Integration Examples
```typescript
// Example: Using metrics in tests
import { performanceTracker, expectRenderTimeBelow } from '@tests/utils';

describe('Performance Tests', () => {
  it('should render efficiently', () => {
    expectRenderTimeBelow(MyComponent, {}, 50);
  });
  
  it('should track custom metrics', () => {
    performanceTracker.startMeasurement('custom-operation');
    
    // Perform operation
    doComplexOperation();
    
    const duration = performanceTracker.endMeasurement('custom-operation');
    expect(duration).toBeLessThan(100);
  });
});
```

## Best Practices

1. **Continuous Monitoring**: Run metrics collection on every build
2. **Trend Analysis**: Track metrics over time to identify patterns
3. **Actionable Insights**: Focus on metrics that drive action
4. **Team Visibility**: Make metrics visible to the entire team
5. **Regular Review**: Review and update metrics thresholds quarterly

## Conclusion

This quality metrics framework provides comprehensive visibility into the health and quality of the Claude UI project. By implementing these metrics and monitoring practices, the team can:

- Maintain high code quality standards
- Catch regressions early
- Make data-driven decisions about technical debt
- Ensure consistent user experience
- Improve development velocity through quality automation

Regular review and refinement of these metrics will ensure they continue to provide value as the project evolves.