import React, { useState, useEffect, useCallback, useRef, ReactNode } from 'react';

interface PerformanceMetrics {
  cpuUsage: number;
  memoryUsage: number;
  memoryUsed: number;
  memoryTotal: number;
  memoryLimit: number;
  networkInfo?: {
    effectiveType: string;
    downlink: number;
    rtt: number;
    saveData: boolean;
  };
  paintMetrics?: {
    firstPaint?: number;
    firstContentfulPaint?: number;
  };
  navigationMetrics?: {
    pageLoad?: number;
    domContentLoaded?: number;
    responseTime?: number;
  };
  resourceMetrics?: {
    resourceCount: number;
    totalTransferSize: number;
  };
  gcEvents?: number;
  longTasks?: number;
  customMetrics?: Record<string, number>;
}

interface PerformanceMonitorProps {
  children?: ReactNode;
  updateInterval?: number;
  memoryThreshold?: number;
  showMemoryDetails?: boolean;
  showMemoryBreakdown?: boolean;
  showNetworkInfo?: boolean;
  showCpuGraph?: boolean;
  showAnimations?: boolean;
  collectPaintMetrics?: boolean;
  collectNavigationMetrics?: boolean;
  collectResourceMetrics?: boolean;
  trackGarbageCollection?: boolean;
  detectLongTasks?: boolean;
  trackInteractions?: boolean;
  useUserTiming?: boolean;
  usePerformanceObserver?: boolean;
  detectMemoryLeaks?: boolean;
  memoryLeakThreshold?: number;
  debounceUpdates?: boolean;
  throttleExpensiveOps?: boolean;
  enableDataExport?: boolean;
  customMetrics?: Record<string, number>;
  showCustomMetrics?: boolean;
  customFormatters?: Record<string, (value: number) => string>;
  onMetricsUpdate?: (metrics: PerformanceMetrics) => void;
  onBottleneckDetected?: (bottleneck: {
    type: string;
    severity: string;
    value: number;
    threshold: number;
  }) => void;
  onMemoryLeak?: (leak: {
    type: string;
    growthRate: number;
    currentUsage: number;
  }) => void;
  onSlowConnection?: (connection: {
    effectiveType: string;
    downlink: number;
    rtt: number;
  }) => void;
  onDetailedMetrics?: (metrics: PerformanceMetrics) => void;
}

export const PerformanceMonitor: React.FC<PerformanceMonitorProps> = ({
  children,
  updateInterval = 1000,
  memoryThreshold = 0.8,
  showMemoryDetails = false,
  showMemoryBreakdown = false,
  showNetworkInfo = false,
  showCpuGraph = false,
  showAnimations = false,
  collectPaintMetrics = false,
  collectNavigationMetrics = false,
  collectResourceMetrics = false,
  trackGarbageCollection = false,
  detectLongTasks = false,
  trackInteractions = false,
  useUserTiming = false,
  usePerformanceObserver = false,
  detectMemoryLeaks = false,
  memoryLeakThreshold = 1.5,
  debounceUpdates = false,
  throttleExpensiveOps = false,
  enableDataExport = false,
  customMetrics = {},
  showCustomMetrics = false,
  customFormatters = {},
  onMetricsUpdate,
  onBottleneckDetected,
  onMemoryLeak,
  onSlowConnection,
  onDetailedMetrics,
}) => {
  const [metrics, setMetrics] = useState<PerformanceMetrics>({
    cpuUsage: 0,
    memoryUsage: 0,
    memoryUsed: 0,
    memoryTotal: 0,
    memoryLimit: 0,
  });
  
  const [isExpanded, setIsExpanded] = useState(false);
  const [exportFormat, setExportFormat] = useState<'json' | 'csv'>('json');
  const [previousMemory, setPreviousMemory] = useState(0);
  
  const intervalRef = useRef<NodeJS.Timeout>();
  const performanceObserverRef = useRef<PerformanceObserver>();
  const lastUpdateRef = useRef(0);
  const debounceTimeoutRef = useRef<NodeJS.Timeout>();
  const throttleTimeoutRef = useRef<NodeJS.Timeout>();

  // Check for reduced motion preference
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const shouldAnimate = showAnimations && !prefersReducedMotion;

  // Check for high contrast preference
  const prefersHighContrast = window.matchMedia('(prefers-contrast: high)').matches;

  // Format bytes to human readable
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  // Get memory information
  const getMemoryInfo = useCallback((): {
    used: number;
    total: number;
    limit: number;
    usage: number;
  } => {
    if (!(navigator as any).memory) {
      return { used: 0, total: 0, limit: 0, usage: 0 };
    }

    const { usedJSHeapSize, totalJSHeapSize, jsHeapSizeLimit } = (navigator as any).memory;
    return {
      used: usedJSHeapSize,
      total: totalJSHeapSize,
      limit: jsHeapSizeLimit,
      usage: totalJSHeapSize > 0 ? usedJSHeapSize / totalJSHeapSize : 0,
    };
  }, []);

  // Get network information
  const getNetworkInfo = useCallback(() => {
    const connection = (navigator as any).connection;
    if (!connection) return null;

    const info = {
      effectiveType: connection.effectiveType,
      downlink: connection.downlink,
      rtt: connection.rtt,
      saveData: connection.saveData,
    };

    // Check for slow connection
    if (onSlowConnection && (info.effectiveType === '2g' || info.downlink < 1)) {
      onSlowConnection(info);
    }

    return info;
  }, [onSlowConnection]);

  // Get paint metrics
  const getPaintMetrics = useCallback(() => {
    if (!performance.getEntriesByType) return {};

    const paintEntries = performance.getEntriesByType('paint');
    const metrics: any = {};

    paintEntries.forEach((entry) => {
      if (entry.name === 'first-paint') {
        metrics.firstPaint = entry.startTime;
      } else if (entry.name === 'first-contentful-paint') {
        metrics.firstContentfulPaint = entry.startTime;
      }
    });

    return metrics;
  }, []);

  // Get navigation metrics
  const getNavigationMetrics = useCallback(() => {
    if (!performance.getEntriesByType) return {};

    const navigationEntries = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];
    if (navigationEntries.length === 0) return {};

    const entry = navigationEntries[0];
    return {
      pageLoad: entry.loadEventEnd - entry.startTime,
      domContentLoaded: entry.domContentLoadedEventEnd - entry.startTime,
      responseTime: entry.responseEnd - entry.startTime,
    };
  }, []);

  // Get resource metrics
  const getResourceMetrics = useCallback(() => {
    if (!performance.getEntriesByType) return {};

    const resourceEntries = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    const totalTransferSize = resourceEntries.reduce((sum, entry) => sum + (entry.transferSize || 0), 0);

    return {
      resourceCount: resourceEntries.length,
      totalTransferSize,
    };
  }, []);

  // Get garbage collection events
  const getGCEvents = useCallback(() => {
    if (!performance.getEntriesByType) return 0;

    const gcEntries = performance.getEntriesByType('gc');
    return gcEntries.length;
  }, []);

  // Get long tasks
  const getLongTasks = useCallback(() => {
    if (!performance.getEntriesByType) return 0;

    const longTaskEntries = performance.getEntriesByType('longtask');
    return longTaskEntries.length;
  }, []);

  // Calculate CPU usage (simplified estimation)
  const getCPUUsage = useCallback(() => {
    const now = performance.now();
    const deltaTime = now - lastUpdateRef.current;
    lastUpdateRef.current = now;

    // Simple CPU usage estimation based on timing
    return Math.min(100, Math.max(0, (deltaTime / updateInterval) * 100));
  }, [updateInterval]);

  // Update metrics
  const updateMetrics = useCallback(() => {
    if (!performance) {
      console.warn('Performance API not available');
      return;
    }

    try {
      const memoryInfo = getMemoryInfo();
      const networkInfo = showNetworkInfo ? getNetworkInfo() : undefined;
      const paintMetrics = collectPaintMetrics ? getPaintMetrics() : undefined;
      const navigationMetrics = collectNavigationMetrics ? getNavigationMetrics() : undefined;
      const resourceMetrics = collectResourceMetrics ? getResourceMetrics() : undefined;
      const gcEvents = trackGarbageCollection ? getGCEvents() : undefined;
      const longTasks = detectLongTasks ? getLongTasks() : undefined;
      const cpuUsage = getCPUUsage();

      const newMetrics: PerformanceMetrics = {
        cpuUsage,
        memoryUsage: memoryInfo.usage,
        memoryUsed: memoryInfo.used,
        memoryTotal: memoryInfo.total,
        memoryLimit: memoryInfo.limit,
        ...(networkInfo && { networkInfo }),
        ...(paintMetrics && { paintMetrics }),
        ...(navigationMetrics && { navigationMetrics }),
        ...(resourceMetrics && { resourceMetrics }),
        ...(typeof gcEvents === 'number' && { gcEvents }),
        ...(typeof longTasks === 'number' && { longTasks }),
        ...(Object.keys(customMetrics).length > 0 && { customMetrics }),
      };

      setMetrics(newMetrics);

      // Check for memory threshold
      if (memoryInfo.usage > memoryThreshold && onBottleneckDetected) {
        onBottleneckDetected({
          type: 'memory',
          severity: 'high',
          value: memoryInfo.usage,
          threshold: memoryThreshold,
        });
      }

      // Check for memory leaks
      if (detectMemoryLeaks && previousMemory > 0) {
        const growthRate = memoryInfo.used / previousMemory;
        if (growthRate > memoryLeakThreshold && onMemoryLeak) {
          onMemoryLeak({
            type: 'potential_leak',
            growthRate,
            currentUsage: memoryInfo.used,
          });
        }
      }
      setPreviousMemory(memoryInfo.used);

      if (onMetricsUpdate) {
        if (debounceUpdates) {
          clearTimeout(debounceTimeoutRef.current);
          debounceTimeoutRef.current = setTimeout(() => {
            onMetricsUpdate(newMetrics);
          }, 100);
        } else {
          onMetricsUpdate(newMetrics);
        }
      }
    } catch (error) {
      console.error('Error updating performance metrics:', error);
    }
  }, [
    getMemoryInfo,
    showNetworkInfo,
    getNetworkInfo,
    collectPaintMetrics,
    getPaintMetrics,
    collectNavigationMetrics,
    getNavigationMetrics,
    collectResourceMetrics,
    getResourceMetrics,
    trackGarbageCollection,
    getGCEvents,
    detectLongTasks,
    getLongTasks,
    getCPUUsage,
    customMetrics,
    memoryThreshold,
    onBottleneckDetected,
    detectMemoryLeaks,
    memoryLeakThreshold,
    onMemoryLeak,
    previousMemory,
    onMetricsUpdate,
    debounceUpdates,
  ]);

  // Setup performance observer
  useEffect(() => {
    if (!usePerformanceObserver || !window.PerformanceObserver) return;

    try {
      const observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        // Process performance entries
        console.log('Performance entries:', entries);
      });

      observer.observe({ entryTypes: ['measure', 'navigation', 'paint'] });
      performanceObserverRef.current = observer;

      return () => {
        observer.disconnect();
      };
    } catch (error) {
      console.warn('PerformanceObserver setup failed:', error);
    }
  }, [usePerformanceObserver]);

  // Setup user timing
  useEffect(() => {
    if (useUserTiming && performance.mark) {
      performance.mark('performance-monitor-start');
    }
  }, [useUserTiming]);

  // Setup interval for updates
  useEffect(() => {
    updateMetrics(); // Initial update

    intervalRef.current = setInterval(updateMetrics, updateInterval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      if (throttleTimeoutRef.current) {
        clearTimeout(throttleTimeoutRef.current);
      }
      if (performanceObserverRef.current) {
        performanceObserverRef.current.disconnect();
      }
    };
  }, [updateMetrics, updateInterval]);

  // Handle interaction tracking
  const handleInteraction = useCallback((type: string) => {
    if (!trackInteractions || !performance.mark) return;

    const markName = `interaction-start-${type}-${Date.now()}`;
    performance.mark(markName);

    setTimeout(() => {
      if (performance.measure) {
        performance.measure(`interaction-duration-${type}`, markName);
      }
    }, 0);
  }, [trackInteractions]);

  // Export data
  const handleExport = useCallback(() => {
    const data = exportFormat === 'json' 
      ? JSON.stringify(metrics, null, 2)
      : Object.entries(metrics).map(([key, value]) => `${key},${value}`).join('\n');

    const blob = new Blob([data], { 
      type: exportFormat === 'json' ? 'application/json' : 'text/csv' 
    });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `performance-metrics.${exportFormat}`;
    link.click();
    
    URL.revokeObjectURL(url);
  }, [metrics, exportFormat]);

  // Clear metrics
  const handleClearMetrics = useCallback(() => {
    handleInteraction('click');
    // Reset metrics logic here
    setMetrics({
      cpuUsage: 0,
      memoryUsage: 0,
      memoryUsed: 0,
      memoryTotal: 0,
      memoryLimit: 0,
    });
  }, [handleInteraction]);

  // Show details
  const handleShowDetails = useCallback(() => {
    if (throttleExpensiveOps) {
      clearTimeout(throttleTimeoutRef.current);
      throttleTimeoutRef.current = setTimeout(() => {
        if (onDetailedMetrics) {
          onDetailedMetrics(metrics);
        }
        setIsExpanded(true);
      }, 100);
    } else {
      if (onDetailedMetrics) {
        onDetailedMetrics(metrics);
      }
      setIsExpanded(true);
    }
  }, [throttleExpensiveOps, onDetailedMetrics, metrics]);

  // Check if performance monitoring is available
  if (!performance) {
    return (
      <div role="region" aria-label="Performance Monitor">
        <p>Performance monitoring unavailable</p>
        {children}
      </div>
    );
  }

  // Check if memory info is available
  const memoryAvailable = !!(navigator as any).memory;

  return (
    <div
      role="region"
      aria-label="Performance Monitor"
      className={prefersHighContrast ? 'high-contrast' : ''}
      style={{
        padding: '16px',
        border: '1px solid #e2e8f0',
        borderRadius: '8px',
        backgroundColor: prefersHighContrast ? '#000' : '#f7fafc',
        color: prefersHighContrast ? '#fff' : '#2d3748',
        fontFamily: 'system-ui, sans-serif',
      }}
    >
      <h3 style={{ margin: '0 0 16px 0', fontSize: '18px', fontWeight: 600 }}>
        Performance Monitor
      </h3>

      <div
        role="status"
        aria-live="polite"
        aria-label={`Performance status: ${metrics.memoryUsage > memoryThreshold ? 'Warning' : 'Normal'}`}
        style={{
          display: 'flex',
          gap: '16px',
          flexWrap: 'wrap',
          marginBottom: '16px',
        }}
      >
        <div>
          <strong>CPU Usage:</strong> {metrics.cpuUsage.toFixed(1)}%
        </div>
        <div>
          <strong>Memory Usage:</strong> {(metrics.memoryUsage * 100).toFixed(1)}%
        </div>
        <div>
          <strong>Network:</strong> {showNetworkInfo ? (metrics.networkInfo?.effectiveType || 'Unknown') : 'N/A'}
        </div>
      </div>

      {showMemoryDetails && memoryAvailable && (
        <div style={{ marginBottom: '16px' }}>
          <div><strong>Used Memory:</strong> {formatBytes(metrics.memoryUsed)}</div>
          <div><strong>Total Memory:</strong> {formatBytes(metrics.memoryTotal)}</div>
        </div>
      )}

      {showMemoryBreakdown && memoryAvailable && (
        <div style={{ marginBottom: '16px' }}>
          <div><strong>Used Memory:</strong> {formatBytes(metrics.memoryUsed)}</div>
          <div><strong>Available Memory:</strong> {formatBytes(metrics.memoryTotal - metrics.memoryUsed)}</div>
          <div><strong>Memory Limit:</strong> {formatBytes(metrics.memoryLimit)}</div>
        </div>
      )}

      {!memoryAvailable && (
        <div style={{ marginBottom: '16px', color: '#e53e3e' }}>
          Memory info unavailable
        </div>
      )}

      {showNetworkInfo && metrics.networkInfo && (
        <div style={{ marginBottom: '16px' }}>
          <div><strong>Connection:</strong> {metrics.networkInfo.effectiveType}</div>
          <div><strong>Speed:</strong> {metrics.networkInfo.downlink} Mbps</div>
          <div><strong>RTT:</strong> {metrics.networkInfo.rtt}ms</div>
          {metrics.networkInfo.effectiveType === '2g' && (
            <div style={{ color: '#e53e3e' }}>Slow connection detected</div>
          )}
        </div>
      )}

      {showCpuGraph && (
        <div
          role="img"
          aria-label="CPU usage graph"
          style={{
            width: '100%',
            height: '60px',
            backgroundColor: '#e2e8f0',
            borderRadius: '4px',
            marginBottom: '16px',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              width: `${metrics.cpuUsage}%`,
              height: '100%',
              backgroundColor: '#3182ce',
              transition: shouldAnimate ? 'width 0.3s ease' : 'none',
            }}
          />
        </div>
      )}

      {collectPaintMetrics && metrics.paintMetrics && (
        <div style={{ marginBottom: '16px' }}>
          {metrics.paintMetrics.firstPaint && (
            <div><strong>First Paint:</strong> {metrics.paintMetrics.firstPaint.toFixed(0)}ms</div>
          )}
          {metrics.paintMetrics.firstContentfulPaint && (
            <div><strong>First Contentful Paint:</strong> {metrics.paintMetrics.firstContentfulPaint.toFixed(0)}ms</div>
          )}
        </div>
      )}

      {collectNavigationMetrics && metrics.navigationMetrics && (
        <div style={{ marginBottom: '16px' }}>
          {metrics.navigationMetrics.pageLoad && (
            <div><strong>Page Load:</strong> {metrics.navigationMetrics.pageLoad.toFixed(0)}ms</div>
          )}
          {metrics.navigationMetrics.domContentLoaded && (
            <div><strong>DOM Content Loaded:</strong> {metrics.navigationMetrics.domContentLoaded.toFixed(0)}ms</div>
          )}
        </div>
      )}

      {collectResourceMetrics && metrics.resourceMetrics && (
        <div style={{ marginBottom: '16px' }}>
          <div><strong>Resources Loaded:</strong> {metrics.resourceMetrics.resourceCount}</div>
          <div><strong>Total Transfer Size:</strong> {formatBytes(metrics.resourceMetrics.totalTransferSize)}</div>
        </div>
      )}

      {trackGarbageCollection && typeof metrics.gcEvents === 'number' && (
        <div style={{ marginBottom: '16px' }}>
          <strong>GC Events:</strong> {metrics.gcEvents}
        </div>
      )}

      {detectLongTasks && typeof metrics.longTasks === 'number' && (
        <div style={{ marginBottom: '16px' }}>
          <strong>Long Tasks Detected:</strong> {metrics.longTasks}
        </div>
      )}

      {showCustomMetrics && Object.keys(customMetrics).length > 0 && (
        <div style={{ marginBottom: '16px' }}>
          {Object.entries(customMetrics).map(([key, value]) => {
            const formatter = customFormatters[key];
            const displayValue = formatter ? formatter(value) : value.toString();
            return (
              <div key={key}>
                <strong>{key}:</strong> {displayValue}
              </div>
            );
          })}
        </div>
      )}

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <button
          onClick={handleShowDetails}
          style={{
            padding: '8px 16px',
            backgroundColor: '#3182ce',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          {isExpanded ? 'Hide Details' : 'Expand Details'}
        </button>

        <button
          onClick={handleClearMetrics}
          style={{
            padding: '8px 16px',
            backgroundColor: '#e53e3e',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          Clear Metrics
        </button>

        <button
          onClick={handleShowDetails}
          style={{
            padding: '8px 16px',
            backgroundColor: '#38a169',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          Show Details
        </button>

        {enableDataExport && (
          <>
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as 'json' | 'csv')}
              aria-label="Export Format"
              style={{
                padding: '8px',
                borderRadius: '4px',
                border: '1px solid #e2e8f0',
              }}
            >
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
            <button
              onClick={handleExport}
              style={{
                padding: '8px 16px',
                backgroundColor: '#805ad5',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              Export Data
            </button>
          </>
        )}
      </div>

      {isExpanded && (
        <div style={{ marginTop: '16px', padding: '16px', backgroundColor: '#f1f5f9', borderRadius: '4px' }}>
          <h4>Detailed Metrics</h4>
          <pre style={{ fontSize: '12px', overflow: 'auto' }}>
            {JSON.stringify(metrics, null, 2)}
          </pre>
        </div>
      )}

      {children && (
        <div 
          style={{ marginTop: '16px' }}
          onClickCapture={() => handleInteraction('child-click')}
          onKeyDownCapture={() => handleInteraction('child-keydown')}
        >
          {children}
        </div>
      )}
    </div>
  );
};