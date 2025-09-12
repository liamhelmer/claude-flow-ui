import { useState, useEffect, useCallback, useRef } from 'react';

interface TerminalDimensions {
  cols: number;
  rows: number;
  width: number;
  height: number;
}

interface Terminal {
  resize?: (cols: number, rows: number) => void;
  cols?: number;
  rows?: number;
}

interface UseTerminalResizeOptions {
  charWidth?: number;
  charHeight?: number;
  padding?: {
    top?: number;
    bottom?: number;
    left?: number;
    right?: number;
  };
  minCols?: number;
  minRows?: number;
  maxCols?: number;
  maxRows?: number;
  aspectRatio?: number;
  debounceMs?: number;
  responsive?: {
    mobile?: { maxWidth: number; cols: number; rows: number };
    tablet?: { maxWidth: number; cols: number; rows: number };
    desktop?: { minWidth: number; cols: number; rows: number };
  };
  onDimensionChange?: (dimensions: TerminalDimensions) => void;
}

export const useTerminalResize = (
  terminal: Terminal | null,
  container: HTMLElement | null,
  options: UseTerminalResizeOptions = {}
) => {
  const {
    charWidth = 8,
    charHeight = 16,
    padding = { top: 0, bottom: 0, left: 0, right: 0 },
    minCols = 1,
    minRows = 1,
    maxCols,
    maxRows,
    aspectRatio,
    debounceMs = 0,
    responsive,
    onDimensionChange,
  } = options;

  const [dimensions, setDimensions] = useState<TerminalDimensions>(() => {
    const initialWidth = container?.getBoundingClientRect().width || 0;
    const initialHeight = container?.getBoundingClientRect().height || 0;
    
    return {
      cols: terminal?.cols || 80,
      rows: terminal?.rows || 24,
      width: initialWidth,
      height: initialHeight,
    };
  });

  const resizeObserverRef = useRef<ResizeObserver | null>(null);
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const previousDimensionsRef = useRef<TerminalDimensions | null>(null);

  // Calculate terminal dimensions based on container size
  const calculateDimensions = useCallback(
    (containerWidth: number, containerHeight: number): TerminalDimensions => {
      const horizontalPadding = (padding.left || 0) + (padding.right || 0);
      const verticalPadding = (padding.top || 0) + (padding.bottom || 0);

      const availableWidth = Math.max(0, containerWidth - horizontalPadding);
      const availableHeight = Math.max(0, containerHeight - verticalPadding);

      let cols = Math.floor(availableWidth / charWidth);
      let rows = Math.floor(availableHeight / charHeight);

      // Check responsive breakpoints
      if (responsive) {
        if (responsive.mobile && containerWidth <= responsive.mobile.maxWidth) {
          cols = responsive.mobile.cols;
          rows = responsive.mobile.rows;
        } else if (responsive.tablet && containerWidth <= responsive.tablet.maxWidth) {
          cols = responsive.tablet.cols;
          rows = responsive.tablet.rows;
        } else if (responsive.desktop && containerWidth >= responsive.desktop.minWidth) {
          cols = responsive.desktop.cols;
          rows = responsive.desktop.rows;
        }
      }

      // Apply aspect ratio constraints
      if (aspectRatio) {
        const currentRatio = cols / rows;
        if (currentRatio > aspectRatio) {
          cols = Math.floor(rows * aspectRatio);
        } else if (currentRatio < aspectRatio) {
          rows = Math.floor(cols / aspectRatio);
        }
      }

      // Apply min/max constraints
      cols = Math.max(minCols, cols);
      rows = Math.max(minRows, rows);

      if (maxCols !== undefined) {
        cols = Math.min(maxCols, cols);
      }
      if (maxRows !== undefined) {
        rows = Math.min(maxRows, rows);
      }

      return {
        cols,
        rows,
        width: containerWidth,
        height: containerHeight,
      };
    },
    [charWidth, charHeight, padding, minCols, minRows, maxCols, maxRows, aspectRatio, responsive]
  );

  // Handle resize with debouncing
  const handleResize = useCallback(
    (entries: ResizeObserverEntry[]) => {
      if (!entries.length) return;

      const entry = entries[0];
      const { width, height } = entry.contentRect;

      const updateDimensions = () => {
        const newDimensions = calculateDimensions(width, height);

        // Check if dimensions actually changed
        const previousDims = previousDimensionsRef.current;
        if (
          previousDims &&
          previousDims.cols === newDimensions.cols &&
          previousDims.rows === newDimensions.rows &&
          previousDims.width === newDimensions.width &&
          previousDims.height === newDimensions.height
        ) {
          return;
        }

        setDimensions(newDimensions);
        previousDimensionsRef.current = newDimensions;

        // Resize terminal if available
        if (terminal?.resize) {
          try {
            terminal.resize(newDimensions.cols, newDimensions.rows);
          } catch (error) {
            console.error('Terminal resize failed:', error);
          }
        }

        // Call dimension change callback
        if (onDimensionChange) {
          onDimensionChange(newDimensions);
        }
      };

      if (debounceMs > 0) {
        if (debounceTimeoutRef.current) {
          clearTimeout(debounceTimeoutRef.current);
        }
        debounceTimeoutRef.current = setTimeout(updateDimensions, debounceMs);
      } else {
        updateDimensions();
      }
    },
    [calculateDimensions, terminal, debounceMs, onDimensionChange]
  );

  // Setup ResizeObserver
  useEffect(() => {
    if (!container) {
      return;
    }

    // Check if ResizeObserver is available
    if (typeof ResizeObserver === 'undefined') {
      console.warn('ResizeObserver not available');
      return;
    }

    try {
      // Get initial dimensions
      const rect = container.getBoundingClientRect();
      const initialDimensions = calculateDimensions(rect.width, rect.height);
      setDimensions(initialDimensions);
      previousDimensionsRef.current = initialDimensions;

      // Setup observer
      const observer = new ResizeObserver(handleResize);
      observer.observe(container);
      resizeObserverRef.current = observer;

      return () => {
        observer.disconnect();
        if (debounceTimeoutRef.current) {
          clearTimeout(debounceTimeoutRef.current);
        }
      };
    } catch (error) {
      console.warn('Failed to setup ResizeObserver:', error);
    }
  }, [container, calculateDimensions, handleResize]);

  // Handle container changes
  useEffect(() => {
    if (!container) return;

    try {
      const rect = container.getBoundingClientRect();
      const newDimensions = calculateDimensions(rect.width, rect.height);
      
      if (
        newDimensions.width !== dimensions.width ||
        newDimensions.height !== dimensions.height
      ) {
        setDimensions(newDimensions);
        previousDimensionsRef.current = newDimensions;

        if (terminal?.resize) {
          try {
            terminal.resize(newDimensions.cols, newDimensions.rows);
          } catch (error) {
            console.error('Terminal resize failed:', error);
          }
        }

        if (onDimensionChange) {
          onDimensionChange(newDimensions);
        }
      }
    } catch (error) {
      console.warn('Error calculating container dimensions:', error);
    }
  }, [container, calculateDimensions, terminal, dimensions.width, dimensions.height, onDimensionChange]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (resizeObserverRef.current) {
        resizeObserverRef.current.disconnect();
      }
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, []);

  return {
    dimensions,
  };
};