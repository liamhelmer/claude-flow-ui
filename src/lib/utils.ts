import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';
  
  // Handle negative numbers as edge case
  if (bytes < 0) {
    return 'NaN Bytes';
  }
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  // Handle invalid indices
  if (i < 0 || i >= sizes.length) {
    return 'NaN Bytes';
  }
  
  const result = (bytes / Math.pow(k, i)).toFixed(dm);
  // For custom decimals > 2, ensure trailing zeros are kept
  const formattedResult = decimals > 2 ? result : parseFloat(result).toString();
  
  return formattedResult + ' ' + sizes[i];
}

export function formatPercentage(value: number, decimals = 1): string {
  // Cap at 999.9% to handle very large values
  const cappedValue = Math.min(value, 999.9);
  return `${cappedValue.toFixed(decimals)}%`;
}

export function formatDuration(ms: number): string {
  // Handle negative durations as edge case
  if (ms < 0) {
    return formatDuration(-ms).replace(/^/, '-');
  }
  
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
  return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`;
}

export function generateSessionId(): string {
  return `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function generateId() {
  return `id-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function formatDate(date: Date) {
  return new Intl.DateTimeFormat('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout;
  return function (this: any, ...args: Parameters<T>) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}