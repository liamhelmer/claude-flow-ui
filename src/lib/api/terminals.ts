/**
 * Terminal API client with exponential backoff and request deduplication
 *
 * Prevents multiple simultaneous requests to /api/terminals which can cause
 * terminal startup issues.
 */

interface RetryConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
}

interface PendingRequest<T> {
  promise: Promise<T>;
  timestamp: number;
}

/**
 * Request deduplication cache
 * Prevents multiple simultaneous requests to the same endpoint
 */
const pendingRequests = new Map<string, PendingRequest<any>>();

/**
 * Retry state per endpoint
 */
const retryState = new Map<string, { count: number; lastAttempt: number }>();

/**
 * Default retry configuration
 */
const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 30000, // 30 seconds
};

/**
 * Calculate exponential backoff delay
 */
function calculateBackoff(retryCount: number, config: RetryConfig): number {
  const delay = config.baseDelay * Math.pow(2, retryCount);
  return Math.min(delay, config.maxDelay);
}

/**
 * Get authentication headers
 */
function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Cache-Control': 'no-cache',
  };

  if (typeof window !== 'undefined') {
    const token = sessionStorage.getItem('backstage_jwt_token');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  return headers;
}

/**
 * Fetch with exponential backoff and request deduplication
 *
 * @param url - The URL to fetch
 * @param options - Fetch options
 * @param retryConfig - Retry configuration
 * @returns Promise resolving to the response
 */
async function fetchWithBackoff<T = any>(
  url: string,
  options: RequestInit = {},
  retryConfig: Partial<RetryConfig> = {}
): Promise<T> {
  const config = { ...DEFAULT_RETRY_CONFIG, ...retryConfig };
  const cacheKey = `${options.method || 'GET'}:${url}`;

  // Check for pending request (deduplication)
  const pending = pendingRequests.get(cacheKey);
  if (pending) {
    const age = Date.now() - pending.timestamp;
    // Reuse pending request if it's less than 1 second old
    if (age < 1000) {
      console.debug(`[API] Reusing pending request for ${url} (age: ${age}ms)`);
      return pending.promise;
    } else {
      // Clean up stale pending request
      pendingRequests.delete(cacheKey);
    }
  }

  // Check retry state and enforce backoff
  const state = retryState.get(cacheKey);
  if (state && state.count > 0) {
    const timeSinceLastAttempt = Date.now() - state.lastAttempt;
    const requiredDelay = calculateBackoff(state.count - 1, config);

    if (timeSinceLastAttempt < requiredDelay) {
      const waitTime = requiredDelay - timeSinceLastAttempt;
      console.debug(`[API] Backoff enforced for ${url}, waiting ${waitTime}ms`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }

  // Create the request
  const executeRequest = async (): Promise<T> => {
    let retryCount = state?.count || 0;

    while (retryCount <= config.maxRetries) {
      try {
        // Update retry state
        retryState.set(cacheKey, {
          count: retryCount,
          lastAttempt: Date.now(),
        });

        console.debug(`[API] Fetching ${url} (attempt ${retryCount + 1}/${config.maxRetries + 1})`);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
          headers: {
            ...getAuthHeaders(),
            ...options.headers,
          },
        });

        clearTimeout(timeoutId);

        // Success - reset retry state
        if (response.ok) {
          retryState.delete(cacheKey);
          pendingRequests.delete(cacheKey);
          return await response.json();
        }

        // Handle 401 - don't retry
        if (response.status === 401) {
          console.debug(`[API] Authentication required for ${url}`);
          retryState.delete(cacheKey);
          pendingRequests.delete(cacheKey);
          throw new Error('Authentication required');
        }

        // Other errors - prepare for retry
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);

      } catch (error) {
        // Don't retry on AbortError or auth errors
        if (error instanceof Error &&
            (error.name === 'AbortError' || error.message === 'Authentication required')) {
          pendingRequests.delete(cacheKey);
          throw error;
        }

        retryCount++;

        if (retryCount > config.maxRetries) {
          console.error(`[API] Failed after ${config.maxRetries} retries:`, error);
          retryState.delete(cacheKey);
          pendingRequests.delete(cacheKey);
          throw error;
        }

        const delay = calculateBackoff(retryCount, config);
        console.debug(`[API] Retry ${retryCount}/${config.maxRetries} in ${delay}ms`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('Max retries exceeded');
  };

  // Store pending request
  const promise = executeRequest();
  pendingRequests.set(cacheKey, {
    promise,
    timestamp: Date.now(),
  });

  return promise;
}

/**
 * Terminal interface
 */
export interface Terminal {
  id: string;
  name: string;
  command: string;
  createdAt: string;
}

/**
 * Get list of terminals
 * Includes request deduplication and exponential backoff
 */
export async function getTerminals(): Promise<Terminal[]> {
  return fetchWithBackoff<Terminal[]>('/api/terminals');
}

/**
 * Spawn a new terminal
 */
export async function spawnTerminal(): Promise<Terminal> {
  return fetchWithBackoff<Terminal>('/api/terminals/spawn', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

/**
 * Clear retry state for a specific endpoint
 * Useful for forcing an immediate retry
 */
export function clearRetryState(url: string, method: string = 'GET'): void {
  const cacheKey = `${method}:${url}`;
  retryState.delete(cacheKey);
  pendingRequests.delete(cacheKey);
}

/**
 * Clear all retry state
 */
export function clearAllRetryState(): void {
  retryState.clear();
  pendingRequests.clear();
}
