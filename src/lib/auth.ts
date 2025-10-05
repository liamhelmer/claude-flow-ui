/**
 * Authentication utility for managing JWT tokens
 */

const TOKEN_KEY = 'backstage_jwt_token';

/**
 * Store JWT token in sessionStorage
 * Clears API retry state to allow immediate retries with new credentials
 */
export function setAuthToken(token: string): void {
  if (typeof window !== 'undefined') {
    sessionStorage.setItem(TOKEN_KEY, token);

    // Clear API retry state so requests can be retried immediately with new token
    // Import is done dynamically to avoid circular dependencies
    import('./api').then(({ clearAllRetryState }) => {
      clearAllRetryState();
      console.debug('[Auth] Token set, retry state cleared');
    }).catch(() => {
      // Ignore errors if API module not loaded yet
    });
  }
}

/**
 * Get JWT token from sessionStorage
 */
export function getAuthToken(): string | null {
  if (typeof window !== 'undefined') {
    return sessionStorage.getItem(TOKEN_KEY);
  }
  return null;
}

/**
 * Remove JWT token from sessionStorage
 */
export function clearAuthToken(): void {
  if (typeof window !== 'undefined') {
    sessionStorage.removeItem(TOKEN_KEY);
  }
}

/**
 * Check if user is authenticated (has token)
 */
export function isAuthenticated(): boolean {
  return !!getAuthToken();
}

/**
 * Parse JWT token to extract payload (without verification)
 * This is for display purposes only - server validates the token
 */
export function parseJwtPayload(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  } catch (error) {
    console.error('Failed to parse JWT payload:', error);
    return null;
  }
}

/**
 * Check if JWT token is expired (client-side check only)
 * Server performs the authoritative validation
 *
 * Note: JWT exp times are in UTC (seconds since epoch), so we compare
 * against UTC time, not local time. Date.now() returns UTC milliseconds.
 */
export function isTokenExpired(token: string): boolean {
  const payload = parseJwtPayload(token);
  if (!payload || !payload.exp) {
    return true;
  }

  // JWT exp is in seconds since epoch (UTC)
  // Date.now() returns milliseconds since epoch (UTC)
  // Both are UTC, so direct comparison is correct
  const nowSeconds = Math.floor(Date.now() / 1000);

  // Add 30 second buffer to account for clock skew
  const bufferSeconds = 30;

  return payload.exp < (nowSeconds - bufferSeconds);
}

/**
 * Get user info from JWT token
 */
export function getUserInfo(token?: string): { sub?: string; name?: string; email?: string } | null {
  const authToken = token || getAuthToken();
  if (!authToken) {
    return null;
  }

  const payload = parseJwtPayload(authToken);
  if (!payload) {
    return null;
  }

  return {
    sub: payload.sub,
    name: payload.name || payload['backstage.io/user']?.displayName,
    email: payload.email || payload['backstage.io/user']?.email,
  };
}

/**
 * Add Authorization header to fetch options
 */
export function withAuthHeader(options: RequestInit = {}): RequestInit {
  const token = getAuthToken();

  if (!token) {
    return options;
  }

  return {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
    },
  };
}

/**
 * Fetch with automatic authentication
 */
export async function authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  return fetch(url, withAuthHeader(options));
}

/**
 * Extract token from URL query parameter
 * Supports: /?backstage_token=TOKEN
 *
 * @param paramName - Name of the query parameter (default: 'backstage_token')
 * @returns Token string or null if not found
 */
export function extractTokenFromUrl(paramName: string = 'backstage_token'): string | null {
  if (typeof window === 'undefined') {
    return null;
  }

  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(paramName);
}

/**
 * Remove token from URL (security best practice)
 * Cleans up the URL after extracting the token to prevent it from being logged or shared
 *
 * @param paramName - Name of the query parameter to remove (default: 'backstage_token')
 */
export function removeTokenFromUrl(paramName: string = 'backstage_token'): void {
  if (typeof window === 'undefined') {
    return;
  }

  const newUrl = new URL(window.location.href);
  if (newUrl.searchParams.has(paramName)) {
    newUrl.searchParams.delete(paramName);
    window.history.replaceState({}, '', newUrl.toString());
  }
}

/**
 * Handle automatic login from URL parameter
 * Extracts token from URL, stores it, and cleans up the URL
 *
 * Usage:
 * ```typescript
 * // In your component
 * useEffect(() => {
 *   handleUrlAuthentication();
 * }, []);
 * ```
 *
 * Backstage can generate links like:
 * https://your-app.com/?backstage_token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
 *
 * @param paramName - Name of the query parameter (default: 'backstage_token')
 * @returns True if token was found and stored, false otherwise
 */
export function handleUrlAuthentication(paramName: string = 'backstage_token'): boolean {
  const token = extractTokenFromUrl(paramName);

  if (token) {
    console.log('[Auth] Found token in URL, storing for authentication');
    setAuthToken(token);
    removeTokenFromUrl(paramName);
    console.log('[Auth] Token stored, URL cleaned');
    return true;
  }

  return false;
}
