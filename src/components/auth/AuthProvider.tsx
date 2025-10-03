'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import LoginDialog from './LoginDialog';
import { setAuthToken, getAuthToken, clearAuthToken, getUserInfo, isTokenExpired } from '@/lib/auth';

interface AuthContextType {
  isAuthenticated: boolean;
  token: string | null;
  userInfo: any;
  login: (token: string) => void;
  logout: () => void;
  showLoginDialog: () => void;
  isAuthRequired: boolean; // Indicates if auth dialog is currently shown
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
  requireAuth?: boolean;
}

export default function AuthProvider({ children, requireAuth = false }: AuthProviderProps) {
  const [token, setToken] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<any>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [loginError, setLoginError] = useState('');

  // Check for stored token on mount and verify with server
  useEffect(() => {
    const checkAuthStatus = async () => {
      const storedToken = getAuthToken();

      if (storedToken) {
        // Check if token is expired
        if (isTokenExpired(storedToken)) {
          clearAuthToken();
          setShowLogin(true);
          setLoginError('Your token has expired. Please log in again.');
          return;
        }

        // Verify token with server
        try {
          const response = await fetch('/api/health', {
            headers: {
              'Authorization': `Bearer ${storedToken}`,
            },
          });

          if (response.status === 401) {
            // Token is invalid, clear it and show login
            clearAuthToken();
            setShowLogin(true);
            setLoginError('Authentication required. Please log in.');
          } else if (response.ok) {
            // Token is valid
            setToken(storedToken);
            setUserInfo(getUserInfo(storedToken));
          } else {
            // Some other error, still show login
            clearAuthToken();
            setShowLogin(true);
            setLoginError('Authentication required. Please log in.');
          }
        } catch (error) {
          console.error('[AuthProvider] Failed to verify token:', error);
          // On error, try to proceed with stored token but show login if it fails
          setToken(storedToken);
          setUserInfo(getUserInfo(storedToken));
        }
      } else {
        // No stored token - check if server requires auth
        try {
          const response = await fetch('/api/health', {
            headers: {
              'Cache-Control': 'no-cache',
            },
          });

          if (response.ok) {
            const data = await response.json();
            // Check if authentication is required
            if (data.auth?.required) {
              setShowLogin(true);
              setLoginError('Authentication required. Please log in.');
            }
          }
        } catch (error) {
          console.error('[AuthProvider] Failed to check auth status:', error);
        }
      }
    };

    checkAuthStatus();
  }, []);

  // Listen for 401 responses globally with retry limit
  useEffect(() => {
    const originalFetch = window.fetch;
    const failureCountMap = new Map<string, number>();

    window.fetch = async (...args) => {
      const response = await originalFetch(...args);

      // Clone response to avoid consuming it
      const clonedResponse = response.clone();

      // Extract URL for tracking
      const getUrl = (): string => {
        if (typeof args[0] === 'string') {
          return args[0];
        }
        if (args[0] instanceof Request) {
          return args[0].url;
        }
        if (args[0] instanceof URL) {
          return args[0].toString();
        }
        return 'unknown';
      };

      if (clonedResponse.status === 401) {
        // Track failures per endpoint
        const url = getUrl();
        const currentCount = failureCountMap.get(url) || 0;
        failureCountMap.set(url, currentCount + 1);

        // After 2 consecutive 401s from the same endpoint, show login
        if (currentCount + 1 >= 2) {
          // Clear invalid token
          clearAuthToken();
          setToken(null);
          setUserInfo(null);

          // Show login dialog
          setShowLogin(true);
          setLoginError('Your session has expired. Please log in again.');

          // Reset counter after showing dialog
          failureCountMap.clear();
        }
      } else if (clonedResponse.ok) {
        // Clear failure count on successful response
        const url = getUrl();
        failureCountMap.delete(url);
      }

      return response;
    };

    return () => {
      window.fetch = originalFetch;
    };
  }, []);

  // Listen for auth-error events from WebSocket
  useEffect(() => {
    const handleAuthError = (event: Event) => {
      const customEvent = event as CustomEvent;
      console.error('[AuthProvider] WebSocket authentication error:', customEvent.detail);

      // Clear invalid token
      clearAuthToken();
      setToken(null);
      setUserInfo(null);

      // Show login dialog
      setShowLogin(true);
      setLoginError('WebSocket authentication failed. Please log in again.');
    };

    window.addEventListener('auth-error', handleAuthError);

    return () => {
      window.removeEventListener('auth-error', handleAuthError);
    };
  }, []);

  const login = async (newToken: string) => {
    try {
      // Basic validation
      if (isTokenExpired(newToken)) {
        setLoginError('This token has expired. Please get a new one from Backstage.');
        return;
      }

      // Test the token by making a request to the health endpoint
      const response = await fetch('/api/health', {
        headers: {
          'Authorization': `Bearer ${newToken}`,
        },
      });

      if (response.status === 401) {
        setLoginError('Invalid token. Please check your token and try again.');
        return;
      }

      if (response.status === 403) {
        setLoginError('You do not have permission to access this application. Please contact your administrator.');
        return;
      }

      if (!response.ok) {
        setLoginError('Failed to authenticate. Please try again.');
        return;
      }

      // Token is valid, store it
      setAuthToken(newToken);
      setToken(newToken);
      setUserInfo(getUserInfo(newToken));
      setShowLogin(false);
      setLoginError('');

      // Reload the page to apply authentication to all components
      window.location.reload();
    } catch (error) {
      console.error('Login error:', error);
      setLoginError('An error occurred during login. Please try again.');
    }
  };

  const logout = () => {
    clearAuthToken();
    setToken(null);
    setUserInfo(null);

    if (requireAuth) {
      setShowLogin(true);
    }

    // Reload to clear any authenticated state
    window.location.reload();
  };

  const showLoginDialog = () => {
    setShowLogin(true);
    setLoginError('');
  };

  const value: AuthContextType = {
    isAuthenticated: !!token,
    token,
    userInfo,
    login,
    logout,
    showLoginDialog,
    isAuthRequired: showLogin, // Expose auth dialog state
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
      <LoginDialog
        isOpen={showLogin}
        onLogin={login}
        errorMessage={loginError}
      />
    </AuthContext.Provider>
  );
}
