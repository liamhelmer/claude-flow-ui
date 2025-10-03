'use client';

import { useState, useEffect } from 'react';

interface LoginDialogProps {
  isOpen: boolean;
  onLogin: (token: string) => void;
  errorMessage?: string;
}

export default function LoginDialog({ isOpen, onLogin, errorMessage }: LoginDialogProps) {
  const [token, setToken] = useState('');
  const [localError, setLocalError] = useState('');
  const [showTokenInput, setShowTokenInput] = useState(false);

  useEffect(() => {
    if (errorMessage) {
      setLocalError(errorMessage);
    }
  }, [errorMessage]);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!token.trim()) {
      setLocalError('Please enter a valid JWT token');
      return;
    }

    // Basic JWT format validation (three parts separated by dots)
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      setLocalError('Invalid JWT token format. Expected format: header.payload.signature');
      return;
    }

    setLocalError('');
    onLogin(token.trim());
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setToken(text);
      setLocalError('');
    } catch (err) {
      setLocalError('Failed to read from clipboard. Please paste manually.');
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-[#1a1b26] border border-[#414868] rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
        <div className="flex items-center mb-4">
          <svg className="w-6 h-6 text-[#7aa2f7] mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <h2 className="text-xl font-semibold text-[#c0caf5]">Authentication Required</h2>
        </div>

        <p className="text-[#a9b1d6] mb-4 text-sm">
          Please authenticate to access this application.
        </p>

        {!showTokenInput ? (
          <div className="mb-4">
            <button
              type="button"
              onClick={() => setShowTokenInput(true)}
              className="w-full px-4 py-3 bg-[#414868] hover:bg-[#565f89] text-[#c0caf5] rounded font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-[#7aa2f7] focus:ring-offset-2 focus:ring-offset-[#1a1b26]"
            >
              Enter JWT Token Manually
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div className="mb-4">
              <label htmlFor="token" className="block text-[#a9b1d6] text-sm font-medium mb-2">
                JWT Token
              </label>
              <div className="relative">
                <textarea
                  id="token"
                  value={token}
                  onChange={(e) => {
                    setToken(e.target.value);
                    setLocalError('');
                  }}
                  className="w-full px-3 py-2 bg-[#15161e] border border-[#414868] rounded text-[#c0caf5] text-sm font-mono focus:outline-none focus:border-[#7aa2f7] resize-none"
                  rows={4}
                  placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ..."
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus
                />
                <button
                  type="button"
                  onClick={handlePaste}
                  className="absolute top-2 right-2 px-2 py-1 bg-[#414868] hover:bg-[#565f89] text-[#c0caf5] text-xs rounded transition-colors"
                  title="Paste from clipboard"
                >
                  Paste
                </button>
              </div>
              <p className="mt-1 text-xs text-[#565f89]">
                Format: header.payload.signature
              </p>
            </div>

            {localError && (
              <div className="mb-4 p-3 bg-[#f7768e] bg-opacity-10 border border-[#f7768e] rounded">
                <p className="text-[#f7768e] text-sm flex items-center">
                  <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                  {localError}
                </p>
              </div>
            )}

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => {
                  setShowTokenInput(false);
                  setToken('');
                  setLocalError('');
                }}
                className="flex-1 px-4 py-2 bg-[#414868] hover:bg-[#565f89] text-[#c0caf5] rounded font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-[#414868] focus:ring-offset-2 focus:ring-offset-[#1a1b26]"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex-1 px-4 py-2 bg-[#7aa2f7] hover:bg-[#7dcfff] text-white rounded font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-[#7aa2f7] focus:ring-offset-2 focus:ring-offset-[#1a1b26]"
              >
                Login
              </button>
            </div>
          </form>
        )}

        {localError && !showTokenInput && (
          <div className="mb-4 p-3 bg-[#f7768e] bg-opacity-10 border border-[#f7768e] rounded">
            <p className="text-[#f7768e] text-sm flex items-center">
              <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              {localError}
            </p>
          </div>
        )}

        <div className="mt-4 pt-4 border-t border-[#414868]">
          <p className="text-xs text-[#565f89]">
            <strong>How to get your token:</strong>
          </p>
          <ol className="text-xs text-[#565f89] mt-2 space-y-1 list-decimal list-inside">
            <li>Open your Backstage instance</li>
            <li>Open browser DevTools (F12)</li>
            <li>Go to Application → Local Storage</li>
            <li>Find your authentication token</li>
            <li>Copy and paste it above</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
