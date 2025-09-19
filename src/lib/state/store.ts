import { create } from 'zustand';
import { devtools, subscribeWithSelector } from 'zustand/middleware';
import type { AppState, TerminalSession } from '@/types';

// Enhanced store with performance optimizations and better selectors

interface AppActions {
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;
  setActiveSession: (sessionId: string | null) => void;
  addSession: (session: TerminalSession) => void;
  removeSession: (sessionId: string) => void;
  updateSession: (sessionId: string, updates: Partial<TerminalSession>) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  createNewSession: () => string;
  clearSessions: () => void;
  batchUpdate: (updates: Partial<AppState>) => void;
}

type Store = AppState & AppActions;

const generateSessionId = () => `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

export const useAppStore = create<Store>()(
  devtools(
    subscribeWithSelector((set, get) => ({
      // Initial state
      terminalSessions: [],
      activeSessionId: null,
      sidebarOpen: true, // Start with sidebar open for better UX
      loading: false,
      error: null,

      // Actions
      setSidebarOpen: (open: boolean) =>
        set({ sidebarOpen: open }, false, 'setSidebarOpen'),

      toggleSidebar: () =>
        set((state) => ({ sidebarOpen: !state.sidebarOpen }), false, 'toggleSidebar'),

      setActiveSession: (sessionId: string | null) =>
        set({ activeSessionId: sessionId }, false, 'setActiveSession'),

      addSession: (session: TerminalSession) =>
        set(
          (state) => ({
            terminalSessions: [...state.terminalSessions, session],
          }),
          false,
          'addSession'
        ),

      removeSession: (sessionId: string) =>
        set(
          (state) => {
            const newSessions = state.terminalSessions.filter((s) => s.id !== sessionId);
            const newActiveId = 
              state.activeSessionId === sessionId 
                ? newSessions[0]?.id || null 
                : state.activeSessionId;
            
            return {
              terminalSessions: newSessions,
              activeSessionId: newActiveId,
            };
          },
          false,
          'removeSession'
        ),

      updateSession: (sessionId: string, updates: Partial<TerminalSession>) =>
        set(
          (state) => ({
            terminalSessions: state.terminalSessions.map((session) =>
              session.id === sessionId ? { ...session, ...updates } : session
            ),
          }),
          false,
          'updateSession'
        ),

      setLoading: (loading: boolean) =>
        set({ loading }, false, 'setLoading'),

      setError: (error: string | null) =>
        set({ error }, false, 'setError'),

      createNewSession: () => {
        const sessionId = generateSessionId();
        const newSession: TerminalSession = {
          id: sessionId,
          name: `Terminal ${get().terminalSessions.length + 1}`,
          isActive: true,
          lastActivity: new Date(),
        };

        set((state) => ({
          terminalSessions: [...state.terminalSessions, newSession],
          activeSessionId: sessionId,
        }), false, 'createNewSession');

        return sessionId;
      },

      clearSessions: () =>
        set(
          { terminalSessions: [], activeSessionId: null },
          false,
          'clearSessions'
        ),

      batchUpdate: (updates: Partial<AppState>) =>
        set(
          (state) => ({ ...state, ...updates }),
          false,
          'batchUpdate'
        ),
    })),
    {
      name: 'claude-flow-store',
    }
  )
);

// Optimized selectors to prevent unnecessary re-renders
export const useTerminalSessions = () => useAppStore(state => state.terminalSessions);
export const useActiveSession = () => useAppStore(state =>
  state.terminalSessions.find(s => s.id === state.activeSessionId)
);
export const useActiveSessionId = () => useAppStore(state => state.activeSessionId);
export const useSidebarOpen = () => useAppStore(state => state.sidebarOpen);
export const useAppError = () => useAppStore(state => state.error);
export const useAppLoading = () => useAppStore(state => state.loading);

// Computed selectors
export const useSessionCount = () => useAppStore(state => state.terminalSessions.length);
export const useHasActiveSessions = () => useAppStore(state => state.terminalSessions.length > 0);
export const useSessionNames = () => useAppStore(state =>
  state.terminalSessions.map(s => ({ id: s.id, name: s.name }))
);

// Store subscriptions for external use
export const subscribeToActiveSession = (callback: (sessionId: string | null) => void) => {
  return useAppStore.subscribe(
    state => state.activeSessionId,
    callback
  );
};

// Store persistence utilities
export const getStoreSnapshot = () => {
  const state = useAppStore.getState();
  return {
    terminalSessions: state.terminalSessions,
    activeSessionId: state.activeSessionId,
    sidebarOpen: state.sidebarOpen,
  };
};

export const restoreStoreSnapshot = (snapshot: Partial<AppState>) => {
  useAppStore.getState().batchUpdate(snapshot);
};

// Auto-close sidebar on mobile for better UX
export const initializeSidebarForViewport = () => {
  if (typeof window !== 'undefined') {
    const isMobile = window.innerWidth < 768;
    if (isMobile && useAppStore.getState().sidebarOpen) {
      useAppStore.getState().setSidebarOpen(false);
    }
  }
};

// Development utilities
if (process.env.NODE_ENV === 'development' && typeof window !== 'undefined') {
  // @ts-ignore
  window.claudeFlowStore = useAppStore;
  // @ts-ignore
  window.getStoreSnapshot = getStoreSnapshot;
  // @ts-ignore
  window.restoreStoreSnapshot = restoreStoreSnapshot;
}