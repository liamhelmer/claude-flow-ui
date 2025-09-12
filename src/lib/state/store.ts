import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import type { AppState, TerminalSession } from '@/types';

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
}

type Store = AppState & AppActions;

const generateSessionId = () => `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

export const useAppStore = create<Store>()(
  devtools(
    (set, get) => ({
      // Initial state
      terminalSessions: [],
      activeSessionId: null,
      sidebarOpen: true,
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
    }),
    {
      name: 'claude-flow-store',
    }
  )
);