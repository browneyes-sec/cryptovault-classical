// sessionLite.js — localStorage wrapper for session persistence

const STORAGE_KEY = 'cryptovault_island';

const DEFAULT_SESSION = {
  stagesCleared: [],
  totalScore: 0,
  currentStage: null,
};

export function loadSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SESSION };
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_SESSION, ...parsed };
  } catch {
    return { ...DEFAULT_SESSION };
  }
}

export function saveSession(session) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch (e) {
    console.warn('[sessionLite] Could not save session:', e);
  }
}

export function clearSession() {
  localStorage.removeItem(STORAGE_KEY);
}
