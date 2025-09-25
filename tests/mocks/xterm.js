// Mock xterm.js for testing
const mockTerminal = {
  write: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  blur: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(() => ({ dispose: jest.fn() })),
  onResize: jest.fn(() => ({ dispose: jest.fn() })),
  onTitleChange: jest.fn(() => ({ dispose: jest.fn() })),
  open: jest.fn(),
  loadAddon: jest.fn(),
  fit: jest.fn(),
  resize: jest.fn(),
  scrollToBottom: jest.fn(),
  scrollToTop: jest.fn(),
  selectAll: jest.fn(),
  getSelection: jest.fn(() => ''),
  hasSelection: jest.fn(() => false),
  clearSelection: jest.fn(),
  element: {
    classList: {
      add: jest.fn(),
      remove: jest.fn(),
      contains: jest.fn(() => false),
    },
    querySelector: jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 1000,
      clientHeight: 600,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      focus: jest.fn(),
    })),
    offsetHeight: 600,
    offsetWidth: 800,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    scrollIntoView: jest.fn(),
  },
  cols: 80,
  rows: 24,
  unicode: {
    activeVersion: '11',
  },
  buffer: {
    active: {
      type: 'normal',
      cursorY: 0,
      cursorX: 0,
      length: 24,
      getLine: jest.fn(() => ({
        translateToString: jest.fn(() => ''),
        isWrapped: false,
      })),
    },
    normal: {},
    alternate: {},
  },
  modes: {
    applicationCursorKeysMode: false,
    applicationKeypadMode: false,
    bracketedPasteMode: false,
    insertMode: false,
  },
  options: {
    cols: 80,
    rows: 24,
    cursorBlink: true,
    fontSize: 14,
  },
};

// Mock Terminal constructor
export const Terminal = jest.fn().mockImplementation((options = {}) => ({
  ...mockTerminal,
  options: { ...mockTerminal.options, ...options },
  cols: options.cols || 80,
  rows: options.rows || 24,
}));

// Mock addons
export const FitAddon = jest.fn().mockImplementation(() => ({
  fit: jest.fn(),
  proposeDimensions: jest.fn(() => ({ cols: 80, rows: 24 })),
}));

export const WebLinksAddon = jest.fn().mockImplementation(() => ({
  activate: jest.fn(),
  dispose: jest.fn(),
}));

export const SearchAddon = jest.fn().mockImplementation(() => ({
  findNext: jest.fn(),
  findPrevious: jest.fn(),
}));

export const SerializeAddon = jest.fn().mockImplementation(() => ({
  serialize: jest.fn(() => 'terminal content'),
}));

export const Unicode11Addon = jest.fn().mockImplementation(() => ({
  activate: jest.fn(),
  dispose: jest.fn(),
}));

export const WebglAddon = jest.fn().mockImplementation(() => ({
  activate: jest.fn(),
  dispose: jest.fn(),
}));

export const CanvasAddon = jest.fn().mockImplementation(() => ({
  activate: jest.fn(),
  dispose: jest.fn(),
}));

// Mock the modules
jest.mock('@xterm/xterm', () => ({
  Terminal,
}));

jest.mock('@xterm/addon-fit', () => ({
  FitAddon,
}));

jest.mock('@xterm/addon-web-links', () => ({
  WebLinksAddon,
}));

jest.mock('@xterm/addon-search', () => ({
  SearchAddon,
}));

jest.mock('@xterm/addon-serialize', () => ({
  SerializeAddon,
}));

jest.mock('@xterm/addon-unicode11', () => ({
  Unicode11Addon,
}));

jest.mock('@xterm/addon-webgl', () => ({
  WebglAddon,
}));

jest.mock('@xterm/addon-canvas', () => ({
  CanvasAddon,
}));

export default {
  Terminal,
  FitAddon,
  WebLinksAddon,
  SearchAddon,
  SerializeAddon,
  Unicode11Addon,
  WebglAddon,
  CanvasAddon,
};