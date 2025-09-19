import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: 'var(--background)',
        foreground: 'var(--foreground)',
        terminal: {
          bg: '#1e1e1e',
          text: '#f0f0f0',
          cursor: '#00ff00',
          selection: '#3a3a3a',
        },
        sidebar: {
          bg: '#2a2a2a',
          border: '#404040',
          text: '#e0e0e0',
          hover: '#3a3a3a',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
export default config