import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import '@xterm/xterm/css/xterm.css';

const inter = Inter({ 
  subsets: ['latin'],
  variable: '--font-inter',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
});

export const metadata: Metadata = {
  title: 'Claude Flow UI',
  description: 'Interactive terminal and monitoring interface for Claude Flow',
  keywords: ['terminal', 'claude', 'flow', 'websocket', 'xterm', 'monitoring', 'ui'],
  authors: [{ name: 'Claude Flow Team' }],
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
        <div id="root" className="h-screen w-screen overflow-hidden">
          {children}
        </div>
      </body>
    </html>
  );
}