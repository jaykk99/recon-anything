import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "ReconAnything",
  description: "Universal OSINT and attack-surface recon",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen">
        <header className="border-b border-slate-800 px-6 py-3 flex items-center gap-3">
          <a href="/" className="text-xl font-bold text-sky-300">ReconAnything</a>
          <span className="text-xs text-slate-500">universal recon, passive by default</span>
          <nav className="ml-auto flex gap-4 text-sm text-slate-400">
            <a href="/" className="hover:text-sky-300">New scan</a>
            <a href="/keys" className="hover:text-sky-300">API keys</a>
            <a href="/runs" className="hover:text-sky-300">Runs</a>
          </nav>
        </header>
        <main className="max-w-6xl mx-auto px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
