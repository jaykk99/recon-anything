import "./globals.css";
import type { Metadata } from "next";
import { headers } from "next/headers";
import AuthStatus from "../components/AuthStatus";

export const metadata: Metadata = {
  title: "ReconAnything",
  description: "Universal OSINT and attack-surface recon",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // The middleware stamps the request with the app's auth state.
  // In sign-in mode a signed-out visitor gets ONLY the brand and
  // the sign-in link - no app tabs are served at all. In fallback
  // (access-code) mode, and whenever the state could not be
  // determined, the header renders exactly as before.
  const h = headers();
  const ghAnon = h.get("x-recon-auth-mode") === "github"
    && h.get("x-recon-signed-in") !== "1";
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen">
        <header className="border-b border-slate-800 px-6 py-3 flex items-center gap-3">
          <a href="/" className="text-xl font-bold text-sky-300">ReconAnything</a>
          <span className="text-xs text-slate-500">universal recon, passive by default</span>
          <nav className="ml-auto flex gap-4 text-sm text-slate-400">
            {ghAnon ? (
              <a href="/api/auth/github" className="text-sky-300 hover:text-sky-200">
                Sign in with GitHub
              </a>
            ) : (
              <>
                <a href="/" className="hover:text-sky-300">New scan</a>
                <a href="/keys" className="hover:text-sky-300">API keys</a>
                <a href="/hunters" className="hover:text-sky-300">Hunters</a>
                <a href="/runs" className="hover:text-sky-300">Runs</a>
                <a href="/pricing" className="hover:text-sky-300">Pricing</a>
                <a href="/settings" className="hover:text-sky-300">Settings</a>
                <AuthStatus />
              </>
            )}
          </nav>
        </header>
        <main className="max-w-6xl mx-auto px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
