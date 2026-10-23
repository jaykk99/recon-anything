// The one sign-in gate card for sign-in mode (GitHub OAuth
// configured server-side, access code retired). Rendered by the
// server on the home page, by AuthGate on protected pages, and by
// ScanHome if the client-side identity check resolves after first
// paint. Copy lives in exactly one place so the gate never drifts.
export default function SignInCard() {
  return (
    <div className="card p-6 space-y-4 max-w-xl">
      <h1 className="text-lg font-semibold">Sign in to run a scan</h1>
      <p className="text-sm text-slate-400">
        ReconAnything uses GitHub sign-in. Sign in to create runs,
        see your findings, export reports, and use the Crypto Pack.
        The free plan includes 3 scans a day and 1 revealed finding
        per day.
      </p>
      <p>
        <a href="/api/auth/github" className="btn px-6 py-3 min-h-[48px] inline-flex items-center text-base">
          Sign in with GitHub
        </a>
      </p>
      <p className="text-xs text-slate-500">
        Plans and pricing are on the{" "}
        <a href="/pricing" className="text-sky-300 hover:text-sky-200">pricing page</a>.
      </p>
    </div>
  );
}
