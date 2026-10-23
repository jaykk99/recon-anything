"use client";
import { useEffect, useState } from "react";
import { clearCode, fetchMe, signOut, type MeInfo } from "../lib/api";

// Header sign-in state. Renders ONLY in sign-in mode (GitHub OAuth
// configured server-side): a "Sign in with GitHub" link when signed
// out, or the account login + Sign out when signed in. In fallback
// (access-code) mode it renders nothing, so the header is unchanged.
export default function AuthStatus() {
  const [me, setMe] = useState<MeInfo | null>(null);

  useEffect(() => {
    fetchMe().then((m) => {
      setMe(m);
      // Sign-in mode retires the access code: drop any stored code so
      // it is never sent to the API again.
      if (m && m.auth_mode === "github") clearCode();
    });
  }, []);

  if (!me || me.auth_mode !== "github") return null;

  if (me.signed_in && me.user) {
    return (
      <span className="flex items-center gap-3">
        <span className="text-slate-300">
          {me.user.login}
          {me.is_owner ? " (owner)" : ""}
        </span>
        <button
          type="button"
          className="hover:text-sky-300"
          onClick={async () => {
            await signOut();
            window.location.href = "/";
          }}
        >
          Sign out
        </button>
      </span>
    );
  }

  return (
    <a href="/api/auth/github" className="text-sky-300 hover:text-sky-200">
      Sign in with GitHub
    </a>
  );
}
