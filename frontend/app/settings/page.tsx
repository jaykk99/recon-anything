"use client";
import { useEffect, useState } from "react";
import { fetchMe, getCode, type MeInfo } from "../../lib/api";
import AuthGate from "../../components/AuthGate";

function SettingsPageInner() {
  const [me, setMe] = useState<MeInfo | null>(null);

  useEffect(() => { fetchMe().then(setMe); }, []);

  return (
    <div className="space-y-4 max-w-2xl">
      <h1 className="text-lg font-semibold">Settings</h1>
      <div className="card p-4 space-y-2">
        <h2 className="font-semibold text-sky-300">Account</h2>
        <p className="text-sm text-slate-400">
          {me?.auth_mode === "github"
            ? `Signed in with GitHub${me.user ? ` as ${me.user.login}` : ""}.`
            : `Access code: ${getCode() ? "set" : "not set"} (set it on the home page).`}
        </p>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <AuthGate>
      <SettingsPageInner />
    </AuthGate>
  );
}
