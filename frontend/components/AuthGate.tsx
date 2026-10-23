"use client";
import { useEffect, useState, type ReactNode } from "react";
import { fetchMe, type MeInfo } from "../lib/api";
import SignInCard from "./SignInCard";

// Client-side second layer of the sign-in gate for protected pages.
// The middleware keeps signed-out visitors from ever receiving these
// pages in sign-in mode; this wrapper covers the moments the
// middleware could not decide (identity endpoint briefly
// unreachable) by swapping the page for the sign-in card the moment
// /api/me resolves to "github mode, signed out". In access-code
// (fallback) mode, and for signed-in users, it renders children
// untouched, exactly as before.
export default function AuthGate({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<MeInfo | null>(null);

  useEffect(() => {
    let live = true;
    fetchMe().then((m) => { if (live) setMe(m); });
    return () => { live = false; };
  }, []);

  if (me && me.auth_mode === "github" && !me.signed_in) {
    return <SignInCard />;
  }
  return <>{children}</>;
}
