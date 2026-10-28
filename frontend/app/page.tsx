import { headers } from "next/headers";
import ScanHome from "../components/ScanHome";
import SignInCard from "../components/SignInCard";

// Server wrapper for the home page. The middleware stamps each
// request with the app's auth state (x-recon-auth-mode /
// x-recon-signed-in, decided against the backend's /api/me). In
// sign-in mode a signed-out visitor is served ONLY the sign-in
// card: the scan form, and with it the retired access-code field,
// is never part of the page. Signed-in users, fallback
// (access-code) mode, and any request the middleware could not
// stamp get the regular client home, whose own identity check
// still applies.
export default function HomePage() {
  const h = headers();
  const ghAnon = h.get("x-recon-auth-mode") === "github"
    && h.get("x-recon-signed-in") !== "1";
  if (ghAnon) return <SignInCard />;
  return <ScanHome />;
}
