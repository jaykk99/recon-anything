/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    const api = process.env.RECON_API_URL || "http://127.0.0.1:8000";
    return [
      { source: "/api/:path*", destination: `${api}/api/:path*` },
      // The MCP server lives on the backend (app/mcp_server.py, mounted
      // at /mcp). Without this rewrite the public host answers /mcp with
      // the Next app and MCP clients never reach it.
      { source: "/mcp", destination: `${api}/mcp` },
      { source: "/mcp/:path*", destination: `${api}/mcp/:path*` },
    ];
  },
};
export default nextConfig;
