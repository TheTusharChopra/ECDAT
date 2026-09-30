import { networkInterfaces } from "node:os";
import type { NextConfig } from "next";

/**
 * Every non-internal IPv4 address this machine currently holds.
 *
 * `next dev` advertises the LAN address in its banner ("Network: http://…"), and opening
 * that URL makes every `/_next/*` request cross-origin -- which the dev server rejects
 * with 403 unless the host is allow-listed. Reading the interfaces at startup keeps that
 * working after a DHCP lease change or a move to a different network, which a hard-coded
 * address would not.
 */
function localAddresses(): string[] {
  const addresses: string[] = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) addresses.push(entry.address);
    }
  }
  return addresses;
}

const nextConfig: NextConfig = {
  // Dev-only. Next blocks cross-origin requests to dev assets and endpoints by default;
  // the server is initialised with `localhost`, so anything else -- 127.0.0.1, the LAN
  // address in its own startup banner -- 403s on every chunk. A 403'd chunk means React
  // never hydrates, which in turn means no API request is ever made, so this single
  // setting is what stands between a working page and an empty one.
  //
  // The production server (`next build && next start`) has no such restriction.
  allowedDevOrigins: ["127.0.0.1", ...localAddresses()],

  // The dev overlay's default bottom-left position lands directly on the
  // sidebar footer (Scan / Settings), so it covers navigation during a live
  // walkthrough. Moved rather than disabled: compile and runtime errors should
  // stay visible while building.
  devIndicators: {
    position: "bottom-right",
  },

  async rewrites() {
    const backendUrl = process.env.ECDAT_BACKEND_INTERNAL_URL || "http://127.0.0.1:8787";
    return [
      {
        source: "/api/backend/:path*",
        destination: `${backendUrl}/:path*`,
      },
    ];
  },
};

export default nextConfig;
