import type { NextConfig } from "next";

const isGitHubPages = process.env.GITHUB_PAGES === "true";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  env: { NEXT_PUBLIC_GITHUB_PAGES: isGitHubPages ? "true" : "false" },
  output: "export",
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  ...(isGitHubPages
    ? {
        basePath: "/torn-note-cryptography",
      }
    : {}),
};

export default nextConfig;
