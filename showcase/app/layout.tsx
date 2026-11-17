import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Torn Note — Authorization for actions that matter",
  description: "Discover how Torn Note explores verifiable, single-use authorization for consequential business actions, beyond identity and login.",
  applicationName: "Torn Note",
  openGraph: {
    title: "Torn Note — Not just who you are. What you're allowed to do.",
    description: "An animated, plain-language introduction to issuer-committed, single-use transaction authorization.",
    type: "website",
  },
};

export const viewport: Viewport = { themeColor: "#070c12", colorScheme: "dark" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" className="dark"><body>{children}</body></html>;
}
