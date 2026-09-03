import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import { Providers } from "./providers";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "ECDAT — Enterprise Cryptographic Discovery & Analysis",
    template: "%s · ECDAT",
  },
  description:
    "Discover cryptographic assets across an enterprise estate, assess classical risk and quantum exposure on independent axes, and produce an evidence-backed post-quantum migration roadmap.",
  applicationName: "ECDAT",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // `suppressHydrationWarning` is required by next-themes: it sets the theme
    // class on <html> before React hydrates, so server and client markup differ
    // by design on this one element.
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="ecdat-scrollbar flex min-h-full flex-col">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
