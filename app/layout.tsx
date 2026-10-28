import type { Metadata } from "next";
import { JetBrains_Mono, Space_Grotesk } from "next/font/google";
import "./globals.css";

const sans = Space_Grotesk({ subsets: ["latin"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "DevSec Guard: AI Scraper & Vulnerability Auditor",
  description:
    "Scan any site for AI crawler exposure, missing security headers and leaked dev files, then get a security grade and fix.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="min-h-screen bg-ink-950 font-sans text-slate-200 antialiased">{children}</body>
    </html>
  );
}
