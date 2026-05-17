import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { GoogleAnalytics } from "@next/third-parties/google";
import "./globals.css";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import PostHogProvider from "@/components/PostHogProvider";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://cyberarmor.ai"),
  title: {
    default: "CyberArmor.AI — AI Security Runtime for Governed Enterprise AI",
    template: "%s | CyberArmor.AI",
  },
  description:
    "CyberArmor.AI helps enterprises control and prove AI activity with detection, policy enforcement, redaction, routing, identity, response, audit, and decision-level evidence.",
  keywords: [
    "AI security platform",
    "enterprise AI security",
    "AI governance platform",
    "shadow AI security",
    "AI runtime protection",
    "AI agent security",
    "cyber trust platform",
    "secure enterprise AI adoption",
    "AI policy enforcement",
    "AI data protection",
  ],
  authors: [{ name: "CyberArmor AI, Inc." }],
  creator: "CyberArmor AI, Inc.",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://cyberarmor.ai",
    siteName: "CyberArmor.AI",
    title: "CyberArmor.AI — AI Security Runtime for Governed Enterprise AI",
    description:
      "The AI security runtime for governed enterprise AI. Detect risk, enforce policy, redact sensitive data in supported paths, route approved provider use, and preserve decision-level evidence.",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "CyberArmor.AI Platform",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "CyberArmor.AI — AI Security Runtime",
    description:
      "Control and prove enterprise AI activity across users, applications, agents, APIs, providers, models, and data.",
    images: ["/og-image.png"],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true },
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const gaId = process.env.NEXT_PUBLIC_GA_ID;
  return (
    <html lang="en" className={`${inter.variable} h-full`}>
      <body className="min-h-full flex flex-col antialiased" style={{ backgroundColor: "#000000", color: "#ffffff" }}>
        <PostHogProvider>
          <Navbar />
          <main className="flex-1">{children}</main>
          <Footer />
        </PostHogProvider>
        {gaId ? <GoogleAnalytics gaId={gaId} /> : null}
      </body>
    </html>
  );
}
