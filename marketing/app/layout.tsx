import type { Metadata } from "next";
import { Inter } from "next/font/google";
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
    default: "CyberArmor.AI — The Enterprise AI Security & Cyber Trust Platform",
    template: "%s | CyberArmor.AI",
  },
  description:
    "CyberArmor.AI is the unified AI security and cyber trust platform that helps enterprises govern, protect, and operationalize trust across AI systems, agents, applications, and data — at scale.",
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
    title: "CyberArmor.AI — Govern, Protect, and Prove Trust Across Enterprise AI",
    description:
      "The unified AI security and cyber trust platform. Discover shadow AI, enforce policy, protect runtime environments, and generate evidence-based trust — built for enterprise scale.",
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
    title: "CyberArmor.AI — Enterprise AI Security & Cyber Trust",
    description:
      "Govern, protect, and prove trust across every AI system, agent, and workflow your enterprise runs.",
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
  return (
    <html lang="en" className={`${inter.variable} h-full`}>
      <body className="min-h-full flex flex-col antialiased" style={{ backgroundColor: "#000000", color: "#ffffff" }}>
        <PostHogProvider>
          <Navbar />
          <main className="flex-1">{children}</main>
          <Footer />
        </PostHogProvider>
      </body>
    </html>
  );
}
