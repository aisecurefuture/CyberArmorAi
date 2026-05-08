import type { Metadata } from "next";
import Hero from "@/components/sections/Hero";
import TrustBand from "@/components/sections/TrustBand";
import ProblemStatement from "@/components/sections/ProblemStatement";
import WhyExistingToolsMissThis from "@/components/sections/WhyExistingToolsMissThis";
import PlatformOverview from "@/components/sections/PlatformOverview";
import ProofOfReality from "@/components/sections/ProofOfReality";
import ProtectionBackedEvidence from "@/components/sections/ProtectionBackedEvidence";
import ProductAvailability from "@/components/sections/ProductAvailability";
import FrameworkAlignment from "@/components/sections/FrameworkAlignment";
import Capabilities from "@/components/sections/Capabilities";
import Differentiators from "@/components/sections/Differentiators";
import UseCases from "@/components/sections/UseCases";
import HowItWorks from "@/components/sections/HowItWorks";
import EvidenceLayer from "@/components/sections/EvidenceLayer";
import WhyNow from "@/components/sections/WhyNow";
import FounderCredibility from "@/components/sections/FounderCredibility";
import BrandClarification from "@/components/sections/BrandClarification";
import BuyerBoundary from "@/components/sections/BuyerBoundary";
import FAQ from "@/components/sections/FAQ";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "CyberArmor.AI — Stop hostile web content before it becomes AI context",
  description:
    "Pre-ingestion AI context security for URLs, web pages, prompts, agents, browsers, apps, and enterprise AI workflows. CyberArmor.AI gates external URLs and web content before they reach AI context or AI agents or users — detecting promptware, hidden prompt injection, phishing, and IOCs. Then controls and proves enterprise AI activity with runtime enforcement, redaction, routing, identity, and decision-level evidence.",
  openGraph: {
    title: "CyberArmorAI — Stop hostile web content before it becomes AI context",
    description:
      "Pre-ingestion AI trust control for URLs, prompts, pages, agents, browsers, apps, and enterprise AI workflows.",
    url: "https://cyberarmor.ai/",
    siteName: "CyberArmorAI",
    images: [
      {
        url: "/CyberArmorLinkImage.png?v=20260508",
        width: 1200,
        height: 630,
        alt: "CyberArmorAI — Stop hostile web content before it becomes AI context",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "CyberArmorAI — Stop hostile web content before it becomes AI context",
    description:
      "Pre-ingestion AI trust control for URLs, prompts, pages, agents, browsers, apps, and enterprise AI workflows.",
    images: ["/CyberArmorLinkImage.png?v=20260508"],
  },
  };

export default function HomePage() {
  return (
    <>
      <Hero />
      <TrustBand />
      <ProblemStatement />
      <WhyExistingToolsMissThis />
      <PlatformOverview />
      <ProofOfReality />
      <ProtectionBackedEvidence />
      <ProductAvailability />
      <FrameworkAlignment />
      <Capabilities />
      <Differentiators />
      <UseCases />
      <HowItWorks />
      <EvidenceLayer />
      <WhyNow />
      <FounderCredibility />
      <BrandClarification />
      <BuyerBoundary />
      <FAQ />
      <FinalCTA />
    </>
  );
}
