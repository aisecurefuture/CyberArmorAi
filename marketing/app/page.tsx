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
  title: "CyberArmor.AI — Pre-Ingestion URL Trust Gate and AI Security Runtime",
  description:
    "CyberArmor.AI gates external URLs and web content before they reach AI agents or users — detecting promptware, hidden prompt injection, phishing, and IOCs. Then controls and proves enterprise AI activity with runtime enforcement, redaction, routing, identity, and decision-level evidence.",
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
