import type { Metadata } from "next";
import Hero from "@/components/sections/Hero";
import TrustBand from "@/components/sections/TrustBand";
import ProblemStatement from "@/components/sections/ProblemStatement";
import PlatformOverview from "@/components/sections/PlatformOverview";
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
import FAQ from "@/components/sections/FAQ";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "CyberArmor.AI — AI Security Runtime for Governed Enterprise AI",
  description:
    "CyberArmor.AI controls and proves enterprise AI activity across users, applications, agents, APIs, providers, and models with runtime enforcement, redaction, routing, identity, and decision-level evidence.",
};

export default function HomePage() {
  return (
    <>
      <Hero />
      <TrustBand />
      <ProblemStatement />
      <PlatformOverview />
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
      <FAQ />
      <FinalCTA />
    </>
  );
}
