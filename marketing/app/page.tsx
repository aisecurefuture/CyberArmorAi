import type { Metadata } from "next";
import Hero from "@/components/sections/Hero";
import TrustBand from "@/components/sections/TrustBand";
import ProblemStatement from "@/components/sections/ProblemStatement";
import PlatformOverview from "@/components/sections/PlatformOverview";
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
  title: "CyberArmor AI — Enterprise AI Security & Cyber Trust Platform",
  description:
    "One control layer for enterprise AI. CyberArmor.AI unifies discovery, policy enforcement, runtime protection, and evidence so teams can stop pre-breach AI risk before it becomes exposure.",
};

export default function HomePage() {
  return (
    <>
      <Hero />
      <TrustBand />
      <ProblemStatement />
      <PlatformOverview />
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
