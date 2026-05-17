"use client";

import Script from "next/script";

/**
 * LinkedIn Insight Tag.
 *
 * Drops the standard LinkedIn snippet on every page so Campaign Manager's
 * Website Demographics / Audience Insights surface which companies are
 * visiting the marketing site — the most actionable B2B signal we get
 * without paying for ads.
 *
 * Null-guarded: if NEXT_PUBLIC_LINKEDIN_PARTNER_ID isn't set at build
 * time, nothing renders and no requests fire. Same posture as the
 * GoogleAnalytics + PostHog guards in the layout.
 */
export default function LinkedInInsight() {
  const partnerId = process.env.NEXT_PUBLIC_LINKEDIN_PARTNER_ID;
  if (!partnerId) return null;

  // The setup script seeds window._linkedin_data_partner_ids; the loader
  // script injects insight.min.js from snap.licdn.com which then posts
  // pageviews to px.ads.linkedin.com. CSP must allow both hosts.
  return (
    <>
      <Script
        id="linkedin-insight-setup"
        strategy="afterInteractive"
        dangerouslySetInnerHTML={{
          __html: `
            _linkedin_partner_id = "${partnerId}";
            window._linkedin_data_partner_ids = window._linkedin_data_partner_ids || [];
            window._linkedin_data_partner_ids.push(_linkedin_partner_id);
          `,
        }}
      />
      <Script
        id="linkedin-insight-loader"
        strategy="afterInteractive"
        dangerouslySetInnerHTML={{
          __html: `
            (function(l) {
              if (!l){window.lintrk = function(a,b){window.lintrk.q.push([a,b])};
              window.lintrk.q=[]}
              var s = document.getElementsByTagName("script")[0];
              var b = document.createElement("script");
              b.type = "text/javascript"; b.async = true;
              b.src = "https://snap.licdn.com/li.lms-analytics/insight.min.js";
              s.parentNode.insertBefore(b, s);
            })(window.lintrk);
          `,
        }}
      />
      {/* Noscript pixel for visitors with JS disabled. Belt-and-suspenders. */}
      <noscript>
        <img
          height="1"
          width="1"
          style={{ display: "none" }}
          alt=""
          src={`https://px.ads.linkedin.com/collect/?pid=${partnerId}&fmt=gif`}
        />
      </noscript>
    </>
  );
}
