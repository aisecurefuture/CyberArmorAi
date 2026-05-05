import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class", '[data-theme="dark"]'],
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#000000",
        surface: "#0F1117",
        "surface-2": "#12151E",
        border: "#1E2335",
        "border-light": "#252D42",
        primary: "#00A3FF",
        "primary-dark": "#0066CC",
        "primary-glow": "rgba(0,163,255,0.15)",
        "text-primary": "#FFFFFF",
        "text-muted": "#8892A4",
        "text-subtle": "#4A5568",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "monospace"],
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic":
          "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))",
        "hero-gradient":
          "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.12) 0%, transparent 60%)",
        "card-gradient":
          "linear-gradient(135deg, rgba(0,163,255,0.05) 0%, transparent 100%)",
        "glow-gradient":
          "radial-gradient(ellipse 60% 40% at 50% 100%, rgba(0,163,255,0.08) 0%, transparent 70%)",
        "section-gradient":
          "linear-gradient(180deg, #000000 0%, #0A0A0F 50%, #000000 100%)",
      },
      boxShadow: {
        glow: "0 0 40px rgba(0,163,255,0.15)",
        "glow-sm": "0 0 20px rgba(0,163,255,0.1)",
        card: "0 1px 0 0 rgba(30,35,53,1), 0 0 0 1px rgba(30,35,53,0.5)",
        "card-hover":
          "0 0 0 1px rgba(0,163,255,0.3), 0 4px 40px rgba(0,163,255,0.08)",
      },
      animation: {
        "fade-up": "fadeUp 0.6s ease-out forwards",
        "fade-in": "fadeIn 0.5s ease-out forwards",
        pulse: "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "gradient-shift": "gradientShift 8s ease infinite",
        float: "float 6s ease-in-out infinite",
      },
      keyframes: {
        fadeUp: {
          from: { opacity: "0", transform: "translateY(24px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        fadeIn: {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        gradientShift: {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-10px)" },
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
