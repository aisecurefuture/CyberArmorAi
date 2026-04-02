import esbuild from "esbuild";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const entry = path.join(__dirname, "src", "pqc_auth_entry.js");
const outputs = [
  path.join(__dirname, "pqc_auth.js"),
  path.join(__dirname, "..", "firefox", "pqc_auth.js"),
];

for (const outfile of outputs) {
  await esbuild.build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    format: "iife",
    globalName: "CyberArmorPQCAuthBundle",
    platform: "browser",
    target: ["chrome109", "firefox109"],
    logLevel: "info",
  });
}
