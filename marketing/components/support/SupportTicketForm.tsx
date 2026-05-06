"use client";

import { FormEvent, useMemo, useState } from "react";
import { UploadCloud } from "lucide-react";

const severityOptions = [
  { value: "S1", label: "S1 - outage or security-critical" },
  { value: "S2", label: "S2 - major workflow blocked" },
  { value: "S3", label: "S3 - degraded or isolated" },
];

const surfaceOptions = [
  "Deployment / routing",
  "Customer portal",
  "Admin portal",
  "Docs / support",
  "Bootstrap / enrollment",
  "Runtime / policy",
  "Detection / evidence",
  "Other",
];

const MAX_FILES = 3;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;

type SubmitState =
  | { status: "idle"; message: string }
  | { status: "submitting"; message: string }
  | { status: "success"; message: string }
  | { status: "error"; message: string };

const fieldStyle = {
  width: "100%",
  boxSizing: "border-box",
  border: "1px solid #1E2335",
  borderRadius: 10,
  background: "#050508",
  color: "#ffffff",
  padding: "12px 13px",
  fontSize: 14,
  outline: "none",
} as const;

const labelStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 8,
  color: "#D6E2F0",
  fontSize: 13,
  fontWeight: 700,
} as const;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function validateFiles(files: FileList | null): string | null {
  if (!files || files.length === 0) {
    return null;
  }

  if (files.length > MAX_FILES) {
    return `Attach up to ${MAX_FILES} files.`;
  }

  let total = 0;
  for (const file of Array.from(files)) {
    total += file.size;
    if (file.size > MAX_FILE_BYTES) {
      return `${file.name} exceeds ${formatBytes(MAX_FILE_BYTES)}.`;
    }
  }

  if (total > MAX_TOTAL_BYTES) {
    return `Total upload size must stay under ${formatBytes(MAX_TOTAL_BYTES)}.`;
  }

  return null;
}

export default function SupportTicketForm() {
  const [state, setState] = useState<SubmitState>({ status: "idle", message: "" });
  const [files, setFiles] = useState<FileList | null>(null);
  const fileSummary = useMemo(() => {
    if (!files || files.length === 0) {
      return "No files selected";
    }
    return Array.from(files).map((file) => `${file.name} (${formatBytes(file.size)})`).join(", ");
  }, [files]);

  async function submitTicket(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const validationError = validateFiles(files);
    if (validationError) {
      setState({ status: "error", message: validationError });
      return;
    }

    setState({ status: "submitting", message: "Submitting support ticket..." });

    try {
      const response = await fetch("/api/support", {
        method: "POST",
        body: new FormData(form),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || "Support ticket submission failed");
      }
      form.reset();
      setFiles(null);
      setState({ status: "success", message: `Support ticket submitted. Reference: ${data.ticketId || "received"}.` });
    } catch (error) {
      setState({
        status: "error",
        message: error instanceof Error ? error.message : "Support ticket submission failed",
      });
    }
  }

  return (
    <section
      id="ticket"
      style={{
        background: "#0F1117",
        border: "1px solid #1E2335",
        borderRadius: 16,
        padding: "clamp(20px, 4vw, 32px)",
        marginBottom: 52,
      }}
    >
      <div style={{ display: "flex", gap: 14, alignItems: "flex-start", marginBottom: 22 }}>
        <div style={{
          width: 42,
          height: 42,
          borderRadius: 10,
          border: "1px solid rgba(0,163,255,0.2)",
          background: "rgba(0,163,255,0.08)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}>
          <UploadCloud size={20} style={{ color: "#00A3FF" }} />
        </div>
        <div>
          <h2 style={{ color: "#ffffff", fontSize: 24, fontWeight: 800, letterSpacing: "-0.02em", marginBottom: 8 }}>
            Open Support Ticket
          </h2>
          <p style={{ color: "#8892A4", fontSize: 14.5, lineHeight: 1.7, maxWidth: 720 }}>
            Submit a support request and attach logs securely. Uploads are validated server-side,
            sent through the configured TLS mail transport, and are not written to marketing server disk.
          </p>
        </div>
      </div>

      <form onSubmit={submitTicket} encType="multipart/form-data">
        <input type="text" name="_hp" tabIndex={-1} autoComplete="off" style={{ display: "none" }} />

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16, marginBottom: 16 }}>
          <label style={labelStyle}>
            Name
            <input name="name" required minLength={2} maxLength={100} autoComplete="name" style={fieldStyle} />
          </label>
          <label style={labelStyle}>
            Work email
            <input name="email" required type="email" maxLength={254} autoComplete="email" style={fieldStyle} />
          </label>
          <label style={labelStyle}>
            Company
            <input name="company" required maxLength={120} autoComplete="organization" style={fieldStyle} />
          </label>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16, marginBottom: 16 }}>
          <label style={labelStyle}>
            Severity
            <select name="severity" required defaultValue="S3" style={fieldStyle}>
              {severityOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <label style={labelStyle}>
            Affected surface
            <select name="surface" required defaultValue="Deployment / routing" style={fieldStyle}>
              {surfaceOptions.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label style={labelStyle}>
            Tenant ID
            <input name="tenantId" maxLength={120} placeholder="optional" style={fieldStyle} />
          </label>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16, marginBottom: 16 }}>
          <label style={labelStyle}>
            Subject
            <input name="subject" required minLength={5} maxLength={160} placeholder="Endpoint enrollment failing" style={fieldStyle} />
          </label>
          <label style={labelStyle}>
            Affected URL
            <input name="affectedUrl" maxLength={500} placeholder="https://app.cyberarmor.ai/..." style={fieldStyle} />
          </label>
          <label style={labelStyle}>
            Request or trace ID
            <input name="requestId" maxLength={160} placeholder="optional" style={fieldStyle} />
          </label>
        </div>

        <label style={{ ...labelStyle, marginBottom: 16 }}>
          What happened?
          <textarea
            name="description"
            required
            minLength={20}
            maxLength={4000}
            rows={7}
            placeholder="Describe the issue, what you expected, what changed, and any commands or timestamps that help reproduce it."
            style={{ ...fieldStyle, resize: "vertical", minHeight: 150, lineHeight: 1.6 }}
          />
        </label>

        <div style={{
          border: "1px dashed #2D3750",
          borderRadius: 14,
          background: "#050508",
          padding: 18,
          marginBottom: 16,
        }}>
          <label style={labelStyle}>
            Secure log upload
            <input
              name="logs"
              type="file"
              multiple
              accept=".log,.txt,.json,.ndjson,.csv,.har,.yaml,.yml,.zip,.gz,.tgz"
              onChange={(event) => {
                setFiles(event.currentTarget.files);
                const validationError = validateFiles(event.currentTarget.files);
                if (validationError) {
                  setState({ status: "error", message: validationError });
                } else if (state.status === "error") {
                  setState({ status: "idle", message: "" });
                }
              }}
              style={{ ...fieldStyle, padding: 10 }}
            />
          </label>
          <p style={{ color: "#8892A4", fontSize: 12.5, lineHeight: 1.6, marginTop: 10 }}>
            Allowed: .log, .txt, .json, .har, .yaml, .zip, .gz, and .tgz. Up to {MAX_FILES} files,
            {` ${formatBytes(MAX_FILE_BYTES)} each and ${formatBytes(MAX_TOTAL_BYTES)} total.`}
          </p>
          <p style={{ color: "#60C8FF", fontSize: 12.5, lineHeight: 1.6, marginTop: 8, overflowWrap: "anywhere" }}>
            {fileSummary}
          </p>
        </div>

        <label style={{ display: "flex", gap: 10, alignItems: "flex-start", color: "#A0AEC0", fontSize: 13.5, lineHeight: 1.6, marginBottom: 20 }}>
          <input name="logConsent" value="true" type="checkbox" style={{ marginTop: 3, flexShrink: 0 }} />
          I have reviewed attached logs for sensitive secrets where practical and approve them for CyberArmor support review.
        </label>

        <div style={{ display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap" }}>
          <button
            type="submit"
            disabled={state.status === "submitting"}
            className="btn-primary"
            style={{ padding: "13px 26px", fontSize: 15, opacity: state.status === "submitting" ? 0.75 : 1 }}
          >
            {state.status === "submitting" ? "Submitting..." : "Submit Ticket"}
          </button>
          {state.message && (
            <p
              role="status"
              style={{
                color: state.status === "success" ? "#22C55E" : state.status === "error" ? "#F87171" : "#8892A4",
                fontSize: 13.5,
                lineHeight: 1.5,
                margin: 0,
              }}
            >
              {state.message}
            </p>
          )}
        </div>
      </form>
    </section>
  );
}
