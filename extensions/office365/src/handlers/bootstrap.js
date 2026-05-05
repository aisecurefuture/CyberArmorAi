async function redeemBootstrapConfig(cfg, packageKey, subjectName) {
  if (!cfg?.bootstrapToken || cfg?.apiKey) {
    return cfg;
  }
  const response = await fetch(`${String(cfg.serverUrl || "http://localhost:8000").replace(/\/$/, "")}/bootstrap/redeem`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      bootstrap_token: cfg.bootstrapToken,
      package_key: packageKey,
      subject_type: "extension",
      subject_name: subjectName,
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Bootstrap redeem failed (${response.status})`);
  }
  return {
    ...cfg,
    serverUrl: data.control_plane_url || cfg.serverUrl,
    apiKey: data.service_api_key || cfg.apiKey,
    tenantId: data.tenant_id || cfg.tenantId,
    bootstrapToken: "",
  };
}

export { redeemBootstrapConfig };
