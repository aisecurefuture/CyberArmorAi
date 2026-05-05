browser.storage.sync.get('cyberarmor_config').then(data => {
  const cfg = data.cyberarmor_config || {};
  document.getElementById('url').value = cfg.controlPlaneUrl || '';
  document.getElementById('key').value = cfg.apiKey || '';
  document.getElementById('tenant').value = cfg.tenantId || 'default';
  document.getElementById('bootstrap').value = cfg.bootstrapToken || '';
});
document.getElementById('save').addEventListener('click', () => {
  browser.storage.sync.set({
    cyberarmor_config: {
      controlPlaneUrl: document.getElementById('url').value,
      apiKey: document.getElementById('key').value,
      tenantId: document.getElementById('tenant').value,
      bootstrapToken: document.getElementById('bootstrap').value,
    }
  }).then(() => { document.getElementById('msg').textContent = 'Saved!'; });
});
document.getElementById('redeem').addEventListener('click', async () => {
  const controlPlaneUrl = document.getElementById('url').value;
  const bootstrapToken = document.getElementById('bootstrap').value;
  if (!bootstrapToken) {
    document.getElementById('msg').textContent = 'Enter a bootstrap token first.';
    return;
  }
  try {
    const response = await fetch(`${controlPlaneUrl.replace(/\/$/, '')}/bootstrap/redeem`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bootstrap_token: bootstrapToken,
        package_key: 'firefox-extension',
        subject_type: 'browser_extension',
        subject_name: 'firefox-extension',
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || `Redeem failed (${response.status})`);
    }
    document.getElementById('key').value = data.service_api_key || '';
    document.getElementById('tenant').value = data.tenant_id || document.getElementById('tenant').value;
    document.getElementById('bootstrap').value = '';
    await browser.storage.sync.set({
      cyberarmor_config: {
        controlPlaneUrl: data.control_plane_url || controlPlaneUrl,
        apiKey: data.service_api_key || '',
        tenantId: data.tenant_id || document.getElementById('tenant').value,
        bootstrapToken: '',
      }
    });
    document.getElementById('msg').textContent = 'Bootstrap token redeemed successfully.';
  } catch (error) {
    document.getElementById('msg').textContent = error.message || String(error);
  }
});
