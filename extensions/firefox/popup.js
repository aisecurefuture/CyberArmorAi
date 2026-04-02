browser.runtime.sendMessage({ type: 'getStatus' }).then(data => {
  document.getElementById('policyCount').textContent = data?.policies || 0;
  const auth = data?.lastAuthStatus || {};
  document.getElementById('authMode').textContent = formatAuthMode(auth);
  if (!data?.active) {
    document.getElementById('statusDot').className = 'dot red';
    document.getElementById('statusText').textContent = 'Inactive';
  }
});
document.getElementById('optionsLink').addEventListener('click', () => {
  browser.runtime.openOptionsPage();
});

function formatAuthMode(info) {
  const mode = info?.mode || 'unknown';
  if (mode === 'native_ml_kem') return 'Native ML-KEM';
  if (mode === 'x25519_fallback') return 'X25519 fallback';
  if (mode === 'plaintext_fallback') return 'Plaintext fallback';
  if (mode === 'precomputed_pqc') return 'Precomputed PQC';
  return 'Unknown';
}
