/**
 * CyberArmor Protect — Safari Background (Service Worker)
 * Safari Web Extension using browser.* APIs (limited DNR support).
 */

const AI_DOMAINS = new Set([
  'api.openai.com','api.anthropic.com','generativelanguage.googleapis.com',
  'chatgpt.com','claude.ai','gemini.google.com','copilot.microsoft.com',
]);

let policies = [];

// Load stored config
browser.storage.sync.get(['cyberarmor_config', 'cyberarmor_policies']).then(data => {
  if (data.cyberarmor_policies) policies = data.cyberarmor_policies;
});

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStatus') {
    sendResponse({ active: true, policies: policies.length });
  } else if (msg.type === 'aiActivity') {
    console.log('[CyberArmor] AI activity:', msg.domain);
  }
  return true;
});

console.log('[CyberArmor Protect] Safari extension loaded');
