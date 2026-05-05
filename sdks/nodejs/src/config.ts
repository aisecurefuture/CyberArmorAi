/** CyberArmor SDK configuration. */
import fetch from 'node-fetch';

export interface CyberArmorConfig {
  controlPlaneUrl: string;
  agentId: string;
  agentSecret: string;
  tenantId?: string;
  bootstrapToken?: string;
  enforceMode?: 'block' | 'monitor';
  timeoutMs?: number;
  auditBatchSize?: number;
  auditFlushIntervalMs?: number;
  failOpen?: boolean;
}

export function loadConfigFromEnv(): CyberArmorConfig {
  return {
    controlPlaneUrl:
      process.env.CYBERARMOR_CONTROL_PLANE_URL || process.env.CYBERARMOR_URL || 'https://cp.cyberarmor.ai',
    agentId:
      process.env.CYBERARMOR_AGENT_ID || '',
    agentSecret:
      process.env.CYBERARMOR_AGENT_SECRET || process.env.CYBERARMOR_API_KEY || '',
    tenantId:
      process.env.CYBERARMOR_TENANT_ID || 'default',
    bootstrapToken:
      process.env.CYBERARMOR_BOOTSTRAP_TOKEN || '',
    enforceMode: (process.env.CYBERARMOR_ENFORCE_MODE as 'block' | 'monitor') || 'block',
    failOpen: process.env.CYBERARMOR_FAIL_OPEN !== 'false',
  };
}

export interface BootstrapRedeemResult {
  install_id: string;
  package_key: string;
  tenant_id: string;
  subject_type: string;
  subject_id: string;
  service_api_key: string;
  control_plane_url: string;
  runtime_env: Record<string, string>;
  config: Record<string, string>;
}

export async function redeemBootstrapToken(config?: Partial<CyberArmorConfig>): Promise<BootstrapRedeemResult | null> {
  const envConfig = loadConfigFromEnv();
  const merged: CyberArmorConfig = {
    ...envConfig,
    ...config,
  };
  if (!merged.bootstrapToken || merged.agentSecret) {
    return null;
  }
  const response = await fetch(`${merged.controlPlaneUrl.replace(/\/$/, '')}/bootstrap/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bootstrap_token: merged.bootstrapToken,
      package_key: 'sdk-nodejs',
      subject_type: 'sdk_client',
      subject_name: merged.agentId || 'nodejs-sdk',
    }),
  });
  if (!response.ok) {
    throw new Error(`Bootstrap redeem failed (${response.status}): ${await response.text()}`);
  }
  return await response.json() as BootstrapRedeemResult;
}

export async function loadConfigFromEnvAsync(config?: Partial<CyberArmorConfig>): Promise<CyberArmorConfig> {
  const envConfig = loadConfigFromEnv();
  const merged: CyberArmorConfig = {
    ...envConfig,
    ...config,
  };
  const redeemed = await redeemBootstrapToken(merged);
  if (!redeemed) {
    return merged;
  }
  return {
    ...merged,
    controlPlaneUrl: redeemed.control_plane_url || merged.controlPlaneUrl,
    agentId: redeemed.subject_id || merged.agentId,
    agentSecret: redeemed.service_api_key || merged.agentSecret,
    tenantId: redeemed.tenant_id || merged.tenantId,
    bootstrapToken: '',
  };
}
