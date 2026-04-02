"use strict";
/**
 * Policy Client — Communicates with CyberArmor control plane for policy sync and telemetry.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyClient = void 0;
const https = __importStar(require("https"));
const http = __importStar(require("http"));
const pqc_auth_1 = require("./pqc-auth");
class PolicyClient {
    constructor(url, apiKey, tenantId) {
        this.policies = [];
        this.syncTimer = null;
        this.lastAuthResult = { value: "", mode: "unknown", algorithm: "unknown" };
        this.url = url;
        this.apiKey = apiKey;
        this.tenantId = tenantId;
    }
    getPolicyCount() { return this.policies.length; }
    getPolicies() { return this.policies; }
    getLastAuthResult() { return this.lastAuthResult; }
    async startSync(intervalSeconds) {
        await this.syncPolicies();
        this.syncTimer = setInterval(() => this.syncPolicies(), intervalSeconds * 1000);
    }
    stopSync() {
        if (this.syncTimer) {
            clearInterval(this.syncTimer);
            this.syncTimer = null;
        }
    }
    async syncPolicies() {
        if (!this.url || !this.apiKey)
            return;
        try {
            const data = await this.fetch(`/policies/${this.tenantId}`);
            if (Array.isArray(data)) {
                this.policies = data;
            }
        }
        catch (e) {
            console.debug('[CyberArmor] Policy sync failed:', e);
        }
    }
    async sendTelemetry(events) {
        if (!this.url || !this.apiKey)
            return;
        try {
            await this.fetch('/telemetry/ingest', 'POST', events);
        }
        catch { }
    }
    async fetch(path, method = 'GET', body) {
        const authResult = await (0, pqc_auth_1.buildAuthHeaderResult)(this.url, this.apiKey);
        this.lastAuthResult = authResult;
        return new Promise((resolve, reject) => {
            const urlObj = new URL(path, this.url);
            const mod = urlObj.protocol === 'https:' ? https : http;
            const opts = {
                hostname: urlObj.hostname,
                port: urlObj.port,
                path: urlObj.pathname,
                method,
                headers: {
                    'x-api-key': authResult.value,
                    'Content-Type': 'application/json',
                },
            };
            const req = mod.request(opts, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch {
                        resolve(data);
                    }
                });
            });
            req.on('error', reject);
            req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
            if (body)
                req.write(JSON.stringify(body));
            req.end();
        });
    }
}
exports.PolicyClient = PolicyClient;
//# sourceMappingURL=policy-client.js.map