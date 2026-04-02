"use strict";
/**
 * AI Code Suggestion Monitor
 * Monitors Copilot and other AI code completions for suspicious patterns.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AIMonitor = void 0;
const SUSPICIOUS_PATTERNS = [
    { name: 'eval_usage', pattern: /\beval\s*\(/, severity: 'high' },
    { name: 'exec_usage', pattern: /\b(exec|execSync|child_process)\s*\(/, severity: 'high' },
    { name: 'shell_injection', pattern: /\b(os\.system|subprocess\.call|Runtime\.exec)\s*\(/, severity: 'critical' },
    { name: 'sql_concatenation', pattern: /["'`]\s*\+\s*.*\+\s*["'`].*(?:SELECT|INSERT|UPDATE|DELETE)/i, severity: 'high' },
    { name: 'hardcoded_secret', pattern: /(?:password|secret|token|api_key)\s*[=:]\s*["'][^"']{8,}["']/i, severity: 'critical' },
    { name: 'disable_security', pattern: /verify\s*[=:]\s*(?:false|False|0)|CURLOPT_SSL_VERIFYPEER.*0/i, severity: 'high' },
    { name: 'dangerous_deserialization', pattern: /\b(pickle\.loads|yaml\.load|unserialize)\s*\(/, severity: 'critical' },
    { name: 'xss_pattern', pattern: /innerHTML\s*=|document\.write\s*\(|\.html\s*\(/, severity: 'medium' },
];
class AIMonitor {
    constructor(policyClient) {
        this.monitoredCount = 0;
        this.policyClient = policyClient;
    }
    getMonitoredCount() { return this.monitoredCount; }
    getCompletionProvider() {
        const self = this;
        return {
            provideInlineCompletionItems(document, position, context, token) {
                // We don't provide completions — we just monitor when they're shown
                self.monitoredCount++;
                return [];
            }
        };
    }
    scanCodeSnippet(code) {
        const findings = [];
        for (const pat of SUSPICIOUS_PATTERNS) {
            const match = code.match(pat.pattern);
            if (match) {
                findings.push({ name: pat.name, severity: pat.severity, match: match[0] });
            }
        }
        return findings;
    }
}
exports.AIMonitor = AIMonitor;
//# sourceMappingURL=ai-monitor.js.map