//! CyberArmor RASP — Rust Runtime Application Self-Protection for AI/LLM APIs.
//! Provides Tower middleware (for axum/tonic) and reqwest client wrapper.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// RASP Configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub control_plane_url: String,
    pub api_key: String,
    pub bootstrap_token: String,
    pub tenant_id: String,
    pub mode: Mode,
    pub dlp_enabled: bool,
    pub prompt_injection_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Mode {
    Monitor,
    Block,
}

impl Default for Config {
    fn default() -> Self {
        fn env_first(keys: &[&str], default: &str) -> String {
            for key in keys {
                if let Ok(value) = std::env::var(key) {
                    if !value.is_empty() {
                        return value;
                    }
                }
            }
            default.to_string()
        }
        Self {
            control_plane_url: env_first(&["CYBERARMOR_CONTROL_PLANE_URL", "CYBERARMOR_URL"], "http://localhost:8000"),
            api_key: env_first(&["CYBERARMOR_API_KEY"], ""),
            bootstrap_token: env_first(&["CYBERARMOR_BOOTSTRAP_TOKEN"], ""),
            tenant_id: env_first(&["CYBERARMOR_TENANT_ID", "CYBERARMOR_TENANT"], "default"),
            mode: if env_first(&["CYBERARMOR_MODE"], "monitor").eq_ignore_ascii_case("block") {
                Mode::Block
            } else {
                Mode::Monitor
            },
            dlp_enabled: true,
            prompt_injection_enabled: true,
        }.with_bootstrap_redeemed()
    }
}

#[derive(Debug, Deserialize)]
struct BootstrapRedeemResponse {
    api_key: Option<String>,
    tenant_id: Option<String>,
}

impl Config {
    pub fn with_bootstrap_redeemed(mut self) -> Self {
        if self.bootstrap_token.is_empty() || !self.api_key.is_empty() {
            return self;
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let Ok(client) = client else {
            return self;
        };

        let payload = serde_json::json!({
            "bootstrap_token": self.bootstrap_token,
            "package_key": "rasp-rust",
            "subject_type": "rasp_runtime",
            "subject_name": std::env::var("CYBERARMOR_RASP_SUBJECT_NAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "rust-rasp".to_string()),
        });

        let response = client
            .post(format!("{}/bootstrap/redeem", self.control_plane_url.trim_end_matches('/')))
            .json(&payload)
            .send();
        if let Ok(response) = response {
            if let Ok(redeemed) = response.error_for_status() {
                if let Ok(body) = redeemed.json::<BootstrapRedeemResponse>() {
                    if let Some(api_key) = body.api_key {
                        self.api_key = api_key;
                    }
                    if let Some(tenant_id) = body.tenant_id {
                        self.tenant_id = tenant_id;
                    }
                }
            }
        }
        self
    }
}

/// Inspection result
#[derive(Debug)]
pub struct InspectionResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Core RASP inspector
pub struct Inspector {
    config: Config,
    ai_domains: HashSet<String>,
    prompt_injection_patterns: Vec<Regex>,
    dlp_patterns: Vec<(&'static str, Regex)>,
    events: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Inspector {
    pub fn new(config: Config) -> Self {
        let ai_domains: HashSet<String> = vec![
            "api.openai.com", "api.anthropic.com",
            "generativelanguage.googleapis.com", "api.cohere.ai",
            "api.mistral.ai", "api-inference.huggingface.co",
            "api.together.xyz", "api.replicate.com", "api.groq.com",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let prompt_injection_patterns = vec![
            Regex::new(r"(?i)ignore\s+(all\s+)?previous\s+instructions").unwrap(),
            Regex::new(r"(?i)you\s+are\s+now\s+(a|an|in)").unwrap(),
            Regex::new(r"(?i)system\s*:\s*you\s+are").unwrap(),
            Regex::new(r"(?i)<\s*(system|prompt|instruction)\s*>").unwrap(),
            Regex::new(r"(?i)jailbreak|DAN\s+mode|bypass\s+filter").unwrap(),
        ];

        let dlp_patterns = vec![
            ("ssn", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
            ("credit_card", Regex::new(r"\b4[0-9]{12}(?:[0-9]{3})?\b").unwrap()),
            ("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            ("private_key", Regex::new(r"-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----").unwrap()),
        ];

        info!("CyberArmor RASP initialized (mode={:?})", config.mode);
        Self {
            config,
            ai_domains,
            prompt_injection_patterns,
            dlp_patterns,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn is_ai_endpoint(&self, host: &str) -> bool {
        let clean = host.split(':').next().unwrap_or(host);
        self.ai_domains.contains(clean)
            || clean.ends_with(".openai.azure.com")
            || clean.ends_with(".cognitiveservices.azure.com")
    }

    pub fn inspect(&self, url: &str, body: &str) -> InspectionResult {
        let host = extract_host(url);
        if !self.is_ai_endpoint(&host) {
            return InspectionResult { allowed: true, reason: None };
        }

        self.record_event("ai_request", url, "");

        if self.config.prompt_injection_enabled && !body.is_empty() {
            for p in &self.prompt_injection_patterns {
                if p.is_match(body) {
                    let pat = p.as_str().to_string();
                    warn!("Prompt injection detected: {}", pat);
                    self.record_event("prompt_injection", url, &pat);
                    if self.config.mode == Mode::Block {
                        return InspectionResult {
                            allowed: false,
                            reason: Some(format!("Prompt injection: {}", pat)),
                        };
                    }
                }
            }
        }

        if self.config.dlp_enabled && !body.is_empty() {
            let findings: Vec<&str> = self.dlp_patterns.iter()
                .filter(|(_, p)| p.is_match(body))
                .map(|(name, _)| *name)
                .collect();
            if !findings.is_empty() {
                let detail = findings.join(",");
                warn!("Sensitive data detected: {}", detail);
                self.record_event("sensitive_data", url, &detail);
                if self.config.mode == Mode::Block {
                    return InspectionResult {
                        allowed: false,
                        reason: Some(format!("Sensitive data: {}", detail)),
                    };
                }
            }
        }

        InspectionResult { allowed: true, reason: None }
    }

    fn record_event(&self, event_type: &str, url: &str, detail: &str) {
        let evt = serde_json::json!({
            "ts": chrono_ts(),
            "type": event_type,
            "url": url,
            "detail": &detail[..detail.len().min(200)],
            "tenant": &self.config.tenant_id,
        });
        if let Ok(mut buf) = self.events.lock() {
            buf.push(evt);
        }
    }
}

fn extract_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

fn chrono_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
