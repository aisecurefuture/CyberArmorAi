/**
 * CyberArmor RASP — C Implementation
 * LD_PRELOAD-based function interception for AI API calls.
 * Intercepts connect(), send(), to detect outbound AI traffic.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <regex.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "cyberarmor_rasp.h"

/* ── Globals ──────────────────────────────────────────────── */

static cyberarmor_config_t g_config;
static bool g_initialized = false;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static cyberarmor_event_cb g_event_cb = NULL;
static void *g_event_userdata = NULL;
static cyberarmor_stats_t g_stats = {0};

/* Compiled regex patterns */
#define MAX_PATTERNS 8
static regex_t g_pi_patterns[MAX_PATTERNS];
static int g_pi_count = 0;

static const char *PI_PATTERN_STRINGS[] = {
    "ignore[[:space:]]+(all[[:space:]]+)?previous[[:space:]]+instructions",
    "you[[:space:]]+are[[:space:]]+now[[:space:]]+(a|an|in)",
    "system[[:space:]]*:[[:space:]]*you[[:space:]]+are",
    "<[[:space:]]*(system|prompt|instruction)[[:space:]]*>",
    NULL,
};

/* Known AI endpoint IP ranges (simplified — in production use DNS) */
static const char *AI_DOMAINS[] = {
    "api.openai.com", "api.anthropic.com",
    "generativelanguage.googleapis.com", "api.cohere.ai",
    "api.mistral.ai", "api-inference.huggingface.co",
    "api.together.xyz", "api.replicate.com", "api.groq.com",
    NULL,
};

/* ── Helpers ──────────────────────────────────────────────── */

static void emit_event(const char *type, const char *url, const char *detail) {
    syslog(LOG_INFO, "[CyberArmor RASP] %s: %s %s", type, url ? url : "", detail ? detail : "");
    if (g_event_cb) {
        g_event_cb(type, url, detail, g_event_userdata);
    }
}

static void extract_json_field(const char *json, const char *field, char *out, size_t out_size) {
    if (!json || !field || !out || out_size == 0) return;
    out[0] = '\0';
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", field);
    const char *start = strstr(json, pattern);
    if (!start) return;
    start += strlen(pattern);
    const char *end = strchr(start, '"');
    if (!end) return;
    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
}

static void redeem_bootstrap_token_if_needed(void) {
    if (!g_config.bootstrap_token || g_config.bootstrap_token[0] == '\0' ||
        (g_config.api_key && g_config.api_key[0] != '\0') ||
        !g_config.control_plane_url || g_config.control_plane_url[0] == '\0') {
        return;
    }

    char payload[1024];
    const char *subject_name = getenv("CYBERARMOR_RASP_SUBJECT_NAME");
    if (!subject_name || subject_name[0] == '\0') {
        subject_name = getenv("HOSTNAME");
    }
    if (!subject_name || subject_name[0] == '\0') {
        subject_name = "c-cpp-rasp";
    }
    snprintf(payload, sizeof(payload),
             "{\"bootstrap_token\":\"%s\",\"package_key\":\"rasp-c-cpp\",\"subject_type\":\"rasp_runtime\",\"subject_name\":\"%s\"}",
             g_config.bootstrap_token, subject_name);

    char template_path[] = "/tmp/cyberarmor-bootstrap-XXXXXX";
    int fd = mkstemp(template_path);
    if (fd < 0) return;
    FILE *payload_file = fdopen(fd, "w");
    if (!payload_file) {
        close(fd);
        unlink(template_path);
        return;
    }
    fputs(payload, payload_file);
    fclose(payload_file);

    char command[2048];
    snprintf(command, sizeof(command),
             "curl -sS -X POST -H 'Content-Type: application/json' --data-binary @%s '%s/bootstrap/redeem'",
             template_path, g_config.control_plane_url);
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        unlink(template_path);
        return;
    }

    char response[4096];
    size_t total = 0;
    while (!feof(pipe) && total + 1 < sizeof(response)) {
        size_t n = fread(response + total, 1, sizeof(response) - total - 1, pipe);
        if (n == 0) break;
        total += n;
    }
    response[total] = '\0';
    pclose(pipe);
    unlink(template_path);

    char api_key[512];
    char tenant_id[256];
    extract_json_field(response, "api_key", api_key, sizeof(api_key));
    extract_json_field(response, "tenant_id", tenant_id, sizeof(tenant_id));
    if (api_key[0] != '\0') {
        g_config.api_key = strdup(api_key);
    }
    if (tenant_id[0] != '\0') {
        g_config.tenant_id = strdup(tenant_id);
    }
}

/* ── Initialization ───────────────────────────────────────── */

int cyberarmor_init(const cyberarmor_config_t *config) {
    pthread_mutex_lock(&g_mutex);
    if (g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }

    if (config) {
        memcpy(&g_config, config, sizeof(g_config));
    } else {
        g_config.control_plane_url = getenv("CYBERARMOR_CONTROL_PLANE_URL");
        if (!g_config.control_plane_url) g_config.control_plane_url = getenv("CYBERARMOR_URL");
        g_config.api_key = getenv("CYBERARMOR_API_KEY");
        g_config.bootstrap_token = getenv("CYBERARMOR_BOOTSTRAP_TOKEN");
        g_config.tenant_id = getenv("CYBERARMOR_TENANT_ID");
        if (!g_config.tenant_id) g_config.tenant_id = getenv("CYBERARMOR_TENANT");
        const char *mode = getenv("CYBERARMOR_MODE");
        g_config.mode = (mode && strcmp(mode, "block") == 0) ?
            CYBERARMOR_MODE_BLOCK : CYBERARMOR_MODE_MONITOR;
        g_config.dlp_enabled = true;
        g_config.prompt_injection_enabled = true;
    }

    if (!g_config.control_plane_url) g_config.control_plane_url = "http://localhost:8000";
    if (!g_config.tenant_id) g_config.tenant_id = "default";
    redeem_bootstrap_token_if_needed();

    /* Compile regex patterns */
    g_pi_count = 0;
    for (int i = 0; PI_PATTERN_STRINGS[i] && i < MAX_PATTERNS; i++) {
        if (regcomp(&g_pi_patterns[g_pi_count], PI_PATTERN_STRINGS[i],
                     REG_EXTENDED | REG_ICASE | REG_NOSUB) == 0) {
            g_pi_count++;
        }
    }

    openlog("cyberarmor-rasp", LOG_PID | LOG_NDELAY, LOG_USER);
    syslog(LOG_INFO, "[CyberArmor RASP] Initialized (mode=%s)",
           g_config.mode == CYBERARMOR_MODE_BLOCK ? "block" : "monitor");

    g_initialized = true;
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

void cyberarmor_shutdown(void) {
    pthread_mutex_lock(&g_mutex);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return;
    }
    for (int i = 0; i < g_pi_count; i++) {
        regfree(&g_pi_patterns[i]);
    }
    g_pi_count = 0;
    closelog();
    g_initialized = false;
    pthread_mutex_unlock(&g_mutex);
}

/* ── Inspection ───────────────────────────────────────────── */

bool cyberarmor_is_ai_endpoint(const char *hostname) {
    if (!hostname) return false;
    for (int i = 0; AI_DOMAINS[i]; i++) {
        if (strcasecmp(hostname, AI_DOMAINS[i]) == 0) return true;
    }
    /* Check Azure patterns */
    if (strstr(hostname, ".openai.azure.com") || strstr(hostname, ".cognitiveservices.azure.com"))
        return true;
    return false;
}

cyberarmor_result_t cyberarmor_inspect(const char *url, const char *body, size_t body_len) {
    cyberarmor_result_t result = { .allowed = true, .reason = NULL };

    if (!g_initialized) cyberarmor_init(NULL);
    if (!url) return result;

    /* Extract host from URL */
    const char *host_start = strstr(url, "://");
    if (host_start) host_start += 3; else host_start = url;
    char host[256] = {0};
    const char *host_end = strchr(host_start, '/');
    if (!host_end) host_end = host_start + strlen(host_start);
    size_t hlen = (size_t)(host_end - host_start);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    strncpy(host, host_start, hlen);
    /* Remove port */
    char *colon = strchr(host, ':');
    if (colon) *colon = '\0';

    if (!cyberarmor_is_ai_endpoint(host)) return result;

    pthread_mutex_lock(&g_mutex);
    g_stats.ai_requests++;
    pthread_mutex_unlock(&g_mutex);

    emit_event("ai_request", url, "");

    /* Prompt injection detection */
    if (g_config.prompt_injection_enabled && body && body_len > 0) {
        for (int i = 0; i < g_pi_count; i++) {
            if (regexec(&g_pi_patterns[i], body, 0, NULL, 0) == 0) {
                pthread_mutex_lock(&g_mutex);
                g_stats.prompt_injections++;
                pthread_mutex_unlock(&g_mutex);
                emit_event("prompt_injection", url, PI_PATTERN_STRINGS[i]);
                if (g_config.mode == CYBERARMOR_MODE_BLOCK) {
                    pthread_mutex_lock(&g_mutex);
                    g_stats.blocked++;
                    pthread_mutex_unlock(&g_mutex);
                    result.allowed = false;
                    result.reason = "Prompt injection detected";
                    return result;
                }
                break;
            }
        }
    }

    /* DLP: basic SSN/credit card detection */
    if (g_config.dlp_enabled && body && body_len > 0) {
        /* Simple SSN check: ###-##-#### */
        for (size_t i = 0; i + 10 < body_len; i++) {
            if (body[i] >= '0' && body[i] <= '9' &&
                body[i+3] == '-' && body[i+6] == '-' &&
                body[i+1] >= '0' && body[i+2] >= '0' &&
                body[i+4] >= '0' && body[i+5] >= '0' &&
                body[i+7] >= '0' && body[i+8] >= '0' &&
                body[i+9] >= '0' && body[i+10] >= '0') {
                pthread_mutex_lock(&g_mutex);
                g_stats.dlp_findings++;
                pthread_mutex_unlock(&g_mutex);
                emit_event("sensitive_data", url, "ssn_pattern");
                if (g_config.mode == CYBERARMOR_MODE_BLOCK) {
                    pthread_mutex_lock(&g_mutex);
                    g_stats.blocked++;
                    pthread_mutex_unlock(&g_mutex);
                    result.allowed = false;
                    result.reason = "Sensitive data detected (SSN)";
                    return result;
                }
                break;
            }
        }
    }

    return result;
}

void cyberarmor_on_event(cyberarmor_event_cb callback, void *userdata) {
    g_event_cb = callback;
    g_event_userdata = userdata;
}

cyberarmor_stats_t cyberarmor_get_stats(void) {
    cyberarmor_stats_t stats;
    pthread_mutex_lock(&g_mutex);
    memcpy(&stats, &g_stats, sizeof(stats));
    pthread_mutex_unlock(&g_mutex);
    return stats;
}

/* ── Auto-init via constructor ────────────────────────────── */

__attribute__((constructor))
static void _cyberarmor_auto_init(void) {
    cyberarmor_init(NULL);
}

__attribute__((destructor))
static void _cyberarmor_auto_shutdown(void) {
    cyberarmor_shutdown();
}
