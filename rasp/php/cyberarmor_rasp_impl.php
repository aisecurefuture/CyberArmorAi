<?php
/**
 * CyberArmor RASP — PHP Runtime Application Self-Protection
 * Supports: PSR-15 middleware, cURL hook, Laravel/Symfony integration
 */

namespace CyberArmor\RASP;

class Config {
    public string $controlPlaneUrl;
    public string $apiKey;
    public string $bootstrapToken;
    public string $tenantId;
    public string $mode; // 'monitor' or 'block'
    public bool $dlpEnabled;
    public bool $promptInjectionEnabled;

    public function __construct() {
        $this->controlPlaneUrl = getenv('CYBERARMOR_CONTROL_PLANE_URL') ?: (getenv('CYBERARMOR_URL') ?: 'http://localhost:8000');
        $this->apiKey = getenv('CYBERARMOR_API_KEY') ?: '';
        $this->bootstrapToken = getenv('CYBERARMOR_BOOTSTRAP_TOKEN') ?: '';
        $this->tenantId = getenv('CYBERARMOR_TENANT_ID') ?: (getenv('CYBERARMOR_TENANT') ?: 'default');
        $this->mode = getenv('CYBERARMOR_MODE') ?: 'monitor';
        $this->dlpEnabled = true;
        $this->promptInjectionEnabled = true;
        $this->redeemBootstrapTokenIfNeeded();
    }

    private function redeemBootstrapTokenIfNeeded(): void {
        if ($this->bootstrapToken === '' || $this->apiKey !== '') {
            return;
        }

        $subjectName = getenv('CYBERARMOR_RASP_SUBJECT_NAME') ?: (gethostname() ?: 'php-rasp');
        $payload = json_encode([
            'bootstrap_token' => $this->bootstrapToken,
            'package_key' => 'rasp-php',
            'subject_type' => 'rasp_runtime',
            'subject_name' => $subjectName,
        ]);

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $payload,
                'timeout' => 10,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents(rtrim($this->controlPlaneUrl, '/') . '/bootstrap/redeem', false, $context);
        if ($response === false) {
            error_log('[CyberArmor RASP] bootstrap redeem failed');
            return;
        }

        $decoded = json_decode($response, true);
        if (is_array($decoded)) {
            if (!empty($decoded['api_key'])) {
                $this->apiKey = $decoded['api_key'];
            }
            if (!empty($decoded['tenant_id'])) {
                $this->tenantId = $decoded['tenant_id'];
            }
        }
    }
}

class InspectionResult {
    public bool $allowed;
    public ?string $reason;

    public function __construct(bool $allowed, ?string $reason = null) {
        $this->allowed = $allowed;
        $this->reason = $reason;
    }
}

class Inspector {
    private Config $config;
    private array $aiDomains = [
        'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com',
        'api.cohere.ai', 'api.mistral.ai', 'api-inference.huggingface.co',
        'api.together.xyz', 'api.replicate.com', 'api.groq.com',
    ];

    private array $promptInjectionPatterns = [
        '/ignore\s+(all\s+)?previous\s+instructions/i',
        '/you\s+are\s+now\s+(a|an|in)/i',
        '/system\s*:\s*you\s+are/i',
        '/<\s*(system|prompt|instruction)\s*>/i',
        '/jailbreak|DAN\s+mode|bypass\s+filter/i',
    ];

    private array $dlpPatterns = [
        'ssn' => '/\b\d{3}-\d{2}-\d{4}\b/',
        'credit_card' => '/\b4[0-9]{12}(?:[0-9]{3})?\b/',
        'aws_key' => '/AKIA[0-9A-Z]{16}/',
        'private_key' => '/-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/',
    ];

    public function __construct(?Config $config = null) {
        $this->config = $config ?? new Config();
    }

    public function isAiEndpoint(string $host): bool {
        $clean = explode(':', $host)[0];
        return in_array($clean, $this->aiDomains) ||
            str_ends_with($clean, '.openai.azure.com') ||
            str_ends_with($clean, '.cognitiveservices.azure.com');
    }

    public function inspect(string $url, string $body = ''): InspectionResult {
        $parsed = parse_url($url);
        $host = $parsed['host'] ?? '';
        if (!$this->isAiEndpoint($host)) {
            return new InspectionResult(true);
        }

        // Prompt injection detection
        if ($this->config->promptInjectionEnabled && $body) {
            foreach ($this->promptInjectionPatterns as $pattern) {
                if (preg_match($pattern, $body)) {
                    error_log("[CyberArmor RASP] Prompt injection detected: $pattern");
                    if ($this->config->mode === 'block') {
                        return new InspectionResult(false, "Prompt injection detected");
                    }
                }
            }
        }

        // DLP scanning
        if ($this->config->dlpEnabled && $body) {
            $findings = [];
            foreach ($this->dlpPatterns as $name => $pattern) {
                if (preg_match($pattern, $body)) {
                    $findings[] = $name;
                }
            }
            if (!empty($findings)) {
                error_log("[CyberArmor RASP] Sensitive data: " . implode(',', $findings));
                if ($this->config->mode === 'block') {
                    return new InspectionResult(false, "Sensitive data: " . implode(',', $findings));
                }
            }
        }

        return new InspectionResult(true);
    }
}

/**
 * PSR-15 Middleware
 */
class PSR15Middleware {
    private Inspector $inspector;

    public function __construct(?Inspector $inspector = null) {
        $this->inspector = $inspector ?? new Inspector();
    }

    public function process($request, $handler) {
        if ($request->getMethod() === 'POST') {
            $host = $request->getHeaderLine('X-Forwarded-Host') ?: $request->getUri()->getHost();
            if ($this->inspector->isAiEndpoint($host)) {
                $body = (string) $request->getBody();
                $result = $this->inspector->inspect($request->getUri()->__toString(), $body);
                if (!$result->allowed) {
                    $response = new \Nyholm\Psr7\Response(403, ['Content-Type' => 'application/json'],
                        json_encode(['error' => $result->reason, 'policy' => 'cyberarmor-rasp']));
                    return $response;
                }
            }
        }
        return $handler->handle($request);
    }
}

/**
 * Laravel Middleware
 */
class LaravelMiddleware {
    private Inspector $inspector;

    public function __construct() {
        $this->inspector = new Inspector();
    }

    public function handle($request, \Closure $next) {
        if ($request->isMethod('POST')) {
            $host = $request->header('X-Forwarded-Host', $request->getHost());
            if ($this->inspector->isAiEndpoint($host)) {
                $result = $this->inspector->inspect($request->fullUrl(), $request->getContent());
                if (!$result->allowed) {
                    return response()->json(['error' => $result->reason, 'policy' => 'cyberarmor-rasp'], 403);
                }
            }
        }
        return $next($request);
    }
}
