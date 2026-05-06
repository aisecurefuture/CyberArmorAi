package cyberarmor

import "testing"

func TestInspectRedactsProviderPayload(t *testing.T) {
	ins := New(Config{
		Mode:            "redact-secrets",
		DLPEnabled:      true,
		PromptInjection: true,
	})

	result := ins.Inspect(
		"https://api.openai.com/v1/chat/completions",
		`{"prompt":"password=supersecret sk-abcdefghijklmnopqrstuvwxyz"}`,
	)

	if !result.Allowed {
		t.Fatalf("expected redaction to allow request, got blocked: %s", result.Reason)
	}
	if result.RedactedBody == "" {
		t.Fatal("expected redacted body")
	}
	if result.RedactedBody == `{"prompt":"password=supersecret sk-abcdefghijklmnopqrstuvwxyz"}` {
		t.Fatal("expected body to change")
	}
	if containsAny(result.RedactedBody, []string{"supersecret", "sk-abcdefghijklmnopqrstuvwxyz"}) {
		t.Fatalf("raw credential remained in redacted body: %s", result.RedactedBody)
	}
}

func TestInspectRedactsOnlySelectedCategory(t *testing.T) {
	ins := New(Config{
		Mode:            "redact-pci",
		DLPEnabled:      true,
		PromptInjection: true,
	})

	result := ins.Inspect(
		"https://api.openai.com/v1/chat/completions",
		`{"prompt":"password=supersecret card 4111111111111111"}`,
	)

	if result.RedactedBody == "" {
		t.Fatal("expected redacted body")
	}
	if containsAny(result.RedactedBody, []string{"4111111111111111"}) {
		t.Fatalf("raw card remained in redacted body: %s", result.RedactedBody)
	}
	if !containsAny(result.RedactedBody, []string{"password=supersecret"}) {
		t.Fatalf("redact-pci should not redact secrets: %s", result.RedactedBody)
	}
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && stringsContains(value, needle) {
			return true
		}
	}
	return false
}

func stringsContains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
