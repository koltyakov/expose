package config

import (
	"strings"
	"testing"
)

func TestServerBypassesConfig(t *testing.T) {
	t.Setenv("EXPOSE_BYPASSES", `[{"subdomain":" App ","port":3000},{"subdomain":"ci","port":8080,"disable_waf":true,"disable_rate_limit":true}]`)
	cfg, err := ParseServerFlags([]string{"--domain=example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Bypasses) != 2 || cfg.Bypasses[0] != (ServerBypass{Subdomain: "app", Port: 3000}) || !cfg.Bypasses[1].DisableWAF || !cfg.Bypasses[1].DisableRateLimit {
		t.Fatalf("unexpected bypasses: %+v", cfg.Bypasses)
	}
	cfg, err = ParseServerFlags([]string{"--domain=example.com", `--bypasses=[{"subdomain":"other","port":9000}]`})
	if err != nil || len(cfg.Bypasses) != 1 || cfg.Bypasses[0].Subdomain != "other" {
		t.Fatalf("flag override: %+v, %v", cfg.Bypasses, err)
	}
	cfg, err = ParseServerFlags([]string{"--domain=example.com", "--bypasses=[]"})
	if err != nil || len(cfg.Bypasses) != 0 {
		t.Fatalf("empty override: %+v, %v", cfg.Bypasses, err)
	}
	if _, err := ParseClientFlags([]string{"--port=3000", "--bypasses=[]"}); err == nil {
		t.Fatal("client accepted server-only flag")
	}
}

func TestServerBypassesRejectInvalidConfig(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `[{`, `[] []`, `[null]`,
		`[{"subdomain":"app","port":0}]`,
		`[{"subdomain":"app","port":65536}]`,
		`[{"subdomain":"app","port":-1}]`,
		`[{"port":3000}]`,
		`[{"subdomain":"https://app","port":3000}]`,
		`[{"subdomain":"bad name","port":3000}]`,
		`[{"subdomain":"app","port":3000,"disable_waf":"true"}]`,
		`[{"subdomain":"app","port":3000,"disable_wfa":true}]`,
		`[{"subdomain":"app","port":3000},{"subdomain":"APP","port":9000}]`,
		`[{"subdomain":"` + strings.Repeat("a", 63) + `.` + strings.Repeat("b", 63) + `.` + strings.Repeat("c", 63) + `.` + strings.Repeat("d", 63) + `","port":3000}]`,
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("EXPOSE_BYPASSES", raw)
			if _, err := ParseServerFlags([]string{"--domain=example.com"}); err == nil {
				t.Fatal("accepted invalid bypass configuration")
			}
		})
	}
}
