package waf

import "testing"

func TestEngineBlocksKnownSignatures(t *testing.T) {
	engine := NewEngine(CompileDefaultRules(), true)

	malicious := []string{
		`id=1' OR '1'='1`,
		`q=<script>alert(1)</script>`,
		`name=' UNION SELECT password FROM users--`,
		`file=../../../../etc/passwd`,
		`img=<img src=javascript:alert(1)>`,
		`cb=onerror=alert(1)`,
	}
	for _, payload := range malicious {
		d := engine.Inspect(payload)
		if !d.Blocked {
			t.Errorf("expected payload to be blocked: %q", payload)
		}
	}
}

func TestEngineAllowsBenignTraffic(t *testing.T) {
	engine := NewEngine(CompileDefaultRules(), true)

	benign := []string{
		"/api/users?id=42",
		"/search?q=golang+concurrency+patterns",
		"/checkout?total=19.99&currency=usd",
		"/blog/2024/10/building-a-reverse-proxy",
	}
	for _, payload := range benign {
		d := engine.Inspect(payload)
		if d.Blocked {
			t.Errorf("expected payload to be allowed, blocked by %q: %q", d.RuleName, payload)
		}
	}
}

func TestStructuralAnalyzerCatchesObfuscatedSQLi(t *testing.T) {
	// A predicate clause the regex signatures don't have a literal for:
	// no "or 1=1", no "union select", no comment marker, just the token
	// shape "<keyword> <operand> <operator> <operand>".
	v := AnalyzeStructure(`item=widget and 5=5`)
	if !v.Suspicious {
		t.Error("expected structural analyzer to flag the predicate-clause shape")
	}

	// A query spread across multiple clause keywords, with none of the
	// individual signature strings present.
	v2 := AnalyzeStructure(`select name from accounts where balance`)
	if !v2.Suspicious {
		t.Error("expected structural analyzer to flag multiple SQL clause keywords")
	}
}

func TestInspectionLatencyBudget(t *testing.T) {
	engine := NewEngine(CompileDefaultRules(), true)
	payload := "/api/products?search=a+reasonably+long+but+benign+query+string+for+latency+testing"

	d := engine.Inspect(payload)
	if d.Elapsed.Microseconds() > 3000 {
		t.Errorf("WAF inspection exceeded 3ms budget: took %s", d.Elapsed)
	}
}
