package waf

import (
	"time"
)

type Decision struct {
	Blocked  bool
	RuleName string
	Category string
	Reason   string
	Elapsed  time.Duration
}

// Engine runs the regex signature set and the structural analyzer against a
// single payload (URL path+query, or a bounded prefix of the request body).
// Both passes are O(n) in payload length with no backtracking, which is what
// keeps this engine's latency bounded regardless of attacker-supplied input
// — the thing naive backtracking regex engines get wrong and that attackers
// exploit for ReDoS. Go's regexp package is RE2-based, so even the regex
// pass here cannot exhibit catastrophic backtracking.
type Engine struct {
	rules      []*CompiledRule
	blockOnAST bool
}

func NewEngine(rules []*CompiledRule, blockOnAST bool) *Engine {
	return &Engine{rules: rules, blockOnAST: blockOnAST}
}

func (e *Engine) Inspect(payload string) Decision {
	start := time.Now()

	for _, r := range e.rules {
		if r.MatchString(payload) {
			return Decision{
				Blocked:  r.Action == "block",
				RuleName: r.Name,
				Category: r.Category,
				Reason:   "signature match",
				Elapsed:  time.Since(start),
			}
		}
	}

	verdict := AnalyzeStructure(payload)
	if verdict.Suspicious {
		return Decision{
			Blocked:  e.blockOnAST,
			RuleName: "structural-anomaly",
			Category: "structural",
			Reason:   verdict.Reason,
			Elapsed:  time.Since(start),
		}
	}

	return Decision{Blocked: false, Elapsed: time.Since(start)}
}
