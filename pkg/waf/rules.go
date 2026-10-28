package waf

import "regexp"

// CompiledRule is a config.WAFRule with its regex pre-compiled once at load
// time, so the hot path never compiles a pattern per-request.
type CompiledRule struct {
	Name     string
	Category string
	Action   string
	re       *regexp.Regexp
}

func (r *CompiledRule) MatchString(s string) bool {
	return r.re.MatchString(s)
}

// DefaultRules is used when config.yaml defines no rules of its own.
// Patterns are deliberately simple, bounded (no nested quantifiers) regexes:
// signature matching for common SQLi / XSS / path-traversal strings. They
// are intentionally not exhaustive — see ast_matcher.go for the structural
// check that catches obfuscated variants these signatures miss.
var DefaultRules = []struct {
	Name, Pattern, Category, Action string
}{
	{"sqli-or-1-1", `(?i)(\bor\b|\band\b)\s+[\d'"]+\s*=\s*[\d'"]+`, "sqli", "block"},
	{"sqli-union-select", `(?i)\bunion\b\s+(all\s+)?\bselect\b`, "sqli", "block"},
	{"sqli-comment", `(--|#|/\*)\s*$`, "sqli", "block"},
	{"sqli-stacked", `;\s*(drop|delete|update|insert)\s+`, "sqli", "block"},
	{"sqli-sleep", `(?i)\b(sleep|benchmark|waitfor\s+delay)\s*\(`, "sqli", "block"},
	{"xss-script-tag", `(?i)<script[\s>]`, "xss", "block"},
	{"xss-onerror", `(?i)on(error|load|click|mouseover)\s*=`, "xss", "block"},
	{"xss-javascript-uri", `(?i)javascript:`, "xss", "block"},
	{"xss-img-src", `(?i)<img[^>]+src\s*=\s*["']?javascript:`, "xss", "block"},
	{"path-traversal", `(\.\./|\.\.\\){2,}`, "path_traversal", "block"},
	{"path-traversal-encoded", `(?i)%2e%2e(%2f|%5c)`, "path_traversal", "block"},
}

func CompileDefaultRules() []*CompiledRule {
	out := make([]*CompiledRule, 0, len(DefaultRules))
	for _, r := range DefaultRules {
		out = append(out, &CompiledRule{
			Name: r.Name, Category: r.Category, Action: r.Action,
			re: regexp.MustCompile(r.Pattern),
		})
	}
	return out
}

func CompileRule(name, pattern, category, action string) (*CompiledRule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &CompiledRule{Name: name, Category: category, Action: action, re: re}, nil
}
