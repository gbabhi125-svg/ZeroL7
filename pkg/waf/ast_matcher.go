package waf

import (
	"strings"
	"unicode"
)

// Structural analysis complements the regex signatures in rules.go.
// It does not build a true SQL/HTML parse tree (that would cost far more
// than the 2-3ms budget on arbitrary payloads); instead it tokenizes the
// payload once and walks the token stream for *shapes* regex can't express
// cheaply: a run of SQL keywords/operators that forms a clause, or a tag
// open/attribute/event-handler shape, even when the attacker has broken up
// or re-cased the literal signature. This is what the project's docs call
// "AST matching" — honestly, a single-pass structural token analyzer, not a
// recursive-descent parser.

type tokenKind int

const (
	tokIdent tokenKind = iota
	tokKeyword
	tokOperator
	tokString
	tokNumber
	tokPunct
)

type token struct {
	kind tokenKind
	text string
}

var sqlKeywords = map[string]bool{
	"select": true, "union": true, "insert": true, "update": true, "delete": true,
	"drop": true, "where": true, "from": true, "or": true, "and": true,
	"sleep": true, "benchmark": true, "exec": true, "execute": true, "declare": true,
	"cast": true, "convert": true, "having": true, "group": true, "order": true,
	"waitfor": true, "xp_cmdshell": true, "information_schema": true,
}

var htmlEventAttrs = map[string]bool{
	"onerror": true, "onload": true, "onclick": true, "onmouseover": true,
	"onfocus": true, "onblur": true, "onchange": true, "onsubmit": true,
}

// tokenize splits the payload into a coarse token stream. It is intentionally
// a single linear pass (no backtracking, no recursion) so its cost is
// strictly O(n) in payload length.
func tokenize(s string) []token {
	var toks []token
	runes := []rune(s)
	n := len(runes)
	i := 0
	for i < n {
		c := runes[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '\'' || c == '"':
			quote := c
			j := i + 1
			for j < n && runes[j] != quote {
				if runes[j] == '\\' && j+1 < n {
					j++
				}
				j++
			}
			if j >= n {
				// Unterminated quote: a classic injection shape (`' OR 1=1`
				// never closes its string). Don't let it swallow the rest
				// of the payload as one opaque string token — treat the
				// quote itself as punctuation and keep tokenizing what
				// follows, so later keywords/operators still get seen.
				toks = append(toks, token{tokPunct, string(quote)})
				i++
				continue
			}
			j++
			toks = append(toks, token{tokString, string(runes[i:j])})
			i = j
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < n && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_') {
				j++
			}
			word := string(runes[i:j])
			lower := strings.ToLower(word)
			kind := tokIdent
			if sqlKeywords[lower] || htmlEventAttrs[lower] {
				kind = tokKeyword
			}
			toks = append(toks, token{kind, lower})
			i = j
		case unicode.IsDigit(c):
			j := i
			for j < n && unicode.IsDigit(runes[j]) {
				j++
			}
			toks = append(toks, token{tokNumber, string(runes[i:j])})
			i = j
		case strings.ContainsRune("=<>!", c):
			j := i
			for j < n && strings.ContainsRune("=<>!", runes[j]) {
				j++
			}
			toks = append(toks, token{tokOperator, string(runes[i:j])})
			i = j
		default:
			toks = append(toks, token{tokPunct, string(c)})
			i++
		}
	}
	return toks
}

// StructuralVerdict is the result of the structural pass.
type StructuralVerdict struct {
	Suspicious bool
	Reason     string
}

// AnalyzeStructure scans a bounded-length payload for SQL-clause-shaped or
// script-tag-with-event-handler-shaped token runs.
func AnalyzeStructure(payload string) StructuralVerdict {
	toks := tokenize(payload)

	// Shape 1: "<keyword> <ident|number|string> <operator> <ident|number|string>"
	// e.g. `where id = 1`, `' or 'a'='a`, `and 1=1` — a predicate clause,
	// however the literal spacing/casing was mangled.
	for i := 0; i+3 < len(toks); i++ {
		if toks[i].kind == tokKeyword && isOperand(toks[i+1].kind) &&
			toks[i+2].kind == tokOperator && isOperand(toks[i+3].kind) {
			return StructuralVerdict{true, "sql-predicate-clause: " + toks[i].text}
		}
	}

	// Shape 2: two or more SQL keywords from different clause families within
	// a short token window (e.g. select ... from, union ... select, drop ...
	// table) — catches queries split across encoded fragments.
	keywordHits := 0
	for _, t := range toks {
		if t.kind == tokKeyword && sqlKeywords[t.text] {
			keywordHits++
		}
	}
	if keywordHits >= 3 {
		return StructuralVerdict{true, "multiple-sql-keywords"}
	}

	// Shape 3: an identifier matching a known event-handler attribute directly
	// followed by '=' — covers onError / ONERROR / on\terror variants that a
	// literal <script> signature misses.
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind == tokKeyword && htmlEventAttrs[toks[i].text] && toks[i+1].kind == tokOperator {
			return StructuralVerdict{true, "event-handler-assignment: " + toks[i].text}
		}
	}

	return StructuralVerdict{false, ""}
}

func isOperand(k tokenKind) bool {
	return k == tokIdent || k == tokNumber || k == tokString || k == tokKeyword
}
