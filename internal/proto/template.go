package proto

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// URI Templates (RFC 6570) as RFC 9484 §3 restricts them: level 3 or lower,
// absolute, ASCII, variables only in the path or query, and none of the
// + # . / ; operators. That leaves simple {a,b}, form-style query {?a,b}
// and query continuation {&a,b} expressions. The proxy matches a request's
// path and query against its template to recover the variables.

type op int

const (
	opSimple op = iota
	opQuery
	opQueryContinuation
)

type part struct {
	literal string // when vars is nil
	op      op
	vars    []string
}

// Template is a parsed URI Template.
type Template struct {
	raw       string
	authority string
	parts     []part
	m         *matcher // nil when requests cannot be matched: see matchErr
	matchErr  error
}

// TemplateError reports an invalid template.
type TemplateError string

func (e TemplateError) Error() string { return "invalid URI template: " + string(e) }

// ParseTemplate parses an absolute template, enforcing RFC 9484 §3.
func ParseTemplate(raw string) (*Template, error) {
	if raw == "" {
		return nil, TemplateError("only ASCII characters 0x21-0x7E are allowed")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return nil, TemplateError("only ASCII characters 0x21-0x7E are allowed")
		}
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, TemplateError("must be absolute (scheme://authority/path)")
	}
	if scheme == "" || strings.Trim(scheme, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.") != "" {
		return nil, TemplateError("missing or invalid scheme")
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return nil, TemplateError("path must not be empty and must start with '/'")
	}
	authority, path := rest[:slash], rest[slash:]
	if authority == "" {
		return nil, TemplateError("authority must not be empty")
	}
	if strings.ContainsAny(authority, "{}") {
		return nil, TemplateError("variables are only allowed in the path or query")
	}
	parts, err := parseParts(path)
	if err != nil {
		return nil, err
	}
	m, merr := compile(parts)
	return &Template{raw: raw, authority: authority, parts: parts, m: m, matchErr: merr}, nil
}

// ParsePathTemplate parses a template for just the path and query, as the
// proxy configures its endpoint.
func ParsePathTemplate(path string) (*Template, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, TemplateError("path must start with '/'")
	}
	t, err := ParseTemplate("https://server" + path)
	if err != nil {
		return nil, err
	}
	// The proxy matches requests against it: a template it could not
	// match is refused now rather than failing every request.
	if t.matchErr != nil {
		return nil, t.matchErr
	}
	return t, nil
}

func validVarName(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func parseParts(s string) ([]part, error) {
	var parts []part
	for s != "" {
		i := strings.IndexByte(s, '{')
		switch {
		case i == 0:
			end := strings.IndexByte(s, '}')
			if end < 0 {
				return nil, TemplateError("unterminated expression")
			}
			body := s[1:end]
			o, list := opSimple, body
			if body != "" {
				switch body[0] {
				case '?':
					o, list = opQuery, body[1:]
				case '&':
					o, list = opQueryContinuation, body[1:]
				case '+', '#', '.', '/', ';':
					return nil, TemplateError("operators + # . / ; are not allowed")
				case '=', ',', '!', '@', '|':
					return nil, TemplateError("reserved operator")
				}
			}
			vars := strings.Split(list, ",")
			for _, v := range vars {
				if strings.ContainsAny(v, ":*") {
					return nil, TemplateError("level 4 modifiers are not allowed")
				}
				if !validVarName(v) {
					return nil, TemplateError("invalid variable name")
				}
			}
			parts = append(parts, part{op: o, vars: vars})
			s = s[end+1:]
		case i > 0:
			parts = append(parts, part{literal: s[:i]})
			s = s[i:]
		default:
			parts = append(parts, part{literal: s})
			s = ""
		}
	}
	for _, p := range parts {
		if p.vars == nil && strings.Contains(p.literal, "}") {
			return nil, TemplateError("unmatched '}'")
		}
	}
	return parts, nil
}

func (t *Template) String() string { return t.raw }

// HasVariable reports whether the template defines a variable. CONNECT-IP
// requires non-empty values for the target and ipproto it defines.
func (t *Template) HasVariable(name string) bool {
	for _, p := range t.parts {
		for _, v := range p.vars {
			if v == name {
				return true
			}
		}
	}
	return false
}

// Expand expands the template into a path and query with vars (name,
// value pairs); undefined variables are left out (RFC 6570). "*" is
// written literally, as in the RFC 9484 examples.
func (t *Template) Expand(vars map[string]string) string {
	var out strings.Builder
	for _, p := range t.parts {
		if p.vars == nil {
			out.WriteString(p.literal)
			continue
		}
		var names []string
		for _, n := range p.vars {
			if _, ok := vars[n]; ok {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			continue
		}
		switch p.op {
		case opSimple:
			for i, n := range names {
				if i > 0 {
					out.WriteByte(',')
				}
				out.WriteString(encode(vars[n]))
			}
		default:
			if p.op == opQuery {
				out.WriteByte('?')
			} else {
				out.WriteByte('&')
			}
			for i, n := range names {
				if i > 0 {
					out.WriteByte('&')
				}
				out.WriteString(n + "=" + encode(vars[n]))
			}
		}
	}
	return out.String()
}

// matcher recovers a template's variables from a request's path and
// query: the path as literals and simple expressions, matched left to
// right; the query as parameters found by name, so that their order and
// other parameters do not matter.
type matcher struct {
	path  []part
	query []queryParam
}

// queryParam is a parameter of the template's query: name=value where the
// value is literals and simple expressions, or a variable of a {?...} or
// {&...} expression, which may be left out.
type queryParam struct {
	name    string // decoded
	value   []part
	formVar string
}

// compile prepares the matcher, or tells why requests cannot be matched
// against the template unambiguously.
func compile(parts []part) (*matcher, error) {
	m := &matcher{}
	var query []part
	// The path: up to a literal '?' or a {?...} expression.
	for i, p := range parts {
		if p.vars == nil {
			before, after, found := strings.Cut(p.literal, "?")
			if before != "" {
				m.path = append(m.path, part{literal: normalize(before)})
			}
			if found {
				query = append([]part{{literal: after}}, parts[i+1:]...)
				break
			}
			continue
		}
		if p.op != opSimple {
			query = parts[i:]
			break
		}
		if n := len(m.path); n > 0 && m.path[n-1].vars != nil {
			return nil, TemplateError("two expressions in a row cannot be told apart")
		}
		m.path = append(m.path, p)
	}
	// The query.
	var pair []part
	afterForm := false
	flush := func() error {
		defer func() { pair = nil }()
		if len(pair) == 0 {
			return nil
		}
		if pair[0].vars != nil {
			return TemplateError("a query parameter name cannot be a variable")
		}
		name, rest, hasValue := strings.Cut(pair[0].literal, "=")
		if !hasValue && len(pair) > 1 {
			return TemplateError("a query parameter name cannot be a variable")
		}
		dname, ok := decode(name)
		if !ok || name == "" {
			return TemplateError("invalid query parameter name")
		}
		var value []part
		if rest != "" {
			value = append(value, part{literal: normalize(rest)})
		}
		for _, p := range pair[1:] {
			if p.vars != nil && len(value) > 0 && value[len(value)-1].vars != nil {
				return TemplateError("two expressions in a row cannot be told apart")
			}
			if p.vars == nil {
				p.literal = normalize(p.literal)
			}
			value = append(value, p)
		}
		m.query = append(m.query, queryParam{name: dname, value: value})
		return nil
	}
	for _, p := range query {
		switch {
		case p.vars == nil:
			lit := p.literal
			if afterForm && lit != "" && lit[0] != '&' {
				return nil, TemplateError("text after a {?...} or {&...} expression must start with '&'")
			}
			afterForm = false
			for {
				before, after, more := strings.Cut(lit, "&")
				if before != "" {
					pair = append(pair, part{literal: before})
				}
				if !more {
					break
				}
				if err := flush(); err != nil {
					return nil, err
				}
				lit = after
			}
		case p.op == opSimple:
			if afterForm {
				return nil, TemplateError("text after a {?...} or {&...} expression must start with '&'")
			}
			pair = append(pair, p)
		default:
			if p.op == opQuery && (len(m.query) > 0 || len(pair) > 0) {
				return nil, TemplateError("{?...} after the query started: use {&...}")
			}
			if err := flush(); err != nil {
				return nil, err
			}
			for _, v := range p.vars {
				m.query = append(m.query, queryParam{name: v, formVar: v})
			}
			afterForm = true
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return m, nil
}

// Match matches a request's path and query against the template and
// returns the percent-decoded variables it carries, or nil and false. A
// variable whose value is not percent-encoded UTF-8 is left out: the
// request is for the template's resource, but malformed (RFC 9484 §4.1).
func (t *Template) Match(pathAndQuery string) (map[string]string, bool) {
	if t.m == nil {
		return nil, false
	}
	path, query, _ := strings.Cut(pathAndQuery, "?")
	out := map[string]string{}
	if !matchSegments(t.m.path, normalize(path), out) {
		return nil, false
	}
	type kv struct{ k, v string }
	var params []kv
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if dk, ok := decode(k); ok {
			params = append(params, kv{dk, v})
		}
	}
	for _, q := range t.m.query {
		var value string
		found := false
		for _, p := range params {
			if p.k == q.name {
				value, found = p.v, true
				break
			}
		}
		switch {
		case q.formVar != "":
			if d, ok := decode(value); found && ok {
				out[q.formVar] = d
			}
		case !found:
			// A fixed parameter must be there; without a parameter that
			// carries variables, they are missing.
			if !hasVariables(q.value) {
				return nil, false
			}
		case !matchSegments(q.value, normalize(value), out):
			return nil, false
		}
	}
	return out, true
}

func hasVariables(parts []part) bool {
	for _, p := range parts {
		if p.vars != nil {
			return true
		}
	}
	return false
}

// matchSegments matches literals and simple expressions left to right.
// An expression captures up to an occurrence of the literal after it
// (compile rules out two expressions in a row): the first, unless only a
// later one lets the rest match, as when the value contains the literal
// (t={target}.example with target foo.example). Requests come before
// authentication, so the attempts are bounded.
func matchSegments(parts []part, s string, out map[string]string) bool {
	// Reject an impossible literal suffix before exploring split points.
	// Matching runs before authentication; otherwise a long request with
	// many delimiters can repeatedly copy and decode captures that cannot
	// possibly match the end of the template.
	if len(parts) > 0 && parts[len(parts)-1].vars == nil && !strings.HasSuffix(s, parts[len(parts)-1].literal) {
		return false
	}
	budget := maxMatchSteps
	return matchFrom(parts, s, out, &budget)
}

// maxMatchSteps bounds the split points tried for one request.
const maxMatchSteps = 1024

func matchFrom(parts []part, s string, out map[string]string, budget *int) bool {
	if len(parts) == 0 {
		return s == ""
	}
	p := parts[0]
	if p.vars == nil {
		return strings.HasPrefix(s, p.literal) && matchFrom(parts[1:], s[len(p.literal):], out, budget)
	}
	if len(parts) == 1 {
		return assign(p.vars, s, out)
	}
	next := parts[1].literal
	if len(parts) == 2 {
		// The literal ends it: no choice to make.
		return strings.HasSuffix(s, next) && assign(p.vars, s[:len(s)-len(next)], out)
	}
	for end := 0; end <= len(s); end++ {
		i := strings.Index(s[end:], next)
		if i < 0 {
			return false
		}
		end += i
		if *budget--; *budget < 0 {
			return false
		}
		trial := map[string]string{}
		if assign(p.vars, s[:end], trial) && matchFrom(parts[1:], s[end:], trial, budget) {
			for k, v := range trial {
				out[k] = v
			}
			return true
		}
	}
	return false
}

// clientVariables are those a CONNECT-IP client defines (RFC 9484 §3).
// It leaves the template's other variables undefined, so they are left out
// of its expansions (RFC 6570 §3.2.1).
var clientVariables = map[string]bool{"target": true, "ipproto": true}

// assign gives a simple expression's variables the comma-separated values
// captured: one each, or, when the client left the other variables out,
// one to each of target and ipproto in order.
func assign(vars []string, captured string, out map[string]string) bool {
	values := strings.Split(captured, ",")
	names := vars
	if len(values) != len(vars) {
		names = nil
		for _, v := range vars {
			if clientVariables[v] {
				names = append(names, v)
			}
		}
		if len(names) == 0 && captured == "" {
			return true // all left out: an empty expansion
		}
		if len(values) != len(names) {
			return false
		}
	}
	for j, name := range names {
		// Keep empty values so the protocol layer can reject them.
		if d, ok := decode(values[j]); ok {
			out[name] = d
		}
	}
	return true
}

// normalize applies percent-encoding normalization (RFC 3986 §6.2.2):
// escaped unreserved characters are decoded, other escapes uppercased.
func normalize(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				c := byte(b)
				if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
					out.WriteByte(c)
				} else {
					fmt.Fprintf(&out, "%%%02X", c)
				}
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func encode(value string) string {
	if value == "*" {
		return "*"
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			out.WriteByte(c)
		} else {
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String()
}

// decode percent-decodes a URI component; false for malformed escapes or
// invalid UTF-8.
func decode(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, utf8.ValidString(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+3 > len(s) {
			return "", false
		}
		b, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		out = append(out, byte(b))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}
