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
	return &Template{raw: raw, authority: authority, parts: parts}, nil
}

// ParsePathTemplate parses a template for just the path and query, as the
// proxy configures its endpoint.
func ParsePathTemplate(path string) (*Template, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, TemplateError("path must start with '/'")
	}
	return ParseTemplate("https://server" + path)
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

// Match matches a request's path and query against the template and
// returns the percent-decoded variables it carries, or nil and false.
func (t *Template) Match(pathAndQuery string) (map[string]string, bool) {
	path, query, _ := strings.Cut(pathAndQuery, "?")
	var pathParts []part
	type queryExpr struct{ param, variable string }
	var queryExprs []queryExpr
	var queryLiteral strings.Builder
	inQuery := false
	for _, p := range t.parts {
		switch {
		case p.vars == nil && !inQuery:
			before, after, found := strings.Cut(p.literal, "?")
			if found {
				pathParts = append(pathParts, part{literal: before})
				queryLiteral.WriteString(after)
				inQuery = true
			} else {
				pathParts = append(pathParts, p)
			}
		case p.vars == nil:
			queryLiteral.WriteString(p.literal)
		case p.op == opSimple && inQuery:
			// A simple expression in a literal query such as ?t={target}.
			lit := queryLiteral.String()
			name := lit[strings.LastIndexAny(lit, "&?")+1:]
			name = strings.TrimRight(name, "=")
			if len(p.vars) != 1 || name == "" {
				return nil, false
			}
			queryExprs = append(queryExprs, queryExpr{name, p.vars[0]})
			queryLiteral.WriteByte(0) // placeholder for the value
		case p.op == opSimple:
			pathParts = append(pathParts, p)
		default:
			inQuery = true
			for _, v := range p.vars {
				queryExprs = append(queryExprs, queryExpr{v, v})
			}
		}
	}
	out := map[string]string{}
	if !matchPath(pathParts, path, out) {
		return nil, false
	}
	type kv struct {
		k, v string
		ok   bool // the value is well encoded
	}
	var params []kv
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		dk, ok := decode(k)
		if !ok {
			continue // not a parameter of the template
		}
		dv, ok := decode(v)
		params = append(params, kv{dk, dv, ok})
	}
	// Fixed parameters written in the template must be present.
	for _, pair := range strings.Split(queryLiteral.String(), "&") {
		if pair == "" || strings.ContainsRune(pair, 0) {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		found := false
		for _, p := range params {
			if p.k == k && p.ok && p.v == v {
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	for _, e := range queryExprs {
		for _, p := range params {
			if p.k == e.param {
				// Like a path, a variable badly encoded does not match.
				if !p.ok {
					return nil, false
				}
				out[e.variable] = p.v
				break
			}
		}
	}
	return out, true
}

// matchPath matches path parts left to right: a simple expression captures
// up to the next literal; two expressions in a row are ambiguous.
func matchPath(parts []part, path string, out map[string]string) bool {
	for i, p := range parts {
		if p.vars == nil {
			if !strings.HasPrefix(path, p.literal) {
				return false
			}
			path = path[len(p.literal):]
			continue
		}
		var captured string
		if i+1 < len(parts) {
			next := parts[i+1]
			if next.vars != nil || next.literal == "" {
				return false
			}
			end := strings.Index(path, next.literal)
			if end < 0 {
				return false
			}
			captured, path = path[:end], path[end:]
		} else {
			captured, path = path, ""
		}
		values := strings.Split(captured, ",")
		if len(values) != len(p.vars) {
			return false
		}
		for j, name := range p.vars {
			// Keep empty values so the protocol layer can reject them.
			d, ok := decode(values[j])
			if !ok {
				return false
			}
			out[name] = d
		}
	}
	return path == ""
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
