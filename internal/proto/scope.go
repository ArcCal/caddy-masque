package proto

import (
	"net/netip"
	"strconv"
	"strings"
)

// Target is the requested scope of destinations (RFC 9484 §4.6): any
// (Any), an address or prefix (Prefix), or a host name (Host).
type Target struct {
	Any    bool
	Prefix netip.Prefix // valid when !Any and Host == ""
	Host   string       // lower case
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// ParseTarget parses the value of the target variable.
func ParseTarget(value string) (Target, error) {
	if value == "*" {
		return Target{Any: true}, nil
	}
	if value == "" {
		return Target{}, MalformedError("target must not be empty")
	}
	addr, lenStr, hasLen := strings.Cut(value, "/")
	bits := -1
	if hasLen {
		if len(lenStr) > 3 || !isDigits(lenStr) {
			return Target{}, MalformedError("invalid prefix length in target")
		}
		n, err := strconv.Atoi(lenStr)
		if err != nil || n > 255 {
			return Target{}, MalformedError("invalid prefix length in target")
		}
		bits = n
	}
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Zone() == "" {
		if bits < 0 {
			return Target{Prefix: Host(ip)}, nil
		}
		p, err := NewPrefix(ip, bits)
		if err != nil {
			return Target{}, err
		}
		return Target{Prefix: p}, nil
	}
	if hasLen || strings.ContainsAny(addr, ":%") {
		return Target{}, MalformedError("invalid IP prefix in target")
	}
	if !isHostName(addr) {
		return Target{}, MalformedError("target is not a valid host name")
	}
	return Target{Host: strings.ToLower(addr)}, nil
}

// Value is the target variable's value for this target.
func (t Target) Value() string {
	switch {
	case t.Any:
		return "*"
	case t.Host != "":
		return t.Host
	case t.Prefix.Bits() == t.Prefix.Addr().BitLen():
		return t.Prefix.Addr().String()
	default:
		return t.Prefix.String()
	}
}

func isHostName(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// IPProtocol is the requested protocol: Any, or one protocol number.
type IPProtocol struct {
	Any    bool
	Number uint8
}

// ParseIPProtocol parses the value of the ipproto variable.
func ParseIPProtocol(value string) (IPProtocol, error) {
	if value == "*" {
		return IPProtocol{Any: true}, nil
	}
	if len(value) > 3 || !isDigits(value) {
		return IPProtocol{}, MalformedError("ipproto must be * or a number from 0 to 255")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n > 255 {
		return IPProtocol{}, MalformedError("ipproto must be * or a number from 0 to 255")
	}
	return IPProtocol{Number: uint8(n)}, nil
}

// RouteProtocol is the protocol field for routes: 0 for any.
func (p IPProtocol) RouteProtocol() uint8 {
	if p.Any {
		return 0
	}
	return p.Number
}

// IsIPv6ExtensionHeader reports protocol numbers that are IPv6 extension
// headers, which a proxy may refuse as a scope (RFC 9484 §4.8).
func IsIPv6ExtensionHeader(n uint8) bool {
	switch n {
	case 0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254:
		return true
	}
	return false
}
