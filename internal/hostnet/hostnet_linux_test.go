package hostnet

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func TestRuleset(t *testing.T) {
	v4, v6 := netip.MustParsePrefix("10.89.0.1/24"), netip.MustParsePrefix("fd89:6d61:7371::1/64")
	for _, tc := range []struct {
		name       string
		v6         netip.Prefix
		hostAccess bool
	}{{"v4", netip.Prefix{}, false}, {"dual stack", v6, false}, {"host access", v6, true}} {
		t.Run(tc.name, func(t *testing.T) {
			rs := Ruleset("masque0", v4, tc.v6, tc.hostAccess)
			if has := strings.Contains(rs, "chain input"); has == tc.hostAccess {
				t.Errorf("input chain present = %v with host access %v:\n%s", has, tc.hostAccess, rs)
			}
			if has := strings.Contains(rs, "ip6 saddr"); has != tc.v6.IsValid() {
				t.Errorf("IPv6 NAT present = %v:\n%s", has, rs)
			}
			if _, err := exec.LookPath("nft"); err != nil {
				t.Skip("no nft to check the syntax")
			}
			// -c only checks; it still needs the right to talk to nftables.
			cmd := exec.Command("nft", "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(rs)
			if out, err := cmd.CombinedOutput(); err != nil {
				if strings.Contains(string(out), "Operation not permitted") {
					t.Skip("not allowed to use nftables")
				}
				t.Errorf("nft rejects the ruleset: %v: %s\n%s", err, out, rs)
			}
		})
	}
}
