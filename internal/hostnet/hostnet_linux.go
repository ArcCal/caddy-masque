// Package hostnet sets up the server's side of the tunnel on Linux: the
// TUN device, its addresses, forwarding and NAT, and the deletion of
// connection tracking entries of reused addresses. It follows masque-vpn's
// HostNetwork and conntrack modules.
package hostnet

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NFTTable is the nftables table of forwarding and NAT.
const NFTTable = "caddy-masque"

// Config describes the tunnel interface.
type Config struct {
	Interface string
	IPv4      netip.Prefix // the server's own address and the client pool
	IPv6      netip.Prefix // invalid: IPv4 only
	MTU       int
	// Manage forwarding and NAT (sysctls and nftables).
	Manage bool
	// Let clients reach the host's own services (any local address) instead
	// of only ping it. Off by default: the tunnel's clients arrive on an
	// interface the host's firewall may trust.
	HostAccess bool
	// Log receives notices.
	Log func(msg string)
}

// Network is the TUN device and the host configuration around it.
type Network struct {
	cfg  Config
	tun  *os.File
	nft  bool
	name string
	// Sysctls this process changed, with their earlier values, for Close.
	changed []sysctl
}

type sysctl struct{ key, old string }

// Open creates the TUN device and configures the host. Close undoes it.
func Open(cfg Config) (*Network, error) {
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	tun, name, err := openTUN(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("creating TUN device %s (needs CAP_NET_ADMIN; fails if another instance uses it): %w", cfg.Interface, err)
	}
	n := &Network{cfg: cfg, tun: tun, name: name}
	if err := n.setup(); err != nil {
		n.Close()
		return nil, err
	}
	return n, nil
}

func openTUN(name string) (*os.File, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	// Non-blocking, so reads go through Go's poller and Close ends them.
	return os.NewFile(uintptr(fd), "/dev/net/tun"), ifr.Name(), nil
}

func (n *Network) setup() error {
	iface := n.name
	if err := run(nil, "ip", "link", "set", "dev", iface, "mtu", fmt.Sprint(n.cfg.MTU)); err != nil {
		return err
	}
	if err := run(nil, "ip", "addr", "replace", n.cfg.IPv4.String(), "dev", iface); err != nil {
		return err
	}
	if n.cfg.IPv6.IsValid() {
		if err := run(nil, "ip", "-6", "addr", "replace", n.cfg.IPv6.String(), "dev", iface, "nodad"); err != nil {
			return err
		}
	} else {
		// Keep the kernel from using the interface for IPv6.
		_ = SetSysctl("net.ipv6.conf."+iface+".disable_ipv6", "1")
	}
	if err := run(nil, "ip", "link", "set", "dev", iface, "up"); err != nil {
		return err
	}
	// The ICMP errors the proxy sends toward the network (RFC 9484 §10.1
	// "packet too big") come from its own tunnel address; without this the
	// kernel drops them as martians.
	if err := SetSysctl("net.ipv4.conf."+iface+".accept_local", "1"); err != nil {
		n.cfg.Log(fmt.Sprintf("%v: senders may not learn about packets too big for the tunnel", err))
	}
	if !n.cfg.Manage {
		return nil
	}
	if err := n.changeSysctl("net.ipv4.ip_forward", "1"); err != nil {
		return err
	}
	if n.cfg.IPv6.IsValid() {
		n.keepRouterAdvertisements()
		if err := n.changeSysctl("net.ipv6.conf.all.forwarding", "1"); err != nil {
			return err
		}
	}
	if err := n.installRules(); err != nil {
		return err
	}
	n.cfg.Log("enabled forwarding and NAT")
	return nil
}

func (n *Network) installRules() error {
	ruleset := Ruleset(n.name, n.cfg.IPv4, n.cfg.IPv6, n.cfg.HostAccess)
	if err := run([]byte(ruleset), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("installing nftables NAT rules: %w", err)
	}
	n.nft = true
	return nil
}

// changeSysctl sets a sysctl and remembers its value for Close.
func (n *Network) changeSysctl(key, value string) error {
	old, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err := SetSysctl(key, value); err != nil {
		return err
	}
	if v := strings.TrimSpace(string(old)); err == nil && v != value {
		n.changed = append(n.changed, sysctl{key, v})
	}
	return nil
}

// Repair puts back what something else undid in the host's configuration
// since Open: the nftables table (a firewall that reloads with `nft flush
// ruleset` removes it, and the tunnel then carries no traffic) and IP
// forwarding. It returns what it repaired.
func (n *Network) Repair() []string {
	if !n.cfg.Manage {
		return nil
	}
	var fixed []string
	if err := run(nil, "nft", "list", "table", "inet", NFTTable); err != nil {
		if err := n.installRules(); err != nil {
			fixed = append(fixed, "the nftables rules are gone and could not be installed again: "+err.Error())
		} else {
			fixed = append(fixed, "the nftables rules were removed by something else; installed them again")
		}
	}
	keys := []string{"net.ipv4.ip_forward"}
	if n.cfg.IPv6.IsValid() {
		keys = append(keys, "net.ipv6.conf.all.forwarding")
	}
	for _, key := range keys {
		if v, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/")); err == nil && strings.TrimSpace(string(v)) != "1" {
			if err := SetSysctl(key, "1"); err != nil {
				fixed = append(fixed, err.Error())
			} else {
				fixed = append(fixed, key+" was turned off by something else; turned it on again")
			}
		}
	}
	return fixed
}

// Ruleset is the nftables script of forwarding, NAT and the protection of the
// host itself for the tunnel interface. The first two lines make loading
// idempotent.
//
// Traffic from clients to the host (the input chain) is limited to ICMP and
// replies unless hostAccess: the server's own tunnel address and its public
// addresses are reachable by clients, and without this, so would be every
// service listening on all addresses.
func Ruleset(iface string, v4, v6 netip.Prefix, hostAccess bool) string {
	nat := fmt.Sprintf("\t\tip saddr %s oifname != %q masquerade\n", v4.Masked(), iface)
	if v6.IsValid() {
		nat += fmt.Sprintf("\t\tip6 saddr %s oifname != %q masquerade\n", v6.Masked(), iface)
	}
	input := ""
	if !hostAccess {
		input = fmt.Sprintf(`	chain input {
		type filter hook input priority filter; policy accept;
		iifname %[1]q ct state established,related accept
		iifname %[1]q meta l4proto { icmp, ipv6-icmp } accept
		iifname %[1]q drop
	}
`, iface)
	}
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
%[4]s	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname %[2]q accept
		oifname %[2]q ct state established,related accept
		oifname %[2]q drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
%[3]s	}
}
`, NFTTable, iface, nat, input)
}

// keepRouterAdvertisements: enabling IPv6 forwarding makes Linux ignore
// router advertisements, which can remove the server's own IPv6 default
// route; accept_ra = 2 keeps accepting them where they are accepted now.
func (n *Network) keepRouterAdvertisements() {
	dirs, _ := filepath.Glob("/proc/sys/net/ipv6/conf/*")
	for _, dir := range dirs {
		name := filepath.Base(dir)
		if name == "all" || name == "default" || name == "lo" || name == n.name {
			continue
		}
		v, err := os.ReadFile(filepath.Join(dir, "accept_ra"))
		if err != nil || strings.TrimSpace(string(v)) != "1" {
			continue
		}
		if err := n.changeSysctl("net.ipv6.conf."+name+".accept_ra", "2"); err != nil {
			n.cfg.Log(fmt.Sprintf("could not keep router advertisements on %s: %v", name, err))
		} else {
			n.cfg.Log("set accept_ra=2 on " + name + " so IPv6 forwarding keeps the default route")
		}
	}
}

// Name is the TUN device's name.
func (n *Network) Name() string { return n.name }

// Read reads one packet from the TUN device.
func (n *Network) Read(b []byte) (int, error) { return n.tun.Read(b) }

// Write writes one packet to the TUN device.
func (n *Network) Write(b []byte) (int, error) { return n.tun.Write(b) }

// Close removes the device (it disappears with its file descriptor), the
// NAT rules, and the sysctl changes (forwarding) made for them.
func (n *Network) Close() error {
	if n.nft {
		_ = run(nil, "nft", "delete", "table", "inet", NFTTable)
		n.nft = false
	}
	// Forwarding was off before: the host is not a router any more.
	for i := len(n.changed) - 1; i >= 0; i-- {
		_ = SetSysctl(n.changed[i].key, n.changed[i].old)
	}
	n.changed = nil
	return n.tun.Close()
}

// SetSysctl writes a sysctl such as "net.ipv4.ip_forward".
func SetSysctl(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if err := os.WriteFile(path, []byte(value), 0); err != nil {
		return fmt.Errorf("setting %s=%s: %w", key, value, err)
	}
	return nil
}

func run(stdin []byte, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Forget deletes the kernel's connection tracking entries whose original
// source or destination is in prefixes, and returns how many it deleted.
// The NAT keeps an entry for each connection a client made, for up to five
// days for an established TCP connection; replies matching it reach whoever
// holds the address now. So before an address another session used is
// handed out again, and for the whole pool at start-up, its entries go.
func Forget(prefixes []netip.Prefix) (int, error) {
	total := 0
	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		var filters []netlink.CustomConntrackFilter
		for _, p := range prefixes {
			if p.Addr().Is4() != (family == unix.AF_INET) {
				continue
			}
			ipnet := &net.IPNet{IP: p.Masked().Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
			for _, t := range []netlink.ConntrackFilterType{netlink.ConntrackOrigSrcIP, netlink.ConntrackOrigDstIP} {
				f := &netlink.ConntrackFilter{}
				if err := f.AddIPNet(t, ipnet); err != nil {
					return total, err
				}
				filters = append(filters, f)
			}
		}
		if len(filters) == 0 {
			continue
		}
		n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, family, filters...)
		total += int(n)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return total, err
		}
	}
	return total, nil
}

// SetTCPUserTimeout sets TCP_USER_TIMEOUT: the kernel ends the connection
// when data sent on it stays unacknowledged for d, and also when keepalive
// probes go unanswered that long.
func SetTCPUserTimeout(c *net.TCPConn, d time.Duration) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d.Milliseconds()))
	}); err != nil {
		return err
	}
	return serr
}
