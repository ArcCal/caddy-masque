//go:build !linux

// The host side of the tunnel needs Linux (a TUN device, nftables and
// connection tracking). Elsewhere the module builds, so a Caddy with it can
// serve its other sites, but the masque app refuses to start.
package hostnet

import (
	"errors"
	"net/netip"
	"runtime"
)

// NFTTable is the nftables table of forwarding and NAT.
const NFTTable = "caddy-masque"

// Config describes the tunnel interface.
type Config struct {
	Interface  string
	IPv4       netip.Prefix
	IPv6       netip.Prefix
	MTU        int
	Manage     bool
	HostAccess bool
	Log        func(msg string)
}

// Network is the TUN device and the host configuration around it.
type Network struct{}

var errLinuxOnly = errors.New("the masque app needs Linux (a TUN device, nftables and connection tracking); this is " + runtime.GOOS)

// Open fails: the tunnel's host side exists only on Linux.
func Open(Config) (*Network, error) { return nil, errLinuxOnly }

func (*Network) Name() string              { return "" }
func (*Network) Read([]byte) (int, error)  { return 0, errLinuxOnly }
func (*Network) Write([]byte) (int, error) { return 0, errLinuxOnly }
func (*Network) Close() error              { return nil }
func (*Network) Repair() []string          { return nil }
func SetSysctl(string, string) error       { return errLinuxOnly }
func Forget([]netip.Prefix) (int, error)   { return 0, errLinuxOnly }
