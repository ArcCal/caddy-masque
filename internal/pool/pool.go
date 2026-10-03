// Package pool assigns tunnel addresses. RFC 9484 §11: proxies SHOULD
// avoid persistent per-client assignment, so each session gets a random
// free address that goes back to the pool when the session ends.
//
// A returned address is handed out again as late as possible: first come
// addresses no session has used yet, picked at random, then the one that
// was returned longest ago, which keeps it free for its user's
// reconnection. The kernel keeps the NAT state of a session's connections
// after the session ends, and replies matching it would reach whoever holds
// the address next, so the pool tells which addresses were used before:
// the server deletes their connection tracking entries before handing them
// out. It follows masque-vpn's pool module.
package pool

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net/netip"
)

// IPv6 prefixes with at least this many host bits (a /64 or shorter) get
// random interface identifiers, which essentially never repeat, instead of
// tracked reuse. In a smaller prefix a random pick can be an address
// another session used while its connection tracking entries are still
// there (a /112 holds only 65 536 addresses), so those are tracked like IPv4
// pools, and a reused address is cleared first. masque-vpn uses the same
// threshold.
const randomIIDBits = 64

type entry struct {
	host uint64
	seq  uint64
}

// family holds the client addresses of one family as host numbers within
// the prefix.
type family struct {
	v6       bool
	base     netip.Addr // network address
	hostBits int
	// Tracked families: assignable host numbers are 1..last except own.
	last    uint64
	own     uint64
	tracked bool
	inUse   map[netip.Addr]bool
	// Returned addresses not in use, with the sequence number of their
	// return, and the same in order of return; order may hold stale
	// entries (reused since), only those matching returned count.
	returned map[uint64]uint64
	order    []entry
	nextSeq  uint64
	ownAddr  netip.Addr
}

func newFamily(p netip.Prefix) *family {
	base := p.Masked().Addr()
	hostBits := p.Addr().BitLen() - p.Bits()
	f := &family{v6: p.Addr().Is6(), base: base, hostBits: hostBits, inUse: map[netip.Addr]bool{},
		returned: map[uint64]uint64{}, ownAddr: p.Addr()}
	if !f.v6 || hostBits < randomIIDBits {
		f.tracked = true
		if f.v6 {
			// Host 0 is the subnet-router anycast address (RFC 4291 §2.6.1).
			f.last = 1<<hostBits - 1
		} else {
			// Neither the network nor the broadcast address.
			if hostBits >= 2 {
				f.last = 1<<hostBits - 2
			}
		}
		f.own = f.host(p.Addr())
	}
	return f
}

// host is the host number of an address in a tracked family.
func (f *family) host(a netip.Addr) uint64 {
	b, base := a.AsSlice(), f.base.AsSlice()
	var n uint64
	for i := range b {
		n = n<<8 | uint64(b[i]-base[i])
	}
	return n
}

func (f *family) addr(host uint64) netip.Addr {
	b := f.base.AsSlice()
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], host)
	for i := 0; i < 8 && i < len(b); i++ {
		b[len(b)-1-i] |= hb[7-i]
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// hostOf is the host number of an assignable address of the pool.
func (f *family) hostOf(a netip.Addr) (uint64, bool) {
	if !netip.PrefixFrom(f.base, f.base.BitLen()-f.hostBits).Contains(a) || a.Is4() == f.v6 {
		return 0, false
	}
	h := f.host(a)
	return h, h >= 1 && h <= f.last && h != f.own
}

func (f *family) capacity() uint64 {
	if f.own >= 1 && f.own <= f.last {
		return f.last - 1
	}
	return f.last
}

func randomUint64(n uint64) uint64 {
	v, err := rand.Int(rand.Reader, new(big.Int).SetUint64(n))
	if err != nil {
		panic("system random number generator: " + err.Error())
	}
	return v.Uint64()
}

func (f *family) allocate() (netip.Addr, bool, bool) {
	if !f.tracked {
		for range 64 {
			b := f.base.AsSlice()
			r := make([]byte, len(b))
			_, _ = rand.Read(r)
			bits := f.hostBits
			for i := len(b) - 1; i >= 0 && bits > 0; i-- {
				n := min(bits, 8)
				b[i] |= r[i] & byte(1<<n-1)
				bits -= n
			}
			a, _ := netip.AddrFromSlice(b)
			if a != f.base && a != f.ownAddr && !f.inUse[a] {
				f.inUse[a] = true
				// Random identifiers in a prefix this large essentially
				// never repeat; the server clears the prefix at start-up.
				return a, false, true
			}
		}
		return netip.Addr{}, false, false
	}
	if f.last == 0 {
		return netip.Addr{}, false, false
	}
	var host uint64
	used := false
	if f.capacity() > uint64(len(f.inUse)+len(f.returned)) {
		// Some address has never been used: pick one at random.
		start := randomUint64(f.last)
		found := false
		for i := uint64(0); i < f.last; i++ {
			h := 1 + (start+i)%f.last
			if _, back := f.returned[h]; h != f.own && !f.inUse[f.addr(h)] && !back {
				host, found = h, true
				break
			}
		}
		if !found {
			return netip.Addr{}, false, false
		}
	} else {
		// All have been used: the one returned longest ago.
		for {
			if len(f.order) == 0 {
				return netip.Addr{}, false, false
			}
			e := f.order[0]
			f.order = f.order[1:]
			if seq, ok := f.returned[e.host]; ok && seq == e.seq {
				delete(f.returned, e.host)
				host, used = e.host, true
				break
			}
		}
	}
	a := f.addr(host)
	f.inUse[a] = true
	return a, used, true
}

func (f *family) claim(a netip.Addr) bool {
	if f.tracked {
		h, ok := f.hostOf(a)
		if !ok || f.inUse[a] {
			return false
		}
		f.inUse[a] = true
		delete(f.returned, h)
		return true
	}
	if !netip.PrefixFrom(f.base, f.base.BitLen()-f.hostBits).Contains(a) || a == f.base || a == f.ownAddr || f.inUse[a] {
		return false
	}
	f.inUse[a] = true
	return true
}

func (f *family) release(a netip.Addr) {
	if !f.inUse[a] {
		return
	}
	delete(f.inUse, a)
	if !f.tracked {
		return
	}
	h := f.host(a)
	f.nextSeq++
	f.returned[h] = f.nextSeq
	f.order = append(f.order, entry{h, f.nextSeq})
	// Addresses claimed again leave stale entries behind; keep them from
	// piling up when the pool is never short of fresh addresses.
	if len(f.order) > 2*len(f.returned)+64 {
		kept := f.order[:0]
		for _, e := range f.order {
			if seq, ok := f.returned[e.host]; ok && seq == e.seq {
				kept = append(kept, e)
			}
		}
		f.order = kept
	}
}

// Pool hands out client addresses of up to one IPv4 and one IPv6 prefix.
// Not safe for concurrent use.
type Pool struct{ v4, v6 *family }

// New makes a pool. The prefixes carry the server's own tunnel addresses
// (for example 10.89.0.1/24); clients get other addresses in them. An
// invalid prefix leaves the family out.
func New(v4, v6 netip.Prefix) *Pool {
	p := &Pool{}
	if v4.IsValid() {
		p.v4 = newFamily(v4)
	}
	if v6.IsValid() {
		p.v6 = newFamily(v6)
	}
	return p
}

func (p *Pool) family(v6 bool) *family {
	if v6 {
		return p.v6
	}
	return p.v4
}

// Allocate picks a free address of a family (see the package
// documentation for which) and tells whether a session used it before.
func (p *Pool) Allocate(v6 bool) (addr netip.Addr, usedBefore bool, ok bool) {
	f := p.family(v6)
	if f == nil {
		return netip.Addr{}, false, false
	}
	return f.allocate()
}

// Claim reserves a specific address if it belongs to the pool and is free.
func (p *Pool) Claim(a netip.Addr) bool {
	f := p.family(a.Is6())
	return f != nil && f.claim(a)
}

// Release returns an address.
func (p *Pool) Release(a netip.Addr) {
	if f := p.family(a.Is6()); f != nil {
		f.release(a)
	}
}
