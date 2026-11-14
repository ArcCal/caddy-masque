package quic

import (
	"crypto/rand"
	"net"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type pathID int64

const invalidPathID pathID = -1

// Maximum number of paths to keep track of.
// If the peer probes another path (before the pathTimeout of an existing path expires),
// this probing attempt is ignored.
const maxPaths = 3

// If no packet is received for a path for pathTimeout,
// the path can be evicted when the peer probes another path.
// This prevents an attacker from churning through paths by duplicating packets and
// sending them with spoofed source addresses.
const pathTimeout = 5 * time.Second

type path struct {
	id               pathID
	addr             net.Addr
	lastPacketTime   monotime.Time
	pathChallenge    [8]byte
	validated        bool
	rcvdNonProbing   bool
	probedPrevious   bool
	bytesReceived    protocol.ByteCount
	bytesSent        protocol.ByteCount
	challengePadded  bool
	mtuValidated     bool
	needsMTUProbe    bool
	info             packetInfo
	pathChallenges   [][8]byte
	nextProbeTime    monotime.Time
	paddedChallenges map[[8]byte]bool
}

type pathManager struct {
	nextPathID pathID
	// ordered by lastPacketTime, with the most recently used path at the end
	paths []*path

	getConnID    func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID func(pathID)

	logger utils.Logger
}

func newPathManager(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	logger utils.Logger,
) *pathManager {
	return &pathManager{
		paths:        make([]*path, 0, maxPaths+1),
		getConnID:    getConnID,
		retireConnID: retireConnID,
		logger:       logger,
	}
}

// Returns a path challenge frame if one should be sent.
// May return nil.
// The path must have been created by GetOrCreatePath.
func (pm *pathManager) HandlePacket(
	remoteAddr net.Addr,
	t monotime.Time,
	pathChallenges []*wire.PathChallengeFrame, // may be nil if the packet did not contain a PATH_CHALLENGE
	isNonProbing bool,
	bytesReceived protocol.ByteCount,
	info packetInfo,
) (_ protocol.ConnectionID, _ []ackhandler.Frame, shouldSwitch bool) {
	if _, _, ok := pm.GetOrCreatePath(remoteAddr, t); !ok {
		return protocol.ConnectionID{}, nil, false
	}
	var p *path
	for i, path := range pm.paths {
		if addrsEqual(path.addr, remoteAddr) {
			p = path
			p.lastPacketTime = t
			p.bytesReceived += bytesReceived
			p.info = info
			if isNonProbing {
				path.rcvdNonProbing = true
			}
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for path %s, validated: %t", remoteAddr, path.validated)
			}
			shouldSwitch = path.validated && path.mtuValidated && path.rcvdNonProbing
			if i != len(pm.paths)-1 {
				// move the path to the end of the list
				pm.paths = slices.Delete(pm.paths, i, i+1)
				pm.paths = append(pm.paths, p)
			}
			if len(pathChallenges) == 0 && !path.needsMTUProbe && (path.mtuValidated || t.Before(path.nextProbeTime)) {
				return protocol.ConnectionID{}, nil, shouldSwitch
			}
			break
		}
	}

	if p == nil {
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	connID, ok := pm.getConnID(p.id)
	if !ok {
		pm.logger.Debugf("skipping validation of new path %s since no connection ID is available", remoteAddr)
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	frames := make([]ackhandler.Frame, 0, 2)
	// Probe an unvalidated path with a new PATH_CHALLENGE:
	// * sent on the next packet once nextProbeTime has passed, and
	// * repeated until a PATH_RESPONSE arrives, ignoring ACKs and loss.
	if (!p.mtuValidated && !t.Before(p.nextProbeTime)) || p.needsMTUProbe {
		backoffFactor := 1 << len(p.pathChallenges)
		p.nextProbeTime = t.Add(utils.DefaultInitialRTT * time.Duration(backoffFactor))
		var b [8]byte
		rand.Read(b[:])
		p.pathChallenges = append(p.pathChallenges, b)
		p.pathChallenge = b
		p.challengePadded = false
		p.needsMTUProbe = false
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: b},
			Handler: emptyHandler{},
		})
		pm.logger.Debugf("enqueueing PATH_CHALLENGE for new path %s", remoteAddr)
	}
	for _, challenge := range pathChallenges {
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathResponseFrame{Data: challenge.Data},
			Handler: emptyHandler{},
		})
	}
	return connID, frames, shouldSwitch
}

// NextMTUProbe also runs when a PATH_RESPONSE arrived on a different path.
// Address validation is path-independent; the MTU probe must use the path
// where the undersized challenge was sent.
func (pm *pathManager) NextMTUProbe() (protocol.ConnectionID, []ackhandler.Frame, *path) {
	for _, p := range pm.paths {
		if !p.needsMTUProbe {
			continue
		}
		connID, ok := pm.getConnID(p.id)
		if !ok {
			continue
		}
		p.nextProbeTime = monotime.Now().Add(utils.DefaultInitialRTT * time.Duration(1<<len(p.pathChallenges)))
		rand.Read(p.pathChallenge[:])
		p.pathChallenges = append(p.pathChallenges, p.pathChallenge)
		p.needsMTUProbe = false
		p.challengePadded = false
		return connID, []ackhandler.Frame{{
			Frame:   &wire.PathChallengeFrame{Data: p.pathChallenge},
			Handler: emptyHandler{},
		}}, p
	}
	return protocol.ConnectionID{}, nil, nil
}

// GetOrCreatePath returns the ID of the path for the remote address, creating the path if necessary.
// It returns false if the path limit is reached.
func (pm *pathManager) GetOrCreatePath(remoteAddr net.Addr, t monotime.Time) (_ pathID, isNew, ok bool) {
	for _, p := range pm.paths {
		if addrsEqual(p.addr, remoteAddr) {
			return p.id, false, true
		}
	}

	// new path while already at maxPaths
	if len(pm.paths) >= maxPaths {
		// ignore it if the oldest path received a packet within pathTimeout
		if pm.paths[0].lastPacketTime.Add(pathTimeout).After(t) {
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for previously unseen path %s, but already have %d paths", remoteAddr, len(pm.paths))
			}
			return invalidPathID, false, false
		}
		// evict the oldest path, if the last packet was received more than pathTimeout ago
		pm.retireConnID(pm.paths[0].id)
		pm.paths = pm.paths[1:]
	}

	p := &path{
		id:             pm.nextPathID,
		addr:           remoteAddr,
		lastPacketTime: t,
		nextProbeTime:  t,
		pathChallenges: make([][8]byte, 0, 2),
	}
	pm.nextPathID++
	pm.paths = append(pm.paths, p)
	return p.id, true, true
}

func (pm *pathManager) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	for _, p := range pm.paths {
		if slices.Contains(p.pathChallenges, f.Data) {
			// path validated
			p.validated = true
			p.mtuValidated = p.mtuValidated || p.paddedChallenges[f.Data]
			// Consume the proof once: duplicate small responses cannot create more MTU probes.
			p.pathChallenges = slices.DeleteFunc(p.pathChallenges, func(data [8]byte) bool { return data == f.Data })
			delete(p.paddedChallenges, f.Data)
			p.needsMTUProbe = !p.mtuValidated
			if p.mtuValidated {
				p.pathChallenges = nil
				clear(p.paddedChallenges)
			}
			pm.logger.Debugf("path %s validated", p.addr)
			break
		}
	}
}

func (pm *pathManager) ProbeSize(addr net.Addr) protocol.ByteCount {
	for _, p := range pm.paths {
		if addrsEqual(p.addr, addr) {
			if p.validated {
				return protocol.MinInitialPacketSize
			}
			return min(protocol.MinInitialPacketSize, 3*p.bytesReceived-p.bytesSent)
		}
	}
	return 0
}

func (pm *pathManager) SentProbe(addr net.Addr, size protocol.ByteCount, frames []ackhandler.Frame) {
	for _, p := range pm.paths {
		if !addrsEqual(p.addr, addr) {
			continue
		}
		p.bytesSent += size
		for _, frame := range frames {
			if challenge, ok := frame.Frame.(*wire.PathChallengeFrame); ok && slices.Contains(p.pathChallenges, challenge.Data) {
				if p.paddedChallenges == nil {
					p.paddedChallenges = make(map[[8]byte]bool)
				}
				p.paddedChallenges[challenge.Data] = size >= protocol.MinInitialPacketSize
				if challenge.Data == p.pathChallenge {
					p.challengePadded = size >= protocol.MinInitialPacketSize
				}
			}
		}
		return
	}
}

func (pm *pathManager) IDForPath(addr net.Addr) (pathID, bool) {
	for _, p := range pm.paths {
		if addrsEqual(p.addr, addr) {
			return p.id, true
		}
	}
	return invalidPathID, false
}

// SwitchToPath is called when the connection switches to a new path
func (pm *pathManager) SwitchToPath(addr net.Addr) {
	// retire all other paths
	for _, path := range pm.paths {
		if addrsEqual(path.addr, addr) {
			pm.logger.Debugf("switching to path %d (%s)", path.id, addr)
			continue
		}
		pm.retireConnID(path.id)
	}
	clear(pm.paths)
	pm.paths = pm.paths[:0]
}

func addrsEqual(addr1, addr2 net.Addr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	a1, ok1 := addr1.(*net.UDPAddr)
	a2, ok2 := addr2.(*net.UDPAddr)
	if ok1 && ok2 {
		return a1.IP.Equal(a2.IP) && a1.Port == a2.Port
	}
	return addr1.String() == addr2.String()
}
