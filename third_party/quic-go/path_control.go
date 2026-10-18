package quic

import (
	"crypto/rand"
	"net"
	"slices"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// Capture the route when a control frame is queued: processing another packet
// in the same receive batch can migrate the connection before it is sent.
type boundPathControl struct {
	frame  wire.Frame
	connID protocol.ConnectionID
	addr   net.Addr
	info   packetInfo
	credit *pathControlCredit
}

// Former paths have independent probe recovery. Limit each bound route to
// one outstanding 1200-byte datagram instead of borrowing the new path's window.
type pathControlCredit struct {
	addr     net.Addr
	info     packetInfo
	inFlight bool
}

type pathControlCreditHandler struct {
	credit   *pathControlCredit
	conn     *Conn
	released bool
}

func (h *pathControlCreditHandler) OnAcked(wire.Frame) { h.release() }
func (h *pathControlCreditHandler) OnLost(wire.Frame)  { h.release() }
func (h *pathControlCreditHandler) release() {
	if h.released {
		return
	}
	h.released = true
	h.credit.inFlight = false
	h.conn.scheduleSending()
}

func (c *Conn) pathControlCredit(addr net.Addr, info packetInfo) *pathControlCredit {
	for _, credit := range c.pathControlCredits {
		if addrsEqual(credit.addr, addr) && credit.info == info {
			return credit
		}
	}
	// Keep credit discoverable until both the queued frames and the sent
	// datagram are gone. The store shares the queue's explicit resource bound.
	c.pathControlCredits = slices.DeleteFunc(c.pathControlCredits, func(credit *pathControlCredit) bool {
		if credit.inFlight {
			return false
		}
		for _, control := range c.boundPathControls {
			if control.credit == credit {
				return false
			}
		}
		return true
	})
	if len(c.pathControlCredits) >= maxPathResponses+maxPaths {
		return nil
	}
	credit := &pathControlCredit{addr: addr, info: info}
	c.pathControlCredits = append(c.pathControlCredits, credit)
	return credit
}

type previousPathProbe struct {
	addr      net.Addr
	data      [8]byte
	validated bool
}

func (c *Conn) queueBoundPathResponses(challenges []*wire.PathChallengeFrame, addr net.Addr, info packetInfo) {
	if len(challenges) == 0 {
		return
	}
	credit := c.pathControlCredit(addr, info)
	if credit == nil {
		return
	}
	for _, challenge := range challenges {
		if len(c.boundPathControls) >= maxPathResponses {
			break // retain the existing bounded PATH_RESPONSE queue policy
		}
		c.boundPathControls = append(c.boundPathControls, boundPathControl{
			frame: &wire.PathResponseFrame{Data: challenge.Data}, connID: c.connIDManager.PinPathControlCID(), addr: addr, info: info, credit: credit,
		})
	}
	if len(challenges) > 0 {
		c.scheduleSending()
	}
}

func (c *Conn) probePreviousPath(candidate net.Addr) {
	var path *path
	for _, p := range c.pathManager.paths {
		if addrsEqual(p.addr, candidate) {
			path = p
			break
		}
	}
	if path == nil || path.probedPrevious {
		return
	}
	addr := c.RemoteAddr()
	p := &previousPathProbe{addr: addr}
	rand.Read(p.data[:])
	var info packetInfo
	if conn, ok := c.conn.(interface{ currentPacketInfo() packetInfo }); ok {
		info = conn.currentPacketInfo()
	}
	// Old-path challenges have at most maxPaths additional slots, independent
	// of the existing response cap. They are not retransmitted after loss.
	if len(c.boundPathControls) >= maxPathResponses+maxPaths {
		return
	}
	credit := c.pathControlCredit(addr, info)
	if credit == nil {
		return
	}
	path.probedPrevious = true
	if len(c.previousPathProbes) == maxPaths {
		c.previousPathProbes = c.previousPathProbes[1:]
	}
	c.previousPathProbes = append(c.previousPathProbes, p)
	c.boundPathControls = append(c.boundPathControls, boundPathControl{
		frame: &wire.PathChallengeFrame{Data: p.data}, connID: c.connIDManager.PinPathControlCID(), addr: addr, info: info, credit: credit,
	})
	c.scheduleSending()
}

func (c *Conn) refreshBoundPathCID(index int) bool {
	first := c.boundPathControls[index]
	if c.connIDManager.PathControlCIDValid(first.connID) {
		return true
	}
	// A peer's Retire Prior To overrides local pins. Refresh every frame
	// on this bound route together, so one temporary CID covers the batch.
	for i, control := range c.boundPathControls {
		if control.connID != first.connID || !addrsEqual(control.addr, first.addr) || control.info != first.info {
			continue
		}
		var replacement protocol.ConnectionID
		if addrsEqual(control.addr, c.RemoteAddr()) {
			if !c.connIDManager.HasActiveConnectionID() {
				return false
			}
			replacement = c.connIDManager.PinPathControlCID()
		} else {
			var ok bool
			replacement, ok = c.connIDManager.RefreshPathControlCID(first.connID)
			if !ok {
				return false // RFC 9000 section 9.5: wait for an unused CID
			}
		}
		c.boundPathControls[i].connID = replacement
		c.connIDManager.ReleasePathControlCID(first.connID)
	}
	return true
}

func (c *Conn) flushBoundPathControls(now monotime.Time) error {
	for len(c.boundPathControls) > 0 {
		if !c.sentPacketHandler.HasCongestionBudget(protocol.MinInitialPacketSize) {
			return nil
		}
		index := -1
		for i, control := range c.boundPathControls {
			if addrsEqual(control.addr, c.RemoteAddr()) || !control.credit.inFlight {
				if !c.refreshBoundPathCID(i) {
					continue
				}
				index = i
				break
			}
		}
		if index < 0 {
			return nil
		}
		first := c.boundPathControls[index]
		maxPayload := protocol.MinInitialPacketSize - protocol.ByteCount(1+first.connID.Len()+4+16)
		var size protocol.ByteCount
		var frames []ackhandler.Frame
		var hasChallenge bool
		for _, next := range c.boundPathControls[index:] {
			if !addrsEqual(next.addr, first.addr) || next.info != first.info || next.connID != first.connID {
				break
			}
			if _, ok := next.frame.(*wire.PathChallengeFrame); ok {
				if hasChallenge {
					break // RFC 9000 section 8.2.1: one challenge per packet
				}
				hasChallenge = true
			}
			size += next.frame.Length(c.version)
			if size > maxPayload {
				break
			}
			frames = append(frames, ackhandler.Frame{Frame: next.frame})
		}
		probe, buf, err := c.packer.PackPathProbePacket(first.connID, frames, protocol.MinInitialPacketSize, c.version)
		if err != nil {
			return err
		}
		// The still-active path consumes its ordinary congestion credit. A
		// former path uses independent probe recovery (RFC 9000 section 9.4)
		// so its acknowledgments cannot update the new path's RTT or window.
		probe.IsPathProbePacket = !addrsEqual(first.addr, c.RemoteAddr())
		if probe.IsPathProbePacket {
			first.credit.inFlight = true
			handler := &pathControlCreditHandler{credit: first.credit, conn: c}
			for i := range probe.Frames {
				probe.Frames[i].Handler = handler
			}
		}
		c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
		c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
		c.sendQueue.SendProbe(buf, first.addr, first.info)
		for _, control := range c.boundPathControls[index : index+len(frames)] {
			c.connIDManager.ReleasePathControlCID(control.connID)
		}
		c.boundPathControls = slices.Delete(c.boundPathControls, index, index+len(frames))
	}
	return nil
}
