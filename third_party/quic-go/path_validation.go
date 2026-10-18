package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
)

func (c *Conn) sendPathProbeFrames(destConnID protocol.ConnectionID, frames []ackhandler.Frame, remoteAddr net.Addr, info packetInfo, now monotime.Time, datagramPayloadChecksum qlog.DatagramPayloadChecksum) error {
	for len(frames) > 0 {
		maxSize := c.pathManager.ProbeSize(remoteAddr)
		// Reserve the largest packet number and AEAD tag before selecting
		// responses. A packet can contain more challenges than fit in one reply.
		maxPayload := maxSize - protocol.ByteCount(1+destConnID.Len()+4+16)
		var numFrames int
		var payloadSize protocol.ByteCount
		for _, frame := range frames {
			payloadSize += frame.Frame.Length(c.version)
			if payloadSize > maxPayload {
				break
			}
			numFrames++
		}
		if numFrames == 0 {
			break // the unvalidated path's remaining allowance is exhausted
		}
		probeFrames := frames[:numFrames]
		probe, buf, err := c.packer.PackPathProbePacket(destConnID, probeFrames, maxSize, c.version)
		if err != nil {
			return err
		}
		c.logger.Debugf("sending path probe packet to %s", remoteAddr)
		c.logShortHeaderPacketWithDatagramPayloadChecksum(probe, protocol.ECNNon, buf.Len(), false, datagramPayloadChecksum)
		c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
		c.pathManager.SentProbe(remoteAddr, buf.Len(), probeFrames)
		c.sendQueue.SendProbe(buf, remoteAddr, info)
		frames = frames[numFrames:]
	}
	return nil
}

func (c *Conn) flushPathMTUProbes(now monotime.Time) error {
	if c.pathManager == nil {
		return nil
	}
	for {
		connID, frames, path := c.pathManager.NextMTUProbe()
		if path == nil {
			return nil
		}
		if err := c.sendPathProbeFrames(connID, frames, path.addr, path.info, now, 0); err != nil {
			return err
		}
	}
}
