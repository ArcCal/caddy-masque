package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestBufferedPacketReceiptAccounting(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(map[int]string{1: "single", 2: "coalesced"}[count], func(t *testing.T) {
			ctrl := gomock.NewController(t)
			unpacker := NewMockUnpacker(ctrl)
			tc := newServerTestConnection(t, ctrl, nil, false, connectionOptUnpacker(unpacker))
			c := tc.conn
			// 0-RTT can be buffered before read keys exist and processed before
			// a Handshake packet validates the address. Keep the real budget.
			c.sentPacketHandler = ackhandler.NewSentPacketHandler(0, 1200, c.rttStats, &c.connStats,
				false, false, c.receivedPacketHandler.IgnorePacketsBelow, protocol.PerspectiveServer, nil, c.logger)
			hdr := wire.ExtendedHeader{Header: wire.Header{
				Type: protocol.PacketType0RTT, DestConnectionID: tc.srcConnID,
				SrcConnectionID: tc.destConnID, Length: 2, Version: protocol.Version1,
			}, PacketNumberLen: protocol.PacketNumberLen1}
			packet := getLongHeaderPacket(t, tc.remoteAddr, &hdr, []byte{0})
			for i := 1; i < count; i++ {
				hdr.PacketNumber = protocol.PacketNumber(i)
				next := getLongHeaderPacket(t, tc.remoteAddr, &hdr, []byte{0})
				packet.data = append(packet.data, next.data...)
				next.buffer.Release()
			}
			physicalBytes := packet.Size()
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable).Times(count)
			processed, err := c.handleOnePacket(packet, 0)
			require.NoError(t, err)
			require.False(t, processed)
			require.Len(t, c.undecryptablePackets, count)
			require.Equal(t, 3*physicalBytes, c.sentPacketHandler.AmplificationBudget())

			// A new key event retries every buffered encryption level. Keys
			// for this packet may still be unavailable (including rejected
			// 0-RTT before Initial keys are discarded).
			queued := c.undecryptablePackets
			c.undecryptablePackets = nil
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable).Times(count)
			for _, p := range queued {
				_, err = c.handleOnePacket(p.receivedPacket, p.checksum)
				require.NoError(t, err)
			}
			t.Logf("network bytes=%d, bytes recorded after deferred retry=%d, remaining budget=%d", physicalBytes,
				c.connStats.BytesReceived.Load(), c.sentPacketHandler.AmplificationBudget())
			require.Equal(t, 3*physicalBytes, c.sentPacketHandler.AmplificationBudget())

			var pn protocol.PacketNumber
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
				func(h *wire.Header, _ []byte) (*unpackedPacket, error) {
					result := &unpackedPacket{hdr: &wire.ExtendedHeader{Header: *h,
						PacketNumberLen: protocol.PacketNumberLen1, PacketNumber: pn},
						encryptionLevel: protocol.Encryption0RTT, data: []byte{0}}
					pn++
					return result, nil
				}).Times(count)
			queued = c.undecryptablePackets
			c.undecryptablePackets = nil
			for _, p := range queued {
				processed, err = c.handleOnePacket(p.receivedPacket, p.checksum)
				require.NoError(t, err)
				require.True(t, processed)
			}
			require.Equal(t, uint64(physicalBytes), c.connStats.BytesReceived.Load(), "decrypting buffered packets is not a new UDP receipt")
			require.Equal(t, 3*physicalBytes, c.sentPacketHandler.AmplificationBudget(), "buffer processing must not create send credit")

			// A separately received duplicate datagram really uses network
			// bytes, so it still earns credit even if its packets are duplicates.
			duplicate := receivedPacket{remoteAddr: tc.remoteAddr, data: append([]byte(nil), packet.data...),
				buffer: getPacketBuffer(), rcvTime: packet.rcvTime}
			pn = 0
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
				func(h *wire.Header, _ []byte) (*unpackedPacket, error) {
					result := &unpackedPacket{hdr: &wire.ExtendedHeader{Header: *h,
						PacketNumberLen: protocol.PacketNumberLen1, PacketNumber: pn},
						encryptionLevel: protocol.Encryption0RTT, data: []byte{0}}
					pn++
					return result, nil
				}).Times(count)
			_, err = c.handleOnePacket(duplicate, 0)
			require.NoError(t, err)
			require.Equal(t, uint64(2*physicalBytes), c.connStats.BytesReceived.Load())
			require.Equal(t, 6*physicalBytes, c.sentPacketHandler.AmplificationBudget())
		})
	}
}

func TestDuplicateNetworkReceiptEarnsCredit(t *testing.T) {
	ctrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(ctrl)
	tc := newServerTestConnection(t, ctrl, nil, false, connectionOptUnpacker(unpacker))
	c := tc.conn
	c.sentPacketHandler = ackhandler.NewSentPacketHandler(0, 1200, c.rttStats, &c.connStats,
		false, false, c.receivedPacketHandler.IgnorePacketsBelow, protocol.PerspectiveServer, nil, c.logger)
	hdr := wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketType0RTT,
		DestConnectionID: tc.srcConnID, SrcConnectionID: tc.destConnID, Length: 2, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen1}
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysDropped).Times(2)
	var total protocol.ByteCount
	for i := 0; i < 2; i++ {
		p := getLongHeaderPacket(t, tc.remoteAddr, &hdr, []byte{0})
		total += p.Size()
		_, err := c.handleOnePacket(p, 0)
		require.NoError(t, err)
		require.Equal(t, 3*total, c.sentPacketHandler.AmplificationBudget())
	}
	require.Equal(t, uint64(total), c.connStats.BytesReceived.Load())
}
