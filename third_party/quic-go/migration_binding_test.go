package quic

import (
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestMigrationBindsLatestNonProbingPathAndConnectionID(t *testing.T) {
	for _, tc := range []struct {
		name           string
		newIncomingCID bool
		newerOldPacket bool
	}{
		{"NAT same incoming CID", false, false},
		{"intentional new incoming CID", true, false},
		{"newer non-probing packet on original path", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			unpacker := NewMockUnpacker(ctrl)
			c := newServerTestConnection(t, ctrl, nil, false, connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed())
			require.NoError(t, c.conn.handleTransportParameters(&wire.TransportParameters{MaxUDPPayloadSize: 1452, InitialSourceConnectionID: protocol.ZeroLengthConnectionID}))
			oldCID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
			newCID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
			c.conn.connIDManager = newConnIDManager(oldCID, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
			require.NoError(t, c.conn.connIDManager.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: newCID, StatelessResetToken: protocol.StatelessResetToken{2}}))
			c.conn.connIDManager.SetHandshakeComplete()
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
			var challenge [8]byte
			var probeNumber protocol.PacketNumber
			c.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(cid protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
					for _, frame := range frames {
						if pc, ok := frame.Frame.(*wire.PathChallengeFrame); ok && cid == newCID {
							challenge = pc.Data
						}
					}
					probeNumber++
					b := getPacketBuffer()
					b.Data = b.Data[:maxSize]
					return shortHeaderPacket{PacketNumber: probeNumber, Frames: frames, Length: maxSize, IsPathProbePacket: true}, b, nil
				},
			).AnyTimes()
			c.sendConn.EXPECT().WriteTo(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			if !tc.newerOldPacket {
				c.sendConn.EXPECT().ChangeRemoteAddr(addr, gomock.Any())
			}
			receive := func(pn protocol.PacketNumber, remote net.Addr, incomingCID protocol.ConnectionID, payload []byte) {
				t.Helper()
				unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil)
				data := make([]byte, 1200)
				data[0] = 0x40
				copy(data[1:], incomingCID.Bytes())
				b := getPacketBuffer()
				processed, err := c.conn.handleShortHeaderPacket(receivedPacket{data: data, buffer: b, remoteAddr: remote, rcvTime: monotime.Now()}, false, 0, activePathID)
				b.MaybeRelease()
				require.NoError(t, err)
				require.True(t, processed)
			}
			incomingCID := c.srcConnID
			if tc.newIncomingCID {
				incomingCID = protocol.ParseConnectionID([]byte{9, 8, 7, 6, 5, 4})
			}
			receive(10, addr, incomingCID, []byte{1}) // non-probing PING
			require.NotEqual(t, [8]byte{}, challenge)
			if tc.newerOldPacket {
				receive(11, c.remoteAddr, c.srcConnID, []byte{1})
			}
			response, err := (&wire.PathResponseFrame{Data: challenge}).Append(nil, protocol.Version1)
			require.NoError(t, err)
			receive(12, addr, incomingCID, response)
			if tc.newerOldPacket {
				require.Equal(t, oldCID, c.conn.connIDManager.Get())
			} else {
				require.Equal(t, newCID, c.conn.connIDManager.Get(), "the validated path's reserved CID must become the application packet CID")
				require.Empty(t, c.conn.connIDManager.pathProbing, "a promoted CID is no longer a probing reservation")
			}
		})
	}
}
