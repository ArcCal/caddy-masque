package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestBoundCurrentPathWaitsForReplacementCID(t *testing.T) {
	ctrl := gomock.NewController(t)
	tc := newServerTestConnection(t, ctrl, nil, false)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	tc.conn.sentPacketHandler = sph
	h := newConnIDManager(protocol.ParseConnectionID([]byte{0, 0, 0, 0}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
	tc.conn.connIDManager = h
	require.NoError(t, h.Add(pathCIDFrame(1, 0)))
	_, ok := h.GetConnIDForPath(10)
	require.True(t, ok)
	require.NoError(t, h.Add(pathCIDFrame(2, 0)))
	h.SetHandshakeComplete()
	require.Equal(t, pathCIDFrame(2, 0).ConnectionID, h.Get())
	require.True(t, h.PromotePathConnectionID(10))
	require.NoError(t, h.Add(pathCIDFrame(2, 2))) // reordered, already-retired CID with a newer peer floor
	require.False(t, h.HasActiveConnectionID())
	tc.conn.queueBoundPathResponses([]*wire.PathChallengeFrame{{Data: [8]byte{1}}}, tc.remoteAddr, packetInfo{})
	require.Len(t, tc.conn.boundPathControls, 1)
	require.NotZero(t, tc.conn.boundPathControls[0].connID.Len(), "CID exhaustion is distinct from negotiated zero-length CIDs")
	require.False(t, h.PathControlCIDValid(tc.conn.boundPathControls[0].connID))
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(1200)).Return(true)
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Len(t, tc.conn.boundPathControls, 1)

	require.NoError(t, h.Add(pathCIDFrame(3, 0)))
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(1200)).Return(true)
	tc.packer.EXPECT().PackPathProbePacket(pathCIDFrame(3, 0).ConnectionID, gomock.Any(), protocol.ByteCount(1200), gomock.Any()).DoAndReturn(
		func(cid protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			buf := getPacketBuffer()
			buf.Data = buf.Data[:1200]
			return shortHeaderPacket{PacketNumber: 1, Length: 1200, Frames: frames, DestConnID: cid}, buf, nil
		})
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(1200), false, false)
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.remoteAddr, packetInfo{})
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Empty(t, tc.conn.boundPathControls)
	require.Empty(t, h.pathControlRefs)
}

func TestBoundCurrentPathNegotiatedZeroLengthCID(t *testing.T) {
	ctrl := gomock.NewController(t)
	tc := newServerTestConnection(t, ctrl, nil, false)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	tc.conn.sentPacketHandler = sph
	tc.conn.connIDManager = newConnIDManager(protocol.ConnectionID{}, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
	tc.conn.queueBoundPathResponses([]*wire.PathChallengeFrame{{Data: [8]byte{1}}}, tc.remoteAddr, packetInfo{})
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(1200)).Return(true)
	tc.packer.EXPECT().PackPathProbePacket(protocol.ConnectionID{}, gomock.Any(), protocol.ByteCount(1200), gomock.Any()).DoAndReturn(
		func(cid protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			buf := getPacketBuffer()
			buf.Data = buf.Data[:1200]
			return shortHeaderPacket{PacketNumber: 1, Length: 1200, Frames: frames, DestConnID: cid}, buf, nil
		})
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(1200), false, false)
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.remoteAddr, packetInfo{})
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Empty(t, tc.conn.boundPathControls)
}
