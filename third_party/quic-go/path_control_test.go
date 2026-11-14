package quic

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type reviewPathSendConn struct {
	sendConn
	remote net.Addr
	info   packetInfo
}

func (c *reviewPathSendConn) RemoteAddr() net.Addr          { return c.remote }
func (c *reviewPathSendConn) currentPacketInfo() packetInfo { return c.info }

func TestBoundPathResponseDefersWithoutLosingRoute(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	tc := newServerTestConnection(t, ctrl, nil, false)
	tc.conn.sentPacketHandler = sph
	old := tc.remoteAddr
	info := packetInfo{addr: netip.MustParseAddr("192.0.2.10"), ifIndex: 42}
	sc := &reviewPathSendConn{sendConn: tc.conn.conn, remote: old, info: info}
	tc.conn.conn = sc
	challenge := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3}}
	tc.conn.queueBoundPathResponses([]*wire.PathChallengeFrame{challenge}, old, info)
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(protocol.MinInitialPacketSize)).Return(false)
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Len(t, tc.conn.boundPathControls, 1)
	// Promotion before the next send must not redirect the queued response.
	sc.remote = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 4321}
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(protocol.MinInitialPacketSize)).Return(true)
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), protocol.ByteCount(protocol.MinInitialPacketSize), gomock.Any()).DoAndReturn(
		func(cid protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			require.Equal(t, challenge.Data, frames[0].Frame.(*wire.PathResponseFrame).Data)
			buf := getPacketBuffer()
			buf.Data = make([]byte, 1200)
			return shortHeaderPacket{PacketNumber: 1, Length: 1200, Frames: frames, DestConnID: cid}, buf, nil
		})
	sph.EXPECT().SentPacket(gomock.Any(), protocol.PacketNumber(1), protocol.InvalidPacketNumber, gomock.Any(), gomock.Any(), protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(1200), false, true)
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), old, info)
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Empty(t, tc.conn.boundPathControls)
	credit := tc.conn.pathControlCredit(old, info)
	require.True(t, credit.inFlight)
	// Re-enqueueing after the old entry was dequeued must reuse its credit.
	tc.conn.queueBoundPathResponses([]*wire.PathChallengeFrame{challenge}, old, info)
	require.Same(t, credit, tc.conn.boundPathControls[0].credit)
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(protocol.MinInitialPacketSize)).Return(true)
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Len(t, tc.conn.boundPathControls, 1)
}

func TestPreviousPathProbeIsPerCandidateAndRetainsSource(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	info := packetInfo{addr: netip.MustParseAddr("2001:db8::10"), ifIndex: 7}
	tc.conn.conn = &reviewPathSendConn{sendConn: tc.conn.conn, remote: tc.remoteAddr, info: info}
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}
	b := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2}
	tc.conn.pathManager = &pathManager{paths: []*path{{addr: a}, {addr: b}}}
	tc.conn.probePreviousPath(a)
	tc.conn.probePreviousPath(a)
	require.Len(t, tc.conn.boundPathControls, 1)
	tc.conn.probePreviousPath(b)
	require.Len(t, tc.conn.boundPathControls, 2)
	require.Len(t, tc.conn.previousPathProbes, 2)
	require.NotEqual(t, tc.conn.previousPathProbes[0].data, tc.conn.previousPathProbes[1].data)
	for _, queued := range tc.conn.boundPathControls {
		require.True(t, addrsEqual(tc.remoteAddr, queued.addr))
		require.Equal(t, info, queued.info)
	}
	probe := tc.conn.previousPathProbes[0]
	require.False(t, probe.validated)
	require.NoError(t, tc.conn.handlePathResponseFrameServer(&wire.PathResponseFrame{Data: probe.data}))
	require.True(t, probe.validated)
	// Eviction and a later apparent migration to the same candidate must
	// start another independent validation, even if the active address stayed.
	tc.conn.pathManager.paths[0] = &path{addr: a}
	tc.conn.probePreviousPath(a)
	require.Len(t, tc.conn.boundPathControls, 3)
}

func TestFormerPathMultiResponseLossReleasesCredit(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	now := monotime.Now()
	tc.conn.sentPacketHandler.ReceivedPacket(protocol.EncryptionHandshake, now)
	tc.conn.sentPacketHandler.DropPackets(protocol.EncryptionInitial, now)
	tc.conn.sentPacketHandler.DropPackets(protocol.EncryptionHandshake, now)
	old := tc.remoteAddr
	tc.conn.queueBoundPathResponses([]*wire.PathChallengeFrame{{Data: [8]byte{1}}, {Data: [8]byte{2}}}, old, packetInfo{})
	tc.conn.conn = &reviewPathSendConn{sendConn: tc.conn.conn, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 1}}
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), protocol.ByteCount(1200), gomock.Any()).DoAndReturn(
		func(cid protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			require.Len(t, frames, 2)
			buf := getPacketBuffer()
			buf.Data = make([]byte, 1200)
			return shortHeaderPacket{PacketNumber: 0, Length: 1200, Frames: frames, DestConnID: cid}, buf, nil
		})
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), old, packetInfo{})
	require.NoError(t, tc.conn.flushBoundPathControls(now))
	credit := tc.conn.pathControlCredit(old, packetInfo{})
	require.True(t, credit.inFlight)
	// Exercise the real path-probe loss detector, which calls OnLost for
	// every frame. Every frame needs a handler; shared release is idempotent.
	require.NotPanics(t, func() {
		require.NoError(t, tc.conn.sentPacketHandler.OnLossDetectionTimeout(now.Add(2*time.Second)))
	})
	require.False(t, credit.inFlight)
}

func TestBoundPathCreditReleaseAndResourceBound(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	credit := tc.conn.pathControlCredit(tc.remoteAddr, packetInfo{})
	credit.inFlight = true
	h := &pathControlCreditHandler{credit: credit, conn: tc.conn.Conn}
	h.OnAcked(&wire.PathResponseFrame{})
	require.False(t, credit.inFlight)
	credit.inFlight = true // another packet has borrowed the same credit
	h.OnLost(&wire.PathResponseFrame{})
	require.True(t, credit.inFlight, "a duplicate callback must not release another packet's credit")
	for i := 1; i < maxPathResponses+maxPaths; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(192, 0, byte(i>>8), byte(i)), Port: 1}
		c := tc.conn.pathControlCredit(addr, packetInfo{})
		require.NotNil(t, c)
		c.inFlight = true
	}
	other := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1}
	require.Nil(t, tc.conn.pathControlCredit(other, packetInfo{}))
	require.Len(t, tc.conn.pathControlCredits, maxPathResponses+maxPaths)
	credit.inFlight = false
	require.NotNil(t, tc.conn.pathControlCredit(other, packetInfo{}), "released and unqueued credits must be reclaimable")
	require.Len(t, tc.conn.pathControlCredits, maxPathResponses+maxPaths)
}

func TestBoundPathCIDPinsReleaseOnSendAndClose(t *testing.T) {
	ctrl := gomock.NewController(t)
	tc := newServerTestConnection(t, ctrl, nil, false)
	tc.conn.connIDManager.ChangeInitialConnID(tc.destConnID)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	tc.conn.sentPacketHandler = sph
	challenges := []*wire.PathChallengeFrame{{Data: [8]byte{1}}, {Data: [8]byte{2}}}
	tc.conn.queueBoundPathResponses(challenges, tc.remoteAddr, packetInfo{})
	cid := tc.conn.boundPathControls[0].connID
	require.Equal(t, 2, tc.conn.connIDManager.pathControlRefs[cid].refs)
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(1200)).Return(true)
	tc.packer.EXPECT().PackPathProbePacket(cid, gomock.Any(), protocol.ByteCount(1200), gomock.Any()).DoAndReturn(
		func(cid protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			buf := getPacketBuffer()
			buf.Data = make([]byte, 1200)
			return shortHeaderPacket{PacketNumber: 1, Length: 1200, Frames: frames, DestConnID: cid}, buf, nil
		})
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(1200), false, false)
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.remoteAddr, packetInfo{})
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Empty(t, tc.conn.connIDManager.pathControlRefs)
	tc.conn.queueBoundPathResponses(challenges, tc.remoteAddr, packetInfo{})
	require.Len(t, tc.conn.connIDManager.pathControlRefs, 1)
	tc.conn.connIDManager.Close()
	require.Empty(t, tc.conn.connIDManager.pathControlRefs)
}

func TestBoundFormerPathWaitsForFreshCIDAfterPeerRetirement(t *testing.T) {
	ctrl := gomock.NewController(t)
	tc := newServerTestConnection(t, ctrl, nil, false)
	tc.conn.connIDManager.ChangeInitialConnID(tc.destConnID)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	tc.conn.sentPacketHandler = sph
	tc.conn.queueBoundPathResponses([]*wire.PathChallengeFrame{{Data: [8]byte{1}}, {Data: [8]byte{2}}}, tc.remoteAddr, packetInfo{})
	oldCID := tc.conn.boundPathControls[0].connID
	h := tc.conn.connIDManager
	h.peerRetirePriorTo = 1
	h.invalidatePathControlCIDs()
	require.False(t, h.PathControlCIDValid(oldCID))
	tc.conn.conn = &reviewPathSendConn{sendConn: tc.conn.conn, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 1}}
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(1200)).Return(true)
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Len(t, tc.conn.boundPathControls, 2, "no CID may be reused across routes or after peer retirement")
	newCID := protocol.ParseConnectionID([]byte{5, 6, 7, 8})
	token := protocol.StatelessResetToken{3, 4}
	h.queue = append(h.queue, newConnID{SequenceNumber: 2, ConnectionID: newCID, StatelessResetToken: token})
	tc.connRunner.EXPECT().AddResetToken(token, &tc.conn.pathReceiver)
	tc.connRunner.EXPECT().RemoveResetToken(token)
	sph.EXPECT().HasCongestionBudget(protocol.ByteCount(1200)).Return(true)
	tc.packer.EXPECT().PackPathProbePacket(newCID, gomock.Any(), protocol.ByteCount(1200), gomock.Any()).DoAndReturn(
		func(cid protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			require.Len(t, frames, 2, "one fresh CID covers the whole old-route batch")
			buf := getPacketBuffer()
			buf.Data = make([]byte, 1200)
			return shortHeaderPacket{PacketNumber: 1, Length: 1200, Frames: frames, DestConnID: cid}, buf, nil
		})
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(1200), false, true)
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.remoteAddr, packetInfo{})
	require.NoError(t, tc.conn.flushBoundPathControls(monotime.Now()))
	require.Empty(t, tc.conn.boundPathControls)
	require.Empty(t, h.pathControlRefs)
}
