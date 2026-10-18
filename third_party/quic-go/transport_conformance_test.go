package quic

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnectionPeerUDPPayloadSizeClamp(t *testing.T) {
	for _, peerLimit := range []protocol.ByteCount{1200, 1201, 1396, 1397, 1399, 1400, 1452} {
		t.Run(fmt.Sprint(peerLimit), func(t *testing.T) {
			tc := newServerTestConnection(t, nil, &Config{InitialPacketSize: 1400, EnableDatagrams: true}, false)
			require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
				InitialSourceConnectionID: tc.conn.handshakeDestConnID,
				ActiveConnectionIDLimit:   2,
				MaxUDPPayloadSize:         peerLimit,
				MaxDatagramFrameSize:      wire.MaxDatagramSize,
			}))
			require.Equal(t, min(protocol.ByteCount(1400), peerLimit), tc.conn.maxPacketSize())
			require.Equal(t, uint32(estimateMaxPayloadSize(tc.conn.maxPacketSize())), tc.conn.maxPayloadSizeEstimate.Load())
		})
	}
}

func TestConnectionDatagramCapacityFitsPacket(t *testing.T) {
	const mtu protocol.ByteCount = 1400
	for _, cidLen := range []int{0, 4, 8, 20} {
		for _, pnLen := range []protocol.PacketNumberLen{1, 2, 3, 4} {
			t.Run(fmt.Sprintf("CID%d/PN%d", cidLen, pnLen), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				tc := newServerTestConnection(t, ctrl, &Config{InitialPacketSize: uint16(mtu), EnableDatagrams: true}, false)
				tc.conn.peerParams = &wire.TransportParameters{MaxDatagramFrameSize: wire.MaxDatagramSize}
				capacity := int(tc.conn.maxPayloadSizeEstimate.Load())
				var tooLarge *DatagramTooLargeError
				require.ErrorAs(t, tc.conn.SendDatagram(make([]byte, capacity+1)), &tooLarge)
				require.Equal(t, int64(capacity), tooLarge.MaxDatagramPayloadSize)
				require.NoError(t, tc.conn.SendDatagram(make([]byte, capacity)))
				frame := tc.conn.datagramQueue.Peek()
				require.NotNil(t, frame)

				tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveServer)
				tp.packer.getDestConnID = func() protocol.ConnectionID { return protocol.ParseConnectionID(make([]byte, cidLen)) }
				require.NoError(t, tp.datagramQueue.Add(frame))
				sealer := mocks.NewMockShortHeaderSealer(ctrl)
				sealer.EXPECT().KeyPhase().Return(protocol.KeyPhaseOne).AnyTimes()
				sealer.EXPECT().Overhead().Return(16).AnyTimes()
				sealer.EXPECT().EncryptHeader(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) []byte {
					return append(src, bytes.Repeat([]byte{'s'}, 16)...)
				})
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil)
				tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), pnLen)
				tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				tp.framer.EXPECT().HasData().Return(false)
				tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Return(nil)
				buf := getPacketBuffer()
				defer buf.Release()
				p, err := tp.packer.AppendPacket(buf, mtu, monotime.Now(), protocol.Version1)
				require.NoError(t, err)
				require.Len(t, p.Frames, 1)
				require.Same(t, frame, p.Frames[0].Frame)
				require.LessOrEqual(t, buf.Len(), mtu)
				require.Nil(t, tp.datagramQueue.Peek())
			})
		}
	}
}

func TestConnectionMTUProbeRespectsCongestionBudget(t *testing.T) {
	ctrl := gomock.NewController(t)
	tc := newServerTestConnection(t, ctrl, &Config{InitialPacketSize: 1400}, false, connectionOptHandshakeConfirmed())
	now := monotime.Now()
	h := ackhandler.NewSentPacketHandler(0, 1400, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveServer, nil, utils.DefaultLogger)
	for range 31 {
		pn := h.PopPacketNumber(protocol.Encryption1RTT)
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1400, false, false)
	}
	tc.conn.sentPacketHandler = h
	tc.conn.mtuDiscoverer = newMTUDiscoverer(tc.conn.rttStats, 1400, 1452, nil)
	tc.conn.mtuDiscoverer.Start(now.Add(-time.Minute))
	require.True(t, h.HasCongestionBudget(1400))
	require.False(t, h.HasCongestionBudget(tc.conn.mtuDiscoverer.nextProbeSize()))
	tc.packer.EXPECT().AppendPacket(gomock.Any(), protocol.ByteCount(1400), now, protocol.Version1).Return(shortHeaderPacket{}, errNothingToPack)
	require.NoError(t, tc.conn.sendPackets(now))
	// A rejected larger probe must not mark an unsent probe as in flight.
	require.Equal(t, protocol.InvalidByteCount, tc.conn.mtuDiscoverer.inFlight)
	require.True(t, tc.conn.mtuDiscoverer.ShouldSendProbe(now))
}

func TestMTUDiscovererClampsInitialAndReset(t *testing.T) {
	d := newMTUDiscoverer(utils.NewRTTStats(), 1400, 1200, nil)
	require.Equal(t, protocol.ByteCount(1200), d.CurrentSize())
	now := monotime.Now()
	d.Start(now.Add(-time.Minute))
	require.False(t, d.ShouldSendProbe(now))
	d.Reset(now, 1400, 1300)
	require.Equal(t, protocol.ByteCount(1300), d.CurrentSize())
	require.False(t, d.ShouldSendProbe(now.Add(time.Minute)))
}

func TestPackInitialRequiresMinimumDatagramSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveServer)
	initial := &wire.CryptoFrame{Data: []byte("Initial")}
	tp.retransmissionQueue.addInitial(initial)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	p, err := tp.packer.PackCoalescedPacket(false, 800, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, p)
	require.True(t, tp.retransmissionQueue.HasData(protocol.EncryptionInitial))
	p, err = tp.packer.PackPTOProbePacket(protocol.EncryptionInitial, 800, true, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, p)
	require.True(t, tp.retransmissionQueue.HasData(protocol.EncryptionInitial))
}

func TestPackPartialAmplificationBudgetSendsHandshakeOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveServer)
	tp.retransmissionQueue.addInitial(&wire.CryptoFrame{Data: []byte("Initial")})
	tp.packer.handshakeStream.Write(make([]byte, 2000))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false).Return(nil)
	p, err := tp.packer.PackCoalescedPacket(false, 806, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p)
	defer p.buffer.Release()
	require.LessOrEqual(t, p.buffer.Len(), protocol.ByteCount(806))
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionHandshake, p.longHdrPackets[0].EncryptionLevel())
	require.True(t, tp.retransmissionQueue.HasData(protocol.EncryptionInitial))
	require.True(t, tp.packer.handshakeStream.HasData())
}
