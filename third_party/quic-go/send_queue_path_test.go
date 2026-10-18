package quic

import (
	"net"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSendQueueRetainsQueuedPacketPath(t *testing.T) {
	for _, gso := range []uint16{0, 100} {
		t.Run(map[bool]string{false: "ordinary", true: "GSO"}[gso != 0], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw := NewMockRawConn(gomock.NewController(t))
				raw.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
				old := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1000}
				fresh := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2000}
				oldInfo := packetInfo{addr: netip.MustParseAddr("192.0.2.10"), ifIndex: 7}
				newInfo := packetInfo{addr: netip.MustParseAddr("192.0.2.20"), ifIndex: 8}
				sc := newSendConn(raw, old, oldInfo, utils.DefaultLogger)
				q := newSendQueue(sc)
				type sent struct {
					data string
					addr net.Addr
					oob  []byte
					gso  uint16
					ecn  protocol.ECN
				}
				writes := make(chan sent, 2)
				raw.EXPECT().WritePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(data []byte, addr net.Addr, oob []byte, size uint16, ecn protocol.ECN) (int, error) {
						writes <- sent{string(data), addr, append([]byte(nil), oob...), size, ecn}
						return len(data), nil
					},
				).Times(2)
				// Delay the send worker until after migration. The first packet
				// was packed for the original CID/route and must retain that route.
				q.Send(getPacketWithContents([]byte("old-CID-packet")), gso, protocol.ECT1)
				sc.ChangeRemoteAddr(fresh, newInfo)
				q.Send(getPacketWithContents([]byte("new-CID-packet")), gso, protocol.ECNCE)
				done := make(chan error, 1)
				go func() { done <- q.Run() }()
				q.Close()
				require.NoError(t, <-done)
				first, second := <-writes, <-writes
				require.Equal(t, "old-CID-packet", first.data)
				require.Equal(t, old, first.addr)
				require.Equal(t, oldInfo.OOB(), first.oob)
				require.Equal(t, gso, first.gso)
				require.Equal(t, protocol.ECT1, first.ecn)
				require.Equal(t, "new-CID-packet", second.data)
				require.Equal(t, fresh, second.addr)
				require.Equal(t, newInfo.OOB(), second.oob)
				require.Equal(t, gso, second.gso)
				require.Equal(t, protocol.ECNCE, second.ecn)
			})
		})
	}
}
