package quic

import (
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// The path is established by receiving a non-probing packet.
// The first non-probing packet is received after path validation has completed.
// This is the typical scenario when the client initiates connection migration.
func TestPathManagerIntentionalMigration(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
		protocol.ParseConnectionID([]byte{3, 4, 5, 6, 7, 8, 9, 0}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	// the connection creates the path before handling the packet's frames
	id, isNew, ok := pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now)
	require.True(t, ok)
	require.True(t, isNew)
	require.Equal(t, pathID(0), id)
	connID, frames, shouldSwitch := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		[]*wire.PathChallengeFrame{{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 2)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.NotEqual(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, pc1.Data)
	require.IsType(t, &wire.PathResponseFrame{}, frames[1].Frame)
	require.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, frames[1].Frame.(*wire.PathResponseFrame).Data)
	require.False(t, shouldSwitch)

	// receiving another packet for the same path doesn't trigger another PATH_CHALLENGE
	id, isNew, ok = pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now)
	require.True(t, ok)
	require.False(t, isNew)
	require.Equal(t, pathID(0), id)
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// receiving a packet for a different path triggers another PATH_CHALLENGE
	addr2 := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000}
	id, isNew, ok = pm.GetOrCreatePath(addr2, now)
	require.True(t, ok)
	require.True(t, isNew)
	require.Equal(t, pathID(1), id)
	connID, frames, shouldSwitch = pm.HandlePacket(addr2, now, nil, false, protocol.MinInitialPacketSize, packetInfo{})
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc2 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)
	require.False(t, shouldSwitch)

	// acknowledging the PATH_CHALLENGE doesn't confirm the path
	for _, f := range frames {
		f.Handler.OnAcked(f.Frame)
	}
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.SentProbe(addr2, protocol.MinInitialPacketSize, []ackhandler.Frame{{Frame: pc2}})
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	connID, frames, shouldSwitch = pm.HandlePacket(addr2, now, nil, false, protocol.MinInitialPacketSize, packetInfo{})
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch) // no non-probing packet received yet
	require.Empty(t, retiredConnIDs)

	// confirming the path doesn't remove other paths
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// now receive a non-probing packet for the new path
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000},
		now,
		nil,
		true,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)

	// now switch to the new path
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000})

	// switching to the path removes other paths
	pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now)
	connID, frames, shouldSwitch = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false, protocol.MinInitialPacketSize, packetInfo{})
	require.Equal(t, connIDs[2], connID)
	require.NotEmpty(t, frames)
	require.NotEqual(t, frames[0].Frame.(*wire.PathChallengeFrame).Data, pc1.Data)
	require.False(t, shouldSwitch)
	require.Equal(t, []protocol.ConnectionID{connIDs[0]}, retiredConnIDs)
}

func TestPathManagerMultipleProbes(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) {},
		utils.DefaultLogger,
	)
	now := monotime.Now()
	// first receive a packet without a PATH_CHALLENGE
	pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now)
	connID, frames, shouldSwitch := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// now receive a packet on the same path with a PATH_CHALLENGE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		[]*wire.PathChallengeFrame{{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// now receive another packet on the same path with a PATH_RESPONSE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		[]*wire.PathChallengeFrame{{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}},
		false,
		protocol.MinInitialPacketSize,
		packetInfo{},
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// lose the response packet
	frames[0].Handler.OnLost(frames[0].Frame)
}

// The first packet received on the new path is already a non-probing packet.
// We still need to validate the new path, but we can then switch over immediately.
// This is the typical scenario when a NAT rebinding happens.
func TestPathManagerNATRebinding(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		utils.DefaultLogger,
	)

	now := monotime.Now()
	pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now)
	connID, frames, shouldSwitch := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.SentProbe(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, protocol.MinInitialPacketSize, []ackhandler.Frame{{Frame: pc1}})
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	// we now switch to the new path, as soon as the next packet on that path is received
	connID, frames, shouldSwitch = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false, protocol.MinInitialPacketSize, packetInfo{})
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
}

func TestPathManagerBudgetAndMTURevalidation(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	pm := newPathManager(func(pathID) (protocol.ConnectionID, bool) { return connID, true }, func(pathID) {}, utils.DefaultLogger)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	info := packetInfo{addr: netip.MustParseAddr("192.0.2.2"), ifIndex: 7}
	_, frames, switchPath := pm.HandlePacket(addr, monotime.Now(), nil, true, 26, info)
	require.False(t, switchPath)
	require.Equal(t, protocol.ByteCount(78), pm.ProbeSize(addr))
	firstChallenge := frames[0].Frame.(*wire.PathChallengeFrame)
	pm.SentProbe(addr, 78, frames)
	require.Zero(t, pm.ProbeSize(addr))

	// A matching response is valid on any path, including the old active path.
	// No further HandlePacket call on addr is needed to dispatch the MTU probe.
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: firstChallenge.Data})
	probeConnID, mtuFrames, target := pm.NextMTUProbe()
	require.Equal(t, connID, probeConnID)
	require.Equal(t, addr, target.addr)
	require.Equal(t, info, target.info)
	require.False(t, target.mtuValidated)
	require.Equal(t, protocol.ByteCount(1200), pm.ProbeSize(addr))
	secondChallenge := mtuFrames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, firstChallenge.Data, secondChallenge.Data)
	_, _, pending := pm.NextMTUProbe()
	require.Nil(t, pending)
	pm.SentProbe(addr, 1200, mtuFrames)

	// An old duplicate response cannot complete the new full-size validation.
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: firstChallenge.Data})
	_, _, duplicateProbe := pm.NextMTUProbe()
	require.Nil(t, duplicateProbe, "an old response must not enqueue another full-size probe")
	_, _, switchPath = pm.HandlePacket(addr, monotime.Now(), nil, false, 26, info)
	require.False(t, switchPath)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: secondChallenge.Data})
	_, _, switchPath = pm.HandlePacket(addr, monotime.Now(), nil, false, 1200, info)
	require.True(t, switchPath)
}

func TestPathManagerPerAddressBudgetAndMultipleChallenges(t *testing.T) {
	pm := newPathManager(func(pathID) (protocol.ConnectionID, bool) { return protocol.ConnectionID{}, true }, func(pathID) {}, utils.DefaultLogger)
	addr1 := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	addr2 := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5678}
	_, frames, _ := pm.HandlePacket(addr1, monotime.Now(), nil, false, 26, packetInfo{})
	pm.SentProbe(addr1, 78, frames)
	_, _, _ = pm.HandlePacket(addr2, monotime.Now(), nil, false, 1200, packetInfo{})
	require.Zero(t, pm.ProbeSize(addr1))
	require.Equal(t, protocol.ByteCount(1200), pm.ProbeSize(addr2))
	challenges := []*wire.PathChallengeFrame{{Data: [8]byte{1}}, {Data: [8]byte{2}}}
	_, frames, _ = pm.HandlePacket(addr1, monotime.Now(), challenges, false, 39, packetInfo{})
	require.Len(t, frames, 2)
	require.Equal(t, &wire.PathResponseFrame{Data: challenges[0].Data}, frames[0].Frame)
	require.Equal(t, &wire.PathResponseFrame{Data: challenges[1].Data}, frames[1].Frame)
	require.Equal(t, protocol.ByteCount(117), pm.ProbeSize(addr1))
}

func TestPathManagerRetransmissions(t *testing.T) {
	for _, response := range []struct {
		name          string
		respondToLast bool
	}{
		{name: "response to first challenge"},
		{name: "response to last challenge", respondToLast: true},
	} {
		t.Run(response.name, func(t *testing.T) {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
			pm := newPathManager(
				func(id pathID) (protocol.ConnectionID, bool) {
					require.Zero(t, id)
					return connID, true
				},
				func(pathID) { t.Fatal("didn't expect a connection ID to be retired") },
				utils.DefaultLogger,
			)
			addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
			now := monotime.Now()
			rtt := utils.DefaultInitialRTT
			var challenges [][8]byte
			pm.GetOrCreatePath(addr, now)
			for _, packet := range []struct {
				at            time.Duration
				wantChallenge bool
			}{
				{0, true}, // initial challenge
				{rtt / 2, false},
				{rtt, true}, // first retry after one RTT
				{2 * rtt, false},
				{3 * rtt, true}, // second retry after two more RTTs
				{5 * rtt, false},
				{15 * rtt, true}, // third retry was due at 7 RTTs, but this packet arrives late
				{19 * rtt, false},
				{23 * rtt, true}, // fourth retry after eight RTTs from the late packet
			} {
				id, frames, shouldSwitch := pm.HandlePacket(addr, now.Add(packet.at), nil, true, protocol.MinInitialPacketSize, packetInfo{})
				require.False(t, shouldSwitch, "packet at %s", packet.at)
				if !packet.wantChallenge {
					require.Zero(t, id)
					require.Empty(t, frames, "packet at %s", packet.at)
					continue
				}
				require.Equal(t, connID, id)
				require.Len(t, frames, 1, "packet at %s", packet.at)
				pm.SentProbe(addr, protocol.MinInitialPacketSize, frames)
				challenge := frames[0].Frame.(*wire.PathChallengeFrame).Data
				require.NotContains(t, challenges, challenge)
				challenges = append(challenges, challenge)
				if packet.at == 0 {
					// An ACK doesn't replace the missing PATH_RESPONSE.
					frames[0].Handler.OnAcked(frames[0].Frame)
				} else {
					// Loss doesn't remove the path or reset its backoff.
					frames[0].Handler.OnLost(frames[0].Frame)
				}
			}
			challenge := challenges[0]
			if response.respondToLast {
				challenge = challenges[len(challenges)-1]
			}
			pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenge})
			// Once validated, even a packet at the next retry deadline needs no new challenge.
			now = now.Add((23 + 16) * rtt)
			id, frames, shouldSwitch := pm.HandlePacket(addr, now, nil, false, protocol.MinInitialPacketSize, packetInfo{})
			require.Zero(t, id)
			require.Empty(t, frames)
			require.True(t, shouldSwitch)

			// A validated path still answers the peer's challenges without probing again.
			pc := &wire.PathChallengeFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}
			id, frames, shouldSwitch = pm.HandlePacket(addr, now, []*wire.PathChallengeFrame{pc}, false, protocol.MinInitialPacketSize, packetInfo{})
			require.Equal(t, connID, id)
			require.Len(t, frames, 1)
			require.Equal(t, &wire.PathResponseFrame{Data: pc.Data}, frames[0].Frame)
			require.True(t, shouldSwitch)
		})
	}
}

func TestPathManagerLimits(t *testing.T) {
	var connIDs []protocol.ConnectionID
	for range 2*maxPaths + 2 {
		b := make([]byte, 8)
		rand.Read(b)
		connIDs = append(connIDs, protocol.ParseConnectionID(b))
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		utils.DefaultLogger,
	)

	now := monotime.Now()
	firstPathTime := now
	var firstPathConnID protocol.ConnectionID
	require.Greater(t, pathTimeout, maxPaths*time.Second)
	for i := range maxPaths {
		pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now)
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[i], connID)
		if i == 0 {
			firstPathConnID = connID
		}
		now = now.Add(time.Second)
	}
	// the maximum number of paths is already being probed
	now = firstPathTime.Add(pathTimeout - time.Nanosecond)
	_, _, ok := pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now)
	require.False(t, ok)
	connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
	require.Zero(t, connID)
	require.Empty(t, frames)

	// challenge the newest path so the oldest path can be evicted below
	pc := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	// 1. Before the oldest path expires, respond even though all path slots are occupied.
	// 2. After it expires, respond without evicting it, since this is an existing path.
	for _, rcvTime := range []monotime.Time{now, firstPathTime.Add(pathTimeout + time.Second)} {
		connID, frames, shouldSwitch := pm.HandlePacket(
			&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + maxPaths - 1}, rcvTime, []*wire.PathChallengeFrame{pc}, false, protocol.MinInitialPacketSize, packetInfo{},
		)
		require.Equal(t, connIDs[maxPaths-1], connID)
		require.Len(t, frames, 2)
		require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
		require.Equal(t, &wire.PathResponseFrame{Data: pc.Data}, frames[1].Frame)
		require.False(t, shouldSwitch)
		require.Empty(t, retiredConnIDs)
	}

	// receiving another packet after the pathTimeout of the first path evicts the first path
	now = firstPathTime.Add(pathTimeout + time.Second)
	connIDIndex := maxPaths
	pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + maxPaths}, now)
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + maxPaths}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
	require.NotEmpty(t, frames)
	require.Equal(t, connIDs[connIDIndex], connID)
	require.Equal(t, []protocol.ConnectionID{firstPathConnID}, retiredConnIDs)
	connIDIndex++

	// switching to a new path frees is up all paths
	var f1 []ackhandler.Frame
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000})
	for i := range maxPaths {
		pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 3000 + i}, now)
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 3000 + i}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
		if i == 0 {
			f1 = frames
		}
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[connIDIndex], connID)
		connIDIndex++
	}
	// again, the maximum number of paths is already being probed
	pm.GetOrCreatePath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now)
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
	require.Zero(t, connID)
	require.Empty(t, frames)

	// losing the frame doesn't free up a path
	f1[0].Handler.OnLost(f1[0].Frame)

	// Loss leaves every slot reserved until the inactivity timeout.
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4000}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
	require.Empty(t, frames)
	require.Zero(t, connID)
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4001}, now, nil, true, protocol.MinInitialPacketSize, packetInfo{})
	require.Zero(t, connID)
	require.Empty(t, frames)
}

type mockAddr struct {
	str string
}

func (a *mockAddr) Network() string { return "mock" }
func (a *mockAddr) String() string  { return a.str }

func TestAddrsEqual(t *testing.T) {
	tests := []struct {
		name     string
		addr1    net.Addr
		addr2    net.Addr
		expected bool
	}{
		{
			name:     "nil addresses",
			addr1:    nil,
			addr2:    nil,
			expected: false,
		},
		{
			name:     "one nil address",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    nil,
			expected: false,
		},
		{
			name:     "same IPv4 addresses",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			expected: true,
		},
		{
			name:     "different IPv4 addresses",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1), Port: 1234},
			expected: false,
		},
		{
			name:     "different ports",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321},
			expected: false,
		},
		{
			name:     "same IPv6 addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			expected: true,
		},
		{
			name:     "different IPv6 addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1234},
			expected: false,
		},
		{
			name:     "non-UDP addresses with same string representation",
			addr1:    &mockAddr{str: "192.0.2.1:1234"},
			addr2:    &mockAddr{str: "192.0.2.1:1234"},
			expected: true,
		},
		{
			name:     "non-UDP addresses with different string representation",
			addr1:    &mockAddr{str: "192.0.2.1:1234"},
			addr2:    &mockAddr{str: "192.0.2.2:1234"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addrsEqual(tt.addr1, tt.addr2)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPathManagerRetriesLostMTUProbe(t *testing.T) {
	pm := newPathManager(func(pathID) (protocol.ConnectionID, bool) { return protocol.ZeroLengthConnectionID, true }, func(pathID) {}, utils.DefaultLogger)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	now := monotime.Now()
	_, initial, _ := pm.HandlePacket(addr, now, nil, true, 26, packetInfo{})
	pm.SentProbe(addr, 78, initial)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: initial[0].Frame.(*wire.PathChallengeFrame).Data})
	_, first, p := pm.NextMTUProbe()
	require.NotNil(t, p)
	pm.SentProbe(addr, 1200, first)
	first[0].Handler.OnLost(first[0].Frame)
	_, retry, switchPath := pm.HandlePacket(addr, p.nextProbeTime, nil, true, 26, packetInfo{})
	require.False(t, switchPath)
	require.Len(t, retry, 1)
	require.NotEqual(t, first[0].Frame, retry[0].Frame)
	pm.SentProbe(addr, 1200, retry)
	// A delayed response to the earlier full-size challenge remains valid.
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: first[0].Frame.(*wire.PathChallengeFrame).Data})
	_, _, switchPath = pm.HandlePacket(addr, p.nextProbeTime, nil, true, 26, packetInfo{})
	require.True(t, switchPath)
}
