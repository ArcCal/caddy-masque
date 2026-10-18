package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func pathCIDFrame(seq byte, retire uint64) *wire.NewConnectionIDFrame {
	return &wire.NewConnectionIDFrame{SequenceNumber: uint64(seq), RetirePriorTo: retire, ConnectionID: protocol.ParseConnectionID([]byte{seq, seq, seq, seq}), StatelessResetToken: protocol.StatelessResetToken{seq}}
}

func TestConnIDManagerPromotesOlderReservedPath(t *testing.T) {
	var added, removed []protocol.StatelessResetToken
	var retired []uint64
	m := newConnIDManager(protocol.ParseConnectionID([]byte{0, 0, 0, 0}), func(token protocol.StatelessResetToken) { added = append(added, token) }, func(token protocol.StatelessResetToken) { removed = append(removed, token) }, func(f wire.Frame) { retired = append(retired, f.(*wire.RetireConnectionIDFrame).SequenceNumber) })
	require.NoError(t, m.Add(pathCIDFrame(1, 0)))
	reserved, ok := m.GetConnIDForPath(10)
	require.True(t, ok)
	require.NoError(t, m.Add(pathCIDFrame(2, 0)))
	m.SetHandshakeComplete()
	require.Equal(t, pathCIDFrame(2, 0).ConnectionID, m.Get())
	require.True(t, m.PromotePathConnectionID(10))
	require.Equal(t, reserved, m.Get())
	require.Empty(t, m.pathProbing)
	require.Equal(t, []uint64{0, 2}, retired)
	require.Equal(t, []protocol.StatelessResetToken{{1}, {2}}, added)
	require.Equal(t, []protocol.StatelessResetToken{{2}}, removed)
	// Local sequence history does not retire a known live older CID.
	require.NoError(t, m.Add(pathCIDFrame(1, 0)))
	require.Equal(t, []uint64{0, 2}, retired)
	require.Equal(t, reserved, m.Get())

	// A reordered, already-retired frame can still carry a higher peer floor.
	require.NoError(t, m.Add(pathCIDFrame(2, 2)))
	require.False(t, m.HasActiveConnectionID())
	require.False(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{1}))
	require.NoError(t, m.Add(pathCIDFrame(3, 0)))
	require.True(t, m.HasActiveConnectionID())
	require.Equal(t, pathCIDFrame(3, 0).ConnectionID, m.Get())
	m.Close()
	require.ElementsMatch(t, []protocol.StatelessResetToken{{1}, {2}, {3}}, removed)
}

func TestConnIDManagerReservedDuplicatesRemainDistinct(t *testing.T) {
	var retired []uint64
	m := newConnIDManager(protocol.ParseConnectionID([]byte{0, 0, 0, 0}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(f wire.Frame) { retired = append(retired, f.(*wire.RetireConnectionIDFrame).SequenceNumber) })
	require.NoError(t, m.Add(pathCIDFrame(1, 0)))
	m.SetHandshakeComplete()
	require.Equal(t, pathCIDFrame(1, 0).ConnectionID, m.Get())
	require.NoError(t, m.Add(pathCIDFrame(2, 0)))
	_, ok := m.GetConnIDForPath(10)
	require.True(t, ok)
	retired = nil
	require.NoError(t, m.Add(pathCIDFrame(1, 0)))
	require.NoError(t, m.Add(pathCIDFrame(2, 0)))
	require.Empty(t, retired)
	_, ok = m.GetConnIDForPath(11)
	require.False(t, ok, "an identical NEW_CONNECTION_ID must not make an assigned CID available on a second path")
	require.Error(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: protocol.ParseConnectionID([]byte{9}), StatelessResetToken: protocol.StatelessResetToken{2}}))
}

func TestConnIDManagerPathControlPinsLocalRetirement(t *testing.T) {
	var retired []uint64
	var removed []protocol.StatelessResetToken
	m := newConnIDManager(protocol.ParseConnectionID([]byte{0, 0, 0, 0}), func(protocol.StatelessResetToken) {}, func(token protocol.StatelessResetToken) { removed = append(removed, token) }, func(f wire.Frame) { retired = append(retired, f.(*wire.RetireConnectionIDFrame).SequenceNumber) })
	m.SetStatelessResetToken(protocol.StatelessResetToken{9})
	old := m.PinPathControlCID()
	require.Equal(t, old, m.PinPathControlCID())
	require.NoError(t, m.Add(pathCIDFrame(1, 0)))
	_, ok := m.GetConnIDForPath(10)
	require.True(t, ok)
	require.True(t, m.PromotePathConnectionID(10))
	require.Empty(t, retired)
	require.Empty(t, removed)
	require.True(t, m.PathControlCIDValid(old))
	require.True(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{9}))
	m.ReleasePathControlCID(old)
	require.Empty(t, retired)
	m.ReleasePathControlCID(old)
	require.Equal(t, []uint64{0}, retired)
	require.Equal(t, []protocol.StatelessResetToken{{9}}, removed)
	require.Empty(t, m.pathControlRefs)

	// Ordinary automatic CID rotation follows the same pin rule.
	newPin := m.PinPathControlCID()
	require.NoError(t, m.Add(pathCIDFrame(2, 0)))
	m.updateConnectionID()
	require.True(t, m.PathControlCIDValid(newPin))
	require.Equal(t, []uint64{0}, retired)
	m.ReleasePathControlCID(newPin)
	require.Equal(t, []uint64{0, 1}, retired)
	m.Close()
	require.ElementsMatch(t, []protocol.StatelessResetToken{{9}, {1}, {2}}, removed)
}

func TestConnIDManagerPathControlForcedRetirementAndRefresh(t *testing.T) {
	var removed []protocol.StatelessResetToken
	m := newConnIDManager(protocol.ParseConnectionID([]byte{0, 0, 0, 0}), func(protocol.StatelessResetToken) {}, func(token protocol.StatelessResetToken) { removed = append(removed, token) }, func(wire.Frame) {})
	m.SetStatelessResetToken(protocol.StatelessResetToken{9})
	old := m.PinPathControlCID()
	require.Equal(t, old, m.PinPathControlCID())
	require.NoError(t, m.Add(pathCIDFrame(1, 1)))
	require.False(t, m.PathControlCIDValid(old))
	require.False(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{9}))
	_, ok := m.RefreshPathControlCID(old)
	require.False(t, ok, "do not reuse the current route's CID on a former route")
	require.NoError(t, m.Add(pathCIDFrame(2, 0)))
	fresh, ok := m.RefreshPathControlCID(old)
	require.True(t, ok)
	require.Equal(t, pathCIDFrame(2, 0).ConnectionID, fresh)
	freshAgain, ok := m.RefreshPathControlCID(old)
	require.True(t, ok)
	require.Equal(t, fresh, freshAgain)
	m.ReleasePathControlCID(old)
	m.ReleasePathControlCID(old)
	require.True(t, m.PathControlCIDValid(fresh))
	m.ReleasePathControlCID(fresh)
	require.True(t, m.PathControlCIDValid(fresh))
	m.ReleasePathControlCID(fresh)
	require.Empty(t, m.pathControlRefs)
	require.ElementsMatch(t, []protocol.StatelessResetToken{{9}, {2}}, removed)
	m.Close()
	require.ElementsMatch(t, []protocol.StatelessResetToken{{9}, {1}, {2}}, removed)
}

func TestConnIDManagerPathPromotionLimitsAndUnavailableSend(t *testing.T) {
	m := newConnIDManager(protocol.ConnectionID{}, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
	require.True(t, m.PromotePathConnectionID(999))
	require.Zero(t, m.PinPathControlCID())
	m.ReleasePathControlCID(protocol.ConnectionID{})
	require.Empty(t, m.pathControlRefs)
	m = newConnIDManager(protocol.ParseConnectionID([]byte{0}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
	require.False(t, m.PromotePathConnectionID(999))
	old := m.PinPathControlCID()
	for i := byte(1); i < protocol.MaxActiveConnectionIDs; i++ {
		require.NoError(t, m.Add(pathCIDFrame(i, 0)))
		_, ok := m.GetConnIDForPath(pathID(i))
		require.True(t, ok)
	}
	require.ErrorIs(t, m.Add(pathCIDFrame(protocol.MaxActiveConnectionIDs, 0)), &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
	m.ReleasePathControlCID(old)
	m.Close()

	c := newServerTestConnection(t, nil, nil, false)
	c.conn.connIDManager.activeRetired = true
	require.NoError(t, c.conn.triggerSending(monotime.Now()))
	require.Equal(t, blockModeHardBlocked, c.conn.blocked)
	packet, err := c.conn.sendConnectionClose(&qerr.TransportError{ErrorCode: qerr.InternalError})
	require.NoError(t, err)
	require.Empty(t, packet)
}
