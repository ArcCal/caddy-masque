package quic

import (
	"fmt"
	"slices"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type newConnID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

type connIDManager struct {
	queue []newConnID

	highestUsedSequenceNumber uint64
	pathMx                    sync.Mutex
	pathProbing               map[pathID]newConnID // initialized lazily
	pathControlRefs           map[protocol.ConnectionID]*pathControlCIDReference
	peerRetirePriorTo         uint64
	activeRetired             bool

	handshakeComplete         bool
	activeSequenceNumber      uint64
	highestRetired            uint64 // the highest Retire Prior To value received
	activeConnectionID        protocol.ConnectionID
	activeStatelessResetToken *protocol.StatelessResetToken

	// We change the connection ID after sending on average
	// protocol.PacketsPerConnectionID packets. The actual value is randomized
	// hide the packet loss rate from on-path observers.
	rand                   utils.Rand
	packetsSinceLastChange uint32
	packetsPerConnectionID uint32

	addStatelessResetToken    func(protocol.StatelessResetToken)
	removeStatelessResetToken func(protocol.StatelessResetToken)
	queueControlFrame         func(wire.Frame)

	closed bool
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID,
	addStatelessResetToken func(protocol.StatelessResetToken),
	removeStatelessResetToken func(protocol.StatelessResetToken),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		activeConnectionID:        initialDestConnID,
		addStatelessResetToken:    addStatelessResetToken,
		removeStatelessResetToken: removeStatelessResetToken,
		queueControlFrame:         queueControlFrame,
		queue:                     make([]newConnID, 0, protocol.MaxActiveConnectionIDs),
	}
}

func (h *connIDManager) AddFromPreferredAddress(connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	return h.addConnectionID(1, connID, resetToken)
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if err := h.add(f); err != nil {
		return err
	}
	if h.activeConnectionIDCount() > protocol.MaxActiveConnectionIDs {
		return &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}
	}
	return nil
}

func (h *connIDManager) add(f *wire.NewConnectionIDFrame) error {
	if h.activeConnectionID.Len() == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_CONNECTION_ID frame but zero-length connection IDs are in use",
		}
	}
	h.peerRetirePriorTo = max(h.peerRetirePriorTo, f.RetirePriorTo)
	h.invalidatePathControlCIDs()

	if f.RetirePriorTo != 0 && h.pathProbing != nil {
		for id, entry := range h.pathProbing {
			if entry.SequenceNumber < f.RetirePriorTo {
				h.retireConnectionID(entry, true)
				delete(h.pathProbing, id)
			}
		}
	}
	// Retire elements in the queue.
	// Doesn't retire the active connection ID.
	if f.RetirePriorTo > 0 {
		var newQueue []newConnID
		for _, entry := range h.queue {
			if entry.SequenceNumber >= f.RetirePriorTo {
				newQueue = append(newQueue, entry)
			} else {
				h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
			}
		}
		h.queue = newQueue
		h.highestRetired = max(h.highestRetired, f.RetirePriorTo)
	}

	known := !h.activeRetired && f.SequenceNumber == h.activeSequenceNumber
	for _, entry := range h.pathProbing {
		if entry.SequenceNumber == f.SequenceNumber {
			if err := checkKnownConnectionID(entry, f); err != nil {
				return err
			}
			known = true
		}
	}
	for _, reference := range h.pathControlRefs {
		if reference.valid && reference.entry.SequenceNumber == f.SequenceNumber {
			if err := checkKnownConnectionID(reference.entry, f); err != nil {
				return err
			}
			known = true
		}
	}
	if !known {
		if f.SequenceNumber <= h.highestUsedSequenceNumber || f.SequenceNumber < h.highestRetired {
			h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: f.SequenceNumber})
		} else if err := h.addConnectionID(f.SequenceNumber, f.ConnectionID, f.StatelessResetToken); err != nil {
			return err
		}
	}

	if !h.activeRetired && h.activeSequenceNumber < h.peerRetirePriorTo {
		h.retireActiveConnectionID()
		h.activeRetired = true
	}
	if h.activeRetired && len(h.queue) > 0 {
		h.updateConnectionID()
	}
	return nil
}

func (h *connIDManager) isInUse(seq uint64) bool {
	if seq == h.activeSequenceNumber {
		return true
	}
	for _, entry := range h.pathProbing {
		if entry.SequenceNumber == seq {
			return true
		}
	}
	return false
}

func (h *connIDManager) addConnectionID(seq uint64, connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	// fast path: add to the end of the queue
	if len(h.queue) == 0 || h.queue[len(h.queue)-1].SequenceNumber < seq {
		h.queue = append(h.queue, newConnID{
			SequenceNumber:      seq,
			ConnectionID:        connID,
			StatelessResetToken: resetToken,
		})
		return nil
	}

	// slow path: insert in the middle
	for i, entry := range h.queue {
		if entry.SequenceNumber == seq {
			if entry.ConnectionID != connID {
				return fmt.Errorf("received conflicting connection IDs for sequence number %d", seq)
			}
			if entry.StatelessResetToken != resetToken {
				return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", seq)
			}
			return nil
		}

		// insert at the correct position to maintain sorted order
		if entry.SequenceNumber > seq {
			h.queue = slices.Insert(h.queue, i, newConnID{
				SequenceNumber:      seq,
				ConnectionID:        connID,
				StatelessResetToken: resetToken,
			})
			return nil
		}
	}
	return nil // unreachable
}

func (h *connIDManager) updateConnectionID() {
	h.assertNotClosed()
	front := h.queue[0]
	h.queue = h.queue[1:]
	h.highestUsedSequenceNumber = max(h.highestUsedSequenceNumber, front.SequenceNumber)
	h.replaceActiveConnectionID(front)
	h.addStatelessResetToken(front.StatelessResetToken)
}

// replaceActiveConnectionID preserves references held by queued path controls.
// The caller registers a reset token only for a newly allocated connection ID.
func (h *connIDManager) replaceActiveConnectionID(c newConnID) {
	if !h.activeRetired {
		h.retireActiveConnectionID()
	}
	h.activeSequenceNumber = c.SequenceNumber
	h.activeConnectionID = c.ConnectionID
	h.activeStatelessResetToken = &c.StatelessResetToken
	h.activeRetired = false
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + h.rand.Uint32N(protocol.PacketsPerConnectionID)
}

func (h *connIDManager) Close() {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.closed = true
	if !h.activeRetired && h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
	for _, entry := range h.pathProbing {
		h.removeStatelessResetToken(entry.StatelessResetToken)
	}
	for _, reference := range h.pathControlRefs {
		if reference.valid && reference.retirePending && reference.hasResetToken {
			h.removeStatelessResetToken(reference.entry.StatelessResetToken)
		}
	}
	clear(h.pathProbing)
	clear(h.pathControlRefs)
}

// is called when the server performs a Retry
// and when the server changes the connection ID in the first Initial sent
func (h *connIDManager) ChangeInitialConnID(newConnID protocol.ConnectionID) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeConnectionID = newConnID
}

// is called when the server provides a stateless reset token in the transport parameters
func (h *connIDManager) SetStatelessResetToken(token protocol.StatelessResetToken) {
	h.assertNotClosed()
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeStatelessResetToken = &token
	h.addStatelessResetToken(token)
}

func (h *connIDManager) SentPacket() {
	h.packetsSinceLastChange++
}

func (h *connIDManager) shouldUpdateConnID() bool {
	if h.activeRetired {
		return len(h.queue) > 0
	}
	if !h.handshakeComplete {
		return false
	}
	// initiate the first change as early as possible (after handshake completion)
	if len(h.queue) > 0 && h.activeSequenceNumber == 0 {
		return true
	}
	// For later changes, only change if
	// 1. The queue of connection IDs is filled more than 50%.
	// 2. We sent at least PacketsPerConnectionID packets
	return 2*len(h.queue) >= protocol.MaxActiveConnectionIDs &&
		h.packetsSinceLastChange >= h.packetsPerConnectionID
}

func (h *connIDManager) Get() protocol.ConnectionID {
	h.assertNotClosed()
	if h.shouldUpdateConnID() {
		h.updateConnectionID()
	}
	return h.activeConnectionID
}

func (h *connIDManager) SetHandshakeComplete() {
	h.handshakeComplete = true
}

// GetConnIDForPath retrieves a connection ID for a new path (i.e. not the active one).
// Once a connection ID is allocated for a path, it cannot be used for a different path.
// When called with the same pathID, it will return the same connection ID,
// unless the peer requested that this connection ID be retired.
func (h *connIDManager) GetConnIDForPath(id pathID) (protocol.ConnectionID, bool) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	// if we're using zero-length connection IDs, we don't need to change the connection ID
	if h.activeConnectionID.Len() == 0 {
		return h.activeConnectionID, true
	}

	if h.pathProbing == nil {
		h.pathProbing = make(map[pathID]newConnID)
	}
	entry, ok := h.pathProbing[id]
	if ok {
		return entry.ConnectionID, true
	}
	if len(h.queue) == 0 {
		return protocol.ConnectionID{}, false
	}
	front := h.queue[0]
	h.queue = h.queue[1:]
	h.pathProbing[id] = front
	h.highestUsedSequenceNumber = max(h.highestUsedSequenceNumber, front.SequenceNumber)
	h.addStatelessResetToken(front.StatelessResetToken)
	return front.ConnectionID, true
}

func (h *connIDManager) RetireConnIDForPath(pathID pathID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	entry, ok := h.pathProbing[pathID]
	if !ok {
		return
	}
	h.retireConnectionID(entry, true)
	delete(h.pathProbing, pathID)
}

// SwitchToPath is called when the connection switches to a path.
// The connection ID allocated to the path becomes the active connection ID,
// and the previously active connection ID is retired.
func (h *connIDManager) SwitchToPath(id pathID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	next, ok := h.pathProbing[id]
	if !ok {
		// The path doesn't have a connection ID if the connection switched away from it before,
		// or if the peer retired it (using Retire Prior To).
		// If there's no unused connection ID, there's no choice but to keep using the active one.
		if len(h.queue) > 0 {
			h.updateConnectionID()
		}
		return
	}
	delete(h.pathProbing, id)
	h.replaceActiveConnectionID(next)
}

func (h *connIDManager) IsActiveStatelessResetToken(token protocol.StatelessResetToken) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if !h.activeRetired && h.activeStatelessResetToken != nil {
		if *h.activeStatelessResetToken == token {
			return true
		}
	}
	if h.pathProbing != nil {
		for _, entry := range h.pathProbing {
			if entry.StatelessResetToken == token {
				return true
			}
		}
	}
	for _, reference := range h.pathControlRefs {
		if reference.valid && reference.hasResetToken && reference.entry.StatelessResetToken == token {
			return true
		}
	}
	return false
}

// Using the connIDManager after it has been closed can have disastrous effects:
// If the connection ID is rotated, a new entry would be inserted into the packet handler map,
// leading to a memory leak of the connection struct.
// See https://github.com/quic-go/quic-go/pull/4852 for more details.
func (h *connIDManager) assertNotClosed() {
	if h.closed {
		panic("connection ID manager is closed")
	}
}
