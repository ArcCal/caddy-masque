package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// References are bounded by the bounded path-control queue. Retiring a local
// CID waits for its last queued packet; peer-requested retirement overrides it.
type pathControlCIDReference struct {
	entry         newConnID
	refs          int
	valid         bool
	hasResetToken bool
	retirePending bool
	replacement   protocol.ConnectionID
}

func checkKnownConnectionID(entry newConnID, f *wire.NewConnectionIDFrame) error {
	if entry.ConnectionID != f.ConnectionID {
		return fmt.Errorf("received conflicting connection IDs for sequence number %d", f.SequenceNumber)
	}
	if entry.StatelessResetToken != f.StatelessResetToken {
		return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", f.SequenceNumber)
	}
	return nil
}

func (h *connIDManager) activeConnectionIDCount() int {
	ids := make(map[uint64]struct{}, protocol.MaxActiveConnectionIDs+1)
	if !h.activeRetired {
		ids[h.activeSequenceNumber] = struct{}{}
	}
	for _, entry := range h.queue {
		ids[entry.SequenceNumber] = struct{}{}
	}
	for _, entry := range h.pathProbing {
		ids[entry.SequenceNumber] = struct{}{}
	}
	for _, reference := range h.pathControlRefs {
		if reference.valid {
			ids[reference.entry.SequenceNumber] = struct{}{}
		}
	}
	return len(ids)
}

func (h *connIDManager) retireConnectionID(entry newConnID, hasToken bool) {
	if reference := h.pathControlRefs[entry.ConnectionID]; reference != nil {
		if !reference.valid {
			return // already forcibly retired while queued
		}
		if reference.refs > 0 && entry.SequenceNumber >= h.peerRetirePriorTo {
			reference.retirePending = true
			return
		}
		reference.valid = false
		reference.hasResetToken = false
		reference.retirePending = false
	}
	h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
	if hasToken {
		h.removeStatelessResetToken(entry.StatelessResetToken)
	}
}

func (h *connIDManager) retireActiveConnectionID() {
	entry := newConnID{SequenceNumber: h.activeSequenceNumber, ConnectionID: h.activeConnectionID}
	if h.activeStatelessResetToken != nil {
		entry.StatelessResetToken = *h.activeStatelessResetToken
	}
	h.retireConnectionID(entry, h.activeStatelessResetToken != nil)
	// This is a local history bound, not the peer's Retire Prior To floor.
	// Known live older reservations and pins are exempt from this bound.
	h.highestRetired = max(h.highestRetired, h.activeSequenceNumber+1)
}

func (h *connIDManager) invalidatePathControlCIDs() {
	for _, reference := range h.pathControlRefs {
		if reference.valid && reference.entry.SequenceNumber < h.peerRetirePriorTo {
			h.retireConnectionID(reference.entry, reference.hasResetToken)
		}
	}
}

func (h *connIDManager) HasActiveConnectionID() bool { return !h.activeRetired }

// PromotePathConnectionID keeps the CID already used for validation on that
// path. In particular, it does not send the old path's CID to a new address.
func (h *connIDManager) PromotePathConnectionID(id pathID) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()
	h.assertNotClosed()
	if h.activeConnectionID.Len() == 0 {
		return true
	}
	entry, ok := h.pathProbing[id]
	if !ok {
		return false
	}
	if !h.activeRetired {
		h.retireActiveConnectionID()
	}
	delete(h.pathProbing, id)
	h.activeSequenceNumber = entry.SequenceNumber
	h.activeConnectionID = entry.ConnectionID
	h.activeStatelessResetToken = &entry.StatelessResetToken
	h.activeRetired = false
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + h.rand.Uint32N(protocol.PacketsPerConnectionID)
	return true // the reservation's reset token was already registered
}

func (h *connIDManager) PinPathControlCID() protocol.ConnectionID {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()
	cid := h.Get()
	if cid.Len() == 0 {
		return cid
	}
	if h.pathControlRefs == nil {
		h.pathControlRefs = make(map[protocol.ConnectionID]*pathControlCIDReference)
	}
	reference := h.pathControlRefs[cid]
	if reference == nil {
		reference = &pathControlCIDReference{entry: newConnID{SequenceNumber: h.activeSequenceNumber, ConnectionID: cid}, valid: !h.activeRetired, hasResetToken: !h.activeRetired && h.activeStatelessResetToken != nil}
		if reference.hasResetToken {
			reference.entry.StatelessResetToken = *h.activeStatelessResetToken
		}
		h.pathControlRefs[cid] = reference
	}
	reference.refs++
	return cid
}

func (h *connIDManager) ReleasePathControlCID(cid protocol.ConnectionID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()
	reference := h.pathControlRefs[cid]
	if reference == nil {
		return
	}
	reference.refs--
	if reference.refs > 0 {
		return
	}
	if reference.valid && reference.retirePending {
		h.retireConnectionID(reference.entry, reference.hasResetToken)
	}
	delete(h.pathControlRefs, cid)
}

func (h *connIDManager) PathControlCIDValid(cid protocol.ConnectionID) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()
	if cid.Len() == 0 {
		return true
	}
	reference := h.pathControlRefs[cid]
	return reference != nil && reference.valid
}

// Refresh adds one reference to a replacement unused on any other route.
// The caller separately releases the old reference after updating its queue.
func (h *connIDManager) RefreshPathControlCID(cid protocol.ConnectionID) (protocol.ConnectionID, bool) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()
	reference := h.pathControlRefs[cid]
	if reference == nil {
		return protocol.ConnectionID{}, false
	}
	if replacement := h.pathControlRefs[reference.replacement]; replacement != nil && replacement.valid {
		replacement.refs++
		return replacement.entry.ConnectionID, true
	}
	if len(h.queue) == 0 {
		return protocol.ConnectionID{}, false
	}
	entry := h.queue[0]
	h.queue = h.queue[1:]
	h.highestUsedSequenceNumber = max(h.highestUsedSequenceNumber, entry.SequenceNumber)
	h.addStatelessResetToken(entry.StatelessResetToken)
	h.pathControlRefs[entry.ConnectionID] = &pathControlCIDReference{entry: entry, refs: 1, valid: true, hasResetToken: true, retirePending: true}
	reference.replacement = entry.ConnectionID
	return entry.ConnectionID, true
}
