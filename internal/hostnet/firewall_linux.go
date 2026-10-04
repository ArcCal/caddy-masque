package hostnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

func (n *Network) repairFirewall() []string {
	snapshot, inspectErr := readFirewallSnapshot()
	needsRepair := inspectErr == nil && !bytes.Equal(snapshot, n.rulesSnapshot)
	if inspectErr != nil {
		absent, err := firewallTableAbsent()
		if err != nil || !absent {
			return []string{"could not inspect nftables rules: " + errors.Join(inspectErr, err).Error()}
		}
		needsRepair = true
	}
	if needsRepair {
		if err := n.installRules(); err != nil {
			return []string{"the nftables rules changed or disappeared and could not be installed again: " + err.Error()}
		}
		return []string{"the nftables rules changed or disappeared; installed them again"}
	}
	return nil
}

// Compare the kernel's JSON representation with the representation read back
// after our own transaction. Handles and metainfo change between loads; chain
// policies, hooks, priorities, rule order and every expression must match.
func firewallSnapshot(raw []byte) ([]byte, error) {
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decoding nftables JSON: %w", err)
	}
	if doc.NFTables == nil {
		return nil, fmt.Errorf("missing nftables JSON array")
	}
	var objects []map[string]any
	for _, entry := range doc.NFTables {
		if len(entry) != 1 {
			return nil, fmt.Errorf("invalid nftables JSON entry")
		}
		for kind, raw := range entry {
			if kind == "metainfo" {
				continue
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
				return nil, fmt.Errorf("invalid nftables %s object", kind)
			}
			if kind == "table" || kind == "chain" || kind == "rule" {
				delete(fields, "handle")
			}
			objects = append(objects, map[string]any{kind: fields})
		}
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("empty nftables table snapshot")
	}
	return json.Marshal(objects)
}

func readFirewallSnapshot() ([]byte, error) {
	out, err := runOutput(context.Background(), nil, "nft", "-j", "list", "table", "inet", NFTTable)
	if err != nil {
		return nil, err
	}
	return firewallSnapshot(out)
}

// A failed inspection (permission denied, timeout, invalid output) is not
// proof of deletion. Only a successful table enumeration can establish that.
func firewallTableAbsent() (bool, error) {
	out, err := runOutput(context.Background(), nil, "nft", "-j", "list", "tables")
	if err != nil {
		return false, err
	}
	var doc struct {
		NFTables []struct {
			Table *struct{ Family, Name string } `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || doc.NFTables == nil {
		return false, fmt.Errorf("invalid nftables table enumeration")
	}
	for _, entry := range doc.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == NFTTable {
			return false, nil
		}
	}
	return true, nil
}
