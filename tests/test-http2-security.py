#!/usr/bin/env python3
"""Exercise fixed upstream HTTP/2 security contracts against the shipped fork.

Upstream fixtures cover Trailer allocation (GO-2026-6603), framing response
headers (GO-2026-6610), flow-control limits (GO-2026-6611), single refund after
reset/disposal (GO-2026-6612), and deferred HPACK encoder SETTINGS updates
(GO-2026-6617). See https://pkg.go.dev/vuln/GO-2026-6603 and the related IDs.
The extra bounded window test checks shared accounting with 128 active streams;
it has no wall-clock performance threshold or exhaustion benchmark.

The http2legacy tag selects the upstream internal test harness on Go 1.27.
The shipped MASQUE fork already selects its patched transport on both supported
Go versions; no extra tag is required to build the production server.
"""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


GROUPS = {
    "GO-2026-6603": ["TestMetaFrameHeader"],
    "GO-2026-6610": [
        "TestTransportResponseContentLength", "TestTransportResponseConnHeaders",
    ],
    "GO-2026-6611": [
        "TestSecurityServerInitialWindowChangesUseSharedAccounting",
        "TestSecurityClientInitialWindowChangesUseSharedAccounting",
        "TestServerSettingsFlowControlUpdateBeyondLimit",
        "TestServerSettingsFlowControlUpdateWithinLimit",
        "TestTransportSettingsFlowControlUpdateBeyondLimit",
        "TestTransportSettingsFlowControlUpdateWithinLimit",
    ],
    "GO-2026-6612": ["TestServerResetStreamUnreadBody"],
    "GO-2026-6617": ["TestServer_HeaderTableSizeDuringWrite"],
}

NESTED = {
    "TestTransportResponseContentLength": [
        "single_value", "identical_duplicate_values", "different_duplicate_values",
        "extraneous_whitespace", "identical_duplicate_values_with_extraneous_whitespace",
        "plus_sign", "non-numeric", "empty_value", "no_header",
    ],
    "TestTransportResponseConnHeaders": [
        "unaffected_header", "transfer-encoding", "transfer-encoding_alongside_content-length",
        "connection_and_keep-alive", "proxy-connection", "upgrade",
    ],
    "TestServerResetStreamUnreadBody": [
        "read_after_reset", "exit_without_reading", "read_after_handler_exit",
        "unstarted_handler", "middleware_replaces_body",
    ],
}

SHARED_ACCOUNTING_TEST = r"""
package http2

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// SETTINGS_INITIAL_WINDOW_SIZE must change the shared initial window, rather
// than mutating every active stream's private accounting. This bounded test
// checks that property and the resulting usable windows. It does not use a
// timing threshold or claim to measure CPU exhaustion. Verified upstream source
// additionally establishes that neither SETTINGS handler traverses stream maps.
func TestSecurityServerInitialWindowChangesUseSharedAccounting(t *testing.T) {
	sc := &serverConn{
		serveG:     newGoroutineLock(),
		hs:         &http.Server{},
		baseCtx:    context.Background(),
		streams:    make(map[uint32]*stream),
		writeSched: NewRoundRobinWriteScheduler(),
	}
	sc.flow.add(1 << 20)
	if err := sc.processSettingInitialWindowSize(initialWindowSize); err != nil {
		t.Fatal(err)
	}
	flows := make([]*outflow, 128)
	for i := range flows {
		st := sc.newStream(uint32(i*2+1), 0, stateOpen, PriorityParam{})
		defer st.cancelCtx()
		flows[i] = &st.flow
	}
	checkSecuritySharedAccounting(t, flows, func(size uint32) error {
		return sc.processSettingInitialWindowSize(size)
	})
}

func TestSecurityClientInitialWindowChangesUseSharedAccounting(t *testing.T) {
	cc := &ClientConn{
		t:                &Transport{},
		streams:          make(map[uint32]*clientStream),
		seenSettingsChan: make(chan struct{}),
		nextStreamID:     1,
	}
	cc.cond = sync.NewCond(&cc.mu)
	cc.flow.add(1 << 20)
	rl := &clientConnReadLoop{cc: cc}
	apply := func(size uint32) error {
		var wire bytes.Buffer
		fr := NewFramer(&wire, &wire)
		if err := fr.WriteSettings(Setting{SettingInitialWindowSize, size}); err != nil {
			return err
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		return rl.processSettingsNoWrite(frame.(*SettingsFrame))
	}
	if err := apply(initialWindowSize); err != nil {
		t.Fatal(err)
	}
	flows := make([]*outflow, 128)
	for i := range flows {
		st := &clientStream{}
		cc.addStreamLocked(st)
		flows[i] = &st.flow
	}
	checkSecuritySharedAccounting(t, flows, apply)
}

func checkSecuritySharedAccounting(t *testing.T, flows []*outflow, apply func(uint32) error) {
	t.Helper()
	snapshots := make([]string, len(flows))
	deltas := make([]int32, len(flows))
	for i, flow := range flows {
		// Model differently consumed/granted windows, including streams that
		// become temporarily negative after a SETTINGS shrink and recover.
		deltas[i] = []int32{0, 7, -11, -initialWindowSize + 2}[i%4]
		if !flow.add(deltas[i]) {
			t.Fatalf("stream %d: failed to prepare window", i)
		}
		snapshots[i] = fmt.Sprintf("%#v", *flow)
		if got := securityAvailable(t, flow); got != initialWindowSize+deltas[i] {
			t.Fatalf("stream %d: initial window %d, want %d", i, got, initialWindowSize+deltas[i])
		}
	}
	for _, size := range []uint32{initialWindowSize - 1, 0, 5, initialWindowSize, initialWindowSize + 9} {
		if err := apply(size); err != nil {
			t.Fatal(err)
		}
		changed := 0
		for i, flow := range flows {
			if fmt.Sprintf("%#v", *flow) != snapshots[i] {
				changed++
			}
			if got, want := securityAvailable(t, flow), int32(size)+deltas[i]; got != want {
				t.Errorf("stream %d after initial window %d: available %d, want %d", i, size, got, want)
			}
		}
		if changed != 0 {
			t.Fatalf("SETTINGS initial window %d eagerly changed %d of %d stream accounts; shared updates must leave stream-local counters untouched", size, changed, len(flows))
		}
	}
}

// The pre-fix API returned one value; the fixed API also reports lazy overflow.
// Keeping this adapter allows identical regression code to exercise both the
// vulnerable baseline and fixed implementation without patching either source.
func securityAvailable(t *testing.T, flow *outflow) int32 {
	t.Helper()
	switch value := any(flow).(type) {
	case interface{ available() (int32, bool) }:
		n, ok := value.available()
		if !ok {
			t.Fatal("unexpected flow-control overflow")
		}
		return n
	case interface{ available() int32 }:
		return value.available()
	default:
		t.Fatal("unrecognized flow-control API")
		return 0
	}
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-summary", type=Path, help="Write the gate result and matched test counts.")
    parser.add_argument("--json-log", type=Path, help="Save the exact go test JSON output, including failures.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = re.search(r"^\s*(?:require\s+)?golang\.org/x/net\s+(\S+)", (root / "go.mod").read_text(), re.MULTILINE)
    if not version or version.group(1) != "v0.62.0":
        raise SystemExit("Security fixture baseline requires the verified x/net v0.62.0 fork; review this gate with future upgrades")

    # This binds the complete fork, including every upstream fixture, to the
    # checksum-verified security release plus the documented MASQUE patch.
    verified = subprocess.run(
        [sys.executable, str(root / "tests" / "verify-http2-fork.py")],
        cwd=root, capture_output=True, text=True,
    )
    if verified.stdout:
        print(verified.stdout, end="", file=sys.stderr)
    if verified.stderr:
        print(verified.stderr, end="", file=sys.stderr)
    if verified.returncode:
        return verified.returncode

    names = [name for group in GROUPS.values() for name in group]
    pattern = "^(" + "|".join(names) + ")$"
    with tempfile.TemporaryDirectory(prefix="masque-http2-security-") as temporary:
        target = Path(temporary) / "xnet"
        shutil.copytree(root / "third_party" / "xnet", target)
        extra = target / "http2" / "masque_security_shared_accounting_test.go"
        if extra.exists():
            raise SystemExit("Supplemental security fixture would replace an existing source file")
        extra.write_text(SHARED_ACCOUNTING_TEST, encoding="utf-8")
        command = [
            "go", "test", "-json", "-race", "-p", "2", "-count=1",
            "-timeout=2m", "-tags=http2legacy", "-run", pattern, "./http2",
        ]
        tested = subprocess.run(command, cwd=target, capture_output=True, text=True)

    if args.json_log:
        args.json_log.write_text(tested.stdout, encoding="utf-8")
    events = []
    malformed = []
    for line in tested.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            malformed.append(line)
    passed = {item["Test"] for item in events if item.get("Action") == "pass" and "Test" in item}
    failures = [item.get("Test", item.get("Package", "unknown")) for item in events if item.get("Action") == "fail"]
    skipped = [item.get("Test", item.get("Package", "unknown")) for item in events if item.get("Action") == "skip"]
    required = set(names)
    required.update(f"{parent}/{child}" for parent, children in NESTED.items() for child in children)
    missing = sorted(required - passed)
    package_passed = any(item.get("Action") == "pass" and "Test" not in item for item in events)
    success = not (tested.returncode or malformed or failures or skipped or missing) and package_passed
    result = {
        "status": "passed" if success else "failed",
        "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
        "upstream_version": version.group(1),
        "command": command,
        "go_test_exit_status": tested.returncode,
        "passed_test_events": len(passed),
        "required_top_level_tests": len(names),
        "required_nested_tests": len(required) - len(names),
        "missing_required_passes": missing,
        "failed": failures,
        "skipped": skipped,
        "malformed_output_lines": malformed,
        "advisory_groups": {
            advisory: {"required": group, "passed": [name for name in group if name in passed]}
            for advisory, group in GROUPS.items()
        },
    }
    rendered = json.dumps(result, indent=2)
    if args.json_summary:
        args.json_summary.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if not success:
        if tested.stderr:
            print(tested.stderr, end="", file=sys.stderr)
        if tested.stdout:
            print(tested.stdout, end="", file=sys.stderr)
    return 0 if success else (tested.returncode or 1)


if __name__ == "__main__":
    sys.exit(main())
