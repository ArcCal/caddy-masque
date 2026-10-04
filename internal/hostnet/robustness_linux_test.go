package hostnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNetworkOwnership(t *testing.T) {
	dir := t.TempDir()
	owner, err := acquireNetworkOwner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if other, err := acquireNetworkOwner(dir); err == nil {
		other.Close()
		t.Fatal("two managers acquired the same namespace")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := func(mode string) *exec.Cmd {
		return exec.Command(exe, "-test.run=^TestNetworkOwnershipHelper$", "--", dir, mode)
	}
	if out, err := command("acquire").CombinedOutput(); err == nil {
		t.Fatalf("another process acquired an owned namespace: %s", out)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	child := command("hold")
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "LOCKED\n" {
			t.Fatalf("child did not acquire lock: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child stalled")
	}
	if other, err := acquireNetworkOwner(dir); err == nil {
		other.Close()
		t.Fatal("parent acquired child's namespace")
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	recovered, err := acquireNetworkOwner(dir)
	if err != nil {
		t.Fatalf("crashed manager retained ownership: %v", err)
	}
	defer recovered.Close()
}

func TestNetworkOwnershipHelper(t *testing.T) {
	args := os.Args
	if len(args) < 4 || args[len(args)-3] != "--" {
		t.Skip("subprocess helper")
	}
	owner, err := acquireNetworkOwner(args[len(args)-2])
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if args[len(args)-1] == "hold" {
		fmt.Println("LOCKED")
		select {}
	}
}

func TestNetworkOwnershipRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"directory symlink", "writable directory", "file symlink", "hard link"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			lock, err := acquireNetworkOwner(dir)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, lock.Name())
			lock.Close()
			switch kind {
			case "directory symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "writable directory":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "file symlink":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(t.TempDir(), "target"), name); err != nil {
					t.Fatal(err)
				}
			case "hard link":
				if err := os.Link(name, filepath.Join(dir, "other")); err != nil {
					t.Fatal(err)
				}
			}
			if lock, err := acquireNetworkOwner(dir); err == nil {
				lock.Close()
				t.Fatal("accepted unsafe ownership path")
			}
		})
	}
}

func TestNetworkCloseIsIdempotent(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	owner, err := acquireNetworkOwner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n := &Network{tun: r, owner: owner}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := n.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("TUN not closed: %v", err)
	}
}

func TestSysctlRestoreRespectsLaterChange(t *testing.T) {
	for _, current := range []string{"2", "0"} {
		t.Run(current, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "accept_ra")
			if err := os.WriteFile(path, []byte(current), 0600); err != nil {
				t.Fatal(err)
			}
			if err := (sysctl{"accept_ra", "1", "2"}).restore(path); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := current
			if current == "2" {
				want = "1"
			}
			if string(got) != want {
				t.Fatalf("restored %s to %s, want %s", current, got, want)
			}
		})
	}
	if err := (sysctl{"missing", "0", "1"}).restore(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("lost sysctl cleanup error")
	}
}

func TestHostCommandsAreBounded(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = runOutput(ctx, nil, exe, "-test.run=^TestHostCommandHelper$", "--", "block")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost timeout: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("command did not terminate promptly")
	}
	_, err = runOutput(context.Background(), nil, exe, "-test.run=^TestHostCommandHelper$", "--", "output")
	if err == nil || !strings.Contains(err.Error(), "exceeded 64 KiB") || len(err.Error()) > commandOutputLimit+1024 {
		t.Fatalf("unbounded or silently truncated command output: error length %d", len(fmt.Sprint(err)))
	}
}

func TestHostCommandHelper(t *testing.T) {
	args := os.Args
	if len(args) < 3 || args[len(args)-2] != "--" {
		t.Skip("subprocess helper")
	}
	if args[len(args)-1] == "block" {
		select {}
	}
	fmt.Print(strings.Repeat("x", commandOutputLimit*2))
}

func TestFirewallSnapshotDetectsDrift(t *testing.T) {
	fixture := `{"nftables":[{"metainfo":{"version":"1"}},{"table":{"family":"inet","name":"caddy-masque","handle":1}},{"chain":{"family":"inet","table":"caddy-masque","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"caddy-masque","chain":"forward","handle":3,"expr":[{"drop":null}]}}]}`
	baseline, err := firewallSnapshot([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, raw string
		equal     bool
	}{
		{"new handles", strings.ReplaceAll(fixture, `"handle":`, `"handle":9`), true},
		{"metainfo", strings.Replace(fixture, `"version":"1"`, `"version":"2"`, 1), true},
		{"verdict", strings.Replace(fixture, `"drop":null`, `"accept":null`, 1), false},
		{"hook", strings.Replace(fixture, `"hook":"forward"`, `"hook":"input"`, 1), false},
		{"policy", strings.Replace(fixture, `"policy":"accept"`, `"policy":"drop"`, 1), false},
		{"priority", strings.Replace(fixture, `"prio":0`, `"prio":1`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := firewallSnapshot([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, baseline) != tc.equal {
				t.Fatal("incorrect drift detection")
			}
		})
	}
	for _, invalid := range []string{`{}`, `{"nftables":[]}`, `{"nftables":[{"rule":null}]}`, `{"nftables":[{"rule":{},"chain":{}}]}`} {
		if _, err := firewallSnapshot([]byte(invalid)); err == nil {
			t.Fatalf("accepted invalid snapshot %s", invalid)
		}
	}
}

func TestFirewallInspectionFailureDoesNotOverwrite(t *testing.T) {
	for _, enumeration := range []string{
		`{"nftables":[{"table":{"family":"inet","name":"caddy-masque"}}]}`,
		`invalid JSON`,
	} {
		t.Run(enumeration, func(t *testing.T) {
			dir := t.TempDir()
			// This spy never invokes a real networking tool. It records a
			// mistaken replacement transaction in its own temporary directory.
			script := "#!/bin/sh\ncase \"$*\" in\n'-j list tables') printf '%s' '" + enumeration + "';;\n'-f -') printf x > \"$0.mutated\";;\n*) printf 'inspection failed' >&2; exit 1;;\nesac\n"
			tool := filepath.Join(dir, "nft")
			if err := os.WriteFile(tool, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			n := &Network{name: "masque0", cfg: Config{IPv4: netip.MustParsePrefix("10.89.0.1/24")}}
			if messages := n.repairFirewall(); len(messages) != 1 || !strings.Contains(messages[0], "could not inspect") {
				t.Fatalf("lost inspection failure: %v", messages)
			}
			if _, err := os.Stat(tool + ".mutated"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("overwrote rules without proof of deletion: %v", err)
			}
		})
	}
}
