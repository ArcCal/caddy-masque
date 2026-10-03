package masque

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallBinaryPreservesWorkingInstallation(t *testing.T) {
	for _, tc := range []struct {
		name, existing, candidate string
		invalidConfig             bool
		wantError                 bool
	}{
		{"valid upgrade", "masque\nhttp.handlers.masque\ndns.providers.cloudflare", "masque\nhttp.handlers.masque\ndns.providers.cloudflare", false, false},
		{"missing DNS plugin", "masque\nhttp.handlers.masque\ndns.providers.cloudflare", "masque\nhttp.handlers.masque", false, true},
		{"missing handler", "masque\nhttp.handlers.masque", "masque", false, true},
		{"invalid configuration", "masque\nhttp.handlers.masque", "masque\nhttp.handlers.masque", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target, candidate, config := filepath.Join(dir, "caddy"), filepath.Join(dir, "candidate"), filepath.Join(dir, "Caddyfile")
			fake := func(modules, marker string, invalid bool) string {
				code := 0
				if invalid {
					code = 1
				}
				return fmt.Sprintf("#!/usr/bin/env bash\n# %s\ncase $1 in\nlist-modules) cat <<'EOF'\n%s\n\n  Non-standard modules: 3\nEOF\n;;\nvalidate) exit %d;;\nesac\n", marker, modules, code)
			}
			old := fake(tc.existing, "original", false)
			newBinary := fake(tc.candidate, "new", tc.invalidConfig)
			for path, contents := range map[string]string{target: old, candidate: newBinary, config: "test configuration"} {
				if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command("bash", "deploy/install-binary.sh", candidate, config, target).CombinedOutput()
			if (err != nil) != tc.wantError {
				t.Fatalf("result %v: %s", err, out)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			want := newBinary
			if tc.wantError {
				want = old
			}
			if string(got) != want {
				t.Fatal("installed binary was unexpectedly changed")
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.wantError && info.Mode().Perm() != 0755 {
				t.Fatalf("mode %o", info.Mode().Perm())
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".caddy-install.") {
					t.Error("staging file leaked")
				}
			}
		})
	}
}
