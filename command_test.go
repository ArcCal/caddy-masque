package masque

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

// `caddy run` with a Caddyfile that cannot be adapted says why it stops; on
// its own, Caddy v2.11.6 exits with status 1 and no error (flushStartupLog).
func TestRunPrintsConfigError(t *testing.T) {
	if config := os.Getenv("MASQUE_TEST_RUN_CONFIG"); config != "" {
		os.Args = []string{"caddy", "run", "--config", config}
		caddycmd.Main() // exits
		return
	}
	config := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(config, []byte("example.com {\n\tno_such_directive\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunPrintsConfigError$")
	cmd.Env = append(os.Environ(), "MASQUE_TEST_RUN_CONFIG="+config)
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("caddy run: %v, want exit status 1; output:\n%s", err, out)
	}
	if !strings.Contains(string(out), "unrecognized directive: no_such_directive") {
		t.Errorf("caddy run does not say why it stopped; output:\n%s", out)
	}
}
