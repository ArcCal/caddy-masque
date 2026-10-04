package hostnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const commandTimeout = 5 * time.Second
const commandOutputLimit = 64 << 10

// A broken tool must not retain an unbounded amount of output or prevent
// startup, firewall repair or shutdown from finishing.
type commandOutput struct {
	sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (b *commandOutput) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	n := len(p)
	if remaining := commandOutputLimit - b.buf.Len(); len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return n, nil
}

func runOutput(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out commandOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if out.truncated {
		err = errors.Join(err, errors.New("command output exceeded 64 KiB"))
	}
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.buf.String()))
	}
	return out.buf.Bytes(), nil
}

func run(stdin []byte, name string, args ...string) error {
	_, err := runOutput(context.Background(), stdin, name, args...)
	return err
}
