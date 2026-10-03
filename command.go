package masque

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"

	"github.com/ArcCal/caddy-masque/internal/auth"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "masque-passwd",
		Usage: "--name <user> [--stdin]",
		Short: "Creates a masque user: a random password and its hash",
		Long: `
Creates a user for the masque app and prints the line for the Caddyfile and
the lines for the masque-vpn client configuration.

--name
    User name: 1-64 letters, digits, '-', '_' or '.'.

--stdin
    Read the password from standard input instead of generating one.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().String("name", "", "User name")
			cmd.Flags().Bool("stdin", false, "Read the password from standard input")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdPasswd)
		},
	})
	cobra.OnFinalize(flushStartupLog)
}

// flushStartupLog writes the log entries Caddy still holds back to standard
// error. `caddy run` keeps its log in memory until the configuration's logging
// is set up; when reading or adapting the configuration fails (a missing file,
// a Caddyfile error), it writes out what it held, then logs the error into the
// same buffer, which nothing writes out again: the program exits with status 1
// without saying why (Caddy v2.11.6 and v2.11.7). Cobra runs this when a
// command returns; Caddy's logger is then still the buffer only in that case.
func flushStartupLog() {
	buffer, ok := caddy.Log().Core().(interface{ FlushTo(*zap.Logger) })
	if !ok {
		return
	}
	buffer.FlushTo(zap.New(zapcore.NewCore(stderrLogEncoder(), zapcore.Lock(os.Stderr), zapcore.DebugLevel)))
}

// stderrLogEncoder formats log entries the way Caddy's default logger does.
func stderrLogEncoder() zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return zapcore.NewJSONEncoder(cfg)
	}
	cfg.EncodeTime = func(ts time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(ts.UTC().Format("2006/01/02 15:04:05.000"))
	}
	if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "xterm-mono" {
		cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	return zapcore.NewConsoleEncoder(cfg)
}

func cmdPasswd(fl caddycmd.Flags) (int, error) {
	name := fl.String("name")
	if err := auth.ValidateUserName(name); err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	password, generated := "", true
	if fl.Bool("stdin") {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("reading the password: %w", err)
		}
		password, generated = strings.TrimRight(string(b), "\r\n"), false
		if utf8.RuneCountInString(password) < auth.MinPasswordLen {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("the password must have at least %d characters", auth.MinPasswordLen)
		}
		if strings.ContainsFunc(password, unicode.IsControl) {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("the password must not contain control characters")
		}
	} else {
		password = auth.GeneratePassword()
	}
	hash := auth.HashPassword(password)
	fmt.Println("# Add to the masque block of the Caddyfile's global options, then: caddy reload")
	fmt.Printf("user %s %s\n\n", name, hash)
	fmt.Println("# Add to the client's /etc/masque/client.toml (before the first [section]):")
	fmt.Printf("username = %q\n", name)
	if generated {
		fmt.Printf("password = %q\n", password)
	} else {
		fmt.Println(`password = "..."   # the password you entered`)
	}
	return 0, nil
}
