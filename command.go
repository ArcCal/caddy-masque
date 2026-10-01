package masque

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"

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
