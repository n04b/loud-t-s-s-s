package loudtsss

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Version is set at build time with -ldflags "-X github.com/n04b/loud-t-s-s-s/internal/loudtsss.Version=...".
var Version = "dev"

const usage = `loudtsss: typed environment config with encrypted values. Secrets stay quiet, errors stay loud.

Usage:
  loudtsss keygen <env>          create the key of an environment and its first, empty block
  loudtsss unpack <env>          decrypt an environment into the working file
  loudtsss pack                  validate the working file, encrypt pending values, update loudtsss.json
  loudtsss check                 validate loudtsss.json and every block you have a key for
  loudtsss export <env>          write .env and .env.example for an environment
  loudtsss install-hook          install a git pre-commit hook that runs "loudtsss check --hook"
  loudtsss version

Common flags:
  -c, --config <path>     committed file (default loudtsss.json)
  -w, --working <path>    working file (default: the config name with .local.json)
  --keys-dir <dir>        directory with key files (default $LOUD_T_S_S_S_KEYS_DIR,
                          or loud-t-s-s-s/keys in the user config directory)

Command flags:
  unpack --force          overwrite a working file with changes that are not packed
  check --hook            also check the git index and the working file (pre-commit)
  check --all-keys        fail when a block cannot be verified for lack of a key (CI)
  export -o <path>        output file (default .env; "-" for stdout)
  export --example <path> .env.example path (default .env.example; "" to skip)
  export --force          write the output even if git does not ignore it
  install-hook --force    replace an existing pre-commit hook

A key is read from $LOUD_T_S_S_S_KEY_<ENV> (e.g. LOUD_T_S_S_S_KEY_PRODUCTION) or from <keys-dir>/<keyId>.key.
Exit codes: 0 success, 1 validation or check failed, 2 usage error.
`

// Main runs the CLI and returns the exit code.
func Main(args []string, stdout, stderr io.Writer, getenv func(string) string, cwd string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	if cmd == "version" || cmd == "--version" {
		fmt.Fprintln(stdout, "loudtsss", Version)
		return 0
	}

	fs := flag.NewFlagSet("loudtsss "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, "run \"loudtsss help\" for usage\n") }
	config := fs.String("config", "loudtsss.json", "")
	fs.StringVar(config, "c", "loudtsss.json", "")
	working := fs.String("working", "", "")
	fs.StringVar(working, "w", "", "")
	keysDir := fs.String("keys-dir", "", "")
	force := fs.Bool("force", false, "")
	hook := fs.Bool("hook", false, "")
	allKeys := fs.Bool("all-keys", false, "")
	output := fs.String("output", ".env", "")
	fs.StringVar(output, "o", ".env", "")
	example := fs.String("example", ".env.example", "")

	pos, err := parseInterspersed(fs, rest)
	if err != nil {
		return 2
	}
	allowed := map[string][]string{
		"keygen": {}, "unpack": {"force"}, "pack": {}, "check": {"hook", "all-keys"},
		"export": {"output", "o", "example", "force"}, "install-hook": {"force"},
	}
	cmdFlags, ok := allowed[cmd]
	if !ok {
		fmt.Fprintf(stderr, "error: unknown command %q; run \"loudtsss help\"\n", cmd)
		return 2
	}
	var bad []string
	fs.Visit(func(f *flag.Flag) {
		if !contains([]string{"config", "c", "working", "w", "keys-dir"}, f.Name) && !contains(cmdFlags, f.Name) {
			bad = append(bad, "--"+f.Name)
		}
	})
	if len(bad) > 0 {
		fmt.Fprintf(stderr, "error: %s does not take %s\n", cmd, strings.Join(bad, ", "))
		return 2
	}
	wantArgs := map[string]int{"keygen": 1, "unpack": 1, "export": 1}[cmd]
	if len(pos) != wantArgs {
		if wantArgs == 1 {
			fmt.Fprintf(stderr, "error: usage: loudtsss %s <env>\n", cmd)
		} else {
			fmt.Fprintf(stderr, "error: %s takes no arguments, got %s\n", cmd, strings.Join(pos, " "))
		}
		return 2
	}

	abs := func(p string) string {
		if p == "" || p == "-" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(cwd, p)
	}
	a := &App{ConfigPath: abs(*config), Stdout: stdout, Stderr: stderr}
	a.WorkingPath = abs(*working)
	if a.WorkingPath == "" {
		a.WorkingPath = strings.TrimSuffix(a.ConfigPath, ".json") + ".local.json"
	}
	dir := *keysDir
	if dir == "" {
		dir = getenv(keysDirVar)
	}
	if dir == "" {
		if base, err := os.UserConfigDir(); err == nil {
			dir = filepath.Join(base, "loud-t-s-s-s", "keys")
		}
	}
	a.Keys = KeyStore{Dir: abs(dir), Getenv: getenv}

	switch cmd {
	case "keygen":
		return a.Keygen(pos[0])
	case "unpack":
		return a.Unpack(pos[0], *force)
	case "pack":
		return a.Pack()
	case "check":
		return a.Check(*hook, *allKeys)
	case "export":
		return a.Export(pos[0], abs(*output), abs(*example), *force)
	case "install-hook":
		return a.InstallHook(*force)
	}
	return 2
}

// parseInterspersed allows flags before and after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
